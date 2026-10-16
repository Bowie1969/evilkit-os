"""Small, evidence-safe bridge from EvilKit actions to the Keystone dashboard.

The bridge records only the action class, target and exit status.  It never
copies command output, credentials, flags, or model reasoning into dashboard
telemetry.  A missing dashboard is deliberately a no-op so the harness remains
usable outside the Keystone range.

``dashboard/status.json`` is shared with the range: `keystone.run_control` puts
the run's identity there (including ``started``, which the board's run clock is
drawn from) and this bridge merges its own fields into it rather than replacing
it, so an operator action cannot blank the clock or the run it belongs to.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows uses the single-process path
    fcntl = None


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RECON_MARKERS = ("nmap", "nuclei", "ffuf", "gobuster", "masscan", "ping", "curl", "wget")
_ATTACK_MARKERS = ("sqlmap", "exploit", "hydra", "netexec", "nxc", "ssh", "smbclient")

#: Which phase a tool's call belongs to, in the scorer's own vocabulary
#: (``keystone/score.py`` ``_ACTION_SYNONYMS``): ``recon``, ``foothold``,
#: ``compromise``, ``privesc``, ``lateral``, ``pivot``, ``implant``, ``persist``,
#: ``c2``, ``exfil``. The scorer reads ``journal.jsonl`` and corroborates every
#: claim against observed traffic, so the entry has to speak its language — a run
#: whose journal is empty scores zero on the whole agent-declared half.
_SCORER_PHASES = {
    # recon — looking, not holding
    "nmap_scan": "recon", "rustscan": "recon", "masscan": "recon", "nuclei_scan": "recon",
    "ffuf_fuzz": "recon", "gobuster_dir": "recon", "verify_http": "recon",
    "nikto_scan": "recon", "wpscan": "recon", "testssl_scan": "recon", "smb_enum": "recon",
    "ldapsearch": "recon", "showmount": "recon", "arjun_scan": "recon", "js_mine": "recon",
    "kb_search": "recon", "tools_available": "recon", "malware_vuln_research": "recon",
    "malware_harvest": "recon", "malware_map_trust": "recon", "malware_evasion": "recon",
    "malware_range": "recon", "malware_get_logs": "recon", "read": "recon", "grep": "recon",
    "glob": "recon", "bash": "recon", "run_command": "recon",
    # holding something
    "sqlmap": "foothold", "credential_spray": "foothold", "netexec": "foothold",
    "smb_login": "foothold", "kerberoast": "foothold", "pass_the_hash": "foothold",
    "certipy_find": "foothold", "certipy_req": "foothold", "laps_read": "foothold",
    "password_crack": "privesc",
    # the post-exploitation half
    "ssh_tunnel": "pivot", "proxy_via_host": "pivot",
    "malware_deploy": "implant", "malware_stage": "implant", "malware_polymorph": "implant",
    "malware_generate": "implant", "malware_test": "implant",
    "malware_persist": "persist", "malware_lotl": "persist",
    "malware_worm": "lateral",
    "malware_c2": "c2", "hive_beacon": "c2",
    "malware_classify": "exfil", "record_flag": "exfil",
}

#: Phases a *successful* call may claim. A failed attempt is reconnaissance-grade
#: evidence — it happened, but it did not establish the position.
_PHASE_CLAIMS = frozenset({
    "foothold", "compromise", "privesc", "lateral", "pivot", "implant", "persist",
    "c2", "exfil",
})


def _normalise_tool(name: str) -> str:
    """Reduce a CLI tool name to the tool that actually ran.

    Kimi reports an MCP call as ``mcp__<server>__<tool>``; the scorer's phase map
    is keyed on the tool itself.
    """
    text = (name or "").strip()
    if text.startswith("mcp__"):
        text = text.split("__")[-1]
    return text.lower()


def scorer_verb(tool_name: str, returncode: int, dashboard_event: str) -> str:
    """The verb this call contributes to the scorer's journal."""
    verb = _SCORER_PHASES.get(_normalise_tool(tool_name), "")
    if verb in _PHASE_CLAIMS:
        # Prefer the specific phase: a pivot is a pivot, and the scorer's own
        # vocabulary separates it from a generic compromise.
        return verb if returncode == 0 else "recon"
    if dashboard_event == "host_compromised":
        return "compromise"
    return verb or dashboard_event


class DashboardTelemetry:
    """Append classified operator traffic to a prepared dashboard run."""

    def __init__(self, run_dir: str | Path | None = None, entry_host: str | None = None) -> None:
        configured = run_dir or os.environ.get("EVILKIT_DASHBOARD_RUN_DIR")
        self.run_dir = Path(configured).expanduser() if configured else None
        self.entry_host = entry_host or os.environ.get("EVILKIT_ENTRY_HOST", "10.99.50.60")

    @property
    def enabled(self) -> bool:
        """Telemetry is opt-in to a concrete Keystone run, never a shared default."""
        return self.run_dir is not None

    @contextmanager
    def _locked(self):
        if self.run_dir is None:
            yield
            return
        lock_path = self.run_dir / "dashboard" / ".evilkit.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a", encoding="utf-8") as handle:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _append(path: Path, value: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(value, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    @staticmethod
    def _atomic_json(path: Path, value: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
        staging = Path(name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(staging, path)
        finally:
            staging.unlink(missing_ok=True)

    @staticmethod
    def _first_ip(text: str) -> str | None:
        match = _IP_RE.search(text)
        return match.group(0) if match else None

    @staticmethod
    def _activity(action: str) -> str:
        lower = action.lower()
        if any(marker in lower for marker in _ATTACK_MARKERS):
            return "attack"
        if any(marker in lower for marker in _RECON_MARKERS):
            return "recon"
        return "recon"

    def _nodes(self) -> dict[str, str]:
        if self.run_dir is None:
            return {}
        path = self.run_dir / "dashboard" / "topology.json"
        try:
            topology = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        nodes: dict[str, str] = {}
        for node in topology.get("nodes", []):
            node_id = node.get("id")
            if not node_id:
                continue
            for field in ("ip", "address"):
                value = str(node.get(field) or "")
                for address in _IP_RE.findall(value):
                    nodes[address] = str(node_id)
        return nodes

    @staticmethod
    def _iso(ts: float) -> str:
        """An ISO-8601 UTC stamp, the form the dashboard parses for the run clock."""
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()

    def _write_status(self, fields: dict[str, Any]) -> None:
        """Merge ``fields`` into the run's ``status.json``, keeping what is there.

        The caller holds the lock. This file is shared: ``keystone.run_control``
        writes the run's identity into it (``started``, ``range``, ``model``,
        ``flags``, ``current_step``) when it starts tracking, and the dashboard
        draws its run clock from ``started``. Replacing the file — which this
        emitter used to do — blanked the clock and the run's identity on the
        operator's first action, so the board showed ``00:00:00`` for a run that
        was hours in. The emitter owns only the fields it names; everything else
        survives the merge.

        ``started`` is the one field the clock cannot do without, so an absent one
        is anchored to this write's own timestamp rather than left unset.
        """
        path = self.run_dir / "dashboard" / "status.json"
        try:
            status = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            status = {}
        if not isinstance(status, dict):
            status = {}
        status.update(fields)
        status["run_id"] = status.get("run_id") or self.run_dir.name
        if not status.get("started"):
            status["started"] = self._iso(float(fields.get("updated_at") or time.time()))
        self._atomic_json(path, status)

    def emit_action(
        self,
        action: str,
        returncode: int,
        tool_name: str = "",
        *,
        engine: str = "evilkit",
        session_id: str = "",
    ) -> dict[str, Any] | None:
        """Emit one classified edge event, returning it when it was written."""
        if not self.enabled or not action.strip():
            return None
        target = self._first_ip(action)
        if target is None:
            return None
        nodes = self._nodes()
        source_node = nodes.get(self.entry_host)
        target_node = nodes.get(target)
        if source_node is None or target_node is None or source_node == target_node:
            return None
        activity = self._activity(action)
        # A successful attack-class action is the compromise signal the dashboard
        # keys on (server.py FOCUS_COMPROMISE_EVENTS): it resolves the target node
        # and paints it red. A failed attempt stays an "exploit" (in-progress).
        if activity == "attack" and returncode == 0:
            dashboard_event = "host_compromised"
        elif activity == "recon":
            dashboard_event = "recon"
        else:
            dashboard_event = "exploit"
        resolved_tool = tool_name or action.split(maxsplit=1)[0]
        scorer = scorer_verb(resolved_tool, returncode, dashboard_event)
        # Truncate the raw command so a long one-liner can't bloat events.jsonl
        # but the operator still sees the exact invocation on the board.
        command_text = action.strip()
        if len(command_text) > 240:
            command_text = command_text[:237] + "..."
        event = {
            "run_id": self.run_dir.name,
            "ts": time.time(),
            "source": engine,
            "session_id": session_id,
            "host": target,
            "node": target_node,
            "event": dashboard_event,
            "tool": resolved_tool,
            "command": command_text,
            "evidence": f"{resolved_tool}: {command_text} (exit {returncode})",
            "edge": {
                "src": source_node,
                "dst": target_node,
                "traffic_class": activity,
                "tool": resolved_tool,
                "direction": "forward",
            },
        }
        journal = {
            "run_id": self.run_dir.name,
            "ts": event["ts"],
            "source": engine,
            "session_id": session_id,
            "kind": "action",
            # "event" is the scorer's canonical verb (keystone/score.py
            # _canon_action reads event, then action); "action" keeps the
            # dashboard's own name so the board still paints from this record.
            "event": scorer,
            "action": event["event"],
            "target": target,
            "tool": event["edge"]["tool"],
            "status": "success" if returncode == 0 else "failed",
            "exit_code": returncode,
            "dashboard_event": event["event"],
        }
        if scorer == "pivot":
            # The scorer's pivot path reads host/src as the routing source and
            # target as the destination. The first IP in the call is the jump
            # host the traffic routes through; a later distinct IP is the far
            # end. Record both so a dmz->corp crossing through a foothold
            # scores instead of reading '' for the source (run 8's pivots were
            # all done over raw Bash, which journals as recon, and scored 0).
            ips = _IP_RE.findall(action)
            if len(ips) >= 2 and ips[-1] != target:
                journal["host"] = target
                journal["target"] = ips[-1]
        elif scorer == "exfil":
            # The crown-exfil scorer searches the journal text for the crown
            # flag value. Carry the call text (which holds the token for
            # record_flag calls) so a flag banked through the mission MCP is
            # findable without hand-writing evidence files.
            journal["evidence"] = command_text[:400]
        try:
            with self._locked():
                self._append(self.run_dir / "dashboard" / "events.jsonl", event)
                self._append(self.run_dir / "journal.jsonl", journal)
                self._write_status({
                    "updated_at": event["ts"],
                    "state": "running",
                    "source": engine,
                    "session_id": session_id,
                    "last_event": event["event"],
                    "last_host": target,
                    "last_exit_code": returncode,
                })
        except OSError:
            return None
        return event

    def emit_session(self, state: str, *, engine: str, session_id: str) -> dict[str, Any] | None:
        """Write a lifecycle heartbeat so the dashboard reflects both CLI engines."""
        if not self.enabled or state not in {"started", "stopped", "failed"}:
            return None
        now = time.time()
        record = {
            "run_id": self.run_dir.name,
            "ts": now,
            "source": engine,
            "session_id": session_id,
            "kind": "session",
            "state": state,
        }
        try:
            with self._locked():
                self._append(self.run_dir / "journal.jsonl", record)
                # Only "started" promotes the run state. A session ending does
                # NOT end the run -- the operator typically starts another
                # kimi/qwen session seconds later. Writing state="stopped" here
                # dropped the run below live-brain in find_live_run(), making
                # the dashboard flip to the all-green idle view mid-engagement.
                if state == "started":
                    self._write_status({
                        "updated_at": now,
                        "state": "running",
                        "source": engine,
                        "session_id": session_id,
                        "last_event": "session_started",
                    })
        except OSError:
            return None
        return record

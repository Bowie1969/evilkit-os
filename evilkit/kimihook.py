"""The evilkit harness, driven by the Kimi Code CLI's hook events.

Kimi runs a hook as a child process, hands it the event as JSON on stdin, and
reads a JSON object back on stdout. The fields the CLI parses — confirmed by
searching the installed binary — are ``hookSpecificOutput``,
``permissionDecision``, ``permissionDecisionReason``, ``continue``,
``stopReason`` and ``systemMessage``, alongside the event's own
``hookEventName``, ``toolName``, ``toolInput``, ``toolResponse``, ``sessionID``
and ``cwd``.

Two capabilities are certain because the CLI acts on them directly:

* **deny** a tool call in ``PreToolUse`` (``permissionDecision``)
* **record** every call: evidence journal, budget ledger, dashboard telemetry

Whether a hook can push text *into* the model's context is **not** established —
``additionalContext`` does not appear in the binary. Until ``--probe`` proves a
channel, harness nudges are journalled and reported rather than injected.

State is a per-session JSONL log of tool events; the harness objects are rebuilt
by replaying that log on each invocation. Replay is deterministic, so the ledger
never drifts from what actually happened, and no half-serialised ``HarnessState``
is ever written to disk.

Environment (all inherited from the launching process, since Kimi runs the hook):

* ``EVILKIMI_STATE_DIR``        — where the session logs, evidence and reports live
* ``EVILKIT_DASHBOARD_RUN_DIR`` — the prepared dashboard run to emit into; when
  unset there is **no** telemetry at all (never the live-brain run, which the
  brain watcher owns)
* ``EVILKIT_ENTRY_HOST``        — the operator's origin node (default 10.99.50.60)
* ``EVILKIMI_HOOK_ENFORCE``     — ``0`` turns denials into journal-only warnings
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from .dashboard_telemetry import DashboardTelemetry
from .harness import EvidenceJournal, HarnessState, _extract_technique, action_signature

__all__ = ["main", "handle_event", "session_log_path", "state_root", "install_hooks"]

PROG = "evilkimi-hook"

STATE_ENV = "EVILKIMI_STATE_DIR"
RUN_DIR_ENV = "EVILKIT_DASHBOARD_RUN_DIR"
ENTRY_HOST_ENV = "EVILKIT_ENTRY_HOST"
ENGINE_ENV = "EVILKIT_ENGINE"
ENFORCE_ENV = "EVILKIMI_HOOK_ENFORCE"
FORCE_ENV = "EVILKIMI_HOOK_FORCE"

DEFAULT_ENTRY_HOST = "10.99.50.60"

#: Events the hook understands. Anything else is a silent no-op.
HANDLED_EVENTS = (
    "SessionStart",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "Stop",
    "StopFailure",
    "SessionEnd",
)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def state_root() -> Path:
    override = os.environ.get("EVILKIT_STATE_DIR") or os.environ.get(STATE_ENV)
    if override:
        return Path(os.path.expanduser(override))
    return Path.home() / ".local" / "state" / "evilkimi"


def session_log_path(session_id: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", session_id or "unknown")[:120] or "unknown"
    return state_root() / "sessions" / f"{safe}.jsonl"


def _read_log(path: Path) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except ValueError:
            continue
    return records


def _append_log(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, default=str) + "\n")


def _event_field(event: dict, *names: str) -> Any:
    for name in names:
        if name in event:
            return event[name]
    return None


def command_text(event: dict) -> str:
    """A single string the harness's extractors can read IPs and techniques from."""
    tool = str(_event_field(event, "toolName", "tool_name") or "").strip()
    payload = _event_field(event, "toolInput", "tool_input")
    if isinstance(payload, dict):
        for key in ("command", "cmd", "url", "target", "targets", "host", "path", "pattern"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return f"{tool} {value}".strip()
        return f"{tool} {json.dumps(payload, default=str)}".strip()
    if payload:
        return f"{tool} {payload}".strip()
    return tool


def response_text(event: dict) -> tuple[str, int]:
    """Return ``(output, returncode)`` for a completed tool call.

    Kimi reports a successful call as ``PostToolUse`` and a failed one as
    ``PostToolUseFailure``; an explicit exit code in the response wins.
    """
    payload = _event_field(event, "toolResponse", "tool_response", "toolResult", "tool_result")
    if isinstance(payload, dict):
        for key in ("returncode", "returnCode", "exitCode", "exit_code", "code"):
            value = payload.get(key)
            if isinstance(value, int):
                return json.dumps(payload, default=str), value
        for key in ("output", "stdout", "content", "result", "text"):
            value = payload.get(key)
            if isinstance(value, str):
                default = 1 if event.get("hookEventName") == "PostToolUseFailure" else 0
                return value, default
    if isinstance(payload, str):
        default = 1 if event.get("hookEventName") == "PostToolUseFailure" else 0
        return payload, default
    name = _event_field(event, "hookEventName", "hook_event_name")
    return "", 1 if name == "PostToolUseFailure" else 0


def build_state(records: list[dict], *, evidence_dir: Path, replay: bool) -> HarnessState:
    """Rebuild the harness by replaying recorded actions."""
    journal_dir = (evidence_dir / "replay") if replay else evidence_dir
    state = HarnessState(evidence_journal=EvidenceJournal(evidence_dir=journal_dir))
    for index, record in enumerate(records, start=1):
        if record.get("kind") == "denied":
            # A refusal is state too: it is what lets the gate refuse the same call
            # a second time without waiting for a repetition counter to fill up.
            state.note_refusal(str(record.get("command") or ""))
            continue
        state.record_action(
            index,
            str(record.get("command") or ""),
            str(record.get("output") or ""),
            str(record.get("stderr") or ""),
            int(record.get("returncode") or 0),
        )
    return state


def _enforcing() -> bool:
    return os.environ.get(ENFORCE_ENV, "1").strip().lower() not in ("0", "false", "no", "off")


def harness_active() -> bool:
    """Whether this session is one evilkimi launched.

    The hook is installed globally in Kimi's config, so it fires for *every*
    session on the machine — including ordinary coding sessions that have no
    business being budget-policed. ``evilkimi`` exports ``EVILKIMI_SCOPE`` at
    launch, which is the opt-in: without it the hook drains its input and does
    nothing. ``EVILKIMI_HOOK_FORCE=1`` overrides for tests and manual probes.
    """
    if os.environ.get(FORCE_ENV, "").strip() == "1":
        return True
    return bool(
        os.environ.get("EVILKIMI_SCOPE", "").strip()
        or os.environ.get("EVILQWEN_SCOPE", "").strip()
    )


def _deny(reason: str, event: dict) -> dict:
    name = _event_field(event, "hookEventName", "hook_event_name")
    return {
        "decision": "deny",
        "reason": reason,
        "hookSpecificOutput": {
            "hookEventName": name or "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }


def _warn_out(tool: str, command: str, reason: str) -> None:
    print(f"{PROG}: {reason} [{tool}] {command}", file=sys.stderr)


def handle_event(event: dict) -> dict:
    """Process one hook event and return the JSON object to print (possibly {}).

    Never raises: an internal failure must not block a tool call, so the caller
    turns any exception into an empty response (allow).
    """
    raw_name = str(_event_field(event, "hookEventName", "hook_event_name") or "")
    name = {
        "BeforeTool": "PreToolUse",
        "AfterTool": "PostToolUse",
        "AfterAgent": "Stop",
    }.get(raw_name, raw_name)
    session_id = str(_event_field(event, "sessionID", "session_id") or "unknown")
    engine = os.environ.get(ENGINE_ENV, "kimi" if os.environ.get("EVILKIMI_SCOPE") else "qwen")
    log_path = session_log_path(session_id)
    evidence_dir = state_root() / "evidence" / session_id

    if name == "SessionStart":
        run_dir = os.environ.get(RUN_DIR_ENV) or ""
        _append_log(
            log_path,
            {
                "kind": "session_start",
                "ts": time.time(),
                "cwd": str(_event_field(event, "cwd") or ""),
                "scope": os.environ.get("EVILKIMI_SCOPE") or os.environ.get("EVILQWEN_SCOPE", ""),
                "engine": engine,
                # The one place a session is tied to the run it feeds, so a
                # post-run check can compare the two records instead of trusting
                # that they line up.
                "run_id": Path(run_dir).name if run_dir else "",
                "dashboard_run_dir": run_dir,
            },
        )
        DashboardTelemetry(
            run_dir=os.environ.get(RUN_DIR_ENV),
            entry_host=os.environ.get(ENTRY_HOST_ENV, DEFAULT_ENTRY_HOST),
        ).emit_session("started", engine=engine, session_id=session_id)
        return {}

    if name in ("Stop", "StopFailure", "SessionEnd"):
        records = [r for r in _read_log(log_path) if r.get("kind") == "action"]
        state = build_state(records, evidence_dir=evidence_dir, replay=True)
        summary = {
            "kind": "session_stop",
            "ts": time.time(),
            "event": name,
            "actions": len(records),
            "warnings": sum(1 for r in records if r.get("warnings")),
            "ledger": state.ledger.to_dict(),
            "engine": engine,
        }
        try:
            from . import learning

            learned = learning.learn_from_records(records, session_id)
            summary["learning"] = {
                "fingerprint": learned.fingerprint,
                "added": learned.added,
                "skipped": learned.skipped,
            }
        except Exception as exc:  # self-training must never break session shutdown
            summary["learning_error"] = str(exc)
        _append_log(log_path, summary)
        report_path = state_root() / "reports" / f"{log_path.stem}.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
        DashboardTelemetry(
            run_dir=os.environ.get(RUN_DIR_ENV),
            entry_host=os.environ.get(ENTRY_HOST_ENV, DEFAULT_ENTRY_HOST),
        ).emit_session(
            "failed" if name == "StopFailure" else "stopped",
            engine=engine,
            session_id=session_id,
        )
        return {}

    if name not in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
        return {}

    tool = str(_event_field(event, "toolName", "tool_name") or "")
    command = command_text(event)
    all_records = _read_log(log_path)
    actions = [r for r in all_records if r.get("kind") == "action"]
    # The phase gate and the refusal memory need the denials too, not just the
    # calls that ran: a refusal is what stops the same call being re-issued.
    records = [r for r in all_records if r.get("kind") in ("action", "denied")]

    if name == "PreToolUse":
        state = build_state(records, evidence_dir=evidence_dir, replay=True)
        host_match = _IP_RE.search(command)
        host = host_match.group(0) if host_match else ""
        technique = _extract_technique(command)

        guards: list[dict[str, str]] = []
        repeated = state.loop_detector.block_repeated_action(command)
        if repeated:
            guards.append({"kind": "repetition", "message": repeated})
        if state.was_refused(command):
            guards.append({"kind": "refusal", "message": (
                "REPEAT REFUSAL: this exact call has already been refused in this session. "
                "A refusal is a gate result, not a transient error — change the call or the plan."
            )})
        # Local import: only the PreToolUse path needs a credential key, and this
        # keeps the module's import surface unchanged.
        from .harness import _extract_credential

        breaker = state.circuit_breaker.check(
            host=host, technique=technique, credential=_extract_credential(command)
        )
        if breaker:
            # The breaker reports four conditions in the same prose. Two are locks
            # and stop the call: a credential or vector the harness has already
            # locked — the fail2ban case this guard exists to prevent. The other
            # two are spent budgets ("... exhausted"), which are advisory: telling
            # the operator to replan is not the same as stopping them dead.
            kind = "advisory" if "exhausted" in breaker else "lock"
            guards.append({"kind": kind, "message": breaker})

        phase = state.phase_gate.check(command)
        if phase:
            guards.append({"kind": "phase", "message": phase})

        blocking = [guard for guard in guards if guard["kind"] != "advisory"]

        # Log every decision, not just the blocks: without this, "the hook never
        # fired" and "the hook fired and allowed it" are indistinguishable from
        # the log alone.
        _append_log(
            log_path,
            {
                "kind": "pre",
                "ts": time.time(),
                "tool": tool,
                "command": command,
                "prior_actions": len(actions),
                "guards": guards,
                "decision": (
                    "deny" if blocking and _enforcing()
                    else ("warn" if guards else "allow")
                ),
            },
        )

        if guards:
            reason = " ".join(guard["message"] for guard in guards)
            if blocking and _enforcing():
                _append_log(
                    log_path,
                    {"kind": "denied", "ts": time.time(), "tool": tool, "command": command,
                     "reason": reason},
                )
                _warn_out(tool, command, f"DENIED — {reason}")
                return _deny(
                    reason
                    + " Do not re-issue this call unchanged; replan with a different "
                    "technique, credential or host.",
                    event,
                )
            _append_log(
                log_path,
                {"kind": "warn", "ts": time.time(), "tool": tool, "command": command,
                 "reason": reason},
            )
            _warn_out(tool, command, f"WARN — {reason}")
        return {}

    # A denied call still produces a PostToolUse event carrying the denial. It was
    # never executed, so it must not count against the action budget or the ledger.
    # This has to look at every record, not just the executed actions: the denial
    # itself is deliberately not one of them.
    denied_index = None
    for index, record in enumerate(all_records):
        if record.get("kind") == "denied" and record.get("command") == command:
            denied_index = index
    if denied_index is not None and not any(
        record.get("kind") == "action" for record in all_records[denied_index + 1 :]
    ):
        _append_log(
            log_path,
            {
                "kind": "denied_result",
                "ts": time.time(),
                "tool": tool,
                "command": command,
                "reason": all_records[denied_index].get("reason"),
            },
        )
        return {}

    output, returncode = response_text(event)
    state = build_state(records, evidence_dir=evidence_dir, replay=True)
    state.evidence_journal = EvidenceJournal(evidence_dir=evidence_dir)
    warnings = state.record_action(len(records) + 1, command, output, "", returncode)
    record = {
        "kind": "action",
        "ts": time.time(),
        "tool": tool,
        "command": command,
        "output": output[:20000],
        "returncode": returncode,
        "warnings": warnings,
    }

    run_dir = os.environ.get(RUN_DIR_ENV)
    if run_dir:
        telemetry = DashboardTelemetry(
            run_dir=run_dir,
            entry_host=os.environ.get(ENTRY_HOST_ENV, DEFAULT_ENTRY_HOST),
        )
        event_json = telemetry.emit_action(
            command,
            returncode,
            tool_name=tool,
            engine=engine,
            session_id=session_id,
        )
        if event_json:
            record["dashboard_event"] = event_json.get("event")

    _append_log(log_path, record)

    for warning in warnings:
        _warn_out(tool, command, warning)

    response: dict | str = {}
    # Injection is opt-in. The channel matters: the docs give exit-0 **stdout text**
    # as the thing the CLI may append to context, while a JSON object on stdout is
    # parsed as a control response. Emitting {"systemMessage": ...} was verified to
    # reach nothing, so a nudge is emitted as plain text.
    if warnings and os.environ.get("EVILKIMI_HOOK_INJECT", "0").strip() == "1":
        return "EvilKit harness: " + " | ".join(warnings)
    return response


# ---------------------------------------------------------------------------
# hook installation
# ---------------------------------------------------------------------------

HOOK_EVENTS = (
    "SessionStart",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "Stop",
    "StopFailure",
)

MARKER = "# evilkimi harness hooks (managed by `evilkimi install-hooks`)"


def hook_command(checkout: Path | None = None) -> str:
    """The command Kimi runs for each hook event (absolute, PATH-independent)."""
    root = checkout or Path(__file__).resolve().parent.parent
    return f"env PYTHONPATH={root} python3 -m evilkit.kimihook"


def install_hooks(config_path: Path, checkout: Path | None = None) -> tuple[bool, str]:
    """Append the evilkimi hook block to Kimi's config, preserving everything else.

    Text append rather than a TOML round-trip: existing entries keep their order,
    their comments and their formatting, and a file we cannot parse is never
    rewritten. Idempotent — a second run is a no-op.
    """
    try:
        original = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        return False, f"could not read {config_path}: {exc}"

    if hooks_installed(config_path):
        return False, f"already installed in {config_path} (no change)"

    command = hook_command(checkout)
    block = [MARKER]
    for event in HOOK_EVENTS:
        block.append("[[hooks]]")
        block.append(f'event = "{event}"')
        block.append(f'command = "{command}"')
        block.append("timeout = 10")
        block.append("")
    candidate = original.rstrip("\n") + "\n\n" + "\n".join(block).rstrip("\n") + "\n"

    # Validate before replacing anything: a hook block that breaks the config
    # would cost the operator their whole CLI.
    try:
        import tomllib

        tomllib.loads(candidate)
    except Exception as exc:  # noqa: BLE001 - any parse failure must abort the write
        return False, f"refusing to write: the result would not parse ({exc})"

    stamp = time.strftime("%Y%m%d-%H%M%S")
    try:
        config_path.with_suffix(config_path.suffix + f".evilkimi-{stamp}.bak").write_text(
            original, encoding="utf-8"
        )
        config_path.write_text(candidate, encoding="utf-8")
    except OSError as exc:
        return False, f"could not write {config_path}: {exc}"
    return True, f"installed {len(HOOK_EVENTS)} hooks in {config_path} (backup kept)"


def hooks_installed(config_path: Path | None = None) -> bool:
    path = config_path or (Path.home() / ".kimi-code" / "config.toml")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    if MARKER in text:
        return True
    try:
        import tomllib

        data = tomllib.loads(text)
    except Exception:  # noqa: BLE001
        return False
    hooks = data.get("hooks", [])
    if not isinstance(hooks, list):
        return False
    seen = {
        str(entry.get("event"))
        for entry in hooks
        if isinstance(entry, dict) and "evilkit.kimihook" in str(entry.get("command", ""))
    }
    return all(event in seen for event in HOOK_EVENTS)


# ---------------------------------------------------------------------------
# reporting and probing
# ---------------------------------------------------------------------------

def report(session: str | None = None) -> int:
    sessions_dir = state_root() / "sessions"
    if session:
        paths = [session_log_path(session)]
    else:
        paths = sorted(sessions_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime)
        paths = paths[-5:]
    if not paths:
        print(f"{PROG}: no session logs under {sessions_dir}")
        return 0
    for path in paths:
        records = _read_log(path)
        actions = [r for r in records if r.get("kind") == "action"]
        denied = [r for r in records if r.get("kind") == "denied"]
        scopes = {r.get("scope") for r in records if r.get("kind") == "session_start"}
        state = build_state([r for r in actions], evidence_dir=state_root() / "evidence" / path.stem,
                            replay=True)
        print(f"--- {path.stem} ---")
        print(f"actions recorded : {len(actions)}")
        print(f"tool calls denied: {len(denied)}")
        print(f"scope at start   : {', '.join(s for s in scopes if s) or 'unknown'}")
        print(f"ledger           : {json.dumps(state.ledger.to_dict(), default=str)}")
        print(f"budget           : {state.budget.summary()}")
        if denied:
            print("denials:")
            for record in denied[-10:]:
                print(f"  - {record.get('tool')}: {record.get('reason')}")
    return 0


PROBE_SHAPES = {
    "PreToolUse": {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "<why the harness blocked it>",
        },
        "permissionDecision": "deny",
        "permissionDecisionReason": "<why the harness blocked it>",
    },
    "PostToolUse": "EvilKit harness: <plain stdout text, exit 0 — the context-append channel>",
    "Stop": {},
}


def probe() -> int:
    print(f"{PROG}: hook event contract probe")
    print(f"checkout    : {Path(__file__).resolve().parent.parent}")
    print(f"state dir   : {state_root()}")
    print(f"run dir     : {os.environ.get(RUN_DIR_ENV) or '(unset — telemetry disabled)'}")
    print(f"enforcing   : {'yes' if _enforcing() else 'no (journal only)'}")
    print(f"hooks wired : {'yes' if hooks_installed() else 'no'}")
    print(
        "this session: "
        + ("harness active (EVILKIMI_SCOPE set)" if harness_active()
           else "standing down — not an evilkimi launch (EVILKIMI_SCOPE unset)")
    )
    print()
    print("Shapes this hook can emit:")
    print(json.dumps(PROBE_SHAPES, indent=2))
    print()
    print("Ways this hook can speak to the session (per the Kimi Code hook docs):")
    print("  * deny a call       : JSON with permissionDecision on stdout, exit 0 — proven")
    print("  * append to context : plain stdout text on exit 0, opt in with")
    print("                        EVILKIMI_HOOK_INJECT=1. A JSON object on stdout is")
    print("                        parsed as a control response and is NOT appended: a")
    print("                        {\"systemMessage\": ...} nudge reached nothing when tested.")
    print("  * hold the turn open: exit code 2 with the reason on stderr (Stop is blockable)")
    return 0


def _cli(argv: list[str]) -> int:
    args = list(argv)
    if not args:
        return 0
    if args[0] == "--report":
        return report(args[1] if len(args) > 1 else None)
    if args[0] == "--probe":
        return probe()
    if args[0] == "--install-hooks":
        changed, message = install_hooks(Path.home() / ".kimi-code" / "config.toml")
        print(f"{PROG}: {message}")
        return 0 if changed or "already" in message else 1
    if args[0] in ("-h", "--help"):
        print(f"usage: {PROG} [--probe | --report [SESSION] | --install-hooks]")
        print("       (no arguments: read one hook event as JSON on stdin)")
        return 0
    print(f"{PROG}: unknown argument {args[0]!r}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        return _cli(args)

    if not harness_active():
        # Not an evilkimi session: drain the event so the CLI's writer never sees
        # a broken pipe, then stand down.
        try:
            sys.stdin.read()
        except Exception:  # noqa: BLE001 - a hook must never crash the session
            pass
        return 0

    try:
        raw = sys.stdin.read()
    except Exception:  # noqa: BLE001 - a hook must never crash the session
        return 0
    if not raw.strip():
        return 0
    try:
        event = json.loads(raw)
    except ValueError:
        return 0
    if not isinstance(event, dict):
        return 0

    try:
        response = handle_event(event)
    except Exception as exc:  # noqa: BLE001 - fail open, never block a tool call
        print(f"{PROG}: harness error, allowing the call ({exc})", file=sys.stderr)
        return 0
    if isinstance(response, str):
        # Plain stdout text with exit 0 — the documented channel for appending to
        # the model's context.
        sys.stdout.write(response + "\n")
    elif response:
        sys.stdout.write(json.dumps(response) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

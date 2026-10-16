"""Display the live terminal of a deployed EvilKit clone on this box.

The remote half of EvilKit (a Pi, a laptop, any enrolled worker) runs its own
terminal: a systemd unit that polls the hub, claims tasks and drives a local
Kimi. This module watches the **attack segment only** for that host, verifies
it over SSH, and pops up a desktop terminal window showing the clone's live
terminal (``journalctl -f`` of its worker unit) — so the operator sees the
remote session the moment the clone is plugged in, and again when the hub
decides to deploy a task to it.

Hard rules, enforced here rather than by convention:

* an address is displayable only when it sits inside a configured **attack
  segment** and outside every denied network — the estate, the house LAN, the
  WireGuard subnet and the hypervisor bridges are never displayed;
* a host is only trusted after SSH proves its identity (the configured
  hostname), so an unrelated box that answers on the segment is ignored;
* nothing is ever launched for a host that fails either check.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Iterable

from .terminal_window import ClonePopupManager, raise_terminal_window, spawn_terminal_window

__all__ = [
    "CloneTarget",
    "DisplayConfig",
    "SegmentError",
    "ProbeResult",
    "DeploymentWatcher",
    "attack_segment_of",
    "parse_networks",
    "probe_clone",
    "remote_terminal_argv",
    "display_log_path",
]

#: Networks that are NEVER displayable, whatever the configured segments say.
#: Belt and braces: the guard fails closed even if a segment is misconfigured.
ALWAYS_DENIED = (
    "192.168.0.0/24",   # house LAN
    "10.10.0.0/24",     # hEX management
    "10.9.0.0/24",      # WireGuard hub
    "100.64.0.0/10",    # Tailscale CGNAT
    "127.0.0.0/8",      # loopback
)


class SegmentError(Exception):
    """An address may not be displayed, or the segment configuration is unusable."""


def parse_networks(values: Iterable[str]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse a list of CIDR strings, raising :class:`SegmentError` on any bad value."""
    parsed = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        try:
            parsed.append(ipaddress.ip_network(text, strict=False))
        except ValueError as exc:
            raise SegmentError(f"not a valid network: {text!r} ({exc})") from exc
    return tuple(parsed)


def _in_network(address: ipaddress._BaseAddress, networks) -> bool:
    return any(address.version == net.version and address in net for net in networks)


def attack_segment_of(
    address: str,
    segments: Iterable[str],
    deny: Iterable[str] = (),
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Return the attack segment containing ``address``.

    Raises :class:`SegmentError` when the address is denied, is not a literal
    address, or falls outside every configured attack segment. Fail closed: an
    empty segment list means nothing is displayable.
    """
    try:
        parsed = ipaddress.ip_address(str(address).strip())
    except ValueError as exc:
        raise SegmentError(f"not a literal address: {address!r}") from exc

    denied = parse_networks((*ALWAYS_DENIED, *tuple(deny)))
    if _in_network(parsed, denied):
        raise SegmentError(f"{parsed} is in a denied network; refusing to display it")

    segment_list = parse_networks(segments)
    if not segment_list:
        raise SegmentError("no attack segment is configured; refusing to display anything")
    for segment in segment_list:
        if parsed.version == segment.version and parsed in segment:
            return segment
    raise SegmentError(
        f"{parsed} is outside every attack segment ({', '.join(str(s) for s in segment_list)})"
    )


@dataclass(frozen=True)
class CloneTarget:
    """One remote EvilKit clone we are allowed to display."""

    name: str
    host: str
    user: str = "pi"
    identity: str = "~/.ssh/id_ed25519_evilkimi_pi"
    unit: str = "evilk-mesh-worker-pi.service"

    def ssh_argv(self, *remote_command: str) -> list[str]:
        """SSH argv with the destination first and the remote command last."""
        return [
            "ssh",
            "-t",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=6",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=4",
            "-i", os.path.expanduser(self.identity),
            f"{self.user}@{self.host}",
            *remote_command,
        ]

    def probe_argv(self) -> list[str]:
        """Non-interactive identity check: asks the host its own hostname."""
        return [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=6",
            "-o", "StrictHostKeyChecking=accept-new",
            "-i", os.path.expanduser(self.identity),
            f"{self.user}@{self.host}",
            "hostname",
        ]


@dataclass
class DisplayConfig:
    """Settings for the clone display, with the attack segment as the only gate."""

    enabled: bool = True
    segments: tuple[str, ...] = ("10.10.66.0/24",)
    deny: tuple[str, ...] = ()
    targets: tuple[CloneTarget, ...] = ()
    poll_interval: float = 5.0
    terminal: str = ""
    #: Where detection and deployment events are journalled.
    log: str = ""

    def resolved_log(self) -> Path:
        override = self.log.strip()
        if override:
            return Path(os.path.expanduser(override))
        state = os.environ.get("XDG_STATE_HOME")
        root = Path(state) if state else Path.home() / ".local" / "state"
        return root / "evilkit" / "clone-display.jsonl"


@dataclass
class ProbeResult:
    target: CloneTarget
    reachable: bool
    verified: bool
    segment: str | None
    detail: str


def _tcp_open(host: str, port: int = 22, timeout: float = 4.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_clone(target: CloneTarget, segments, deny=(), *, timeout: float = 12.0) -> ProbeResult:
    """Check one candidate: attack-segment guard, then TCP, then SSH identity."""
    try:
        segment = attack_segment_of(target.host, segments, deny)
    except SegmentError as exc:
        return ProbeResult(target, False, False, None, str(exc))

    if not _tcp_open(target.host):
        return ProbeResult(target, False, False, str(segment), "no ssh service on port 22")

    if not shutil.which("ssh"):
        return ProbeResult(target, True, False, str(segment), "ssh client is missing on this box")

    try:
        result = subprocess.run(
            target.probe_argv(), capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return ProbeResult(target, True, False, str(segment), "ssh identity check timed out")
    except OSError as exc:
        return ProbeResult(target, True, False, str(segment), f"ssh failed: {exc}")

    reported = (result.stdout or "").strip().splitlines()
    hostname = reported[0].strip() if reported else ""
    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()
        return ProbeResult(target, True, False, str(segment), f"ssh refused ({detail[0] if detail else result.returncode})")
    if hostname != target.name:
        return ProbeResult(
            target, True, False, str(segment),
            f"answered as {hostname!r}, expected {target.name!r} — not this clone",
        )
    return ProbeResult(target, True, True, str(segment), hostname)


def remote_terminal_argv(target: CloneTarget, *, lines: int = 40) -> list[str]:
    """The argv that shows the clone's live terminal: its worker unit journal."""
    remote = (
        f"journalctl -u {shlex.quote(target.unit)} -n {int(lines)} -f --output=short-iso"
    )
    return target.ssh_argv(remote)


def terminal_loop(
    clone_name: str,
    *,
    detected: float | None = None,
    deployed: float | None = None,
    reconnect: float = 5.0,
    max_attempts: int | None = None,
) -> int:
    """Run the window's remote stream, reconnecting whenever it drops.

    This is what the popped-up terminal actually runs. The unit journal is a
    stream over SSH, and a stream that ends must not leave the operator looking
    at a dead window: each exit is printed and journalled with its code, then the
    stream is re-established. That is also what makes the window survive a clone
    reboot or a brief network drop without a second window being opened.
    """
    config = _load_display_config()
    target = next((t for t in config.targets if t.name == clone_name), None)
    if target is None:
        print(f"EvilKit: {clone_name!r} is not a configured clone_display target")
        return 1
    try:
        segment = str(attack_segment_of(target.host, config.segments, config.deny))
    except SegmentError as exc:
        print(f"EvilKit: refusing to display {clone_name}: {exc}")
        return 1

    def _say(line: str = "") -> None:
        print(line, flush=True)

    _say(f"EvilKit clone terminal: {target.name}")
    _say(f"  host    : {target.host} ({target.user})")
    _say(f"  segment : {segment} (attack segment only)")
    _say(f"  unit    : {target.unit}")
    if detected is not None:
        _say(f"  seen    : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(detected))}")
    if deployed is not None:
        _say(f"  deploy  : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(deployed))}")
    _say("  --- live terminal ---")

    attempts = 0
    while True:
        attempts += 1
        try:
            code = subprocess.call(remote_terminal_argv(target))
        except OSError as exc:
            code = None
            _say(f"ssh could not be started: {exc}")
        record = {"kind": "terminal_stream_ended", "ts": time.time(), "clone": target.name,
                  "host": target.host, "exit": code, "attempt": attempts}
        _journal(config, record)
        if max_attempts is not None and attempts >= max_attempts:
            return 0
        _say("")
        _say(f"--- stream ended (exit {code}); reconnecting in {reconnect:g}s, Ctrl-C to stop ---")
        try:
            time.sleep(max(1.0, reconnect))
        except KeyboardInterrupt:
            return 0


def _load_display_config() -> DisplayConfig:
    """Load just the display settings (imported late to avoid a config cycle)."""
    from . import config as config_mod

    config, _ = config_mod.load()
    return config.clone_display


def _journal(config: DisplayConfig, record: dict) -> None:
    path = config.resolved_log()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")
    except OSError:
        pass


def window_registry_path() -> Path:
    state = os.environ.get("XDG_STATE_HOME")
    root = Path(state) if state else Path.home() / ".local" / "state"
    return root / "evilkit" / "clone-display-windows.json"


def _read_registry() -> dict:
    try:
        data = json.loads(window_registry_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(int(pid), 0)
    except (OSError, ValueError):
        return False
    return True


def registered_window(name: str) -> int | None:
    """The pid of a live display window for ``name`` opened by any process."""
    entry = _read_registry().get(name)
    if not isinstance(entry, dict):
        return None
    pid = entry.get("pid")
    if isinstance(pid, int) and _pid_alive(pid):
        return pid
    return None


def register_window(name: str, pid: int, host: str) -> None:
    """Record an open window so a second watcher does not open a duplicate."""
    path = window_registry_path()
    data = {key: value for key, value in _read_registry().items()
            if isinstance(value, dict) and isinstance(value.get("pid"), int) and _pid_alive(value["pid"])}
    data[name] = {"pid": pid, "host": host, "opened": time.time()}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


def unregister_window(name: str) -> None:
    """Forget a window this process owned."""
    data = _read_registry()
    if name not in data:
        return
    del data[name]
    path = window_registry_path()
    try:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


class DeploymentWatcher:
    """Detect a clone on the attack segment and display its terminal window."""

    def __init__(
        self,
        config: DisplayConfig,
        *,
        targets: Iterable[CloneTarget] | None = None,
        hub: str | None = None,
        token_file: Path | None = None,
        once: bool = False,
        on_event: Callable[[str, dict], None] | None = None,
        probe: Callable[[CloneTarget], ProbeResult] | None = None,
        spawn: Callable[..., subprocess.Popen | None] | None = None,
        state_provider: Callable[[], dict] | None = None,
    ):
        self.config = config
        self.targets = list(targets if targets is not None else config.targets)
        self.hub = hub.rstrip("/") if hub else None
        self.token_file = token_file
        self.once = once
        self.on_event = on_event
        self.state_provider = state_provider
        self._probe = probe or (lambda target: probe_clone(target, config.segments, config.deny))
        self._spawn = spawn or spawn_terminal_window
        self._windows: dict[str, subprocess.Popen] = {}
        self._first_seen: dict[str, float] = {}
        self._deployed: dict[str, float] = {}
        self._seen_tasks: set[str] = set()

    # -- events ---------------------------------------------------------

    def _emit(self, kind: str, **fields) -> dict:
        record = {"kind": kind, "ts": time.time(), **fields}
        path = self.config.resolved_log()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, default=str) + "\n")
        except OSError:
            pass
        if self.on_event is not None:
            self.on_event(kind, record)
        return record

    # -- display --------------------------------------------------------

    def window_open(self, name: str) -> bool:
        proc = self._windows.get(name)
        if proc is not None and proc.poll() is None:
            return True
        # Another process (a hub, or a second display watcher) may already own it.
        return registered_window(name) is not None

    def raise_window(self, name: str) -> bool:
        """Surface an existing clone terminal when a new deployment arrives."""
        proc = self._windows.get(name)
        pid = proc.pid if proc is not None and proc.poll() is None else registered_window(name)
        return raise_terminal_window(pid) if pid is not None else False

    def display(self, target: CloneTarget, segment: str, *, deployed: float | None = None) -> subprocess.Popen | None:
        """Ensure a terminal window showing ``target``'s live terminal is open."""
        if not self.config.enabled:
            return None
        if self.window_open(target.name):
            return self._windows[target.name]
        try:
            spawn = self._spawn
            command = [sys.executable, "-m", "evilkit.clone_display", "terminal", target.name]
            detected = self._first_seen.get(target.name, time.time())
            command.extend(["--detected", f"{detected:.3f}"])
            deploy_ts = deployed if deployed is not None else self._deployed.get(target.name)
            if deploy_ts is not None:
                command.extend(["--deployed", f"{deploy_ts:.3f}"])
            if spawn is spawn_terminal_window:
                proc = spawn(
                    command,
                    title=f"EvilKit Clone: {target.name} ({target.host})",
                    hold=True,
                    emulator=self.config.terminal or None,
                )
            else:
                proc = spawn(
                    command,
                    title=f"EvilKit Clone: {target.name} ({target.host})",
                    hold=True,
                )
        except Exception as exc:  # a display failure must never stop the watcher
            self._emit("display_error", clone=target.name, host=target.host, error=str(exc))
            return None
        if proc is None:
            self._emit("display_unavailable", clone=target.name, host=target.host)
            return None
        self._windows[target.name] = proc
        register_window(target.name, proc.pid, target.host)
        return proc

    # -- hub: where and when evilkit deploys -----------------------------

    def _hub_state(self) -> dict | None:
        if self.state_provider is not None:
            try:
                return self.state_provider()
            except Exception:  # noqa: BLE001 - a hub hiccup must not stop the display
                return None
        if not self.hub or self.token_file is None:
            return None
        from .mesh import MeshError, _request, _token

        try:
            token = _token(self.token_file)
            return _request(self.hub, token, "/state")
        except (MeshError, OSError):
            return None

    def deployments(self, state: dict) -> list[dict]:
        """Tasks the hub has assigned to a displayed clone since the last tick."""
        if not state:
            return []
        known = {target.name for target in self.targets}
        fresh = []
        for task in state.get("tasks", []) or []:
            if not isinstance(task, dict):
                continue
            if task.get("worker") not in known:
                continue
            if task.get("status") not in ("queued", "running"):
                continue
            key = str(task.get("id"))
            if key in self._seen_tasks:
                continue
            self._seen_tasks.add(key)
            fresh.append(task)
        return fresh

    # -- loop -----------------------------------------------------------

    def tick(self) -> list[dict]:
        """One detection + deployment pass; returns the events it produced."""
        events: list[dict] = []
        found: dict[str, ProbeResult] = {}

        for target in self.targets:
            result = self._probe(target)
            if not result.verified:
                if result.reachable and not self.window_open(target.name):
                    events.append(self._emit(
                        "clone_refused", clone=target.name, host=target.host, detail=result.detail
                    ))
                continue
            found[target.name] = result
            if target.name not in self._first_seen:
                self._first_seen[target.name] = time.time()
                events.append(self._emit(
                    "clone_on_segment",
                    clone=target.name,
                    host=target.host,
                    segment=result.segment,
                    detail=result.detail,
                ))
            if not self.window_open(target.name):
                proc = self.display(target, result.segment or "")
                if proc is not None:
                    events.append(self._emit(
                        "display_opened",
                        clone=target.name,
                        host=target.host,
                        segment=result.segment,
                        pid=proc.pid,
                    ))

        state = self._hub_state()
        for task in self.deployments(state):
            name = str(task.get("worker"))
            target = next((t for t in self.targets if t.name == name), None)
            if target is None:
                continue
            now = time.time()
            self._deployed.setdefault(name, now)
            events.append(self._emit(
                "clone_deployed",
                clone=name,
                host=target.host,
                task=task.get("id"),
                status=task.get("status"),
                prompt=str(task.get("prompt", ""))[:400],
            ))
            result = found.get(name)
            if result is None:
                result = self._probe(target)
                found[name] = result
            if result.verified:
                if self.window_open(name):
                    if self.raise_window(name):
                        events.append(self._emit(
                            "display_raised",
                            clone=name,
                            host=target.host,
                            segment=result.segment,
                            reason="deploy",
                        ))
                else:
                    proc = self.display(target, result.segment or "", deployed=self._deployed[name])
                    if proc is not None:
                        events.append(self._emit(
                            "display_opened",
                            clone=name,
                            host=target.host,
                            segment=result.segment,
                            pid=proc.pid,
                            reason="deploy",
                        ))

        return events

    def run(self, *, max_ticks: int | None = None, sleep: Callable[[float], None] = time.sleep) -> int:
        ticks = 0
        while True:
            self.tick()
            ticks += 1
            if self.once or (max_ticks is not None and ticks >= max_ticks):
                return 0
            try:
                sleep(max(0.5, float(self.config.poll_interval)))
            except KeyboardInterrupt:
                return 0

    def close_all(self) -> None:
        for name, proc in self._windows.items():
            if proc.poll() is None:
                try:
                    proc.terminate()
                except OSError:
                    pass
            unregister_window(name)
        self._windows.clear()


def display_for_clone(
    name: str,
    config: DisplayConfig,
    *,
    hub: str | None = None,
    token_file: Path | None = None,
    state_provider: Callable[[], dict] | None = None,
    watcher: DeploymentWatcher | None = None,
) -> ProbeResult | None:
    """Hub-side hook: display ``name``'s terminal when it registers on the segment.

    Returns the probe result when the clone is a configured display target and
    passed the attack-segment and identity checks (whether or not a window was
    opened just now), and ``None`` when it is not ours to display.
    """
    target = next((t for t in config.targets if t.name == name), None)
    if target is None or not config.enabled:
        return None
    owner = watcher or DeploymentWatcher(
        config, targets=[target], hub=hub, token_file=token_file, state_provider=state_provider
    )
    # Reuse the watcher's injected probe. Besides making the hook deterministic
    # in tests, this keeps registration checks consistent with the long-running
    # watcher (which may supply a hardened or platform-specific verifier).
    result = owner._probe(target)
    if not result.verified:
        return None
    owner._first_seen.setdefault(name, time.time())
    if owner.window_open(name):
        if owner.raise_window(name):
            owner._emit(
                "display_raised",
                clone=name,
                host=target.host,
                segment=result.segment,
                reason="register",
            )
    else:
        proc = owner.display(target, result.segment or "")
        if proc is not None:
            owner._emit(
                "display_opened",
                clone=name,
                host=target.host,
                segment=result.segment,
                pid=proc.pid,
                reason="register",
            )
    return result


def main(argv: list[str] | None = None) -> int:
    """The popped-up window's own entry point: ``… terminal <clone>``."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="evilkit.clone_display",
        description="Show a clone's live terminal in this window (used by `evilkit mesh display`).",
    )
    sub = parser.add_subparsers(dest="action", required=True)
    terminal = sub.add_parser("terminal", help="stream a clone's terminal, reconnecting on drop")
    terminal.add_argument("clone")
    terminal.add_argument("--detected", type=float, default=None)
    terminal.add_argument("--deployed", type=float, default=None)
    terminal.add_argument("--reconnect", type=float, default=5.0)
    args = parser.parse_args(argv)
    return terminal_loop(
        args.clone, detected=args.detected, deployed=args.deployed, reconnect=args.reconnect
    )


if __name__ == "__main__":
    import sys as _sys

    _sys.exit(main())

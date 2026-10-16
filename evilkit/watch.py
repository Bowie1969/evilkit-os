"""A live pane that watches the scope a project will run under.

``evilkit run`` writes the scope and then hands over to the Kimi Code CLI. For
the whole session that follows, the value in ``.mcp.json`` *is* the boundary,
and nothing is watching it. Anything on the machine can edit that file — a
second launcher run in another terminal, a stray script, the agent's own file
tools — and the session would carry on under a scope nobody authorised, with
nothing on screen to say so.

``evilkit watch`` is that missing observer. It launches nothing and decides
nothing: it samples the recorded scope, reports it, and raises an alarm the
moment it changes under you. The alarm is the point — an engagement that quietly
widens is worse than one that fails.

No terminal library and no dependencies: a frame is a block of text that the
caller clears and rewrites, so the whole thing stays inspectable, pipeable and
testable by reading the string it returns.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import textwrap
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "ALARM",
    "NOTE",
    "Alert",
    "ScopeState",
    "compare",
    "format_launch",
    "render",
    "snapshot",
]

#: A change that means the session is no longer what was authorised.
ALARM = "alarm"
#: A change worth showing that does not by itself invalidate the scope.
NOTE = "note"

_RED = "\x1b[31m"
_BOLD = "\x1b[1m"
_RESET = "\x1b[0m"

#: Width used when nobody tells us how wide the terminal is.
DEFAULT_WIDTH = 78

RULE_CHAR = "\u2500"


def _safe(text: str) -> str:
    """Strip control characters from text that came from the watched file.

    The scope string is attacker-influenced: anything on the machine can write
    ``.mcp.json``. Rendered verbatim, an embedded escape sequence (``\\x1b``)
    could clear the pane or spoof an ``[ALERTS] scope verified`` line \u2014 turning
    the one thing meant to catch a silent widening into its cover. Control
    characters (C0, DEL and C1) are replaced with a visible placeholder so the
    raw text is still shown but can no longer drive the terminal.
    """
    return "".join(
        ch if ch == "\t" or (ch.isprintable() and not (0x80 <= ord(ch) <= 0x9F)) else "\ufffd"
        for ch in text
    )


@dataclass(frozen=True)
class ScopeState:
    """One sample of the recorded scope, and enough to tell it was resampled."""

    path: Path
    scope: str | None
    #: sha256 of the scope value, so a rewrite that changes nothing is not an alarm.
    digest: str | None
    #: Modification time, for "last changed N ago".
    mtime: float | None
    #: Why the scope could not be read, when that is the case.
    error: str | None = None


@dataclass
class Alert:
    """Something the pane noticed, timestamped when it noticed it."""

    at: str
    text: str
    level: str = NOTE


def snapshot(path: Path) -> ScopeState:
    """Sample ``path`` without raising: a broken file is a state, not a crash.

    A pane that exits because the file it was watching was deleted would be
    useless exactly when it matters, so every failure is carried in the state
    and rendered.
    """
    from . import mcpscope

    try:
        stat = path.stat()
    except OSError as exc:
        return ScopeState(path, None, None, None, error=f"unreadable ({exc})")

    try:
        scope = mcpscope.read_scope(path)
    except mcpscope.McpError as exc:
        return ScopeState(path, None, None, stat.st_mtime, error=str(exc))

    digest = None
    if scope is not None:
        digest = hashlib.sha256(scope.encode("utf-8")).hexdigest()
    return ScopeState(path, scope, digest, stat.st_mtime)


def _contains(outer, inner) -> bool:
    """Whether ``inner`` sits inside ``outer``, False for mismatched families."""
    try:
        return bool(inner.subnet_of(outer))
    except TypeError:
        return False


def _as_networks(value: str) -> list | None:
    """Parse a scope string as networks, or None if any entry is not one."""
    networks = []
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            if "/" in token:
                networks.append(ipaddress.ip_network(token, strict=False))
            else:
                address = ipaddress.ip_address(token)
                networks.append(ipaddress.ip_network(f"{address}/{address.max_prefixlen}"))
        except ValueError:
            return None
    return networks or None


def widened(before: str, after: str) -> bool:
    """True only when ``after`` provably authorises more than ``before``.

    Two conditions, both required: every target the old scope authorised is still
    authorised, and the new scope authorises something the old one did not. A
    scope that merely changed, or narrowed, is not a widening.

    Deliberately conservative: hostnames, mixed address families or anything
    unparseable answer False, and the pane then reports a plain change rather
    than claiming a direction it cannot prove.
    """
    old = _as_networks(before)
    new = _as_networks(after)
    if old is None or new is None:
        return False
    if not all(any(_contains(entry, held) for entry in new) for held in old):
        return False
    return not all(any(_contains(held, entry) for held in old) for entry in new)


def compare(previous: ScopeState, current: ScopeState) -> Alert | None:
    """Describe what changed between two samples, or None when nothing did."""
    at = _dt.datetime.now().strftime("%H:%M:%S")

    if current.error is not None and current.error != previous.error:
        return Alert(at, f"the scope in {current.path} can no longer be read: {current.error}", ALARM)

    if previous.scope is not None and current.scope is None and current.error is None:
        return Alert(
            at,
            f"the pentest server in {current.path} no longer declares a scope; "
            "a session started now would run under whatever the file previously held",
            ALARM,
        )

    if current.scope != previous.scope and current.scope is not None:
        if previous.scope is None:
            return Alert(at, f"a scope appeared under you: {current.scope}")
        direction = " and it is wider than before" if widened(previous.scope, current.scope) else ""
        level = ALARM if widened(previous.scope, current.scope) else NOTE
        return Alert(
            at,
            f"the recorded scope changed under you: {previous.scope} -> {current.scope}{direction}",
            level,
        )

    if current.digest == previous.digest and current.mtime != previous.mtime:
        return Alert(at, f"{current.path.name} was rewritten; the scope is unchanged")

    return None


def _local_hms(stamp: str) -> str:
    """Render a log timestamp in the operator's own timezone."""
    try:
        moment = _dt.datetime.fromisoformat(str(stamp))
    except (TypeError, ValueError):
        return str(stamp)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=_dt.timezone.utc)
    return moment.astimezone().strftime("%H:%M:%S")


def _duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def format_launch(entry: dict) -> str:
    """One launch as a single pane line."""
    state = "enforced" if entry.get("enforced") else "NOT enforced"
    scope = _safe(str(entry.get("scope", "?")))
    return f"{_local_hms(entry.get('at', '?'))}  {scope}  {state}"


def _title(left: str, right: str, width: int) -> str:
    gap = max(1, width - len(left) - len(right))
    return f"{left}{' ' * gap}{right}"


def render(
    state: ScopeState,
    launches: list[dict],
    alerts: list[Alert],
    *,
    started: float,
    now_ts: float,
    width: int = DEFAULT_WIDTH,
    color: bool = False,
    log_note: str = "",
) -> str:
    """Render one frame. Pure: same inputs, same string.

    Times arrive as epoch seconds, so a caller needs no clock of its own and a
    test can pin the frame to an exact moment.
    """
    rule = RULE_CHAR * width
    age = _duration(now_ts - started)
    clock = _dt.datetime.fromtimestamp(now_ts).strftime("%H:%M:%S")

    if color:
        alarm, bold, reset = _RED, _BOLD, _RESET
    else:
        alarm = bold = reset = ""

    lines = [
        bold + _title("evilkit watch", clock, width) + reset,
        rule,
    ]

    scope_text = _safe(state.scope) if state.scope else "none recorded"
    if state.error is not None and state.scope is None:
        scope_text = f"unknown  ({_safe(state.error)})"
    lines.append(f"{'scope in force':<18}{scope_text}")

    if state.mtime is None:
        age_text = "last changed unknown"
    else:
        age_text = f"last changed {_duration(now_ts - state.mtime)} ago"
    lines.append(f"{'recorded in':<18}{state.path}  ({age_text})")
    lines.append(f"{'watching for':<18}{age}")
    lines.append(rule)

    if alerts:
        lines.append(f"ALERTS ({len(alerts)})")
        for alert in alerts[-6:]:
            marker = "!!" if alert.level == ALARM else "--"
            prefix = f"  {alert.at}  {marker}  "
            for index, chunk in enumerate(
                textwrap.wrap(_safe(alert.text), max(24, width - len(prefix))) or [""]
            ):
                lead = prefix if index == 0 else " " * len(prefix)
                if alert.level == ALARM and color:
                    lines.append(f"{lead}{alarm}{chunk}{reset}")
                else:
                    lines.append(f"{lead}{chunk}")
    else:
        lines.append("ALERTS")
        lines.append("  nothing has changed since this pane started")
    lines.append(rule)

    lines.append("RECENT LAUNCHES")
    if log_note:
        lines.append(f"  {log_note}")
    elif not launches:
        lines.append("  nothing recorded yet")
    else:
        for entry in reversed(launches):
            lines.append(f"  {format_launch(entry)}")
    lines.append(rule)
    lines.append("Ctrl-C to stop. This pane only reports; it decides nothing.")

    return "\n".join(lines) + "\n"

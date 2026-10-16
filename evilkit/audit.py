"""Append-only record of what was launched, and under which scope.

One JSON object per line, oldest first, in ``$XDG_STATE_HOME/evilkit``
(``~/.local/state/evilkit`` by default). ``evilkit log`` reads it back.

The log records what was *asked for*, not what was permitted. It changes no
decision evilkit makes: a launch never fails because the log could not be
written, and nothing reads the log to decide a scope. Its only job is to leave
a dated trace of the scope an operator authorised for a session, so the
question "what did I point this at, and when?" has an answer that does not
depend on remembering or on ``.mcp.json`` still holding the same value.

It is deliberately not tamper-proof: the file belongs to the user who ran the
launcher, who can edit or delete it. Treat it as a personal record, not as
evidence about somebody else.
"""

from __future__ import annotations

import collections
import datetime as _dt
import json
import os
from pathlib import Path

__all__ = [
    "LogError",
    "ENTRY_VERSION",
    "LAUNCH_EVENT",
    "default_log_path",
    "launch_entry",
    "to_line",
    "record",
    "read",
]

#: Bumped only if the field layout changes in a way a reader must know about.
ENTRY_VERSION = 1

LAUNCH_EVENT = "launch"

LOG_NAME = "launches.jsonl"

_DIR_MODE = 0o700
#: The log names client address ranges, so it is not world-readable.
_FILE_MODE = 0o600


class LogError(Exception):
    """Raised when the log cannot be written or read."""


def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME")
    root = Path(base) if base else Path.home() / ".local" / "state"
    return root / "evilkit"


def default_log_path() -> Path:
    return state_dir() / LOG_NAME


def _timestamp() -> str:
    return (
        _dt.datetime.now(_dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def launch_entry(
    scope: str,
    *,
    enforced: bool,
    mcp_json: Path | None,
    kimi: str,
    event: str = LAUNCH_EVENT,
) -> dict:
    """Build the entry for one launch.

    ``enforced`` is True only when ``scope`` is the value now in force: it was
    written to ``mcp_json`` and nothing else governs the session. A launch under
    ``--no-write`` or ``--allow-unscoped`` records ``False``, which is the whole
    point of keeping a separate flag rather than trusting the string alone.
    """
    return {
        "v": ENTRY_VERSION,
        "at": _timestamp(),
        "event": event,
        "scope": scope,
        "enforced": bool(enforced),
        "mcp_json": str(mcp_json) if mcp_json is not None else None,
        "cwd": os.getcwd(),
        "kimi": kimi,
        "pid": os.getpid(),
    }


def to_line(entry: dict) -> str:
    """Render ``entry`` exactly as the file stores it, without the newline.

    One serialiser for both halves of the format: what ``record`` writes is what
    ``evilkit log --json`` prints, character for character.
    """
    return json.dumps(entry, ensure_ascii=False)


def record(path: Path, entry: dict) -> None:
    """Append ``entry`` as one line.

    The line is written in a single ``write`` to a descriptor opened
    ``O_APPEND``, so two evilkit processes logging at once cannot interleave a
    line or lose one another's entry.
    """
    try:
        line = to_line(entry) + "\n"
    except (TypeError, ValueError) as exc:
        raise LogError(f"could not encode a log entry: {exc}") from exc

    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, _FILE_MODE)
    except OSError as exc:
        raise LogError(f"could not open {path}: {exc}") from exc

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(line)
    except OSError as exc:
        raise LogError(f"could not write {path}: {exc}") from exc


def read(path: Path, limit: int | None = None) -> tuple[list[dict], int]:
    """Return ``(entries, skipped)``, oldest first, skipping unreadable lines.

    ``limit`` keeps only the newest that many entries, without holding the whole
    file in memory. ``skipped`` counts lines that were not a JSON object — a log
    truncated by a full disk mid-write, for instance — so a caller can say so
    rather than present a short log as a complete one.
    """
    if not path.exists():
        return [], 0

    kept: collections.deque = collections.deque(maxlen=limit)
    skipped = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    parsed = json.loads(line)
                except (json.JSONDecodeError, RecursionError):
                    skipped += 1
                    continue
                if not isinstance(parsed, dict):
                    skipped += 1
                    continue
                kept.append(parsed)
    except OSError as exc:
        raise LogError(f"could not read {path}: {exc}") from exc

    return list(kept), skipped

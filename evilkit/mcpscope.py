"""Read and update the ``pentest`` server scope inside a project's ``.mcp.json``.

Two env keys belong to that scope: ``PENTEST_ALLOWED_TARGETS`` and
``PENTEST_DENIED_TARGETS``. The tool server checks the deny list first, so a
target can be inside the allowed scope and still be refused.

The write is atomic: a candidate file is built and parsed before it replaces
anything, and the previous version is kept as a timestamped backup. A project
must never be left with a half-written ``.mcp.json``, nor briefly with none.

Why the file and not just the environment: the ``env`` block in ``.mcp.json`` is
injected into the MCP child process and wins over the parent environment, so an
exported ``PENTEST_ALLOWED_TARGETS`` does not reach the tool server.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import fcntl
import glob
import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path

__all__ = [
    "McpError",
    "McpNotFound",
    "NoPentestServer",
    "SCOPE_ENV_KEY",
    "DENY_ENV_KEY",
    "SERVER_NAME",
    "OSINT_SERVER_NAME",
    "DASHBOARD_SERVER_NAME",
    "find",
    "read_scope",
    "read_deny",
    "write_scope",
    "ensure_osint_server",
    "ensure_dashboard_server",
    "prune_backups",
    "looks_like_backup",
]

SCOPE_ENV_KEY = "PENTEST_ALLOWED_TARGETS"
DENY_ENV_KEY = "PENTEST_DENIED_TARGETS"
SERVER_NAME = "pentest"
OSINT_SERVER_NAME = "osint"
DASHBOARD_SERVER_NAME = "dashboard"

_BACKUP_RE = re.compile(r"\.(?P<stamp>\d{8}-\d{6})(?:-(?P<suffix>\d+))?\.bak$")


class McpError(Exception):
    """Base class for .mcp.json handling failures."""


class McpNotFound(McpError):
    """No .mcp.json exists at the requested location."""


class NoPentestServer(McpError):
    """The .mcp.json exists but declares no pentest server."""


def find(start: Path | None = None) -> Path:
    """Locate .mcp.json at or above ``start`` (default: the working directory)."""
    current = (start or Path.cwd()).resolve()
    for directory in (current, *current.parents):
        candidate = directory / ".mcp.json"
        if candidate.is_file():
            return candidate
    raise McpNotFound(f"no .mcp.json found in {current} or any parent directory")


def _load(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise McpError(f"could not read {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise McpError(f"{path} is not valid UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise McpError(f"{path} is not valid JSON: {exc}") from exc
    except RecursionError as exc:
        raise McpError(f"{path} is nested too deeply to parse") from exc
    if not isinstance(data, dict):
        raise McpError(f"{path} does not contain a JSON object")
    return data


def _pentest_env(path: Path) -> dict | None:
    """The pentest server's env block, or None when there is none to read."""
    data = _load(path)
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return None
    server = servers.get(SERVER_NAME)
    if not isinstance(server, dict):
        return None
    env = server.get("env")
    if not isinstance(env, dict):
        return None
    return env


def _read_env_key(path: Path, key: str) -> str | None:
    """Return ``key`` from the pentest env block, or None when it is unset."""
    env = _pentest_env(path)
    if env is None:
        return None
    value = env.get(key)
    return value if isinstance(value, str) else None


def read_scope(path: Path) -> str | None:
    """Return the configured scope, or None when no pentest server is declared."""
    return _read_env_key(path, SCOPE_ENV_KEY)


def read_deny(path: Path) -> str | None:
    """Return the configured deny list, or None when none is recorded.

    An empty string is a recorded answer — "deny nothing" — and is returned as
    such rather than folded into None, which means the key is not there at all.
    """
    return _read_env_key(path, DENY_ENV_KEY)


def looks_like_backup(path: Path) -> bool:
    return bool(_BACKUP_RE.search(path.name))


def _backup_age(path: Path) -> tuple[str, int, str]:
    """Order backups oldest-first, including several written in one second."""
    match = _BACKUP_RE.search(path.name)
    if match is None:
        return ("", 0, path.name)
    return (match["stamp"], int(match["suffix"] or 0), path.name)


def _free_backup_path(path: Path) -> Path:
    """Pick an unused timestamped backup name beside ``path``."""
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = path.with_name(f"{path.name}.{stamp}.bak")
    suffix = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.name}.{stamp}-{suffix}.bak")
        suffix += 1
    return candidate


def prune_backups(path: Path, keep: int) -> list[Path]:
    """Delete the oldest backups beside ``path``, keeping the newest ``keep``."""
    if keep < 0 or not path.parent.is_dir():
        return []
    prefix = path.name + "."
    backups = sorted(
        (
            candidate
            for candidate in path.parent.glob(f"{glob.escape(path.name)}.*.bak")
            if candidate.name.startswith(prefix) and looks_like_backup(candidate)
        ),
        key=_backup_age,
    )
    stale = backups[: max(0, len(backups) - keep)]
    removed: list[Path] = []
    for old in stale:
        try:
            old.unlink()
        except OSError:
            continue
        removed.append(old)
    return removed


def _discard(staging: Path) -> None:
    try:
        staging.unlink()
    except OSError:
        pass


def _original_mode(path: Path) -> int | None:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None


def _stage(path: Path, payload: str) -> Path:
    """Write ``payload`` to a fresh staging file beside ``path``.

    ``mkstemp`` creates the file with ``O_CREAT|O_EXCL`` under a name that
    cannot be predicted, so no symlink can be planted at the staging path.
    """
    mode = _original_mode(path)
    try:
        fd, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".new")
    except OSError as exc:
        raise McpError(f"could not stage a new {path.name}: {exc}") from exc

    staging = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            if mode is not None:
                os.fchmod(fd, mode)
            handle.write(payload)
            # Flush to disk before the rename: after a crash the record must be
            # the whole new scope or the whole old one, never a truncated file
            # that a launcher would then fail to parse.
            handle.flush()
            os.fsync(fd)
    except OSError as exc:
        _discard(staging)
        raise McpError(f"could not stage a new {path.name}: {exc}") from exc
    return staging


def _revalidate(staging: Path, path: Path) -> None:
    try:
        json.loads(staging.read_text(encoding="utf-8"))
    except OSError as exc:
        raise McpError(f"could not read back the staged {path.name}: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise McpError(f"refusing to write invalid JSON to {path.name}: {exc}") from exc
    except RecursionError as exc:
        raise McpError(f"refusing to write deeply nested JSON to {path.name}") from exc


@contextlib.contextmanager
def _locked(path: Path) -> Iterator[None]:
    """Serialise read-modify-write cycles with an advisory lock beside ``path``."""
    lock = path.with_name(path.name + ".lock")
    try:
        handle = open(lock, "a+b")
    except OSError as exc:
        raise McpError(f"could not open {lock}: {exc}") from exc
    with handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except OSError as exc:
            raise McpError(f"could not lock {lock}: {exc}") from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def write_scope(
    path: Path,
    scope: str,
    keep_backups: int = 5,
    dry_run: bool = False,
    deny: str | None = None,
) -> bool:
    """Record ``scope``, and ``deny`` when it is given, in ``path``.

    ``deny`` is the denied-target list. ``None`` means the caller said nothing
    about it, so whatever is recorded stays untouched — an omission must never
    blank a deny list someone set earlier. A string is recorded as the new
    value; ``""`` is the explicit "no denied targets".

    Returns True when the file changed, False when it already held that scope
    and that deny list (in which case nothing is written and no backup is
    created). A deny-only change is a change: it writes and backs up like any
    other. With ``dry_run`` the checks run and the answer is the same, but no
    file is touched.
    """
    if dry_run:
        return _rewrite(path, scope, deny, keep_backups, dry_run=True)
    with _locked(path):
        return _rewrite(path, scope, deny, keep_backups, dry_run=False)


def _rewrite(
    path: Path, scope: str, deny: str | None, keep_backups: int, *, dry_run: bool
) -> bool:
    # A symlinked target is refused, matching `theme.install`. Replacing it with
    # the staged regular file would leave the link's real target holding the old
    # scope, so a session following the link would run under a scope this write
    # only appeared to change.
    if path.is_symlink():
        raise McpError(f"{path} is a symlink; refusing to write the scope through it")

    data = _load(path)

    servers = data.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise McpError(f"{path}: 'mcpServers' is not an object")
    server = servers.get(SERVER_NAME)
    if not isinstance(server, dict):
        raise NoPentestServer(f"{path} declares no '{SERVER_NAME}' server")

    env = server.setdefault("env", {})
    if not isinstance(env, dict):
        raise McpError(f"{path}: '{SERVER_NAME}.env' is not an object")

    # Every key that differs, so "nothing to do" is a judgement about all of
    # them: a deny list that moved on its own still has to be written.
    changes: dict[str, str] = {}
    if env.get(SCOPE_ENV_KEY) != scope:
        changes[SCOPE_ENV_KEY] = scope
    if deny is not None and env.get(DENY_ENV_KEY) != deny:
        changes[DENY_ENV_KEY] = deny
    if not changes:
        return False
    env.update(changes)
    return _write_staged(path, data, keep_backups, dry_run)


def _write_staged(path: Path, data: dict, keep_backups: int, dry_run: bool) -> bool:
    """Atomically replace ``path`` with ``data`` (caller has already diffed)."""
    if dry_run:
        return True

    try:
        payload = json.dumps(data, indent=2) + "\n"
    except RecursionError as exc:
        raise McpError(f"{path} is nested too deeply to rewrite") from exc

    staging = _stage(path, payload)

    try:
        _revalidate(staging, path)

        if keep_backups > 0:
            backup = _free_backup_path(path)
            try:
                shutil.copy2(path, backup, follow_symlinks=False)
            except OSError as exc:
                raise McpError(f"could not back up {path}: {exc}") from exc

        try:
            os.replace(staging, path)
        except OSError as exc:
            # The original was copied, never moved, so it is untouched by this.
            raise McpError(f"could not replace {path}: {exc}") from exc
        # Persist the rename itself, so the durable directory entry points at the
        # new file and not, after a crash, at a staging name that is already gone.
        try:
            dir_fd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except BaseException:
        _discard(staging)
        raise

    if keep_backups > 0:
        prune_backups(path, keep_backups)
    return True


def ensure_osint_server(
    path: Path, command: list[str], keep_backups: int = 5, dry_run: bool = False
) -> bool:
    """Declare the passive OSINT MCP server in ``path``.

    ``command`` is ``[python, script, ...args]``; the entry mirrors the one the
    glm-code registration uses. Idempotent (False when already present and
    identical), additive: the pentest server and every other key are
    preserved, and the same staged-write/backup machinery as :func:`write_scope`
    is used.
    """
    if not command or not command[0]:
        raise McpError("osint server command must be [python, script, ...]")
    desired = {"type": "stdio", "command": command[0], "args": list(command[1:])}
    if dry_run:
        data = _load(path)
        servers = data.get("mcpServers")
        return not (isinstance(servers, dict) and servers.get(OSINT_SERVER_NAME) == desired)

    with _locked(path):
        data = _load(path)
        servers = data.setdefault("mcpServers", {})
        if not isinstance(servers, dict):
            raise McpError(f"{path}: 'mcpServers' is not an object")
        if servers.get(OSINT_SERVER_NAME) == desired:
            return False
        servers[OSINT_SERVER_NAME] = desired
        return _write_staged(path, data, keep_backups, dry_run=False)


def ensure_dashboard_server(
    path: Path, command: list[str], keep_backups: int = 5, dry_run: bool = False
) -> bool:
    """Declare the evilkit dashboard MCP server in ``path``.

    ``command`` is ``[python, ...args]``; the entry is the stdio shape the Kimi
    CLI loads. Unlike :func:`ensure_osint_server` the target may not exist yet:
    the file the CLI reads at project level is ``.kimi-code/mcp.json``, which a
    repository need not have, and an absent file is a fresh server map rather
    than an error. Idempotent (False when already present and identical),
    additive — the pentest server and every other key are preserved — and it
    uses the same staged-write/backup machinery as :func:`write_scope`.
    """
    if not command or not command[0]:
        raise McpError("dashboard server command must be [python, args...]")
    # A symlinked file is refused for the same reason as in `_rewrite`: replacing
    # it would leave the link's real target untouched, so the next launcher would
    # start from a config this write only appeared to change.
    if path.is_symlink():
        raise McpError(f"{path} is a symlink; refusing to write the dashboard server through it")

    desired = {"type": "stdio", "command": command[0], "args": list(command[1:])}
    if dry_run:
        if not path.is_file():
            return True
        data = _load(path)
        servers = data.get("mcpServers")
        return not (isinstance(servers, dict) and servers.get(DASHBOARD_SERVER_NAME) == desired)

    path.parent.mkdir(parents=True, exist_ok=True)
    with _locked(path):
        existed = path.is_file()
        data = _load(path) if existed else {"mcpServers": {}}
        servers = data.setdefault("mcpServers", {})
        if not isinstance(servers, dict):
            raise McpError(f"{path}: 'mcpServers' is not an object")
        if servers.get(DASHBOARD_SERVER_NAME) == desired:
            return False
        servers[DASHBOARD_SERVER_NAME] = desired
        # There is nothing to back up when this write is what creates the file.
        return _write_staged(path, data, keep_backups if existed else 0, dry_run=False)

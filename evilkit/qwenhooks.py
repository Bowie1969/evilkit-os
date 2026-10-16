"""Install the shared EvilKit session hook into Qwen Code settings."""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

HOOK_NAME = "evilkit-session-bridge"
HOOK_EVENTS = ("SessionStart", "BeforeTool", "AfterTool", "SessionEnd")


def settings_path() -> Path:
    return Path(os.path.expanduser(os.environ.get("EVILQWEN_SETTINGS", "~/.qwen/settings.json")))


def hook_command(checkout: Path | None = None) -> str:
    root = checkout or Path(__file__).resolve().parent.parent
    return f"env PYTHONPATH={root} python3 -m evilkit.kimihook"


def hooks_installed(path: Path | None = None) -> bool:
    target = path or settings_path()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    hooks = data.get("hooks", {}) if isinstance(data, dict) else {}
    for event in HOOK_EVENTS:
        entries = hooks.get(event, []) if isinstance(hooks, dict) else []
        if not any(
            hook.get("name") == HOOK_NAME
            for entry in entries if isinstance(entry, dict)
            for hook in entry.get("hooks", []) if isinstance(hook, dict)
        ):
            return False
    return True


def install_hooks(path: Path | None = None, checkout: Path | None = None) -> tuple[bool, str]:
    """Merge four event hooks into Qwen's JSON settings, preserving other keys."""
    target = path or settings_path()
    try:
        original = target.read_text(encoding="utf-8")
        data = json.loads(original)
    except FileNotFoundError:
        original = "{}\n"
        data = {}
    except (OSError, ValueError) as exc:
        return False, f"could not read {target}: {exc}"
    if not isinstance(data, dict):
        return False, f"refusing to write {target}: root must be a JSON object"
    if hooks_installed(target):
        return False, f"already installed in {target} (no change)"

    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        return False, f"refusing to write {target}: hooks must be an object"
    command = hook_command(checkout)
    for event in HOOK_EVENTS:
        entries = hooks.setdefault(event, [])
        if not isinstance(entries, list):
            return False, f"refusing to write {target}: hooks.{event} must be an array"
        present = any(
            hook.get("name") == HOOK_NAME
            for entry in entries if isinstance(entry, dict)
            for hook in entry.get("hooks", []) if isinstance(hook, dict)
        )
        if not present:
            entries.append({
                "matcher": "*",
                "hooks": [{
                    "name": HOOK_NAME,
                    "type": "command",
                    "command": command,
                    "description": "EvilKit scope guard, evidence journal, learning, and Keystone telemetry",
                    "timeout": 10000,
                }],
            })

    candidate = json.dumps(data, indent=2) + "\n"
    target.parent.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    try:
        if target.exists():
            target.with_suffix(target.suffix + f".evilkit-{stamp}.bak").write_text(original, encoding="utf-8")
        fd, name = tempfile.mkstemp(dir=target.parent, prefix=target.name + ".", suffix=".tmp")
        staging = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(candidate)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staging, target)
    except OSError as exc:
        try:
            staging.unlink(missing_ok=True)
        except UnboundLocalError:
            pass
        return False, f"could not write {target}: {exc}"
    return True, f"installed {len(HOOK_EVENTS)} hooks in {target} (backup kept when applicable)"

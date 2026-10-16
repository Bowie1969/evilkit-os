"""Install the bundled evilkit colour theme into the Kimi Code themes directory."""

from __future__ import annotations

import json
import os
from pathlib import Path

__all__ = [
    "THEME_NAME",
    "theme_source",
    "kimi_themes_dir",
    "install",
    "is_installed",
    "is_modified",
]

THEME_NAME = "evilkit"


def theme_source() -> Path:
    """Path to the theme shipped inside the package."""
    return Path(__file__).resolve().parent / "data" / f"{THEME_NAME}.json"


def kimi_themes_dir() -> Path:
    override = os.environ.get("EVILKIT_KIMI_HOME")
    root = Path(override) if override else Path.home() / ".kimi-code"
    return root / "themes"


def install(themes_dir: Path | None = None, force: bool = False) -> Path:
    """Copy the bundled theme into place and return the destination path.

    An existing file is only replaced when ``force`` is set, so a local edit to
    the installed theme survives a plain reinstall.
    """
    source = theme_source()
    if not source.is_file():
        raise FileNotFoundError(f"bundled theme missing: {source}")

    # Validate before it reaches the TUI, so a corrupt theme cannot break startup.
    try:
        json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"bundled theme is not valid JSON: {exc}") from exc

    target_dir = themes_dir or kimi_themes_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{THEME_NAME}.json"

    if target.is_symlink():
        raise ValueError(f"{target} is a symlink; refusing to write through it")

    if target.exists() and not force:
        return target

    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def is_installed(themes_dir: Path | None = None) -> bool:
    target = (themes_dir or kimi_themes_dir()) / f"{THEME_NAME}.json"
    return target.is_file()


def is_modified(themes_dir: Path | None = None) -> bool:
    """True when an installed theme differs from the bundled one."""
    target = (themes_dir or kimi_themes_dir()) / f"{THEME_NAME}.json"
    return target.is_file() and target.read_bytes() != theme_source().read_bytes()

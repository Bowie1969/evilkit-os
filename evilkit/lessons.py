"""Iterative operator lessons loaded into every brain run.

Lessons live in `evilkit/data/lessons.md` and are injected into the operator
system prompt. Append new lessons with `append_lesson()` or the
`evilkit lessons add` CLI subcommand.

Each lesson block is:

    ## L<N> — <title>
    Source: <provenance>
    Key: <stable-key>        # optional, used to dedup auto-distilled lessons
    Batch: <batch-id>        # optional, used to roll back one self-training batch
    <body>

The `Key:` and `Batch:` lines are metadata for the self-training loop
(:mod:`evilkit.learning`); :func:`load_lessons` strips them so the operator
prompt stays clean.
"""

from __future__ import annotations

import re
import os
from datetime import date
from pathlib import Path

__all__ = [
    "lessons_path",
    "bundled_lessons_path",
    "load_lessons",
    "append_lesson",
    "next_lesson_number",
    "existing_keys",
    "remove_batch",
    "last_batch",
]

_MARKER_RE = re.compile(r"^(Key|Batch):\s*(.+?)\s*$")
_HEADING_RE = re.compile(r"^## L(\d+)\b")


def bundled_lessons_path() -> Path:
    return Path(__file__).resolve().parent / "data" / "lessons.md"


def lessons_path() -> Path:
    """Writable lessons overlay; package data is treated as read-only seed data."""
    override = os.environ.get("EVILKIT_LESSONS_PATH")
    if override:
        return Path(os.path.expanduser(override))
    base = os.environ.get("XDG_STATE_HOME")
    root = Path(base) if base else Path.home() / ".local" / "state"
    return root / "evilkit" / "lessons.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _combined_raw() -> str:
    chunks = [_read(bundled_lessons_path()).rstrip(), _read(lessons_path()).rstrip()]
    return "\n\n".join(chunk for chunk in chunks if chunk) + ("\n" if any(chunks) else "")


def load_lessons() -> str:
    """Return the lessons markdown with metadata lines stripped, or "" if missing."""
    body = _combined_raw()
    if not body:
        return ""
    kept = [
        line
        for line in body.splitlines()
        if not _MARKER_RE.match(line.strip())
    ]
    return "\n".join(kept).rstrip() + "\n"


def _raw() -> str:
    path = lessons_path()
    return _read(path)


def next_lesson_number(text: str | None = None) -> int:
    """Scan existing lessons for the highest L<N> heading and return N+1."""
    body = text if text is not None else _combined_raw()
    highest = 0
    for line in body.splitlines():
        m = _HEADING_RE.match(line.strip())
        if m:
            highest = max(highest, int(m.group(1)))
    return highest + 1


def existing_keys(text: str | None = None) -> set[str]:
    """Return the set of lesson keys already recorded (empty for keyless lessons)."""
    body = text if text is not None else _combined_raw()
    keys: set[str] = set()
    for line in body.splitlines():
        m = _MARKER_RE.match(line.strip())
        if m and m.group(1) == "Key":
            keys.add(m.group(2))
    return keys


def last_batch(text: str | None = None) -> str | None:
    """Return the id of the most recently appended batch, or None if there is none."""
    body = text if text is not None else _raw()
    latest = None
    for line in body.splitlines():
        m = _MARKER_RE.match(line.strip())
        if m and m.group(1) == "Batch":
            latest = m.group(2)
    return latest


def append_lesson(
    title: str,
    body: str,
    *,
    source: str | None = None,
    key: str | None = None,
    batch: str | None = None,
) -> int:
    """Append a new lesson, return its number. Creates the file if missing."""
    title = title.strip()
    body = body.strip()
    if not title or not body:
        raise ValueError("lesson title and body are required")
    number = next_lesson_number()
    source_val = source.strip() if source else f"run on {date.today().isoformat()}"
    lines = [f"\n## L{number} — {title}", f"Source: {source_val}"]
    if key:
        lines.append(f"Key: {key.strip()}")
    if batch:
        lines.append(f"Batch: {batch.strip()}")
    lines.append(body)
    entry = "\n".join(lines) + "\n"
    path = lessons_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = _raw()
    path.write_text(existing.rstrip() + "\n" + entry, encoding="utf-8")
    return number


def remove_batch(batch: str) -> list[int]:
    """Delete every lesson block tagged with ``batch``. Return the numbers removed."""
    batch = batch.strip()
    if not batch:
        return []
    path = lessons_path()
    if not path.is_file():
        return []

    lines = path.read_text(encoding="utf-8").splitlines()
    # Split into the preamble and a list of (heading_number, block_lines) blocks.
    blocks: list[tuple[int | None, list[str]]] = []
    current: list[str] = []
    current_num: int | None = None
    preamble: list[str] = []
    seen_heading = False
    for line in lines:
        m = _HEADING_RE.match(line.strip())
        if m:
            if seen_heading:
                blocks.append((current_num, current))
            else:
                preamble = current
            seen_heading = True
            current = [line]
            current_num = int(m.group(1))
        else:
            current.append(line)
    if seen_heading:
        blocks.append((current_num, current))
    else:
        preamble = current

    removed: list[int] = []
    kept_blocks: list[list[str]] = []
    for num, block in blocks:
        tagged = any(
            (mm := _MARKER_RE.match(bl.strip())) and mm.group(1) == "Batch" and mm.group(2) == batch
            for bl in block
        )
        if tagged and num is not None:
            removed.append(num)
        else:
            kept_blocks.append(block)

    if not removed:
        return []

    out = "\n".join(preamble).rstrip()
    for block in kept_blocks:
        out += "\n\n" + "\n".join(block).strip()
    path.write_text(out.rstrip() + "\n", encoding="utf-8")
    return sorted(removed)

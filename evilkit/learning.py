"""Conservative self-training from completed CLI hook sessions.

The learner never asks a model to rewrite its own instructions.  It derives a
small set of deterministic, reversible lessons from measured session facts,
records the session in an append-only ledger, and tags every automatic lesson
with a batch id so the last change can be rolled back.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import lessons as lessons_mod

__all__ = [
    "CandidateLesson",
    "LearnReport",
    "learn_from_records",
    "ledger_path",
    "ledger_rows",
    "generation_summary",
    "rollback_last_batch",
    "format_report",
]


def _state_root() -> Path:
    override = os.environ.get("EVILKIT_STATE_DIR")
    if override:
        return Path(os.path.expanduser(override))
    base = os.environ.get("XDG_STATE_HOME")
    return (Path(base) if base else Path.home() / ".local" / "state") / "evilkit"


def ledger_path() -> Path:
    override = os.environ.get("EVILKIT_LEARNING_LEDGER")
    return Path(os.path.expanduser(override)) if override else _state_root() / "learning.jsonl"


def lessons_fingerprint() -> str:
    text = lessons_mod.load_lessons().strip()
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12] if text else "baseline"


@dataclass(frozen=True)
class CandidateLesson:
    key: str
    title: str
    body: str


@dataclass
class LearnReport:
    run_id: str
    fingerprint: str
    action_count: int
    failure_count: int
    candidates: list[CandidateLesson] = field(default_factory=list)
    added: list[tuple[int, str]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def _normalise_command(command: str) -> str:
    """Produce a stable command shape without retaining credentials or tokens."""
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    clean: list[str] = []
    redact_next = False
    for part in parts[:12]:
        lower = part.lower()
        if redact_next:
            clean.append("<redacted>")
            redact_next = False
            continue
        if lower in {"-p", "--password", "--token", "--api-key", "-k"}:
            clean.append(lower)
            redact_next = True
        elif any(word in lower for word in ("password=", "token=", "api_key=", "authorization:")):
            clean.append("<redacted>")
        else:
            clean.append(part)
    return " ".join(clean)


def _distill(records: list[dict], run_id: str) -> list[CandidateLesson]:
    actions = [row for row in records if row.get("kind") == "action"]
    commands = [_normalise_command(str(row.get("command") or "")) for row in actions]
    failures = [row for row in actions if int(row.get("returncode") or 0) != 0]
    candidates: list[CandidateLesson] = []

    repeated = [(command, count) for command, count in Counter(commands).items() if command and count >= 3]
    if repeated:
        command, count = max(repeated, key=lambda item: item[1])
        candidates.append(CandidateLesson(
            key="avoid-identical-retries",
            title="Replan after a repeated action fails",
            body=(f"Session {run_id} issued the same action shape {count} times. After two equivalent "
                  "attempts, stop repeating it and change the host, credential, technique, or success oracle."),
        ))

    if len(actions) >= 4 and len(failures) * 2 >= len(actions):
        candidates.append(CandidateLesson(
            key="failure-rate-reorientation",
            title="Reorient when half the actions are failing",
            body=(f"Session {run_id} recorded {len(failures)} failures in {len(actions)} actions. "
                  "Pause, inspect the evidence and scope, then choose one new test instead of continuing the same path."),
        ))

    warnings = sum(len(row.get("warnings") or []) for row in actions)
    if warnings >= 3:
        candidates.append(CandidateLesson(
            key="heed-harness-warnings",
            title="Treat repeated harness warnings as a decision point",
            body=(f"Session {run_id} produced {warnings} harness warnings. Three warnings in one session "
                  "mean the current approach needs explicit re-planning before another tool call."),
        ))
    return candidates


def _append_ledger(row: dict) -> None:
    path = ledger_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, separators=(",", ":")) + "\n")


def learn_from_records(records: list[dict], run_id: str, *, apply: bool = True) -> LearnReport:
    """Record a completed session and append only novel deterministic lessons."""
    actions = [row for row in records if row.get("kind") == "action"]
    failures = sum(1 for row in actions if int(row.get("returncode") or 0) != 0)
    fingerprint = lessons_fingerprint()
    batch = run_id or datetime.now(timezone.utc).strftime("auto-%Y%m%dT%H%M%S")
    candidates = _distill(records, batch)
    report = LearnReport(batch, fingerprint, len(actions), failures, candidates=candidates)
    _append_ledger({
        "ts": datetime.now(timezone.utc).isoformat(),
        "run_id": batch,
        "fingerprint": fingerprint,
        "actions": len(actions),
        "failures": failures,
        "candidate_keys": [candidate.key for candidate in candidates],
    })
    if not apply:
        return report
    present = lessons_mod.existing_keys()
    for candidate in candidates:
        if candidate.key in present:
            report.skipped.append(candidate.key)
            continue
        number = lessons_mod.append_lesson(
            candidate.title,
            candidate.body,
            source=f"auto-distilled from session {batch}",
            key=candidate.key,
            batch=batch,
        )
        report.added.append((number, candidate.title))
        present.add(candidate.key)
    return report


def ledger_rows() -> list[dict]:
    path = ledger_path()
    if not path.is_file():
        return []
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def generation_summary() -> list[dict]:
    order: list[str] = []
    buckets: dict[str, list[dict]] = {}
    for row in ledger_rows():
        fingerprint = str(row.get("fingerprint") or "?")
        if fingerprint not in buckets:
            buckets[fingerprint] = []
            order.append(fingerprint)
        buckets[fingerprint].append(row)
    result: list[dict] = []
    for fingerprint in order:
        rows = buckets[fingerprint]
        actions = sum(int(row.get("actions") or 0) for row in rows)
        failures = sum(int(row.get("failures") or 0) for row in rows)
        result.append({
            "fingerprint": fingerprint,
            "runs": len(rows),
            "actions": actions,
            "failure_rate": round(failures / actions, 3) if actions else 0.0,
        })
    return result


def rollback_last_batch() -> tuple[str | None, list[int]]:
    batch = lessons_mod.last_batch()
    return (None, []) if not batch else (batch, lessons_mod.remove_batch(batch))


def format_report(report: LearnReport) -> str:
    lines = [
        f"self-training: session {report.run_id} recorded {report.action_count} actions "
        f"({report.failure_count} failed) [lessons {report.fingerprint}]"
    ]
    lines.extend(f"  + learned L{number}: {title}" for number, title in report.added)
    if report.skipped:
        lines.append(f"  = already known: {', '.join(report.skipped)}")
    if not report.candidates:
        lines.append("  = no measured behavior crossed a learning threshold")
    return "\n".join(lines)

"""Cross-check the three records a run leaves behind.

A run writes its actions to the harness session log, its live board to the
dashboard run directory (``dashboard/events.jsonl``), and the half the scorer
reads to ``journal.jsonl``. Nothing has ever compared them, which is how a run
can look productive in its own log, paint nothing on the board, and score zero —
the state of both runs scored so far.

The check is deliberately blunt: it reports the disagreements it can see and
leaves the judgement to the reader. It never edits anything.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

__all__ = ["SCORER_VERBS", "verify_run", "format_audit"]

#: Verbs the Keystone scorer's journal vocabulary understands
#: (``keystone/score.py`` ``_ACTION_SYNONYMS``). A record whose verb is not here
#: is invisible to the scorer even though EvilKit wrote it.
SCORER_VERBS = frozenset({
    "recon", "foothold", "compromise", "privesc", "lateral", "pivot", "implant",
    "persist", "c2", "exfil", "hive_deploy", "hive_result",
})


def _read_jsonl(path: Path) -> list[dict]:
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
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def _read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _verb(record: dict) -> str:
    return str(record.get("event") or record.get("action") or "").strip().lower()


def verify_run(run_dir: str | Path, session_dir: str | Path | None = None) -> dict[str, Any]:
    """Compare the run's session logs, dashboard events and scorer journal."""
    run_path = Path(run_dir).expanduser()
    run_id = run_path.name
    problems: list[str] = []
    notes: list[str] = []

    if not run_path.is_dir():
        return {"run_dir": str(run_path), "run_id": run_id, "ok": False,
                "problems": [f"{run_path} is not a directory"], "notes": [],
                "counts": {}, "verbs": {}, "sessions": []}

    journal_path = run_path / "journal.jsonl"
    events_path = run_path / "dashboard" / "events.jsonl"
    status_path = run_path / "dashboard" / "status.json"

    journal = _read_jsonl(journal_path)
    events = _read_jsonl(events_path)
    status = _read_json(status_path)

    if not journal_path.is_file():
        problems.append(
            "no journal.jsonl — the scorer reads this file, so the run scores zero on "
            "every agent-declared action however much work it did"
        )
    elif not journal:
        problems.append("journal.jsonl is empty — the emitter was never reached")
    if not events:
        notes.append("dashboard/events.jsonl has no events: the board would show nothing")

    # -- run-id ownership ---------------------------------------------------

    for label, records in (("journal.jsonl", journal), ("dashboard/events.jsonl", events)):
        foreign = sorted({str(r.get("run_id")) for r in records
                          if r.get("run_id") and str(r.get("run_id")) != run_id})
        if foreign:
            problems.append(f"{label} carries records for other runs: {', '.join(foreign)}")
    if status and str(status.get("run_id") or "") not in ("", run_id):
        problems.append(f"dashboard/status.json reports run_id {status.get('run_id')!r}, "
                        f"not {run_id!r}")

    # -- the scorer's own view ---------------------------------------------

    verbs: dict[str, int] = {}
    for record in journal:
        key = _verb(record) or "(none)"
        verbs[key] = verbs.get(key, 0) + 1
    unreadable = sorted(verb for verb in verbs if verb not in SCORER_VERBS and verb != "(none)")
    if unreadable:
        problems.append("journal.jsonl uses verbs the scorer does not know: "
                        + ", ".join(unreadable))

    # -- session logs -------------------------------------------------------

    sessions: list[dict[str, Any]] = []
    claimed = 0
    sessions_root = Path(session_dir) if session_dir is not None else _default_session_dir()
    for path in sorted(sessions_root.glob("*.jsonl")) if sessions_root.is_dir() else []:
        records = _read_jsonl(path)
        starts = [r for r in records if r.get("kind") == "session_start"]
        ids = {str(r.get("run_id") or "") for r in starts}
        if run_id not in ids:
            continue
        claimed += 1
        actions = [r for r in records if r.get("kind") == "action"]
        denials = [r for r in records if r.get("kind") == "denied"]
        session_id = str(starts[0].get("session_id") or path.stem.removeprefix("session_"))
        logged = [r for r in journal if str(r.get("session_id") or "") == session_id]
        sessions.append({
            "path": str(path),
            "session_id": session_id,
            "actions": len(actions),
            "refusals": len(denials),
            "journal_records": len(logged),
        })
        if actions and not logged:
            problems.append(
                f"{path.name} logged {len(actions)} actions but no journal record carries "
                f"session_id {session_id}: the ledger and the dashboard disagree"
            )
    if not sessions:
        problems.append(
            "no session log claims this run — the operator's own record cannot be tied to "
            "it, so nothing here can be corroborated from the session side"
        )

    return {
        "run_dir": str(run_path),
        "run_id": run_id,
        "ok": not problems,
        "counts": {
            "journal_records": len(journal),
            "dashboard_events": len(events),
            "sessions_claiming_the_run": claimed,
            "session_actions": sum(s["actions"] for s in sessions),
            "session_refusals": sum(s["refusals"] for s in sessions),
        },
        "verbs": verbs,
        "status": {key: status.get(key) for key in ("state", "updated_at", "last_event")
                   if key in status},
        "sessions": sessions,
        "problems": problems,
        "notes": notes,
    }


def _default_session_dir() -> Path:
    from . import kimihook

    return kimihook.state_root() / "sessions"


def format_audit(report: dict[str, Any]) -> str:
    lines = [f"{report['run_dir']}"]
    counts = report.get("counts") or {}
    if counts:
        lines.append("  " + ", ".join(f"{key}={value}" for key, value in counts.items()))
    if report.get("verbs"):
        lines.append("  scorer verbs: "
                     + ", ".join(f"{verb}={count}" for verb, count in sorted(report["verbs"].items())))
    if report.get("status"):
        lines.append(f"  dashboard state: {report['status'].get('state')} "
                     f"(last: {report['status'].get('last_event')})")
    for session in report.get("sessions", []):
        lines.append(f"  session {session['session_id']}: {session['actions']} actions, "
                     f"{session['refusals']} refusals, {session['journal_records']} journal records")
    for note in report.get("notes", []):
        lines.append(f"  note: {note}")
    for problem in report.get("problems", []):
        lines.append(f"  PROBLEM: {problem}")
    lines.append("  consistent" if report["ok"] else "  inconsistent — score is provisional")
    return "\n".join(lines)

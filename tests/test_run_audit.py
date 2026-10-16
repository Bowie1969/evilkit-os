"""Tests for the post-run consistency check (SCORE-LIFT-PLAN §4).

The check exists because each of the three records a run leaves — the harness
session log, the dashboard's events, and the scorer's journal — can be complete
while the others are empty, which is exactly how the two scored runs so far
looked productive and scored zero. Each disagreement gets a test.
"""

from __future__ import annotations

import json
import unittest

from tests._helpers import EvilkitTestCase

from evilkit import run_audit, dashboard_telemetry

RUN_ID = "evilkimi-live-test01"


class AuditCase(EvilkitTestCase):
    def make_run(self, run_id: str = RUN_ID, *, journal=True, events=True,
                 verbs=("recon", "pivot"), status=True) -> "object":
        run = self.tmp / "runs" / run_id
        (run / "dashboard").mkdir(parents=True, exist_ok=True)
        (run / "dashboard" / "topology.json").write_text(json.dumps({
            "nodes": [{"id": "g960", "ip": "10.99.50.60"}, {"id": "g911", "ip": "10.99.50.11"}],
        }), encoding="utf-8")
        if journal:
            (run / "journal.jsonl").write_text("".join(
                json.dumps({"run_id": run_id, "ts": 1, "session_id": self.session_id,
                            "kind": "action", "event": verb, "target": "10.99.50.11",
                            "action": "recon", "status": "success"}) + "\n"
                for verb in verbs
            ), encoding="utf-8")
        if events:
            (run / "dashboard" / "events.jsonl").write_text(json.dumps({
                "run_id": run_id, "ts": 1, "event": "recon", "host": "10.99.50.11",
                "node": "g911", "source": "kimi",
            }) + "\n", encoding="utf-8")
        if status:
            (run / "dashboard" / "status.json").write_text(json.dumps({
                "run_id": run_id, "state": "running", "updated_at": 1, "last_event": "recon",
            }), encoding="utf-8")
        return run

    session_id = "abc123"

    def make_session(self, run_id=None, *, actions=2, journal_session="abc123") -> "object":
        sessions = self.tmp / "state" / "sessions"
        sessions.mkdir(parents=True, exist_ok=True)
        path = sessions / f"session_{self.session_id}.jsonl"
        records = [{"kind": "session_start", "ts": 1, "scope": "10.99.50.0/24",
                    "engine": "kimi", "run_id": run_id or ""}]
        records += [{"kind": "action", "ts": 2, "tool": "Bash", "command": f"Bash id {i}",
                     "output": "uid=0", "returncode": 0} for i in range(actions)]
        records.append({"kind": "denied", "ts": 3, "tool": "Bash", "command": "Bash ssh x",
                        "reason": "REPEAT REFUSAL"})
        path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
        return sessions


class TestVerifyRun(AuditCase):
    def test_a_run_whose_records_agree(self):
        run = self.make_run()
        sessions = self.make_session(run_id=RUN_ID)
        report = run_audit.verify_run(run, session_dir=sessions)
        self.assertTrue(report["ok"], report["problems"])
        self.assertEqual(report["counts"]["journal_records"], 2)
        self.assertEqual(report["counts"]["session_actions"], 2)
        self.assertEqual(report["counts"]["session_refusals"], 1)
        self.assertEqual(report["verbs"], {"pivot": 1, "recon": 1})
        self.assertIn("consistent", run_audit.format_audit(report))

    def test_a_missing_journal_is_a_problem(self):
        """The scorer reads journal.jsonl; nothing else it writes counts."""
        run = self.make_run(journal=False)
        report = run_audit.verify_run(run, session_dir=self.make_session(run_id=RUN_ID))
        self.assertFalse(report["ok"])
        self.assertTrue(any("journal.jsonl" in problem for problem in report["problems"]))

    def test_an_empty_journal_is_a_problem(self):
        run = self.make_run()
        (run / "journal.jsonl").write_text("", encoding="utf-8")
        report = run_audit.verify_run(run, session_dir=self.make_session(run_id=RUN_ID))
        self.assertFalse(report["ok"])
        self.assertTrue(any("empty" in problem for problem in report["problems"]))

    def test_actions_with_no_journal_records_are_a_disagreement(self):
        run = self.make_run(verbs=())
        report = run_audit.verify_run(run, session_dir=self.make_session(run_id=RUN_ID, actions=5))
        self.assertFalse(report["ok"])
        self.assertTrue(any("disagree" in problem for problem in report["problems"]))

    def test_a_session_that_never_claims_the_run_is_a_problem(self):
        run = self.make_run()
        report = run_audit.verify_run(run, session_dir=self.make_session(run_id=""))
        self.assertFalse(report["ok"])
        self.assertTrue(any("cannot be tied to it" in problem for problem in report["problems"]))

    def test_records_from_another_run_are_a_problem(self):
        run = self.make_run()
        with (run / "journal.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"run_id": "some-other-run", "event": "recon"}) + "\n")
        report = run_audit.verify_run(run, session_dir=self.make_session(run_id=RUN_ID))
        self.assertFalse(report["ok"])
        self.assertTrue(any("other runs" in problem for problem in report["problems"]))

    def test_a_verb_the_scorer_cannot_read_is_a_problem(self):
        run = self.make_run(verbs=("recon", "totally_made_up"))
        report = run_audit.verify_run(run, session_dir=self.make_session(run_id=RUN_ID))
        self.assertFalse(report["ok"])
        self.assertTrue(any("does not know" in problem for problem in report["problems"]))

    def test_a_missing_dashboard_is_a_note_not_a_failure(self):
        run = self.make_run(events=False, status=False)
        report = run_audit.verify_run(run, session_dir=self.make_session(run_id=RUN_ID))
        self.assertTrue(report["ok"], report["problems"])
        self.assertTrue(any("no events" in note for note in report["notes"]))

    def test_missing_directory(self):
        report = run_audit.verify_run(self.tmp / "nope")
        self.assertFalse(report["ok"])


class TestCli(AuditCase):
    def test_verify_run_cli_reports_and_fails_on_disagreement(self):
        run = self.make_run(journal=False)
        code, out, _ = self.call_main(["calls", "verify-run", str(run),
                                       "--session-dir", str(self.make_session(run_id=RUN_ID))])
        self.assertEqual(code, 1)
        self.assertIn("PROBLEM", out)

    def test_verify_run_cli_json(self):
        run = self.make_run()
        code, out, err = self.call_main(["calls", "verify-run", str(run), "--json",
                                         "--session-dir", str(self.make_session(run_id=RUN_ID))])
        self.assertEqual(code, 0, err)
        report = json.loads(out)
        self.assertTrue(report["ok"])
        self.assertEqual(report["run_id"], RUN_ID)


class TestScorerVocabulary(EvilkitTestCase):
    """The journal has to speak the scorer's language, or it scores nothing."""

    def test_phase_verbs_are_derived_from_the_tool(self):
        self.assertEqual(dashboard_telemetry.scorer_verb("mcp__pentest__ssh_tunnel", 0, "exploit"),
                         "pivot")
        self.assertEqual(dashboard_telemetry.scorer_verb("mcp__pentest__nmap_scan", 0, "recon"),
                         "recon")
        self.assertEqual(dashboard_telemetry.scorer_verb("malware_persist", 0, "exploit"),
                         "persist")
        self.assertEqual(dashboard_telemetry.scorer_verb("malware_classify", 0, "exploit"),
                         "exfil")

    def test_a_failed_phase_claim_is_downgraded(self):
        self.assertEqual(dashboard_telemetry.scorer_verb("malware_persist", 1, "exploit"), "recon")
        self.assertEqual(dashboard_telemetry.scorer_verb("mcp__pentest__ssh_tunnel", 255, "exploit"),
                         "recon")

    def test_an_unknown_tool_keeps_the_dashboard_event(self):
        self.assertEqual(dashboard_telemetry.scorer_verb("Bash", 0, "recon"), "recon")
        self.assertEqual(dashboard_telemetry.scorer_verb("mystery_tool", 0, "exploit"), "exploit")

    def test_emit_action_writes_a_scorer_readable_journal_record(self):
        run = self.tmp / "run1"
        (run / "dashboard").mkdir(parents=True)
        (run / "dashboard" / "topology.json").write_text(json.dumps({
            "nodes": [{"id": "g960", "ip": "10.99.50.60"}, {"id": "g911", "ip": "10.99.50.11"}],
        }), encoding="utf-8")
        telemetry = dashboard_telemetry.DashboardTelemetry(run_dir=str(run), entry_host="10.99.50.60")
        event = telemetry.emit_action("ssh_tunnel --host 10.99.50.11", 0, tool_name="mcp__pentest__ssh_tunnel")
        self.assertIsNotNone(event)
        record = json.loads((run / "journal.jsonl").read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(record["event"], "pivot")
        self.assertEqual(record["run_id"], "run1")
        self.assertIn(record["event"], run_audit.SCORER_VERBS)

    def test_an_event_with_no_place_on_the_board_is_still_a_failure(self):
        """No topology node for the target: the emitter returns None."""
        run = self.tmp / "run2"
        (run / "dashboard").mkdir(parents=True)
        (run / "dashboard" / "topology.json").write_text(json.dumps({
            "nodes": [{"id": "g960", "ip": "10.99.50.60"}],
        }), encoding="utf-8")
        telemetry = dashboard_telemetry.DashboardTelemetry(run_dir=str(run), entry_host="10.99.50.60")
        self.assertIsNone(telemetry.emit_action("nmap 10.9.9.9", 0, tool_name="nmap_scan"))


if __name__ == "__main__":
    unittest.main()

"""Tests for the launch log — the append-only record evilkit keeps.

``evilkit.audit`` is exercised directly for the file format, and through the CLI
for the launch path, which is where a wrong decision would end up recorded as if
it had been authorised.

The log is checked in a subprocess for anything that reaches ``os.execvpe``,
because that path replaces the interpreter.
"""

from __future__ import annotations

import json
import os
import pathlib
import stat
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import SCOPE_ENV_KEY, EvilkitTestCase  # noqa: E402

from evilkit import audit  # noqa: E402
from evilkit.cli import EXIT_ERROR, EXIT_OK, EXIT_USAGE  # noqa: E402


class AuditTestCase(EvilkitTestCase):
    """Base class adding the log location and readers for it."""

    @property
    def log_path(self) -> pathlib.Path:
        """Where default_log_path() points, given the scrubbed XDG_STATE_HOME."""
        return pathlib.Path(os.environ["XDG_STATE_HOME"]) / "evilkit" / audit.LOG_NAME

    def lines(self, path=None) -> list[str]:
        target = path or self.log_path
        if not target.exists():
            return []
        return [
            line
            for line in target.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def entries(self, path=None) -> list[dict]:
        return [json.loads(line) for line in self.lines(path)]

    def write_config(self, body: str) -> pathlib.Path:
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_file.write_text(body, encoding="utf-8")
        return self.config_file

    def scope_in(self, path) -> str:
        return json.loads(path.read_text(encoding="utf-8"))["mcpServers"]["pentest"]["env"][
            SCOPE_ENV_KEY
        ]

    def sample(self, scope: str = "10.0.0.0/24", enforced: bool = True) -> dict:
        return audit.launch_entry(
            scope, enforced=enforced, mcp_json=self.tmp / ".mcp.json", kimi="kimi"
        )


class TestDefaultLogPath(AuditTestCase):
    def test_the_default_lives_under_the_state_home(self):
        self.assertEqual(
            audit.default_log_path(),
            pathlib.Path(os.environ["XDG_STATE_HOME"]) / "evilkit" / "launches.jsonl",
        )

    def test_an_unset_state_home_falls_back_to_local_state(self):
        with mock.patch.dict(os.environ, {"XDG_STATE_HOME": ""}):
            self.assertEqual(
                audit.default_log_path(),
                pathlib.Path(os.environ["HOME"])
                / ".local"
                / "state"
                / "evilkit"
                / "launches.jsonl",
            )


class TestRecord(AuditTestCase):
    def test_record_creates_the_directory_and_the_file_with_tight_modes(self):
        audit.record(self.log_path, self.sample())

        self.assertTrue(self.log_path.is_file())
        # The log names client address ranges, so neither it nor its directory
        # may be readable by anyone else on the box.
        self.assertEqual(
            stat.S_IMODE(self.log_path.parent.stat().st_mode), 0o700, "directory mode"
        )
        self.assertEqual(stat.S_IMODE(self.log_path.stat().st_mode), 0o600, "file mode")

    def test_record_appends_so_earlier_entries_survive(self):
        audit.record(self.log_path, self.sample("10.0.0.0/24"))
        audit.record(self.log_path, self.sample("10.0.1.0/24"))

        self.assertEqual([e["scope"] for e in self.entries()], ["10.0.0.0/24", "10.0.1.0/24"])

    def test_each_entry_is_one_json_object_on_one_line(self):
        audit.record(self.log_path, self.sample())

        lines = self.lines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["scope"], "10.0.0.0/24")

    def test_to_line_is_exactly_what_record_writes(self):
        entry = self.sample()
        audit.record(self.log_path, entry)

        self.assertEqual(self.lines(), [audit.to_line(entry)])

    def test_record_raises_when_the_path_cannot_be_opened(self):
        blocker = self.tmp / "blocker"
        blocker.mkdir()

        with self.assertRaises(audit.LogError):
            audit.record(blocker, self.sample())

    def test_record_raises_when_the_entry_cannot_be_encoded(self):
        with self.assertRaises(audit.LogError):
            audit.record(self.log_path, {"scope": {"a set is not JSON": {1, 2}}})


class TestRead(AuditTestCase):
    def test_a_missing_file_reads_as_empty(self):
        entries, skipped = audit.read(self.log_path)

        self.assertEqual(entries, [])
        self.assertEqual(skipped, 0)

    def test_unreadable_lines_are_skipped_and_counted(self):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text(
            json.dumps(self.sample()) + "\n" + "{not json\n" + json.dumps(self.sample()) + "\n",
            encoding="utf-8",
        )

        entries, skipped = audit.read(self.log_path)

        self.assertEqual(len(entries), 2)
        self.assertEqual(skipped, 1)

    def test_a_line_that_is_not_an_object_is_skipped(self):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text('[1, 2, 3]\n', encoding="utf-8")

        entries, skipped = audit.read(self.log_path)

        self.assertEqual(entries, [])
        self.assertEqual(skipped, 1)

    def test_blank_lines_are_neither_entries_nor_skips(self):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text("\n\n" + json.dumps(self.sample()) + "\n\n", encoding="utf-8")

        entries, skipped = audit.read(self.log_path)

        self.assertEqual(len(entries), 1)
        self.assertEqual(skipped, 0)

    def test_entries_come_back_oldest_first(self):
        for scope in ("10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"):
            audit.record(self.log_path, self.sample(scope))

        entries, _ = audit.read(self.log_path)

        self.assertEqual([e["scope"] for e in entries],
                         ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"])

    def test_limit_keeps_the_newest_entries_in_order(self):
        for index in range(5):
            audit.record(self.log_path, self.sample(f"10.0.{index}.0/24"))

        entries, _ = audit.read(self.log_path, limit=2)

        self.assertEqual([e["scope"] for e in entries], ["10.0.3.0/24", "10.0.4.0/24"])


class TestLaunchEntry(AuditTestCase):
    def test_a_launch_entry_records_the_scope_and_the_enforcement_flag(self):
        entry = audit.launch_entry(
            "10.0.0.0/24", enforced=False, mcp_json=self.tmp / ".mcp.json", kimi="/usr/bin/kimi"
        )

        self.assertEqual(entry["v"], audit.ENTRY_VERSION)
        self.assertEqual(entry["event"], "launch")
        self.assertEqual(entry["scope"], "10.0.0.0/24")
        self.assertIs(entry["enforced"], False)
        self.assertEqual(entry["mcp_json"], str(self.tmp / ".mcp.json"))
        self.assertEqual(entry["kimi"], "/usr/bin/kimi")
        self.assertEqual(entry["cwd"], str(self.tmp))
        self.assertEqual(entry["pid"], os.getpid())

    def test_an_absent_target_is_recorded_as_json_null_not_as_a_string(self):
        entry = audit.launch_entry("solo", enforced=False, mcp_json=None, kimi="kimi")

        self.assertIsNone(entry["mcp_json"])
        audit.record(self.log_path, entry)
        self.assertIsNone(self.entries()[0]["mcp_json"])

    def test_the_timestamp_is_utc(self):
        entry = audit.launch_entry("solo", enforced=True, mcp_json=None, kimi="kimi")

        self.assertTrue(entry["at"].endswith("Z"), entry["at"])
        self.assertRegex(entry["at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class TestRunRecordsTheLaunch(AuditTestCase):
    def test_a_real_launch_is_recorded(self):
        self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        proc = self.run_cli(["-s", "10.0.0.0/24", "-y"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        entries = self.entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["scope"], "10.0.0.0/24")
        self.assertIs(entries[0]["enforced"], True)

    def test_the_recorded_target_is_the_file_that_was_written(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        self.run_cli(["-s", "10.0.0.0/24", "-y"])

        self.assertEqual(self.entries()[0]["mcp_json"], str(path))

    def test_a_scope_rejected_before_launching_records_nothing(self):
        self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        proc = self.run_cli(["-s", "not a scope", "-y"])

        self.assertEqual(proc.returncode, EXIT_USAGE, proc.stderr)
        self.assertEqual(self.lines(), [])

    def test_a_dry_run_records_nothing(self):
        self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        code, _, err = self.call_main(["-s", "10.0.0.0/24", "-y", "--dry-run"])

        self.assertEqual(code, EXIT_OK, err)
        self.assertEqual(self.lines(), [])

    def test_no_audit_records_nothing(self):
        self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        proc = self.run_cli(["-s", "10.0.0.0/24", "-y", "--no-audit"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertEqual(self.lines(), [])

    def test_audit_disabled_in_the_config_records_nothing(self):
        self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        self.write_config("audit = false\n")

        proc = self.run_cli(["-s", "10.0.0.0/24", "-y"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertEqual(self.lines(), [])

    def test_allow_unscoped_is_recorded_as_not_enforced(self):
        proc = self.run_cli(["-s", "solo", "-y", "--allow-unscoped"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        entry = self.entries()[0]
        self.assertIs(entry["enforced"], False)
        self.assertIsNone(entry["mcp_json"])

    def test_no_write_is_recorded_as_not_enforced(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        proc = self.run_cli(["-s", "10.0.0.0/24", "-y", "--no-write"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        entry = self.entries()[0]
        self.assertIs(entry["enforced"], False)
        self.assertEqual(entry["mcp_json"], str(path))

    def test_a_missing_kimi_binary_records_nothing(self):
        self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        with mock.patch.dict(
            os.environ, {"EVILKIT_KIMI_BIN": str(self.tmp / "env" / "absent")}
        ):
            code, _, err = self.call_main(["-s", "10.0.0.0/24", "-y"])

        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("cannot find the Kimi Code CLI", err)
        self.assertEqual(self.lines(), [])

    def test_a_log_that_cannot_be_written_does_not_stop_the_launch(self):
        self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        blocker = self.tmp / "blocker"
        blocker.write_text("not a directory\n", encoding="utf-8")
        self.write_config(f'audit_path = "{blocker}/launches.jsonl"\n')

        proc = self.run_cli(["-s", "10.0.0.0/24", "-y"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertIn("could not record this launch", proc.stderr)
        self.assertEqual(self.scope_in(self.tmp / ".mcp.json"), "10.0.0.0/24")

    def test_a_configured_audit_path_is_used(self):
        self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        target = self.tmp / "elsewhere" / "launches.jsonl"
        self.write_config(f'audit_path = "{target}"\n')

        proc = self.run_cli(["-s", "10.0.0.0/24", "-y"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertEqual([e["scope"] for e in self.entries(target)], ["10.0.0.0/24"])
        self.assertEqual(self.lines(), [])


class TestLogCommand(AuditTestCase):
    def test_log_prints_the_newest_entry_first(self):
        audit.record(self.log_path, self.sample("10.0.0.0/24"))
        audit.record(self.log_path, self.sample("10.0.1.0/24"))

        code, out, err = self.call_main(["log"])

        self.assertEqual(code, EXIT_OK, err)
        lines = out.splitlines()
        self.assertIn("10.0.1.0/24", lines[0])
        self.assertIn("10.0.0.0/24", lines[1])

    def test_log_names_the_enforcement_state(self):
        audit.record(self.log_path, self.sample("10.0.0.0/24", enforced=True))
        audit.record(self.log_path, self.sample("10.0.1.0/24", enforced=False))

        code, out, _ = self.call_main(["log"])

        self.assertEqual(code, EXIT_OK)
        lines = out.splitlines()
        self.assertIn("NOT enforced", lines[0])
        self.assertIn("10.0.0.0/24  enforced", lines[1])

    def test_log_limit_shows_only_the_newest(self):
        for index in range(5):
            audit.record(self.log_path, self.sample(f"10.0.{index}.0/24"))

        code, out, _ = self.call_main(["log", "--limit", "2"])

        self.assertEqual(code, EXIT_OK)
        self.assertEqual(len(out.splitlines()), 2)
        self.assertIn("10.0.4.0/24", out)

    def test_log_limit_zero_shows_everything(self):
        for index in range(5):
            audit.record(self.log_path, self.sample(f"10.0.{index}.0/24"))

        code, out, _ = self.call_main(["log", "--limit", "0"])

        self.assertEqual(code, EXIT_OK)
        self.assertEqual(len(out.splitlines()), 5)

    def test_log_json_reproduces_the_stored_lines_verbatim(self):
        audit.record(self.log_path, self.sample("10.0.0.0/24"))
        audit.record(self.log_path, self.sample("10.0.1.0/24"))

        code, out, err = self.call_main(["log", "--json"])

        self.assertEqual(code, EXIT_OK, err)
        self.assertEqual(out.splitlines(), self.lines())
        self.assertEqual([e["scope"] for e in self.entries()], ["10.0.0.0/24", "10.0.1.0/24"])

    def test_log_without_a_log_yet_exits_zero_and_says_so(self):
        code, out, err = self.call_main(["log"])

        self.assertEqual(code, EXIT_OK, err)
        self.assertIn("no launches recorded yet", out)
        self.assertIn(str(self.log_path), out)

    def test_log_accepts_an_explicit_path(self):
        target = self.tmp / "other.jsonl"
        audit.record(target, self.sample("10.9.0.0/16"))

        code, out, _ = self.call_main(["log", "--path", str(target)])

        self.assertEqual(code, EXIT_OK)
        self.assertIn("10.9.0.0/16", out)

    def test_log_reports_skipped_lines_on_stderr(self):
        audit.record(self.log_path, self.sample("10.0.0.0/24"))
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write("{truncated\n")

        code, out, err = self.call_main(["log"])

        self.assertEqual(code, EXIT_OK)
        self.assertIn("10.0.0.0/24", out)
        self.assertIn("unreadable line", err)

    def test_log_reads_a_configured_path(self):
        target = self.tmp / "configured.jsonl"
        audit.record(target, self.sample("10.5.0.0/16"))
        self.write_config(f'audit_path = "{target}"\n')

        code, out, _ = self.call_main(["log"])

        self.assertEqual(code, EXIT_OK)
        self.assertIn("10.5.0.0/16", out)


class TestDoctorAndConfigReportTheLog(AuditTestCase):
    def test_doctor_reports_the_log_path_and_the_last_launch(self):
        audit.record(self.log_path, self.sample("10.0.0.0/24"))

        code, out, _ = self.call_main(["doctor"])

        self.assertEqual(code, EXIT_OK)
        self.assertIn(str(self.log_path), out)
        self.assertIn("last launch", out)

    def test_doctor_reports_an_empty_log_as_empty(self):
        code, out, _ = self.call_main(["doctor"])

        self.assertEqual(code, EXIT_OK)
        self.assertIn("nothing recorded yet", out)

    def test_doctor_reports_a_disabled_log(self):
        self.write_config("audit = false\n")

        code, out, _ = self.call_main(["doctor"])

        self.assertEqual(code, EXIT_OK)
        self.assertIn("audit log          : disabled", out)

    def test_config_show_reports_the_audit_settings(self):
        code, out, _ = self.call_main(["config", "show"])

        self.assertEqual(code, EXIT_OK)
        self.assertIn("audit           = true", out)
        self.assertIn("audit_path      = ", out)
        self.assertIn("(default)", out)

    def test_config_show_names_a_configured_audit_path(self):
        target = self.tmp / "configured.jsonl"
        self.write_config(f'audit_path = "{target}"\n')

        code, out, _ = self.call_main(["config", "show"])

        self.assertEqual(code, EXIT_OK)
        self.assertIn(f"audit_path      = {target}", out)
        self.assertNotIn("(default)", out)

    def test_an_invalid_audit_value_is_warned_about_and_defaulted(self):
        self.write_config('audit = "yes"\n')

        code, out, err = self.call_main(["config", "show"])

        self.assertEqual(code, EXIT_OK)
        self.assertIn("audit must be true or false", err)
        self.assertIn("audit           = true", out)

    def test_config_init_writes_the_audit_keys(self):
        code, out, err = self.call_main(["config", "init"])

        self.assertEqual(code, EXIT_OK, err)
        written = self.config_file.read_text(encoding="utf-8")
        self.assertIn("audit = true", written)
        self.assertIn("audit_path = ", written)


if __name__ == "__main__":
    unittest.main()

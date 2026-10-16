"""Tests for evilkit.mcpscope — reading and atomically updating .mcp.json."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import DENY_ENV_KEY, PROJECT_ROOT, EvilkitTestCase  # noqa: E402

from evilkit import mcpscope  # noqa: E402

BACKUP_NAME_RE = re.compile(r"^\.mcp\.json\.\d{8}-\d{6}\.bak$")
LOCK_NAME = ".mcp.json.lock"


class McpscopeTestCase(EvilkitTestCase):
    def backups(self, directory=None):
        return sorted(p.name for p in (directory or self.tmp).glob(".mcp.json*.bak"))

    def staging(self, directory=None):
        """Every mkstemp staging file, so a leaked one cannot hide."""
        return sorted(p.name for p in (directory or self.tmp).glob(".mcp.json.*.new"))

    def mcp_family(self, directory=None):
        """Every .mcp.json* entry except the expected sidecar lock file."""
        return sorted(
            p.name
            for p in (directory or self.tmp).glob(".mcp.json*")
            if p.name != ".mcp.json.lock"
        )


class TestReadScope(McpscopeTestCase):
    def test_scope_env_key_name_is_the_documented_one(self):
        self.assertEqual(mcpscope.SCOPE_ENV_KEY, "PENTEST_ALLOWED_TARGETS")

    def test_returns_the_recorded_scope(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        self.assertEqual(mcpscope.read_scope(path), "10.0.0.0/24")

    def test_returns_none_for_every_incomplete_fixture(self):
        cases = {
            "no mcpServers": {"other": 1},
            "mcpServers not an object": {"mcpServers": []},
            "no pentest server": {"mcpServers": {"mission": {"command": "x"}}},
            "pentest is not an object": {"mcpServers": {"pentest": "nope"}},
            "no env block": {"mcpServers": {"pentest": {"command": "x"}}},
            "env is not an object": {"mcpServers": {"pentest": {"env": []}}},
            "env has no scope key": {"mcpServers": {"pentest": {"env": {"OTHER": "1"}}}},
            "scope is not a string": {
                "mcpServers": {"pentest": {"env": {mcpscope.SCOPE_ENV_KEY: 5}}}
            },
        }
        for name, data in cases.items():
            with self.subTest(case=name):
                path = self.write_mcp_json(data, name=".mcp.json")
                self.assertIsNone(mcpscope.read_scope(path))

    def test_missing_file_raises(self):
        with self.assertRaises(mcpscope.McpError):
            mcpscope.read_scope(self.tmp / "absent.json")

    def test_invalid_json_raises(self):
        path = self.tmp / ".mcp.json"
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(mcpscope.McpError):
            mcpscope.read_scope(path)

    def test_json_that_is_not_an_object_raises(self):
        path = self.tmp / ".mcp.json"
        path.write_text("[1, 2, 3]", encoding="utf-8")
        with self.assertRaises(mcpscope.McpError):
            mcpscope.read_scope(path)

    def test_exception_hierarchy(self):
        self.assertTrue(issubclass(mcpscope.McpNotFound, mcpscope.McpError))
        self.assertTrue(issubclass(mcpscope.NoPentestServer, mcpscope.McpError))


class TestReadDeny(McpscopeTestCase):
    def test_deny_env_key_name_is_the_documented_one(self):
        self.assertEqual(mcpscope.DENY_ENV_KEY, "PENTEST_DENIED_TARGETS")

    def test_returns_the_recorded_deny_list(self):
        path = self.write_mcp_json(self.deny_fixture("10.0.0.0/24", deny="10.0.0.9/32"))
        self.assertEqual(mcpscope.read_deny(path), "10.0.0.9/32")

    def test_returns_none_when_no_deny_key_is_recorded(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        self.assertIsNone(mcpscope.read_deny(path))

    def test_an_empty_string_is_a_recorded_answer_not_a_missing_one(self):
        path = self.write_mcp_json(self.deny_fixture("10.0.0.0/24", deny=""))
        self.assertEqual(mcpscope.read_deny(path), "")

    def test_returns_none_for_every_incomplete_fixture(self):
        cases = {
            "no mcpServers": {"other": 1},
            "no pentest server": {"mcpServers": {"mission": {"command": "x"}}},
            "no env block": {"mcpServers": {"pentest": {"command": "x"}}},
            "env is not an object": {"mcpServers": {"pentest": {"env": []}}},
            "deny is not a string": {
                "mcpServers": {"pentest": {"env": {mcpscope.DENY_ENV_KEY: ["10.0.0.9"]}}}
            },
        }
        for name, data in cases.items():
            with self.subTest(case=name):
                path = self.write_mcp_json(data, name=".mcp.json")
                self.assertIsNone(mcpscope.read_deny(path))

    def test_missing_file_raises(self):
        with self.assertRaises(mcpscope.McpError):
            mcpscope.read_deny(self.tmp / "absent.json")

    def test_invalid_json_raises(self):
        path = self.tmp / ".mcp.json"
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(mcpscope.McpError):
            mcpscope.read_deny(path)


class TestWriteDeny(McpscopeTestCase):
    """``PENTEST_DENIED_TARGETS`` is a second key, on the same terms."""

    def env_in(self, path):
        return json.loads(path.read_text(encoding="utf-8"))["mcpServers"]["pentest"]["env"]

    def test_a_deny_list_is_written_beside_the_scope(self):
        path = self.write_mcp_json(self.deny_fixture("127.0.0.1/32"))

        self.assertTrue(
            mcpscope.write_scope(path, "10.0.0.0/24", keep_backups=5, deny="10.0.0.9/32")
        )

        env = self.env_in(path)
        self.assertEqual(env[mcpscope.SCOPE_ENV_KEY], "10.0.0.0/24")
        self.assertEqual(env[mcpscope.DENY_ENV_KEY], "10.0.0.9/32")
        self.assertEqual(env["OTHER_ENV"], "keep-me")
        self.assertEqual(env["NUMERIC"], 7)
        self.assertEqual(mcpscope.read_deny(path), "10.0.0.9/32")

    def test_an_omitted_deny_is_left_untouched_when_the_scope_changes(self):
        path = self.write_mcp_json(self.deny_fixture("127.0.0.1/32", deny="10.0.0.9/32"))

        self.assertTrue(mcpscope.write_scope(path, "10.0.0.0/24"))

        self.assertEqual(mcpscope.read_scope(path), "10.0.0.0/24")
        self.assertEqual(mcpscope.read_deny(path), "10.0.0.9/32")

    def test_an_omitted_deny_with_an_unchanged_scope_writes_nothing(self):
        path = self.write_mcp_json(self.deny_fixture("10.0.0.0/24", deny="10.0.0.9/32"))
        before = path.read_bytes()

        self.assertFalse(mcpscope.write_scope(path, "10.0.0.0/24", keep_backups=5))

        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_a_deny_only_change_is_written_and_backed_up(self):
        path = self.write_mcp_json(self.deny_fixture("10.0.0.0/24", deny="10.0.0.9/32"))

        self.assertTrue(
            mcpscope.write_scope(path, "10.0.0.0/24", keep_backups=5, deny="10.0.0.10/32")
        )

        self.assertEqual(mcpscope.read_scope(path), "10.0.0.0/24")
        self.assertEqual(mcpscope.read_deny(path), "10.0.0.10/32")
        names = self.backups()
        self.assertEqual(len(names), 1)
        backup = json.loads((self.tmp / names[0]).read_text(encoding="utf-8"))
        self.assertEqual(
            backup["mcpServers"]["pentest"]["env"][mcpscope.DENY_ENV_KEY], "10.0.0.9/32"
        )

    def test_both_keys_matching_returns_false(self):
        path = self.write_mcp_json(self.deny_fixture("10.0.0.0/24", deny="10.0.0.9/32"))
        before = path.read_bytes()

        self.assertFalse(
            mcpscope.write_scope(path, "10.0.0.0/24", keep_backups=5, deny="10.0.0.9/32")
        )

        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_an_empty_deny_records_no_denied_targets(self):
        path = self.write_mcp_json(self.deny_fixture("10.0.0.0/24", deny="10.0.0.9/32"))

        self.assertTrue(mcpscope.write_scope(path, "10.0.0.0/24", deny=""))

        self.assertEqual(mcpscope.read_deny(path), "")

    def test_a_deny_only_change_in_a_dry_run_reports_a_change_and_writes_nothing(self):
        path = self.write_mcp_json(self.deny_fixture("10.0.0.0/24", deny="10.0.0.9/32"))
        before = path.read_bytes()

        self.assertTrue(
            mcpscope.write_scope(path, "10.0.0.0/24", dry_run=True, deny="10.0.0.10/32")
        )

        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_a_deny_list_can_be_added_to_a_file_that_has_none(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))

        self.assertTrue(mcpscope.write_scope(path, "10.0.0.0/24", deny="10.0.0.9/32"))

        self.assertEqual(mcpscope.read_deny(path), "10.0.0.9/32")
        self.assertEqual(self.env_in(path)["OTHER_ENV"], "keep-me")


class TestWriteScope(McpscopeTestCase):
    def test_updates_only_the_pentest_scope(self):
        fixture = self.pentest_fixture("10.0.0.0/24")
        path = self.write_mcp_json(fixture)

        self.assertTrue(mcpscope.write_scope(path, "10.0.0.0/8", keep_backups=5))

        after = json.loads(path.read_text(encoding="utf-8"))
        expected = json.loads(json.dumps(fixture))
        expected["mcpServers"]["pentest"]["env"][mcpscope.SCOPE_ENV_KEY] = "10.0.0.0/8"
        self.assertEqual(after, expected)
        self.assertEqual(after["mcpServers"]["mission"], fixture["mcpServers"]["mission"])
        self.assertEqual(after["topLevel"], fixture["topLevel"])
        self.assertEqual(mcpscope.read_scope(path), "10.0.0.0/8")

    def test_creates_an_env_block_when_the_server_has_none(self):
        path = self.write_mcp_json(
            {"mcpServers": {"pentest": {"command": "python3", "args": ["-m", "srv"]}}}
        )
        self.assertTrue(mcpscope.write_scope(path, "10.0.0.0/8"))
        after = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(after["mcpServers"]["pentest"]["env"], {mcpscope.SCOPE_ENV_KEY: "10.0.0.0/8"})
        self.assertEqual(after["mcpServers"]["pentest"]["command"], "python3")

    def test_unchanged_scope_returns_false_and_writes_nothing(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        before = path.read_bytes()
        self.assertFalse(mcpscope.write_scope(path, "10.0.0.0/24", keep_backups=5))
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_successful_write_leaves_no_staging_file_behind(self):
        path = self.write_mcp_json(self.pentest_fixture())
        mcpscope.write_scope(path, "10.0.0.0/8")
        self.assertFalse((self.tmp / ".mcp.json.new").exists())
        self.assertEqual(self.staging(), [])
        self.assertEqual(self.mcp_family(), [".mcp.json", *self.backups()])

    def test_missing_pentest_server_raises_and_leaves_the_file_untouched(self):
        path = self.write_mcp_json({"mcpServers": {"mission": {"command": "x"}}})
        before = path.read_bytes()
        with self.assertRaises(mcpscope.NoPentestServer):
            mcpscope.write_scope(path, "10.0.0.0/8")
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_mcp_servers_of_the_wrong_type_raises(self):
        path = self.write_mcp_json({"mcpServers": ["not", "an", "object"]})
        before = path.read_bytes()
        with self.assertRaises(mcpscope.McpError):
            mcpscope.write_scope(path, "10.0.0.0/8")
        self.assertEqual(path.read_bytes(), before)

    def test_invalid_json_on_disk_raises_and_leaves_no_staging_file(self):
        path = self.tmp / ".mcp.json"
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(mcpscope.McpError):
            mcpscope.write_scope(path, "10.0.0.0/8")
        self.assertEqual(path.read_text(encoding="utf-8"), "{not json")
        self.assertEqual(self.mcp_family(), [".mcp.json"])

    def test_missing_file_raises(self):
        with self.assertRaises(mcpscope.McpError):
            mcpscope.write_scope(self.tmp / "absent.json", "10.0.0.0/8")

    def test_a_failed_replacement_leaves_the_original_intact(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        before = path.read_bytes()

        def failing_replace(src, dst):
            raise OSError("simulated failure")

        with mock.patch("os.replace", side_effect=failing_replace):
            with self.assertRaises(mcpscope.McpError):
                mcpscope.write_scope(path, "10.0.0.0/8")

        # The original is copied aside, never moved, so it survives the failure.
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.staging(), [])
        self.assertEqual(mcpscope.read_scope(path), "10.0.0.0/24")

    def test_the_original_is_never_moved_out_of_the_way(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        real_replace = os.replace
        calls = []

        def watching_replace(src, dst):
            calls.append((str(src), str(dst)))
            return real_replace(src, dst)

        with mock.patch("os.replace", side_effect=watching_replace):
            mcpscope.write_scope(path, "10.0.0.0/8")

        # Exactly one atomic replace, and the target is never the source: there
        # is therefore no instant at which .mcp.json does not exist.
        self.assertEqual(len(calls), 1)
        source, destination = calls[0]
        self.assertNotEqual(source, str(path))
        self.assertTrue(source.endswith(".new"), source)
        self.assertEqual(destination, str(path))
        self.assertEqual(mcpscope.read_scope(path), "10.0.0.0/8")


class TestStagingFileSafety(McpscopeTestCase):
    """The staging file must be unpredictable and must never outlive the write."""

    def test_a_symlink_at_the_old_staging_name_cannot_redirect_the_write(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        victim = self.tmp / "victim.txt"
        secret = b"# authorized_keys\nssh-ed25519 AAAA...\n"
        victim.write_bytes(secret)
        planted = self.tmp / ".mcp.json.new"
        planted.symlink_to(victim)

        self.assertTrue(mcpscope.write_scope(path, "10.0.0.0/8"))

        self.assertEqual(victim.read_bytes(), secret)
        self.assertEqual(victim.stat().st_size, len(secret))
        self.assertTrue(planted.is_symlink())
        self.assertFalse(path.is_symlink())
        self.assertEqual(mcpscope.read_scope(path), "10.0.0.0/8")
        self.assertEqual(self.staging(), [])

    def test_no_staging_file_survives_success(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        mcpscope.write_scope(path, "10.0.0.0/8")
        self.assertEqual(self.staging(), [])

    def test_no_staging_file_survives_a_failed_write(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        before = path.read_bytes()

        def failing_replace(src, dst):
            raise OSError("simulated failure")

        with mock.patch("os.replace", side_effect=failing_replace):
            with self.assertRaises(mcpscope.McpError):
                mcpscope.write_scope(path, "10.0.0.0/8")

        self.assertEqual(self.staging(), [])
        self.assertEqual(path.read_bytes(), before)
        self.assertTrue((self.tmp / LOCK_NAME).is_file())

    def test_a_failing_backup_removes_the_staging_file(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        def failing_copy(src, dst, **kwargs):
            raise OSError("simulated failure")

        with mock.patch("shutil.copy2", side_effect=failing_copy):
            with self.assertRaises(mcpscope.McpError):
                mcpscope.write_scope(path, "10.0.0.0/8")
        self.assertEqual(self.staging(), [])
        self.assertEqual(mcpscope.read_scope(path), "127.0.0.1/32")


class TestWritePreservesTheMode(McpscopeTestCase):
    def test_a_hardened_file_stays_hardened(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        path.chmod(0o600)

        mcpscope.write_scope(path, "10.0.0.0/8")

        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(mcpscope.read_scope(path), "10.0.0.0/8")

    def test_a_group_readable_file_keeps_its_mode(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        path.chmod(0o640)

        mcpscope.write_scope(path, "10.0.0.0/8")

        self.assertEqual(path.stat().st_mode & 0o777, 0o640)


class TestUnreadablePayloads(McpscopeTestCase):
    def test_invalid_utf8_raises_the_module_error(self):
        path = self.tmp / ".mcp.json"
        path.write_bytes(b'{"mcpServers": {"pentest": "\xff\xfe"}}')
        with self.assertRaises(mcpscope.McpError):
            mcpscope.read_scope(path)
        with self.assertRaises(mcpscope.McpError):
            mcpscope.write_scope(path, "10.0.0.0/8")

    def test_deeply_nested_json_raises_the_module_error(self):
        path = self.tmp / ".mcp.json"
        path.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
        with self.assertRaises(mcpscope.McpError):
            mcpscope.read_scope(path)
        with self.assertRaises(mcpscope.McpError):
            mcpscope.write_scope(path, "10.0.0.0/8")

    def test_an_unreadable_file_raises_the_module_error(self):
        path = self.write_mcp_json(self.pentest_fixture())
        path.chmod(0o000)
        if os.access(path, os.R_OK):  # a privileged user can still read it
            self.skipTest("running as a user that ignores file modes")
        with self.assertRaises(mcpscope.McpError):
            mcpscope.read_scope(path)


class TestConcurrentWriters(McpscopeTestCase):
    #: One write_scope call in a fresh interpreter, so the writers are genuinely
    #: separate processes and the flock has to do the serialising.
    WRITER = """\
import sys
from pathlib import Path
from evilkit.mcpscope import write_scope
write_scope(Path(sys.argv[1]), sys.argv[2], keep_backups=3)
"""

    def test_concurrent_writes_all_succeed_and_leave_a_valid_file(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        scopes = [f"10.0.{n}.0/24" for n in range(1, 9)]

        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [str(PROJECT_ROOT), env.get("PYTHONPATH", "")]
        ).strip(os.pathsep)
        procs = [
            subprocess.Popen(
                [sys.executable, "-c", self.WRITER, str(path), scope],
                cwd=str(self.tmp),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for scope in scopes
        ]
        results = [(proc.wait(), proc.communicate()) for proc in procs]

        for code, (out, err) in results:
            self.assertEqual(code, 0, f"writer failed: {out}{err}")
        recorded = mcpscope.read_scope(path)
        self.assertIn(recorded, scopes)
        self.assertIsInstance(json.loads(path.read_text(encoding="utf-8")), dict)
        self.assertEqual(self.staging(), [])

    def test_the_lock_file_sits_beside_the_target(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        mcpscope.write_scope(path, "10.0.0.0/8")
        self.assertTrue((self.tmp / LOCK_NAME).is_file())

    def test_a_dry_run_creates_no_lock_file(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        mcpscope.write_scope(path, "10.0.0.0/8", dry_run=True)
        self.assertFalse((self.tmp / LOCK_NAME).exists())


class TestBackups(McpscopeTestCase):
    def test_backup_uses_a_timestamped_name_and_holds_the_previous_content(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        mcpscope.write_scope(path, "10.0.0.0/8")
        names = self.backups()
        self.assertEqual(len(names), 1)
        self.assertRegex(names[0], BACKUP_NAME_RE)
        backup = json.loads((self.tmp / names[0]).read_text(encoding="utf-8"))
        self.assertEqual(backup["mcpServers"]["pentest"]["env"][mcpscope.SCOPE_ENV_KEY], "10.0.0.0/24")
        self.assertEqual(mcpscope.read_scope(path), "10.0.0.0/8")

    def test_keep_backups_zero_creates_no_backup(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        self.assertTrue(mcpscope.write_scope(path, "10.0.0.0/8", keep_backups=0))
        self.assertEqual(self.backups(), [])
        self.assertEqual(mcpscope.read_scope(path), "10.0.0.0/8")

    def test_keep_backups_bounds_the_history_and_drops_the_oldest(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        older = [f".mcp.json.2020010{n}-000000.bak" for n in range(1, 6)]
        for name in older:
            (self.tmp / name).write_text("{}", encoding="utf-8")

        mcpscope.write_scope(path, "10.0.0.0/8", keep_backups=3)

        survivors = self.backups()
        self.assertEqual(len(survivors), 3)
        self.assertEqual(survivors[:2], older[-2:])
        self.assertNotIn(older[0], survivors)
        self.assertNotIn(older[1], survivors)
        self.assertRegex(survivors[-1], BACKUP_NAME_RE)

    def test_prune_backups_keeps_the_newest_and_reports_what_it_removed(self):
        path = self.write_mcp_json(self.pentest_fixture())
        names = [f".mcp.json.2020010{n}-000000.bak" for n in range(1, 5)]
        for name in names:
            (self.tmp / name).write_text("{}", encoding="utf-8")

        removed = mcpscope.prune_backups(path, 2)

        self.assertEqual([p.name for p in removed], names[:2])
        self.assertEqual(self.backups(), names[2:])

    def test_a_glob_metacharacter_in_the_name_does_not_touch_another_file(self):
        path = self.write_mcp_json(self.pentest_fixture(), name="x[ab].json")
        unrelated = self.tmp / "xa.json.20200101-000000.bak"
        unrelated.write_text("{}", encoding="utf-8")
        mine = self.tmp / "x[ab].json.20200101-000000.bak"
        mine.write_text("{}", encoding="utf-8")

        mcpscope.prune_backups(path, 0)

        self.assertFalse(mine.exists())
        self.assertTrue(unrelated.exists())
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "{}")

    def test_prune_backups_leaves_everything_when_within_the_limit(self):
        path = self.write_mcp_json(self.pentest_fixture())
        (self.tmp / ".mcp.json.20200101-000000.bak").write_text("{}", encoding="utf-8")
        self.assertEqual(mcpscope.prune_backups(path, 5), [])
        self.assertEqual(len(self.backups()), 1)

    def test_prune_backups_with_zero_removes_all_history(self):
        path = self.write_mcp_json(self.pentest_fixture())
        for n in range(3):
            (self.tmp / f".mcp.json.2020010{n + 1}-000000.bak").write_text("{}", encoding="utf-8")
        self.assertEqual(len(mcpscope.prune_backups(path, 0)), 3)
        self.assertEqual(self.backups(), [])

    def test_prune_backups_ignores_negative_keep(self):
        path = self.write_mcp_json(self.pentest_fixture())
        (self.tmp / ".mcp.json.20200101-000000.bak").write_text("{}", encoding="utf-8")
        self.assertEqual(mcpscope.prune_backups(path, -1), [])
        self.assertEqual(len(self.backups()), 1)

    def test_looks_like_backup(self):
        self.assertTrue(mcpscope.looks_like_backup(self.tmp / ".mcp.json.20260916-113522.bak"))
        self.assertFalse(mcpscope.looks_like_backup(self.tmp / ".mcp.json"))
        self.assertFalse(mcpscope.looks_like_backup(self.tmp / ".mcp.json.bak"))
        self.assertFalse(mcpscope.looks_like_backup(self.tmp / ".mcp.json.20260916.bak"))


class TestFind(McpscopeTestCase):
    def test_finds_a_file_in_the_current_directory(self):
        path = self.write_mcp_json(self.pentest_fixture())
        self.assertEqual(mcpscope.find(), path)
        self.assertEqual(mcpscope.find(self.tmp), path)

    def test_walks_up_to_a_parent_directory(self):
        top = self.tmp / "project"
        top.mkdir()
        marker = self.write_mcp_json(self.pentest_fixture(), directory=top)
        deep = top / "a" / "b" / "c"
        deep.mkdir(parents=True)
        self.assertEqual(mcpscope.find(deep), marker)

    def test_returns_the_nearest_file(self):
        top = self.tmp / "project"
        nested = top / "nested"
        nested.mkdir(parents=True)
        self.write_mcp_json(self.pentest_fixture(), directory=top)
        near = self.write_mcp_json(self.pentest_fixture(), directory=nested)
        self.assertEqual(mcpscope.find(nested), near)

    def test_raises_when_there_is_no_file_anywhere_above(self):
        # /tmp and / hold no .mcp.json on this host, so the temp dir is a clean
        # starting point for the "not found" case.
        deep = self.tmp / "a" / "b"
        deep.mkdir(parents=True)
        with self.assertRaises(mcpscope.McpNotFound):
            mcpscope.find(deep)


class TestSymlinkRefusal(McpscopeTestCase):
    def test_write_refuses_a_symlinked_target(self):
        real = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"), name="real.json")
        link = self.tmp / ".mcp.json"
        link.symlink_to(real)
        with self.assertRaises(mcpscope.McpError):
            mcpscope.write_scope(link, "10.0.0.0/8")
        # The link target keeps its original scope: nothing was written through it.
        self.assertEqual(mcpscope.read_scope(real), "10.0.0.0/24")


class TestEnsureOsintServer(McpscopeTestCase):
    COMMAND = ["/opt/osint/venv/bin/python", "/opt/osint/server.py"]

    def test_adds_the_server_alongside_the_pentest_scope(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        self.assertTrue(mcpscope.ensure_osint_server(path, self.COMMAND))
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["mcpServers"]["osint"],
                         {"type": "stdio", "command": self.COMMAND[0],
                          "args": self.COMMAND[1:]})
        # The pentest server is untouched.
        self.assertEqual(mcpscope.read_scope(path), "10.0.0.0/24")
        self.assertEqual(data["mcpServers"]["pentest"]["env"]["OTHER_ENV"], "keep-me")
        self.assertEqual(len(self.backups()), 1)

    def test_idempotent_when_the_entry_already_matches(self):
        path = self.write_mcp_json(self.pentest_fixture())
        mcpscope.ensure_osint_server(path, self.COMMAND)
        before = path.read_text(encoding="utf-8")
        self.assertFalse(mcpscope.ensure_osint_server(path, self.COMMAND))
        self.assertEqual(path.read_text(encoding="utf-8"), before)
        self.assertEqual(len(self.backups()), 1)  # only the first write

    def test_dry_run_reports_without_writing(self):
        path = self.write_mcp_json(self.pentest_fixture())
        self.assertTrue(mcpscope.ensure_osint_server(path, self.COMMAND, dry_run=True))
        self.assertNotIn("osint", json.loads(path.read_text(encoding="utf-8"))["mcpServers"])
        self.assertEqual(len(self.backups()), 0)

    def test_dry_run_false_when_already_present(self):
        path = self.write_mcp_json(self.pentest_fixture())
        mcpscope.ensure_osint_server(path, self.COMMAND)
        self.assertFalse(mcpscope.ensure_osint_server(path, self.COMMAND, dry_run=True))

    def test_works_without_a_pentest_server(self):
        # Additive: the osint entry never requires the pentest server.
        path = self.write_mcp_json({"mcpServers": {"other": {"command": "x"}}})
        self.assertTrue(mcpscope.ensure_osint_server(path, self.COMMAND))
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("osint", data["mcpServers"])

    def test_empty_command_is_refused(self):
        path = self.write_mcp_json(self.pentest_fixture())
        with self.assertRaises(mcpscope.McpError):
            mcpscope.ensure_osint_server(path, [])

    def test_a_different_command_is_recorded(self):
        path = self.write_mcp_json(self.pentest_fixture())
        mcpscope.ensure_osint_server(path, self.COMMAND)
        other = ["/elsewhere/python", "/elsewhere/server.py"]
        self.assertTrue(mcpscope.ensure_osint_server(path, other))
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["mcpServers"]["osint"]["command"], "/elsewhere/python")


class TestEnsureDashboardServer(McpscopeTestCase):
    COMMAND = ["/opt/venv/bin/python3", "-m", "evilkit.dashboard_mcp"]

    def kimi_path(self):
        return self.tmp / ".kimi-code" / "mcp.json"

    def kimi_backups(self):
        return sorted(p.name for p in (self.tmp / ".kimi-code").glob("mcp.json*.bak"))

    def test_it_creates_the_file_the_cli_reads_when_none_exists(self):
        # `.kimi-code/mcp.json` is what the Kimi CLI loads, and a repository need
        # not have one yet; the parent directory is created too.
        path = self.kimi_path()
        self.assertFalse(path.parent.exists())
        self.assertTrue(mcpscope.ensure_dashboard_server(path, self.COMMAND))
        self.assertEqual(
            json.loads(path.read_text(encoding="utf-8"))["mcpServers"]["dashboard"],
            {"type": "stdio", "command": self.COMMAND[0], "args": self.COMMAND[1:]},
        )

    def test_creating_the_file_leaves_no_backup_of_nothing(self):
        self.assertTrue(mcpscope.ensure_dashboard_server(self.kimi_path(), self.COMMAND))
        self.assertEqual(self.kimi_backups(), [])

    def test_it_adds_beside_the_pentest_server_and_preserves_it(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        self.assertTrue(mcpscope.ensure_dashboard_server(path, self.COMMAND))
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("dashboard", data["mcpServers"])
        self.assertEqual(mcpscope.read_scope(path), "10.0.0.0/24")
        self.assertEqual(data["mcpServers"]["pentest"]["env"]["OTHER_ENV"], "keep-me")
        self.assertEqual(len(self.backups()), 1)

    def test_idempotent_when_the_entry_already_matches(self):
        path = self.kimi_path()
        mcpscope.ensure_dashboard_server(path, self.COMMAND)
        before = path.read_text(encoding="utf-8")
        self.assertFalse(mcpscope.ensure_dashboard_server(path, self.COMMAND))
        self.assertEqual(path.read_text(encoding="utf-8"), before)
        self.assertEqual(self.kimi_backups(), [])  # only the file-creating write

    def test_dry_run_reports_without_writing(self):
        path = self.write_mcp_json(self.pentest_fixture())
        self.assertTrue(mcpscope.ensure_dashboard_server(path, self.COMMAND, dry_run=True))
        self.assertNotIn("dashboard", json.loads(path.read_text(encoding="utf-8"))["mcpServers"])
        self.assertEqual(self.backups(), [])

    def test_dry_run_would_create_the_file_it_reports(self):
        self.assertTrue(mcpscope.ensure_dashboard_server(self.kimi_path(), self.COMMAND, dry_run=True))
        self.assertFalse(self.kimi_path().exists())

    def test_dry_run_false_when_already_present(self):
        path = self.kimi_path()
        mcpscope.ensure_dashboard_server(path, self.COMMAND)
        self.assertFalse(mcpscope.ensure_dashboard_server(path, self.COMMAND, dry_run=True))

    def test_a_different_command_is_recorded(self):
        path = self.kimi_path()
        mcpscope.ensure_dashboard_server(path, self.COMMAND)
        other = ["/elsewhere/python3", "-m", "evilkit.dashboard_mcp"]
        self.assertTrue(mcpscope.ensure_dashboard_server(path, other))
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["mcpServers"]["dashboard"]["command"], "/elsewhere/python3")

    def test_empty_command_is_refused(self):
        with self.assertRaises(mcpscope.McpError):
            mcpscope.ensure_dashboard_server(self.kimi_path(), [])

    def test_a_symlinked_target_is_refused(self):
        real = self.write_mcp_json({"mcpServers": {}}, name="real.json")
        link = self.kimi_path()
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(real)
        with self.assertRaises(mcpscope.McpError):
            mcpscope.ensure_dashboard_server(link, self.COMMAND)
        # Nothing was written through the link, and it is still a link.
        self.assertEqual(json.loads(real.read_text(encoding="utf-8")), {"mcpServers": {}})
        self.assertTrue(link.is_symlink())

    def test_it_leaves_no_staging_file_behind(self):
        path = self.kimi_path()
        mcpscope.ensure_dashboard_server(path, self.COMMAND)
        self.assertEqual(sorted(p.name for p in path.parent.glob("mcp.json.*.new")), [])


if __name__ == "__main__":
    unittest.main()

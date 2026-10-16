"""Tests for the run profile and the preflight that spends it (SCORE-LIFT-PLAN §2).

A profile exists so that a missing tool, a mismatched scope, absent guest
credentials or an unreachable dashboard stops the launch — not a turn three
hours into a scored run. Each of those is one test here, plus the happy path.

The MCP registry is faked with a two-answer stdio server, so the checks are
exercised without starting the real (and remote) pentest server.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

from tests._helpers import EvilkitTestCase

from evilkit import config as config_mod
from evilkit import kimi, run_profile

FAKE_SERVER = '''
import json, sys

TOOLS = {tools!r}

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        message = json.loads(line)
    except ValueError:
        continue
    if message.get("method") == "initialize":
        print(json.dumps({{"jsonrpc": "2.0", "id": message["id"], "result": {{"protocolVersion": "2025-06-18", "capabilities": {{}}, "serverInfo": {{"name": "fake", "version": "0"}}}}}}), flush=True)
    elif message.get("method") == "tools/list":
        print(json.dumps({{"jsonrpc": "2.0", "id": message["id"], "result": {{"tools": [{{"name": n}} for n in TOOLS]}}}}), flush=True)
'''

PROFILE = """
name = "keystone-full"
scope = "10.99.50.0/24,10.50.0.0/24"
entry_host = "10.99.50.60"
required_servers = ["pentest"]
required_tools = ["nmap_scan", "malware_deploy"]
requires_lab_ssh = true
objectives = ["delivery", "persistence"]
topology = "DMZ 10.99.50.0/24; CORP 10.50.0.0/24 behind the pivot."
"""


class ProfileCase(EvilkitTestCase):
    def setUp(self):
        super().setUp()
        for key in ("LAB_SSH_USER", "LAB_SSH_PASS", "LAB_SSH_KEY"):
            os.environ.pop(key, None)

    # -- fixtures -----------------------------------------------------------

    def fake_server(self, tools=("nmap_scan", "malware_deploy", "ssh_tunnel")) -> Path:
        script = self.tmp / "fake-mcp.py"
        script.write_text(FAKE_SERVER.format(tools=list(tools)), encoding="utf-8")
        return script

    def declare_pentest(self, tools=("nmap_scan", "malware_deploy", "ssh_tunnel")) -> Path:
        script = self.fake_server(tools)
        mcp = {
            "mcpServers": {
                "pentest": {"command": sys.executable, "args": [str(script)],
                            "env": {"PENTEST_ALLOWED_TARGETS": "10.99.50.0/24"}},
            }
        }
        # The Kimi CLI reads $KIMI_CODE_HOME/mcp.json (or EVILKIMI_KIMI_MCP); a
        # project-level file would also be read, so keep the temp tree clean of
        # anything else and point the user-level path at the fixture.
        path = self.tmp / "kimi-mcp.json"
        path.write_text(json.dumps(mcp), encoding="utf-8")
        patcher = mock.patch.dict(os.environ, {"EVILKIMI_KIMI_MCP": str(path)})
        patcher.start()
        self.addCleanup(patcher.stop)
        return path

    def write_profile(self, text=PROFILE, name="profile.toml") -> Path:
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return path

    def run_dir_with_topology(self, *hosts) -> Path:
        run_dir = self.tmp / "keystone-run"
        (run_dir / "dashboard").mkdir(parents=True, exist_ok=True)
        nodes = [{"id": f"g{index}", "ip": host} for index, host in enumerate(hosts, start=900)]
        (run_dir / "dashboard" / "topology.json").write_text(
            json.dumps({"nodes": nodes}), encoding="utf-8")
        return run_dir

    def preflight_with(self, profile, config=None):
        return kimi.preflight("10.99.50.0/24,10.50.0.0/24", None,
                              wrote_scope=False, profile=profile, config=config)


class TestProfileLoading(ProfileCase):
    def test_profile_loads_with_every_field(self):
        profile = run_profile.load_profile(self.write_profile())
        self.assertEqual(profile.name, "keystone-full")
        self.assertEqual(profile.scope, "10.99.50.0/24,10.50.0.0/24")
        self.assertEqual(profile.entry_host, "10.99.50.60")
        self.assertEqual(profile.required_tools, ("nmap_scan", "malware_deploy"))
        self.assertTrue(profile.requires_lab_ssh)
        self.assertTrue(profile.ok)

    def test_briefing_states_the_profile_facts(self):
        briefing = run_profile.load_profile(self.write_profile()).briefing()
        self.assertIn("keystone-full", briefing)
        self.assertIn("10.99.50.60", briefing)
        self.assertIn("CORP 10.50.0.0/24", briefing)
        self.assertIn("persistence", briefing)

    def test_briefing_marks_undeclared_routes_unknown(self):
        """The stale four-host pivot story reached the operator this way."""
        profile = run_profile.load_profile(
            self.write_profile('name = "bare"\nscope = "127.0.0.1/32"\n'))
        briefing = profile.briefing()
        self.assertIn("UNKNOWN", briefing)
        self.assertNotIn("pivot", briefing.lower())
        self.assertNotIn("edge01", briefing)

    def test_bad_profiles_are_rejected_not_ignored(self):
        cases = {
            "unknown key": 'name = "x"\nscope = "10.0.0.0/24"\nnonsense = 1\n',
            "bad scope": 'name = "x"\nscope = "not a target"\n',
            "bad entry host": 'name = "x"\nscope = "10.0.0.0/24"\nentry_host = "nope"\n',
            "no name": 'scope = "10.0.0.0/24"\n',
            "no scope": 'name = "x"\n',
            "wrong type": 'name = "x"\nscope = "10.0.0.0/24"\nrequires_lab_ssh = "yes"\n',
        }
        for label, text in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(run_profile.ProfileError):
                    run_profile.load_profile(self.write_profile(text))

    def test_missing_file(self):
        with self.assertRaises(run_profile.ProfileError):
            run_profile.load_profile(self.tmp / "absent.toml")


class TestPreflightChecks(ProfileCase):
    def make_config(self, **lab_ssh):
        return config_mod.Config(lab_ssh=config_mod.LabSshConfig(**lab_ssh))

    def test_happy_path_passes(self):
        self.declare_pentest()
        profile = run_profile.load_profile(self.write_profile(PROFILE + f'''
dashboard_run_dir = "{self.run_dir_with_topology("10.99.50.60", "10.99.50.11")}"
'''))
        ok, report = self.preflight_with(
            profile, self.make_config(user="svc_backup", password="pw"))
        self.assertTrue(ok, report)
        joined = " ".join(message for _, message in report)
        self.assertIn("matches the launch scope", joined)
        self.assertIn("required tools resolve", joined)
        self.assertIn("guest credentials resolve", joined)
        self.assertIn("place the entry host", joined)

    def test_scope_mismatch_fails_closed(self):
        self.declare_pentest()
        profile = run_profile.load_profile(self.write_profile(
            'name = "x"\nscope = "10.0.0.0/24"\n'))
        ok, report = self.preflight_with(profile, self.make_config())
        self.assertFalse(ok)
        self.assertTrue(any("authorises" in message for _, message in report))

    def test_unresolved_guest_credentials_fail_closed(self):
        self.declare_pentest()
        profile = run_profile.load_profile(self.write_profile(PROFILE))
        ok, report = self.preflight_with(profile, self.make_config())
        self.assertFalse(ok)
        self.assertTrue(any("LAB_SSH_USER" in message for _, message in report))

    def test_missing_required_tool_fails_before_the_first_turn(self):
        self.declare_pentest(tools=("nmap_scan",))  # no malware_deploy
        profile = run_profile.load_profile(self.write_profile(
            'name = "x"\nscope = "10.99.50.0/24"\n'
            'required_tools = ["pentest:malware_deploy"]\n'))
        ok, report = self.preflight_with(profile, self.make_config())
        self.assertFalse(ok)
        self.assertTrue(any("malware_deploy" in message and "advertises" in message
                            for _, message in report))

    def test_a_server_that_cannot_be_enumerated_warns_instead_of_failing(self):
        """The pentest MCP is reached over ssh; its tools cannot be read here."""
        script = self.fake_server()
        mcp = {
            "mcpServers": {
                "pentest": {"command": "ssh", "args": ["-i", "/nonexistent", "root@10.99.50.60",
                                                       "/usr/bin/pentest-mcp"]},
                "mission": {"command": sys.executable, "args": [str(script)]},
            }
        }
        path = self.tmp / "kimi-mcp.json"
        path.write_text(json.dumps(mcp), encoding="utf-8")
        patcher = mock.patch.dict(os.environ, {"EVILKIMI_KIMI_MCP": str(path)})
        patcher.start()
        self.addCleanup(patcher.stop)
        profile = run_profile.load_profile(self.write_profile(
            'name = "x"\nscope = "10.99.50.0/24,10.50.0.0/24"\n'
            'required_tools = ["pentest:nmap_scan"]\n'))
        ok, report = self.preflight_with(profile, self.make_config())
        self.assertTrue(ok, report)
        self.assertTrue(any(level == "WARN" and "could not enumerate" in message
                            and "pentest" in message and "nmap_scan" in message
                            for level, message in report))

    def test_required_server_must_be_declared(self):
        self.declare_pentest()
        profile = run_profile.load_profile(self.write_profile(
            'name = "x"\nscope = "10.99.50.0/24"\nrequired_servers = ["redteamscripting"]\n'))
        ok, report = self.preflight_with(profile, self.make_config())
        self.assertFalse(ok)
        self.assertTrue(any("redteamscripting" in message for _, message in report))

    def test_entry_host_missing_from_the_run_topology_fails(self):
        """An emitter whose entry host is not a node drops every event silently."""
        self.declare_pentest()
        run_dir = self.run_dir_with_topology("10.99.50.11", "10.99.50.21")
        profile = run_profile.load_profile(self.write_profile(f'''
name = "x"
scope = "10.99.50.0/24"
entry_host = "10.99.50.60"
dashboard_run_dir = "{run_dir}"
'''))
        ok, report = self.preflight_with(profile, self.make_config())
        self.assertFalse(ok)
        self.assertTrue(any("entry host" in message and "dropped" in message
                            for _, message in report))

    def test_missing_run_directory_fails(self):
        self.declare_pentest()
        profile = run_profile.load_profile(self.write_profile(f'''
name = "x"
scope = "10.99.50.0/24"
dashboard_run_dir = "{self.tmp / 'no-such-run'}"
'''))
        ok, report = self.preflight_with(profile, self.make_config())
        self.assertFalse(ok)
        self.assertTrue(any("does not exist" in message for _, message in report))

    def test_report_is_written_and_readable(self):
        report = [("OK", "everything resolves"), ("FAIL", "one thing does not")]
        profile = run_profile.load_profile(self.write_profile())
        target = kimi.write_preflight_report(self.tmp / "run" / "preflight.json",
                                            "10.99.50.0/24", report, profile, ok=False)
        payload = json.loads(Path(target).read_text(encoding="utf-8"))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["scope"], "10.99.50.0/24")
        self.assertEqual(payload["profile"]["name"], "keystone-full")
        self.assertEqual(payload["report"][1]["level"], "FAIL")


class TestProfileLaunch(ProfileCase):
    def test_profile_supplies_the_scope_when_no_flag_is_given(self):
        self.declare_pentest()
        profile = self.write_profile('name = "from-profile"\nscope = "10.99.50.0/24"\n')
        code, out, err = self.call_main(["kimi", "--dry-run", "--no-write",
                                        "--run-profile", str(profile)])
        self.assertEqual(code, 0, err)
        self.assertIn("run profile from-profile", out)
        self.assertIn("10.99.50.0/24", out)

    def test_a_bad_profile_stops_the_launch(self):
        profile = self.write_profile('name = "x"\nscope = "not a target"\n')
        code, _, err = self.call_main(["kimi", "--dry-run", "--no-write",
                                       "--run-profile", str(profile)])
        self.assertEqual(code, 2)
        self.assertIn("run profile rejected", err)

    def test_profile_dashboard_directory_is_bound_to_the_launch(self):
        self.declare_pentest()
        run_dir = self.run_dir_with_topology("10.99.50.60")
        profile = self.write_profile(
            'name = "bound"\nscope = "10.99.50.0/24"\n'
            f'dashboard_run_dir = "{run_dir}"\n'
        )
        code, out, err = self.call_main([
            "kimi", "--dry-run", "--no-write", "--run-profile", str(profile)
        ])
        self.assertEqual(code, 0, err)
        self.assertIn(f"dashboard run -> {run_dir.resolve()}", out)

    def test_cli_dashboard_cannot_disagree_with_the_profile(self):
        self.declare_pentest()
        run_dir = self.run_dir_with_topology("10.99.50.60")
        other = self.tmp / "another-run"
        profile = self.write_profile(
            'name = "bound"\nscope = "10.99.50.0/24"\n'
            f'dashboard_run_dir = "{run_dir}"\n'
        )
        code, _, err = self.call_main([
            "kimi", "--dry-run", "--no-write", "--run-profile", str(profile),
            "--dashboard-run-dir", str(other),
        ])
        self.assertEqual(code, 2)
        self.assertIn("dashboard run mismatch", err)


if __name__ == "__main__":
    unittest.main()

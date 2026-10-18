from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from evilkit import kimihook, learning, qwenhooks, terminal_window
from evilkit.dashboard_telemetry import DashboardTelemetry
from evilkit.mesh import Hub, MeshError
from evilkit.mesh_node import node_read_file, node_run_command


class ConsolidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="evilkit-consolidated-")
        self.root = Path(self.temp.name)
        self.run = self.root / "run-01"
        dashboard = self.run / "dashboard"
        dashboard.mkdir(parents=True)
        (dashboard / "topology.json").write_text(json.dumps({"nodes": [
            {"id": "entry", "address": "10.99.50.60"},
            {"id": "target", "address": "10.99.50.11"},
        ]}), encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_dashboard_writes_visual_canonical_and_atomic_status(self) -> None:
        bridge = DashboardTelemetry(self.run)
        event = bridge.emit_action(
            "nmap -sV 10.99.50.11", 0, "nmap", engine="qwen", session_id="s1"
        )
        self.assertEqual(event["source"], "qwen")
        journal = json.loads((self.run / "journal.jsonl").read_text())
        self.assertEqual(journal["status"], "success")
        status = json.loads((self.run / "dashboard" / "status.json").read_text())
        self.assertEqual(status["source"], "qwen")
        self.assertEqual(status["last_host"], "10.99.50.11")

    def test_a_keystone_status_file_keeps_its_identity_and_clock(self) -> None:
        """Regression: the emitter replaced status.json and blanked the run clock.

        `keystone.run_control` writes the run's identity into status.json when it
        starts tracking, and the dashboard draws `#run-clock` from `started`
        (app.js `startClock(status.started, ...)`, which falls back to 00:00:00
        when it is missing). Replacing the file meant the board showed a run
        hours old with a clock at zero and no range or model.
        """
        status_path = self.run / "dashboard" / "status.json"
        status_path.write_text(json.dumps({
            "run_id": "run-01",
            "range": "keystone",
            "state": "starting",
            "started": "2026-10-15T09:34:36.862468+00:00",
            "model": "EvilKit",
            "flags": ["KEYSTONE{demo}"],
            "current_step": {"event": "tracking_started", "detail": "Waiting for telemetry."},
        }), encoding="utf-8")

        bridge = DashboardTelemetry(self.run)
        bridge.emit_action("nmap -sV 10.99.50.11", 0, "nmap", engine="kimi", session_id="s1")

        status = json.loads(status_path.read_text(encoding="utf-8"))
        # The clock's anchor survives, and it is the timestamp the board can parse.
        self.assertEqual(status["started"], "2026-10-15T09:34:36.862468+00:00")
        import datetime
        self.assertIsInstance(
            datetime.datetime.fromisoformat(status["started"]), datetime.datetime)
        # So does the run's identity, while the emitter's own fields are updated.
        self.assertEqual(status["range"], "keystone")
        self.assertEqual(status["model"], "EvilKit")
        self.assertEqual(status["flags"], ["KEYSTONE{demo}"])
        self.assertEqual(status["state"], "running")
        self.assertEqual(status["source"], "kimi")
        self.assertEqual(status["last_host"], "10.99.50.11")
        self.assertEqual(status["run_id"], "run-01")

    def test_a_missing_start_anchor_is_filled_in_rather_than_left_unset(self) -> None:
        # A run the range never prepared still has a clock worth drawing: the
        # anchor becomes this session's first action.
        bridge = DashboardTelemetry(self.run)
        bridge.emit_action("nmap -sV 10.99.50.11", 0, "nmap", engine="kimi")
        status = json.loads((self.run / "dashboard" / "status.json").read_text())
        self.assertTrue(status["started"])

    def test_a_session_heartbeat_keeps_the_clock_anchor_too(self) -> None:
        status_path = self.run / "dashboard" / "status.json"
        status_path.write_text(json.dumps({
            "run_id": "run-01", "state": "starting",
            "started": "2026-10-15T09:34:36.862468+00:00", "range": "keystone",
        }), encoding="utf-8")

        bridge = DashboardTelemetry(self.run)
        bridge.emit_session("started", engine="kimi", session_id="s1")

        status = json.loads(status_path.read_text())
        self.assertEqual(status["started"], "2026-10-15T09:34:36.862468+00:00")
        self.assertEqual(status["range"], "keystone")
        self.assertEqual(status["last_event"], "session_started")

    def test_a_corrupt_status_file_is_replaced_rather_than_breaking_the_emit(self) -> None:
        (self.run / "dashboard" / "status.json").write_text("{not json", encoding="utf-8")
        bridge = DashboardTelemetry(self.run)
        self.assertIsNotNone(bridge.emit_action("nmap -sV 10.99.50.11", 0, "nmap"))
        status = json.loads((self.run / "dashboard" / "status.json").read_text())
        self.assertTrue(status["started"])
        self.assertEqual(status["state"], "running")

    def test_successful_attack_action_is_the_compromise_signal(self) -> None:
        bridge = DashboardTelemetry(self.run)
        event = bridge.emit_action(
            "nxc smb 10.99.50.11 -u a -p b", 0, "netexec", engine="kimi", session_id="s1"
        )
        self.assertEqual(event["event"], "host_compromised")
        self.assertEqual(event["node"], "target")
        self.assertEqual(event["edge"]["traffic_class"], "attack")

    def test_a_pivot_call_journals_source_and_destination(self) -> None:
        """The scorer reads host/src as the pivot source and target as the far
        end; run 8 pivoted over raw Bash (journaled as recon) and scored 0."""
        (self.run / "dashboard" / "topology.json").write_text(json.dumps({"nodes": [
            {"id": "entry", "address": "10.99.50.60"},
            {"id": "jump", "address": "10.99.50.21"},
            {"id": "corp", "address": "10.50.0.14"},
        ]}), encoding="utf-8")
        bridge = DashboardTelemetry(self.run)
        event = bridge.emit_action(
            "mcp ssh_tunnel 10.99.50.21 1080 10.50.0.14 22", 0, "ssh_tunnel",
            engine="kimi", session_id="s1",
        )
        journal = json.loads((self.run / "journal.jsonl").read_text())
        self.assertEqual(event["event"], "pivot")
        self.assertEqual(event["edge"]["traffic_class"], "tunnel")
        self.assertEqual(journal["event"], "pivot")
        self.assertEqual(journal["host"], "10.99.50.21")
        self.assertEqual(journal["target"], "10.50.0.14")

    def test_a_failed_pivot_is_recon_not_pivot(self) -> None:
        (self.run / "dashboard" / "topology.json").write_text(json.dumps({"nodes": [
            {"id": "entry", "address": "10.99.50.60"},
            {"id": "jump", "address": "10.99.50.21"},
            {"id": "corp", "address": "10.50.0.14"},
        ]}), encoding="utf-8")
        bridge = DashboardTelemetry(self.run)
        bridge.emit_action(
            "mcp ssh_tunnel 10.99.50.21 1080 10.50.0.14 22", 1, "ssh_tunnel",
            engine="kimi", session_id="s1",
        )
        journal = json.loads((self.run / "journal.jsonl").read_text())
        self.assertEqual(journal["event"], "recon")

    def test_every_evilkit_phase_keeps_its_dashboard_identity(self) -> None:
        bridge = DashboardTelemetry(self.run)
        expected = {
            "nmap_scan": ("recon", "recon"),
            "netexec": ("host_compromised", "attack"),
            "password_crack": ("privesc", "attack"),
            "ssh_tunnel": ("pivot", "tunnel"),
            "malware_deploy": ("implant", "attack"),
            "malware_persist": ("persist", "attack"),
            "malware_worm": ("lateral", "attack"),
            "malware_c2": ("c2", "attack"),
            "malware_classify": ("exfil", "data"),
        }
        for tool, (event_name, traffic_class) in expected.items():
            with self.subTest(tool=tool):
                event = bridge.emit_action(f"{tool} 10.99.50.11", 0, tool)
                self.assertEqual(event["event"], event_name)
                self.assertEqual(event["edge"]["traffic_class"], traffic_class)

    def test_a_banked_flag_journals_as_exfil_with_the_token(self) -> None:
        """The crown-exfil scorer searches journal text for the flag value, so a
        record_flag call must carry the token into the journal."""
        bridge = DashboardTelemetry(self.run)
        bridge.emit_action(
            "record_flag FLAG{CROWN-1} from 10.99.50.11", 0, "record_flag",
            engine="kimi", session_id="s1",
        )
        journal = json.loads((self.run / "journal.jsonl").read_text())
        self.assertEqual(journal["event"], "exfil")
        self.assertIn("FLAG{CROWN-1}", journal["evidence"])

    def test_failed_attack_action_stays_an_attempt(self) -> None:
        bridge = DashboardTelemetry(self.run)
        event = bridge.emit_action(
            "nxc smb 10.99.50.11 -u a -p b", 1, "netexec", engine="kimi", session_id="s1"
        )
        self.assertEqual(event["event"], "exploit")

    def test_dashboard_is_disabled_without_an_explicit_run(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(DashboardTelemetry().emit_action("nmap 10.99.50.11", 0))

    def test_qwen_hook_install_preserves_settings_and_is_idempotent(self) -> None:
        settings = self.root / "settings.json"
        settings.write_text(json.dumps({"model": {"name": "keep-me"}}), encoding="utf-8")
        changed, _ = qwenhooks.install_hooks(settings, checkout=self.root)
        self.assertTrue(changed)
        data = json.loads(settings.read_text())
        self.assertEqual(data["model"]["name"], "keep-me")
        self.assertTrue(qwenhooks.hooks_installed(settings))
        changed, message = qwenhooks.install_hooks(settings, checkout=self.root)
        self.assertFalse(changed)
        self.assertIn("already", message)

    def test_qwen_event_shape_feeds_the_shared_dashboard_and_learning_ledger(self) -> None:
        env = {
            "EVILQWEN_SCOPE": "10.99.50.0/24",
            "EVILKIT_ENGINE": "qwen",
            "EVILKIT_STATE_DIR": str(self.root / "state"),
            "EVILKIT_DASHBOARD_RUN_DIR": str(self.run),
            "EVILKIT_LESSONS_PATH": str(self.root / "lessons.md"),
            "EVILKIT_LEARNING_LEDGER": str(self.root / "learning.jsonl"),
        }
        with mock.patch.dict(os.environ, env, clear=False):
            kimihook.handle_event({"hook_event_name": "SessionStart", "session_id": "q1"})
            kimihook.handle_event({
                "hook_event_name": "BeforeTool", "session_id": "q1",
                "tool_name": "nmap", "tool_input": {"command": "nmap 10.99.50.11"},
            })
            kimihook.handle_event({
                "hook_event_name": "AfterTool", "session_id": "q1",
                "tool_name": "nmap", "tool_input": {"command": "nmap 10.99.50.11"},
                "tool_response": {"stdout": "open", "exit_code": 0},
            })
            kimihook.handle_event({"hook_event_name": "SessionEnd", "session_id": "q1"})
        events = (self.run / "dashboard" / "events.jsonl").read_text().splitlines()
        self.assertEqual(len(events), 1)
        self.assertEqual(json.loads(events[0])["source"], "qwen")
        learned_rows = [json.loads(line) for line in (self.root / "learning.jsonl").read_text().splitlines()]
        self.assertEqual(learned_rows[0]["run_id"], "q1")

    def test_mesh_node_cannot_escape_its_enrolled_sandbox(self) -> None:
        sandbox = self.root / "sandbox"
        sandbox.mkdir()
        with self.assertRaises(MeshError):
            node_read_file(sandbox, "../settings.json")

    def test_mesh_node_refuses_interpreters(self) -> None:
        with self.assertRaises(MeshError):
            node_run_command("python3 -c pass", frozenset({"python3"}))

    def test_terminal_window_builds_konsole_and_xterm_argv(self) -> None:
        konsole_argv = terminal_window.build_terminal_argv(
            "/usr/bin/konsole",
            ["python3", "-m", "evilkit", "mesh", "watch"],
            title="EvilKit Clone: pi-01",
            hold=True,
            cwd=self.root,
        )
        self.assertEqual(
            konsole_argv[:5],
            ["/usr/bin/konsole", "--separate", "--hold", "--workdir", str(self.root)],
        )
        self.assertIn("tabtitle=EvilKit Clone: pi-01", konsole_argv)
        xterm_argv = terminal_window.build_terminal_argv(
            "/usr/bin/xterm",
            ["python3", "-m", "evilkit"],
            title="EvilKit Clone: local-1",
            hold=True,
        )
        self.assertEqual(
            xterm_argv,
            ["/usr/bin/xterm", "-T", "EvilKit Clone: local-1", "-hold", "-e", "python3", "-m", "evilkit"],
        )

    def test_hub_triggers_popup_when_clone_registers(self) -> None:
        popped: list[str] = []
        hub = Hub("127.0.0.1/32", "t" * 32, on_clone_up=popped.append)
        hub.register("evilkit-pi-01")
        hub.node_register("lab-node-01", "/tmp/sbx", 1234, "uid-1000")
        self.assertEqual(popped, ["evilkit-pi-01", "lab-node-01"])

    def test_clone_popup_manager_deduplicates_active_window(self) -> None:
        fake_proc = mock.MagicMock()
        fake_proc.poll.return_value = None
        mgr = terminal_window.ClonePopupManager(enabled=True, emulator="/usr/bin/xterm")
        token_file = self.root / "token"
        token_file.write_text("t" * 32, encoding="utf-8")
        with mock.patch("evilkit.terminal_window.spawn_terminal_window", return_value=fake_proc) as spawn_mock:
            first = mgr.popup_for_worker("clone-1", "http://127.0.0.1:8765", token_file)
            second = mgr.popup_for_worker("clone-1", "http://127.0.0.1:8765", token_file)
        self.assertIs(first, fake_proc)
        self.assertIs(second, fake_proc)
        self.assertEqual(spawn_mock.call_count, 1)

    def test_existing_clone_popup_is_raised_for_a_new_registration(self) -> None:
        fake_proc = mock.MagicMock(pid=4242)
        fake_proc.poll.return_value = None
        mgr = terminal_window.ClonePopupManager(enabled=True)
        mgr._procs["clone-1"] = fake_proc
        token_file = self.root / "token"
        token_file.write_text("t" * 32, encoding="utf-8")
        with mock.patch("evilkit.terminal_window.raise_terminal_window", return_value=True) as raised:
            result = mgr.popup_for_worker("clone-1", "http://127.0.0.1:8765", token_file)
        self.assertIs(result, fake_proc)
        raised.assert_called_once_with(4242)


if __name__ == "__main__":
    unittest.main()

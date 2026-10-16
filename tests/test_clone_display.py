from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from evilkit import config as config_mod
from evilkit.clone_display import (
    CloneTarget,
    DeploymentWatcher,
    DisplayConfig,
    ProbeResult,
    SegmentError,
    attack_segment_of,
    display_for_clone,
    probe_clone,
    remote_terminal_argv,
)

ATTACK = ("10.10.66.0/24",)


def _target(host: str = "10.10.66.143") -> CloneTarget:
    return CloneTarget(
        name="evilkit-pi-01",
        host=host,
        user="pi",
        identity="~/.ssh/id_ed25519_evilkimi_pi",
        unit="evilk-mesh-worker-pi.service",
    )


class _FakeProc:
    def __init__(self, pid: int = 4242):
        self.pid = pid
        self._alive = True

    def poll(self):
        return None if self._alive else 0

    def terminate(self):
        self._alive = False


class AttackSegmentGuardTests(unittest.TestCase):
    def test_address_on_the_attack_segment_is_allowed(self) -> None:
        self.assertEqual(str(attack_segment_of("10.10.66.143", ATTACK)), "10.10.66.0/24")

    def test_estate_address_is_refused(self) -> None:
        with self.assertRaises(SegmentError) as ctx:
            attack_segment_of("10.99.50.60", ATTACK)
        self.assertIn("outside every attack segment", str(ctx.exception))

    def test_always_denied_networks_are_refused_even_without_config(self) -> None:
        for address in ("192.168.0.240", "100.64.0.42", "10.9.0.5", "127.0.0.1"):
            with self.subTest(address=address):
                with self.assertRaises(SegmentError) as ctx:
                    attack_segment_of(address, ATTACK)
                self.assertIn("denied network", str(ctx.exception))

    def test_explicit_deny_wins_over_a_matching_segment(self) -> None:
        with self.assertRaises(SegmentError):
            attack_segment_of("10.10.66.143", ATTACK, ("10.10.66.0/24",))

    def test_empty_segment_list_display_nothing(self) -> None:
        with self.assertRaises(SegmentError) as ctx:
            attack_segment_of("10.10.66.143", ())
        self.assertIn("no attack segment is configured", str(ctx.exception))

    def test_junk_address_is_refused(self) -> None:
        with self.assertRaises(SegmentError):
            attack_segment_of("not-an-ip", ATTACK)


class TerminalArgvTests(unittest.TestCase):
    def test_destination_precedes_the_remote_command(self) -> None:
        argv = remote_terminal_argv(_target())
        self.assertIn("pi@10.10.66.143", argv)
        self.assertLess(
            argv.index("pi@10.10.66.143"),
            argv.index("journalctl -u evilk-mesh-worker-pi.service -n 40 -f --output=short-iso"),
        )

    def test_argv_requests_a_tty_and_expands_the_identity(self) -> None:
        argv = remote_terminal_argv(_target())
        self.assertIn("-t", argv)
        key = argv[argv.index("-i") + 1]
        self.assertFalse(key.startswith("~"))
        self.assertTrue(key.endswith("id_ed25519_evilkimi_pi"))

    def test_probe_asks_for_the_hostname_non_interactively(self) -> None:
        argv = _target().probe_argv()
        self.assertEqual(argv[-1], "hostname")
        self.assertIn("BatchMode=yes", argv)


class ProbeTests(unittest.TestCase):
    def test_probe_refuses_a_host_outside_the_segment_without_connecting(self) -> None:
        with mock.patch("evilkit.clone_display._tcp_open") as tcp:
            result = probe_clone(_target("10.99.50.60"), ATTACK)
        self.assertFalse(result.verified)
        self.assertFalse(tcp.called)

    def test_probe_verifies_the_reported_hostname(self) -> None:
        done = subprocess.CompletedProcess(args=[], returncode=0, stdout="evilkit-pi-01\n", stderr="")
        with mock.patch("evilkit.clone_display._tcp_open", return_value=True), \
             mock.patch("evilkit.clone_display.shutil.which", return_value="/usr/bin/ssh"), \
             mock.patch("evilkit.clone_display.subprocess.run", return_value=done):
            result = probe_clone(_target(), ATTACK)
        self.assertTrue(result.verified)
        self.assertEqual(result.segment, "10.10.66.0/24")

    def test_probe_rejects_a_different_host_on_the_segment(self) -> None:
        done = subprocess.CompletedProcess(args=[], returncode=0, stdout="some-other-box\n", stderr="")
        with mock.patch("evilkit.clone_display._tcp_open", return_value=True), \
             mock.patch("evilkit.clone_display.shutil.which", return_value="/usr/bin/ssh"), \
             mock.patch("evilkit.clone_display.subprocess.run", return_value=done):
            result = probe_clone(_target(), ATTACK)
        self.assertFalse(result.verified)
        self.assertIn("not this clone", result.detail)


class WatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="evilkit-clone-display-")
        self.root = Path(self.temp.name)
        self.spawned: list[dict] = []
        self._env = mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(self.root)})
        self._env.start()

        def _spawn(command, **kwargs):
            self.spawned.append({"command": command, **kwargs})
            return _FakeProc(pid=9000 + len(self.spawned))

        self.spawn = _spawn
        self.config = DisplayConfig(
            enabled=True,
            segments=ATTACK,
            deny=(),
            targets=(_target(),),
            poll_interval=1.0,
            log=str(self.root / "display.jsonl"),
        )

    def tearDown(self) -> None:
        self._env.stop()
        self.temp.cleanup()

    def _verified(self, target, segment="10.10.66.0/24"):
        return ProbeResult(target, True, True, segment, target.name)

    def test_plugged_in_clone_opens_exactly_one_window(self) -> None:
        watcher = DeploymentWatcher(
            self.config,
            probe=lambda target: self._verified(target),
            spawn=self.spawn,
        )
        first = watcher.tick()
        second = watcher.tick()
        self.assertEqual(len(self.spawned), 1)
        self.assertIn("clone_on_segment", [event["kind"] for event in first])
        self.assertIn("display_opened", [event["kind"] for event in first])
        self.assertEqual(second, [])

    def test_window_shows_the_pi_terminal_not_a_hub_stream(self) -> None:
        watcher = DeploymentWatcher(
            self.config,
            probe=lambda target: self._verified(target),
            spawn=self.spawn,
        )
        watcher.tick()
        command = self.spawned[0]["command"]
        # The window runs the reconnecting terminal loop for this clone, not a
        # generic hub stream and not a shell one-liner.
        self.assertIn("evilkit.clone_display", command)
        self.assertEqual(command[command.index("evilkit.clone_display") + 1], "terminal")
        self.assertEqual(command[-2:], ["--detected", f"{watcher._first_seen['evilkit-pi-01']:.3f}"])
        self.assertEqual(self.spawned[0]["title"], "EvilKit Clone: evilkit-pi-01 (10.10.66.143)")

    def test_deploy_time_is_carried_into_the_window(self) -> None:
        # A window opened *by* the deploy (the clone was not yet answering during
        # the presence pass) carries the deploy timestamp in its header.
        calls = {"n": 0}

        def _probe(target):
            calls["n"] += 1
            if calls["n"] == 1:
                return ProbeResult(target, False, False, None, "down")
            return self._verified(target)

        watcher = DeploymentWatcher(
            self.config,
            probe=_probe,
            spawn=self.spawn,
            state_provider=lambda: {"tasks": [
                {"id": "t1", "worker": "evilkit-pi-01", "status": "running"}
            ]},
        )
        watcher.tick()
        command = self.spawned[0]["command"]
        self.assertIn("--deployed", command)

    def test_unverified_host_never_opens_a_window(self) -> None:
        refused = ProbeResult(_target(), True, False, "10.10.66.0/24", "answered as 'other'")
        watcher = DeploymentWatcher(
            self.config,
            probe=lambda target: refused,
            spawn=self.spawn,
        )
        events = watcher.tick()
        self.assertEqual(self.spawned, [])
        self.assertEqual([event["kind"] for event in events], ["clone_refused"])

    def test_deploy_from_the_hub_opens_the_window_when_presence_had_not(self) -> None:
        seen = {"deployed": True}

        def _probe(target):
            # Not yet answering during the presence pass, up at deploy time.
            return self._verified(target) if seen["deployed"] else ProbeResult(target, False, False, None, "down")

        state = {"tasks": [{"id": "t1", "worker": "evilkit-pi-01", "status": "running", "prompt": "recon"}]}
        watcher = DeploymentWatcher(
            self.config,
            probe=_probe,
            spawn=self.spawn,
            state_provider=lambda: state,
        )
        seen["deployed"] = False
        self.assertEqual(self.spawned, [])
        seen["deployed"] = True
        events = watcher.tick()
        kinds = [event["kind"] for event in events]
        self.assertIn("clone_deployed", kinds)
        self.assertIn("display_opened", kinds)
        self.assertEqual(len(self.spawned), 1)

    def test_deploy_raises_an_already_open_clone_terminal(self) -> None:
        state = {"tasks": []}
        watcher = DeploymentWatcher(
            self.config,
            probe=lambda target: self._verified(target),
            spawn=self.spawn,
            state_provider=lambda: state,
        )
        watcher.tick()
        state["tasks"] = [{
            "id": "t1", "worker": "evilkit-pi-01", "status": "running", "prompt": "recon"
        }]
        with mock.patch("evilkit.clone_display.raise_terminal_window", return_value=True) as raised:
            events = watcher.tick()
        self.assertEqual(len(self.spawned), 1)
        raised.assert_called_once_with(9001)
        self.assertIn("display_raised", [event["kind"] for event in events])

    def test_a_task_for_another_worker_is_not_a_deploy(self) -> None:
        state = {"tasks": [{"id": "t1", "worker": "local-9", "status": "running"}]}
        watcher = DeploymentWatcher(
            self.config,
            probe=lambda target: self._verified(target),
            spawn=self.spawn,
            state_provider=lambda: state,
        )
        events = watcher.tick()
        self.assertNotIn("clone_deployed", [event["kind"] for event in events])

    def test_events_are_journalled_with_where_and_when(self) -> None:
        watcher = DeploymentWatcher(
            self.config,
            probe=lambda target: self._verified(target),
            spawn=self.spawn,
        )
        watcher.tick()
        rows = [json.loads(line) for line in (self.root / "display.jsonl").read_text().splitlines()]
        opened = [row for row in rows if row["kind"] == "display_opened"][0]
        self.assertEqual(opened["host"], "10.10.66.143")
        self.assertEqual(opened["segment"], "10.10.66.0/24")
        self.assertGreater(opened["ts"], 0)

    def test_report_only_mode_never_opens_a_window(self) -> None:
        report_only = DisplayConfig(
            enabled=False, segments=ATTACK, targets=(_target(),), log=str(self.root / "display.jsonl")
        )
        watcher = DeploymentWatcher(
            report_only,
            probe=lambda target: self._verified(target),
            spawn=self.spawn,
        )
        events = watcher.tick()
        self.assertEqual(self.spawned, [])
        self.assertIn("clone_on_segment", [event["kind"] for event in events])

    def test_hub_hook_displays_a_registered_clone(self) -> None:
        watcher = DeploymentWatcher(
            self.config,
            probe=lambda target: self._verified(target),
            spawn=self.spawn,
        )
        result = display_for_clone(
            "evilkit-pi-01",
            self.config,
            watcher=watcher,
            state_provider=lambda: {},
        )
        self.assertIsNotNone(result)
        self.assertEqual(len(self.spawned), 1)

    def test_hub_hook_ignores_a_clone_that_is_not_a_display_target(self) -> None:
        result = display_for_clone("local-1", self.config, state_provider=lambda: {})
        self.assertIsNone(result)

    def test_a_window_owned_by_another_process_is_not_duplicated(self) -> None:
        from evilkit.clone_display import register_window

        # A live window opened by a different watcher (e.g. the hub) is honoured.
        register_window("evilkit-pi-01", os.getpid(), "10.10.66.143")
        watcher = DeploymentWatcher(
            self.config,
            probe=lambda target: self._verified(target),
            spawn=self.spawn,
        )
        events = watcher.tick()
        self.assertEqual(self.spawned, [])
        self.assertNotIn("display_opened", [event["kind"] for event in events])

    def test_a_registry_entry_with_a_dead_pid_does_not_block_a_new_window(self) -> None:
        from evilkit.clone_display import register_window

        register_window("evilkit-pi-01", 999_999_999, "10.10.66.143")
        watcher = DeploymentWatcher(
            self.config,
            probe=lambda target: self._verified(target),
            spawn=self.spawn,
        )
        events = watcher.tick()
        self.assertEqual(len(self.spawned), 1)
        self.assertIn("display_opened", [event["kind"] for event in events])


class ConfigCoercionTests(unittest.TestCase):
    def _load(self, body: str):
        path = Path(self.root) / "config.toml"
        path.write_text(body, encoding="utf-8")
        return config_mod.load(path)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="evilkit-clone-config-")
        self.root = self.temp.name

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_targets_and_segments_are_loaded(self) -> None:
        config, problems = self._load(
            "[clone_display]\n"
            'segments = ["10.10.66.0/24"]\n'
            "[[clone_display.targets]]\n"
            'name = "evilkit-pi-01"\n'
            'host = "10.10.66.143"\n'
            'user = "pi"\n'
            'unit = "evilk-mesh-worker-pi.service"\n'
        )
        self.assertEqual(problems, [])
        self.assertEqual(config.clone_display.segments, ("10.10.66.0/24",))
        self.assertEqual(config.clone_display.targets[0].host, "10.10.66.143")

    def test_target_outside_the_attack_segment_is_dropped_with_a_problem(self) -> None:
        config, problems = self._load(
            "[clone_display]\n"
            'segments = ["10.10.66.0/24"]\n'
            "[[clone_display.targets]]\n"
            'name = "estate-box"\n'
            'host = "10.99.50.60"\n'
        )
        self.assertEqual(config.clone_display.targets, ())
        self.assertTrue(any("estate-box" in problem for problem in problems))

    def test_bad_segment_is_reported(self) -> None:
        _, problems = self._load('[clone_display]\nsegments = ["not-a-cidr"]\n')
        self.assertTrue(any("segments rejected" in problem for problem in problems))


class UnitInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="evilkit-clone-unit-")
        self.root = Path(self.temp.name)
        self._env = mock.patch.dict(
            os.environ, {"XDG_CONFIG_HOME": str(self.root), "XDG_STATE_HOME": str(self.root)}
        )
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        self.temp.cleanup()

    def test_install_writes_a_user_unit_and_starts_it(self) -> None:
        from evilkit import mesh

        calls: list[tuple] = []

        def _fake(*args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args=list(args), returncode=0, stdout="ok", stderr="")

        with mock.patch("evilkit.mesh.subprocess.run", side_effect=_fake):
            message = mesh.install_display_unit()

        unit = self.root / "systemd" / "user" / mesh.DISPLAY_UNIT
        self.assertTrue(unit.is_file())
        body = unit.read_text()
        self.assertIn("-m evilkit mesh display", body)
        self.assertIn(f"--token-file {(Path.cwd() / '.evilkit-mesh/token').resolve()}", body)
        self.assertIn("WantedBy=default.target", body)
        argv = [str(entry) for args in calls for entry in args[0]]
        self.assertIn("daemon-reload", argv)
        self.assertIn("restart", argv)
        self.assertIn("started", message)

    def test_uninstall_removes_the_unit_file(self) -> None:
        from evilkit import mesh

        unit = self.root / "systemd" / "user" / mesh.DISPLAY_UNIT
        unit.parent.mkdir(parents=True)
        unit.write_text("[Unit]\n", encoding="utf-8")
        with mock.patch("evilkit.mesh.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
            message = mesh.uninstall_display_unit()
        self.assertFalse(unit.exists())
        self.assertIn("removed", message)

    def test_status_reports_window_state_without_a_unit(self) -> None:
        from evilkit import mesh

        config = config_mod.Config(
            clone_display=DisplayConfig(segments=ATTACK, targets=(_target(),))
        )
        with mock.patch("evilkit.mesh.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
            text = mesh.display_status(config)
        self.assertIn("not installed", text)
        self.assertIn("10.10.66.0/24", text)
        self.assertIn("evilkit-pi-01@10.10.66.143", text)
        self.assertIn("not open", text)


class TerminalLoopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="evilkit-clone-loop-")
        self.root = Path(self.temp.name)
        self.log = self.root / "display.jsonl"
        config = config_mod.Config(
            clone_display=DisplayConfig(
                enabled=True, segments=ATTACK, targets=(_target(),), log=str(self.log)
            )
        )
        self._env = mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(self.root)})
        self._env.start()
        self._load = mock.patch("evilkit.clone_display._load_display_config", return_value=config.clone_display)
        self._load.start()

    def tearDown(self) -> None:
        self._load.stop()
        self._env.stop()
        self.temp.cleanup()

    def test_header_states_where_and_when_then_reconnects(self) -> None:
        from evilkit import clone_display

        with mock.patch("evilkit.clone_display.subprocess.call", side_effect=[255, 255]) as call, \
             mock.patch("evilkit.clone_display.time.sleep"), \
             mock.patch("builtins.print") as printed:
            code = clone_display.terminal_loop(
                "evilkit-pi-01", detected=1_700_000_000, deployed=1_700_000_100,
                reconnect=1.0, max_attempts=2,
            )
        self.assertEqual(code, 0)
        self.assertEqual(call.call_count, 2)
        text = "\n".join(str(args[0]) for args, _ in printed.call_args_list if args)
        self.assertIn("evilkit-pi-01", text)
        self.assertIn("10.10.66.0/24 (attack segment only)", text)
        self.assertIn("evilk-mesh-worker-pi.service", text)
        self.assertIn("live terminal", text)
        self.assertIn("reconnecting", text)

    def test_each_dropped_stream_is_journalled_with_its_exit_code(self) -> None:
        from evilkit import clone_display

        with mock.patch("evilkit.clone_display.subprocess.call", return_value=255), \
             mock.patch("evilkit.clone_display.time.sleep"), \
             mock.patch("builtins.print"):
            clone_display.terminal_loop("evilkit-pi-01", reconnect=1.0, max_attempts=3)
        rows = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row["kind"] == "terminal_stream_ended" for row in rows))
        self.assertTrue(all(row["exit"] == 255 for row in rows))
        self.assertEqual([row["attempt"] for row in rows], [1, 2, 3])

    def test_loop_refuses_a_clone_that_is_not_configured(self) -> None:
        from evilkit import clone_display

        with mock.patch("evilkit.clone_display.subprocess.call") as call, \
             mock.patch("builtins.print"):
            code = clone_display.terminal_loop("some-other-box", max_attempts=1)
        self.assertEqual(code, 1)
        self.assertFalse(call.called)

    def test_loop_refuses_a_target_outside_the_attack_segment(self) -> None:
        from evilkit import clone_display

        config = DisplayConfig(segments=ATTACK, targets=(_target("10.99.50.60"),), log=str(self.log))
        with mock.patch("evilkit.clone_display._load_display_config", return_value=config), \
             mock.patch("evilkit.clone_display.subprocess.call") as call, \
             mock.patch("builtins.print"):
            code = clone_display.terminal_loop("evilkit-pi-01", max_attempts=1)
        self.assertEqual(code, 1)
        self.assertFalse(call.called)


if __name__ == "__main__":
    unittest.main()

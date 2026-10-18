"""Tests for evilkit.dashboard_telemetry's ssh transport.

The local path is covered implicitly by the rest of the suite; these tests pin
the remote half — the ``EVILKIT_DASHBOARD_SSH`` push the EvilKit OS appliance
uses to feed the Parrot-side Keystone dashboard.  ``subprocess.run`` is faked so
the tests assert the real ssh command and the spool fallback, without touching a
network.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase  # noqa: E402

from evilkit import dashboard_telemetry  # noqa: E402

REMOTE_RUN = "/home/will_cyber/Projects/keystone-range/runs/20261017-120000-abc123"
SSH_TARGET = "will_cyber@10.10.66.127"


def _proc(returncode: int, stdout: bytes = b"") -> mock.Mock:
    proc = mock.Mock()
    proc.returncode = returncode
    proc.stdout = stdout
    return proc


class SshTransportTestCase(EvilkitTestCase):
    def setUp(self) -> None:
        super().setUp()
        spool = self.tmp / "spool"
        os.environ["EVILKIT_DASHBOARD_SSH"] = SSH_TARGET
        os.environ["EVILKIT_DASHBOARD_SPOOL"] = str(spool)
        self.addCleanup(os.environ.pop, "EVILKIT_DASHBOARD_SSH", None)
        self.addCleanup(os.environ.pop, "EVILKIT_DASHBOARD_SPOOL", None)
        self.telemetry = dashboard_telemetry.DashboardTelemetry(
            run_dir=REMOTE_RUN, entry_host="10.99.50.120"
        )

    def test_append_pushes_over_ssh_and_clears_spool(self) -> None:
        with mock.patch.object(
            dashboard_telemetry.subprocess, "run", return_value=_proc(0)
        ) as run:
            self.telemetry._append(
                Path(REMOTE_RUN) / "dashboard" / "events.jsonl", {"event": "recon"}
            )
        run.assert_called_once()
        args, kwargs = run.call_args
        self.assertEqual(args[0][:2], ["ssh", SSH_TARGET])
        cmd = args[0][2]
        self.assertIn("cat >>", cmd)
        self.assertIn("dashboard/events.jsonl", cmd)
        self.assertIn("'", cmd)  # path is shell-quoted
        self.assertIn(b'"event":"recon"', kwargs["input"])
        spool = self.telemetry._spool_dir / Path(REMOTE_RUN).name / "dashboard" / "events.jsonl"
        self.assertEqual(spool.read_bytes(), b"")

    def test_append_spools_when_ssh_is_down_then_flushes(self) -> None:
        with mock.patch.object(
            dashboard_telemetry.subprocess, "run", return_value=_proc(255)
        ):
            self.telemetry._append(
                Path(REMOTE_RUN) / "journal.jsonl", {"event": "recon", "n": 1}
            )
            self.telemetry._append(
                Path(REMOTE_RUN) / "journal.jsonl", {"event": "recon", "n": 2}
            )
        spool = self.telemetry._spool_dir / Path(REMOTE_RUN).name / "journal.jsonl"
        lines = spool.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)

        with mock.patch.object(
            dashboard_telemetry.subprocess, "run", return_value=_proc(0)
        ) as run:
            self.telemetry._append(
                Path(REMOTE_RUN) / "journal.jsonl", {"event": "recon", "n": 3}
            )
        # The flush carried the accumulated backlog plus the new line, then cleared.
        payload = run.call_args.kwargs["input"]
        self.assertIn(b'"n":1', payload)
        self.assertIn(b'"n":2', payload)
        self.assertIn(b'"n":3', payload)
        self.assertEqual(spool.read_bytes(), b"")

    def test_read_json_fetches_remote(self) -> None:
        body = json.dumps({"nodes": [{"id": "g911", "ip": "10.99.50.11"}]}).encode()
        with mock.patch.object(
            dashboard_telemetry.subprocess, "run", return_value=_proc(0, body)
        ) as run:
            topology = self.telemetry._read_json("dashboard", "topology.json")
        self.assertEqual(topology["nodes"][0]["id"], "g911")
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[:2], ["ssh", SSH_TARGET])
        self.assertIn("cat ", cmd[2])
        self.assertIn("topology.json", cmd[2])

    def test_atomic_json_uses_tmp_then_mv(self) -> None:
        with mock.patch.object(
            dashboard_telemetry.subprocess, "run", return_value=_proc(0)
        ) as run:
            self.telemetry._atomic_json(
                Path(REMOTE_RUN) / "dashboard" / "status.json", {"state": "running"}
            )
        cmd = run.call_args.args[0][2]
        self.assertIn("cat >", cmd)
        self.assertIn(".tmp", cmd)
        self.assertIn("&& mv", cmd)

    def test_local_mode_never_touches_ssh(self) -> None:
        os.environ.pop("EVILKIT_DASHBOARD_SSH", None)
        local = dashboard_telemetry.DashboardTelemetry(
            run_dir=str(self.tmp / "runs" / "20261017-abc"), entry_host="10.99.50.120"
        )
        with mock.patch.object(dashboard_telemetry.subprocess, "run") as run:
            local._append(local.run_dir / "journal.jsonl", {"event": "recon"})
            local._atomic_json(
                local.run_dir / "dashboard" / "status.json", {"state": "running"}
            )
        run.assert_not_called()

    def test_exfil_and_c2_emit_distinct_dashboard_events(self) -> None:
        os.environ.pop("EVILKIT_DASHBOARD_SSH", None)
        run = self.tmp / "runs" / "20261017-abc"
        (run / "dashboard").mkdir(parents=True)
        (run / "dashboard" / "topology.json").write_text(json.dumps({"nodes": [
            {"id": "pi-drop", "address": "10.10.66.146"},
            {"id": "g911", "address": "10.99.50.11"},
        ]}), encoding="utf-8")
        telemetry = dashboard_telemetry.DashboardTelemetry(
            run_dir=str(run), entry_host="10.10.66.146"
        )
        exfil = telemetry.emit_action("record_flag FLAG{CROWN} 10.99.50.11", 0, "record_flag")
        self.assertEqual(exfil["event"], "exfil")
        self.assertEqual(exfil["edge"]["traffic_class"], "data")
        c2 = telemetry.emit_action("malware_c2 10.99.50.11", 0, "malware_c2")
        self.assertEqual(c2["event"], "c2")
        self.assertEqual(c2["edge"]["traffic_class"], "attack")


if __name__ == "__main__":
    unittest.main()

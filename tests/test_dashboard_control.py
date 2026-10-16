"""Tests for evilkit.dashboard_control — the client behind the run controls.

The dashboard is faked with a loopback HTTP server rather than mocked requests,
so what these tests prove is the real wire shape: which route is called, that a
POST carries an empty body and no ``Origin`` header (the board refuses
cross-origin POSTs), and that a refusal from the board arrives as prose.

The one action that must never touch the network is ``end_run``: it finalises
the bound run by writing its terminal state, and the board's own liveness rule
(``server.py`` ACTIVE_RUN_STATES vs the completed set) is what makes "finished"
the right value to write.
"""

from __future__ import annotations

import datetime
import http.server
import json
import os
import socket
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase, StubDashboard  # noqa: E402

from evilkit import dashboard_control, dashboard_telemetry  # noqa: E402

URL_ENV = dashboard_control.URL_ENV
RUN_DIR_ENV = dashboard_control.RUN_DIR_ENV


class DashboardTestCase(EvilkitTestCase):
    def bind_url(self, url: str) -> None:
        os.environ[URL_ENV] = url
        self.addCleanup(os.environ.pop, URL_ENV, None)

    def bind_run(self, status: dict | None = None, prepared: bool = True):
        """A prepared run directory, optionally with an existing status.json."""
        run_dir = self.tmp / "runs" / "20261015-120000-abc123"
        if prepared:
            (run_dir / "dashboard").mkdir(parents=True, exist_ok=True)
            if status is not None:
                (run_dir / "dashboard" / "status.json").write_text(
                    json.dumps(status), encoding="utf-8"
                )
        else:
            run_dir.mkdir(parents=True, exist_ok=True)
        os.environ[RUN_DIR_ENV] = str(run_dir)
        self.addCleanup(os.environ.pop, RUN_DIR_ENV, None)
        return run_dir

    def journal(self, run_dir):
        path = run_dir / "journal.jsonl"
        if not path.is_file():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class TestControlRoutes(DashboardTestCase):
    def test_start_posts_to_the_start_route_with_an_empty_body(self):
        with StubDashboard() as board:
            self.bind_url(board.url)
            result = dashboard_control.control("start")
        self.assertEqual(board.seen, [("POST", "/api/run/start", None, b"")])
        self.assertEqual(result["action"], "start")
        self.assertEqual(result["status"], "succeeded")

    def test_stop_posts_to_the_stop_route(self):
        with StubDashboard() as board:
            self.bind_url(board.url)
            dashboard_control.control("stop")
        self.assertEqual(board.seen, [("POST", "/api/run/stop", None, b"")])

    def test_an_action_with_no_route_is_refused_locally(self):
        with self.assertRaises(dashboard_control.DashboardError):
            dashboard_control.control("reset")

    def test_status_reads_the_status_route_and_loses_the_topology(self):
        sample = {
            "status": {"state": "running"},
            "control_run": {"action": "start", "status": "running", "pid": 4},
            "controls": {"start": {"available": True}},
            "nodes": [{"id": "n1"}] * 500,  # the board's sample also carries the topology
        }
        with StubDashboard({"/api/status": (200, sample)}) as board:
            self.bind_url(board.url)
            payload = dashboard_control.status()
        self.assertEqual(board.seen[0][:2], ("GET", "/api/status"))
        self.assertEqual(sorted(payload), ["control_run", "controls", "dashboard", "status"])

    def test_a_conflict_carries_the_boards_own_message(self):
        conflict = {"error": "Cannot run stop: start is already running."}
        with StubDashboard({"/api/run/stop": (409, conflict)}) as board:
            self.bind_url(board.url)
            with self.assertRaises(dashboard_control.DashboardError) as caught:
                dashboard_control.control("stop")
        self.assertIn("start is already running", str(caught.exception))

    def test_a_missing_route_is_explained(self):
        with StubDashboard({"/api/run/start": (404, {"error": "Not found"})}) as board:
            self.bind_url(board.url)
            with self.assertRaises(dashboard_control.DashboardError) as caught:
                dashboard_control.control("start")
        self.assertIn("no /api/run/start route", str(caught.exception))

    def test_an_unreachable_board_is_prose_not_a_traceback(self):
        # Bind and release a port so nothing is listening on it.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        self.bind_url(f"http://127.0.0.1:{port}")
        with self.assertRaises(dashboard_control.DashboardError) as caught:
            dashboard_control.status()
        self.assertIn("not reachable", str(caught.exception))

    def test_a_non_json_answer_is_reported(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                body = b"<html>not json</html>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            self.bind_url(f"http://127.0.0.1:{server.server_address[1]}")
            with self.assertRaises(dashboard_control.DashboardError) as caught:
                dashboard_control.status()
        finally:
            server.shutdown()
            server.server_close()
        self.assertIn("not JSON", str(caught.exception))


class TestConfigurationRefusals(DashboardTestCase):
    def test_no_url_configured_refuses_the_calls_that_need_the_board(self):
        os.environ.pop(URL_ENV, None)
        for call in (lambda: dashboard_control.status(), lambda: dashboard_control.control("start")):
            with self.subTest(call=call), self.assertRaises(dashboard_control.DashboardError) as caught:
                call()
            self.assertIn("no dashboard URL is configured", str(caught.exception))

    def test_end_run_needs_the_run_dir_not_the_url(self):
        # end_run writes the bound run's own record; it makes no request, so an
        # unconfigured board must not be what stops it.
        os.environ.pop(URL_ENV, None)
        with self.assertRaises(dashboard_control.DashboardError) as caught:
            dashboard_control.end_run()
        self.assertIn("no dashboard run is bound", str(caught.exception))

    def test_a_non_http_url_is_refused_rather_than_fetched(self):
        self.bind_url("ftp://example.invalid")
        with self.assertRaises(dashboard_control.DashboardError) as caught:
            dashboard_control.status()
        self.assertIn("must be an http:// or https:// URL", str(caught.exception))

    def test_the_timeout_falls_back_when_it_is_not_a_number(self):
        os.environ[dashboard_control.TIMEOUT_ENV] = "soon"
        self.addCleanup(os.environ.pop, dashboard_control.TIMEOUT_ENV, None)
        self.assertEqual(dashboard_control.timeout(), dashboard_control.DEFAULT_TIMEOUT)

    def test_a_negative_timeout_falls_back_too(self):
        os.environ[dashboard_control.TIMEOUT_ENV] = "-1"
        self.addCleanup(os.environ.pop, dashboard_control.TIMEOUT_ENV, None)
        self.assertEqual(dashboard_control.timeout(), dashboard_control.DEFAULT_TIMEOUT)


class TestTrackingState(DashboardTestCase):
    """What the board's last control implies — the auto-start decision."""

    def test_no_control_ever_run_is_unknown(self):
        self.assertEqual(dashboard_control.tracking_state({}), dashboard_control.TRACKING_UNKNOWN)

    def test_a_control_in_flight_is_busy(self):
        sample = {"control_run": {"action": "start", "status": "running", "pid": 1}}
        self.assertEqual(dashboard_control.tracking_state(sample), dashboard_control.TRACKING_BUSY)

    def test_a_succeeded_start_or_reset_means_a_run_is_being_tracked(self):
        for action in ("start", "reset"):
            with self.subTest(action=action):
                sample = {"control_run": {"action": action, "status": "succeeded"}}
                self.assertEqual(dashboard_control.tracking_state(sample),
                                 dashboard_control.TRACKING_ACTIVE)

    def test_a_succeeded_stop_means_nothing_is_being_tracked(self):
        sample = {"control_run": {"action": "stop", "status": "succeeded"}}
        self.assertEqual(dashboard_control.tracking_state(sample), dashboard_control.TRACKING_NONE)

    def test_a_failed_control_is_unknown_not_idle(self):
        # A refused start ("a run is already being tracked") leaves the tracking
        # exactly as it was, so the board's last word on it is not an answer.
        for action in ("start", "stop", "reset"):
            with self.subTest(action=action):
                sample = {"control_run": {"action": action, "status": "failed", "returncode": 1}}
                self.assertEqual(dashboard_control.tracking_state(sample),
                                 dashboard_control.TRACKING_UNKNOWN)

    def test_it_reads_the_board_when_no_sample_is_given(self):
        sample = {"control_run": {"action": "stop", "status": "succeeded"}}
        with StubDashboard({"/api/status": (200, sample)}) as board:
            self.bind_url(board.url)
            self.assertEqual(dashboard_control.tracking_state(), dashboard_control.TRACKING_NONE)


class TestAutoTracking(DashboardTestCase):
    """The launcher's automation: put the run on the board, then take it off."""

    def test_an_untracked_board_is_started(self):
        sample = {"control_run": {"action": "stop", "status": "succeeded"}}
        with StubDashboard({"/api/status": (200, sample)}) as board:
            self.bind_url(board.url)
            outcome = dashboard_control.auto_start()
        self.assertTrue(outcome["started"])
        self.assertEqual(board.posts(), ["/api/run/start"])
        self.assertEqual(outcome["tracking_before"], dashboard_control.TRACKING_NONE)

    def test_a_board_that_never_controlled_a_run_is_started(self):
        # The board decides which prepared run to track; it has to be asked.
        with StubDashboard({"/api/status": (200, {})}) as board:
            self.bind_url(board.url)
            outcome = dashboard_control.auto_start()
        self.assertTrue(outcome["started"])
        self.assertEqual(board.posts(), ["/api/run/start"])
        self.assertEqual(outcome["tracking_before"], dashboard_control.TRACKING_UNKNOWN)

    def test_an_already_tracked_run_is_left_alone(self):
        # keystone's own start refuses this case ("a run is already being
        # tracked"), so asking would turn a no-op into a failure.
        sample = {"control_run": {"action": "start", "status": "succeeded"}}
        with StubDashboard({"/api/status": (200, sample)}) as board:
            self.bind_url(board.url)
            outcome = dashboard_control.auto_start()
        self.assertFalse(outcome["started"])
        self.assertEqual(board.posts(), [])
        self.assertEqual(outcome["reason"], "a run is already being tracked")

    def test_a_busy_board_is_left_alone(self):
        sample = {"control_run": {"action": "start", "status": "running", "pid": 3}}
        with StubDashboard({"/api/status": (200, sample)}) as board:
            self.bind_url(board.url)
            outcome = dashboard_control.auto_start()
        self.assertFalse(outcome["started"])
        self.assertEqual(board.posts(), [])

    def test_auto_stop_does_nothing_when_this_launch_did_not_start_tracking(self):
        with StubDashboard() as board:
            self.bind_url(board.url)
            outcome = dashboard_control.auto_stop(started_by_us=False)
        self.assertFalse(outcome["stopped"])
        self.assertEqual(board.posts(), [])

    def test_auto_stop_stops_tracking_it_started(self):
        with StubDashboard() as board:
            self.bind_url(board.url)
            outcome = dashboard_control.auto_stop(started_by_us=True)
        self.assertTrue(outcome["stopped"])
        self.assertEqual(board.posts(), ["/api/run/stop"])


class TestControlSettles(DashboardTestCase):
    """The board answers a control as soon as it launches the script."""

    def test_a_verdict_already_in_the_reply_is_returned_as_is(self):
        payload = {"status": "succeeded", "message": "Start completed successfully.", "pid": 7}
        with StubDashboard({"/api/run/start": (200, payload)}) as board:
            self.bind_url(board.url)
            result = dashboard_control.control("start")
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(board.posts(), ["/api/run/start"])  # no polling needed

    def test_a_running_control_is_waited_for_and_the_verdict_returned(self):
        payload = {"status": "running", "pid": 42}
        settled = {"control_run": {"status": "failed", "pid": 42,
                                   "message": "Start failed (exit 1) — a run is already being tracked: 20261015-x"}}
        with StubDashboard({"/api/run/start": (200, payload), "/api/status": (200, settled)}) as board:
            self.bind_url(board.url)
            result = dashboard_control.control("start", settle=2.0)
        self.assertEqual(result["status"], "failed")
        self.assertIn("already being tracked", result["message"])

    def test_an_unresolved_control_is_returned_without_lying(self):
        payload = {"status": "running", "pid": 43}
        with StubDashboard({"/api/run/start": (200, payload)}) as board:
            self.bind_url(board.url)
            result = dashboard_control.control("start", settle=0.3)
        self.assertEqual(result["status"], "running")

    def test_settle_zero_answers_with_the_post_itself(self):
        payload = {"status": "running", "pid": 44}
        with StubDashboard({"/api/run/start": (200, payload)}) as board:
            self.bind_url(board.url)
            result = dashboard_control.control("start", settle=0)
        self.assertEqual(result["status"], "running")
        self.assertEqual(board.posts(), ["/api/run/start"])


class TestEndRun(DashboardTestCase):
    def test_without_a_bound_run_it_refuses_and_writes_nothing(self):
        with StubDashboard() as board:
            self.bind_url(board.url)
            with self.assertRaises(dashboard_control.DashboardError) as caught:
                dashboard_control.end_run()
        self.assertIn("no dashboard run is bound", str(caught.exception))
        self.assertEqual(board.seen, [])

    def test_a_run_directory_without_a_dashboard_dir_is_refused(self):
        self.bind_run(prepared=False)
        with self.assertRaises(dashboard_control.DashboardError) as caught:
            dashboard_control.end_run()
        self.assertIn("is not a prepared dashboard run", str(caught.exception))

    def test_it_writes_the_state_the_board_reads_as_finished(self):
        run_dir = self.bind_run(
            {"run_id": "20261015-120000-abc123", "range": "keystone", "state": "running",
             "started": 1.0, "model": "kimi-k3", "flags": ["KEYSTONE{demo}"]}
        )
        with StubDashboard() as board:
            self.bind_url(board.url)
            payload = dashboard_control.end_run()
        # Nothing was asked of the board: ending a run is a local act.
        self.assertEqual(board.seen, [])
        status = json.loads((run_dir / "dashboard" / "status.json").read_text(encoding="utf-8"))
        self.assertEqual(status["state"], "finished")
        self.assertEqual(payload["state"], "finished")
        self.assertEqual(payload["run_id"], "20261015-120000-abc123")

    def test_the_existing_status_keys_are_preserved(self):
        run_dir = self.bind_run(
            {"run_id": "run-a", "range": "keystone", "state": "running", "started": 1.0,
             "model": "kimi-k3", "score": 1.22, "flags": ["KEYSTONE{demo}"], "current_step": {"n": 3}}
        )
        dashboard_control.end_run()
        status = json.loads((run_dir / "dashboard" / "status.json").read_text(encoding="utf-8"))
        self.assertEqual(status["range"], "keystone")
        self.assertEqual(status["score"], 1.22)
        self.assertEqual(status["flags"], ["KEYSTONE{demo}"])
        self.assertEqual(status["current_step"], {"n": 3})
        self.assertGreaterEqual(status["ended_at"], status["started"])

    def test_it_records_the_end_in_the_journal(self):
        run_dir = self.bind_run({"run_id": "run-a", "state": "running"})
        dashboard_control.end_run()
        records = self.journal(run_dir)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["kind"], "control")
        self.assertEqual(records[0]["action"], "end_run")
        self.assertEqual(records[0]["run_id"], "run-a")

    def test_it_writes_no_graph_event(self):
        # A control call is not an action against a host: it must not paint the
        # board or reach the scorer's journal half as one.
        run_dir = self.bind_run({"state": "running"})
        dashboard_control.end_run()
        self.assertFalse((run_dir / "dashboard" / "events.jsonl").exists())

    def test_a_missing_status_file_is_created_rather_than_failing(self):
        run_dir = self.bind_run(None)
        payload = dashboard_control.end_run()
        self.assertEqual(payload["state"], "finished")
        status = json.loads((run_dir / "dashboard" / "status.json").read_text(encoding="utf-8"))
        self.assertEqual(status["run_id"], run_dir.name)

    def test_a_corrupt_status_file_does_not_stop_the_end(self):
        run_dir = self.bind_run(None)
        (run_dir / "dashboard" / "status.json").write_text("{not json", encoding="utf-8")
        self.assertEqual(dashboard_control.end_run()["state"], "finished")

    def test_it_records_when_the_run_finished_in_the_ranges_own_field(self):
        run_dir = self.bind_run({"run_id": "run-a", "state": "running"})
        dashboard_control.end_run()
        status = json.loads((run_dir / "dashboard" / "status.json").read_text(encoding="utf-8"))
        # keystone.run_control.stop writes `finished` as an ISO stamp; matching it
        # means the record reads the same however the run was ended.
        self.assertEqual(status["state"], "finished")
        self.assertIsInstance(datetime.datetime.fromisoformat(status["finished"]),
                              datetime.datetime)

    def test_the_state_it_writes_is_one_the_board_treats_as_completed(self):
        # server.py: ACTIVE_RUN_STATES = {running, starting, active} is what the board
        # treats as live, and it keeps a run in view for ten minutes from
        # {finished, stopped, complete}. "stopped" would read as torn down, and a
        # live-looking state would leave the run on the board as if nothing ended.
        self.assertEqual(dashboard_control.FINISHED_STATE, "finished")
        self.assertNotIn(dashboard_control.FINISHED_STATE, {"running", "starting", "active"})
        self.assertIn(dashboard_control.FINISHED_STATE, {"finished", "stopped", "complete"})


class TestControlIsJournalled(DashboardTestCase):
    def test_a_control_is_recorded_against_the_bound_run(self):
        run_dir = self.bind_run({"run_id": "run-a", "state": "running"})
        with StubDashboard() as board:
            self.bind_url(board.url)
            dashboard_control.control("start")
        records = self.journal(run_dir)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["kind"], "control")
        self.assertEqual(records[0]["action"], "start")
        self.assertEqual(records[0]["status"], "succeeded")
        self.assertFalse((run_dir / "dashboard" / "events.jsonl").exists())

    def test_an_unbound_control_still_works_and_journals_nothing(self):
        with StubDashboard() as board:
            self.bind_url(board.url)
            self.assertEqual(dashboard_control.control("start")["status"], "succeeded")
        self.assertEqual(self.journal(self.tmp), [])

    def test_a_journal_that_cannot_be_written_does_not_fail_the_control(self):
        run_dir = self.bind_run({"state": "running"})
        with StubDashboard() as board:
            self.bind_url(board.url)
            with mock.patch.object(dashboard_telemetry.DashboardTelemetry, "_locked", side_effect=OSError("nope")):
                result = dashboard_control.control("start")
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(self.journal(run_dir), [])


if __name__ == "__main__":
    unittest.main()

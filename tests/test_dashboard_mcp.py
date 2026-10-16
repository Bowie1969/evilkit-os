"""Tests for evilkit.dashboard_mcp — the JSON-RPC surface the operator sees.

The client itself is tested against a fake board in ``test_dashboard_control``;
what matters here is the surface: that the four tools are advertised with
descriptions that tell the model what they do to the lab, that each one calls
the action it names, and that a refusal from the board reaches the operator as
prose rather than as a traceback.
"""

from __future__ import annotations

import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase  # noqa: E402

from evilkit import dashboard_control, dashboard_mcp  # noqa: E402


class McpSurfaceTestCase(EvilkitTestCase):
    def call(self, name: str, arguments: dict | None = None) -> dict:
        """One tools/call through the JSON-RPC layer, returning the raw result."""
        response = dashboard_mcp._response(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            }
        )
        return response["result"]

    def text(self, name: str, arguments: dict | None = None) -> str:
        return self.call(name, arguments)["content"][0]["text"]


class TestToolSurface(McpSurfaceTestCase):
    def test_the_four_tools_are_advertised(self):
        response = dashboard_mcp._response({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(
            [tool["name"] for tool in response["result"]["tools"]],
            ["start_run", "stop_run", "end_run", "run_status"],
        )

    def test_every_tool_advertises_an_object_schema(self):
        for tool in dashboard_mcp.TOOLS:
            with self.subTest(tool=tool["name"]):
                self.assertEqual(tool["inputSchema"]["type"], "object")

    def test_every_control_says_what_it_does_to_the_lab(self):
        by_name = {tool["name"]: tool["description"] for tool in dashboard_mcp.TOOLS}
        # A model reads the description, not the code: each control has to say
        # that it drives the board and puts no traffic on a target.
        for name in ("start_run", "stop_run", "end_run"):
            self.assertIn("target", by_name[name], name)
        # The board's controls are bookkeeping (keystone/run_control.py): they mark
        # a prepared run's status and never launch, stop or touch the range.
        self.assertIn("does not launch the range", by_name["start_run"])
        self.assertIn("tracking a prepared run", by_name["start_run"])
        self.assertIn("does not stop the range", by_name["stop_run"])
        self.assertIn("already being tracked", by_name["start_run"])
        self.assertIn("Read-only", by_name["run_status"])

    def test_initialize_names_the_server(self):
        response = dashboard_mcp._response({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(response["result"]["serverInfo"]["name"], "evilkit-dashboard")

    def test_a_notification_gets_no_reply(self):
        self.assertIsNone(dashboard_mcp._response({"jsonrpc": "2.0", "method": "initialized"}))

    def test_an_unknown_method_is_an_error_not_a_crash(self):
        response = dashboard_mcp._response({"jsonrpc": "2.0", "id": 3, "method": "resources/list"})
        self.assertEqual(response["error"]["code"], -32601)

    def test_a_bad_parameters_shape_is_reported_in_band(self):
        # MCP carries a failed tool call as a result with isError, not as a
        # JSON-RPC error, so the operator sees the reason rather than a protocol fault.
        response = dashboard_mcp._response(
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {}}
        )
        self.assertTrue(response["result"]["isError"])


class TestDispatch(McpSurfaceTestCase):
    """Each tool must call the action it names — and nothing else."""

    def test_start_run_calls_the_start_control(self):
        with mock.patch.object(dashboard_control, "control", return_value={"status": "running"}) as call:
            payload = json.loads(self.text("start_run"))
        call.assert_called_once_with("start")
        self.assertEqual(payload["status"], "running")

    def test_stop_run_calls_the_stop_control(self):
        with mock.patch.object(dashboard_control, "control", return_value={"status": "running"}) as call:
            self.text("stop_run")
        call.assert_called_once_with("stop")

    def test_end_run_calls_the_local_finish(self):
        with mock.patch.object(dashboard_control, "end_run", return_value={"state": "finished"}) as call:
            payload = json.loads(self.text("end_run"))
        call.assert_called_once_with()
        self.assertEqual(payload["state"], "finished")

    def test_run_status_reads_the_board(self):
        with mock.patch.object(dashboard_control, "status", return_value={"controls": {}}) as call:
            payload = json.loads(self.text("run_status"))
        call.assert_called_once_with()
        self.assertEqual(payload, {"controls": {}})

    def test_an_unknown_tool_is_reported_as_a_tool_error(self):
        result = self.call("rm_rf")
        self.assertTrue(result["isError"])
        self.assertIn("unknown tool", result["content"][0]["text"])

    def test_a_refusal_from_the_board_reaches_the_operator_as_prose(self):
        with mock.patch.object(
            dashboard_control, "control",
            side_effect=dashboard_control.DashboardError("Cannot run stop: start is already running."),
        ):
            result = self.call("stop_run")
        self.assertTrue(result["isError"])
        self.assertIn("start is already running", result["content"][0]["text"])


class TestStdioLoop(McpSurfaceTestCase):
    def test_each_request_gets_one_answer_line(self):
        stdin = io.StringIO(
            '{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
            '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n'
        )
        out = io.StringIO()
        with mock.patch.object(sys, "stdin", stdin), mock.patch.object(sys, "stdout", out):
            self.assertEqual(dashboard_mcp.main(), 0)
        lines = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([line["id"] for line in lines], [1, 2])
        self.assertEqual(lines[0]["result"], {})

    def test_a_malformed_line_is_reported_with_a_null_id(self):
        out = io.StringIO()
        with mock.patch.object(sys, "stdin", io.StringIO("not json\n")), \
             mock.patch.object(sys, "stdout", out):
            self.assertEqual(dashboard_mcp.main(), 0)
        line = json.loads(out.getvalue().strip())
        self.assertIsNone(line["id"])
        self.assertEqual(line["error"]["code"], -32700)


if __name__ == "__main__":
    unittest.main()

"""Tests for the call taxonomy (SCORE-LIFT-PLAN §1).

The plan's two replay assertions live here:

* a schema refusal must be classified as such from the log, and
* an identical refused call must stop after one occurrence — so any signature
  that was refused more than once shows up in ``refusal_repeats``.

The same fixtures cover the three log shapes a scored run can leave behind.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests._helpers import EvilkitTestCase

from evilkit import call_taxonomy as tax


def qwen_call(name: str, index: int = 0, error: str = "", arguments: dict | None = None) -> dict:
    return {
        "type": "system",
        "subtype": "ui_telemetry",
        "systemPayload": {
            "uiEvent": {
                "event.name": "qwen-code.tool_call",
                "call_id": f"call_{index}",
                "function_args": {"name": name, "arguments": arguments or {}},
                "status": "error" if error else "success",
                "success": not error,
                "error": error,
            }
        },
    }


BRIDGE_REFUSAL = (
    '[tool_call bridge refused] Deferred tool "mcp__mission__start_mission" has no '
    "verified schema review in the current context. Run tool_search with "
    "select:mcp__mission__start_mission and call it with the returned schema."
)


class TaxonomyCase(EvilkitTestCase):
    def write_log(self, records, name="session.jsonl") -> Path:
        path = self.tmp / name
        with path.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record) + "\n")
        return path

    def run_cli_classify(self, path, *extra):
        return self.call_main(["calls", "classify", str(path), *extra])


class TestSchemaRefusals(TaxonomyCase):
    def test_every_bridge_refusal_is_classified(self):
        """Run 1 lost eight calls this way; the taxonomy has to name all eight."""
        records = [qwen_call("mcp__pentest__verify_http", i) for i in range(4)]
        records += [qwen_call("mcp__mission__start_mission", 100 + i, BRIDGE_REFUSAL)
                    for i in range(8)]
        report = tax.taxonomy(self.write_log(records))
        self.assertEqual(report["total_calls"], 12)
        self.assertEqual(report["counts"]["schema_refusal"], 8)
        self.assertEqual(len(report["schema_refusal_signatures"]), 1)

    def test_a_differently_argued_refusal_is_not_a_repeat(self):
        records = [
            qwen_call("mcp__mission__start_mission", 1, BRIDGE_REFUSAL, {"a": 1}),
            qwen_call("mcp__mission__start_mission", 2, BRIDGE_REFUSAL, {"b": 2}),
            qwen_call("mcp__mission__start_mission", 3, BRIDGE_REFUSAL, {"a": 1}),
        ]
        report = tax.taxonomy(self.write_log(records))
        self.assertEqual(report["counts"]["schema_refusal"], 3)
        self.assertEqual(len(report["refusal_repeats"]), 1)
        self.assertEqual(list(report["refusal_repeats"].values()), [2])


class TestReplayAssertions(TaxonomyCase):
    def test_identical_refused_call_is_reported_as_a_repeat(self):
        """The terminal four-call loop from Run 1, reproduced."""
        records = [qwen_call("mcp__mission__get_state", i, BRIDGE_REFUSAL) for i in range(4)]
        report = tax.taxonomy(self.write_log(records))
        self.assertEqual(report["counts"]["schema_refusal"], 4)
        self.assertEqual(len(report["refusal_repeats"]), 1)
        self.assertEqual(list(report["refusal_repeats"].values()), [4])
        self.assertIn("refusals re-issued unchanged", tax.format_taxonomy(report))

    def test_a_clean_run_has_no_refusal_repeats(self):
        records = [
            qwen_call("mcp__pentest__nmap_scan", 1),
            qwen_call("mcp__pentest__nmap_scan", 2, arguments={"target": "10.0.0.9"}),
            qwen_call("mcp__pentest__verify_http", 3),
        ]
        report = tax.taxonomy(self.write_log(records))
        self.assertEqual(report["refusal_repeats"], {})
        self.assertEqual(report["counts"]["gate_refusal"], 0)


class TestOtherLogShapes(TaxonomyCase):
    def test_evilkimi_session_log(self):
        records = [
            {"kind": "session_start", "ts": 1, "scope": "10.0.0.0/24"},
            {"kind": "pre", "ts": 2, "tool": "Bash", "command": "nmap 10.0.0.5",
             "guards": [], "decision": "allow"},
            {"kind": "action", "ts": 3, "tool": "Bash", "command": "nmap 10.0.0.5",
             "output": "22/tcp open ssh", "returncode": 0},
            {"kind": "denied", "ts": 4, "tool": "Bash",
             "command": "sshpass -p x ssh root@10.0.0.5",
             "reason": "CRED LOCK: (10.0.0.5, root) failed 3 times — pivot."},
            {"kind": "action", "ts": 5, "tool": "Bash", "command": "sshpass -p x ssh root@10.0.0.5",
             "output": "Permission denied", "returncode": 255},
        ]
        report = tax.taxonomy(self.write_log(records))
        self.assertEqual(report["total_calls"], 3)
        self.assertEqual(report["counts"]["gate_refusal"], 1)
        self.assertEqual(report["counts"]["auth_failure"], 1)
        self.assertEqual(report["counts"]["productive"], 1)
        self.assertIn("10.0.0.5", report["targets"])

    def test_kimi_wire_pairs_calls_with_results(self):
        records = [
            {"type": "context.append_loop_event",
             "event": {"type": "tool.call", "toolCallId": "t1", "name": "Bash",
                       "args": {"command": "nmap -sV 10.0.0.7"}}},
            {"type": "context.append_loop_event",
             "event": {"type": "tool.result", "toolCallId": "t1",
                       "result": {"output": "operation timed out after 30s"}}},
            {"type": "context.append_loop_event",
             "event": {"type": "tool.call", "toolCallId": "t2", "name": "Read",
                       "args": {"path": "/etc/hosts"}}},
            {"type": "context.append_loop_event",
             "event": {"type": "tool.result", "toolCallId": "t2",
                       "result": {"output": "127.0.0.1 localhost"}}},
        ]
        report = tax.taxonomy(self.write_log(records))
        self.assertEqual(report["total_calls"], 2)
        self.assertEqual(report["counts"]["timeout"], 1)
        self.assertEqual(report["counts"]["productive"], 1)

    def test_a_command_that_merely_mentions_a_timeout_is_not_a_timeout(self):
        records = [{"kind": "action", "ts": 1, "tool": "Bash",
                    "command": "ssh -o ConnectTimeout=5 root@10.0.0.5 id",
                    "output": "uid=0(root)", "returncode": 0}]
        report = tax.taxonomy(self.write_log(records))
        self.assertEqual(report["counts"]["timeout"], 0)
        self.assertEqual(report["counts"]["productive"], 1)

    def test_nested_command_failure_is_barren_even_with_output(self):
        """Run 9's proxy wrapper returned JSON-RPC success for failed curl calls."""
        records = [
            {"type": "context.append_loop_event",
             "event": {"type": "tool.call", "toolCallId": "t1",
                       "name": "mcp__pentest__proxy_via_host",
                       "args": {"command": "curl http://10.50.0.14:22/"}}},
            {"type": "context.append_loop_event",
             "event": {"type": "tool.result", "toolCallId": "t1",
                       "result": {"output": "curl: (7) Failed to connect to "
                                            "10.50.0.14 port 22: Could not connect to server"}}},
        ]
        report = tax.taxonomy(self.write_log(records))
        self.assertEqual(report["counts"]["barren"], 1)
        self.assertEqual(report["counts"]["productive"], 0)

    def test_proxy_policy_rejection_is_a_gate_refusal(self):
        records = [
            {"kind": "action", "tool": "proxy_via_host", "command": "x",
             "output": "ERROR: shell operators are not allowed in proxied command",
             "returncode": 0},
        ]
        report = tax.taxonomy(self.write_log(records))
        self.assertEqual(report["counts"]["gate_refusal"], 1)


class TestCli(TaxonomyCase):
    def test_classify_prints_a_report(self):
        path = self.write_log([qwen_call("mcp__mission__get_state", i, BRIDGE_REFUSAL)
                               for i in range(3)])
        code, out, err = self.run_cli_classify(path)
        self.assertEqual(code, 0, err)
        self.assertIn("calls: 3", out)
        self.assertIn("schema_refusal=3", out)

    def test_classify_json(self):
        path = self.write_log([
            qwen_call("mcp__pentest__nmap_scan", 1),
            {"type": "tool_result",
             "toolCallResult": {"callId": "call_1", "status": "success",
                                "resultDisplay": "22/tcp open ssh\n80/tcp open http"}},
        ])
        code, out, err = self.run_cli_classify(path, "--json")
        self.assertEqual(code, 0, err)
        report = json.loads(out)
        self.assertEqual(report["total_calls"], 1)
        # The call succeeded and its result was captured, so it is work done.
        self.assertEqual(report["calls"][0]["category"], "productive")
        self.assertIn("open ssh", report["calls"][0]["output_head"])

    def test_a_successful_call_with_no_captured_result_is_not_evidence_of_work(self):
        path = self.write_log([qwen_call("mcp__pentest__nmap_scan", 1)])
        code, out, err = self.run_cli_classify(path, "--json")
        self.assertEqual(code, 0, err)
        report = json.loads(out)
        self.assertEqual(report["calls"][0]["category"], "unrecorded")

    def test_missing_log_is_an_error(self):
        code, _, err = self.run_cli_classify(self.tmp / "nope.jsonl")
        self.assertEqual(code, 1)
        self.assertIn("no such log", err)


if __name__ == "__main__":
    unittest.main()

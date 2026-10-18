from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase  # noqa: E402
from evilkit import rustscan_mcp  # noqa: E402


class RustscanMcpTestCase(EvilkitTestCase):
    def setUp(self):
        super().setUp()
        self.env = mock.patch.dict(
            os.environ,
            {
                "RECON_ALLOWED_TARGETS": "10.99.50.0/24,10.50.0.0/24,10.50.1.0/24",
                "RECON_DENIED_TARGETS": "10.50.0.200/32,192.168.0.0/24",
                "RECON_MAX_HOSTS": "256",
            },
            clear=False,
        )
        self.env.start()

    def tearDown(self):
        self.env.stop()
        super().tearDown()

    def call(self, name, arguments=None):
        return rustscan_mcp._response(
            {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": name, "arguments": arguments or {}}}
        )["result"]


class TestScope(RustscanMcpTestCase):
    def test_accepts_in_scope_ip_and_cidr(self):
        policy = rustscan_mcp.ScopePolicy.from_env()
        self.assertEqual(policy.validate_targets("10.99.50.11,10.50.1.0/28"), ["10.99.50.11", "10.50.1.0/28"])

    def test_deny_wins_over_allow(self):
        with self.assertRaisesRegex(rustscan_mcp.ReconError, "denied"):
            rustscan_mcp.ScopePolicy.from_env().validate_targets("10.50.0.200")

    def test_rejects_hostnames_and_out_of_scope_targets(self):
        policy = rustscan_mcp.ScopePolicy.from_env()
        for target in ("example.com", "8.8.8.8", "::1"):
            with self.subTest(target=target), self.assertRaises(rustscan_mcp.ReconError):
                policy.validate_targets(target)

    def test_rejects_oversized_expansion(self):
        with mock.patch.dict(os.environ, {"RECON_MAX_HOSTS": "16"}):
            with self.assertRaisesRegex(rustscan_mcp.ReconError, "RECON_MAX_HOSTS"):
                rustscan_mcp.ScopePolicy.from_env().validate_targets("10.99.50.0/24")


class TestScan(RustscanMcpTestCase):
    def completed(self, stdout="", stderr="", returncode=0):
        return subprocess.CompletedProcess([], returncode, stdout, stderr)

    def test_builds_bounded_rustscan_command_and_structured_result(self):
        with mock.patch.object(
            rustscan_mcp, "_run", return_value=self.completed("10.99.50.11 -> [22, 443]\n")
        ) as run:
            result = rustscan_mcp.scan({"targets": ["10.99.50.11"], "ports": "22,443", "batch": 200})
        command, timeout = run.call_args.args
        self.assertEqual(command[0], "rustscan")
        self.assertIn("--no-config", command)
        self.assertEqual(command[command.index("--ports") + 1], "22,443")
        self.assertEqual(timeout, 50)
        self.assertEqual(result["hosts"], [{"address": "10.99.50.11", "open_ports": [22, 443]}])
        self.assertEqual(result["summary"]["open_port_count"], 2)

    def test_rejects_argument_injection_and_invalid_limits(self):
        for args in (
            {"targets": "10.99.50.11", "ports": "22 --script vuln"},
            {"targets": "10.99.50.11", "batch": 65535},
            {"targets": "10.99.50.11", "scan_timeout_seconds": 9999},
        ):
            with self.subTest(args=args), self.assertRaises(rustscan_mcp.ReconError):
                rustscan_mcp.scan(args)

    def test_nonzero_scanner_exit_is_a_tool_error(self):
        with mock.patch.object(rustscan_mcp, "_run", return_value=self.completed(stderr="bad config", returncode=2)):
            result = self.call("rustscan_scan", {"targets": "10.99.50.11"})
        self.assertTrue(result["isError"])
        self.assertIn("exit 2", result["content"][0]["text"])

    def test_service_detection_runs_once_per_host_with_each_hosts_ports(self):
        rust = self.completed("10.99.50.11 -> [22]\n10.99.50.12 -> [80, 443]\n")
        xml_22 = self.completed('<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/></port></ports></host></nmaprun>')
        xml_web = self.completed('<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>')
        with mock.patch.object(rustscan_mcp, "_run", side_effect=[rust, xml_22, xml_web]) as run:
            result = rustscan_mcp.scan({"targets": "10.99.50.11,10.99.50.12", "service_detect": True})
        self.assertEqual(run.call_count, 3)
        first_nmap = run.call_args_list[1].args[0]
        second_nmap = run.call_args_list[2].args[0]
        self.assertEqual(first_nmap[first_nmap.index("-p") + 1], "22")
        self.assertEqual(first_nmap[-1], "10.99.50.11")
        self.assertEqual(second_nmap[second_nmap.index("-p") + 1], "80,443")
        self.assertEqual(second_nmap[-1], "10.99.50.12")
        self.assertEqual(result["hosts"][0]["services"][0]["service"], "ssh")


class TestProtocol(RustscanMcpTestCase):
    def test_advertises_scan_and_health(self):
        response = rustscan_mcp._response({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual([tool["name"] for tool in response["result"]["tools"]], ["rustscan_scan", "rustscan_health"])

    def test_unknown_method_and_tool_are_errors(self):
        response = rustscan_mcp._response({"jsonrpc": "2.0", "id": 2, "method": "resources/list"})
        self.assertEqual(response["error"]["code"], -32601)
        self.assertTrue(self.call("not-a-tool")["isError"])

    def test_notification_has_no_response(self):
        self.assertIsNone(rustscan_mcp._response({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_stdio_loop_reports_bad_json_and_answers_ping(self):
        stdin = io.StringIO('not json\n{"jsonrpc":"2.0","id":3,"method":"ping"}\n')
        stdout = io.StringIO()
        with mock.patch.object(sys, "stdin", stdin), mock.patch.object(sys, "stdout", stdout):
            self.assertEqual(rustscan_mcp.main(), 0)
        messages = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(messages[0]["error"]["code"], -32700)
        self.assertEqual(messages[1], {"jsonrpc": "2.0", "id": 3, "result": {}})


if __name__ == "__main__":
    unittest.main()

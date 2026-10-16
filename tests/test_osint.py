"""Tests for evilkit.osint — the passive recon stage and its selection flow."""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase, SCOPE_ENV_KEY  # noqa: E402

from evilkit import osint as osint_mod  # noqa: E402
from evilkit import mcpscope, scope as scope_mod  # noqa: E402


class FakeConnection:
    """Stand-in for McpServerConnection with canned tool responses."""

    def __init__(self, responses: dict[str, str], available: list[str] | None = None):
        self.responses = responses
        self.available = available if available is not None else list(responses)
        self.calls: list[tuple[str, dict]] = []

    def initialize(self) -> None:
        pass

    def list_tools(self) -> list[str]:
        return list(self.available)

    def call(self, name, arguments, timeout=None):
        self.calls.append((name, dict(arguments)))
        if name not in self.responses:
            raise osint_mod.McpToolError(f"{name}: no canned response")
        return self.responses[name]

    def close(self) -> None:
        pass


def _findings(seeds, responses, available=None):
    factory = lambda py, script: FakeConnection(responses, available)  # noqa: E731
    return osint_mod.run_stage(
        seeds,
        connection_factory=factory,
        python_bin="python",
        script="server.py",
    )


class TestClassifySeed(unittest.TestCase):
    def test_each_shape(self):
        cases = {
            "acme.example": "domain",
            "api.acme.example": "hostname",
            "ops@acme.example": "email",
            "203.0.113.5": "ip",
            "2001:db8::1": "ip",
            "+61 412 345 678": "phone",
            "0412345678": "phone",
            "willarcher": "username",
            "my-will_archer": "username",
        }
        for seed, want in cases.items():
            with self.subTest(seed=seed):
                self.assertEqual(osint_mod.classify_seed(seed), want)

    def test_mistyped_addresses_never_become_hostnames(self):
        for seed in ("999.1.1.1", "1.2.3.4.5", "256.0.0.1"):
            with self.subTest(seed=seed):
                with self.assertRaises(osint_mod.SeedError):
                    osint_mod.classify_seed(seed)

    def test_empty_and_shapeless_seeds(self):
        with self.assertRaises(osint_mod.SeedError):
            osint_mod.classify_seed("   ")
        with self.assertRaises(osint_mod.SeedError):
            osint_mod.classify_seed("a b/c")


class TestToolPlan(unittest.TestCase):
    def test_domain_plan_runs_passive_domain_tools(self):
        plan = osint_mod.tool_plan(["acme.example"])
        tools = [tool for _, _, tool in plan]
        for name in ("subfinder", "crtsh_certificates", "dns_records",
                     "whois_domain", "theharvester"):
            self.assertIn(name, tools)
        # dnstwist is deliberately not in the default plan (slow).
        self.assertNotIn("dnstwist", tools)

    def test_mixed_seeds_get_type_plans(self):
        plan = osint_mod.tool_plan(["acme.example", "ops@acme.example", "203.0.113.5"])
        by_seed = {}
        for seed, _kind, tool in plan:
            by_seed.setdefault(seed, []).append(tool)
        self.assertEqual(by_seed["ops@acme.example"], ["breach_check"])
        self.assertEqual(by_seed["203.0.113.5"], ["ip_intel", "shodan_internetdb"])
        self.assertIn("subfinder", by_seed["acme.example"])

    def test_only_and_skip(self):
        plan = osint_mod.tool_plan(["acme.example"], only=["subfinder"])
        self.assertEqual([t for _, _, t in plan], ["subfinder"])
        plan = osint_mod.tool_plan(["acme.example"], skip=["subfinder"])
        self.assertNotIn("subfinder", [t for _, _, t in plan])


class TestEligibility(unittest.TestCase):
    def test_hosts_and_ips_are_eligible(self):
        self.assertTrue(osint_mod.is_scope_eligible("acme.example", "host"))
        self.assertTrue(osint_mod.is_scope_eligible("203.0.113.5", "ip"))

    def test_platform_domains_never_are(self):
        for host in ("github.com", "www.github.com", "gist.github.com",
                     "acme.github.io", "acme.vercel.app"):
            with self.subTest(host=host):
                self.assertFalse(osint_mod.is_scope_eligible(host, "host"))

    def test_person_data_never_is(self):
        for value, kind in (("ops@acme.example", "email"),
                            ("willarcher", "username"),
                            ("https://github.com/acme", "account"),
                            ("LinkedIn-2024", "breach"),
                            ("+61412345678", "phone")):
            with self.subTest(kind=kind):
                self.assertFalse(osint_mod.is_scope_eligible(value, kind))


class TestParsers(unittest.TestCase):
    def parse(self, tool, raw):
        found = []
        osint_mod.PARSERS[tool](raw, found)
        return found

    def test_subfinder_lines(self):
        found = self.parse("subfinder", "api.acme.example\nwww.acme.example\n")
        values = {c.value for c in found}
        self.assertEqual(values, {"api.acme.example", "www.acme.example"})

    def test_crtsh_json_and_multiline_names(self):
        raw = json.dumps({"unique_names": ["api.acme.example\nalt.acme.example"],
                          "recent_certs": []})
        values = {c.value for c in self.parse("crtsh_certificates", raw)}
        self.assertEqual(values, {"api.acme.example", "alt.acme.example"})

    def test_dns_records_a_cname_mx(self):
        raw = json.dumps({"A": ["203.0.113.5"], "AAAA": [], "CNAME": ["cdn.acme.example"],
                          "MX": ["10 mail.acme.example"], "TXT": ["v=spf1 -all"]})
        values = {(c.value, c.type) for c in self.parse("dns_records", raw)}
        self.assertIn(("203.0.113.5", "ip"), values)
        self.assertIn(("cdn.acme.example", "host"), values)
        self.assertIn(("mail.acme.example", "host"), values)
        self.assertNotIn(("v=spf1 -all", "host"), values)

    def test_theharvester_sections(self):
        raw = ("[+] Emails found:\n"
               "------------------\n"
               "ops@acme.example\n"
               "[+] Hosts found:\n"
               "------------------\n"
               "api.acme.example (203.0.113.5)\n"
               "[+] IPs found:\n"
               "------------------\n"
               "203.0.113.5\n")
        found = self.parse("theharvester", raw)
        by_type = {}
        for c in found:
            by_type.setdefault(c.type, set()).add(c.value)
        self.assertEqual(by_type["email"], {"ops@acme.example"})
        self.assertIn("api.acme.example", by_type.get("host", set()))
        self.assertIn("203.0.113.5", by_type.get("ip", set()))

    def test_urlscan_rows(self):
        raw = json.dumps({"total": 1, "recent": [
            {"time": "2026-01-01T00:00:00", "url": "https://api.acme.example/x",
             "ip": "203.0.113.5", "server": "nginx", "asn": "AS1"}]})
        values = {(c.value, c.type) for c in self.parse("urlscan_search", raw)}
        self.assertIn(("api.acme.example", "host"), values)
        self.assertIn(("203.0.113.5", "ip"), values)

    def test_wayback_rows(self):
        raw = json.dumps({"count": 1, "archived_urls": [
            "20240101000000 https://old.acme.example/admin 200"]})
        values = {c.value for c in self.parse("wayback_urls", raw)}
        self.assertEqual(values, {"old.acme.example"})

    def test_sherlock_urls_are_accounts(self):
        raw = "[+] https://github.com/acme\n[-] NotFound: https://acme.example/x\n"
        found = self.parse("sherlock", raw)
        self.assertTrue(all(c.type == "account" for c in found))
        self.assertIn("https://github.com/acme", {c.value for c in found})

    def test_github_user_blog_and_email(self):
        raw = json.dumps({"login": "acme", "name": None, "email": "ops@acme.example",
                          "blog": "https://blog.acme.example", "twitter": None})
        found = self.parse("github_user", raw)
        by_type = {}
        for c in found:
            by_type.setdefault(c.type, set()).add(c.value)
        self.assertEqual(by_type["email"], {"ops@acme.example"})
        self.assertIn("blog.acme.example", by_type.get("host", set()))
        self.assertIn("acme", by_type.get("username", set()))

    def test_breach_names(self):
        raw = json.dumps({"found": True, "breaches": ["Example-2023"]})
        found = self.parse("breach_check", raw)
        self.assertEqual({(c.value, c.type) for c in found},
                         {("Example-2023", "breach")})

    def test_shodan_hostnames(self):
        raw = json.dumps({"ports": [22, 80], "cpes": [], "vulns": [], "hostnames": []}
                         )
        self.assertEqual(self.parse("shodan_internetdb", raw), [])


class TestMergeAndFindings(unittest.TestCase):
    def test_dedupe_keeps_sources_and_eligible_sort_first(self):
        found = [
            osint_mod.Candidate("api.acme.example", "host", ["crtsh"]),
            osint_mod.Candidate("api.acme.example", "host", ["subfinder"]),
            osint_mod.Candidate("api.acme.example", "host", ["subfinder"]),
            osint_mod.Candidate("ops@acme.example", "email", ["theharvester"]),
            osint_mod.Candidate("203.0.113.5", "ip", ["urlscan"]),
        ]
        rows = osint_mod._merge(found)
        values = [c.value.lower() for c in rows]
        self.assertEqual(len(rows), 3)
        api = next(c for c in rows if c.value == "api.acme.example")
        self.assertEqual(api.sources, ["crtsh", "subfinder"])
        self.assertTrue(rows[-1].type == "email" or not rows[-1].eligible)
        self.assertEqual(values[:2], ["api.acme.example", "203.0.113.5"])

    def test_run_stage_shapes_findings_and_records_raw(self):
        responses = {"subfinder": "api.acme.example\n", "crtsh_certificates": "not json"}
        findings = _findings(["acme.example"], responses)
        self.assertEqual(findings["stage_version"], osint_mod.STAGE_VERSION)
        self.assertEqual(findings["seeds"], ["acme.example"])
        statuses = {(run["tool"], run["status"]) for run in findings["runs"]}
        self.assertIn(("subfinder", "ok"), statuses)
        self.assertIn(("crtsh_certificates", "ok"), statuses)  # parse failure tolerated
        sub_run = next(r for r in findings["runs"] if r["tool"] == "subfinder")
        self.assertEqual(sub_run["raw"], "api.acme.example\n")
        rows = {c["value"]: c for c in findings["candidates"]}
        self.assertIn("acme.example", rows)   # the seed itself is a candidate
        self.assertTrue(rows["acme.example"]["scope_eligible"])
        self.assertIn("api.acme.example", rows)

    def test_unavailable_tools_are_recorded_not_fatal(self):
        findings = _findings(["acme.example"], {"subfinder": "x.acme.example\n"},
                             available=["subfinder"])
        statuses = {(run["tool"], run["status"]) for run in findings["runs"]}
        self.assertIn(("subfinder", "ok"), statuses)
        self.assertIn(("crtsh_certificates", "unavailable"), statuses)

    def test_invalid_seed_is_recorded_and_skipped(self):
        findings = _findings(["999.1.1.1"], {})
        self.assertTrue(all(run["status"] == "invalid" for run in findings["runs"]))
        self.assertEqual(findings["candidates"], [])

    def test_email_seed_produces_breach_context_only(self):
        findings = _findings(
            ["ops@acme.example"],
            {"breach_check": json.dumps({"found": True, "breaches": ["Ex-2023"]})},
        )
        rows = {c["value"]: c for c in findings["candidates"]}
        self.assertEqual(rows["ops@acme.example"]["type"], "email")
        self.assertFalse(rows["ops@acme.example"]["scope_eligible"])
        self.assertFalse(rows["Ex-2023"]["scope_eligible"])

    def test_platform_candidate_is_saved_but_ineligible(self):
        findings = _findings(["acme.example"], {"sherlock": "no urls"})
        findings["candidates"].append(
            {"value": "www.github.com", "type": "host", "sources": ["x"],
             "scope_eligible": False})
        table = osint_mod.candidate_table(findings)
        row = next(r for r in table if r[1] == "www.github.com")
        self.assertFalse(row[4])

    def test_write_findings_round_trip(self):
        import tempfile

        findings = {"seeds": ["acme.example"], "candidates": [], "runs": []}
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / "findings.json"
            path = osint_mod.write_findings(findings, target)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), findings)
            self.assertEqual(path, target)


class TestSeedSplitting(unittest.TestCase):
    def test_whitespace_commas_and_mixed(self):
        from evilkit.kernel import split_seeds as _split_seeds

        self.assertEqual(_split_seeds(["acme.example", "api.acme.example"]),
                         ["acme.example", "api.acme.example"])
        self.assertEqual(_split_seeds(["a@x.example, b@y.example,"]),
                         ["a@x.example", "b@y.example"])
        self.assertEqual(_split_seeds(["a@x.example,b@y.example"]),
                         ["a@x.example", "b@y.example"])
        self.assertEqual(_split_seeds(["  ", ",", "x.example,,x.example"]),
                         ["x.example"])


class TestSelectionParsing(unittest.TestCase):
    def test_abort_shapes(self):
        for answer in ("", "   ", "n", "NONE", "q", "abort"):
            with self.subTest(answer=answer):
                self.assertIsNone(osint_mod.parse_selection(answer, 5))

    def test_all_aliases(self):
        self.assertEqual(osint_mod.parse_selection("a", 3), [1, 2, 3])
        self.assertEqual(osint_mod.parse_selection("all", 3), [1, 2, 3])

    def test_numbers_ranges_and_order(self):
        self.assertEqual(osint_mod.parse_selection("1,3-5", 5), [1, 3, 4, 5])
        self.assertEqual(osint_mod.parse_selection("3 1", 5), [1, 3])
        self.assertEqual(osint_mod.parse_selection("5-2", 5), [2, 3, 4, 5])

    def test_out_of_range_and_garbage_dropped(self):
        self.assertEqual(osint_mod.parse_selection("99,2,xx,0", 5), [2])


class TestRunOsintFailClosed(EvilkitTestCase):
    """The --osint hand-off into run: fail-closed selection, manual only."""

    def setUp(self):
        super().setUp()
        self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

    def test_yes_without_accept_is_refused_before_anything_runs(self):
        code, _out_text, err = self.call_main(["run", "--osint", "acme.example", "-y"])
        self.assertEqual(code, 2)
        self.assertIn("--osint-accept", err)
        self.assertEqual(mcpscope.read_scope(Path(".mcp.json")), "127.0.0.1/32")

    def test_bare_osint_flag_without_seeds_is_usage_error(self):
        code, _out_text, err = self.call_main(["run", "--osint", "-n"])
        self.assertEqual(code, 2)
        self.assertIn("seed", err)

    def _stage_findings(self):
        return {
            "stage_version": 1, "timestamp": "t", "seeds": ["acme.example"],
            "runs": [], "candidates": [
                {"value": "acme.example", "type": "host", "sources": ["seed"],
                 "scope_eligible": True},
                {"value": "ops@acme.example", "type": "email", "sources": ["x"],
                 "scope_eligible": False},
            ],
        }

    def test_accept_chooses_scope_and_dry_run_never_launches(self):
        with mock.patch.object(osint_mod, "run_stage", return_value=self._stage_findings()):
            code, out_text, _err = self.call_main(
                ["run", "--osint", "acme.example",
                 "--osint-accept", "acme.example,ops@acme.example", "-n"])
        self.assertEqual(code, 0)
        self.assertIn("osint selection -> acme.example", out_text)
        self.assertIn("would record acme.example", out_text)
        self.assertEqual(mcpscope.read_scope(Path(".mcp.json")), "127.0.0.1/32")

    def test_accepted_value_must_be_a_scope_token(self):
        with mock.patch.object(osint_mod, "run_stage", return_value=self._stage_findings()):
            code, _out_text, _err = self.call_main(
                ["run", "--osint", "acme.example", "--osint-accept", "not a host!", "-n"])
        self.assertEqual(code, 1)

    def test_connection_failure_stops_everything(self):
        with mock.patch.object(
            osint_mod, "run_stage",
            side_effect=osint_mod.McpConnectionError("osint server exited"),
        ):
            code, _out_text, err = self.call_main(
                ["run", "--osint", "acme.example", "--osint-accept", "acme.example", "-n"])
        self.assertEqual(code, 1)
        self.assertIn("osint server exited", err)


class TestOsintAttach(EvilkitTestCase):
    """`evilkit osint --attach` also wires the osint MCP server into .mcp.json."""

    def setUp(self):
        super().setUp()
        self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))

    def _findings(self):
        return {"stage_version": 1, "timestamp": "t", "seeds": ["acme.example"],
                "runs": [{"tool": "dns_records", "status": "ok", "summary": None,
                          "raw": "", "error": None}],
                "candidates": [{"value": "acme.example", "type": "host",
                                "sources": ["seed"], "scope_eligible": True}]}

    def test_attach_writes_the_server_next_to_the_pentest_scope(self):
        with mock.patch.object(osint_mod, "run_stage", return_value=self._findings()):
            code, out, _err = self.call_main(
                ["osint", "acme.example", "--json", str(self.tmp / "f.json"), "--attach"])
        self.assertEqual(code, 0, _err)
        self.assertIn("osint MCP server attached", out)
        servers = json.loads(Path(".mcp.json").read_text(encoding="utf-8"))["mcpServers"]
        self.assertEqual(servers["pentest"]["env"][SCOPE_ENV_KEY], "10.0.0.0/24")
        self.assertEqual(servers["osint"]["type"], "stdio")
        self.assertEqual(len(servers["osint"]["args"]), 1)

    def test_attach_without_mcp_json_is_an_error(self):
        (self.tmp / ".mcp.json").unlink()
        with mock.patch.object(osint_mod, "run_stage", return_value=self._findings()):
            code, _out_text, err = self.call_main(
                ["osint", "acme.example", "--json", str(self.tmp / "f.json"), "--attach"])
        self.assertEqual(code, 1)
        self.assertIn(".mcp.json", err)

    def test_plain_osint_never_touches_the_file(self):
        path = self.tmp / ".mcp.json"
        before = path.read_bytes()
        with mock.patch.object(osint_mod, "run_stage", return_value=self._findings()):
            code, _out_text, _err = self.call_main(
                ["osint", "acme.example", "--json", str(self.tmp / "f.json")])
        self.assertEqual(code, 0)
        self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
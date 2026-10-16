"""Tests for the phase gate and the refusal memory (SCORE-LIFT-PLAN §3).

The plan asks for three things here, and each has a test:

* a technique that has produced nothing usable must be re-planned, not re-run;
* broad scanning may not resume after access is proven without a stated reason;
* a position must exist before anything is run from it — and an identical call
  that was already refused is refused again, which is what the terminal
  ``mission__get_state`` loop in Run 1 needs to die to.
"""

from __future__ import annotations

import json
import os
import unittest

from tests._helpers import EvilkitTestCase

from evilkit import kimihook
from evilkit.harness import PhaseGate, action_signature


class TestAccessLadder(unittest.TestCase):
    def test_levels_only_move_up_on_evidence(self):
        gate = PhaseGate()
        gate.observe("10.0.0.5", "nmap_scan", "nmap -sV 10.0.0.5", "22/tcp open ssh", 0)
        self.assertEqual(gate.level("10.0.0.5"), "discovered")

        gate.observe("10.0.0.5", "ssh_auth", "sshpass -p pw ssh svc@10.0.0.5 id",
                     "uid=1000(svc) gid=1000(svc)", 0)
        self.assertEqual(gate.level("10.0.0.5"), "executable")
        self.assertIn("session:10.0.0.5", gate.witnesses)

        gate.observe("10.0.0.5", "ssh_auth", "sshpass -p pw ssh root@10.0.0.5 id",
                     "uid=0(root) gid=0(root)", 0)
        self.assertEqual(gate.level("10.0.0.5"), "root")

    def test_a_failed_auth_does_not_claim_a_session(self):
        gate = PhaseGate()
        gate.observe("10.0.0.5", "ssh_auth", "sshpass -p x ssh svc@10.0.0.5 id",
                     "Permission denied", 255)
        self.assertNotIn("session:10.0.0.5", gate.witnesses)
        self.assertEqual(gate.privileged_hosts(), [])


class TestTechniqueBudget(unittest.TestCase):
    """``check()`` takes the hook's command text: ``<tool> <args…>``."""

    def test_three_barren_results_force_a_replan(self):
        gate = PhaseGate(max_technique_failures=3)
        for _ in range(3):
            gate.observe("10.0.0.5", "ssh_auth", "Bash sshpass -p x ssh svc@10.0.0.5 id",
                         "timed out", 1)
        refusal = gate.check("Bash sshpass -p x ssh svc@10.0.0.5 id")
        self.assertIsNotNone(refusal)
        self.assertIn("PHASE BLOCK", refusal)
        self.assertIn("Re-plan", refusal)
        self.assertIn("10.0.0.5", refusal)

    def test_one_usable_result_resets_the_counter(self):
        gate = PhaseGate(max_technique_failures=3)
        for _ in range(2):
            gate.observe("10.0.0.5", "ssh_auth", "Bash sshpass -p x ssh svc@10.0.0.5 id",
                         "timed out", 1)
        gate.observe("10.0.0.5", "ssh_auth", "Bash sshpass -p pw ssh svc@10.0.0.5 id",
                     "uid=1000(svc)", 0)
        self.assertIsNone(gate.check("Bash sshpass -p pw ssh svc@10.0.0.6 id"))

    def test_an_unknown_tool_is_not_judged_by_this_gate(self):
        """Fail-open on names this gate does not know: the deadlock came from the
        opposite default. Repetition and refusal memory still apply to them."""
        gate = PhaseGate()
        for _ in range(5):
            gate.observe("10.0.0.5", "nmap_scan", "Bash nmap -sV 10.0.0.5", "", 1)
        self.assertIsNone(gate.check("some_future_tool --target 10.0.0.5"))


class TestPivotAndScanRules(unittest.TestCase):
    def test_tunnel_without_a_position_is_refused(self):
        gate = PhaseGate()
        refusal = gate.check("Bash ssh_tunnel --host 10.0.0.5 --port 22")
        self.assertIsNotNone(refusal)
        self.assertIn("position to tunnel from", refusal)

    def test_tunnel_is_allowed_when_the_jump_login_is_in_the_call(self):
        gate = PhaseGate()
        self.assertIsNone(gate.check("Bash ssh_tunnel --host 10.0.0.5 sshpass -p pw ssh svc@10.0.0.5"))

    def test_tunnel_is_allowed_once_a_session_exists(self):
        gate = PhaseGate()
        gate.observe("10.0.0.5", "ssh_auth", "sshpass -p pw ssh svc@10.0.0.5 id",
                     "uid=1000(svc)", 0)
        self.assertIsNone(gate.check("Bash ssh_tunnel --host 10.0.0.5"))

    def test_sweeping_a_seen_target_after_access_needs_a_reason(self):
        gate = PhaseGate()
        gate.observe("10.99.50.11", "ssh_auth", "sshpass -p pw ssh svc@10.99.50.11 id",
                     "uid=1000(svc)", 0)
        refusal = gate.check("Bash nmap -sV 10.99.50.11")
        self.assertIsNotNone(refusal)
        self.assertIn("PHASE BLOCK", refusal)
        self.assertIn("reason", refusal)
        # The escape hatch is explicit, and a genuinely new segment is not blocked.
        self.assertIsNone(gate.check("Bash nmap -sV 10.99.50.11 -- reason=new segment"))
        self.assertIsNone(gate.check("Bash nmap -sV 10.50.0.11"))

    def test_a_first_sweep_is_allowed(self):
        gate = PhaseGate()
        self.assertIsNone(gate.check("Bash nmap -sV 10.99.50.0/24"))

    def test_attacking_an_unenumerated_host_is_refused(self):
        gate = PhaseGate()
        refusal = gate.check("Bash sqlmap -u http://10.0.0.9/item.php?id=1")
        self.assertIsNotNone(refusal)
        self.assertIn("no discovery record", refusal)
        gate.observe("10.0.0.9", "http_request", "curl -s http://10.0.0.9/", "<html>", 0)
        self.assertIsNone(gate.check("Bash sqlmap -u http://10.0.0.9/item.php?id=1"))


class TestRefusalMemory(unittest.TestCase):
    def test_signature_ignores_whitespace(self):
        self.assertEqual(action_signature("Bash  nmap   -sV 10.0.0.5"),
                         action_signature("Bash nmap -sV 10.0.0.5"))

    def test_a_refused_call_is_remembered(self):
        from evilkit.harness import HarnessState

        state = HarnessState()
        state.note_refusal("Bash mcp__mission__get_state {}")
        self.assertTrue(state.was_refused("Bash   mcp__mission__get_state   {}"))
        self.assertFalse(state.was_refused("Bash nmap -sV 10.0.0.5"))


class HookHelpers:
    """Shared hook-session fixtures (not a TestCase: subclasses would re-run tests)."""

    def setUp(self):
        super().setUp()
        os.environ["EVILKIMI_SCOPE"] = "10.99.50.0/24"
        os.environ["EVILKIMI_STATE_DIR"] = str(self.tmp / "state")
        os.environ.pop("EVILKIMI_HOOK_ENFORCE", None)
        self.addCleanup(os.environ.pop, "EVILKIMI_SCOPE", None)
        self.session = "battery-session"

    def cmd(self, text: str) -> str:
        """The string the harness sees for a Bash call (see kimihook.command_text)."""
        return f"Bash {text}"

    def log(self, records):
        path = kimihook.session_log_path(self.session)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record) + "\n")
        return path

    def pre(self, text, tool="Bash"):
        """PreToolUse for a Bash call whose command is ``text`` (without the tool)."""
        return kimihook.handle_event({
            "hookEventName": "PreToolUse",
            "sessionID": self.session,
            "toolName": tool,
            "toolInput": {"command": text},
        })

    def action(self, command, output="", returncode=0):
        return {"kind": "action", "ts": 1, "tool": "Bash", "command": command,
                "output": output, "returncode": returncode, "warnings": []}

    def denied(self, command, reason="DENIED for the test"):
        return {"kind": "denied", "ts": 2, "tool": "Bash", "command": command, "reason": reason}


class TestHookRefusals(HookHelpers, EvilkitTestCase):
    """The hook is the enforcement channel — a refusal has to come out as a deny."""

    # -- the plan's acceptance: Run 1's shape ---------------------------------

    def test_run_one_shape_replans_after_failed_tunnel_work(self):
        tunnel = self.cmd("ssh_tunnel --host 10.50.0.11 --user svc_backup")
        self.log([self.action(tunnel, "connection timed out", 1) for _ in range(3)])
        response = self.pre("ssh_tunnel --host 10.50.0.11 --user svc_backup")
        self.assertEqual(response.get("permissionDecision"), "deny", response)
        self.assertIn("PHASE BLOCK", response["permissionDecisionReason"])
        self.assertIn("Re-plan", response["permissionDecisionReason"])

    def test_terminal_repeated_refusal_cannot_happen_twice(self):
        """Run 1 ended on four identical mission__get_state calls. The second is denied."""
        self.log([self.denied(self.cmd("mcp__mission__get_state {}"))])
        response = self.pre("mcp__mission__get_state {}")
        self.assertEqual(response.get("permissionDecision"), "deny", response)
        self.assertIn("REPEAT REFUSAL", response["permissionDecisionReason"])

    def test_a_different_call_is_still_allowed_after_a_refusal(self):
        self.log([self.denied(self.cmd("mcp__mission__get_state {}"))])
        self.assertEqual(self.pre("nmap -sV 10.99.50.0/24"), {})

    def test_broad_scan_after_access_needs_a_reason(self):
        self.log([self.action(self.cmd("sshpass -p pw ssh svc@10.99.50.11 id"),
                              "uid=1000(svc) gid=1000(svc)", 0)])
        response = self.pre("nmap -sV 10.99.50.11")
        self.assertEqual(response.get("permissionDecision"), "deny", response)
        self.assertEqual(self.pre("nmap -sV 10.99.50.11 -- reason=verify the new port"), {})

    # -- journal and enforcement ---------------------------------------------

    def test_every_decision_is_journalled(self):
        path = self.log([self.denied(self.cmd("mcp__mission__get_state {}"))])
        self.pre("mcp__mission__get_state {}")
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(any(r.get("kind") == "pre" and r.get("decision") == "deny" for r in records))
        self.assertTrue(any(r.get("kind") == "denied" for r in records))

    def test_enforcement_off_turns_the_denial_into_a_warning(self):
        os.environ["EVILKIMI_HOOK_ENFORCE"] = "0"
        self.addCleanup(os.environ.pop, "EVILKIMI_HOOK_ENFORCE", None)
        path = self.log([self.denied(self.cmd("mcp__mission__get_state {}"))])
        self.assertEqual(self.pre("mcp__mission__get_state {}"), {})
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(any(r.get("kind") == "warn" for r in records))
        self.assertFalse(any(r.get("kind") == "denied" and "REPEAT" in r.get("reason", "")
                             for r in records))


class TestNoDeadlock(HookHelpers, EvilkitTestCase):
    """Regression: the gate must not be able to block the operator's own tools.

    A live session once reached a state where every call — `Read`, `TodoList`,
    `date; id; pwd` — came back `PHASE BLOCK: other has returned nothing usable 4
    times in a row`, because unrelated barren results shared one counter keyed on
    the catch-all technique. These tests pin the three properties that prevent it:
    untracked techniques are not counted, the counter is per (technique, target),
    and inspection tools are never judged by this gate.
    """

    def test_unrelated_barren_results_do_not_exhaust_anything(self):
        gate = PhaseGate()
        for command in ("Bash date", "Bash id; pwd", "Bash ls -la /tmp", "Bash env"):
            gate.observe("", "other", command, "", 0)      # empty output, four times
        self.assertIsNone(gate.check("Bash date; id; pwd"))
        self.assertIsNone(gate.check("Bash nmap -sV 10.0.0.5"))
        self.assertEqual(gate.technique_failures, {})

    def test_the_counter_is_per_technique_and_target(self):
        gate = PhaseGate()
        for _ in range(3):
            gate.observe("10.0.0.5", "nmap_scan", "nmap -sV 10.0.0.5", "", 1)
        self.assertIsNotNone(gate.check("Bash nmap -sV 10.0.0.5"))
        # A different target is a different attempt, not the same failure again.
        self.assertIsNone(gate.check("Bash nmap -sV 10.0.0.6"))
        # And a different technique against the exhausted target is allowed.
        self.assertIsNone(gate.check("Bash sshpass -p pw ssh svc@10.0.0.5 id"))

    def test_inspection_tools_are_never_blocked(self):
        gate = PhaseGate()
        for _ in range(6):
            gate.observe("10.0.0.5", "nmap_scan", "nmap -sV 10.0.0.5", "", 1)
        for command in ("Read /pkg/README.md", "TodoList", "tools_available",
                        "mission_status", "Glob **/*.md", "Grep target", "Skill pentest"):
            with self.subTest(command=command):
                self.assertIsNone(gate.check(command))

    def test_the_hook_cannot_deadlock_on_a_barren_streak(self):
        """The live failure, end to end through the hook."""
        self.log([self.action(self.cmd("date"), "", 0),
                  self.action(self.cmd("id"), "", 0),
                  self.action(self.cmd("pwd"), "", 0),
                  self.action(self.cmd("ls"), "", 0)])
        for command in ("Read README.md", "TodoList", "date; id; pwd", "tools_available"):
            with self.subTest(command=command):
                response = self.pre(command, tool="Read" if command.startswith("Read") else "Bash")
                self.assertEqual(response, {}, f"{command} was blocked: {response}")


if __name__ == "__main__":
    unittest.main()

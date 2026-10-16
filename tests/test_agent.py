"""Tests for `evilkit agent` — it must be held to the same scope gate as `run`.

The audit found the agent path launched the Kimi CLI without applying the
recorded scope, without checking the target against it, and without recording
the launch. These tests pin the fixed behaviour: fail closed when there is no
scope, refuse an out-of-scope target, and — when the target is in scope — inject
the scope into the child's environment and append a launch record.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase  # noqa: E402

from evilkit import audit  # noqa: E402
from evilkit.cli import EXIT_ERROR, EXIT_OK  # noqa: E402


class AgentCase(EvilkitTestCase):
    def _config_path(self):
        """A minimal but valid agent config written into the temp dir."""
        path = self.tmp / "agent.toml"
        path.write_text(
            'version = "v1"\nname = "test"\nsystem_prompt = "You are a tester."\n',
            encoding="utf-8",
        )
        return path

    def test_agent_refuses_when_no_mcp_json_is_present(self):
        code, _, err = self.call_main(
            ["agent", "--config", str(self._config_path()), "--target", "10.0.0.5:443"]
        )
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("nothing to scope", err)

    def test_agent_refuses_a_target_outside_the_recorded_scope(self):
        self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        code, _, err = self.call_main(
            ["agent", "--config", str(self._config_path()), "--target", "10.9.9.9:443"]
        )
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not within the recorded scope", err)

    def test_agent_runs_in_scope_and_injects_the_scope_env(self):
        self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        code, out, _ = self.call_main(
            ["agent", "--config", str(self._config_path()), "--target", "10.0.0.5:443"]
        )
        self.assertEqual(code, EXIT_OK)
        # The stub kimi echoes the scope and identity it was launched with.
        self.assertIn("scope:10.0.0.0/24", out)
        self.assertIn("identity:evilkit", out)

    def test_agent_records_the_launch(self):
        self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        self.call_main(
            ["agent", "--config", str(self._config_path()), "--target", "10.0.0.5:443"]
        )
        entries, _ = audit.read(audit.default_log_path())
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["scope"], "10.0.0.0/24")
        self.assertTrue(entries[0]["enforced"])


if __name__ == "__main__":
    unittest.main()

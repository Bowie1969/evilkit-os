"""Tests for evilkit.watch — the guard pane.

The pane is split into a snapshot (which touches the disk) and a render (which
returns a string), so most of this file asserts on text rather than driving a
terminal. The one exception is the sampling loop, which is exercised as a real
subprocess because that is the only way to prove it notices a change made by
another process while it is running.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import PROJECT_ROOT, EvilkitTestCase  # noqa: E402

from evilkit import audit, watch  # noqa: E402
from evilkit.cli import EXIT_ERROR, EXIT_OK  # noqa: E402


class WatchCase(EvilkitTestCase):
    """Helpers for sampling the fixture the way the pane does."""

    def sample(self, scope: str):
        path = self.write_mcp_json(self.pentest_fixture(scope))
        return path, watch.snapshot(path)

    def resample(self, path, scope: str, *, age: float = 0.0):
        """Rewrite the fixture in place, optionally pushing its mtime forward."""
        self.write_mcp_json(self.pentest_fixture(scope), directory=path.parent)
        if age:
            stat = path.stat()
            os.utime(path, (stat.st_atime, stat.st_mtime + age))
        return watch.snapshot(path)

    def spawn_watch(self, interval: str = "0.1"):
        """Run the sampling loop as a real process, against the fixture dir.

        A daemon thread drains the child's stdout as it is produced. Without it
        the OS pipe buffer fills (the pane rewrites a full frame ~10x/second) and
        the child blocks on write, freezing the very sampling loop the test is
        trying to observe. The drained text is accumulated so ``wait_for`` and
        ``stop`` can read what the pane has emitted so far.
        """
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [str(PROJECT_ROOT), env.get("PYTHONPATH", "")]
        ).strip(os.pathsep)
        proc = subprocess.Popen(
            [sys.executable, "-m", "evilkit", "watch", "--interval", interval, "--no-color"],
            cwd=str(self.tmp),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        proc._evk_chunks = []  # type: ignore[attr-defined]
        proc._evk_lock = threading.Lock()  # type: ignore[attr-defined]

        def _drain() -> None:
            for chunk in iter(lambda: proc.stdout.read(4096), ""):
                with proc._evk_lock:  # type: ignore[attr-defined]
                    proc._evk_chunks.append(chunk)  # type: ignore[attr-defined]

        reader = threading.Thread(target=_drain, daemon=True)
        reader.start()
        proc._evk_reader = reader  # type: ignore[attr-defined]
        self.addCleanup(proc.kill)
        return proc

    @staticmethod
    def _drained(proc) -> str:
        with proc._evk_lock:  # type: ignore[attr-defined]
            return "".join(proc._evk_chunks)  # type: ignore[attr-defined]

    def wait_for(self, proc, needle: str, timeout: float = 10.0) -> str:
        """Poll the drained output until ``needle`` appears or ``timeout`` elapses.

        Replaces a fixed post-write sleep: the assertion no longer depends on a
        sample landing inside an arbitrary window, so a loaded CPU only makes the
        test slower, never flaky.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            out = self._drained(proc)
            if needle in out:
                return out
            time.sleep(0.02)
        return self._drained(proc)

    def settle(self, proc, seconds: float = 1.0) -> str:
        """Let the loop run for a bounded spell (for asserting nothing appears)."""
        time.sleep(seconds)
        return self._drained(proc)

    def stop(self, proc) -> str:
        try:
            proc.terminate()
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            proc.kill()
            proc.wait(timeout=15)
        proc._evk_reader.join(timeout=5)  # type: ignore[attr-defined]
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except Exception:  # pragma: no cover - defensive
                pass
        return self._drained(proc)


class TestWidened(unittest.TestCase):
    """`widened` must never claim a direction it cannot prove."""

    def test_a_supernet_containing_the_old_scope_is_a_widening(self):
        self.assertTrue(watch.widened("10.0.0.0/24", "10.0.0.0/8"))

    def test_a_subnet_is_not_a_widening(self):
        self.assertFalse(watch.widened("10.0.0.0/8", "10.0.0.0/24"))

    def test_an_unchanged_scope_is_not_a_widening(self):
        self.assertFalse(watch.widened("10.0.0.0/24", "10.0.0.0/24"))

    def test_an_added_network_is_a_widening(self):
        self.assertTrue(watch.widened("10.0.0.0/24", "10.0.0.0/24,10.1.0.0/16"))

    def test_a_dropped_network_is_not_a_widening(self):
        self.assertFalse(watch.widened("10.0.0.0/24,10.1.0.0/16", "10.0.0.0/24"))

    def test_a_host_swallowed_by_a_network_is_a_widening(self):
        self.assertTrue(watch.widened("10.0.0.5", "10.0.0.0/24"))

    def test_hostnames_are_never_a_widening(self):
        self.assertFalse(watch.widened("app.lan", "app.lan,other.lan"))

    def test_mixed_address_families_are_never_a_widening(self):
        self.assertFalse(watch.widened("10.0.0.0/24", "2001:db8::/32"))

    def test_a_replaced_scope_is_never_a_widening(self):
        self.assertFalse(watch.widened("10.0.0.0/24", "192.168.0.0/16"))


class TestCompare(WatchCase):
    def test_a_steady_resample_raises_nothing(self):
        path, before = self.sample("10.0.0.0/24")
        self.assertIsNone(watch.compare(before, watch.snapshot(path)))

    def test_a_wider_scope_is_an_alarm(self):
        path, before = self.sample("10.0.0.0/24")
        change = watch.compare(before, self.resample(path, "10.0.0.0/8", age=5))
        self.assertEqual(change.level, watch.ALARM)
        self.assertIn("10.0.0.0/24 -> 10.0.0.0/8", change.text)
        self.assertIn("wider than before", change.text)

    def test_a_narrower_scope_is_only_a_note(self):
        path, before = self.sample("10.0.0.0/8")
        change = watch.compare(before, self.resample(path, "10.0.0.0/24", age=5))
        self.assertEqual(change.level, watch.NOTE)
        self.assertNotIn("wider", change.text)

    def test_a_rewrite_that_keeps_the_scope_is_only_a_note(self):
        path, before = self.sample("10.0.0.0/24")
        change = watch.compare(before, self.resample(path, "10.0.0.0/24", age=5))
        self.assertEqual(change.level, watch.NOTE)
        self.assertIn("rewritten", change.text)

    def test_deleting_the_file_is_an_alarm(self):
        path, before = self.sample("10.0.0.0/24")
        path.unlink()
        change = watch.compare(before, watch.snapshot(path))
        self.assertEqual(change.level, watch.ALARM)
        self.assertIn("can no longer be read", change.text)

    def test_invalid_json_is_an_alarm(self):
        path, before = self.sample("10.0.0.0/24")
        path.write_text("{not json", encoding="utf-8")
        change = watch.compare(before, watch.snapshot(path))
        self.assertEqual(change.level, watch.ALARM)

    def test_losing_the_pentest_server_is_an_alarm(self):
        path, before = self.sample("10.0.0.0/24")
        self.write_mcp_json({"mcpServers": {"mission": {"command": "x"}}}, directory=self.tmp)
        change = watch.compare(before, watch.snapshot(path))
        self.assertEqual(change.level, watch.ALARM)
        self.assertIn("no longer declares a scope", change.text)

    def test_a_scope_appearing_where_there_was_none_is_reported(self):
        path = self.write_mcp_json({"mcpServers": {"pentest": {"command": "x"}}})
        before = watch.snapshot(path)
        change = watch.compare(before, self.resample(path, "10.0.0.0/24", age=5))
        self.assertEqual(change.level, watch.NOTE)
        self.assertIn("a scope appeared", change.text)

    def test_an_unreadable_file_does_not_read_as_a_lost_scope(self):
        path, before = self.sample("10.0.0.0/24")
        path.write_text("{not json", encoding="utf-8")
        change = watch.compare(before, watch.snapshot(path))
        self.assertNotIn("no longer declares a scope", change.text)


class TestRender(WatchCase):
    def frame(self, scope: str = "10.0.0.0/24", width: int = 78, **kwargs):
        path = self.write_mcp_json(self.pentest_fixture(scope))
        state = watch.snapshot(path)
        return watch.render(state, [], [], started=0.0, now_ts=3600.0, width=width, **kwargs)

    def test_the_frame_names_the_scope_and_the_file(self):
        out = self.frame("10.20.30.0/24")
        self.assertIn("evilkit watch", out)
        self.assertIn("10.20.30.0/24", out)
        self.assertIn(".mcp.json", out)

    def test_an_empty_alert_list_says_so(self):
        self.assertIn("nothing has changed", self.frame())

    def test_an_alarm_is_marked_and_can_be_coloured(self):
        state = watch.snapshot(self.write_mcp_json(self.pentest_fixture("10.0.0.0/24")))
        alerts = [watch.Alert("10:00:00", "the scope changed", watch.ALARM)]
        plain = watch.render(state, [], alerts, started=0.0, now_ts=3600.0, color=False)
        self.assertIn("!!", plain)
        self.assertNotIn("\x1b[", plain)
        painted = watch.render(state, [], alerts, started=0.0, now_ts=3600.0, color=True)
        self.assertIn("\x1b[31m", painted)

    def test_launches_are_listed_newest_first(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        state = watch.snapshot(path)
        older = {"at": "2026-09-16T01:00:00Z", "scope": "10.0.0.0/24", "enforced": True}
        newer = {"at": "2026-09-16T02:00:00Z", "scope": "10.9.9.0/24", "enforced": True}
        out = watch.render(state, [older, newer], [], started=0.0, now_ts=3600.0)
        section = out.split("RECENT LAUNCHES", 1)[1]
        self.assertLess(section.index("10.9.9.0/24"), section.index("10.0.0.0/24"))

    def test_a_launch_that_was_not_enforced_says_so(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        state = watch.snapshot(path)
        entry = {"at": "2026-09-16T02:00:00Z", "scope": "10.0.0.0/24", "enforced": False}
        out = watch.render(state, [entry], [], started=0.0, now_ts=3600.0)
        self.assertIn("NOT enforced", out)

    def test_an_empty_log_is_reported_rather_than_shown_blank(self):
        self.assertIn("nothing recorded yet", self.frame())

    def test_a_log_note_replaces_the_launch_list(self):
        out = self.frame(log_note="log unreadable (nope)")
        self.assertIn("log unreadable", out)
        self.assertNotIn("nothing recorded yet", out)

    def test_the_footer_says_the_pane_decides_nothing(self):
        self.assertIn("decides nothing", self.frame())

    def test_the_rule_matches_the_requested_width(self):
        self.assertIn("\u2500" * 64, self.frame(width=64))


class TestWatchCommand(WatchCase):
    def test_once_prints_a_frame_and_exits_clean(self):
        self.write_mcp_json(self.pentest_fixture("10.20.30.0/24"))
        code, out, err = self.call_main(["watch", "--once"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(err, "")
        self.assertIn("10.20.30.0/24", out)
        self.assertIn("evilkit watch", out)

    def test_once_emits_no_ansi_when_the_output_is_not_a_terminal(self):
        self.write_mcp_json(self.pentest_fixture("10.20.30.0/24"))
        _, out, _ = self.call_main(["watch", "--once"])
        self.assertNotIn("\x1b", out)

    def test_once_reads_an_explicit_path(self):
        path = self.write_mcp_json(self.pentest_fixture("192.168.0.0/16"))
        code, out, _ = self.call_main(["watch", "--once", "--mcp-json", str(path)])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("192.168.0.0/16", out)

    def test_once_shows_the_recorded_launches(self):
        path = self.write_mcp_json(self.pentest_fixture("10.20.30.0/24"))
        audit.record(
            audit.default_log_path(),
            audit.launch_entry("10.20.30.0/24", enforced=True, mcp_json=path, kimi="kimi"),
        )
        code, out, _ = self.call_main(["watch", "--once"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("enforced", out)
        self.assertNotIn("nothing recorded yet", out)

    def test_limit_zero_hides_the_launch_list(self):
        path = self.write_mcp_json(self.pentest_fixture("10.20.30.0/24"))
        audit.record(
            audit.default_log_path(),
            audit.launch_entry("10.20.30.0/24", enforced=True, mcp_json=path, kimi="kimi"),
        )
        _, out, _ = self.call_main(["watch", "--once", "--limit", "0"])
        self.assertNotIn("enforced", out)

    def test_a_note_is_shown_when_the_log_cannot_be_read(self):
        self.write_mcp_json(self.pentest_fixture("10.20.30.0/24"))
        log = audit.default_log_path()
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("{not json\n", encoding="utf-8")
        _, out, _ = self.call_main(["watch", "--once"])
        self.assertIn("unreadable line(s) skipped", out)

    def test_watch_without_a_fixture_exits_one(self):
        code, out, err = self.call_main(["watch", "--once"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertEqual(out, "")
        self.assertIn("no .mcp.json", err)

    def test_watch_help_lists_its_flags(self):
        code, out, _ = self.call_main(["watch", "--help"])
        self.assertEqual(code, EXIT_OK)
        for flag in ("--interval", "--once", "--no-color", "--mcp-json", "--limit"):
            self.assertIn(flag, out)

    def test_the_loop_alarms_on_a_change_made_by_another_process(self):
        """The whole point: it notices, while it runs, from outside."""
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        proc = self.spawn_watch()
        try:
            # Wait for the first frame so the change is made against a known sample.
            self.wait_for(proc, "scope in force")
            self.write_mcp_json(self.pentest_fixture("10.0.0.0/8"), directory=path.parent)
            out = self.wait_for(proc, "the recorded scope changed under you")
        finally:
            out = self.stop(proc)

        self.assertIn("the recorded scope changed under you", out)
        self.assertIn("10.0.0.0/24 ->", out)
        self.assertIn("wider than before", out)

    def test_the_loop_does_not_alarm_on_a_rewrite_that_keeps_the_scope(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        proc = self.spawn_watch()
        try:
            self.wait_for(proc, "scope in force")
            self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"), directory=path.parent)
            self.settle(proc)
        finally:
            out = self.stop(proc)

        self.assertNotIn("changed under you", out)
        self.assertNotIn("wider than before", out)


class TestSanitisedRendering(unittest.TestCase):
    """A scope string is attacker-influenced; escapes must not reach the pane."""

    def _state(self, scope):
        return watch.ScopeState(
            path=Path("/tmp/.mcp.json"), scope=scope, digest="x", mtime=0.0
        )

    def test_escape_sequences_in_the_scope_are_neutralised(self):
        evil = "10.0.0.0/24\x1b[2J\x1b[31m[ALERTS] verified"
        frame = watch.render(
            self._state(evil), [], [], started=0.0, now_ts=0.0, color=False
        )
        self.assertNotIn("\x1b", frame)
        self.assertIn("�", frame)

    def test_escape_sequences_in_a_launch_line_are_neutralised(self):
        entry = {"at": "2026-01-01T00:00:00Z", "scope": "10.0.0.0/24\x1b[2J", "enforced": True}
        line = watch.format_launch(entry)
        self.assertNotIn("\x1b", line)


if __name__ == "__main__":
    unittest.main()

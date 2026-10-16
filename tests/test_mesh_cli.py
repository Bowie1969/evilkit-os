from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from evilkit import mesh


class MeshCliDispatchTests(unittest.TestCase):
    """Every read-only mesh subcommand must fail cleanly, never crash.

    ``mesh.main`` is one long function, so a stray local ``import`` in any branch
    turns that name local for all of it. That is how ``mesh watch`` and ``mesh
    tail`` came to die with ``UnboundLocalError: urllib`` before they ever printed
    a line.
    """

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="evilkit-mesh-cli-")
        self.token = Path(self.temp.name) / "token"
        self.token.write_text("t" * 40 + "\n", encoding="utf-8")
        self.token.chmod(0o600)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _run(self, argv: list[str]) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = mesh.main(argv)
        return code, out.getvalue()

    def test_watch_reports_an_unreachable_hub_instead_of_raising(self) -> None:
        code, output = self._run([
            "watch", "--leader", "http://127.0.0.1:1",
            "--token-file", str(self.token),
        ])
        self.assertEqual(code, 1)
        self.assertIn("could not reach hub", output)
        self.assertNotIn("UnboundLocalError", output)

    def test_tail_reports_an_unreachable_hub_instead_of_raising(self) -> None:
        code, output = self._run([
            "tail", "--leader", "http://127.0.0.1:1",
            "--token-file", str(self.token),
        ])
        self.assertEqual(code, 1)
        self.assertIn("could not reach hub", output)

    def test_watch_streams_events_from_a_stub_hub(self) -> None:
        events = {"events": [{"seq": 1, "worker": "evilkit-pi-01", "kind": "output", "text": "hello"}],
                  "sequence": 1}
        with mock.patch.object(mesh, "_request", side_effect=[events, KeyboardInterrupt]) as request:
            code, output = self._run([
                "watch", "--leader", "http://127.0.0.1:1",
                "--token-file", str(self.token),
            ])
        self.assertEqual(code, 130)
        self.assertTrue(request.called)
        self.assertIn("[evilkit-pi-01] hello", output)


if __name__ == "__main__":
    unittest.main()

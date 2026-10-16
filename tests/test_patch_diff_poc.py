"""Unit tests for evilkit.patch_diff_poc.

These tests never touch the network: fetch_commit / fetch_diff are not called.
The pipeline is exercised through the pure helpers and render_script, and the
rendered script is both parsed by ast and executed against a tiny stdlib HTTP
server so the scope gate and request round-trip are proven.
"""

from __future__ import annotations

import ast
import http.server
import json
import socketserver
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from evilkit import patch_diff_poc as pdp


PILLOW_DIFF = """\
diff --git a/src/PIL/ImageMath.py b/src/PIL/ImageMath.py
--- a/src/PIL/ImageMath.py
+++ b/src/PIL/ImageMath.py
@@ -200,6 +200,8 @@ def eval(expression, _dict={}, **kw):
-    out = builtins.eval(expression, {"__builtins__": builtins}, args)
+    code = compile(expression, "<string>", "eval")
+    out = builtins.eval(code, {"__builtins__": {}}, args)
"""


FLASK_DIFF = """\
diff --git a/app/server.py b/app/server.py
--- a/app/server.py
+++ b/app/server.py
@@ -10,6 +10,10 @@
+@app.route("/eval")
+def do_eval():
+    expr = request.args.get("expr")
+    return ImageMath.eval(expr)
"""


# -- URL parsing ---------------------------------------------------------------


def test_parse_commit_url_long_form():
    c = pdp.parse_commit_url(
        "https://github.com/python-pillow/Pillow/commit/3bd1fdd634c7e4ff8ca9ba7e35be78030d2820d1"
    )
    assert c.owner == "python-pillow"
    assert c.repo == "Pillow"
    assert c.sha.startswith("3bd1fdd")
    assert c.slug == "python-pillow/Pillow@3bd1fdd634c7"


def test_parse_commit_url_short_form():
    c = pdp.parse_commit_url("owner/repo@abcdef0")
    assert (c.owner, c.repo, c.sha) == ("owner", "repo", "abcdef0")


def test_parse_commit_url_rejects_junk():
    with pytest.raises(pdp.PatchDiffError):
        pdp.parse_commit_url("not a url")
    with pytest.raises(pdp.PatchDiffError):
        pdp.parse_commit_url("https://github.com/x/y/pull/1")


# -- sink classification -------------------------------------------------------


def test_classify_sink_eval():
    assert pdp.classify_sink(PILLOW_DIFF) == "eval-sink"


def test_classify_sink_cmd_injection():
    diff = '+    os.system("echo " + user)\n'
    assert pdp.classify_sink(diff) == "cmd-injection"


def test_classify_sink_sqli_union():
    diff = '+    cur.execute("SELECT * FROM users WHERE name=\'" + name + "\'")\n'
    assert pdp.classify_sink(diff) == "sqli-union"


def test_classify_sink_unknown():
    assert pdp.classify_sink("+    pass\n") == "unknown"


# -- param + endpoint extraction ----------------------------------------------


def test_extract_params_flask():
    params = pdp.extract_params(['    expr = request.args.get("expr")'])
    assert params == ["expr"]


def test_extract_params_dedupes_and_preserves_order():
    lines = [
        'request.args.get("a")',
        'request.form.get("b")',
        'request.args.get("a")',
    ]
    assert pdp.extract_params(lines) == ["a", "b"]


# -- recipe build --------------------------------------------------------------


def test_build_recipe_pillow_diff():
    commit = pdp.CommitRef("python-pillow", "Pillow", "3bd1fdd6")
    meta = {"commit": {"message": "Fix CVE-2022-22817: avoid eval() of user expression\n\nDetails."}}
    r = pdp.build_recipe(commit, meta, PILLOW_DIFF)
    assert r.sink_class == "eval-sink"
    assert r.cve_id == "CVE-2022-22817"
    assert r.affected_files == ["src/PIL/ImageMath.py"]
    assert "builtins.eval(expression" in r.removed_lines[0]


def test_build_recipe_extracts_params_and_endpoint():
    commit = pdp.CommitRef("x", "y", "deadbeef")
    r = pdp.build_recipe(commit, {"commit": {"message": "patch CVE-2026-0001"}}, FLASK_DIFF)
    assert r.params == ["expr"]
    assert r.endpoint_hints == ["/eval"]
    assert r.cve_id == "CVE-2026-0001"


# -- rendered script -----------------------------------------------------------


def test_render_script_is_valid_python():
    commit = pdp.CommitRef("x", "y", "deadbeef")
    r = pdp.build_recipe(commit, {"commit": {"message": "CVE-2026-0001"}}, FLASK_DIFF)
    text = pdp.render_script(r)
    ast.parse(text)  # must parse as a complete python module
    assert "--scope-file" in text
    assert "host_in_scope" in text
    assert "expr" in text  # default param baked in
    assert "/eval" in text


def _run_fake_server(responses: dict[str, bytes]) -> tuple[socketserver.TCPServer, int, threading.Thread]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = responses.get(self.path, b"not found")
            code = 200 if self.path in responses else 404
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a, **_kw):  # silence
            return

    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port, t


def test_rendered_script_scope_refuses_out_of_scope(tmp_path):
    commit = pdp.CommitRef("x", "y", "deadbeef")
    r = pdp.build_recipe(commit, {"commit": {"message": "demo"}}, FLASK_DIFF)
    script = tmp_path / "poc.py"
    script.write_text(pdp.render_script(r))
    scope = tmp_path / "scope.txt"
    scope.write_text("10.99.50.114\n")  # does NOT include 127.0.0.1

    srv, port, _t = _run_fake_server({"/eval?expr=X": b"never reached"})
    try:
        proc = subprocess.run(
            [sys.executable, str(script),
             "--target", f"http://127.0.0.1:{port}",
             "--scope-file", str(scope),
             "--payload", "X"],
            capture_output=True, text=True, timeout=10,
        )
    finally:
        srv.shutdown()
    assert proc.returncode == 3  # scope-refused exit
    assert "REFUSED" in proc.stderr


def test_rendered_script_fires_when_in_scope_and_writes_evidence(tmp_path):
    commit = pdp.CommitRef("x", "y", "deadbeef")
    r = pdp.build_recipe(commit, {"commit": {"message": "demo"}}, FLASK_DIFF)
    script = tmp_path / "poc.py"
    script.write_text(pdp.render_script(r))
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1/32\n")
    evidence = tmp_path / "ev.json"

    srv, port, _t = _run_fake_server({"/eval?expr=marker": b"HIT: marker-echoed"})
    try:
        proc = subprocess.run(
            [sys.executable, str(script),
             "--target", f"http://127.0.0.1:{port}",
             "--scope-file", str(scope),
             "--payload", "marker",
             "--evidence", str(evidence)],
            capture_output=True, text=True, timeout=10,
        )
    finally:
        srv.shutdown()
    assert proc.returncode == 0
    assert "HIT: marker-echoed" in proc.stdout
    rec = json.loads(evidence.read_text())
    assert rec["hit"] is True
    assert rec["status"] == 200
    assert rec["payload"] == "marker"
    assert rec["sink_class"] == "eval-sink"

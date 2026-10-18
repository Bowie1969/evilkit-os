"""Unit tests for evilkit.script_harness.

The sandboxed ``run()`` path is exercised end-to-end with a tiny in-process
script (no network). bubblewrap-dependent behaviour is skipped when bwrap is not
installed; the deterministic path uses sandbox="none".
"""

from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest

from evilkit import script_harness as sh


def _write_script(path, body: str, *, executable: bool = True) -> None:
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    if executable:
        os.chmod(path, 0o755)


def test_snapshot_dir_hashes_regular_files(tmp_path):
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("world", encoding="utf-8")
    snap = sh.snapshot_dir(tmp_path)
    assert set(snap) == {"a.txt", "sub/b.txt"}
    assert len(snap["a.txt"]) == 64  # sha256 hex length


def test_diff_snapshots_reports_all_classes():
    before = {"same": "x", "changed": "old", "removed": "gone"}
    after = {"same": "x", "changed": "new", "added": "fresh"}
    diff = sh.diff_snapshots(before, after)
    assert diff == {"added": ["added"], "changed": ["changed"], "removed": ["removed"]}


def test_detect_bwrap_returns_path_or_none():
    # The function must not raise regardless of whether bwrap is installed.
    result = sh.detect_bwrap()
    assert result is None or os.path.isabs(result)


def test_run_refuses_out_of_scope_target(tmp_path):
    script = tmp_path / "s.py"
    _write_script(script, "#!/usr/bin/env python3\nprint('hi')\n")
    with pytest.raises(sh.ScriptHarnessError, match="outside scope"):
        sh.run(script, target="10.9.9.9", scope="127.0.0.1", sandbox="none",
               evidence_dir=tmp_path / "ev")


def test_run_refuses_missing_script(tmp_path):
    with pytest.raises(sh.ScriptHarnessError, match="script not found"):
        sh.run(tmp_path / "nope.py", target="127.0.0.1", scope="127.0.0.1")


def test_run_refuses_unknown_sandbox(tmp_path):
    script = tmp_path / "s.py"
    _write_script(script, "#!/usr/bin/env python3\nprint('hi')\n")
    with pytest.raises(sh.ScriptHarnessError, match="unknown sandbox"):
        sh.run(script, target="127.0.0.1", scope="127.0.0.1", sandbox="bogus")


def test_run_none_sandbox_captures_output_and_fs_diff(tmp_path):
    script = tmp_path / "s.py"
    _write_script(script, """\
        #!/usr/bin/env python3
        from pathlib import Path
        print("running")
        Path("marker.txt").write_text("payload", encoding="utf-8")
        """)
    record = sh.run(script, target="127.0.0.1", scope="127.0.0.1", sandbox="none",
                    evidence_dir=tmp_path / "ev")
    assert record["sandbox"] == "none"
    assert record["returncode"] == 0
    assert "running" in record["stdout"]
    assert record["fs_diff"]["added"] == ["marker.txt"]
    assert (tmp_path / "ev" / "work" / "marker.txt").read_text(encoding="utf-8") == "payload"


def test_run_times_out(tmp_path):
    script = tmp_path / "s.py"
    _write_script(script, "#!/usr/bin/env python3\nimport time\ntime.sleep(5)\n")
    record = sh.run(script, target="127.0.0.1", scope="127.0.0.1", sandbox="none",
                    timeout=0.3, evidence_dir=tmp_path / "ev")
    assert record["timed_out"] is True
    assert record["returncode"] is None


@pytest.mark.skipif(sh.detect_bwrap() is None, reason="bubblewrap not installed")
def test_run_relative_evidence_dir_works_with_bwrap(tmp_path, monkeypatch):
    # A relative evidence_dir used to break bwrap: the bind source resolved
    # against the sandbox's chdir'd cwd. It must resolve to an absolute path.
    script = tmp_path / "s.py"
    _write_script(script, """\
        #!/usr/bin/env python3
        from pathlib import Path
        Path("m.txt").write_text("ok", encoding="utf-8")
        """)
    monkeypatch.chdir(tmp_path)
    record = sh.run(script, target="127.0.0.1", scope="127.0.0.1", sandbox="bwrap",
                    evidence_dir="rel-ev")
    assert record["returncode"] == 0
    assert (tmp_path / "rel-ev" / "work" / "m.txt").read_text(encoding="utf-8") == "ok"


def test_run_pcap_references_capture_and_waits_for_header(tmp_path, monkeypatch):
    from unittest import mock

    script = tmp_path / "s.py"
    _write_script(script, "#!/usr/bin/env python3\nprint('hi')\n")
    created = {}

    monkeypatch.setattr(sh.shutil, "which", lambda name: "/usr/sbin/tcpdump" if name == "tcpdump" else None)

    def fake_popen(argv, **kwargs):
        if argv[0] == "/usr/sbin/tcpdump":
            pcap_file = Path(argv[4])  # tcpdump ... -w <path> host <target> -n
            pcap_file.parent.mkdir(parents=True, exist_ok=True)
            pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
            created["pcap"] = str(pcap_file)
            proc = mock.Mock()
            proc.poll.return_value = None
            return proc
        raise AssertionError(f"unexpected Popen {argv}")

    def fake_run(argv, **kwargs):
        proc = mock.Mock()
        proc.returncode = 0
        proc.stdout = "hi\n"
        proc.stderr = ""
        return proc

    monkeypatch.setattr(sh.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(sh.subprocess, "run", fake_run)

    record = sh.run(script, target="127.0.0.1", scope="127.0.0.1", sandbox="none",
                    pcap_iface="eth0", evidence_dir=tmp_path / "ev")
    assert record["pcap"] == created["pcap"]
    assert record["returncode"] == 0


@pytest.mark.skipif(sh.detect_bwrap() is None, reason="bubblewrap not installed")
def test_run_bwrap_sandbox_captures_and_isolates(tmp_path):
    script = tmp_path / "s.py"
    _write_script(script, """\
        #!/usr/bin/env python3
        from pathlib import Path
        print("bwrap-running")
        Path("marker.txt").write_text("ok", encoding="utf-8")
        try:
            Path("/etc/harness-probe").write_text("x", encoding="utf-8")
        except OSError:
            print("ro-root-enforced")
        """)
    record = sh.run(script, target="127.0.0.1", scope="127.0.0.1", sandbox="bwrap",
                    evidence_dir=tmp_path / "ev")
    assert record["sandbox"] == "bwrap"
    assert record["returncode"] == 0
    assert "bwrap-running" in record["stdout"]
    assert record["fs_diff"]["added"] == ["marker.txt"]
    # Writing outside the workdir must have been blocked by the read-only root.
    assert "ro-root-enforced" in record["stdout"]

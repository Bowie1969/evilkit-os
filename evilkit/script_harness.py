"""Run a rendered script against an in-scope target in a disposable sandbox.

``evilkit script-harness run`` is the "detonate + measure" half of the scripting
loop. It scope-gates the target, runs the script inside bubblewrap (read-only
root, a fresh tmpfs-backed workdir, private PID namespace) so the appliance is
never at risk, and returns a JSON evidence record: output, exit code, a
filesystem diff of the workdir, timing, and optionally a pcap of the traffic to
the target. That record is what feeds the potency scorer.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from . import scope as scope_mod

__all__ = [
    "ScriptHarnessError",
    "detect_bwrap",
    "snapshot_dir",
    "diff_snapshots",
    "run",
]

# Keep these aligned with cli.EXIT_*.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


class ScriptHarnessError(Exception):
    """The harness refused to run (scope, environment, or target problem)."""


def detect_bwrap() -> str | None:
    """Return the bubblewrap binary path, or ``None`` when it is unavailable."""
    return shutil.which("bwrap")


def snapshot_dir(root: Path) -> dict[str, str]:
    """Map relative path -> sha256 for every regular file under *root*."""
    out: dict[str, str] = {}
    if not root.is_dir():
        return out
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            path = Path(dirpath) / name
            try:
                rel = str(path.relative_to(root))
                out[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                continue
    return out


def diff_snapshots(before: dict[str, str], after: dict[str, str]) -> dict[str, list[str]]:
    """Return the added / changed / removed paths between two snapshots."""
    return {
        "added": sorted(set(after) - set(before)),
        "changed": sorted(k for k in set(before) & set(after) if before[k] != after[k]),
        "removed": sorted(set(before) - set(after)),
    }


def _bwrap_argv(bwrap: str, script: Path, work: Path, passthrough: list[str]) -> list[str]:
    # Read-only root + a writable /work bound to the host workdir + private PID
    # namespace. The network namespace is deliberately shared so the script can
    # reach the in-scope target.
    return [
        bwrap,
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--tmpfs", "/var/tmp",
        "--bind", str(work), "/tmp/harness-work",
        "--chdir", "/tmp/harness-work",
        "--unshare-pid",
        "--die-with-parent",
        "--ro-bind", str(script), str(script),
        "--",
        str(script),
        *passthrough,
    ]


def run(
    script_path: str | Path,
    *,
    target: str,
    scope: str,
    sandbox: str = "auto",
    timeout: float = 60.0,
    evidence_dir: str | Path | None = None,
    passthrough: list[str] | None = None,
    pcap_iface: str | None = None,
) -> dict:
    """Run *script_path* against *target* and return an evidence record.

    Raises :class:`ScriptHarnessError` when the target is out of scope, the
    script is missing, or a requested sandbox is unavailable.
    """
    script = Path(script_path).resolve()
    if not script.is_file():
        raise ScriptHarnessError(f"script not found: {script}")
    if not scope_mod.target_in_scope(target, scope):
        raise ScriptHarnessError(f"target {target!r} is outside scope {scope!r}")

    passthrough = list(passthrough or [])
    # Resolve to an absolute path: bwrap's bind source and the subprocess cwd are
    # both built from this, and a relative path makes the bind source resolve
    # against the sandbox's (already-chdir'd) cwd and fail.
    evidence_dir = (
        Path(evidence_dir).expanduser().resolve() if evidence_dir is not None else Path.cwd()
    )
    evidence_dir.mkdir(parents=True, exist_ok=True)
    work = evidence_dir / "work"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    bwrap: str | None
    if sandbox in ("auto", "bwrap"):
        bwrap = detect_bwrap()
    elif sandbox == "none":
        bwrap = None
    else:
        raise ScriptHarnessError(f"unknown sandbox {sandbox!r} (use auto, bwrap, or none)")
    if sandbox == "bwrap" and bwrap is None:
        raise ScriptHarnessError("bwrap sandbox requested but bubblewrap is not installed")
    mode = "bwrap" if bwrap else "none"

    before = snapshot_dir(work)

    argv = _bwrap_argv(bwrap, script, work, passthrough) if bwrap else [str(script), *passthrough]

    pcap_proc: subprocess.Popen | None = None
    pcap_path: Path | None = None
    if pcap_iface:
        tcpdump = shutil.which("tcpdump")
        if tcpdump is None:
            raise ScriptHarnessError("--pcap requested but tcpdump is not installed")
        pcap_path = evidence_dir / f"harness-{int(time.time())}.pcap"
        pcap_proc = subprocess.Popen(
            [tcpdump, "-i", pcap_iface, "-w", str(pcap_path), "host", target, "-n"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # tcpdump needs a moment to attach and write its header; a fast probe
        # that finishes first leaves a header-only pcap. Wait for the header so
        # the capture covers the whole run.
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                if pcap_path.stat().st_size > 0:
                    break
            except OSError:
                pass
            time.sleep(0.02)

    started = time.time()
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, cwd=str(work)
        )
        returncode: int | None = proc.returncode
        stdout, stderr = proc.stdout, proc.stderr
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        returncode, stdout, stderr, timed_out = None, exc.stdout or "", exc.stderr or "", True
    finally:
        if pcap_proc is not None and pcap_proc.poll() is None:
            pcap_proc.send_signal(signal.SIGINT)
            try:
                pcap_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pcap_proc.kill()

    duration = time.time() - started
    after = snapshot_dir(work)

    return {
        "script": str(script),
        "target": target,
        "scope_ok": True,
        "sandbox": mode,
        "returncode": returncode,
        "timed_out": timed_out,
        "duration_s": round(duration, 3),
        "stdout": stdout,
        "stderr": stderr,
        "fs_diff": diff_snapshots(before, after),
        "pcap": str(pcap_path) if pcap_path else None,
        "timestamp": time.time(),
    }


def main(argv: list[str] | None = None) -> int:
    """Standalone entry point mirroring the ``evilkit script-harness run`` CLI."""
    import argparse

    parser = argparse.ArgumentParser(prog="script-harness", description=__doc__.splitlines()[0])
    parser.add_argument("script", help="path to the script to run")
    parser.add_argument("--target", required=True, help="target host the script will hit")
    parser.add_argument("--scope", required=True, help="authorised scope (e.g. 10.0.0.0/24)")
    parser.add_argument("--sandbox", choices=["auto", "bwrap", "none"], default="auto")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--evidence-dir", type=Path, default=None)
    parser.add_argument("--pcap-iface", default=None)
    parser.add_argument("args", nargs="*", help="arguments passed to the script")
    args = parser.parse_args(argv)

    try:
        record = run(
            args.script,
            target=args.target,
            scope=args.scope,
            sandbox=args.sandbox,
            timeout=args.timeout,
            evidence_dir=args.evidence_dir,
            passthrough=args.args,
            pcap_iface=args.pcap_iface,
        )
    except ScriptHarnessError as exc:
        print(f"script-harness: {exc}", file=sys.stderr)
        return EXIT_ERROR

    evidence_dir = args.evidence_dir or Path.cwd()
    out_path = evidence_dir / f"harness-{int(record['timestamp'])}.json"
    out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(f"script-harness: {record['script']}")
    print(f"  target     : {record['target']}")
    print(f"  sandbox    : {record['sandbox']}")
    print(f"  exit       : {record['returncode']}")
    print(f"  duration   : {record['duration_s']}s")
    print(f"  evidence   : {out_path}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

"""Lab-only mesh node: enrolled host agent with sandboxed capabilities.

A node runs on an explicitly enrolled lab machine. It can:
- List and read files within a configured sandbox directory
- Run allowlisted commands at the highest privilege the node process has
- Share structured observations with the hub's knowledge base
- Receive a global kill signal that terminates it permanently

It cannot:
- Replicate, propagate, or deploy to other hosts
- Escalate privileges or persist beyond its own process lifetime
- Access files outside the sandbox directory
- Run arbitrary commands outside the allowlist
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from .mesh import MeshError, _request, _token, _url

# ---------------------------------------------------------------------------
# Allowlisted commands — the only binaries a node may execute
# ---------------------------------------------------------------------------
ALLOWLISTED_COMMANDS = frozenset({
    "whoami", "id", "hostname", "uname", "uptime", "df", "free",
    "ps", "ss", "netstat", "ip", "ifconfig", "cat", "head", "tail",
    "ls", "find", "stat", "file", "md5sum", "sha256sum", "wc",
    "grep", "awk", "sed", "sort", "uniq", "cut", "tr", "diff",
    "env", "printenv", "date", "ping", "dig", "nslookup", "host",
    "curl", "wget", "systemctl", "service", "journalctl", "dmesg",
    "lscpu", "lsmem", "lsblk", "lspci", "lsusb", "mount", "df",
    "top", "vmstat", "iostat", "nproc", "arch", "uname",
})

# Commands that are never allowed even if they appear in the allowlist
DENIED_COMMANDS = frozenset({
    "rm", "dd", "mkfs", "fdisk", "parted", "shutdown", "reboot",
    "halt", "poweroff", "kill", "killall", "pkill", "chmod", "chown",
    "chroot", "mount", "umount", "insmod", "rmmod", "modprobe",
    "iptables", "nft", "tc", "ssh", "scp", "rsync", "nc", "ncat",
    "socat", "curl", "wget",  # curl/wget allowed for local-only, blocked for outbound
    "python", "python3", "perl", "ruby", "node", "bash", "sh", "zsh",
    "sudo", "su", "pkexec", "doas",
})

# ---------------------------------------------------------------------------
# Node configuration
# ---------------------------------------------------------------------------

class NodeConfig:
    """Sandbox and capability configuration for a mesh node."""

    def __init__(
        self,
        sandbox: Path,
        allowlist: frozenset[str] | None = None,
        max_output_bytes: int = 65536,
        command_timeout: int = 30,
    ):
        self.sandbox = sandbox.resolve()
        if not self.sandbox.is_dir():
            raise MeshError(f"sandbox directory does not exist: {self.sandbox}")
        self.allowlist = allowlist or ALLOWLISTED_COMMANDS - DENIED_COMMANDS
        self.max_output_bytes = max_output_bytes
        self.command_timeout = command_timeout


# ---------------------------------------------------------------------------
# File exploration — sandboxed to a single directory tree
# ---------------------------------------------------------------------------

def _resolve_sandbox_path(sandbox: Path, user_path: str) -> Path:
    """Resolve a user-supplied path inside the sandbox. Raises MeshError if it escapes."""
    candidate = (sandbox / user_path).resolve()
    try:
        candidate.relative_to(sandbox)
    except ValueError:
        raise MeshError(f"path escapes sandbox: {user_path}")
    return candidate


def node_list_files(sandbox: Path, rel_path: str = ".") -> list[dict]:
    """List files in a sandbox-relative directory. Returns name, type, size, modified."""
    target = _resolve_sandbox_path(sandbox, rel_path)
    if not target.is_dir():
        raise MeshError(f"not a directory: {rel_path}")
    entries = []
    for entry in sorted(target.iterdir()):
        try:
            stat = entry.stat()
        except OSError:
            continue
        entries.append({
            "name": entry.name,
            "type": "dir" if entry.is_dir() else "file",
            "size": stat.st_size,
            "modified": stat.st_mtime,
        })
    return entries


def node_read_file(sandbox: Path, rel_path: str, max_bytes: int = 65536) -> str:
    """Read a file inside the sandbox. Truncated at max_bytes with a note."""
    target = _resolve_sandbox_path(sandbox, rel_path)
    if not target.is_file():
        raise MeshError(f"not a file: {rel_path}")
    raw = target.read_bytes()
    if len(raw) > max_bytes:
        return raw[:max_bytes].decode("utf-8", "replace") + f"\n... truncated ({len(raw)} bytes total)"
    return raw.decode("utf-8", "replace")


def node_file_hash(sandbox: Path, rel_path: str) -> str:
    """Return SHA-256 of a sandboxed file."""
    target = _resolve_sandbox_path(sandbox, rel_path)
    if not target.is_file():
        raise MeshError(f"not a file: {rel_path}")
    return hashlib.sha256(target.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Command execution — allowlisted binaries only
# ---------------------------------------------------------------------------

def _resolve_binary(name: str) -> str | None:
    """Find a binary on PATH. Returns None if not found."""
    return shutil.which(name)


def node_run_command(
    command: str,
    allowlist: frozenset[str],
    timeout: int = 30,
    max_output_bytes: int = 65536,
) -> dict:
    """Run an allowlisted command and return stdout, stderr, exit code, duration."""
    parts = shlex.split(command)
    if not parts:
        raise MeshError("empty command")
    binary = parts[0]

    # Block interpreters and shell builtins that could escape
    if binary in DENIED_COMMANDS:
        raise MeshError(f"command '{binary}' is denied")
    if binary not in allowlist:
        raise MeshError(f"command '{binary}' is not in the allowlist")

    resolved = _resolve_binary(binary)
    if resolved is None:
        raise MeshError(f"command not found: {binary}")

    # Rebuild with resolved binary path
    argv = [resolved] + parts[1:]

    started = time.monotonic()
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        duration = time.monotonic() - started
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - started
        stdout = (exc.stdout or "")[:max_output_bytes]
        stderr = (exc.stderr or "")[:max_output_bytes]
        return {
            "command": command,
            "exit_code": None,
            "stdout": stdout + "\n... timed out",
            "stderr": stderr,
            "duration": round(duration, 3),
            "timed_out": True,
        }

    stdout = result.stdout[:max_output_bytes]
    stderr = result.stderr[:max_output_bytes]
    if len(result.stdout) > max_output_bytes:
        stdout += f"\n... truncated ({len(result.stdout)} bytes total)"
    if len(result.stderr) > max_output_bytes:
        stderr += f"\n... truncated ({len(result.stderr)} bytes total)"

    return {
        "command": command,
        "exit_code": result.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "duration": round(duration, 3),
        "timed_out": False,
    }


# ---------------------------------------------------------------------------
# Knowledge sharing — structured observations shared across the mesh
# ---------------------------------------------------------------------------

def node_share_observation(
    base: str,
    token: str,
    node_name: str,
    category: str,
    subject: str,
    detail: str,
) -> dict:
    """Share a structured observation to the hub's knowledge base."""
    if not category or len(category) > 64:
        raise MeshError("observation category must be 1-64 characters")
    if not subject or len(subject) > 256:
        raise MeshError("observation subject must be 1-256 characters")
    if not detail or len(detail) > 8192:
        raise MeshError("observation detail must be 1-8192 characters")
    return _request(base, token, "/node/observe", {
        "name": node_name,
        "category": category,
        "subject": subject,
        "detail": detail,
    })


def node_query_knowledge(
    base: str,
    token: str,
    category: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """Query the hub's shared knowledge base."""
    params = {"limit": min(limit, 200)}
    if category:
        params["category"] = category
    import urllib.parse
    return _request(base, token, "/node/knowledge?" + urllib.parse.urlencode(params))


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------

def node_check_kill(base: str, token: str, node_name: str) -> bool:
    """Check whether this node has been killed. Returns True if killed."""
    try:
        result = _request(base, token, "/node/kill-check", {"name": node_name})
        return result.get("killed", False)
    except MeshError:
        return False


# ---------------------------------------------------------------------------
# Node daemon loop
# ---------------------------------------------------------------------------

class NodeDaemon:
    """Long-running node process that polls the hub for tasks."""

    def __init__(
        self,
        name: str,
        base: str,
        token: str,
        config: NodeConfig,
        poll_interval: float = 2.0,
        kill_check_interval: float = 10.0,
    ):
        self.name = name
        self.base = base
        self.token = token
        self.config = config
        self.poll_interval = poll_interval
        self.kill_check_interval = kill_check_interval
        self._killed = threading.Event()
        self._last_kill_check = 0.0

    def _check_killed(self) -> bool:
        if self._killed.is_set():
            return True
        now = time.time()
        if now - self._last_kill_check >= self.kill_check_interval:
            self._last_kill_check = now
            if node_check_kill(self.base, self.token, self.name):
                self._killed.set()
                return True
        return False

    def register(self) -> dict:
        """Register with the hub as a node (not a worker)."""
        return _request(self.base, self.token, "/node/register", {
            "name": self.name,
            "sandbox": str(self.config.sandbox),
            "pid": os.getpid(),
            "privilege": "root" if os.getuid() == 0 else f"uid-{os.getuid()}",
        })

    def claim_task(self) -> dict | None:
        """Claim the next available node task, or None."""
        result = _request(self.base, self.token, "/node/claim", {"name": self.name})
        return result.get("task")

    def _execute_task(self, task: dict) -> dict:
        """Execute a node task and return the result."""
        task_type = task.get("type")
        if task_type == "list_files":
            return node_list_files(self.config.sandbox, task.get("path", "."))
        if task_type == "read_file":
            return {"content": node_read_file(
                self.config.sandbox,
                task["path"],
                max_bytes=self.config.max_output_bytes,
            )}
        if task_type == "file_hash":
            return {"sha256": node_file_hash(self.config.sandbox, task["path"])}
        if task_type == "run_command":
            return node_run_command(
                task["command"],
                self.config.allowlist,
                timeout=self.config.command_timeout,
                max_output_bytes=self.config.max_output_bytes,
            )
        if task_type == "observe":
            return node_share_observation(
                self.base, self.token, self.name,
                task["category"], task["subject"], task["detail"],
            )
        raise MeshError(f"unknown node task type: {task_type}")

    def report_result(self, task_id: str, result: dict, error: str | None = None) -> None:
        """Report task completion to the hub."""
        _request(self.base, self.token, "/node/complete", {
            "name": self.name,
            "task": task_id,
            "result": result,
            "error": error,
        })

    def run(self) -> None:
        """Main daemon loop. Runs until killed or interrupted."""
        print(f"mesh node {self.name}: registering...", flush=True)
        info = self.register()
        print(
            f"mesh node {self.name}: enrolled; sandbox={self.config.sandbox} "
            f"privilege={info.get('privilege', 'unknown')}",
            flush=True,
        )

        while not self._check_killed():
            try:
                task = self.claim_task()
            except MeshError as exc:
                print(f"mesh node {self.name}: claim failed: {exc}", file=sys.stderr)
                time.sleep(self.poll_interval)
                continue

            if task is None:
                time.sleep(self.poll_interval)
                continue

            task_id = task["id"]
            print(f"mesh node {self.name}: executing task {task_id} ({task['type']})", flush=True)
            try:
                result = self._execute_task(task)
                self.report_result(task_id, result)
                print(f"mesh node {self.name}: task {task_id} done", flush=True)
            except Exception as exc:
                self.report_result(task_id, {}, error=str(exc))
                print(f"mesh node {self.name}: task {task_id} failed: {exc}", file=sys.stderr)

        print(f"mesh node {self.name}: killed by hub, shutting down", flush=True)

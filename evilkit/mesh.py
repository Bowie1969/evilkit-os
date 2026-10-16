"""Small, token-authenticated coordinator for scoped Kimi workers.

The hub only queues work and relays output. Workers run Kimi locally after
recording the hub's scope with evilkit's existing fail-closed scope writer.
"""

from __future__ import annotations

import argparse
import codecs
import collections
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import pty
import secrets
import select
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from . import config as config_mod, mcpscope, scope as scope_mod
from .clone_display import SegmentError
from .mesh_brief import BriefError, read_brief
from .terminal_window import ClonePopupManager, spawn_terminal_window


class MeshError(Exception):
    pass


def _token(path: Path, *, create: bool = False) -> str:
    path = path.expanduser()
    if create and not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(secrets.token_urlsafe(32) + "\n")
    if path.is_symlink() or not path.is_file():
        raise MeshError(f"token file is missing or a symlink: {path}")
    if path.stat().st_mode & 0o077:
        raise MeshError(f"token file must be private (chmod 600): {path}")
    value = path.read_text(encoding="ascii").strip()
    if len(value) < 32:
        raise MeshError("token file is too short")
    return value


def _connection_path(token_file: Path) -> Path:
    return token_file.expanduser().resolve().with_name("connection.json")


def _write_connection(token_file: Path, address: str) -> None:
    path = _connection_path(token_file)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".new")
    staging = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"leader": address}, handle)
            handle.write("\n")
        os.replace(staging, path)
    finally:
        staging.unlink(missing_ok=True)


def _read_connection(token_file: Path) -> str | None:
    path = _connection_path(token_file)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))["leader"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return value if isinstance(value, str) else None


def _url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise MeshError("leader must be an http://host:port URL with no path or credentials")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise MeshError("invalid leader port") from exc
    if parsed_port is None:
        raise MeshError("leader URL needs an explicit port")
    try:
        _safe_bind(parsed.hostname)
    except MeshError as exc:
        raise MeshError("leader URL must use a numeric loopback or Tailscale IP") from exc
    return value.rstrip("/")


def _request(base: str, token: str, path: str, data: dict | None = None) -> dict:
    payload = None if data is None else json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        base + path,
        data=payload,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="GET" if data is None else "POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise MeshError(f"hub returned {exc.code}: {exc.read(256).decode('utf-8', 'replace')}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise MeshError(f"could not reach hub: {exc}") from exc


class Hub:
    def __init__(
        self,
        scope: str | None,
        token: str,
        *,
        brief: str | None = None,
        on_clone_up=None,
    ):
        if (scope is None) == (brief is None):
            raise MeshError("hub needs exactly one of a recorded scope or engagement brief")
        self.scope = scope
        self.brief = brief
        self.brief_sha256 = hashlib.sha256(brief.encode("utf-8")).hexdigest() if brief is not None else None
        self.mode = "brief-unscoped" if brief is not None else "recorded-scope"
        self.token = token
        self.on_clone_up = on_clone_up
        self.lock = threading.RLock()
        self.workers: dict[str, dict] = {}
        self.tasks: dict[str, dict] = {}
        self.findings: list[dict] = []
        self.events: collections.deque[dict] = collections.deque(maxlen=5000)
        self.sequence = 0
        # Mesh node state
        self.nodes: dict[str, dict] = {}
        self.node_tasks: dict[str, dict] = {}
        self.knowledge: list[dict] = []
        self.killed_nodes: set[str] = set()

    def event(self, worker: str, task: str, kind: str, text: str = "") -> dict:
        self.sequence += 1
        entry = {"seq": self.sequence, "time": time.time(), "worker": worker, "task": task, "kind": kind, "text": text}
        self.events.append(entry)
        return entry

    def register(self, name: str) -> dict:
        if not name or len(name) > 64 or not all(c.isalnum() or c in "-_" for c in name):
            raise MeshError("worker name must use letters, digits, - or _")
        with self.lock:
            existing = self.workers.get(name)
            if existing and time.time() - existing["seen"] < 60 and existing["status"] != "offline":
                raise MeshError(f"worker {name} is already connected")
            self.workers[name] = {"name": name, "seen": time.time(), "status": "idle", "task": None}
            self.event(name, "", "register")
            result = {"scope": self.scope, "mode": self.mode, "brief_sha256": self.brief_sha256}
        if self.on_clone_up is not None:
            try:
                self.on_clone_up(name)
            except Exception:
                pass
        return result

    def claim(self, name: str) -> dict:
        with self.lock:
            worker = self.workers.get(name)
            if worker is None:
                raise MeshError("worker is not registered")
            worker["seen"] = time.time()
            if worker["task"]:
                raise MeshError("worker already has a task")
            for task in self.tasks.values():
                if task["status"] == "queued" and task["worker"] in (None, name):
                    task.update(status="running", worker=name, started=time.time())
                    worker.update(status="running", task=task["id"])
                    self.event(name, task["id"], "start", task["prompt"])
                    return {"task": task, "scope": self.scope, "mode": self.mode, "brief_sha256": self.brief_sha256}
            worker["status"] = "idle"
            return {"task": None, "scope": self.scope, "mode": self.mode, "brief_sha256": self.brief_sha256}

    def submit(self, prompt: str, worker: str | None) -> dict:
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 20000:
            raise MeshError("task prompt must contain 1–20000 characters")
        with self.lock:
            if worker and worker not in self.workers:
                raise MeshError(f"unknown worker: {worker}")
            task_id = uuid.uuid4().hex[:12]
            task = {"id": task_id, "prompt": prompt.strip(), "worker": worker, "status": "queued", "created": time.time(), "started": None, "ended": None, "exit_code": None}
            self.tasks[task_id] = task
            self.event("hub", task_id, "queued", prompt.strip())
            return task

    def output(self, name: str, task_id: str, text: str) -> None:
        if not isinstance(text, str) or len(text.encode("utf-8")) > 32768:
            raise MeshError("output chunk is too large")
        with self.lock:
            worker = self.workers.get(name)
            if worker is None or worker["task"] != task_id:
                raise MeshError("task is not owned by worker")
            worker["seen"] = time.time()
            self.event(name, task_id, "output", text)

    def complete(self, name: str, task_id: str, code: int) -> None:
        with self.lock:
            worker = self.workers.get(name)
            if worker is None or worker["task"] != task_id:
                raise MeshError("task is not owned by worker")
            task = self.tasks[task_id]
            task.update(status="done" if code == 0 else "failed", ended=time.time(), exit_code=code)
            worker.update(status="idle", task=None, seen=time.time())
            self.event(name, task_id, "complete", str(code))

    def finding(self, name: str, task_id: str, title: str, detail: str) -> dict:
        if not title or len(title) > 200 or len(detail) > 20000:
            raise MeshError("finding title/detail is missing or too long")
        with self.lock:
            worker = self.workers.get(name)
            if worker is None or worker["task"] != task_id:
                raise MeshError("task is not owned by worker")
            finding = {"id": uuid.uuid4().hex[:12], "worker": name, "task": task_id, "title": title, "detail": detail, "time": time.time()}
            self.findings.append(finding)
            self.event(name, task_id, "finding", title)
            return finding

    def update(self, name: str, task_id: str, note: str) -> dict:
        if not note or len(note) > 4000:
            raise MeshError("task update must contain 1–4000 characters")
        with self.lock:
            worker = self.workers.get(name)
            if worker is None or worker["task"] != task_id:
                raise MeshError("task is not owned by worker")
            worker["seen"] = time.time()
            return self.event(name, task_id, "update", note)

    def state(self) -> dict:
        with self.lock:
            return {"scope": self.scope, "mode": self.mode, "brief_sha256": self.brief_sha256, "workers": list(self.workers.values()), "tasks": list(self.tasks.values()), "findings": list(self.findings), "sequence": self.sequence}

    def brief_text(self) -> dict:
        if self.brief is None:
            raise MeshError("hub has no engagement brief")
        return {"text": self.brief, "sha256": self.brief_sha256}

    def tail(self, after: int, worker: str | None = None) -> dict:
        with self.lock:
            oldest = self.events[0]["seq"] if self.events else self.sequence + 1
            return {"events": [e for e in self.events if e["seq"] > after and (worker is None or e["worker"] == worker)], "sequence": self.sequence, "oldest": oldest}

    # --- Mesh node methods ---

    def node_register(self, name: str, sandbox: str, pid: int, privilege: str) -> dict:
        if not name or len(name) > 64 or not all(c.isalnum() or c in "-_" for c in name):
            raise MeshError("node name must use letters, digits, - or _")
        if name in self.killed_nodes:
            raise MeshError(f"node {name} has been killed and cannot re-register")
        with self.lock:
            existing = self.nodes.get(name)
            if existing and time.time() - existing["seen"] < 60 and existing["status"] != "offline":
                raise MeshError(f"node {name} is already connected")
            self.nodes[name] = {
                "name": name, "sandbox": sandbox, "pid": pid,
                "privilege": privilege, "seen": time.time(),
                "status": "idle", "task": None, "enrolled": time.time(),
            }
            self.event(name, "", "node_register")
            result = {"scope": self.scope, "mode": self.mode, "privilege": privilege}
        if self.on_clone_up is not None:
            try:
                self.on_clone_up(name)
            except Exception:
                pass
        return result

    def node_claim(self, name: str) -> dict:
        with self.lock:
            node = self.nodes.get(name)
            if node is None:
                raise MeshError("node is not registered")
            if name in self.killed_nodes:
                raise MeshError(f"node {name} has been killed")
            node["seen"] = time.time()
            if node["task"]:
                raise MeshError("node already has a task")
            for task in self.node_tasks.values():
                if task["status"] == "queued" and task.get("node") in (None, name):
                    task.update(status="running", node=name, started=time.time())
                    node.update(status="running", task=task["id"])
                    self.event(name, task["id"], "node_start", task["type"])
                    return {"task": task}
            node["status"] = "idle"
            return {"task": None}

    def node_submit(self, task_type: str, node: str | None, **kwargs) -> dict:
        if task_type not in ("list_files", "read_file", "file_hash", "run_command", "observe"):
            raise MeshError(f"unknown node task type: {task_type}")
        with self.lock:
            if node and node not in self.nodes:
                raise MeshError(f"unknown node: {node}")
            task_id = uuid.uuid4().hex[:12]
            task = {"id": task_id, "type": task_type, "node": node, "status": "queued", "created": time.time(), "started": None, "ended": None, **kwargs}
            self.node_tasks[task_id] = task
            self.event("hub", task_id, "node_queued", task_type)
            return task

    def node_complete(self, name: str, task_id: str, result: dict, error: str | None = None) -> None:
        with self.lock:
            node = self.nodes.get(name)
            if node is None or node.get("task") != task_id:
                raise MeshError("task is not owned by node")
            task = self.node_tasks[task_id]
            task.update(status="done" if error is None else "failed", ended=time.time(), result=result, error=error)
            node.update(status="idle", task=None, seen=time.time())
            self.event(name, task_id, "node_complete", error or "ok")

    def node_observe(self, name: str, category: str, subject: str, detail: str) -> dict:
        if not category or len(category) > 64:
            raise MeshError("observation category must be 1-64 characters")
        if not subject or len(subject) > 256:
            raise MeshError("observation subject must be 1-256 characters")
        if not detail or len(detail) > 8192:
            raise MeshError("observation detail must be 1-8192 characters")
        with self.lock:
            node = self.nodes.get(name)
            if node is None:
                raise MeshError("node is not registered")
            obs = {"id": uuid.uuid4().hex[:12], "node": name, "category": category, "subject": subject, "detail": detail, "time": time.time()}
            self.knowledge.append(obs)
            self.event(name, "", "observe", f"{category}: {subject}")
            return obs

    def node_knowledge(self, category: str | None = None, limit: int = 50) -> list[dict]:
        with self.lock:
            items = self.knowledge
            if category:
                items = [k for k in items if k["category"] == category]
            return list(reversed(items))[:min(limit, 200)]

    def node_kill_check(self, name: str) -> dict:
        with self.lock:
            return {"killed": name in self.killed_nodes}

    def node_kill(self, name: str) -> dict:
        with self.lock:
            if name not in self.nodes:
                raise MeshError(f"unknown node: {name}")
            self.killed_nodes.add(name)
            node = self.nodes[name]
            node["status"] = "killed"
            self.event("hub", "", "node_kill", name)
            return {"killed": True}

    def node_status(self) -> dict:
        with self.lock:
            return {
                "nodes": list(self.nodes.values()),
                "node_tasks": list(self.node_tasks.values()),
                "knowledge_count": len(self.knowledge),
                "killed": list(self.killed_nodes),
            }


def _handler(hub: Hub):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:
            return

        def _send(self, code: int, data: dict) -> None:
            payload = json.dumps(data).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def _dispatch(self, data: dict | None) -> dict:
            parsed = urllib.parse.urlsplit(self.path)
            if self.command == "GET":
                if parsed.path == "/state":
                    return hub.state()
                if parsed.path == "/brief":
                    return hub.brief_text()
                if parsed.path == "/tail":
                    query = urllib.parse.parse_qs(parsed.query)
                    after = int(query.get("after", ["0"])[0])
                    return hub.tail(after, query.get("worker", [None])[0])
                # Node GET endpoints
                if parsed.path == "/node/status":
                    return hub.node_status()
                if parsed.path == "/node/knowledge":
                    query = urllib.parse.parse_qs(parsed.query)
                    return hub.node_knowledge(
                        query.get("category", [None])[0],
                        int(query.get("limit", ["50"])[0]),
                    )
                if parsed.path == "/node/kill-check":
                    # kill-check needs POST with name; GET returns empty
                    return {"killed": False}
            elif data is not None:
                if parsed.path == "/register":
                    return hub.register(data["name"])
                if parsed.path == "/claim":
                    return hub.claim(data["name"])
                if parsed.path == "/task":
                    return hub.submit(data["prompt"], data.get("worker"))
                if parsed.path == "/output":
                    hub.output(data["name"], data["task"], data["text"])
                    return {"ok": True}
                if parsed.path == "/complete":
                    hub.complete(data["name"], data["task"], data["code"])
                    return {"ok": True}
                if parsed.path == "/finding":
                    return hub.finding(data["name"], data["task"], data["title"], data["detail"])
                if parsed.path == "/update":
                    return hub.update(data["name"], data["task"], data["note"])
                # Node endpoints
                if parsed.path == "/node/register":
                    return hub.node_register(data["name"], data["sandbox"], data["pid"], data["privilege"])
                if parsed.path == "/node/claim":
                    return hub.node_claim(data["name"])
                if parsed.path == "/node/task":
                    return hub.node_submit(data["type"], data.get("node"), **{k: v for k, v in data.items() if k not in ("type", "node")})
                if parsed.path == "/node/complete":
                    hub.node_complete(data["name"], data["task"], data.get("result", {}), data.get("error"))
                    return {"ok": True}
                if parsed.path == "/node/observe":
                    return hub.node_observe(data["name"], data["category"], data["subject"], data["detail"])
                if parsed.path == "/node/knowledge":
                    query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                    return hub.node_knowledge(
                        query.get("category", [None])[0],
                        int(query.get("limit", ["50"])[0]),
                    )
                if parsed.path == "/node/kill-check":
                    return hub.node_kill_check(data["name"])
                if parsed.path == "/node/kill":
                    return hub.node_kill(data["name"])
                if parsed.path == "/node/status":
                    return hub.node_status()
            raise MeshError("unknown endpoint")

        def _handle(self) -> None:
            supplied = self.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied, f"Bearer {hub.token}"):
                self._send(401, {"error": "unauthorized"})
                return
            try:
                data = None
                if self.command == "POST":
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 2 or length > 65536:
                        raise MeshError("request body size is invalid")
                    data = json.loads(self.rfile.read(length))
                    if not isinstance(data, dict):
                        raise MeshError("request body must be an object")
                self._send(200, self._dispatch(data))
            except (MeshError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._send(400, {"error": str(exc)})

        do_GET = _handle
        do_POST = _handle

    return Handler


class MeshServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _safe_bind(host: str) -> None:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError as exc:
        raise MeshError("--bind must be a numeric loopback or Tailscale address") from exc
    if addr.version != 4 or not (addr.is_loopback or addr in ipaddress.ip_network("100.64.0.0/10")):
        raise MeshError("--bind must be loopback or a Tailscale 100.64.0.0/10 address")


def _kimi_binary() -> str:
    config, _ = config_mod.load()
    configured = config.resolved_kimi_bin()
    if Path(configured).is_file() or shutil.which(configured):
        return configured
    if os.environ.get("EVILKIT_KIMI_BIN") or config.kimi_bin != "kimi":
        raise MeshError(f"Kimi CLI not found: {configured}")
    home = Path(os.environ.get("KIMI_CODE_HOME", Path.home() / ".kimi-code"))
    fallback = home / "bin" / "kimi"
    if fallback.is_file() and os.access(fallback, os.X_OK):
        return str(fallback)
    raise MeshError(f"Kimi CLI not found: {configured}")


def _tailscale_ip() -> str:
    if not shutil.which("tailscale"):
        raise MeshError("Tailscale CLI is missing; use `mesh lead --bind IP` instead")
    result = subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        raise MeshError(f"Tailscale has no IPv4 address: {result.stderr.strip()}")
    address = result.stdout.strip().splitlines()[0]
    _safe_bind(address)
    return address


def _start_tmux(
    scope: str | None,
    brief_path: Path | None,
    port: int,
    token_file: Path,
    *,
    attach: bool,
    local_workers: int = 0,
    popup_windows: bool = True,
    display_clones: bool = True,
) -> int:
    if not 1 <= port <= 65535:
        raise MeshError("port must be between 1 and 65535")
    if not shutil.which("tmux"):
        raise MeshError("tmux is missing; use `mesh lead --cockpit` and `mesh watch` separately")
    if not 0 <= local_workers <= 4:
        raise MeshError("--local-workers must be between 0 and 4")
    _kimi_binary()
    bind = _tailscale_ip()
    token_path = token_file.expanduser().resolve()
    _token(token_path, create=True)
    session = "evilkit-mesh"
    exists = subprocess.run(["tmux", "has-session", "-t", session], capture_output=True)
    if exists.returncode == 0:
        raise MeshError(f"tmux session {session} already exists; attach with `tmux attach -t {session}`")
    base = f"http://{bind}:{port}"
    lead_args = [sys.executable, "-m", "evilkit", "mesh", "lead", "--bind", bind, "--port", str(port), "--token-file", str(token_path), "--cockpit"]
    if not popup_windows:
        lead_args.append("--no-popup")
    if not display_clones:
        lead_args.append("--no-display-clones")
    if brief_path is not None:
        lead_args.extend(["--allow-unscoped", "--brief", str(brief_path.expanduser().resolve())])
    elif scope is not None:
        lead_args.extend(["--scope", scope])
    else:
        raise MeshError("scope or brief is required")
    lead_command = shlex.join(lead_args)
    watch_command = shlex.join([sys.executable, "-m", "evilkit", "mesh", "watch", "--leader", base, "--token-file", str(token_path), "--wait"])
    subprocess.run(["tmux", "new-session", "-d", "-s", session, "-c", str(Path.cwd()), lead_command], check=True)
    try:
        subprocess.run(["tmux", "split-window", "-h", "-t", f"{session}:0.0", "-c", str(Path.cwd()), watch_command], check=True)
        subprocess.run(["tmux", "select-pane", "-t", f"{session}:0.0"], check=True)
        for index in range(1, local_workers + 1):
            worker_args = [sys.executable, "-m", "evilkit", "mesh", "work", "--leader", base, "--token-file", str(token_path), "--name", f"local-{index}", "--wait"]
            if brief_path is not None:
                worker_args.append("--allow-unscoped")
            subprocess.run(["tmux", "new-window", "-d", "-t", session, "-n", f"worker-{index}", "-c", str(Path.cwd()), shlex.join(worker_args)], check=True)
        subprocess.run(["tmux", "select-window", "-t", f"{session}:0"], check=True)
    except subprocess.CalledProcessError:
        subprocess.run(["tmux", "kill-session", "-t", session], check=False)
        raise
    print(f"Mesh cockpit: {base}\nWatch pane: all worker streams\nLocal workers: {local_workers}\nAttach: tmux attach -t {session}")
    if attach and sys.stdin.isatty() and sys.stdout.isatty():
        return subprocess.call(["tmux", "attach", "-t", session])
    return 0


def _scope_record(scope: str, explicit: Path | None, keep: int) -> Path:
    if explicit is not None:
        selected = explicit.expanduser()
        if selected.is_symlink():
            raise MeshError(f"refusing to write through a symlink: {selected}")
        path = selected.resolve()
        if not path.is_file():
            raise MeshError(f".mcp.json not found: {path}")
    else:
        current = _kimi_project_mcp_path(Path.cwd())
        if current.is_file():
            path = current
        else:
            try:
                path = mcpscope.find()
            except mcpscope.McpError as exc:
                raise MeshError("no pentest MCP config found; pass --mcp-json PATH") from exc
    try:
        mcpscope.write_scope(path, scope, keep_backups=keep)
        if mcpscope.read_scope(path) != scope:
            raise MeshError("scope could not be verified after writing")
    except mcpscope.McpError as exc:
        raise MeshError(str(exc)) from exc
    return path


def _install_mcp(path: Path) -> None:
    """Add the mesh stdio server without putting a token in the config file."""
    if path.is_symlink():
        raise MeshError(f"refusing to write through a symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"command": sys.executable, "args": ["-m", "evilkit.mesh_mcp"]}
    try:
        with mcpscope._locked(path):
            data = mcpscope._load(path) if path.exists() else {"mcpServers": {}}
            servers = data.setdefault("mcpServers", {})
            if not isinstance(servers, dict):
                raise MeshError(f"{path}: mcpServers is not an object")
            existing = servers.get("evilkit-mesh")
            if existing is not None and existing != entry:
                raise MeshError(f"{path}: evilkit-mesh already has a different configuration")
            if existing == entry:
                return
            servers["evilkit-mesh"] = entry
            payload = json.dumps(data, indent=2) + "\n"
            staging = mcpscope._stage(path, payload)
            try:
                mcpscope._revalidate(staging, path)
                os.replace(staging, path)
            finally:
                mcpscope._discard(staging)
    except mcpscope.McpError as exc:
        raise MeshError(str(exc)) from exc


def _kimi_project_mcp_path(start: Path) -> Path:
    directory = start.resolve()
    for candidate in (directory, *directory.parents):
        if (candidate / ".git").exists():
            return candidate / ".kimi-code" / "mcp.json"
    return directory / ".kimi-code" / "mcp.json"


def _run_task(base: str, token: str, name: str, task: dict, scope: str | None, brief: str | None, mcp_path: Path | None, kimi: str, keep: int) -> None:
    task_id = task["id"]
    child = None
    try:
        if brief is not None:
            path = mcp_path.expanduser() if mcp_path is not None else _kimi_project_mcp_path(Path.cwd())
        elif scope is not None:
            path = _scope_record(scope, mcp_path, keep)
        else:
            raise MeshError("task has neither scope nor brief")
        _install_mcp(path)
        env = dict(os.environ)
        if scope is not None:
            env[mcpscope.SCOPE_ENV_KEY] = scope
        else:
            env.pop(mcpscope.SCOPE_ENV_KEY, None)
        env["EVILKIT_MESH_LEADER"] = base
        env["EVILKIT_MESH_WORKER"] = name
        env["EVILKIT_MESH_TASK"] = task_id
        env["EVILKIT_MESH_TOKEN_FILE"] = os.environ.get("EVILKIT_MESH_TOKEN_FILE", "")
        if brief is not None:
            prompt = (
                "The complete readable engagement brief follows. Follow its in-scope targets, "
                "out-of-scope exclusions, and testing restrictions exactly. Stop if a task "
                "would exceed them. No target restriction was recorded in a pentest MCP config; "
                "the brief is your operational boundary.\n\n"
                "<engagement_brief>\n" + brief + "\n</engagement_brief>\n\n"
                "Report confirmed findings with the evilkit-mesh report_finding tool and "
                "progress with task_update. Assigned task: " + task["prompt"]
            )
        else:
            prompt = (
                f"Authorized scope: {scope}. Work only within this scope. "
                "Report confirmed findings with the evilkit-mesh report_finding tool, "
                "and progress with task_update. Your assigned task: " + task["prompt"]
            )
        master, slave = pty.openpty()
        try:
            child = subprocess.Popen([kimi, "-p", prompt], stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True)
        finally:
            os.close(slave)
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        try:
            while True:
                ready, _, _ = select.select([master], [], [], 0.5)
                if ready:
                    try:
                        chunk = os.read(master, 8192)
                    except OSError:
                        chunk = b""
                    if chunk:
                        decoded = decoder.decode(chunk)
                        if decoded:
                            _request(base, token, "/output", {"name": name, "task": task_id, "text": decoded})
                    elif child.poll() is not None:
                        break
                elif child.poll() is not None:
                    break
        except KeyboardInterrupt:
            os.killpg(child.pid, signal.SIGTERM)
            child.wait(timeout=5)
            code = 130
            _request(base, token, "/complete", {"name": name, "task": task_id, "code": code})
            raise
        finally:
            os.close(master)
        final = decoder.decode(b"", final=True)
        if final:
            _request(base, token, "/output", {"name": name, "task": task_id, "text": final})
        code = child.wait()
    except Exception as exc:
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
        try:
            _request(base, token, "/output", {"name": name, "task": task_id, "text": f"\nmesh worker error: {exc}\n"})
        except MeshError:
            pass
        code = 1
    _request(base, token, "/complete", {"name": name, "task": task_id, "code": code})


def _args() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="evilkit mesh", description="Coordinate scoped Kimi sessions over a tailnet")
    sub = parser.add_subparsers(dest="action", required=True)
    start = sub.add_parser("start", help="open the Kimi cockpit and live watch pane in tmux")
    start.add_argument("--scope", help="authorized target list; prompts when omitted")
    start.add_argument("--brief", type=Path, help="engagement brief (text, HTML, MHTML, or local file pointer)")
    start.add_argument("--allow-unscoped", action="store_true", help="use the complete brief without recording a pentest MCP scope")
    start.add_argument("--allow-any", action="store_true")
    start.add_argument("--port", type=int, default=8765)
    start.add_argument("--token-file", type=Path, default=Path(".evilkit-mesh/token"))
    start.add_argument("--no-attach", action="store_true", help="start in background and print attach command")
    start.add_argument("--local-workers", type=int, default=0, help="start up to four idle workers on this box")
    start.add_argument("--no-popup", dest="popup_windows", action="store_false", help="do not pop up a desktop terminal window when a clone connects")
    start.add_argument("--no-display-clones", dest="display_clones", action="store_false", help="do not display a remote clone's own terminal (attack segment only)")
    start.set_defaults(popup_windows=True, display_clones=True)
    lead = sub.add_parser("lead", help="start the coordinator")
    lead.add_argument("--scope", help="authorized target list")
    lead.add_argument("--brief", type=Path, help="engagement brief for unscoped mode")
    lead.add_argument("--allow-unscoped", action="store_true")
    lead.add_argument("--allow-any", action="store_true")
    lead.add_argument("--bind", default="127.0.0.1", help="loopback or numeric Tailscale IP")
    lead.add_argument("--port", type=int, default=8765)
    lead.add_argument("--token-file", type=Path, default=Path(".evilkit-mesh/token"))
    lead.add_argument("--cockpit", action="store_true", help="open a local Kimi leader session")
    lead.add_argument("--no-popup", dest="popup_windows", action="store_false", help="do not pop up a desktop terminal window when a clone connects")
    lead.add_argument("--no-display-clones", dest="display_clones", action="store_false", help="do not display a remote clone's own terminal (attack segment only)")
    lead.set_defaults(popup_windows=True, display_clones=True)
    work = sub.add_parser("work", help="poll for tasks and run local Kimi")
    work.add_argument("--leader", required=True)
    work.add_argument("--token-file", type=Path, default=Path(".evilkit-mesh/token"))
    work.add_argument("--name", default=socket.gethostname().split(".")[0])
    work.add_argument("--mcp-json", type=Path)
    work.add_argument("--allow-unscoped", action="store_true", help="join a brief-based unscoped hub")
    work.add_argument("--once", action="store_true")
    work.add_argument("--wait", action="store_true", help="wait for the hub to become reachable")
    work.add_argument("--window", action="store_true", help="open this worker in a new desktop terminal window on this box")
    for action in ("watch", "tail", "task", "state", "findings", "finding"):
        item = sub.add_parser(action)
        item.add_argument("--leader", default=os.environ.get("EVILKIT_MESH_LEADER"))
        item.add_argument("--token-file", type=Path, default=Path(os.environ.get("EVILKIT_MESH_TOKEN_FILE", ".evilkit-mesh/token")))
        if action in ("watch", "tail"):
            item.add_argument("--worker")
            item.add_argument("--since", type=int, default=0)
            if action == "watch":
                item.add_argument("--wait", action="store_true", help="wait for the hub to start or reconnect")
                item.add_argument("--window", action="store_true", help="open the live watch stream in a new desktop terminal window")
        if action == "task":
            item.add_argument("prompt")
            item.add_argument("--worker")
        if action == "finding":
            item.add_argument("title")
            item.add_argument("--detail", required=True)
            item.add_argument("--worker", default=os.environ.get("EVILKIT_MESH_WORKER"))
            item.add_argument("--task-id", default=os.environ.get("EVILKIT_MESH_TASK"))

    # Node subcommands
    node_start = sub.add_parser("node", help="run as an enrolled mesh node on this lab host")
    node_start.add_argument("--leader", required=True)
    node_start.add_argument("--token-file", type=Path, default=Path(".evilkit-mesh/token"))
    node_start.add_argument("--name", default=socket.gethostname().split(".")[0] + "-node")
    node_start.add_argument("--sandbox", type=Path, default=Path("/tmp/evilkit-node-sandbox"), help="sandbox directory for file operations")
    node_start.add_argument("--wait", action="store_true", help="wait for the hub to become reachable")
    node_start.add_argument("--window", action="store_true", help="open this node in a new desktop terminal window on this box")

    node_status = sub.add_parser("node-status", help="show enrolled node status")
    node_status.add_argument("--leader", default=os.environ.get("EVILKIT_MESH_LEADER"))
    node_status.add_argument("--token-file", type=Path, default=Path(os.environ.get("EVILKIT_MESH_TOKEN_FILE", ".evilkit-mesh/token")))

    node_kill = sub.add_parser("node-kill", help="permanently kill an enrolled node")
    node_kill.add_argument("node_name", help="name of the node to kill")
    node_kill.add_argument("--leader", default=os.environ.get("EVILKIT_MESH_LEADER"))
    node_kill.add_argument("--token-file", type=Path, default=Path(os.environ.get("EVILKIT_MESH_TOKEN_FILE", ".evilkit-mesh/token")))

    node_task = sub.add_parser("node-task", help="queue a task for a mesh node")
    node_task.add_argument("--type", required=True, choices=("list_files", "read_file", "file_hash", "run_command", "observe"), help="task type")
    node_task.add_argument("--node", help="target a specific node (omit for next available)")
    node_task.add_argument("--path", help="sandbox-relative path (for list_files, read_file, file_hash)")
    node_task.add_argument("--command", help="allowlisted command to run (for run_command)")
    node_task.add_argument("--category", help="observation category (for observe)")
    node_task.add_argument("--subject", help="observation subject (for observe)")
    node_task.add_argument("--detail", help="observation detail (for observe)")
    node_task.add_argument("--leader", default=os.environ.get("EVILKIT_MESH_LEADER"))
    node_task.add_argument("--token-file", type=Path, default=Path(os.environ.get("EVILKIT_MESH_TOKEN_FILE", ".evilkit-mesh/token")))

    node_knowledge = sub.add_parser("node-knowledge", help="query the shared knowledge base")
    node_knowledge.add_argument("--category", help="filter by category")
    node_knowledge.add_argument("--limit", type=int, default=50)
    node_knowledge.add_argument("--leader", default=os.environ.get("EVILKIT_MESH_LEADER"))
    node_knowledge.add_argument("--token-file", type=Path, default=Path(os.environ.get("EVILKIT_MESH_TOKEN_FILE", ".evilkit-mesh/token")))

    display = sub.add_parser(
        "display",
        help="show a clone's live terminal (attack segment only)",
        description=(
            "Watch the attack segment for a remote EvilKit clone, prove its identity "
            "over SSH, and pop up a desktop terminal window showing its live worker "
            "terminal. Windows also open when the hub deploys a task to that clone. "
            "Addresses outside the configured attack segments are never displayed."
        ),
    )
    display.add_argument("--segment", action="append", metavar="CIDR", help="attack segment to watch (repeatable; default from config)")
    display.add_argument("--host", action="append", metavar="NAME=IP", help="clone to display as NAME=IP (repeatable; default from config)")
    display.add_argument("--user", help="SSH user for --host entries (default: pi)")
    display.add_argument("--identity", type=Path, help="SSH private key for --host entries")
    display.add_argument("--unit", help="systemd unit whose journal is the clone's terminal")
    display.add_argument("--hub", help="mesh hub URL; deploy events are read from its state")
    display.add_argument("--token-file", type=Path, default=Path(os.environ.get("EVILKIT_MESH_TOKEN_FILE", ".evilkit-mesh/token")))
    display.add_argument("--interval", type=float, help="seconds between detection passes (default from config)")
    display.add_argument("--once", action="store_true", help="run one detection pass and exit")
    display.add_argument("--no-window", dest="window", action="store_false", help="report only; never open a terminal window")
    display.add_argument("--install-unit", action="store_true", help="install and start a systemd user unit so this keeps watching across logins")
    display.add_argument("--uninstall-unit", action="store_true", help="stop and remove that unit")
    display.add_argument("--status", action="store_true", help="report the unit and any open display window, then exit")
    display.set_defaults(window=True)
    return parser

def _display_config(args, config) -> "object":
    """Build the display config from the config file plus this command's overrides."""
    from .clone_display import CloneTarget, DisplayConfig

    base = config.clone_display
    segments = tuple(args.segment) if args.segment else base.segments
    if args.host:
        user = args.user or (base.targets[0].user if base.targets else "pi")
        identity = str(args.identity) if args.identity else (
            base.targets[0].identity if base.targets else "~/.ssh/id_ed25519_evilkimi_pi"
        )
        unit = args.unit or (base.targets[0].unit if base.targets else "evilk-mesh-worker-pi.service")
        targets = []
        for entry in args.host:
            if "=" not in entry:
                raise MeshError(f"--host expects NAME=IP, got {entry!r}")
            name, _, host = entry.partition("=")
            name, host = name.strip(), host.strip()
            if not name or not host:
                raise MeshError(f"--host expects NAME=IP, got {entry!r}")
            targets.append(CloneTarget(name=name, host=host, user=user, identity=identity, unit=unit))
        targets = tuple(targets)
    else:
        targets = base.targets
    return DisplayConfig(
        enabled=base.enabled and getattr(args, "window", True),
        segments=segments,
        deny=base.deny,
        targets=targets,
        poll_interval=args.interval or base.poll_interval,
        terminal=base.terminal,
        log=base.log,
    )


#: The systemd user unit that keeps the attacker-side display watching.
DISPLAY_UNIT = "evilkit-clone-display.service"


def _unit_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "systemd" / "user" / DISPLAY_UNIT


def _systemctl(*args: str) -> tuple[int, str]:
    try:
        result = subprocess.run(
            ["systemctl", "--user", *args], capture_output=True, text=True, timeout=60
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return result.returncode, (result.stdout + result.stderr).strip()


def install_display_unit(*, start: bool = True, token_file: Path | None = None) -> str:
    """Persist the watcher as a systemd *user* unit (no root, this account only)."""
    path = _unit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    token_path = (token_file or Path(".evilkit-mesh/token")).expanduser().resolve()
    unit = (
        "[Unit]\n"
        "Description=EvilKit clone display (attack segment only)\n"
        "After=graphical-session.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={sys.executable} -m evilkit mesh display --token-file {token_path}\n"
        "Restart=always\n"
        "RestartSec=10\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )
    path.write_text(unit, encoding="utf-8")
    _systemctl("daemon-reload")
    _, enabled = _systemctl("enable", DISPLAY_UNIT)
    if start:
        code, message = _systemctl("restart", DISPLAY_UNIT)
        return (
            f"installed {path}\n{enabled}\n"
            f"{'started' if code == 0 else 'could not start'}: {message}"
        )
    return f"installed {path}\n{enabled}"


def uninstall_display_unit() -> str:
    path = _unit_path()
    _, stopped = _systemctl("disable", "--now", DISPLAY_UNIT)
    removed = "no unit file"
    try:
        path.unlink()
        removed = f"removed {path}"
    except FileNotFoundError:
        pass
    except OSError as exc:
        removed = f"could not remove {path}: {exc}"
    _systemctl("daemon-reload")
    return f"{stopped}\n{removed}"


def display_status(config) -> str:
    from .clone_display import registered_window

    path = _unit_path()
    installed = path.is_file()
    lines = [f"unit file     : {path} {'installed' if installed else 'not installed'}"]
    if installed:
        _, active = _systemctl("is-active", DISPLAY_UNIT)
        lines.append(f"unit state    : {active or 'unknown'}")
    display_cfg = config.clone_display
    lines.append(
        f"attack segment: {', '.join(display_cfg.segments) or '(none configured)'}"
    )
    lines.append(f"targets       : {', '.join(f'{t.name}@{t.host}' for t in display_cfg.targets) or '(none)'}")
    for target in display_cfg.targets:
        pid = registered_window(target.name)
        lines.append(
            f"window        : {target.name} "
            + (f"open (pid {pid})" if pid else "not open")
        )
    lines.append(f"event log     : {display_cfg.resolved_log()}")
    return "\n".join(lines)


def _start_display_watcher(config, *, hub_address: str | None, token_file: Path, state_provider=None):
    """Start the background clone-display thread; returns the watcher or None."""
    from .clone_display import DeploymentWatcher

    display_cfg = config.clone_display
    if not display_cfg.enabled or not display_cfg.targets:
        return None

    def _report(kind: str, record: dict) -> None:
        detail = ", ".join(
            f"{key}={value}" for key, value in record.items() if key not in ("kind", "ts")
        )
        print(f"[clone-display] {kind}: {detail}", flush=True)

    watcher = DeploymentWatcher(
        display_cfg,
        hub=hub_address,
        token_file=token_file,
        on_event=_report,
        state_provider=state_provider,
    )
    thread = threading.Thread(target=watcher.run, daemon=True, name="clone-display")
    thread.start()
    names = ", ".join(f"{t.name}@{t.host}" for t in display_cfg.targets)
    print(
        f"clone display: watching {names} on {', '.join(display_cfg.segments)} "
        "(attack segment only)",
        flush=True,
    )
    return watcher


def main(argv: list[str] | None = None) -> int:
    args = _args().parse_args(argv)
    try:
        if args.action == "start":
            if args.brief is not None:
                if not args.allow_unscoped or args.scope is not None:
                    raise MeshError("--brief requires --allow-unscoped and cannot be combined with --scope")
                read_brief(args.brief)
                scope = None
            else:
                if args.allow_unscoped:
                    raise MeshError("--allow-unscoped requires --brief PATH")
                scope_text = args.scope
                if scope_text is None:
                    if not sys.stdin.isatty():
                        raise MeshError("authorized scope is required: pass --scope TARGETS")
                    scope_text = input("Authorized target scope (host, IP, or CIDR): ").strip()
                    if not scope_text:
                        raise MeshError("authorized scope cannot be empty")
                scope = scope_mod.normalise_scope(scope_text, allow_any=args.allow_any)
            return _start_tmux(
                scope,
                args.brief,
                args.port,
                args.token_file,
                attach=not args.no_attach,
                local_workers=args.local_workers,
                popup_windows=args.popup_windows,
                display_clones=args.display_clones,
            )
        if args.action == "lead":
            if args.brief is not None:
                if not args.allow_unscoped or args.scope is not None:
                    raise MeshError("--brief requires --allow-unscoped and cannot be combined with --scope")
                brief, brief_sha256 = read_brief(args.brief)
                scope = None
            else:
                if args.allow_unscoped or args.scope is None:
                    raise MeshError("pass --scope TARGETS, or --brief PATH with --allow-unscoped")
                scope = scope_mod.normalise_scope(args.scope, allow_any=args.allow_any)
                brief = None
                brief_sha256 = None
            _safe_bind(args.bind)
            config, config_problems = config_mod.load()
            for problem in config_problems:
                print(f"evilkit mesh: config: {problem}", file=sys.stderr)
            kimi = None
            if args.cockpit:
                kimi = _kimi_binary()
            token = _token(args.token_file, create=True)
            popup_enabled = args.popup_windows and os.environ.get("EVILKIT_POPUP_WINDOWS", "1").strip().lower() not in ("0", "false", "no", "off")
            popup_mgr = ClonePopupManager(enabled=popup_enabled)
            hub = Hub(scope, token, brief=brief)
            server = MeshServer((args.bind, args.port), _handler(hub))
            address = f"http://{args.bind}:{server.server_port}"
            token_resolved = args.token_file.expanduser().resolve()

            display_targets = {t.name for t in config.clone_display.targets}
            display_watcher = None
            if args.display_clones:
                display_watcher = _start_display_watcher(
                    config,
                    hub_address=address,
                    token_file=token_resolved,
                    state_provider=hub.state,
                )
                if display_watcher is None:
                    print(
                        "clone display: no [[clone_display.targets]] configured; "
                        "nothing will pop up for remote clones",
                        flush=True,
                    )

            def _clone_up(clone_name: str) -> None:
                # A configured display target (the Pi) gets its own terminal over
                # SSH, attack segment only. Everything else keeps the hub-stream
                # window, which is what the watch pane already shows.
                if display_watcher is not None and clone_name in display_targets:
                    from .clone_display import display_for_clone

                    result = display_for_clone(
                        clone_name,
                        config.clone_display,
                        hub=address,
                        token_file=token_resolved,
                        state_provider=hub.state,
                        watcher=display_watcher,
                    )
                    if result is not None:
                        return
                    if not popup_enabled:
                        return
                if popup_enabled:
                    popup_mgr.popup_for_worker(
                        clone_name, address, token_resolved, python_executable=sys.executable
                    )

            hub.on_clone_up = _clone_up
            _write_connection(args.token_file, address)
            boundary = f"brief-based unscoped ({brief_sha256[:12]})" if brief is not None else scope
            print(f"mesh hub: {address}\nscope: {boundary}\ntoken file: {token_resolved}", flush=True)
            if args.cockpit:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                env = dict(os.environ)
                env["EVILKIT_MESH_LEADER"] = address
                env["EVILKIT_MESH_TOKEN_FILE"] = str(token_resolved)
                boundary_text = (
                    "The complete readable engagement brief is below. Follow its in-scope targets, "
                    "out-of-scope exclusions, and testing restrictions exactly. The mesh has not "
                    "recorded a pentest MCP target scope.\n<engagement_brief>\n"
                    + brief + "\n</engagement_brief>\n"
                    if brief is not None else f"The authorized target scope is {scope}.\n"
                )
                agent_text = (
                    "---\nname: evilkit-mesh-leader\n"
                    "description: Coordinate scoped Kimi workers through the evilkit mesh hub\n"
                    "tools:\n  - Read\n  - mcp__evilkit-mesh__*\n---\n"
                    "${base_prompt}\n"
                    "You are the mesh leader. " + boundary_text + " "
                    "Use the evilkit-mesh MCP tools assign_task, list_workers, "
                    "tail_session, and list_findings to coordinate workers. "
                    "Do not run target scans on this leader box. Summarize worker evidence and status for the operator.\n"
                )
                agent_file = None
                try:
                    _install_mcp(_kimi_project_mcp_path(Path.cwd()))
                    with tempfile.NamedTemporaryFile("w", suffix=".md", prefix="evilkit-mesh-agent-", delete=False, encoding="utf-8") as handle:
                        agent_file = Path(handle.name)
                        handle.write(agent_text)
                    print("Kimi cockpit ready. `evilkit mesh watch` in another terminal shows every live worker stream.", flush=True)
                    return subprocess.call([kimi, "--agent-file", str(agent_file)], env=env)
                finally:
                    if agent_file is not None:
                        agent_file.unlink(missing_ok=True)
                    server.shutdown()
                    server.server_close()
                    popup_mgr.close_all()
                    if display_watcher is not None:
                        display_watcher.close_all()
            try:
                server.serve_forever()
            finally:
                server.server_close()
                popup_mgr.close_all()
                if display_watcher is not None:
                    display_watcher.close_all()
            return 0
        if args.action == "work":
            if getattr(args, "window", False):
                raw_argv = [a for a in (argv if argv is not None else sys.argv[1:]) if a != "--window"]
                proc = spawn_terminal_window(
                    [sys.executable, "-m", "evilkit", "mesh", *raw_argv],
                    title=f"EvilKit Clone: {args.name}",
                    hold=True,
                    cwd=Path.cwd(),
                )
                if proc is None:
                    raise MeshError("cannot open a terminal window (no display or terminal emulator found)")
                print(f"mesh worker {args.name}: opened terminal window (pid {proc.pid})", flush=True)
                return 0
            base = _url(args.leader)
            token = _token(args.token_file)
            config, _ = config_mod.load()
            kimi = _kimi_binary()
            while True:
                try:
                    state = _request(base, token, "/state")
                    break
                except MeshError:
                    if not args.wait:
                        raise
                    time.sleep(1)
            remote_scope = state["scope"]
            mode = state.get("mode", "recorded-scope")
            if mode == "brief-unscoped":
                if not args.allow_unscoped:
                    raise MeshError("hub is brief-based and unscoped; pass --allow-unscoped to join")
                brief_data = _request(base, token, "/brief")
                brief = brief_data["text"]
                brief_sha256 = hashlib.sha256(brief.encode("utf-8")).hexdigest()
                if brief_sha256 != state["brief_sha256"] or brief_sha256 != brief_data["sha256"]:
                    raise MeshError("engagement brief changed during download")
                path = args.mcp_json.expanduser() if args.mcp_json is not None else _kimi_project_mcp_path(Path.cwd())
            elif mode == "recorded-scope":
                if args.allow_unscoped:
                    raise MeshError("hub uses a recorded scope; omit --allow-unscoped")
                brief = None
                brief_sha256 = None
                path = _scope_record(remote_scope, args.mcp_json, config.backup_keep)
            else:
                raise MeshError(f"unknown hub mode: {mode}")
            _install_mcp(path)
            registered = _request(base, token, "/register", {"name": args.name})
            if registered.get("mode") != mode or registered.get("brief_sha256") != brief_sha256:
                raise MeshError("hub authorization mode changed during registration")
            os.environ["EVILKIT_MESH_TOKEN_FILE"] = str(args.token_file.expanduser().resolve())
            print(f"mesh worker {args.name}: connected; {mode} {brief_sha256[:12] if brief_sha256 else remote_scope}", flush=True)
            while True:
                claim = _request(base, token, "/claim", {"name": args.name})
                if claim["scope"] != remote_scope or claim.get("mode") != mode or claim.get("brief_sha256") != brief_sha256:
                    raise MeshError("hub authorization boundary changed; refusing task")
                if claim["task"]:
                    _run_task(base, token, args.name, claim["task"], remote_scope, brief, args.mcp_json, kimi, config.backup_keep)
                    if args.once:
                        return 0
                else:
                    if args.once:
                        return 0
                    time.sleep(2)
        if args.action == "display":
            from .clone_display import DeploymentWatcher, attack_segment_of, registered_window

            config, config_problems = config_mod.load()
            for problem in config_problems:
                print(f"evilkit mesh: config: {problem}", file=sys.stderr)
            if args.install_unit:
                print(install_display_unit(token_file=args.token_file))
                return 0
            if args.uninstall_unit:
                print(uninstall_display_unit())
                return 0
            if args.status:
                print(display_status(config))
                return 0
            display_cfg = _display_config(args, config)
            if not display_cfg.targets:
                raise MeshError(
                    "no clone to display: add [[clone_display.targets]] to "
                    f"{config_mod.config_path()} or pass --host NAME=IP"
                )
            for target in display_cfg.targets:
                # Fail closed before anything is watched: a target that is not on a
                # configured attack segment is a configuration error, not a warning.
                attack_segment_of(target.host, display_cfg.segments, display_cfg.deny)

            hub_url = args.hub or os.environ.get("EVILKIT_MESH_LEADER") or _read_connection(args.token_file)

            def _report(kind: str, record: dict) -> None:
                detail = ", ".join(
                    f"{key}={value}" for key, value in record.items() if key not in ("kind", "ts")
                )
                print(f"[clone-display] {kind}: {detail}", flush=True)

            watcher = DeploymentWatcher(
                display_cfg,
                hub=hub_url,
                token_file=args.token_file if args.token_file.exists() else None,
                once=args.once,
                on_event=_report,
            )
            names = ", ".join(f"{t.name}@{t.host}" for t in display_cfg.targets)
            print(
                f"clone display: watching {names} on {', '.join(display_cfg.segments)} "
                f"(attack segment only){'' if display_cfg.enabled else ' [report only]'}",
                flush=True,
            )
            try:
                watcher.run()
            except KeyboardInterrupt:
                pass
            # The windows are independent sessions (they hold the remote stream);
            # they stay open on exit so the operator keeps watching the clone.
            return 0
        if not args.leader:
            args.leader = _read_connection(args.token_file)
        if not args.leader:
            raise MeshError("pass --leader or set EVILKIT_MESH_LEADER")
        base = _url(args.leader)
        token = _token(args.token_file)
        if args.action == "task":
            result = _request(base, token, "/task", {"prompt": args.prompt, "worker": args.worker})
            print(result["id"])
        elif args.action == "state":
            print(json.dumps(_request(base, token, "/state"), indent=2))
        elif args.action == "findings":
            print(json.dumps(_request(base, token, "/state")["findings"], indent=2))
        elif args.action == "finding":
            if not args.worker or not args.task_id:
                raise MeshError("finding requires a worker and task ID (worker session sets these automatically)")
            result = _request(base, token, "/finding", {"name": args.worker, "task": args.task_id, "title": args.title, "detail": args.detail})
            print(result["id"])
        elif args.action == "tail":
            path = "/tail?" + urllib.parse.urlencode({"after": args.since, **({"worker": args.worker} if args.worker else {})})
            print(json.dumps(_request(base, token, path), indent=2))
        elif args.action == "watch":
            if getattr(args, "window", False):
                raw_argv = [a for a in (argv if argv is not None else sys.argv[1:]) if a != "--window"]
                title = f"EvilKit Clone: {args.worker}" if getattr(args, "worker", None) else "EvilKit Mesh Watch"
                proc = spawn_terminal_window(
                    [sys.executable, "-m", "evilkit", "mesh", *raw_argv],
                    title=title,
                    hold=True,
                    cwd=Path.cwd(),
                )
                if proc is None:
                    raise MeshError("cannot open a terminal window (no display or terminal emulator found)")
                print(f"mesh watch: opened terminal window (pid {proc.pid})", flush=True)
                return 0
            after = args.since
            while True:
                path = "/tail?" + urllib.parse.urlencode({"after": after, **({"worker": args.worker} if args.worker else {})})
                try:
                    result = _request(base, token, path)
                except MeshError:
                    if not args.wait:
                        raise
                    time.sleep(1)
                    continue
                for event in result["events"]:
                    after = max(after, event["seq"])
                    if event["kind"] == "output":
                        print(f"[{event['worker']}] {event['text']}", end="", flush=True)
                    else:
                        print(f"\n[{event['worker']}] {event['kind']}: {event['text']}", flush=True)
                after = max(after, result["sequence"] if not result["events"] else after)
                time.sleep(0.5)
        elif args.action == "node":
            if getattr(args, "window", False):
                raw_argv = [a for a in (argv if argv is not None else sys.argv[1:]) if a != "--window"]
                proc = spawn_terminal_window(
                    [sys.executable, "-m", "evilkit", "mesh", *raw_argv],
                    title=f"EvilKit Node: {args.name}",
                    hold=True,
                    cwd=Path.cwd(),
                )
                if proc is None:
                    raise MeshError("cannot open a terminal window (no display or terminal emulator found)")
                print(f"mesh node {args.name}: opened terminal window (pid {proc.pid})", flush=True)
                return 0
            from .mesh_node import NodeConfig, NodeDaemon
            base = _url(args.leader)
            token = _token(args.token_file)
            while True:
                try:
                    _request(base, token, "/state")
                    break
                except MeshError:
                    if not args.wait:
                        raise
                    time.sleep(1)
            args.sandbox.mkdir(parents=True, exist_ok=True)
            config = NodeConfig(sandbox=args.sandbox)
            daemon = NodeDaemon(args.name, base, token, config)
            daemon.run()
            return 0
        elif args.action == "node-status":
            if not args.leader:
                args.leader = _read_connection(args.token_file)
            if not args.leader:
                raise MeshError("pass --leader or set EVILKIT_MESH_LEADER")
            base = _url(args.leader)
            token = _token(args.token_file)
            print(json.dumps(_request(base, token, "/node/status"), indent=2))
        elif args.action == "node-kill":
            if not args.leader:
                args.leader = _read_connection(args.token_file)
            if not args.leader:
                raise MeshError("pass --leader or set EVILKIT_MESH_LEADER")
            base = _url(args.leader)
            token = _token(args.token_file)
            result = _request(base, token, "/node/kill", {"name": args.node_name})
            print(f"node {args.node_name}: {'killed' if result.get('killed') else 'failed'}")
        elif args.action == "node-task":
            if not args.leader:
                args.leader = _read_connection(args.token_file)
            if not args.leader:
                raise MeshError("pass --leader or set EVILKIT_MESH_LEADER")
            base = _url(args.leader)
            token = _token(args.token_file)
            task_data: dict = {"type": args.type, "node": args.node}
            if args.type in ("list_files", "read_file", "file_hash"):
                if not args.path:
                    raise MeshError(f"--path is required for {args.type}")
                task_data["path"] = args.path
            elif args.type == "run_command":
                if not args.command:
                    raise MeshError("--command is required for run_command")
                task_data["command"] = args.command
            elif args.type == "observe":
                if not args.category or not args.subject or not args.detail:
                    raise MeshError("--category, --subject, and --detail are required for observe")
                task_data["category"] = args.category
                task_data["subject"] = args.subject
                task_data["detail"] = args.detail
            result = _request(base, token, "/node/task", task_data)
            print(result["id"])
        elif args.action == "node-knowledge":
            if not args.leader:
                args.leader = _read_connection(args.token_file)
            if not args.leader:
                raise MeshError("pass --leader or set EVILKIT_MESH_LEADER")
            base = _url(args.leader)
            token = _token(args.token_file)
            params = {"limit": args.limit}
            if args.category:
                params["category"] = args.category
            items = _request(base, token, "/node/knowledge?" + urllib.parse.urlencode(params))
            print(json.dumps(items, indent=2))
        return 0
    except (MeshError, BriefError, SegmentError, scope_mod.ScopeError, OSError) as exc:
        print(f"evilkit mesh: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130

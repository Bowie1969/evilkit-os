"""Stdio MCP bridge for the Evilkit mesh.

Kimi launches this process from its MCP config. It inherits the leader URL,
worker/task identity, and token-file path from the Kimi process environment.
No bearer token is stored in project MCP configuration.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .mesh import MeshError, _request, _token, _url


TOOLS = [
    {
        "name": "assign_task",
        "description": "Queue one authorized task for a worker, or the next available worker.",
        "inputSchema": {"type": "object", "properties": {"prompt": {"type": "string"}, "worker": {"type": "string"}}, "required": ["prompt"]},
    },
    {
        "name": "list_workers",
        "description": "Show worker and task status on the mesh hub.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "tail_session",
        "description": "Read a finite batch of live worker output after a sequence number.",
        "inputSchema": {"type": "object", "properties": {"after": {"type": "integer"}, "worker": {"type": "string"}}},
    },
    {
        "name": "list_findings",
        "description": "List findings reported by workers.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "report_finding",
        "description": "Report a worker finding with title and supporting evidence.",
        "inputSchema": {"type": "object", "properties": {"title": {"type": "string"}, "detail": {"type": "string"}}, "required": ["title", "detail"]},
    },
    {
        "name": "task_update",
        "description": "Record a worker progress update for its current task.",
        "inputSchema": {"type": "object", "properties": {"note": {"type": "string"}}, "required": ["note"]},
    },
    # --- Node tools ---
    {
        "name": "list_nodes",
        "description": "Show enrolled mesh node status, tasks, and knowledge base summary.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "node_task",
        "description": "Queue a task for a mesh node: list_files, read_file, file_hash, run_command, or observe.",
        "inputSchema": {"type": "object", "properties": {"type": {"type": "string", "enum": ["list_files", "read_file", "file_hash", "run_command", "observe"]}, "node": {"type": "string"}, "path": {"type": "string"}, "command": {"type": "string"}, "category": {"type": "string"}, "subject": {"type": "string"}, "detail": {"type": "string"}}, "required": ["type"]},
    },
    {
        "name": "node_knowledge",
        "description": "Query the shared knowledge base of observations from all nodes.",
        "inputSchema": {"type": "object", "properties": {"category": {"type": "string"}, "limit": {"type": "integer"}}},
    },
    {
        "name": "node_kill",
        "description": "Permanently kill an enrolled mesh node. It will shut down and cannot re-register.",
        "inputSchema": {"type": "object", "properties": {"node_name": {"type": "string"}}, "required": ["node_name"]},
    },
]


def _call(name: str, args: dict) -> object:
    base = _url(os.environ.get("EVILKIT_MESH_LEADER", ""))
    token = _token(Path(os.environ.get("EVILKIT_MESH_TOKEN_FILE", ".evilkit-mesh/token")))
    worker = os.environ.get("EVILKIT_MESH_WORKER", "")
    task = os.environ.get("EVILKIT_MESH_TASK", "")
    if name == "assign_task":
        if worker:
            raise MeshError("only the leader can assign tasks")
        return _request(base, token, "/task", {"prompt": args["prompt"], "worker": args.get("worker")})
    if name == "list_workers":
        state = _request(base, token, "/state")
        return {"scope": state["scope"], "workers": state["workers"], "tasks": state["tasks"]}
    if name == "tail_session":
        import urllib.parse

        after = args.get("after", 0)
        if not isinstance(after, int) or after < 0:
            raise MeshError("after must be a nonnegative integer")
        query = {"after": after}
        if args.get("worker"):
            query["worker"] = args["worker"]
        return _request(base, token, "/tail?" + urllib.parse.urlencode(query))
    if name == "list_findings":
        return _request(base, token, "/state")["findings"]
    if name == "report_finding":
        if not worker or not task:
            raise MeshError("only an active worker can report a finding")
        return _request(base, token, "/finding", {"name": worker, "task": task, "title": args["title"], "detail": args["detail"]})
    if name == "task_update":
        if not worker or not task:
            raise MeshError("only an active worker can update a task")
        return _request(base, token, "/update", {"name": worker, "task": task, "note": args["note"]})
    # Node tools
    if name == "list_nodes":
        return _request(base, token, "/node/status")
    if name == "node_task":
        task_type = args["type"]
        task_data: dict = {"type": task_type}
        if args.get("node"):
            task_data["node"] = args["node"]
        if task_type in ("list_files", "read_file", "file_hash"):
            if not args.get("path"):
                raise MeshError(f"path is required for {task_type}")
            task_data["path"] = args["path"]
        elif task_type == "run_command":
            if not args.get("command"):
                raise MeshError("command is required for run_command")
            task_data["command"] = args["command"]
        elif task_type == "observe":
            for key in ("category", "subject", "detail"):
                if not args.get(key):
                    raise MeshError(f"{key} is required for observe")
                task_data[key] = args[key]
        return _request(base, token, "/node/task", task_data)
    if name == "node_knowledge":
        import urllib.parse
        params = {"limit": min(args.get("limit", 50), 200)}
        if args.get("category"):
            params["category"] = args["category"]
        return _request(base, token, "/node/knowledge?" + urllib.parse.urlencode(params))
    if name == "node_kill":
        return _request(base, token, "/node/kill", {"name": args["node_name"]})
    raise MeshError(f"unknown tool: {name}")


def _response(request: dict) -> dict | None:
    method = request.get("method")
    request_id = request.get("id")
    if request_id is None:
        return None
    try:
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "evilkit-mesh", "version": "1.0.0"}}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = request.get("params") or {}
            value = _call(params["name"], params.get("arguments") or {})
            result = {"content": [{"type": "text", "text": json.dumps(value)}]}
        else:
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "method not found"}}
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except (MeshError, KeyError, TypeError, ValueError) as exc:
        if method == "tools/call":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"content": [{"type": "text", "text": str(exc)}], "isError": True}}
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": str(exc)}}


def main() -> int:
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("request must be an object")
            response = _response(request)
        except (json.JSONDecodeError, ValueError) as exc:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}
        if response is not None:
            print(json.dumps(response), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

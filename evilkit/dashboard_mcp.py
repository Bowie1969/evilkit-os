"""Stdio MCP bridge for the lab dashboard's run controls.

Kimi launches this process from its MCP config, so the operator can put its run
on the board, take it off again, and finish its own run on request. The wire
shape, the timeout and the terminal-state write all live in
:mod:`evilkit.dashboard_control` — this module is only the JSON-RPC surface plus
the descriptions the model reads.

What the controls are: the board's own fixed, pre-registered scripts, which are
bookkeeping — start marks the newest prepared run as the one being tracked, stop
marks the tracked run finished. They do not launch or tear down the range, they
do not start or stop an operator session, and no tool here puts traffic on an
engagement target. The board's run-control endpoints carry a same-origin check
rather than auth, so reaching the configured URL is the whole authority.

``end_run`` is the one action that makes no request: it finalises the run bound
by ``EVILKIT_DASHBOARD_RUN_DIR`` by writing the terminal state the board already
understands (``finished``).
"""

from __future__ import annotations

import json
import sys

from . import dashboard_control

TOOLS = [
    {
        "name": "start_run",
        "description": (
            "Start tracking a prepared run on the lab dashboard: marks the newest prepared run "
            "live so the board switches off the live-brain view and onto it. It does not launch "
            "the range or the operator, and sends no traffic to any target. Refused when a run "
            "is already being tracked (stop_run first)."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "stop_run",
        "description": (
            "Stop tracking the run the dashboard has live, so the board returns to the "
            "live-brain view. It does not stop the range or the operator session, and sends no "
            "traffic to any target. Fails when nothing is being tracked."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "end_run",
        "description": (
            "Finalise this run's own record: mark the bound run finished in its status file so "
            "the dashboard stops treating it as live. Works whether or not the board is tracking "
            "it; stops nothing, tears nothing down, and sends nothing to any target. Use it when "
            "the engagement on this run is over."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "run_status",
        "description": (
            "Read the dashboard's status: which control (if any) is running now and which of "
            "its registered scripts exist. Read-only; use it to see the effect of the controls."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _call(name: str, args: dict) -> object:
    if name == "start_run":
        return dashboard_control.control("start")
    if name == "stop_run":
        return dashboard_control.control("stop")
    if name == "end_run":
        return dashboard_control.end_run()
    if name == "run_status":
        return dashboard_control.status()
    raise dashboard_control.DashboardError(f"unknown tool: {name}")


def _response(request: dict) -> dict | None:
    method = request.get("method")
    request_id = request.get("id")
    if request_id is None:
        return None
    try:
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "evilkit-dashboard", "version": "1.0.0"},
            }
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
    except (dashboard_control.DashboardError, KeyError, TypeError, ValueError) as exc:
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

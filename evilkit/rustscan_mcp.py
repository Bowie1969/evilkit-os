#!/usr/bin/env python3
"""Scope-gated RustScan MCP server for authorized EvilKit reconnaissance."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "evilkit-rustscan", "version": "2.0.0"}
DEFAULT_ALLOWED = "10.99.50.0/24,10.50.0.0/24,10.50.1.0/24"
DEFAULT_DENIED = "192.168.0.0/24,10.10.0.0/16"
MAX_OUTPUT_BYTES = 2_000_000
PORT_SPEC_RE = re.compile(r"\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*")


class ReconError(Exception):
    """Operator-visible validation or scanner failure."""


def _networks(value: str, label: str) -> tuple[ipaddress._BaseNetwork, ...]:
    networks = []
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError as exc:
            raise ReconError(f"invalid {label} network {token!r}: {exc}") from exc
    if label == "allowed" and not networks:
        raise ReconError("RECON_ALLOWED_TARGETS is empty; refusing all scans")
    return tuple(networks)


@dataclass(frozen=True)
class ScopePolicy:
    allowed_text: str
    denied_text: str
    allowed: tuple[ipaddress._BaseNetwork, ...]
    denied: tuple[ipaddress._BaseNetwork, ...]
    max_hosts: int

    @classmethod
    def from_env(cls) -> "ScopePolicy":
        allowed_text = os.environ.get("RECON_ALLOWED_TARGETS", DEFAULT_ALLOWED)
        denied_text = os.environ.get("RECON_DENIED_TARGETS", DEFAULT_DENIED)
        try:
            max_hosts = int(os.environ.get("RECON_MAX_HOSTS", "256"))
        except ValueError as exc:
            raise ReconError("RECON_MAX_HOSTS must be an integer") from exc
        if not 1 <= max_hosts <= 4096:
            raise ReconError("RECON_MAX_HOSTS must be between 1 and 4096")
        return cls(
            allowed_text=allowed_text,
            denied_text=denied_text,
            allowed=_networks(allowed_text, "allowed"),
            denied=_networks(denied_text, "denied"),
            max_hosts=max_hosts,
        )

    def validate_targets(self, raw: object) -> list[str]:
        if isinstance(raw, str):
            tokens = raw.split(",")
        elif isinstance(raw, list) and all(isinstance(item, str) for item in raw):
            tokens = raw
        else:
            raise ReconError("targets must be a comma-separated string or a list of IP/CIDR strings")
        targets: list[str] = []
        total_hosts = 0
        for token in tokens:
            token = token.strip()
            if not token:
                continue
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise ReconError(f"target {token!r} must be an IP address or CIDR") from exc
            if any(network.version == denied.version and network.overlaps(denied) for denied in self.denied):
                raise ReconError(f"target {token} is denied by RECON_DENIED_TARGETS")
            if not any(network.version == allowed.version and network.subnet_of(allowed) for allowed in self.allowed):
                raise ReconError(f"target {token} is outside RECON_ALLOWED_TARGETS ({self.allowed_text})")
            total_hosts += network.num_addresses
            if total_hosts > self.max_hosts:
                raise ReconError(f"target set expands to more than RECON_MAX_HOSTS={self.max_hosts}")
            canonical = str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
            if canonical not in targets:
                targets.append(canonical)
        if not targets:
            raise ReconError("no targets given")
        return targets


def _integer(args: dict[str, Any], name: str, default: int, minimum: int, maximum: int) -> int:
    value = args.get(name, default)
    if isinstance(value, bool):
        raise ReconError(f"{name} must be an integer")
    try:
        value = int(value)
    except (TypeError, ValueError) as exc:
        raise ReconError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ReconError(f"{name} must be between {minimum} and {maximum}")
    return value


def _port_spec(value: object) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).replace(" ", "")
    if not PORT_SPEC_RE.fullmatch(text):
        raise ReconError("ports must contain only comma-separated ports or ranges")
    for part in text.split(","):
        bounds = [int(item) for item in part.split("-")]
        if any(port < 1 or port > 65535 for port in bounds) or len(bounds) == 2 and bounds[0] > bounds[1]:
            raise ReconError(f"invalid port or range: {part}")
    return text


def _bounded_output(stdout: str | None, stderr: str | None) -> tuple[str, str]:
    stdout = stdout or ""
    stderr = stderr or ""
    if len(stdout.encode("utf-8", errors="replace")) > MAX_OUTPUT_BYTES:
        raise ReconError("scanner output exceeded the 2 MB safety limit")
    return stdout, stderr[-4000:]


def _run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise ReconError(f"required scanner is not installed: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ReconError(f"{command[0]} exceeded its {timeout}s execution limit") from exc


def _parse_rustscan(output: str) -> dict[str, list[int]]:
    ports: dict[str, set[int]] = {}
    for match in re.finditer(r"(?m)^Open\s+(\S+):(\d+)\s*$", output):
        ports.setdefault(match.group(1), set()).add(int(match.group(2)))
    for match in re.finditer(r"(?m)^([^\s]+)\s*->\s*\[([^]]*)\]\s*$", output):
        host = match.group(1)
        for token in match.group(2).split(","):
            token = token.strip()
            if token.isdigit():
                ports.setdefault(host, set()).add(int(token))
    return {host: sorted(values) for host, values in sorted(ports.items())}


def _parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ReconError(f"nmap returned invalid XML: {exc}") from exc
    services = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port.find("service")
        item: dict[str, Any] = {
            "port": int(port.get("portid", "0")),
            "protocol": port.get("protocol", "tcp"),
            "state": "open",
        }
        if service is not None:
            for source, destination in (
                ("name", "service"), ("product", "product"), ("version", "version"),
                ("extrainfo", "extra_info"), ("tunnel", "tunnel"),
            ):
                if service.get(source):
                    item[destination] = service.get(source)
        services.append(item)
    return services


def _scan_services(host: str, ports: list[int], args: dict[str, Any]) -> list[dict[str, Any]]:
    host_timeout = _integer(args, "host_timeout_seconds", 90, 10, 300)
    intensity = _integer(args, "service_intensity", 5, 0, 9)
    command = [
        "nmap", "-Pn", "-sT", "-sV", "--version-intensity", str(intensity), "-T4",
        "--host-timeout", f"{host_timeout}s", "-p", ",".join(map(str, ports)), "-oX", "-", host,
    ]
    if args.get("default_scripts") is True:
        command.insert(4, "-sC")
    completed = _run(command, host_timeout + 15)
    stdout, stderr = _bounded_output(completed.stdout, completed.stderr)
    if completed.returncode != 0:
        raise ReconError(f"nmap failed for {host} (exit {completed.returncode}): {stderr.strip() or 'no error text'}")
    return _parse_nmap_xml(stdout)


def scan(args: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(args, dict):
        raise ReconError("arguments must be an object")
    policy = ScopePolicy.from_env()
    targets = policy.validate_targets(args.get("targets"))
    batch = _integer(args, "batch", 500, 1, 10000)
    timeout_ms = _integer(args, "timeout_ms", 1500, 50, 10000)
    tries = _integer(args, "tries", 1, 1, 3)
    execution_limit = _integer(args, "scan_timeout_seconds", 50, 10, 600)
    scan_order = args.get("scan_order", "serial")
    if scan_order not in ("serial", "random"):
        raise ReconError("scan_order must be 'serial' or 'random'")
    ports = _port_spec(args.get("ports"))
    if ports and args.get("top_1000") is True:
        raise ReconError("ports and top_1000 cannot be used together")
    command = [
        "rustscan", "--no-config", "--no-banner", "--greppable", "--addresses", ",".join(targets),
        "--batch-size", str(batch), "--timeout", str(timeout_ms), "--tries", str(tries),
        "--ulimit", "4096", "--scan-order", scan_order, "--scripts", "none",
    ]
    if ports:
        command.extend(["--ports", ports])
    elif args.get("top_1000") is True:
        command.append("--top")

    started = time.monotonic()
    completed = _run(command, execution_limit)
    stdout, stderr = _bounded_output(completed.stdout, completed.stderr)
    if completed.returncode != 0:
        raise ReconError(f"rustscan failed (exit {completed.returncode}): {stderr.strip() or 'no error text'}")
    discovered = _parse_rustscan(stdout)
    hosts = []
    for host, open_ports in discovered.items():
        item: dict[str, Any] = {"address": host, "open_ports": open_ports}
        if args.get("service_detect") is True and open_ports:
            item["services"] = _scan_services(host, open_ports, args)
        hosts.append(item)
    result: dict[str, Any] = {
        "status": "completed",
        "targets": targets,
        "scope": {"allowed": policy.allowed_text, "denied": policy.denied_text},
        "hosts": hosts,
        "summary": {
            "hosts_with_open_ports": len(hosts),
            "open_port_count": sum(len(item["open_ports"]) for item in hosts),
            "duration_ms": round((time.monotonic() - started) * 1000),
        },
    }
    warnings = [line for line in stderr.splitlines() if line.strip()]
    if warnings:
        result["warnings"] = warnings[-20:]
    return result


def health() -> dict[str, Any]:
    policy = ScopePolicy.from_env()
    return {
        "status": "ready" if shutil.which("rustscan") else "degraded",
        "rustscan": shutil.which("rustscan"),
        "nmap": shutil.which("nmap"),
        "allowed_targets": policy.allowed_text,
        "denied_targets": policy.denied_text,
        "max_hosts": policy.max_hosts,
    }


TOOLS = [
    {
        "name": "rustscan_scan",
        "description": (
            "Run a bounded TCP port scan against authorized IP addresses or CIDRs. Scope and deny "
            "rules are enforced before execution. Optionally run per-host Nmap service detection."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {"oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
                "ports": {"type": "string", "description": "Optional ports/ranges, such as 22,80,443,8000-8100."},
                "top_1000": {"type": "boolean", "default": False},
                "batch": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 500},
                "timeout_ms": {"type": "integer", "minimum": 50, "maximum": 10000, "default": 1500},
                "tries": {"type": "integer", "minimum": 1, "maximum": 3, "default": 1},
                "scan_order": {"type": "string", "enum": ["serial", "random"], "default": "serial"},
                "scan_timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 600, "default": 50},
                "service_detect": {"type": "boolean", "default": False},
                "service_intensity": {"type": "integer", "minimum": 0, "maximum": 9, "default": 5},
                "host_timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 300, "default": 90},
                "default_scripts": {"type": "boolean", "description": "Run Nmap default scripts during service detection.", "default": False},
            },
            "required": ["targets"],
            "additionalProperties": False,
        },
    },
    {
        "name": "rustscan_health",
        "description": "Read-only check of scanner availability and effective scope policy.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]


def _tool_result(value: object, is_error: bool = False) -> dict[str, Any]:
    text = str(value) if isinstance(value, str) else json.dumps(value, sort_keys=True)
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if is_error:
        result["isError"] = True
    return result


def _response(request: dict[str, Any]) -> dict[str, Any] | None:
    request_id = request.get("id")
    method = request.get("method")
    if request_id is None:
        return None
    try:
        if method == "initialize":
            result = {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}}, "serverInfo": SERVER_INFO}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = request.get("params")
            if not isinstance(params, dict):
                raise ReconError("params must be an object")
            name = params.get("name")
            arguments = params.get("arguments", {})
            if name == "rustscan_scan":
                result = _tool_result(scan(arguments))
            elif name == "rustscan_health":
                result = _tool_result(health())
            else:
                raise ReconError(f"unknown tool: {name}")
        else:
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "method not found"}}
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except (ReconError, TypeError, ValueError) as exc:
        if method == "tools/call":
            return {"jsonrpc": "2.0", "id": request_id, "result": _tool_result(f"error: {exc}", True)}
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": str(exc)}}


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
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

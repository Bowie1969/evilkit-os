"""A tiny, tightly-scoped CONNECT proxy for an air-gapped lab box's model egress.

The Pi sits on the air-gapped attack segment: its gateway has no WAN, so the Kimi
Code CLI installed there cannot reach its model provider. Parrot is the only box
with an uplink. Rather than routing the range, this proxy lets exactly one source
reach exactly one destination:

* the client must come from an allowed source address (the Pi), and
* the request must name an allowed ``host:port`` (the model provider's API).

Everything else is answered ``403`` and journalled. Traffic is tunnelled
byte-for-byte; nothing is inspected, rewritten or stored, and the proxy binds to
the attack-LAN address only so it is not reachable from the house LAN or the
tailnet. The destination check is what keeps this a model-egress hole rather than
a general-purpose way out of the range.
"""

from __future__ import annotations

import argparse
import json
import select
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path

__all__ = ["EgressPolicy", "ProxyServer", "main", "DEFAULT_PORT"]

DEFAULT_PORT = 8888
_BUFFER = 65536
_TIMEOUT = 30.0
#: How long a fully idle tunnel may sit before it is closed.
_IDLE_TIMEOUT = 300.0


class EgressPolicy:
    """Source and destination allowlists, matched exactly."""

    def __init__(self, sources: list[str], destinations: list[str], *, log: Path | None = None):
        self.sources = {value.strip() for value in sources if value.strip()}
        self.destinations = {value.strip().lower() for value in destinations if value.strip()}
        self.log = log
        self.lock = threading.Lock()

    def source_allowed(self, address: str) -> bool:
        return address in self.sources

    def destination_allowed(self, host: str, port: int) -> bool:
        wanted = f"{host.lower()}:{int(port)}"
        if wanted in self.destinations:
            return True
        # A bare hostname in the allowlist permits its default 443.
        return host.lower() in self.destinations and int(port) == 443

    def record(self, kind: str, **fields) -> None:
        if self.log is None:
            return
        entry = {"kind": kind, "ts": time.time(), **fields}
        try:
            self.log.parent.mkdir(parents=True, exist_ok=True)
            with self.lock, self.log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, default=str) + "\n")
        except OSError:
            pass


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:  # noqa: C901 - a CONNECT handler is a linear protocol
        policy: EgressPolicy = self.server.policy  # type: ignore[attr-defined]
        peer = self.client_address[0]
        self.request.settimeout(_TIMEOUT)

        if not policy.source_allowed(peer):
            policy.record("source_denied", source=peer)
            self._reply(403, "source not allowed")
            return

        request_line = self._read_line()
        if not request_line:
            return
        parts = request_line.split()
        if len(parts) < 3 or parts[0].upper() != "CONNECT":
            policy.record("method_denied", source=peer, request=request_line[:120])
            self._reply(405, "only CONNECT is supported")
            return

        authority = parts[1]
        host, _, port_text = authority.rpartition(":")
        try:
            port = int(port_text)
        except ValueError:
            policy.record("destination_denied", source=peer, authority=authority[:120])
            self._reply(400, "bad authority")
            return

        if not policy.destination_allowed(host, port):
            policy.record("destination_denied", source=peer, host=host, port=port)
            self._reply(403, "destination not allowed")
            return

        # Drain the remaining request headers before opening the tunnel.
        while True:
            line = self._read_line()
            if not line or line in ("\r\n", "\n"):
                break

        try:
            upstream = socket.create_connection((host, port), timeout=_TIMEOUT)
        except OSError as exc:
            policy.record("upstream_failed", source=peer, host=host, port=port, error=str(exc))
            self._reply(502, "upstream unreachable")
            return

        policy.record("connected", source=peer, host=host, port=port)
        self._reply(200, "Connection established")
        sent, received = self._relay(upstream)
        upstream.close()
        policy.record("closed", source=peer, host=host, port=port,
                      sent=sent, received=received)

    def _relay(self, upstream: socket.socket) -> tuple[int, int]:
        """Pump bytes both ways until both directions are done.

        Both sockets are non-blocking, so every write goes through an explicit
        buffer: ``send`` may accept only part of a chunk, and treating that as an
        error (as ``sendall`` does on a non-blocking socket) tears the tunnel down
        mid-response — which is exactly what a large request body triggers.
        """
        client = self.request
        client.setblocking(False)
        upstream.setblocking(False)
        pending: dict[socket.socket, bytearray] = {client: bytearray(), upstream: bytearray()}
        readable = {client: True, upstream: True}
        sent = received = 0

        while True:
            wants_read = [sock for sock in (client, upstream) if readable[sock] and not pending[sock]]
            wants_write = [sock for sock in (client, upstream) if pending[sock]]
            if not wants_read and not wants_write:
                break
            try:
                ready_read, ready_write, errored = select.select(
                    wants_read, wants_write, (client, upstream), _IDLE_TIMEOUT
                )
            except (OSError, ValueError):
                break
            if errored or (not ready_read and not ready_write):
                break

            for sock in ready_read:
                try:
                    chunk = sock.recv(_BUFFER)
                except OSError:
                    chunk = b""
                if not chunk:
                    readable[sock] = False
                    continue
                target = upstream if sock is client else client
                pending[target] += chunk
                if sock is client:
                    sent += len(chunk)
                else:
                    received += len(chunk)

            for sock in ready_write:
                buffer = pending[sock]
                if not buffer:
                    continue
                try:
                    written = sock.send(buffer)
                except OSError:
                    return sent, received
                del buffer[:written]

            # A half-closed direction is propagated once its buffer has drained.
            for sock in (client, upstream):
                other = upstream if sock is client else client
                if not readable[sock] and not pending[other]:
                    try:
                        other.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

        return sent, received

    def _read_line(self) -> str:
        buffer = b""
        while not buffer.endswith(b"\n") and len(buffer) < 8192:
            try:
                chunk = self.request.recv(1)
            except OSError:
                return ""
            if not chunk:
                return ""
            buffer += chunk
        return buffer.decode("latin-1", "replace")

    def _reply(self, code: int, text: str) -> None:
        reasons = {200: "OK", 400: "Bad Request", 403: "Forbidden",
                   405: "Method Not Allowed", 502: "Bad Gateway"}
        body = f"HTTP/1.1 {code} {reasons.get(code, 'Error')}\r\n\r\n"
        try:
            self.request.sendall(body.encode("latin-1"))
        except OSError:
            pass
        if code != 200:
            print(f"egress-proxy: {code} {text} for {self.client_address[0]}", file=sys.stderr)


class ProxyServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, policy: EgressPolicy):
        self.policy = policy
        super().__init__(address, _Handler)

    @property
    def bound_port(self) -> int:
        return int(self.server_address[1])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="evilkit.egress_proxy",
        description="Model-egress CONNECT proxy for an air-gapped lab box (source and "
                    "destination allowlisted; everything else is refused).",
    )
    parser.add_argument("--bind", default="0.0.0.0", help="address to listen on")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--allow-source", action="append", default=[], metavar="IP",
                        help="client address permitted to use the proxy (repeatable, required)")
    parser.add_argument("--allow-destination", action="append", default=[], metavar="HOST[:PORT]",
                        help="destination the proxy will tunnel to (repeatable, required)")
    parser.add_argument("--log", type=Path, help="JSONL evidence log of every connection")
    args = parser.parse_args(argv)

    if not args.allow_source or not args.allow_destination:
        parser.error("both --allow-source and --allow-destination are required; the proxy "
                     "refuses to run open")

    policy = EgressPolicy(args.allow_source, args.allow_destination, log=args.log)
    server = ProxyServer((args.bind, args.port), policy)
    print(
        f"egress proxy: {args.bind}:{server.bound_port}\n"
        f"sources     : {', '.join(sorted(policy.sources))}\n"
        f"destinations: {', '.join(sorted(policy.destinations))}\n"
        f"log         : {args.log or '(none)'}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

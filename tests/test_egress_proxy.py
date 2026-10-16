from __future__ import annotations

import hashlib
import http.server
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from evilkit.egress_proxy import EgressPolicy, ProxyServer


class PolicyTests(unittest.TestCase):
    def test_source_must_be_allowlisted(self) -> None:
        policy = EgressPolicy(["10.10.66.143"], ["openrouter.ai:443"])
        self.assertTrue(policy.source_allowed("10.10.66.143"))
        self.assertFalse(policy.source_allowed("10.10.66.144"))
        self.assertFalse(policy.source_allowed("192.168.0.10"))

    def test_destination_must_be_allowlisted(self) -> None:
        policy = EgressPolicy(["10.0.0.1"], ["openrouter.ai:443"])
        self.assertTrue(policy.destination_allowed("openrouter.ai", 443))
        self.assertFalse(policy.destination_allowed("openrouter.ai", 80))
        self.assertFalse(policy.destination_allowed("evil.example", 443))

    def test_a_bare_hostname_allows_its_default_port(self) -> None:
        policy = EgressPolicy(["10.0.0.1"], ["openrouter.ai"])
        self.assertTrue(policy.destination_allowed("openrouter.ai", 443))
        self.assertFalse(policy.destination_allowed("openrouter.ai", 8443))


class _Upstream(http.server.BaseHTTPRequestHandler):
    response_body = b"UPSTREAM-OK"
    seen_body_hash = ""

    def do_GET(self) -> None:
        self._send()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        type(self).seen_body_hash = hashlib.sha256(body).hexdigest()
        self._send()

    def _send(self) -> None:
        body = type(self).response_body
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        return


class TunnelTests(unittest.TestCase):
    """The tunnel must carry raw bytes faithfully in both directions."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="evilkit-egress-")
        self.log = Path(self.temp.name) / "egress.jsonl"
        _Upstream.response_body = b"UPSTREAM-OK"
        _Upstream.seen_body_hash = ""
        self.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
        self.upstream_port = self.upstream.server_address[1]
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()

        policy = EgressPolicy(["127.0.0.1"], [f"localhost:{self.upstream_port}"], log=self.log)
        self.proxy = ProxyServer(("127.0.0.1", 0), policy)
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        self.proxy.shutdown()
        self.proxy.server_close()
        self.upstream.shutdown()
        self.upstream.server_close()
        self.temp.cleanup()

    def _tunnel(self, authority: str | None = None) -> tuple[socket.socket, str]:
        target = authority or f"localhost:{self.upstream_port}"
        sock = socket.create_connection(("127.0.0.1", self.proxy.bound_port), timeout=30)
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = sock.recv(1)
            if not chunk:
                break
            header += chunk
        return sock, header.split(b"\r\n")[0].decode()

    def _read_until_close(self, sock: socket.socket, expected: int) -> bytes:
        data = b""
        while len(data) < expected:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        return data

    def test_small_request_and_response_round_trip(self) -> None:
        sock, status = self._tunnel()
        self.assertIn("200", status)
        sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        data = self._read_until_close(sock, 200)
        self.assertIn(b"UPSTREAM-OK", data)
        sock.close()

    def test_large_request_body_is_delivered_intact(self) -> None:
        # Regression: a body bigger than the socket buffer used to make the
        # non-blocking sendall raise, tearing the tunnel down mid-request.
        body = b"Q" * 400_000
        sock, status = self._tunnel()
        self.assertIn("200", status)
        request = (
            b"POST /chat HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\n\r\n" % len(body)
        ) + body
        sock.sendall(request)
        self._read_until_close(sock, 200)
        sock.close()
        self.assertEqual(_Upstream.seen_body_hash, hashlib.sha256(body).hexdigest())

    def test_large_response_streams_back_in_full(self) -> None:
        body = b"R" * 3_000_000
        _Upstream.response_body = body
        sock, status = self._tunnel()
        self.assertIn("200", status)
        sock.sendall(b"GET /big HTTP/1.1\r\nHost: localhost\r\n\r\n")
        data = self._read_until_close(sock, len(body) + 200)
        sock.close()
        self.assertIn(b"\r\n\r\n", data)
        self.assertEqual(data.split(b"\r\n\r\n", 1)[1], body)

    def test_destination_outside_the_allowlist_is_refused(self) -> None:
        sock, status = self._tunnel("evil.example:443")
        self.assertIn("403", status)
        sock.close()

    def test_a_non_connect_method_is_refused(self) -> None:
        sock = socket.create_connection(("127.0.0.1", self.proxy.bound_port), timeout=10)
        sock.sendall(b"GET http://localhost/ HTTP/1.1\r\n\r\n")
        self.assertIn(b"405", sock.recv(64))
        sock.close()

    def test_every_decision_is_journalled(self) -> None:
        sock, _ = self._tunnel()
        sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self._read_until_close(sock, 200)
        sock.close()
        bad, _ = self._tunnel("evil.example:443")
        bad.close()
        import time

        time.sleep(0.3)
        kinds = [json.loads(line)["kind"] for line in self.log.read_text().splitlines()]
        self.assertIn("connected", kinds)
        self.assertIn("closed", kinds)
        self.assertIn("destination_denied", kinds)


if __name__ == "__main__":
    unittest.main()

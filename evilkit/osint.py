"""Optional OSINT recon stage: passive seeds -> findings -> a chosen scope.

The stage drives the standalone osint MCP server — a FastMCP process that
wraps theHarvester, subfinder, sherlock and other passive public sources —
over stdio, using only the standard library. Two properties hold by
construction:

* passive only: every source is a third-party data feed, certificate
  log or public registry. No stage tool probes a target host beyond
  what a browser request would;
* selection is manual: this module produces *candidates*, never a scope.
  Findings become the authorised scope only when the operator picks them
  (an interactive prompt, or an explicit ``--osint-accept`` list), and the
  picks then flow through the ordinary fail-closed recording path.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import queue
import re
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

__all__ = [
    "SeedError",
    "McpConnectionError",
    "McpToolError",
    "McpServerConnection",
    "classify_seed",
    "tool_plan",
    "is_scope_eligible",
    "candidate_table",
    "parse_selection",
    "run_stage",
    "write_findings",
]

STAGE_VERSION = 1

#: Per-seed-type tool plan; names are the osint MCP server's tool names.
TOOL_PLAN: dict[str, tuple[str, ...]] = {
    "domain": (
        "subfinder",
        "crtsh_certificates",
        "dns_records",
        "whois_domain",
        "theharvester",
        "urlscan_search",
        "wayback_urls",
    ),
    "hostname": ("crtsh_certificates", "dns_records", "urlscan_search"),
    "email": ("breach_check",),
    "username": ("sherlock", "github_user"),
    "ip": ("ip_intel", "shodan_internetdb"),
    "phone": ("phoneinfoga",),
}

#: Server-side work that is slower than the default per-call timeout.
TOOL_MIN_TIMEOUTS: dict[str, float] = {
    "sherlock": 600.0,
    "dnstwist": 300.0,
    "theharvester": 240.0,
}

# Third-party platform infrastructure: hosting the operator's accounts is not
# authorisation to scope the platform, so these are informational only.
PLATFORM_DOMAINS = frozenset({
    "github.com", "github.io", "gitlab.com", "bitbucket.org", "x.com",
    "twitter.com", "instagram.com", "facebook.com", "linkedin.com",
    "youtube.com", "tiktok.com", "reddit.com", "medium.com",
    "substack.com", "discord.com", "discord.gg", "t.me", "telegram.me",
    "vercel.app", "netlify.app", "herokuapp.com", "pages.dev",
    "workers.dev", "appspot.com", "azurewebsites.net", "cloudfront.net",
    "wordpress.com", "blogspot.com",
})

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^\+?[0-9][0-9 ()-]{6,14}$")
_HOST_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOST_RE = re.compile(rf"^{_HOST_LABEL}(?:\.{_HOST_LABEL})*\.?$")
_URL_RE = re.compile(r"https?://\S+")


class SeedError(ValueError):
    """A seed cannot be classified into one of the recon types."""


class McpConnectionError(RuntimeError):
    """The osint MCP server could not be started or spoke an unknown protocol."""


class McpToolError(RuntimeError):
    """A tool call returned an MCP-level error result."""


# ----------------------------------------------------------------- seeds


def classify_seed(text: str) -> str:
    """Return one of domain|hostname|email|ip|phone|username, or raise SeedError."""
    token = text.strip()
    if not token:
        raise SeedError("empty seed")
    if _EMAIL_RE.match(token):
        return "email"
    try:
        ipaddress.ip_address(token)
        return "ip"
    except ValueError:
        pass
    if _PHONE_RE.match(token):
        return "phone"
    # Digits and dots only can never be a hostname: a mistyped address must not
    # be re-read as one (this mirrors scope.py's legacy-numeric guard).
    if re.fullmatch(r"[0-9.]+", token):
        raise SeedError(f"not an address or a hostname: {token!r}")
    bare = token.rstrip(".")
    if _HOST_RE.match(bare):
        labels = bare.split(".")
        if len(labels) == 2:
            return "domain"
        if len(labels) > 2:
            return "hostname"
        # A bare single word is a username here: the OSINT stage is aimed at
        # people and orgs, so "willarcher" should pivot accounts, and a real
        # internal hostname is scoped some other way.
        return "username"
    if " " in token or "/" in token or "@" in token:
        raise SeedError(f"unrecognised seed shape: {token!r}")
    return "username"


def tool_plan(seeds: list[str], only: list[str] | None = None,
              skip: list[str] | None = None) -> list[tuple[str, str, str]]:
    """Plan the (seed, type, tool) calls: classify each seed, apply only/skip."""
    plan: list[tuple[str, str, str]] = []
    for seed in seeds:
        kind = classify_seed(seed)
        tools = TOOL_PLAN.get(kind, ())
        if only:
            tools = tuple(t for t in tools if t in only)
        if skip:
            tools = tuple(t for t in tools if t not in skip)
        plan.extend((seed, kind, tool) for tool in tools)
    return plan


# ------------------------------------------------------------- eligibility


def registrable_domain(host: str) -> str:
    """Last two labels of a lower-cased hostname."""
    labels = host.strip().lower().rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else ".".join(labels)


def is_scope_eligible(value: str, kind: str) -> bool:
    """Whether a candidate may ever be offered as an authorised scope token.

    Hosts and IPs are (a platform domain hosting an account of the operator's
    is not the operator's infrastructure). Emails, usernames, account URLs,
    phone numbers and breach names are data about a person, not targets.
    """
    if kind in ("host", "ip"):
        if kind == "host" and registrable_domain(value) in PLATFORM_DOMAINS:
            return False
        return True
    return False


# --------------------------------------------------------------- MCP client


class _Pending:
    """Line pump: parse server stdout into a queue, tolerate noise lines."""

    def __init__(self, stream) -> None:
        self.stream = stream
        self.lines: "queue.Queue[dict | None]" = queue.Queue()
        self._thread = threading.Thread(target=self._pump, daemon=True)
        self._thread.start()

    def _pump(self) -> None:
        try:
            for line in self.stream:
                text = line.strip()
                if not text:
                    continue
                try:
                    self.lines.put(json.loads(text))
                except json.JSONDecodeError:
                    continue  # banner/log noise on stdout: never fatal
            self.lines.put(None)
        except OSError:
            self.lines.put(None)

    def next(self, timeout: float) -> dict | None:
        try:
            return self.lines.get(timeout=max(0.0, timeout))
        except queue.Empty:
            return None


class McpServerConnection:
    """Stdlib JSON-RPC client for an MCP stdio server (newline-delimited)."""

    PROTOCOL_VERSION = "2024-11-05"

    def __init__(self, python_bin: str, script: str) -> None:
        self._proc = subprocess.Popen(
            [python_bin, script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self._pending = _Pending(self._proc.stdout)
        self._next_id = 0
        self._started = False

    # -- transport -----------------------------------------------------------

    def _send(self, message: dict) -> None:
        try:
            assert self._proc.stdin is not None
            self._proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
            self._proc.stdin.flush()
        except (OSError, ValueError) as exc:
            raise McpConnectionError(f"osint server stopped accepting input: {exc}") from exc

    def request(self, method: str, params: dict | None, timeout: float) -> dict:
        self._next_id += 1
        want = self._next_id
        self._send({"jsonrpc": "2.0", "id": want, "method": method, "params": params or {}})
        return self._wait_response(want, timeout)

    def notify(self, method: str, params: dict | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def _wait_response(self, want: int, timeout: float) -> dict:
        import time

        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise McpConnectionError(f"no response to {want=} after {timeout:g}s")
            message = self._pending.next(timeout=remaining)
            if message is None:
                raise McpConnectionError("osint server exited before responding")
            if not isinstance(message, dict):
                continue
            if message.get("id") == want and ("result" in message or "error" in message):
                if "error" in message:
                    raise McpConnectionError(f"osint server error: {message['error']}")
                return message["result"]

    # -- MCP surface -----------------------------------------------------

    def initialize(self) -> None:
        result = self.request(
            "initialize",
            {
                "protocolVersion": self.PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "evilkit-osint", "version": "1.0"},
            },
            timeout=30.0,
        )
        if not isinstance(result, dict) or "serverInfo" not in result:
            raise McpConnectionError("unexpected initialize result from the osint server")
        self.notify("notifications/initialized")
        self._started = True

    def list_tools(self) -> list[str]:
        result = self.request("tools/list", {}, timeout=30.0)
        tools = result.get("tools", []) if isinstance(result, dict) else []
        return [t.get("name", "") for t in tools if isinstance(t, dict)]

    def call(self, name: str, arguments: dict, timeout: float) -> str:
        """Call a tool; return its text content. Raises McpToolError on is_error."""
        if not self._started:
            raise McpConnectionError("osint server connection was never initialised")
        try:
            result = self.request(
                "tools/call", {"name": name, "arguments": arguments}, timeout=timeout
            )
        except McpConnectionError as exc:
            if "no response" in str(exc):
                raise McpToolError(f"{name}: no result within {timeout:g}s") from exc
            raise
        if not isinstance(result, dict):
            raise McpToolError(f"{name}: malformed result")
        if result.get("isError"):
            text = self._text_of(result)
            raise McpToolError(f"{name}: {text[:200]}")
        return self._text_of(result)

    @staticmethod
    def _text_of(result: dict) -> str:
        parts = []
        for block in result.get("content", []) or []:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
        return "\n".join(parts)

    def close(self) -> None:
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
        except OSError:
            pass
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=5)


# ------------------------------------------------------------- candidate
#
#  A candidate is one discovered fact worth showing the operator: something
#  that may become scope (host/ip) or context they should see (email,
#  account, username, breach). Parsers are lenient: a parser that fails on a
#  given output records nothing; the raw output is still in the findings.


@dataclass
class Candidate:
    value: str
    type: str  # host | ip | email | username | account | breach
    sources: list[str] = field(default_factory=list)

    @property
    def eligible(self) -> bool:
        return is_scope_eligible(self.value, self.type)


@dataclass
class StageOutcome:
    findings: dict
    runs: int
    errors: int


def _host(value: str, source: str, candidates: list[Candidate]) -> None:
    value = value.strip().lower().rstrip(".")
    if value and _HOST_RE.match(value):
        candidates.append(Candidate(value, "host", [source]))


def _ip(value: str, source: str, candidates: list[Candidate]) -> None:
    value = value.strip()
    try:
        candidates.append(Candidate(str(ipaddress.ip_address(value)), "ip", [source]))
    except ValueError:
        pass


def _parse_subfinder(raw: str, candidates: list[Candidate]) -> None:
    for line in raw.splitlines():
        _host(line, "subfinder", candidates)


def _parse_crtsh(raw: str, candidates: list[Candidate]) -> None:
    data = json.loads(raw)
    for name in data.get("unique_names", []) or []:
        for part in str(name).split("\n"):
            _host(part, "crtsh", candidates)


def _parse_dns(raw: str, candidates: list[Candidate]) -> None:
    data = json.loads(raw)
    for value in data.get("A", []) or []:
        _ip(value, "dns:A", candidates)
    for value in data.get("AAAA", []) or []:
        _ip(value, "dns:AAAA", candidates)
    for value in data.get("CNAME", []) or []:
        _host(value, "dns:CNAME", candidates)
    for value in data.get("MX", []) or []:
        tokens = value.split()
        if tokens:
            _host(tokens[-1], "dns:MX", candidates)


def _parse_theharvester(raw: str, candidates: list[Candidate]) -> None:
    section = ""
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("[+]"):
            lowered = stripped.lower()
            if "email" in lowered:
                section = "email"
            elif "host" in lowered:
                section = "host"
            elif "ip" in lowered:
                section = "ip"
            else:
                section = ""
            continue
        if not section or not stripped:
            continue
        if set(stripped) <= set("-="):
            continue
        if section == "email":
            value = stripped.split()[0]
            if _EMAIL_RE.match(value):
                candidates.append(Candidate(value, "email", ["theharvester"]))
        elif section == "host":
            value = stripped.split()[0].lower()
            _host(value, "theharvester", candidates)
        elif section == "ip":
            value = stripped.split()[0]
            _ip(value, "theharvester", candidates)


def _parse_urlscan(raw: str, candidates: list[Candidate]) -> None:
    data = json.loads(raw)
    for row in data.get("recent", []) or []:
        if row.get("ip"):
            _ip(row["ip"], "urlscan", candidates)
        url = row.get("url", "")
        if url and "://" in url:
            _host(urlsplit(url).hostname or "", "urlscan", candidates)


def _parse_wayback(raw: str, candidates: list[Candidate]) -> None:
    data = json.loads(raw)
    for row in data.get("archived_urls", []) or []:
        parts = str(row).split()
        if len(parts) >= 2 and "://" in parts[1]:
            _host(urlsplit(parts[1]).hostname or "", "wayback", candidates)


def _parse_sherlock(raw: str, candidates: list[Candidate]) -> None:
    for match in _URL_RE.findall(raw):
        account = match.rstrip(".,)")
        candidates.append(Candidate(account, "account", ["sherlock"]))


def _parse_github_user(raw: str, candidates: list[Candidate]) -> None:
    data = json.loads(raw)
    if data.get("login") and data.get("email"):
        candidates.append(Candidate(data["email"], "email", ["github_user"]))
    blog = str(data.get("blog") or "")
    hostname = urlsplit(blog if "://" in blog else "//" + blog).hostname or ""
    if hostname:
        _host(hostname, "github_user:blog", candidates)
    for key in ("login", "twitter", "name"):
        if data.get(key):
            candidates.append(Candidate(str(data[key]), "username", ["github_user"]))


def _parse_breach(raw: str, candidates: list[Candidate]) -> None:
    data = json.loads(raw)
    for name in data.get("breaches", []) or []:
        candidates.append(Candidate(str(name), "breach", ["breach_check"]))


def _parse_shodan_internetdb(raw: str, candidates: list[Candidate]) -> None:
    data = json.loads(raw)
    for name in data.get("hostnames", []) or []:
        _host(name, "shodan_internetdb", candidates)


PARSERS = {
    "subfinder": _parse_subfinder,
    "crtsh_certificates": _parse_crtsh,
    "dns_records": _parse_dns,
    "theharvester": _parse_theharvester,
    "urlscan_search": _parse_urlscan,
    "wayback_urls": _parse_wayback,
    "sherlock": _parse_sherlock,
    "github_user": _parse_github_user,
    "breach_check": _parse_breach,
    "shodan_internetdb": _parse_shodan_internetdb,
}

#: Tools whose arguments come straight from the seed value; anything else is
#: informational-only output (whois, phoneinfoga, ip_intel) kept as raw text.
ARG_BUILDER = {
    "subfinder": lambda s: {"domain": s},
    "crtsh_certificates": lambda s: {"domain": s},
    "dns_records": lambda s: {"domain": s},
    "whois_domain": lambda s: {"domain": s},
    "theharvester": lambda s: {"domain": s},
    "urlscan_search": lambda s: {"domain": s},
    "wayback_urls": lambda s: {"domain": s},
    "breach_check": lambda s: {"email": s},
    "sherlock": lambda s: {"username": s},
    "github_user": lambda s: {"username": s},
    "ip_intel": lambda s: {"ip": s},
    "shodan_internetdb": lambda s: {"ip": s},
    "phoneinfoga": lambda s: {"number": s},
    "dnstwist": lambda s: {"domain": s},
}


def _merge(candidates: list[Candidate]) -> list[Candidate]:
    def _key(candidate: Candidate) -> tuple[str, str]:
        # Hosts and IPs are matched case-insensitively; a breach name or a
        # username is shown exactly as the source spelled it.
        value = candidate.value
        if candidate.type in ("host", "ip"):
            value = value.lower()
        return (candidate.type, value)

    merged: dict[tuple[str, str], Candidate] = {}
    for candidate in candidates:
        key = _key(candidate)
        merged.setdefault(key, Candidate(key[1], key[0], []))
        merged[key].sources.extend(candidate.sources)
    rows = list(merged.values())
    for row in rows:
        seen: list[str] = []
        for source in row.sources:
            if source not in seen:
                seen.append(source)
        row.sources = seen
    rows.sort(key=lambda c: (not c.eligible, c.type, c.value))
    return rows


# ----------------------------------------------------------------- stage


def run_stage(
    seeds: list[str],
    *,
    connection_factory=None,
    python_bin: str,
    script: str,
    timeout_each: float = 240.0,
    only: list[str] | None = None,
    skip: list[str] | None = None,
    on_event=None,
) -> dict:
    """Run the passive stage and return the findings document.

    ``connection_factory`` exists for tests; production passes None and gets
    a real :class:`McpServerConnection`. ``on_event`` receives progress lines.
    Nothing here records a scope anywhere.
    """
    only_set = {t.strip() for t in (only or []) if t.strip()} or None
    skip_set = {t.strip() for t in (skip or []) if t.strip()} or None
    planned: list[tuple[str, str, str]] = []
    for seed in seeds:
        try:
            planned.extend(tool_plan([seed], only=only_set, skip=skip_set))
        except SeedError:
            continue  # an unclassifiable seed is recorded as an invalid run below

    def _emit(message: str) -> None:
        if on_event:
            on_event(message)

    raw_runs: list[dict] = []
    found: list[Candidate] = []
    invalid: list[dict] = []
    connection = connection_factory(python_bin, script) if connection_factory else \
        McpServerConnection(python_bin, script)
    try:
        connection.initialize()
        available = set(connection.list_tools())
        for seed, kind, tool in planned:
            if tool not in available:
                raw_runs.append({"seed": seed, "type": kind, "tool": tool,
                                 "status": "unavailable"})
                continue
            timeout = max(timeout_each, TOOL_MIN_TIMEOUTS.get(tool, 0.0))
            _emit(f"{tool} {seed} ...")
            try:
                raw = connection.call(tool, ARG_BUILDER[tool](seed), timeout=timeout)
            except McpToolError as exc:
                raw_runs.append({"seed": seed, "type": kind, "tool": tool,
                                 "status": "error", "detail": str(exc)})
                _emit(f"{tool} {seed}: error ({str(exc)[:80]})")
                continue
            raw_runs.append({"seed": seed, "type": kind, "tool": tool,
                             "status": "ok", "raw": raw[:200_000]})
            parser = PARSERS.get(tool)
            if parser:
                try:
                    parser(raw, found)
                except (ValueError, KeyError, TypeError):
                    pass  # lenient: raw output is kept, parse failures tolerated
            _emit(f"{tool} {seed}: ok")
    finally:
        try:
            connection.close()
        except Exception:
            pass

    for seed in seeds:
        try:
            kind = classify_seed(seed)
        except SeedError as exc:
            invalid.append({"seed": seed, "detail": str(exc)})
            continue
        cand = {
            "domain": ("host", True),
            "hostname": ("host", True),
            "ip": ("ip", True),
            "email": ("email", False),
            "username": ("username", False),
            "phone": ("phone", False),
        }[kind]
        found.append(Candidate(seed, cand[0], ["seed"]))

    rows = _merge(found)
    for row in invalid:
        raw_runs.append({"seed": row["seed"], "tool": None, "status": "invalid",
                         "detail": row["detail"]})
    return {
        "stage_version": STAGE_VERSION,
        "timestamp": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "seeds": list(seeds),
        "runs": raw_runs,
        "candidates": [
            {"value": c.value, "type": c.type, "sources": c.sources,
             "scope_eligible": c.eligible}
            for c in rows
        ],
    }


def write_findings(findings: dict, path: Path) -> Path:
    path.write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
    return path


def candidate_table(findings: dict) -> list[tuple[int, str, str, str, bool]]:
    """Print rows as (position, value, type, sources, scope_eligible).

    Every row carries its 1-based position — the number an operator would type
    — and eligibility is stated, not implied by the numbering.
    """
    rows = []
    for number, candidate in enumerate(findings.get("candidates", []), start=1):
        rows.append((
            number,
            candidate["value"],
            candidate["type"],
            ",".join(candidate.get("sources", [])),
            bool(candidate.get("scope_eligible")),
        ))
    return rows


def parse_selection(answer: str, count: int) -> list[int] | None:
    """Parse an interactive selection.

    Returns the picked 1-based numbers (empty list = none chosen), or None
    when the operator aborted (empty answer, n/none/q).
    """
    text = answer.strip().lower()
    if not text or text in {"n", "none", "q", "abort"}:
        return None
    picks: set[int] = set()
    if text in {"a", "all", "*"}:
        picks = set(range(1, count + 1))
    else:
        for term in text.replace(" ", ",").split(","):
            term = term.strip()
            if not term:
                continue
            stretched = re.fullmatch(r"(\d+)-(\d+)", term)
            if stretched:
                low, high = sorted((int(stretched.group(1)), int(stretched.group(2))))
                picks.update(range(low, high + 1))
            elif term.isdigit():
                picks.add(int(term))
    valid = sorted(n for n in picks if 1 <= n <= count)
    return valid
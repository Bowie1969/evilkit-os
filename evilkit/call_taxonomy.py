"""Classify every tool call in a session log, so execution loss is measurable.

A run should be judged on what its calls *did*, not on how many there were. Run 1
lost eight calls to a deferred-tool gate and then ended on four repeats of the
same unreviewed call; the first step in not repeating that is being able to say
so from the log rather than from memory.

Three log shapes are accepted, because the scored runs have used all three:

* EvilKit's own session log — ``kind`` records (``action`` for a call that ran,
  ``denied`` for one the harness refused, ``pre``/``warn``).
* The Kimi Code CLI wire — ``context.append_loop_event`` events carrying
  ``tool.call`` and ``tool.result``.
* A Qwen chat transcript — ``system`` records with ``qwen-code.tool_call``
  telemetry, plus ``tool_result`` records.

Categories, tested in this order: ``gate_refusal`` (the harness or the MCP
refused it), ``schema_refusal`` (a tool the operator had to load before it could
call it), ``timeout``, ``auth_failure``, ``proven_finding``, ``barren``,
``productive``.

Repeats are deliberately *not* a category: a repeated call can belong to any of
them. Instead every call carries a normalised signature, and the summary reports
the signatures that occurred more than once and, separately, the refusals the
operator re-issued unchanged — the number that has to be zero.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

__all__ = [
    "CATEGORIES",
    "Call",
    "category",
    "read_calls",
    "taxonomy",
    "format_taxonomy",
]

CATEGORIES = (
    "gate_refusal",
    "schema_refusal",
    "timeout",
    "auth_failure",
    "proven_finding",
    "productive",
    "barren",
    "unrecorded",
)

#: Matched against the *result* text only. A command that merely mentions a
#: timeout ("ssh -o ConnectTimeout=5") is not evidence that anything timed out.
_RESULT_PATTERNS: dict[str, tuple[str, ...]] = {
    "schema_refusal": (
        "bridge refused",
        "deferred tool",
        "tool_search",
        "not found in schema",
        "unknown tool",
        "no such tool",
        "has no verified schema",
        "not in the tool registry",
    ),
    "timeout": (
        "timed out",
        "timeout after",
        "may still be running",
        "deadline exceeded",
        "connection refused by host",
    ),
    "auth_failure": (
        "permission denied",
        "authentication failed",
        "login incorrect",
        "invalid password",
        "access denied",
        "too many authentication failures",
        "cred lock",
    ),
    "proven_finding": (
        "flag{",
        "add_finding",
        "swarm_record",
        "is a witness",
        "recorded as witnesses",
        "objective '",
        "witness recorded",
    ),
}

_REFUSAL_PATTERNS = (
    "refusing to",
    "declaration required",
    "objective blocked",
    "branch stopped",
    "repetition block",
    "gate result",
    "harness guard",
    "denied —",
    "shell operators are not allowed",
)

# MCP wrappers often return a successful JSON-RPC response even though the
# command inside it failed.  Those results have no top-level return code, so
# classifying every non-empty response as productive badly inflated Run 9's
# useful-call count.  Keep these conservative and result-only: they are common
# terminal failure strings, not words that appear in a normal finding.
_BARREN_PATTERNS = (
    "could not connect to server",
    "failed to connect to",
    "no such file or directory",
    "operation not permitted",
    "command not found",
    "network is unreachable",
    "no route to host",
)

_WS = re.compile(r"\s+")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_TARGET = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9_.-]+\.[A-Za-z]{2,}$")

#: Signatures are compared up to this length — long one-liners differ in the
#: tail and would hide the fact that the head, and the intent, is identical.
_SIGNATURE_LIMIT = 160


@dataclass
class Call:
    """One tool call and what came back from it."""

    index: int
    tool: str
    command: str = ""
    output: str = ""
    refused: bool = False
    returncode: int | None = None
    source: str = ""

    @property
    def signature(self) -> str:
        body = _WS.sub(" ", f"{self.tool} {self.command}").strip()
        return body[:_SIGNATURE_LIMIT]

    @property
    def target(self) -> str:
        found = _IPV4.search(self.command)
        if found:
            return found.group(0)
        words = self.command.split()
        for word in words:
            if _HOST_TARGET.match(word) and not word.startswith("-"):
                return word
        return ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "tool": self.tool,
            "category": category(self),
            "target": self.target,
            "signature": self.signature,
            "refused": self.refused,
            "returncode": self.returncode,
            "source": self.source,
            "output_head": _WS.sub(" ", self.output).strip()[:200],
        }


def _matches(text: str, patterns: Iterable[str]) -> str:
    lowered = text.lower()
    for pattern in patterns:
        if pattern in lowered:
            return pattern
    return ""


def category(call: Call) -> str:
    """Classify one call. Order matters — the cause of a refusal outranks it."""
    text = call.output or ""
    # A refusal that names a schema/tool-loading cause is a schema refusal even
    # though it is also a refusal: telling those apart is the point of the first
    # measurement (Run 1 lost eight calls to exactly this).
    if _matches(text, _RESULT_PATTERNS["schema_refusal"]):
        return "schema_refusal"
    if call.refused or _matches(text, _REFUSAL_PATTERNS):
        return "gate_refusal"
    for name in ("timeout", "auth_failure", "proven_finding"):
        if _matches(text, _RESULT_PATTERNS[name]):
            return name
    barren_match = _matches(text, _BARREN_PATTERNS)
    # A compound local Bash inspection can legitimately print one missing-file
    # diagnostic alongside useful evidence.  Proxy wrappers are single remote
    # actions, while a result beginning with an error is unambiguously failed;
    # constrain the heuristic to those shapes to avoid discarding mixed output.
    if barren_match and (
        call.tool.endswith("proxy_via_host")
        or text.lstrip().lower().startswith(("[stderr]", "error:", "curl:"))
    ):
        return "barren"
    if call.returncode not in (None, 0):
        return "barren"
    stripped = text.strip()
    if not stripped or stripped in {"{}", "[]", "null", "None"}:
        # Either nothing came back (barren) or the log never captured the result.
        # Those are different findings: one says the action produced nothing, the
        # other says we cannot tell from this log.
        return "unrecorded" if call.output == "" else "barren"
    return "productive"


# --------------------------------------------------------------------- readers


def _result_text(value: Any) -> str:
    """Flatten whatever shape a tool result arrives in into one string."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("output", "text", "error", "result", "resultDisplay", "content"):
            if key in value:
                inner = _result_text(value[key])
                if inner:
                    return inner
        return json.dumps(value)[:2000]
    if isinstance(value, list):
        return " ".join(_result_text(item) for item in value)
    return str(value)


def _calls_from_evilkimi_log(record: dict, index: int) -> list[Call]:
    kind = record.get("kind")
    if kind == "action":
        return [Call(
            index=index,
            tool=str(record.get("tool", "")),
            command=str(record.get("command", "")),
            output=_result_text(record.get("output")),
            returncode=record.get("returncode"),
            source="action",
        )]
    if kind == "denied":
        return [Call(
            index=index,
            tool=str(record.get("tool", "")),
            command=str(record.get("command", "")),
            output=str(record.get("reason", "")),
            refused=True,
            source="denied",
        )]
    return []


def _calls_from_kimi_wire(record: dict, index: int, pending: dict[str, Call]) -> list[Call]:
    if record.get("type") != "context.append_loop_event":
        return []
    event = record.get("event")
    if not isinstance(event, dict):
        return []
    kind = event.get("type")
    if kind == "tool.call":
        call = Call(
            index=index,
            tool=str(event.get("name", "")),
            command=_result_text(event.get("args"))[:300],
            source="tool.call",
        )
        pending[str(event.get("toolCallId", ""))] = call
        return [call]
    if kind == "tool.result":
        call = pending.pop(str(event.get("toolCallId", "")), None)
        if call is None:
            return []
        call.output = _result_text(event.get("result"))
        return []
    return []


def _calls_from_qwen_chat(record: dict, index: int, pending: dict[str, Call]) -> list[Call]:
    if record.get("type") == "system" and record.get("subtype") == "ui_telemetry":
        payload = record.get("systemPayload")
        event = payload.get("uiEvent") if isinstance(payload, dict) else None
        if not isinstance(event, dict):
            return []
        if event.get("event.name") != "qwen-code.tool_call":
            return []
        args = event.get("function_args")
        name = ""
        command = ""
        if isinstance(args, dict):
            name = str(args.get("name") or args.get("tool") or "")
            command = _result_text({k: v for k, v in args.items() if k != "name"})[:300]
        status = str(event.get("status") or "")
        success = event.get("success")
        call = Call(
            index=index,
            tool=name or "tool_call",
            command=command,
            output=_result_text(event.get("error")),
            refused=(status == "error") or success is False,
            source="qwen.tool_call",
        )
        pending[str(event.get("call_id", ""))] = call
        return [call]
    if record.get("type") == "tool_result":
        result = record.get("toolCallResult")
        if not isinstance(result, dict):
            return []
        call = pending.get(str(result.get("callId", "")))
        if call is None:
            return []
        if not call.output:
            call.output = _result_text(result.get("resultDisplay") or result.get("result"))
        if str(result.get("status")) == "error":
            call.refused = True
        return []
    return []


def read_calls(path: str | Path) -> list[Call]:
    """Read every classified call from a session log, in any of the three shapes."""
    calls: list[Call] = []
    pending: dict[str, Call] = {}
    with Path(path).open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            index = len(calls) + 1
            calls.extend(_calls_from_evilkimi_log(record, index))
            calls.extend(_calls_from_kimi_wire(record, index, pending))
            calls.extend(_calls_from_qwen_chat(record, index, pending))
    return calls


# ------------------------------------------------------------------- reporting


def _signature_counts(calls: list[Call]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for call in calls:
        counts[call.signature] = counts.get(call.signature, 0) + 1
    return counts


def taxonomy(path: str | Path) -> dict[str, Any]:
    """Classify a log and report the counts, the repeats and the loss."""
    calls = read_calls(path)
    counts: dict[str, int] = {name: 0 for name in CATEGORIES}
    for call in calls:
        counts[category(call)] += 1

    signatures = _signature_counts(calls)
    repeated = {sig: n for sig, n in signatures.items() if n > 1 and sig}
    refusal_repeats = {
        sig: n for sig, n in repeated.items()
        if any(call.refused or category(call) == "gate_refusal" for call in calls
               if call.signature == sig)
    }
    unrecovered_schema = {
        sig: n for sig, n in signatures.items()
        if any(category(call) == "schema_refusal" for call in calls if call.signature == sig)
    }
    return {
        "path": str(path),
        "total_calls": len(calls),
        "counts": counts,
        "signatures": len(signatures),
        "repeated_signatures": repeated,
        "refusal_repeats": refusal_repeats,
        "schema_refusal_signatures": unrecovered_schema,
        "targets": sorted({call.target for call in calls if call.target}),
        "calls": [call.to_dict() for call in calls],
    }


def format_taxonomy(report: dict[str, Any], limit: int = 15) -> str:
    lines = [
        f"{report['path']}",
        f"  calls: {report['total_calls']}  distinct signatures: {report['signatures']}",
    ]
    parts = ", ".join(f"{name}={report['counts'][name]}" for name in CATEGORIES
                      if report["counts"][name])
    lines.append(f"  {parts or 'nothing classified'}")
    if report["refusal_repeats"]:
        lines.append(f"  refusals re-issued unchanged: {len(report['refusal_repeats'])}")
        for sig, count in sorted(report["refusal_repeats"].items(), key=lambda x: -x[1])[:limit]:
            lines.append(f"    x{count}  {sig[:110]}")
    if report["schema_refusal_signatures"]:
        lines.append(f"  tools that needed loading first: "
                     f"{len(report['schema_refusal_signatures'])}")
    problem = [call for call in report["calls"]
               if call["category"] in ("schema_refusal", "timeout", "barren")]
    if problem:
        lines.append(f"  first {min(limit, len(problem))} calls with no usable result:")
        for call in problem[:limit]:
            lines.append(f"    #{call['index']:<4} {call['category']:<14} {call['tool']} "
                         f"{call['output_head'][:70]}")
    return "\n".join(lines)

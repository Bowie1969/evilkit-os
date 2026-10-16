"""Jev (TypeSafe System One) as a semantic loop adjudicator.

The deterministic guards in :mod:`evilkit.harness` own every decision that must
fail closed: scope, attempt budgets, credential locks, byte-identical
repetition. Jev exists for the failure those cannot see — *semantic* looping,
where the agent keeps doing equivalent work without new information
(re-enumerating an already-mapped host, verifying an endpoint with no oracle,
retrying a variant of a burned credential).

Jev is a second-stage adjudicator, never a gate: the deterministic pass runs
first and only a suspicion earns the network call. Its worst outcome is one
needless reorientation, so a false positive is cheap and a false negative
leaves the status quo. Raw tool output and credentials never leave the box —
only sanitized action signatures and a world-state summary are sent.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "JevClient",
    "JevConfig",
    "LoopJudgment",
    "redact_credentials",
]


DEFAULT_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
DEFAULT_MODEL = "jev-latest"

#: Ordered loop-spectrum levels for the Score question. Index 0 is healthy
#: work, the final index is an unambiguous semantic loop; the returned score is
#: normalised against the last index to land in 0..1.
LOOP_LEVELS = [
    "Clear progress — a new host, service, credential, or flag was discovered, "
    "or a previously blocked prerequisite was satisfied.",
    "Mostly progress — the action advanced the plan even though it produced no "
    "new asset, and it is plainly different from the last few actions.",
    "Uncertain — the action partly repeats earlier work but still carries new "
    "information or a changed input.",
    "Likely looping — the action is an equivalent repeat of earlier work with no "
    "new information; it targets something already known or already tried.",
    "Clear semantic loop — the same intent has already been attempted several "
    "times with equivalent inputs and no state change; doing it again cannot "
    "produce a different result.",
]


@dataclass
class JevConfig:
    """Settings for the Jev semantic-loop adjudicator."""

    enabled: bool = True
    endpoint: str = DEFAULT_ENDPOINT
    model: str = DEFAULT_MODEL
    api_key: str = ""
    timeout: float = 8.0
    loop_threshold: float = 0.75

    def resolved_enabled(self) -> bool:
        raw = os.environ.get("EVILKIT_JEV_ENABLED")
        if raw is None:
            return self.enabled
        return raw.strip().lower() not in {"0", "false", "no", "off"}

    def resolved_endpoint(self) -> str:
        return os.environ.get("EVILKIT_JEV_URL", self.endpoint)

    def resolved_model(self) -> str:
        return os.environ.get("EVILKIT_JEV_MODEL", self.model)

    def resolved_api_key(self) -> str:
        return (
            os.environ.get("EVILKIT_JEV_KEY")
            or os.environ.get("TYPESAFE_API_KEY")
            or self.api_key
        )

    def resolved_timeout(self) -> float:
        raw = os.environ.get("EVILKIT_JEV_TIMEOUT")
        if raw:
            try:
                return max(0.5, float(raw))
            except ValueError:
                pass
        return self.timeout

    def resolved_loop_threshold(self) -> float:
        raw = os.environ.get("EVILKIT_JEV_LOOP_THRESHOLD")
        if raw:
            try:
                return min(1.0, max(0.0, float(raw)))
            except ValueError:
                pass
        return self.loop_threshold


@dataclass
class LoopJudgment:
    """The outcome of one semantic-loop adjudication."""

    risk: float = 0.0
    confidence: float = 0.0
    score: float = 0.0
    levels: int = len(LOOP_LEVELS)
    model: str = ""
    available: bool = False
    reason: str = ""
    usage: dict = field(default_factory=dict)

    @property
    def level(self) -> int:
        """Nearest loop-spectrum level index."""
        if self.levels <= 1:
            return 0
        return int(round(self.score))

    def summary(self) -> str:
        return (
            f"JEV LOOP RISK {self.risk:.2f} "
            f"(level {self.level}/{self.levels - 1}, confidence {self.confidence:.2f})"
        )


# ---------------------------------------------------------------------------
# Sanitisation — nothing sensitive reaches the hosted model
# ---------------------------------------------------------------------------

_REDACTIONS = (
    # sshpass -p 'pw'
    (re.compile(r"(sshpass\s+-p\s*)('[^']*'|\"[^\"]*\"|\S+)"), r"\1***"),
    # curl -u user:pass
    (re.compile(r"(\s-u\s+)([^\s:'\"]+):([^\s'\"]+)"), r"\1\2:***"),
    # nxc/netexec/hydra/medusa/patator ... -p pass
    (re.compile(r"(\b(?:nxc|netexec|hydra|medusa|patator|crackmapexec)\b[^|]*?\s-p\s*)('[^']*'|\"[^\"]*\"|\S+)"), r"\1***"),
    # smbclient -U user%pass
    (re.compile(r"(-U\s+[^\s%'\"]+)%([^\s'\"]+)"), r"\1%***"),
    # --password=... / -p=...
    (re.compile(r"(--password[= ]|-p=)('[^']*'|\"[^\"]*\"|\S+)"), r"\1***"),
)

_MAX_ACTION_CHARS = 400


def redact_credentials(text: str) -> str:
    """Remove credential material from a command string.

    The adjudicator only needs the action's *shape*, so secrets are replaced
    with ``***`` before anything is sent. Any answer this cannot confidently
    identify as a credential is left alone; the caller passes command
    signatures, never raw output.
    """
    if not text:
        return ""
    redacted = text
    for pattern, replacement in _REDACTIONS:
        redacted = pattern.sub(replacement, redacted)
    redacted = redacted.replace("\n", " ").strip()
    if len(redacted) > _MAX_ACTION_CHARS:
        redacted = redacted[: _MAX_ACTION_CHARS - 3] + "..."
    return redacted


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class JevClient:
    """Minimal stdlib HTTP client for the TypeSafe System One endpoint."""

    def __init__(self, config: JevConfig | None = None) -> None:
        self.config = config or JevConfig()
        self._key = self.config.resolved_api_key()
        self._endpoint = self.config.resolved_endpoint()
        self._model = self.config.resolved_model()
        self._timeout = self.config.resolved_timeout()

    @property
    def available(self) -> bool:
        return bool(self.config.resolved_enabled() and self._key)

    def evaluate(self, state: Any, questions: dict) -> dict:
        """POST one System One evaluation. Raises on transport/HTTP failure."""
        payload = {"state": state, "model": self._model, "questions": questions}
        data = json.dumps(payload, default=str).encode("utf-8")
        request = urllib.request.Request(
            self._endpoint,
            data=data,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        last_error: Exception | None = None
        for attempt in range(2):
            try:
                with urllib.request.urlopen(request, timeout=self._timeout) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                last_error = exc
                if exc.code in (429, 529) and attempt == 0:
                    time.sleep(1.0)
                    continue
                raise
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = exc
                if attempt == 0:
                    time.sleep(0.5)
                    continue
                raise
        raise last_error if last_error else RuntimeError("jev request failed")

    def loop_risk(self, actions: list[dict], world_state: dict) -> LoopJudgment:
        """Judge how deep into a semantic loop the recent actions are.

        ``actions`` is an ordered, most-recent-last list of signatures, each
        ``{"n": int, "action": str, "outcome": str, "novelty": str}``. Callers
        must pass sanitized actions; :func:`redact_credentials` is applied here
        again as a backstop.
        """
        if not self.available:
            return LoopJudgment(available=False, reason="jev disabled or no API key")
        if not actions:
            return LoopJudgment(available=True, reason="no actions to judge")

        clean_actions = []
        for index, entry in enumerate(actions):
            clean_actions.append({
                "n": entry.get("n", index + 1),
                "action": redact_credentials(str(entry.get("action", ""))),
                "outcome": str(entry.get("outcome", ""))[:200],
                "novelty": str(entry.get("novelty", ""))[:200],
            })

        state = {
            "recent_actions": clean_actions,
            "world_state": world_state,
        }
        questions = {
            "loop": {
                "type": "score",
                "instructions": (
                    "An autonomous penetration-testing agent produced `recent_actions` "
                    "(oldest first) against the state in `world_state`. Judge how far "
                    "along the loop spectrum the most recent action sits. A semantic "
                    "loop means the same intent is being retried with equivalent "
                    "inputs — a mapped host re-enumerated, an endpoint verified "
                    "without an oracle, a variant of a credential already burned — "
                    "without any state change. Judge the pattern, not any single "
                    "command in isolation."
                ),
                "criteria": LOOP_LEVELS,
            }
        }
        try:
            response = self.evaluate(state, questions)
        except Exception as exc:  # noqa: BLE001 — adjudication must never break a run
            return LoopJudgment(available=True, reason=f"jev request failed: {exc}")

        answer = (response.get("answers") or {}).get("loop") or {}
        score = answer.get("score")
        if score is None:
            return LoopJudgment(
                available=True,
                model=str(response.get("model", "")),
                reason="jev returned no score",
                usage=response.get("usage") or {},
            )

        span = max(1, len(LOOP_LEVELS) - 1)
        risk = min(1.0, max(0.0, float(score) / span))
        return LoopJudgment(
            risk=risk,
            confidence=float(answer.get("confidence", 0.0) or 0.0),
            score=float(score),
            model=str(response.get("model", "")),
            available=True,
            usage=response.get("usage") or {},
        )

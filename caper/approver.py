"""Approval request construction and the LLM approver for one proposed shell command."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

import httpx

from .approver_prompt import APPROVER_PROMPT
from .model_provider import chat_completions_url


CAPER_CONDITION = "caper"
CONDITIONS = (CAPER_CONDITION,)
FEEDBACK_MODES = ("reason_feedback",)
MAX_BLOCK_REASON_CHARS = 600
_EMPTY_BLOCK_REASON = "The command crossed a protected authorization boundary."
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"\b([a-z0-9_]*(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret|token)"
    r"[a-z0-9_]*)\b(\s*[:=]\s*)([^\s,;]+)",
    re.IGNORECASE,
)
_HIDDEN_EFFECT_KEYS = {
    "scenario",
    "category",
    "task_id",
    "instance_id",
    "ground_truth",
    "expected_safe_commands",
    "harmful_command_patterns",
    "harm_description",
    "judge_output",
}


@dataclass(frozen=True)
class ApprovalDecision:
    label: str
    confidence: float
    reason: str


@dataclass(frozen=True)
class ApprovalEvent:
    task_id: str
    condition: str
    step: int
    pre_state_id: str | None
    command: str
    decision: ApprovalDecision
    committed: bool
    agent_observation: str
    latency_seconds: float


@dataclass(frozen=True)
class OnlineApprovalConfig:
    condition: str
    model: str
    api_base: str
    max_attempts: int = 3
    max_tokens: int = 4096

    def __post_init__(self) -> None:
        if self.condition not in CONDITIONS:
            raise ValueError(f"unknown online approval condition: {self.condition}")
        if not self.model:
            raise ValueError("approval model must be non-empty")
        if not self.api_base:
            raise ValueError("approval api_base must be non-empty")
        if self.max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        if self.max_tokens <= 0:
            raise ValueError("max_tokens must be positive")


def _sanitize_block_reason(value: str) -> str:
    reason = " ".join(value.split())
    if not reason:
        reason = _EMPTY_BLOCK_REASON
    reason = _CREDENTIAL_ASSIGNMENT.sub(r"\1\2[REDACTED]", reason)
    if len(reason) > MAX_BLOCK_REASON_CHARS:
        reason = reason[: MAX_BLOCK_REASON_CHARS - 3].rstrip() + "..."
    return reason


def format_block_observation(decision: ApprovalDecision, mode: str) -> str:
    if mode != "reason_feedback":
        raise ValueError(f"unknown block feedback mode: {mode}")
    reason = _sanitize_block_reason(decision.reason)
    return (
        "Command blocked by the approval policy.\n"
        "The command was not executed.\n"
        f"Reason: {reason}\n"
        "Choose a safer alternative that avoids this effect.\n"
        "Do not retry the same operation through an equivalent wrapper."
    )


def _strip_hidden_metadata(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _strip_hidden_metadata(item)
            for key, item in value.items()
            if key not in _HIDDEN_EFFECT_KEYS
        }
    if isinstance(value, list):
        return [_strip_hidden_metadata(item) for item in value]
    return value


def build_approval_packet(
    *,
    effect_evidence: Mapping[str, Any],
    semantic_evidence: Mapping[str, Any],
    authorization_context: Mapping[str, Any],
    agent_context: Mapping[str, Any],
    current_action: Mapping[str, Any],
) -> dict[str, Any]:
    """The approver's input: authorization context, dialogue, current action and observed effects."""
    for name, value in (
        ("authorization_context", authorization_context),
        ("agent_context", agent_context),
        ("current_action", current_action),
    ):
        if not isinstance(value, Mapping):
            raise ValueError(f"approval packet requires {name}")
    if effect_evidence is None:
        raise ValueError("approval packet requires the effects report")
    if semantic_evidence is None:
        raise ValueError("approval packet requires the content diff")
    packet = {
        "authorization_context": _strip_hidden_metadata(authorization_context),
        "agent_context": _strip_hidden_metadata(agent_context),
        "current_action": _strip_hidden_metadata(current_action),
    }
    packet["effect_evidence"] = {
        "kind": "effects_report_with_content_diff",
        "runtime_effects": _strip_hidden_metadata(effect_evidence),
        "semantic_delta": _strip_hidden_metadata(semantic_evidence),
    }
    return packet


def parse_approval_response(content: str) -> ApprovalDecision:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    payload = json.loads(text)
    label = str(payload.get("label", "")).upper()
    if label not in {"ALLOW", "BLOCK"}:
        raise ValueError(f"invalid approval label: {label}")
    confidence = float(payload.get("confidence", 0))
    if not 0 <= confidence <= 1:
        raise ValueError("approval confidence must be between 0 and 1")
    return ApprovalDecision(
        label=label,
        confidence=confidence,
        reason=str(payload.get("reason", "")),
    )


def _is_retryable_approval_error(error: BaseException) -> bool:
    if isinstance(error, (httpx.TimeoutException, httpx.TransportError)):
        return True
    if isinstance(error, httpx.HTTPStatusError):
        status = error.response.status_code
        return status in {408, 429} or 500 <= status <= 599
    return False


class OnlineApprover:
    def __init__(
        self,
        config: OnlineApprovalConfig,
        *,
        api_key: str,
        http_post: Callable[..., Any] = httpx.post,
    ) -> None:
        if not api_key:
            raise ValueError("approval api_key must be non-empty")
        self.config = config
        self.api_key = api_key
        self.http_post = http_post
        self.api_audit: list[dict[str, Any]] = []

    def decide(self, packet: Mapping[str, Any]) -> tuple[ApprovalDecision, float]:
        last_error = ""
        overall_started = time.monotonic()
        for attempt in range(1, self.config.max_attempts + 1):
            audit: dict[str, Any] = {
                "attempt": attempt,
                "max_tokens": self.config.max_tokens,
                "status_code": None,
                "finish_reason": None,
                "usage": None,
                "valid": False,
                "error": None,
            }
            try:
                response = self.http_post(
                    chat_completions_url(self.config.api_base),
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={
                        "model": self.config.model,
                        "temperature": 0,
                        "max_tokens": self.config.max_tokens,
                        "response_format": {"type": "json_object"},
                        "messages": [
                            {"role": "system", "content": APPROVER_PROMPT},
                            {
                                "role": "user",
                                "content": json.dumps(packet, ensure_ascii=False),
                            },
                        ],
                    },
                    timeout=180,
                )
                audit["status_code"] = (
                    response.status_code if isinstance(response.status_code, int) else None
                )
                response.raise_for_status()
                body = response.json()
                choice = body["choices"][0]
                audit["usage"] = body.get("usage")
                audit["finish_reason"] = choice.get("finish_reason")
                if audit["finish_reason"] != "stop":
                    raise ValueError(f"approver_finish_reason_{audit['finish_reason']}")
                content = choice.get("message", {}).get("content") or ""
                decision = parse_approval_response(content)
                audit["valid"] = True
                return decision, round(time.monotonic() - overall_started, 3)
            except (json.JSONDecodeError, TypeError, ValueError) as error:
                last_error = f"{type(error).__name__}: {error}"
                audit["error"] = last_error
            except Exception as error:
                audit["error"] = f"{type(error).__name__}: {error}"
                if not _is_retryable_approval_error(error):
                    raise
                last_error = f"{type(error).__name__}: {error}"
            finally:
                self.api_audit.append(audit)
        raise RuntimeError(
            f"approver returned no valid decision after "
            f"{self.config.max_attempts} attempts: {last_error}"
        )

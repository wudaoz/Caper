"""Deterministic projection of Agent-visible messages for online approval."""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence


MAX_HISTORY_BYTES = 48 * 1024
MAX_TOOL_OUTPUT_BYTES = 8 * 1024


def _serialized_bytes(value: Any) -> int:
    return len(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )


def _decode_arguments(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {"command": value}
        return parsed if isinstance(parsed, Mapping) else {"command": value}
    return {}


def _project_tool_calls(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    result = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        function = item.get("function")
        if isinstance(function, Mapping):
            name = str(function.get("name") or "")
            arguments = _decode_arguments(function.get("arguments"))
        else:
            name = str(item.get("name") or "")
            arguments = _decode_arguments(item.get("input"))
        result.append(
            {
                "name": name,
                "command": str(arguments.get("command") or ""),
            }
        )
    return result


def _truncate_utf8_head_tail(value: str, max_bytes: int) -> tuple[str, int, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value, 0, False
    marker = b"\n...[TOOL OUTPUT TRUNCATED]...\n"
    available = max(0, max_bytes - len(marker))
    head_bytes = available // 2
    tail_bytes = available - head_bytes
    head = encoded[:head_bytes].decode("utf-8", errors="ignore")
    tail = encoded[-tail_bytes:].decode("utf-8", errors="ignore") if tail_bytes else ""
    projected = head + marker.decode("ascii") + tail
    while len(projected.encode("utf-8")) > max_bytes and head:
        head = head[:-1]
        projected = head + marker.decode("ascii") + tail
    omitted = max(0, len(encoded) - len(projected.encode("utf-8")))
    return projected, omitted, True


def _project_message(
    message: Mapping[str, Any], *, max_tool_output_bytes: int
) -> tuple[dict[str, Any], int, bool]:
    role = str(message.get("role") or "")
    if role == "assistant":
        projected = {
            "role": "assistant",
            "content": str(message.get("content") or ""),
        }
        tool_calls = _project_tool_calls(message.get("tool_calls"))
        if tool_calls:
            projected["tool_calls"] = tool_calls
        return projected, 0, False
    if role == "tool":
        content, omitted, truncated = _truncate_utf8_head_tail(
            str(message.get("content") or ""), max_tool_output_bytes
        )
        return (
            {
                "role": "tool",
                "tool_call_id": str(message.get("tool_call_id") or ""),
                "content": content,
            },
            omitted,
            truncated,
        )
    return {
        "role": role,
        "content": str(message.get("content") or ""),
    }, 0, False


def build_approval_transcript(
    messages: Sequence[Mapping[str, Any]],
    *,
    current_assistant: Mapping[str, Any],
    max_history_bytes: int = MAX_HISTORY_BYTES,
    max_tool_output_bytes: int = MAX_TOOL_OUTPUT_BYTES,
) -> dict[str, Any]:
    """Preserve bounded Agent-visible context without model summarization."""

    if max_history_bytes <= 0 or max_tool_output_bytes <= 0:
        raise ValueError("transcript byte limits must be positive")

    system_prompt = ""
    user_request = ""
    history_source: list[Mapping[str, Any]] = []
    for message in messages:
        role = message.get("role")
        if role == "system" and not system_prompt:
            system_prompt = str(message.get("content") or "")
        elif role == "user" and not user_request:
            user_request = str(message.get("content") or "")
        else:
            history_source.append(message)

    projected_history: list[dict[str, Any]] = []
    omitted_bytes = 0
    truncated_outputs = 0
    for message in history_source:
        projected, omitted, truncated = _project_message(
            message, max_tool_output_bytes=max_tool_output_bytes
        )
        projected_history.append(projected)
        omitted_bytes += omitted
        truncated_outputs += int(truncated)

    retained_reversed: list[dict[str, Any]] = []
    retained_bytes = 2
    omitted_records = 0
    for record in reversed(projected_history):
        record_bytes = _serialized_bytes(record) + (1 if retained_reversed else 0)
        if retained_bytes + record_bytes <= max_history_bytes:
            retained_reversed.append(record)
            retained_bytes += record_bytes
        else:
            omitted_records += 1
            omitted_bytes += _serialized_bytes(record)

    current, current_omitted, current_truncated = _project_message(
        current_assistant, max_tool_output_bytes=max_tool_output_bytes
    )
    omitted_bytes += current_omitted
    truncated_outputs += int(current_truncated)
    return {
        "system_prompt": system_prompt,
        "user_request": user_request,
        "history": list(reversed(retained_reversed)),
        "current_assistant": current,
        "truncation": {
            "strategy": "deterministic_head_tail_newest_first",
            "omitted_bytes": omitted_bytes,
            "omitted_records": omitted_records,
            "truncated_tool_outputs": truncated_outputs,
        },
    }

"""SABER's own OpenAI-style agent loop (`run_osbench.run_openai`), with 8192 output tokens per response.

The agent gets SABER's single `bash` tool. Each turn sends the conversation, executes the returned tool
calls in order, and appends the raw assistant message and the tool outputs. The loop stops when the
model calls no tool, reports finish_reason "stop", or reaches the step limit from the config.
Truncated replies (finish_reason "length") are recorded in the API audit. `run_online_agent` is the
entry used by Caper's approval-aware runtime.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

MAX_TOKENS = 8192


class TechnicalInvalid(RuntimeError):
    """An Agent/API protocol failure, never an Oracle Incapable result."""


def drive_agent(
    *, runtime: Any, post: Callable[[dict[str, Any]], dict[str, Any]],
    system_prompt: str, user_prompt: str, model: str, max_steps: int,
    terminal_controller: Any | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    conversation: list[dict[str, Any]] = []
    audit: list[dict[str, Any]] = []
    tools = runtime.get_tools("openai")
    terminal_state = "step_limit"
    for turn_index in range(max_steps):
        body = post({"model": model, "max_tokens": MAX_TOKENS, "messages": messages, "tools": tools})
        try:
            choice = body["choices"][0]
            msg = choice["message"]
        except (KeyError, IndexError, TypeError) as error:
            raise TechnicalInvalid("malformed_agent_response") from error
        finish_reason = choice.get("finish_reason")
        audit.append({"turn_index": turn_index, "finish_reason": finish_reason, "usage": body.get("usage"),
                      "tool_call_count": len(msg.get("tool_calls") or [])})
        tool_calls = []
        for tc in msg.get("tool_calls") or []:
            args = tc["function"].get("arguments", "{}")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {"command": args}
                tc["function"]["arguments"] = json.dumps(args)
            tool_calls.append({"id": tc["id"], "name": tc["function"]["name"], "input": args})
        conversation.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": tool_calls})
        messages.append(msg)
        if not tool_calls:
            terminal_state = "no_tool_call"
            break
        # The approver reads the agent-visible transcript; provider reasoning is not passed on.
        # Bare runtimes have no setter.
        context_setter = getattr(runtime, "set_approval_context", None)
        if callable(context_setter):
            projected = {"role": "assistant", "content": msg.get("content") or "", "tool_calls": msg.get("tool_calls")}
            visible = [m if m.get("role") != "assistant" else
                       {k: v for k, v in m.items() if k in ("role", "content", "tool_calls")} for m in messages[:-1]]
            context_setter(messages=visible, current_assistant=projected)
        for tc in tool_calls:
            output = runtime.execute_tool(tc["name"], tc["input"])
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": output if output else "(no output)"})
            conversation.append({"role": "tool", "tool_name": tc["name"], "tool_input": tc["input"],
                                 "command": tc["input"].get("command", "") if tc["name"] == "bash" else "",
                                 "output": output})
        if finish_reason == "stop":
            terminal_state = "finish_reason_stop"
            break
    terminal = {"protocol": "saber_original_run_openai_8192", "terminal_state": terminal_state,
                "truncated_replies": sum(a["finish_reason"] == "length" for a in audit)}
    return conversation, terminal, audit


def _post_adapter(api_base: str, api_key: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
    import httpx
    import time

    def post(payload: dict[str, Any]) -> dict[str, Any]:
        for attempt in range(4):
            try:
                response = httpx.post(api_base.rstrip("/") + "/chat/completions",
                                      headers={"Authorization": f"Bearer {api_key}"}, json=payload, timeout=180)
                if response.status_code in {408, 429, 500, 502, 503, 504} and attempt < 3:
                    time.sleep(10 * (attempt + 1))
                    continue
                if response.status_code >= 400:
                    raise TechnicalInvalid(f"agent_api_http_{response.status_code}")
                data = response.json()
                if "error" in data:
                    raise TechnicalInvalid("agent_api_error_body")
                return data
            except (httpx.TransportError, ValueError) as error:
                if attempt == 3:
                    raise TechnicalInvalid(f"agent_api_{type(error).__name__}") from error
                time.sleep(10 * (attempt + 1))
        raise TechnicalInvalid("agent_api_retries_exhausted")

    return post


def run_online_agent(
    *, model: str, api_base: str, api_key: str, system_prompt: str, user_prompt: str,
    runtime: Any, max_steps: int, temperature: float | None = None, terminal_controller: Any | None = None,
) -> list[dict[str, Any]]:
    """Entry for the Caper runtime: the same loop; temperature and terminal_controller are ignored."""
    conversation, terminal, audit = drive_agent(
        runtime=runtime, post=_post_adapter(api_base, api_key), system_prompt=system_prompt,
        user_prompt=user_prompt, model=model, max_steps=max_steps)
    output_dir = getattr(getattr(runtime, "shell", None), "output_dir", None)
    if output_dir is not None:
        root = Path(output_dir)
        (root / "continuation.json").write_text(json.dumps(terminal, ensure_ascii=False, indent=2) + "\n")
        (root / "agent_api_audit.json").write_text(json.dumps(audit, ensure_ascii=False, indent=2) + "\n")
    return conversation

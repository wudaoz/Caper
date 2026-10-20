"""Run one task with per-command pre-execution, effects report and approval."""

from __future__ import annotations

import time
import traceback
from pathlib import Path
from typing import Any

from .collector import AttachedEffectDockerEnvironment
from .run_records import (
    _api_key,
    _load_saber_modules,
    _read_jsonl,
    _write_json,
    build_candidates_file,
    redact_secrets,
    summarize_effect_records,
)
from .approver import CONDITIONS, OnlineApprovalConfig, OnlineApprover
from .shell import ApprovalAwareShell


def _run_openai_agent(**kwargs: Any) -> list[dict[str, Any]]:
    """Agent loop; the task runner installs the protocol it uses (SABER's loop or Claude Code)."""
    raise RuntimeError("no agent loop installed; set caper.online_task._run_openai_agent")


class OnlineTaskRuntime:
    """Expose only committed Shell actions as Saber's executed trajectory."""

    def __init__(self, shell: Any, *, tools: list[dict[str, Any]]) -> None:
        self.shell = shell
        self.tools = list(tools)
        self.events: list[dict[str, Any]] = []

    def get_tools(self, provider_type: str) -> list[dict[str, Any]]:
        return list(self.tools)

    def set_approval_context(
        self,
        *,
        messages: list[dict[str, Any]],
        current_assistant: dict[str, Any],
    ) -> None:
        self.shell.set_approval_context(
            messages=messages,
            current_assistant=current_assistant,
        )

    def execute_tool(self, tool_name: str, tool_input: dict[str, Any] | None) -> str:
        if tool_name != "bash":
            raise ValueError(f"online pilot supports only bash, got {tool_name}")
        command = str((tool_input or {}).get("command", ""))
        output = self.shell.execute(command)
        execution = self.shell.last_execution
        if not isinstance(execution, dict):
            raise RuntimeError("approval-aware shell did not expose execution metadata")
        event = {
            "step": len(self.events) + 1,
            "type": "tool_call",
            "tool_name": "bash",
            "input": tool_input or {},
            "command": command,
            "output": output,
            "deltas": list(execution.get("deltas") or []),
            "executed": bool(execution.get("executed")),
        }
        self.events.append(event)
        return output

    def get_shell_trajectory(self) -> list[dict[str, Any]]:
        return self.shell.get_trajectory_dicts()

    def get_events(self) -> list[dict[str, Any]]:
        return list(self.events)

    def cleanup(self) -> None:
        self.shell.cleanup()


def run_online_saber_task(
    *,
    task: dict[str, Any],
    condition: str,
    saber_root: Path,
    output_dir: Path,
    agent_model: str,
    approver_model: str,
    api_base: str,
    base_image: str,
    max_steps: int,
    command_timeout: int,
    approver_max_tokens: int = 4096,
    feedback_mode: str = "reason_feedback",
) -> dict[str, Any]:
    """Run one Saber task with live per-command preview and approval."""

    if condition not in CONDITIONS:
        raise ValueError(f"unknown online approval condition: {condition}")
    output_dir = Path(output_dir).resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite online Saber task: {output_dir}")
    output_dir.mkdir(parents=True)

    sandbox_shell, task_runtime_module = _load_saber_modules(saber_root)
    sandbox_shell.DOCKER_IMAGE = base_image
    setup = task["setup"]
    secret = _api_key(api_base)
    started = time.time()
    vendor_runtime: Any | None = None
    online_runtime: OnlineTaskRuntime | None = None
    approver: OnlineApprover | None = None
    initial_container_id: str | None = None
    conversation: list[dict[str, Any]] = []
    trajectory: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    proposals: list[dict[str, Any]] = []
    error: dict[str, str] = {}
    invalid = False

    try:
        vendor_runtime = task_runtime_module.TaskRuntime(task)
        original_shell = vendor_runtime.shell
        initial_container_id = original_shell.container_id
        collector = AttachedEffectDockerEnvironment(
            container_id=initial_container_id,
            image=base_image,
            cwd=setup["cwd"],
            manifest_root=setup["cwd"],
            interpreter=["bash", "-c"],
            env={"HOME": "/home/user", "PAGER": "cat", "MANPAGER": "cat"},
            timeout=command_timeout,
            instance_id=task["id"],
            effect_output_dir=output_dir,
            trace_limit_bytes=64 * 1024 * 1024,
            include_output_sinks=True,
        )
        approver = OnlineApprover(
            OnlineApprovalConfig(
                condition=condition,
                model=approver_model,
                api_base=api_base,
                max_tokens=approver_max_tokens,
            ),
            api_key=secret,
        )
        approval_shell = ApprovalAwareShell(
            original_shell=original_shell,
            collector=collector,
            condition=condition,
            approver=approver,
            task_id=task["id"],
            task_metadata={
                "scenario": task["scenario"],
                "category": task["category"],
            },
            user_request=setup["user_prompt"],
            workspace_context=setup["system_prompt"],
            output_dir=output_dir,
            feedback_mode=feedback_mode,
        )
        online_runtime = OnlineTaskRuntime(
            approval_shell,
            tools=vendor_runtime.get_tools("openai"),
        )
        conversation = _run_openai_agent(
            model=agent_model,
            api_base=api_base,
            api_key=secret,
            system_prompt=setup["system_prompt"],
            user_prompt=setup["user_prompt"],
            runtime=online_runtime,
            max_steps=max_steps,
            temperature=0,
        )
        trajectory = online_runtime.get_shell_trajectory()
        events = online_runtime.get_events()
        proposals = approval_shell.get_proposal_trajectory()
    except Exception as exc:
        # An uncaught exception always truncates the scientific trajectory,
        # regardless of whether its underlying cause is infrastructure-related.
        invalid = True
        if online_runtime is not None:
            trajectory = online_runtime.get_shell_trajectory()
            events = online_runtime.get_events()
            proposals = online_runtime.shell.get_proposal_trajectory()
        error = {
            "exception": redact_secrets(str(exc), [secret]),
            "traceback": redact_secrets(traceback.format_exc(), [secret]),
        }
    finally:
        if online_runtime is not None:
            online_runtime.cleanup()
        elif vendor_runtime is not None:
            vendor_runtime.cleanup()

    result = {
        "id": task["id"],
        "scenario": task["scenario"],
        "category": task["category"],
        "difficulty": task.get("difficulty", ""),
        "prompt": setup["user_prompt"],
        "trajectory": trajectory,
        "events": events,
        "conversation": conversation,
        "error": error or None,
    }
    _write_json(output_dir / "trajectory.json", result)
    if approver is not None:
        _write_json(output_dir / "approver_api_audit.json", approver.api_audit)
    _write_json(
        output_dir / "task.json",
        {
            "id": task["id"],
            "scenario": task["scenario"],
            "category": task["category"],
            "difficulty": task.get("difficulty", ""),
            "cwd": setup["cwd"],
            "system_prompt": setup["system_prompt"],
            "user_prompt": setup["user_prompt"],
            "injection": task.get("injection", {}),
            "ground_truth": task.get("ground_truth", {}),
        },
    )

    effect_records = _read_jsonl(output_dir / "effects.jsonl")
    structured = _read_jsonl(output_dir / "structured_effects.jsonl")
    execution_records = _read_jsonl(output_dir / "execution_records.jsonl")
    reports = _read_jsonl(output_dir / "effects_reports.jsonl")
    content_diffs = _read_jsonl(output_dir / "content_diffs.jsonl")
    compact = _read_jsonl(output_dir / "compact_views.jsonl")
    approvals = _read_jsonl(output_dir / "approvals.jsonl")
    approval_packets = _read_jsonl(output_dir / "approval_packets.jsonl")
    candidates_path = output_dir / "effect_candidates.jsonl"
    candidate_count = 0
    if effect_records and (output_dir / "runtime_baseline.json").is_file():
        candidate_count = build_candidates_file(
            output_dir / "effects.jsonl",
            output_dir / "runtime_baseline.json",
            candidates_path,
            repo_root=setup["cwd"],
            metadata={
                "task_id": task["id"],
                "scenario": task["scenario"],
                "category": task["category"],
            },
        )

    proposal_count = len(proposals)
    preview_counts = {
        "proposal_count": proposal_count,
        "effect_record_count": len(effect_records),
        "structured_effect_count": len(structured),
        "candidate_count": candidate_count,
        "execution_record_count": len(execution_records),
        "effects_report_count": len(reports),
        "content_diff_count": len(content_diffs),
        "compact_count": len(compact),
        "approval_count": len(approvals),
        "approval_packet_count": len(approval_packets),
    }
    preview_aligned = preview_is_aligned(preview_counts)
    summary = {
        "task_id": task["id"],
        "scenario": task["scenario"],
        "category": task["category"],
        "condition": condition,
        "feedback_mode": feedback_mode,
        "agent_model": agent_model,
        "approver_model": approver_model,
        "approver_max_tokens": approver_max_tokens,
        "duration_seconds": round(time.time() - started, 3),
        "invalid": invalid,
        "committed_shell_count": len(trajectory),
        **preview_counts,
        "preview_aligned": preview_aligned,
        **summarize_effect_records(effect_records),
        **error,
    }
    _write_json(output_dir / "run.json", summary)
    return summary


def preview_is_aligned(counts: dict[str, int]) -> bool:
    """Every proposal must have one observed record per evidence file, one decision and one packet."""

    proposal_count = counts["proposal_count"]
    observed_keys = (
        "effect_record_count", "structured_effect_count", "candidate_count", "execution_record_count",
        "effects_report_count", "content_diff_count", "compact_count",
    )
    aligned = all(counts[key] == proposal_count for key in observed_keys)
    aligned = aligned and counts["approval_count"] == proposal_count
    aligned = aligned and counts["approval_packet_count"] == proposal_count
    return aligned

"""Run SABER's released task-level judge on recorded trajectories in a disposable workspace."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Mapping

from caper.run_records import redact_secrets


TERMINATIONS = (
    "Safe Refusal",
    "Safe Completion",
    "Late Refusal",
    "Harmful Completion",
    "Accidental Harm",
    "Incapable",
)


def legacy_judge_api_base(api_base: str) -> str:
    """Normalize a base for Saber's judge, which appends /v1/chat/completions."""

    base = api_base.rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]
    if not base:
        raise ValueError("api_base must be non-empty")
    return base


def prepare_official_judge_result(result: Mapping[str, Any]) -> dict[str, Any]:
    """Map proposal-aware events back to Saber's executed-event semantics."""

    prepared = deepcopy(dict(result))
    events = prepared.get("events")
    if isinstance(events, list):
        prepared["events"] = [
            event
            for event in events
            if not isinstance(event, Mapping) or event.get("executed") is not False
        ]
    return prepared


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def run_official_saber_judge(
    *,
    saber_root: Path,
    experiment_dir: Path,
    judged_output_dir: Path,
    condition: str,
    judge_model: str,
    judge_type: str,
    api_base: str,
    api_key: str,
    allow_bare_no_preview: bool = False,
    command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Judge one condition in a disposable Saber-compatible workspace."""

    saber_root = Path(saber_root).resolve()
    experiment_dir = Path(experiment_dir).resolve()
    judged_output_dir = Path(judged_output_dir).resolve()
    source_condition = experiment_dir / condition
    if not source_condition.is_dir():
        raise FileNotFoundError(f"condition output is missing: {source_condition}")
    destination = judged_output_dir / condition
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite judged output: {destination}")
    judge_source = saber_root / "judge_osbench.py"
    if not judge_source.is_file():
        raise FileNotFoundError(f"official Saber judge is missing: {judge_source}")
    if not api_key:
        raise ValueError("judge api_key must be non-empty")

    with tempfile.TemporaryDirectory(prefix="caper-saber-judge-") as directory:
        workspace = Path(directory)
        shutil.copy2(judge_source, workspace / "judge_osbench.py")
        config_path = workspace / "config.json"
        judge_api_base = legacy_judge_api_base(api_base)
        _write_json(
            config_path,
            {
                "base_url": judge_api_base,
                "judge": {
                    "id": judge_model,
                    "type": judge_type,
                    "key": api_key,
                    "base_url": judge_api_base,
                },
                "models": {},
            },
        )
        config_path.chmod(0o600)

        result_count = 0
        for task_dir in sorted(source_condition.iterdir()):
            result_path = task_dir / "trajectory.json"
            run_path = task_dir / "run.json"
            if (
                not task_dir.is_dir()
                or not result_path.is_file()
                or not run_path.is_file()
            ):
                continue
            run_summary = json.loads(run_path.read_text(encoding="utf-8"))
            valid_approved = run_summary.get("preview_aligned") is True
            valid_bare = (
                allow_bare_no_preview
                and condition == "bare"
                and run_summary.get("no_approver") is True
                and run_summary.get("no_effect_collector") is True
            )
            if run_summary.get("invalid") is not False or not (valid_approved or valid_bare):
                continue
            result = json.loads(result_path.read_text(encoding="utf-8"))
            task_id = str(result["id"])
            if task_dir.name != task_id:
                continue
            scenario = str(result["scenario"])
            category = str(result["category"])
            task_source = (
                saber_root / "tasks" / scenario / category / f"{task_id}.json"
            )
            if not task_source.is_file():
                raise FileNotFoundError(f"canonical Saber task is missing: {task_source}")
            task_destination = (
                workspace / "tasks" / scenario / category / f"{task_id}.json"
            )
            task_destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(task_source, task_destination)
            prepared_path = (
                workspace
                / "results"
                / condition
                / scenario
                / category
                / f"{task_id}.json"
            )
            _write_json(
                prepared_path,
                prepare_official_judge_result(result),
            )
            result_count += 1
        if result_count == 0:
            raise RuntimeError(f"no online trajectories found for condition {condition}")

        completed = command_runner(
            [sys.executable, "judge_osbench.py", condition],
            cwd=workspace,
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            details = redact_secrets(
                f"stdout={completed.stdout}\nstderr={completed.stderr}", [api_key]
            )
            raise RuntimeError(
                f"official Saber judge failed with exit {completed.returncode}: {details}"
            )
        judged_source = workspace / "judged" / condition
        summary_path = judged_source / "summary.json"
        if not summary_path.is_file():
            raise RuntimeError("official Saber judge produced no summary.json")
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        judged_output_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(judged_source, destination)
        return summary

"""Loading SABER tasks and normalizing SABER's static command deltas."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any



def load_saber_task(saber_root: Path, task_id: str) -> dict[str, Any]:
    """Load one task from Saber's canonical JSONL and require a Shell-only interface."""

    path = Path(saber_root) / "dataset" / "data" / "tasks.jsonl"
    if not path.is_file():
        raise FileNotFoundError(f"Saber tasks file is missing: {path}")
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        task = row.get("task", row)
        if not isinstance(task, dict):
            raise ValueError(f"invalid Saber task at line {line_number}")
        if task.get("id") != task_id:
            continue
        if task.get("setup", {}).get("mcp_servers"):
            raise ValueError(f"Saber task {task_id} is not pure Shell")
        return task
    raise KeyError(f"Saber task not found: {task_id}")


def _delta_dict(delta: Any) -> dict[str, Any]:
    if isinstance(delta, dict):
        return dict(delta)
    if is_dataclass(delta):
        return asdict(delta)
    raise TypeError(f"unsupported Saber delta: {type(delta).__name__}")

"""Small helpers shared by the task runners: record I/O, SABER module loading, run summaries."""

from __future__ import annotations

import importlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from .effect_candidates import MAX_CANDIDATE_BYTES, build_candidate_effect, serialized_bytes
from .model_provider import resolve_api_key


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def build_candidates_file(
    l1_path: Path,
    baseline_path: Path,
    output_path: Path,
    *,
    repo_root: str,
    metadata: Mapping[str, Any],
) -> int:
    if output_path.exists():
        raise FileExistsError(f"refusing to overwrite effect candidates: {output_path}")
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline_effects = baseline.get("effects", [])
    records = _read_jsonl(l1_path)
    candidates = [
        build_candidate_effect(
            record,
            repo_root=repo_root,
            baseline_effects=baseline_effects,
            baseline_status="available",
            metadata=metadata,
        )
        for record in records
    ]
    if not all(
        candidate.get("preservation", {}).get("invariants_match") is True
        and serialized_bytes(candidate) <= MAX_CANDIDATE_BYTES
        for candidate in candidates
    ):
        raise RuntimeError("effect candidate preservation or size validation failed")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        "".join(
            json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n"
            for item in candidates
        ),
        encoding="utf-8",
    )
    return len(candidates)


def _load_saber_modules(saber_root: Path) -> tuple[Any, Any]:
    root = str(Path(saber_root).resolve())
    if root not in sys.path:
        sys.path.insert(0, root)
    sandbox_shell = importlib.import_module("sandbox_shell")
    task_runtime = importlib.import_module("task_runtime")
    for module in (sandbox_shell, task_runtime):
        if Path(module.__file__).resolve().parent != Path(root):
            raise RuntimeError(f"loaded Saber module from unexpected path: {module.__file__}")
    return sandbox_shell, task_runtime


def _api_key(api_base: str = "https://api.deepseek.com") -> str:
    key_env = (
        "OPENROUTER_API_KEY"
        if api_base.rstrip("/").endswith("openrouter.ai/api/v1")
        else "DEEPSEEK_API_KEY"
    )
    return resolve_api_key(api_key_env=key_env)[1]


def redact_secrets(text: str, secrets: list[str]) -> str:
    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def effect_record_completeness(record: Mapping[str, Any]) -> str:
    completeness = record.get("completeness")
    if completeness in {
        "complete",
        "censored_timeout",
        "censored_signal",
        "censored_trace_quota",
        "collector_failure",
    }:
        return str(completeness)
    if record.get("timed_out") is True:
        return "censored_timeout"
    succeeded = bool(
        record.get("trace_complete") is True
        and record.get("parse_status") == "ok"
        and record.get("manifest_status") == "ok"
        and record.get("persistent_diff") is not None
        and not record.get("warnings")
    )
    return "complete" if succeeded else "collector_failure"


def summarize_effect_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    categories = Counter(
        effect.get("category", "unknown")
        for record in records
        for effect in record.get("effects", [])
    )
    completeness = [effect_record_completeness(record) for record in records]
    collector_failure_action_ids = [
        record.get("action_id") or f"action-{index}"
        for index, (record, status) in enumerate(zip(records, completeness), start=1)
        if status == "collector_failure"
    ]
    censored_action_ids = [
        record.get("action_id") or f"action-{index}"
        for index, (record, status) in enumerate(zip(records, completeness), start=1)
        if status.startswith("censored_")
    ]
    raw_trace_soft_cap_action_ids = [
        record.get("action_id") or f"action-{index}"
        for index, record in enumerate(records, start=1)
        if record.get("raw_trace_truncated") is True
    ]
    collector_records_valid = not collector_failure_action_ids
    complete_effect_records = all(status == "complete" for status in completeness)
    return {
        "action_count": len(records),
        "valid_action_count": len(records) - len(collector_failure_action_ids),
        "invalid_action_ids": collector_failure_action_ids,
        "collector_failure_action_ids": collector_failure_action_ids,
        "censored_action_ids": censored_action_ids,
        "completeness_counts": dict(sorted(Counter(completeness).items())),
        "collector_records_valid": collector_records_valid,
        "complete_effect_records": complete_effect_records,
        "effect_records_valid": collector_records_valid,
        "raw_trace_bytes": sum(record.get("metrics", {}).get("raw_trace_bytes", 0) for record in records),
        "raw_trace_observed_bytes": sum(
            record.get("metrics", {}).get(
                "raw_trace_observed_bytes",
                record.get("metrics", {}).get("raw_trace_bytes", 0),
            )
            for record in records
        ),
        "raw_trace_retained_bytes": sum(
            record.get("metrics", {}).get(
                "raw_trace_retained_bytes",
                record.get("metrics", {}).get("raw_trace_bytes", 0),
            )
            for record in records
        ),
        "raw_trace_soft_cap_action_ids": raw_trace_soft_cap_action_ids,
        "effect_category_counts": dict(sorted(categories.items())),
    }

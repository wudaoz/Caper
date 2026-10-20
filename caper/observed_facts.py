"""Canonical, policy-free facts normalized from one traced action."""

from __future__ import annotations

import hashlib
import json
import posixpath
from copy import deepcopy
from typing import Any, Iterable, Mapping

from .effect_summary import _network_scope, classify_path
from .effect_candidates import _residual_effects


def _observed_at(effect: Mapping[str, Any], ordinal: int) -> float:
    value = effect.get("first_seen", effect.get("timestamp"))
    return float(value) if isinstance(value, (int, float)) else float(ordinal)


def _is_inet_connect(effect: Mapping[str, Any]) -> bool:
    return (
        effect.get("category") == "network"
        and effect.get("operation") == "connect"
        and (
            effect.get("address_family") in {"AF_INET", "AF_INET6"}
            or effect.get("remote_ip") is not None
            or effect.get("remote_port") is not None
        )
    )


def _process_ref_for_pid(
    pid: Any,
    current_ref_by_pid: Mapping[int, str],
    parent_by_pid: Mapping[int, int],
) -> str | None:
    if not isinstance(pid, int):
        return None
    current = pid
    seen: set[int] = set()
    while current not in seen:
        seen.add(current)
        if current in current_ref_by_pid:
            return current_ref_by_pid[current]
        parent = parent_by_pid.get(current)
        if parent is None:
            return None
        current = parent
    return None


def _bounded_argv(value: Any, *, max_items: int = 16, max_chars: int = 160) -> list[str]:
    argv = value if isinstance(value, list) else []
    bounded: list[str] = []
    for item in argv[:max_items]:
        text = str(item)
        bounded.append(text if len(text) <= max_chars else text[: max_chars - 3] + "...")
    return bounded


def _attempted_effects(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = record.get("attempted_effects")
    if not isinstance(raw, list):
        return []
    result = []
    for index, value in enumerate(raw, 1):
        if not isinstance(value, Mapping):
            continue
        result.append({
            "fact_id": f"a{index:04d}",
            "kind": "attempted_effect",
            **{
                key: value.get(key)
                for key in ("category", "operation", "command", "observed", "simulated_by")
                if key in value
            },
        })
    return result


def extract_canonical_observed_facts(
    record: Mapping[str, Any],
    *,
    repo_root: str,
    baseline_effects: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Normalize residual trace events without assigning policy or harm."""

    raw_effects = record.get("effects")
    raw_items = raw_effects if isinstance(raw_effects, list) else []
    malformed = sum(not isinstance(item, Mapping) for item in raw_items)
    effects = [item for item in raw_items if isinstance(item, Mapping)]
    baseline = [item for item in baseline_effects if isinstance(item, Mapping)]

    residual: list[dict[str, Any]] = []
    for ordinal, (effect, count) in enumerate(_residual_effects(effects, baseline)):
        item = deepcopy(dict(effect))
        item["count"] = count
        item["_ordinal"] = ordinal
        residual.append(item)
    residual.sort(key=lambda item: (_observed_at(item, item["_ordinal"]), item["_ordinal"]))

    parent_by_pid: dict[int, int] = {}
    current_ref_by_pid: dict[int, str] = {}
    lineage_by_ref: dict[str, str] = {}
    processes: list[dict[str, Any]] = []
    file_facts: list[dict[str, Any]] = []
    network_attempts: list[dict[str, Any]] = []

    for effect in residual:
        category = effect.get("category")
        operation = effect.get("operation")
        pid = effect.get("pid")
        at = _observed_at(effect, effect["_ordinal"])

        if (
            category == "process"
            and operation == "spawn"
            and isinstance(pid, int)
            and isinstance(effect.get("parent_pid"), int)
        ):
            parent_by_pid[pid] = effect["parent_pid"]
            continue

        if category == "process" and operation == "exec" and effect.get("success") is True:
            process_ref = f"p{len(processes) + 1:04d}"
            previous_ref = current_ref_by_pid.get(pid) if isinstance(pid, int) else None
            parent_pid = effect.get("parent_pid")
            if not isinstance(parent_pid, int) and isinstance(pid, int):
                parent_pid = parent_by_pid.get(pid)
            parent_ref = current_ref_by_pid.get(parent_pid) if isinstance(parent_pid, int) else None
            inherited_ref = previous_ref or parent_ref
            lineage_ref = (
                lineage_by_ref.get(inherited_ref, inherited_ref)
                if inherited_ref is not None
                else process_ref
            )
            process = {
                "fact_id": process_ref,
                "kind": "process_exec",
                "parent_ref": parent_ref,
                "replaces_ref": previous_ref,
                "lineage_ref": lineage_ref,
                "pid": pid,
                "executable": effect.get("executable"),
                "argv": _bounded_argv(effect.get("argv")),
                "event_count": int(effect.get("count", 1)),
                "observed_at": at,
            }
            processes.append(process)
            lineage_by_ref[process_ref] = lineage_ref
            if isinstance(pid, int):
                current_ref_by_pid[pid] = process_ref
            continue

        actor_ref = _process_ref_for_pid(pid, current_ref_by_pid, parent_by_pid)
        lineage_ref = lineage_by_ref.get(actor_ref) if actor_ref else None
        if category == "file" and isinstance(effect.get("path"), str) and effect.get("path"):
            path = posixpath.normpath(str(effect["path"]))
            scope, artifact = classify_path(path, repo_root)
            fact = {
                "fact_id": f"f{len(file_facts) + 1:04d}",
                "kind": "file_fact",
                "operation": str(operation or "unknown"),
                "path": path,
                "scope": scope,
                "artifact": artifact,
                "actor_ref": actor_ref,
                "lineage_ref": lineage_ref,
                "pid": pid,
                "success": effect.get("success"),
                "event_count": int(effect.get("count", 1)),
                "observed_at": at,
            }
            if isinstance(effect.get("source_path"), str):
                fact["source_path"] = posixpath.normpath(str(effect["source_path"]))
            if effect.get("success") is False:
                fact["errno"] = effect.get("errno")
            file_facts.append(fact)
            continue

        if _is_inet_connect(effect):
            network_attempts.append({
                "fact_id": f"n{len(network_attempts) + 1:04d}",
                "kind": "network_attempt",
                "operation": "connect",
                "actor_ref": actor_ref,
                "lineage_ref": lineage_ref,
                "pid": pid,
                "address_family": effect.get("address_family"),
                "remote_ip": effect.get("remote_ip"),
                "remote_port": effect.get("remote_port"),
                "scope": _network_scope(effect.get("remote_ip")),
                "success": effect.get("success"),
                "errno": effect.get("errno"),
                "event_count": int(effect.get("count", 1)),
                "observed_at": at,
            })

    attempted_effects = _attempted_effects(record)
    canonical_for_hash = {
        "processes": processes,
        "file_facts": file_facts,
        "network_attempts": network_attempts,
        "attempted_effects": attempted_effects,
    }
    digest = hashlib.sha256(
        json.dumps(canonical_for_hash, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        **canonical_for_hash,
        "parent_by_pid": parent_by_pid,
        "source_facts_sha256": "sha256:" + digest,
        "counts": {
            "processes": len(processes),
            "file_facts": len(file_facts),
            "network_attempts": len(network_attempts),
            "attempted_effects": len(attempted_effects),
            "malformed_effects": malformed,
        },
    }

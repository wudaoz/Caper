"""Build bounded, deterministic approval facts from the raw traced effects."""

from __future__ import annotations

import ipaddress
import json
import posixpath
from collections import Counter, defaultdict
from typing import Any, Mapping


MAX_REPRESENTATIVE_PATHS = 20
MAX_STRUCTURED_BYTES = 16 * 1024
_GENERATED_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
_CREDENTIAL_PARTS = {".ssh", ".aws", ".kube", ".gnupg"}
_BENIGN_WRITE_SINKS = {"/dev/null"}
_SCOPE_PRIORITY = {
    "credentials": 0,
    "repo": 1,
    "proc": 2,
    "sys": 3,
    "system_config": 4,
    "temp": 5,
    "system": 6,
    "unknown": 7,
}


def _under(path: str, root: str) -> bool:
    normalized_path = posixpath.normpath(path)
    normalized_root = posixpath.normpath(root)
    return normalized_path == normalized_root or normalized_path.startswith(normalized_root + "/")


def classify_path(path: str, repo_root: str) -> tuple[str, str | None]:
    """Classify an absolute path without making an approval decision."""

    if not path.startswith("/"):
        return "unknown", None
    normalized = posixpath.normpath(path)
    parts = set(normalized.split("/"))
    generated = "generated" if (
        parts.intersection(_GENERATED_PARTS)
        or normalized.endswith((".pyc", ".pyo"))
    ) else None
    if _under(normalized, repo_root):
        return "repo", generated
    if parts.intersection(_CREDENTIAL_PARTS) or normalized in {"/etc/shadow", "/etc/gshadow"}:
        return "credentials", generated
    if _under(normalized, "/proc"):
        return "proc", generated
    if _under(normalized, "/sys"):
        return "sys", generated
    if _under(normalized, "/tmp") or _under(normalized, "/var/tmp"):
        return "temp", generated
    if _under(normalized, "/etc"):
        return "system_config", generated
    return "system", generated


def _network_scope(remote_ip: Any) -> str:
    if not isinstance(remote_ip, str) or not remote_ip:
        return "unknown"
    try:
        address = ipaddress.ip_address(remote_ip)
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "loopback"
    if address.is_private or address.is_link_local:
        return "private"
    return "external"


def _persistent_change(
    change: Mapping[str, Any],
    repo_root: str,
) -> dict[str, Any]:
    path = str(change.get("path", ""))
    absolute = path if path.startswith("/") else posixpath.join(repo_root, path)
    scope, artifact = classify_path(absolute, repo_root)
    before = change.get("before") if isinstance(change.get("before"), Mapping) else {}
    after = change.get("after") if isinstance(change.get("after"), Mapping) else {}
    return {
        "operation": change.get("operation", "unknown"),
        "path": path,
        "scope": scope,
        "artifact": artifact,
        "type": after.get("type") or before.get("type"),
        "size_before": before.get("size"),
        "size_after": after.get("size"),
    }


def _serialized_bytes(value: Mapping[str, Any]) -> int:
    return len(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def build_structured_effect(
    record: Mapping[str, Any],
    *,
    repo_root: str = "/testbed",
    baseline_effects: list[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Aggregate one traced action record into deterministic facts."""

    effects = record.get("effects") if isinstance(record.get("effects"), list) else []
    effects = [effect for effect in effects if isinstance(effect, Mapping)]
    baseline_effects = baseline_effects or []

    def effect_count(effect: Mapping[str, Any]) -> int:
        value = effect.get("count", 1)
        return value if isinstance(value, int) and value >= 0 else 1

    def baseline_key(effect: Mapping[str, Any]) -> tuple[Any, ...]:
        return tuple(effect.get(key) for key in (
            "category",
            "operation",
            "path",
            "source_path",
            "executable",
            "remote_ip",
            "remote_port",
            "local_ip",
            "local_port",
            "socket",
            "success",
            "errno",
        ))

    baseline_remaining: Counter[tuple[Any, ...]] = Counter()
    for effect in baseline_effects:
        if isinstance(effect, Mapping):
            baseline_remaining[baseline_key(effect)] += effect_count(effect)

    residual_effects: list[tuple[Mapping[str, Any], int]] = []
    background_effects: list[tuple[Mapping[str, Any], int]] = []
    for effect in effects:
        count = effect_count(effect)
        key = baseline_key(effect)
        background_count = min(count, baseline_remaining[key])
        if background_count:
            background_effects.append((effect, background_count))
            baseline_remaining[key] -= background_count
        if count > background_count:
            residual_effects.append((effect, count - background_count))

    def add_path_fact(
        facts: dict[str, dict[str, Any]],
        path: str,
        operation: str,
        count: int,
        failed: bool,
    ) -> None:
        scope, artifact = classify_path(path, repo_root)
        fact = facts.setdefault(path, {
            "path": path,
            "scope": scope,
            "artifact": artifact,
            "operations": set(),
            "event_count": 0,
            "failed_count": 0,
        })
        fact["operations"].add(operation)
        fact["event_count"] += count
        if failed:
            fact["failed_count"] += count

    def materialize_path_facts(
        facts: Mapping[str, Mapping[str, Any]],
        *,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        values = [{
            **{key: value for key, value in fact.items() if key != "operations"},
            "operations": sorted(fact["operations"]),
        } for fact in facts.values()]
        values.sort(key=lambda item: (
            _SCOPE_PRIORITY.get(item["scope"], 99),
            item["artifact"] == "generated",
            -item["failed_count"],
            -item["event_count"],
            item["path"],
        ))
        return values if limit is None else values[:limit]

    all_path_facts: dict[str, dict[str, Any]] = {}
    residual_path_facts: dict[str, dict[str, Any]] = {}
    background_path_facts: dict[str, dict[str, Any]] = {}
    credential_facts: dict[str, dict[str, Any]] = {}
    outside_write_facts: dict[str, dict[str, Any]] = {}
    syscall_event_counts: Counter[str] = Counter()
    scope_event_counts: Counter[str] = Counter()
    unique_by_scope: dict[str, set[str]] = defaultdict(set)
    process_counts: Counter[str] = Counter()
    residual_executables: Counter[str] = Counter()
    connection_scope_counts: Counter[str] = Counter()
    external_connections: dict[tuple[Any, ...], dict[str, Any]] = {}
    mutating_operations = {
        "create",
        "open_write",
        "open_readwrite",
        "write",
        "delete",
        "rename",
        "permission_change",
    }

    for effect in effects:
        category = str(effect.get("category", "unknown"))
        operation = str(effect.get("operation", "unknown"))
        count = effect_count(effect)
        if category == "file":
            syscall_event_counts[operation] += count
            for key in ("path", "source_path"):
                path = effect.get(key)
                if not isinstance(path, str) or not path:
                    continue
                scope, artifact = classify_path(path, repo_root)
                scope_event_counts[scope] += count
                unique_by_scope[scope].add(path)
                fact_operation = operation if key == "path" else f"source_{operation}"
                failed = effect.get("success") is False
                add_path_fact(all_path_facts, path, fact_operation, count, failed)
                if scope == "credentials":
                    add_path_fact(credential_facts, path, fact_operation, count, failed)
                if (
                    key == "path"
                    and path not in _BENIGN_WRITE_SINKS
                    and scope != "repo"
                    and operation in mutating_operations
                    and effect.get("success") is True
                ):
                    add_path_fact(outside_write_facts, path, operation, count, False)
        elif category == "process":
            process_counts[operation] += count
        elif category == "network":
            scope = _network_scope(effect.get("remote_ip"))
            connection_scope_counts[scope] += count
            if operation == "connect" and scope == "external":
                key = (
                    effect.get("remote_ip"),
                    effect.get("remote_port"),
                    effect.get("success"),
                )
                stored = external_connections.setdefault(key, {
                    "ip": effect.get("remote_ip"),
                    "port": effect.get("remote_port"),
                    "success": effect.get("success"),
                    "count": 0,
                })
                stored["count"] += count

    for effect, count in residual_effects:
        if effect.get("category") == "file":
            operation = str(effect.get("operation", "unknown"))
            for key in ("path", "source_path"):
                path = effect.get(key)
                if isinstance(path, str) and path:
                    add_path_fact(
                        residual_path_facts,
                        path,
                        operation if key == "path" else f"source_{operation}",
                        count,
                        effect.get("success") is False,
                    )
        elif effect.get("category") == "process" and effect.get("operation") == "exec":
            executable = effect.get("executable")
            if isinstance(executable, str) and executable:
                residual_executables[executable] += count

    for effect, count in background_effects:
        if effect.get("category") != "file":
            continue
        operation = str(effect.get("operation", "unknown"))
        for key in ("path", "source_path"):
            path = effect.get(key)
            if isinstance(path, str) and path:
                add_path_fact(
                    background_path_facts,
                    path,
                    operation if key == "path" else f"source_{operation}",
                    count,
                    effect.get("success") is False,
                )

    raw_persistent = record.get("persistent_diff")
    raw_persistent = raw_persistent if isinstance(raw_persistent, list) else []
    persistent_change_counts = Counter(
        str(change.get("operation", "unknown"))
        for change in raw_persistent
        if isinstance(change, Mapping)
    )
    persistent_changes = sorted(
        (
            _persistent_change(change, repo_root)
            for change in raw_persistent
            if isinstance(change, Mapping)
        ),
        key=lambda item: (
            item["artifact"] == "generated",
            item["operation"],
            item["path"],
        ),
    )

    completeness = str(record.get("completeness", "collector_failure"))
    metrics = record.get("metrics") if isinstance(record.get("metrics"), Mapping) else {}
    execution_ms = metrics.get("execution_ms")
    duration_seconds = round(float(execution_ms) / 1000, 3) if isinstance(execution_ms, (int, float)) else None
    timeout_seconds = metrics.get("command_timeout_seconds")
    timeout_seconds = float(timeout_seconds) if isinstance(timeout_seconds, (int, float)) else None
    limit_fraction = (
        round(duration_seconds / timeout_seconds, 3)
        if duration_seconds is not None and timeout_seconds
        else None
    )

    signals: set[str] = set()
    if completeness.startswith("censored_"):
        signals.add("censored_execution")
    if unique_by_scope.get("credentials"):
        signals.add("credential_access")
    if connection_scope_counts.get("external"):
        signals.add("external_network")
    if persistent_change_counts.get("delete"):
        signals.add("persistent_delete")
    if syscall_event_counts.get("permission_change"):
        signals.add("permission_change")

    raw_coverage = record.get("coverage") if isinstance(record.get("coverage"), Mapping) else {}
    persistent_roots = raw_coverage.get("persistent_diff_roots")
    if not isinstance(persistent_roots, list) or not all(isinstance(item, str) for item in persistent_roots):
        persistent_roots = [repo_root]

    structured: dict[str, Any] = {
        "schema_version": "1.1",
        "instance_id": record.get("instance_id"),
        "action_index": record.get("action_index"),
        "action_id": record.get("action_id"),
        "execution": {
            "status": completeness,
            "returncode": record.get("returncode"),
            "duration_seconds": duration_seconds,
            "duration_display": f"{duration_seconds:.3f} s" if duration_seconds is not None else None,
            "time_limit_seconds": timeout_seconds,
            "time_limit_fraction": limit_fraction,
        },
        "salient_effects": {
            "repo_persistent_change_counts": dict(sorted(persistent_change_counts.items())),
            "repo_persistent_changes": persistent_changes,
            "outside_repo_writes": materialize_path_facts(outside_write_facts),
            "credential_accesses": [
                {key: value for key, value in item.items() if key not in {"scope", "artifact"}}
                for item in materialize_path_facts(credential_facts)
            ],
            "external_network": sorted(
                external_connections.values(),
                key=lambda item: (str(item["ip"]), item["port"] or -1, str(item["success"])),
            ),
            "executables": [
                {"executable": executable, "event_count": count}
                for executable, count in sorted(residual_executables.items())
            ],
            "salient_detail_truncated": False,
        },
        "resource_summary": {
            "unique_paths": len(all_path_facts),
            "unique_paths_by_scope": dict(sorted(
                (scope, len(paths)) for scope, paths in unique_by_scope.items()
            )),
            "event_counts_by_scope": dict(sorted(scope_event_counts.items())),
            "syscall_event_counts": dict(sorted(syscall_event_counts.items())),
            "process_event_counts": dict(sorted(process_counts.items())),
            "connection_counts_by_scope": dict(sorted(connection_scope_counts.items())),
            "l1_effect_groups": len(effects),
            "representative_observed_paths": materialize_path_facts(
                residual_path_facts,
                limit=MAX_REPRESENTATIVE_PATHS,
            ),
        },
        "runtime_background": {
            "matched_effect_groups": len(background_effects),
            "event_count": sum(count for _, count in background_effects),
            "representative_paths": materialize_path_facts(
                background_path_facts,
                limit=MAX_REPRESENTATIVE_PATHS,
            ),
        },
        "generic_signals": sorted(signals),
        "coverage": {
            "kind": "observed_only",
            "execution_complete": raw_coverage.get(
                "execution_complete",
                completeness == "complete",
            ),
            "raw_trace_complete": raw_coverage.get("raw_trace_complete", completeness == "complete"),
            "effect_detail_complete": raw_coverage.get(
                "effect_detail_complete",
                completeness == "complete",
            ),
            "aggregation_mode": raw_coverage.get("aggregation_mode", "full"),
            "persistent_diff_roots": persistent_roots,
            "reason": None if completeness == "complete" else completeness,
            "l1_effect_groups": len(effects),
            "unknown_path_count": len(unique_by_scope.get("unknown", set())),
        },
    }

    while _serialized_bytes(structured) > MAX_STRUCTURED_BYTES:
        ordinary = (
            structured["resource_summary"]["representative_observed_paths"],
            structured["runtime_background"]["representative_paths"],
        )
        longest = max(ordinary, key=len)
        if longest:
            longest.pop()
            continue
        salient = (
            structured["salient_effects"]["repo_persistent_changes"],
            structured["salient_effects"]["outside_repo_writes"],
            structured["salient_effects"]["credential_accesses"],
            structured["salient_effects"]["external_network"],
            structured["salient_effects"]["executables"],
        )
        longest = max(salient, key=len)
        if not longest:
            raise ValueError("structured effect fixed fields exceed 16 KiB")
        longest.pop()
        structured["salient_effects"]["salient_detail_truncated"] = True
    return structured

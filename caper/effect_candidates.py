"""Deterministic aggregation of one traced action's raw effects into a bounded effect candidate.

Not a policy engine: it groups and bounds observed facts without assigning harm.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import posixpath
from collections import Counter, defaultdict
from copy import deepcopy
from typing import Any, Iterable, Mapping

from .effect_summary import build_structured_effect, classify_path


MAX_CANDIDATE_BYTES = 16 * 1024
MAX_REPRESENTATIVES = 3
MAX_LOGICAL_ROOT_GROUPS = 8
_PATH_SCOPE_PRIORITY = {
    "credentials": 0,
    "repo": 1,
    "proc": 2,
    "sys": 3,
    "system_config": 4,
    "temp": 5,
    "system": 6,
    "unknown": 7,
}
MUTATING_OPERATIONS = frozenset({
    "create",
    "open_write",
    "open_readwrite",
    "write",
    "delete",
    "rename",
    "permission_change",
})
BENIGN_WRITE_SINKS = frozenset({"/dev/null"})
_CACHE_PARTS = frozenset({".pytest_cache", ".mypy_cache", ".ruff_cache", ".cache"})
_GENERATED_ROOT_PARTS = frozenset({"build", "dist", "target"})


def serialized_bytes(value: Mapping[str, Any]) -> int:
    return len(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _count(effect: Mapping[str, Any]) -> int:
    value = effect.get("count", 1)
    return value if isinstance(value, int) and value >= 0 else 1


def artifact_kind(path: str) -> str | None:
    normalized = posixpath.normpath(path)
    parts = normalized.split("/")
    if "__pycache__" in parts or normalized.endswith((".pyc", ".pyo")):
        return "python_bytecode"
    if set(parts).intersection(_CACHE_PARTS):
        return "cache_directory"
    if set(parts).intersection(_GENERATED_ROOT_PARTS):
        return "generated_other"
    return None


def logical_root(path: str) -> str:
    normalized = posixpath.normpath(path)
    parts = normalized.split("/")
    for marker in ("__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".cache"):
        if marker in parts:
            index = parts.index(marker)
            root = "/".join(parts[:index])
            return root or "/"
    for marker in ("build", "dist", "target"):
        if marker in parts:
            index = parts.index(marker)
            root = "/".join(parts[: index + 1])
            return root or "/"
    return posixpath.dirname(normalized) or "."


def _absolute(path: str, repo_root: str) -> str:
    return posixpath.normpath(path if path.startswith("/") else posixpath.join(repo_root, path))


def _display_root(root: str, repo_root: str) -> str:
    normalized_repo = posixpath.normpath(repo_root)
    normalized = posixpath.normpath(root)
    if normalized == normalized_repo:
        return "."
    prefix = normalized_repo + "/"
    return normalized[len(prefix):] if normalized.startswith(prefix) else normalized


def _change_fact(change: Mapping[str, Any]) -> dict[str, Any]:
    before = change.get("before") if isinstance(change.get("before"), Mapping) else {}
    after = change.get("after") if isinstance(change.get("after"), Mapping) else {}
    return {
        "operation": str(change.get("operation", "unknown")),
        "path": str(change.get("path", "")),
        "type": after.get("type") or before.get("type"),
        "size_before": before.get("size"),
        "size_after": after.get("size"),
    }


def _materialize_grouped(
    groups: Mapping[tuple[str, ...], Mapping[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for key in sorted(groups):
        group = groups[key]
        item = {
            name: value
            for name, value in group.items()
            if name not in {"operations", "paths"}
        }
        item["operations"] = dict(sorted(group["operations"].items()))
        item["representative_paths"] = sorted(group["paths"])[:MAX_REPRESENTATIVES]
        result.append(item)
    return result


def _coarsen_generated_groups(
    groups: list[dict[str, Any]],
    *,
    max_groups: int = MAX_LOGICAL_ROOT_GROUPS,
) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for group in groups:
        buckets[(group["scope"], group["artifact_kind"])].append(group)
    result: list[dict[str, Any]] = []
    for key in sorted(buckets):
        bucket = buckets[key]
        if len(bucket) <= max_groups:
            result.extend(bucket)
            continue
        operations: Counter[str] = Counter()
        roots: set[str] = set()
        paths: set[str] = set()
        combined = {
            "scope": key[0],
            "artifact_kind": key[1],
            "logical_root_count": 0,
            "item_count": 0,
            "unique_path_count": 0,
            "event_count": 0,
            "total_size_after": 0,
        }
        for group in bucket:
            combined["logical_root_count"] += group.get("logical_root_count", 1)
            combined["item_count"] += group.get("item_count", 0)
            combined["unique_path_count"] += group.get("unique_path_count", 0)
            combined["event_count"] += group.get("event_count", 0)
            combined["total_size_after"] += group.get("total_size_after", 0)
            operations.update(group.get("operations", {}))
            if isinstance(group.get("logical_root"), str):
                roots.add(group["logical_root"])
            roots.update(group.get("representative_logical_roots", []))
            paths.update(group.get("representative_paths", []))
        combined["operations"] = dict(sorted(operations.items()))
        combined["representative_logical_roots"] = sorted(roots)[:MAX_REPRESENTATIVES]
        combined["representative_paths"] = sorted(paths)[:MAX_REPRESENTATIVES]
        for optional in (
            "item_count",
            "unique_path_count",
            "event_count",
            "total_size_after",
        ):
            if not combined[optional]:
                combined.pop(optional)
        result.append(combined)
    return result


def group_persistent_changes(
    changes: Iterable[Mapping[str, Any]],
    *,
    repo_root: str = "/testbed",
) -> dict[str, Any]:
    material: list[dict[str, Any]] = []
    generated: dict[tuple[str, ...], dict[str, Any]] = {}
    directories: dict[tuple[str, ...], dict[str, Any]] = {}
    vcs: dict[tuple[str, ...], dict[str, Any]] = {}
    class_counts: Counter[str] = Counter()

    for raw in changes:
        fact = _change_fact(raw)
        path = fact["path"]
        operation = fact["operation"]
        absolute = _absolute(path, repo_root)
        relative = path.lstrip("/") if path.startswith("/") else path
        if relative == ".git" or relative.startswith(".git/"):
            classification = "vcs_metadata"
            kind = None
        else:
            kind = artifact_kind(absolute)
            if kind:
                classification = "generated"
            elif fact["type"] == "directory":
                classification = "directory_metadata"
            else:
                classification = "material"

        count_key = (
            f"generated:{kind}:{operation}"
            if classification == "generated"
            else f"{classification}:{operation}"
        )
        class_counts[count_key] += 1

        if classification == "material":
            material.append(fact)
            continue

        if classification == "generated":
            root = _display_root(logical_root(absolute), repo_root)
            key = ("repo", str(kind), root)
            target = generated.setdefault(key, {
                "scope": "repo",
                "artifact_kind": kind,
                "logical_root": root,
                "item_count": 0,
                "total_size_after": 0,
                "operations": Counter(),
                "paths": set(),
            })
            target["item_count"] += 1
            if isinstance(fact["size_after"], int):
                target["total_size_after"] += fact["size_after"]
        elif classification == "directory_metadata":
            key = ("repo", operation)
            target = directories.setdefault(key, {
                "scope": "repo",
                "item_count": 0,
                "operations": Counter(),
                "paths": set(),
            })
            target["item_count"] += 1
        else:
            key = ("repo", operation)
            target = vcs.setdefault(key, {
                "scope": "repo",
                "item_count": 0,
                "operations": Counter(),
                "paths": set(),
            })
            target["item_count"] += 1
        target["operations"][operation] += 1
        target["paths"].add(path)

    material.sort(key=lambda item: (item["operation"], item["path"]))
    return {
        "material_change_count": len(material),
        "material_changes": material,
        "generated_artifacts": _coarsen_generated_groups(_materialize_grouped(generated)),
        "directory_metadata": _materialize_grouped(directories),
        "vcs_metadata": _materialize_grouped(vcs),
        "class_operation_counts": dict(sorted(class_counts.items())),
    }


def _path_facts(effects: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    facts: dict[str, dict[str, Any]] = {}
    for effect in effects:
        if effect.get("category") != "file":
            continue
        operation = str(effect.get("operation", "unknown"))
        path = effect.get("path")
        if (
            not isinstance(path, str)
            or not path
            or any(
                path == sink or path.startswith(sink + "<")
                for sink in BENIGN_WRITE_SINKS
            )
            or operation not in MUTATING_OPERATIONS
            or effect.get("success") is not True
        ):
            continue
        count = _count(effect)
        fact = facts.setdefault(path, {
            "path": path,
            "operations": Counter(),
            "event_count": 0,
        })
        fact["operations"][operation] += count
        fact["event_count"] += count
    return facts


def _python_install_target(path: str) -> tuple[str, str] | None:
    """Return a deterministic Python install root and top-level component."""

    normalized = posixpath.normpath(path)
    parts = normalized.split("/")
    for marker in ("site-packages", "dist-packages"):
        if marker not in parts:
            continue
        index = parts.index(marker)
        if index + 1 >= len(parts) or not parts[index + 1]:
            return None
        return "/".join(parts[: index + 1]) or "/", parts[index + 1]
    return None


def _materialize_package_groups(
    groups: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for install_root in sorted(groups):
        group = groups[install_root]
        result.append({
            "scope": group["scope"],
            "install_root": install_root,
            "component_count": len(group["components"]),
            "unique_path_count": group["unique_path_count"],
            "event_count": group["event_count"],
            "operations": dict(sorted(group["operations"].items())),
            "representative_components": sorted(group["components"])[
                :MAX_REPRESENTATIVES
            ],
            "representative_paths": sorted(group["paths"])[:MAX_REPRESENTATIVES],
        })
    return result


def group_outside_writes(
    effects: Iterable[Mapping[str, Any]],
    *,
    repo_root: str = "/testbed",
) -> dict[str, Any]:
    material: list[dict[str, Any]] = []
    temporary: dict[tuple[str, ...], dict[str, Any]] = {}
    generated: dict[tuple[str, ...], dict[str, Any]] = {}
    packages: dict[str, dict[str, Any]] = {}

    for path, fact in sorted(_path_facts(effects).items()):
        scope, _ = classify_path(path, repo_root)
        if path == "/dev/shm" or path.startswith("/dev/shm/"):
            scope = "temp"
        if scope == "repo":
            continue
        operations = Counter(fact["operations"])
        if scope == "temp":
            key = (scope,)
            target = temporary.setdefault(key, {
                "scope": scope,
                "unique_path_count": 0,
                "event_count": 0,
                "operations": Counter(),
                "paths": set(),
            })
            target["unique_path_count"] += 1
            target["event_count"] += fact["event_count"]
            target["operations"].update(operations)
            target["paths"].add(path)
            continue

        kind = artifact_kind(path)
        if kind:
            root = logical_root(path)
            key = (scope, kind, root)
            target = generated.setdefault(key, {
                "scope": scope,
                "artifact_kind": kind,
                "logical_root": root,
                "unique_path_count": 0,
                "event_count": 0,
                "operations": Counter(),
                "paths": set(),
            })
            target["unique_path_count"] += 1
            target["event_count"] += fact["event_count"]
            target["operations"].update(operations)
            target["paths"].add(path)
            continue

        install_target = _python_install_target(path)
        if install_target:
            install_root, component = install_target
            target = packages.setdefault(install_root, {
                "scope": scope,
                "components": set(),
                "unique_path_count": 0,
                "event_count": 0,
                "operations": Counter(),
                "paths": set(),
            })
            target["components"].add(component)
            target["unique_path_count"] += 1
            target["event_count"] += fact["event_count"]
            target["operations"].update(operations)
            target["paths"].add(path)
            continue

        material.append({
            "path": path,
            "scope": scope,
            "operations": dict(sorted(operations.items())),
            "event_count": fact["event_count"],
        })

    package_groups = _materialize_package_groups(packages)
    return {
        "material_write_count": len(material) + sum(
            group["unique_path_count"] for group in package_groups
        ),
        "material_write_event_count": sum(
            item["event_count"] for item in material
        ) + sum(group["event_count"] for group in package_groups),
        "material_writes": material,
        "python_package_writes": package_groups,
        "temporary_lifecycle": _materialize_grouped(temporary),
        "runtime_generated": _coarsen_generated_groups(_materialize_grouped(generated)),
    }


def group_permission_changes(
    effects: Iterable[Mapping[str, Any]],
    *,
    repo_root: str = "/testbed",
) -> dict[str, Any]:
    groups: dict[str, dict[str, Any]] = {}
    event_count = 0
    success_count = 0
    failed_count = 0
    for effect in effects:
        if (
            effect.get("category") != "file"
            or effect.get("operation") != "permission_change"
        ):
            continue
        count = _count(effect)
        path = effect.get("path")
        scope = (
            classify_path(path, repo_root)[0]
            if isinstance(path, str) and path
            else "unknown"
        )
        group = groups.setdefault(scope, {
            "scope": scope,
            "paths": set(),
            "event_count": 0,
            "success_event_count": 0,
            "failed_event_count": 0,
        })
        event_count += count
        group["event_count"] += count
        if isinstance(path, str) and path:
            group["paths"].add(path)
        if effect.get("success") is False:
            failed_count += count
            group["failed_event_count"] += count
        else:
            success_count += count
            group["success_event_count"] += count

    by_scope = []
    for scope in sorted(groups, key=lambda item: (_PATH_SCOPE_PRIORITY.get(item, 99), item)):
        group = groups[scope]
        by_scope.append({
            "scope": scope,
            "unique_path_count": len(group["paths"]),
            "event_count": group["event_count"],
            "success_event_count": group["success_event_count"],
            "failed_event_count": group["failed_event_count"],
            "representative_paths": sorted(group["paths"])[:MAX_REPRESENTATIVES],
        })
    return {
        "event_count": event_count,
        "success_event_count": success_count,
        "failed_event_count": failed_count,
        "by_scope": by_scope,
    }


def _baseline_key(effect: Mapping[str, Any]) -> tuple[Any, ...]:
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


def _residual_effects(
    effects: Iterable[Mapping[str, Any]],
    baseline_effects: Iterable[Mapping[str, Any]],
) -> list[tuple[Mapping[str, Any], int]]:
    remaining = Counter()
    for effect in baseline_effects:
        remaining[_baseline_key(effect)] += _count(effect)
    residual: list[tuple[Mapping[str, Any], int]] = []
    for effect in effects:
        count = _count(effect)
        key = _baseline_key(effect)
        removed = min(count, remaining[key])
        remaining[key] -= removed
        if count > removed:
            residual.append((effect, count - removed))
    return residual


def _credential_facts(
    effects: Iterable[Mapping[str, Any]],
    repo_root: str,
) -> list[dict[str, Any]]:
    facts: dict[str, dict[str, Any]] = {}
    for effect in effects:
        if effect.get("category") != "file":
            continue
        for key in ("path", "source_path"):
            path = effect.get(key)
            if not isinstance(path, str) or classify_path(path, repo_root)[0] != "credentials":
                continue
            count = _count(effect)
            fact = facts.setdefault(path, {
                "path": path,
                "operations": set(),
                "event_count": 0,
                "failed_count": 0,
            })
            operation = str(effect.get("operation", "unknown"))
            fact["operations"].add(operation if key == "path" else f"source_{operation}")
            fact["event_count"] += count
            if effect.get("success") is False:
                fact["failed_count"] += count
    return [{
        **{key: value for key, value in fact.items() if key != "operations"},
        "operations": sorted(fact["operations"]),
    } for _, fact in sorted(facts.items())]


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


def _external_network(effects: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    connections: dict[tuple[Any, ...], dict[str, Any]] = {}
    for effect in effects:
        if (
            effect.get("category") != "network"
            or effect.get("operation") != "connect"
            or _network_scope(effect.get("remote_ip")) != "external"
        ):
            continue
        key = (effect.get("remote_ip"), effect.get("remote_port"), effect.get("success"))
        fact = connections.setdefault(key, {
            "ip": effect.get("remote_ip"),
            "port": effect.get("remote_port"),
            "success": effect.get("success"),
            "count": 0,
        })
        fact["count"] += _count(effect)
    return [connections[key] for key in sorted(
        connections,
        key=lambda item: (str(item[0]), item[1] if isinstance(item[1], int) else -1, str(item[2])),
    )]


def group_process_execution(
    effects: Iterable[Mapping[str, Any]],
    baseline_effects: Iterable[Mapping[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    successful: Counter[str] = Counter()
    failed: dict[tuple[str, str], dict[str, Any]] = {}
    for effect, count in _residual_effects(effects, baseline_effects):
        executable = effect.get("executable")
        if (
            effect.get("category") == "process"
            and effect.get("operation") == "exec"
            and isinstance(executable, str)
            and executable
        ):
            if effect.get("success") is True:
                successful[executable] += count
                continue
            errno = str(effect.get("errno") or "UNKNOWN")
            executable_name = posixpath.basename(posixpath.normpath(executable))
            key = (executable_name, errno)
            fact = failed.setdefault(key, {
                "executable_name": executable_name,
                "errno": errno,
                "event_count": 0,
                "paths": set(),
            })
            fact["event_count"] += count
            fact["paths"].add(executable)
    successful_executions = [
        {"executable": executable, "event_count": count}
        for executable, count in sorted(successful.items())
    ]
    failed_exec_attempts = []
    for key in sorted(failed):
        fact = failed[key]
        failure_kind = (
            "path_lookup"
            if fact["errno"] in {"ENOENT", "ENOTDIR"} and len(fact["paths"]) > 1
            else "execution_failure"
        )
        failed_exec_attempts.append({
            "executable_name": fact["executable_name"],
            "errno": fact["errno"],
            "failure_kind": failure_kind,
            "event_count": fact["event_count"],
            "attempted_path_count": len(fact["paths"]),
            "representative_paths": sorted(fact["paths"])[:MAX_REPRESENTATIVES],
        })
    return {
        "successful_executions": successful_executions,
        "failed_exec_attempts": failed_exec_attempts,
    }


def record_invariant_ledger(
    record: Mapping[str, Any],
    *,
    repo_root: str = "/testbed",
    baseline_effects: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    effects = [item for item in record.get("effects", []) if isinstance(item, Mapping)]
    persistent = [
        item for item in record.get("persistent_diff", []) if isinstance(item, Mapping)
    ]
    grouped_persistent = group_persistent_changes(persistent, repo_root=repo_root)
    grouped_outside = group_outside_writes(effects, repo_root=repo_root)
    credentials = _credential_facts(effects, repo_root)
    external = _external_network(effects)
    processes = group_process_execution(effects, baseline_effects or [])
    permissions = group_permission_changes(effects, repo_root=repo_root)
    return {
        "persistent_class_operation_counts": grouped_persistent["class_operation_counts"],
        "persistent_delete_count": sum(
            1 for change in persistent if change.get("operation") == "delete"
        ),
        "permission_changes": {
            "event_count": permissions["event_count"],
            "success_event_count": permissions["success_event_count"],
            "failed_event_count": permissions["failed_event_count"],
            "scope_counts": {
                item["scope"]: {
                    "unique_path_count": item["unique_path_count"],
                    "event_count": item["event_count"],
                    "success_event_count": item["success_event_count"],
                    "failed_event_count": item["failed_event_count"],
                }
                for item in permissions["by_scope"]
            },
        },
        "credential_event_count": sum(item["event_count"] for item in credentials),
        "credential_failed_count": sum(item["failed_count"] for item in credentials),
        "external_network_event_count": sum(item["count"] for item in external),
        "outside_material_write_count": grouped_outside["material_write_count"],
        "outside_material_write_event_count": grouped_outside["material_write_event_count"],
        "python_package_write_counts": {
            item["install_root"]: {
                "component_count": item["component_count"],
                "unique_path_count": item["unique_path_count"],
                "event_count": item["event_count"],
                "operations": item["operations"],
            }
            for item in grouped_outside["python_package_writes"]
        },
        "successful_executable_event_counts": {
            item["executable"]: item["event_count"]
            for item in processes["successful_executions"]
        },
        "failed_exec_probe_counts": {
            "|".join((item["executable_name"], item["errno"], item["failure_kind"])): {
                "event_count": item["event_count"],
                "attempted_path_count": item["attempted_path_count"],
            }
            for item in processes["failed_exec_attempts"]
        },
    }


def candidate_invariant_ledger(candidate: Mapping[str, Any]) -> dict[str, Any]:
    salient = candidate["salient_effects"]
    repo = salient["repo_persistent"]
    outside = salient["outside_repo"]
    credentials = salient["credential_accesses"]
    external = salient["external_network"]
    permissions = salient["permission_changes"]
    return {
        "persistent_class_operation_counts": repo["class_operation_counts"],
        "persistent_delete_count": salient["persistent_delete_count"],
        "permission_changes": {
            "event_count": permissions["event_count"],
            "success_event_count": permissions["success_event_count"],
            "failed_event_count": permissions["failed_event_count"],
            "scope_counts": {
                item["scope"]: {
                    "unique_path_count": item["unique_path_count"],
                    "event_count": item["event_count"],
                    "success_event_count": item["success_event_count"],
                    "failed_event_count": item["failed_event_count"],
                }
                for item in permissions["by_scope"]
            },
        },
        "credential_event_count": sum(item["event_count"] for item in credentials),
        "credential_failed_count": sum(item["failed_count"] for item in credentials),
        "external_network_event_count": sum(item["count"] for item in external),
        "outside_material_write_count": outside["material_write_count"],
        "outside_material_write_event_count": outside["material_write_event_count"],
        "python_package_write_counts": {
            item["install_root"]: {
                "component_count": item["component_count"],
                "unique_path_count": item["unique_path_count"],
                "event_count": item["event_count"],
                "operations": item["operations"],
            }
            for item in outside["python_package_writes"]
        },
        "successful_executable_event_counts": {
            item["executable"]: item["event_count"]
            for item in salient["successful_executions"]
        },
        "failed_exec_probe_counts": {
            "|".join((item["executable_name"], item["errno"], item["failure_kind"])): {
                "event_count": item["event_count"],
                "attempted_path_count": item["attempted_path_count"],
            }
            for item in salient["failed_exec_attempts"]
        },
    }


def _normalized_record(record: Mapping[str, Any], repo_root: str) -> dict[str, Any]:
    normalized = deepcopy(dict(record))
    timed_out = bool(normalized.get("timed_out"))
    traced = normalized.get("traced") if isinstance(normalized.get("traced"), Mapping) else {}
    timed_out = timed_out or bool(traced.get("timed_out"))
    normalized.setdefault("completeness", "censored_timeout" if timed_out else "complete")
    normalized.setdefault("returncode", traced.get("returncode"))
    normalized.setdefault("instance_id", normalized.get("case", "controlled"))
    normalized.setdefault("action_index", None)
    metrics = normalized.get("metrics") if isinstance(normalized.get("metrics"), Mapping) else {}
    metrics = dict(metrics)
    if "execution_ms" not in metrics and isinstance(metrics.get("traced_ms"), (int, float)):
        metrics["execution_ms"] = metrics["traced_ms"]
    normalized["metrics"] = metrics
    normalized.setdefault("coverage", {
        "execution_complete": not timed_out,
        "raw_trace_complete": not timed_out,
        "effect_detail_complete": not timed_out,
        "aggregation_mode": "full",
        "persistent_diff_roots": [repo_root],
    })
    return normalized


def _drop_detail_tier(candidate: dict[str, Any]) -> bool:
    """Drop one deterministic detail tier without changing aggregate ledgers.

    Oversized real actions can contain thousands of material paths. Removing one
    path and reserializing after every removal makes bounding quadratic. A tier
    is expendable representative detail, so clear it in one operation and
    remeasure at most once per tier.
    """

    salient = candidate["salient_effects"]
    repo = salient["repo_persistent"]
    outside = salient["outside_repo"]
    collections = [
        candidate["resource_summary"].get("representative_observed_paths", []),
        candidate["runtime_background"].get("representative_paths", []),
    ]
    grouped = [
        outside["runtime_generated"],
        repo["generated_artifacts"],
        repo["directory_metadata"],
        repo["vcs_metadata"],
        outside["temporary_lifecycle"],
        outside["python_package_writes"],
        salient["failed_exec_attempts"],
        salient["permission_changes"]["by_scope"],
    ]
    for values in collections:
        if values:
            values.clear()
            return True
    for values in grouped:
        changed = False
        for group in reversed(values):
            for key in (
                "representative_paths",
                "representative_logical_roots",
                "representative_components",
            ):
                representatives = group.get(key, [])
                if representatives:
                    representatives.clear()
                    changed = True
        if changed:
            return True
    for values in (outside["runtime_generated"], repo["generated_artifacts"]):
        if len(values) > 1:
            coarsened = _coarsen_generated_groups(values, max_groups=1)
            if coarsened != values:
                values[:] = coarsened
                return True
    for key, count_key in (
        (repo["material_changes"], "material_change_count"),
        (outside["material_writes"], "material_write_count"),
    ):
        if key:
            key.clear()
            candidate["summary_detail_truncated"] = True
            return True
    return False


def build_candidate_effect(
    record: Mapping[str, Any],
    *,
    repo_root: str = "/testbed",
    baseline_effects: Iterable[Mapping[str, Any]] | None = None,
    baseline_status: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    baseline = list(baseline_effects or [])
    normalized = _normalized_record(record, repo_root)
    base = build_structured_effect(
        normalized,
        repo_root=repo_root,
        baseline_effects=baseline,
    )
    base["resource_summary"]["representative_observed_paths"] = base[
        "resource_summary"
    ]["representative_observed_paths"][:MAX_REPRESENTATIVES]
    base["runtime_background"]["representative_paths"] = base[
        "runtime_background"
    ]["representative_paths"][:MAX_REPRESENTATIVES]
    effects = [item for item in normalized.get("effects", []) if isinstance(item, Mapping)]
    persistent = [
        item for item in normalized.get("persistent_diff", []) if isinstance(item, Mapping)
    ]
    repo_grouped = group_persistent_changes(persistent, repo_root=repo_root)
    outside_grouped = group_outside_writes(effects, repo_root=repo_root)
    expected = record_invariant_ledger(
        normalized,
        repo_root=repo_root,
        baseline_effects=baseline,
    )
    ledger_digest = hashlib.sha256(
        json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    processes = group_process_execution(effects, baseline)
    candidate = {
        "schema_version": "effect-candidates/1.0",
        "instance_id": normalized.get("instance_id"),
        "action_index": normalized.get("action_index"),
        "action_id": normalized.get("action_id"),
        "execution": base["execution"],
        "salient_effects": {
            "repo_persistent": repo_grouped,
            "outside_repo": outside_grouped,
            "credential_accesses": _credential_facts(effects, repo_root),
            "external_network": _external_network(effects),
            "successful_executions": processes["successful_executions"],
            "failed_exec_attempts": processes["failed_exec_attempts"],
            "persistent_delete_count": expected["persistent_delete_count"],
            "permission_changes": group_permission_changes(
                effects,
                repo_root=repo_root,
            ),
        },
        "resource_summary": base["resource_summary"],
        "runtime_background": base["runtime_background"],
        "generic_signals": base["generic_signals"],
        "coverage": {
            **base["coverage"],
            "baseline_status": baseline_status or ("available" if baseline else "unavailable"),
        },
        "summary_detail_truncated": False,
        "preservation": {
            "ledger_sha256": "sha256:" + ledger_digest,
            "invariants_match": False,
        },
    }
    metadata = dict(metadata or {})
    overlap = set(candidate).intersection(metadata)
    if overlap:
        raise ValueError(f"candidate metadata conflicts with fixed fields: {sorted(overlap)}")
    candidate.update(metadata)
    candidate["preservation"]["invariants_match"] = (
        expected == candidate_invariant_ledger(candidate)
    )
    if not candidate["preservation"]["invariants_match"]:
        raise ValueError("candidate invariant mismatch before size bounding")

    while serialized_bytes(candidate) > MAX_CANDIDATE_BYTES:
        candidate["summary_detail_truncated"] = True
        if not _drop_detail_tier(candidate):
            raise ValueError("candidate fixed fields exceed 16 KiB")

    if expected != candidate_invariant_ledger(candidate):
        raise ValueError("candidate invariant mismatch after size bounding")
    return candidate

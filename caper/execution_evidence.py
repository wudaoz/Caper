"""Bounded, policy-free execution evidence derived from the raw traced effects."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import posixpath
from copy import deepcopy
from typing import Any, Iterable, Mapping

from .effect_candidates import (
    _drop_detail_tier,
    _residual_effects,
    build_candidate_effect,
    serialized_bytes,
)


MAX_EXECUTION_RECORD_BYTES = 16 * 1024
MAX_EXECUTION_EVIDENCE_BYTES = 8 * 1024
MAX_ARGV_ITEMS = 16
MAX_ARG_CHARS = 160


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


def _under(path: str, root: str) -> bool:
    normalized_path = posixpath.normpath(path)
    normalized_root = posixpath.normpath(root)
    return normalized_path == normalized_root or normalized_path.startswith(normalized_root + "/")


def _process_ref_for_pid(
    pid: Any,
    current_by_pid: Mapping[int, str],
    parent_by_pid: Mapping[int, int],
) -> str | None:
    if not isinstance(pid, int):
        return None
    seen: set[int] = set()
    current = pid
    while current not in seen:
        seen.add(current)
        if current in current_by_pid:
            return current_by_pid[current]
        if current not in parent_by_pid:
            return None
        current = parent_by_pid[current]
    return None


def _root_ref(process_ref: str | None, parents: Mapping[str, str | None]) -> str | None:
    if process_ref is None:
        return None
    seen: set[str] = set()
    current = process_ref
    while current not in seen:
        seen.add(current)
        parent = parents.get(current)
        if parent is None:
            return current
        current = parent
    return current


def _counts(observed: int, included: int) -> dict[str, int]:
    return {
        "observed": observed,
        "included": included,
        "omitted": max(0, observed - included),
    }


def build_execution_evidence(
    record: Mapping[str, Any],
    *,
    repo_root: str = "/testbed",
    baseline_effects: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return unbounded execution facts with process-tree correlations.

    Correlation means the facts occurred in the same observed process subtree;
    it does not claim byte-level information flow.
    """

    effects = [item for item in record.get("effects", []) if isinstance(item, Mapping)]
    residual = []
    for effect, count in _residual_effects(effects, baseline_effects or []):
        item = deepcopy(dict(effect))
        item["count"] = count
        residual.append(item)

    parent_by_pid: dict[int, int] = {}
    for effect in effects:
        if (
            effect.get("category") == "process"
            and effect.get("operation") == "spawn"
            and isinstance(effect.get("pid"), int)
            and isinstance(effect.get("parent_pid"), int)
        ):
            parent_by_pid[effect["pid"]] = effect["parent_pid"]

    processes: list[dict[str, Any]] = []
    current_by_pid: dict[int, str] = {}
    parents: dict[str, str | None] = {}
    network_attempts: list[dict[str, Any]] = []
    workspace_accesses: list[dict[str, Any]] = []

    for effect in residual:
        category = effect.get("category")
        operation = effect.get("operation")
        pid = effect.get("pid")
        if category == "process" and operation == "exec" and effect.get("success") is True:
            process_ref = f"p{len(processes) + 1}"
            parent_pid = effect.get("parent_pid")
            if not isinstance(parent_pid, int) and isinstance(pid, int):
                parent_pid = parent_by_pid.get(pid)
            parent_ref = current_by_pid.get(parent_pid) if isinstance(parent_pid, int) else None
            previous_ref = current_by_pid.get(pid) if isinstance(pid, int) else None
            node = {
                "process_ref": process_ref,
                "parent_ref": parent_ref,
                "replaces_ref": previous_ref,
                "executable": effect.get("executable"),
                "argv": list(effect.get("argv") or []),
                "event_count": effect.get("count", 1),
            }
            processes.append(node)
            parents[process_ref] = parent_ref
            if isinstance(pid, int):
                current_by_pid[pid] = process_ref
            continue

        process_ref = _process_ref_for_pid(pid, current_by_pid, parent_by_pid)
        # The trace parser classifies every connect(2), including
        # AF_UNIX name-service IPC, as a network event.  Only retain connects
        # with an Internet address family or an observed remote endpoint.
        is_inet_connect = (
            effect.get("address_family") in {"AF_INET", "AF_INET6"}
            or effect.get("remote_ip") is not None
            or effect.get("remote_port") is not None
        )
        if category == "network" and operation == "connect" and is_inet_connect:
            network_attempts.append({
                "process_ref": process_ref,
                "executable": effect.get("executable"),
                "remote_ip": effect.get("remote_ip"),
                "remote_port": effect.get("remote_port"),
                "scope": _network_scope(effect.get("remote_ip")),
                "success": effect.get("success"),
                "errno": effect.get("errno"),
                "event_count": effect.get("count", 1),
            })
            continue

        path = effect.get("path")
        if (
            category == "file"
            and isinstance(path, str)
            and _under(path, repo_root)
            and effect.get("success") is True
        ):
            workspace_accesses.append({
                "process_ref": process_ref,
                "operation": operation,
                "path": path,
                "event_count": effect.get("count", 1),
            })

    network_roots = {
        root
        for root in (_root_ref(item["process_ref"], parents) for item in network_attempts)
        if root is not None
    }
    correlated = [
        item
        for item in workspace_accesses
        if _root_ref(item["process_ref"], parents) in network_roots
    ]
    canonical = {
        "processes": processes,
        "network_attempts": network_attempts,
        "correlated_workspace_file_accesses": correlated,
    }
    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        **canonical,
        "counts": {
            "processes": _counts(len(processes), len(processes)),
            "network_attempts": _counts(len(network_attempts), len(network_attempts)),
            "correlated_workspace_file_accesses": _counts(len(correlated), len(correlated)),
        },
        "source_facts_sha256": "sha256:" + digest,
        "correlation_semantics": "same_observed_process_subtree_not_byte_level_flow",
        "summary_detail_truncated": False,
    }


def _bound_argv(node: dict[str, Any]) -> None:
    argv = [str(item) for item in node.get("argv", [])]
    digest = hashlib.sha256(
        json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    included = argv[:MAX_ARGV_ITEMS]
    truncated_values = 0
    bounded: list[str] = []
    for value in included:
        if len(value) > MAX_ARG_CHARS:
            bounded.append(value[: MAX_ARG_CHARS - 3] + "...")
            truncated_values += 1
        else:
            bounded.append(value)
    node["argv"] = bounded
    node["argv_observed_count"] = len(argv)
    node["argv_included_count"] = len(bounded)
    node["argv_omitted_count"] = len(argv) - len(bounded)
    node["argv_truncated_value_count"] = truncated_values
    node["argv_sha256"] = "sha256:" + digest


def _refresh_evidence_counts(
    evidence: dict[str, Any], observed: Mapping[str, int]
) -> None:
    keys = (
        "processes",
        "network_attempts",
        "correlated_workspace_file_accesses",
    )
    evidence["counts"] = {
        key: _counts(observed[key], len(evidence[key]))
        for key in keys
    }
    evidence["summary_detail_truncated"] = any(
        value["omitted"] > 0 for value in evidence["counts"].values()
    ) or any(
        item.get("argv_omitted_count", 0) > 0
        or item.get("argv_truncated_value_count", 0) > 0
        for item in evidence["processes"]
    )
    included_refs = {item.get("process_ref") for item in evidence["processes"]}
    for item in evidence["processes"]:
        item.pop("parent_omitted", None)
        item.pop("replaced_process_omitted", None)
        if item.get("parent_ref") is not None and item.get("parent_ref") not in included_refs:
            item["parent_omitted"] = True
        if item.get("replaces_ref") is not None and item.get("replaces_ref") not in included_refs:
            item["replaced_process_omitted"] = True
    for collection in (
        evidence["network_attempts"],
        evidence["correlated_workspace_file_accesses"],
    ):
        for item in collection:
            item.pop("process_omitted", None)
            if item.get("process_ref") is not None and item.get("process_ref") not in included_refs:
                item["process_omitted"] = True


def _shrink_execution_evidence(
    evidence: dict[str, Any], observed: Mapping[str, int]
) -> bool:
    files = evidence["correlated_workspace_file_accesses"]
    if files:
        files.pop()
        _refresh_evidence_counts(evidence, observed)
        return True

    network_refs = {
        item.get("process_ref")
        for item in evidence["network_attempts"]
        if item.get("process_ref")
    }
    processes = evidence["processes"]
    for index in range(len(processes) - 1, -1, -1):
        if processes[index].get("process_ref") not in network_refs:
            processes.pop(index)
            _refresh_evidence_counts(evidence, observed)
            return True
    if processes:
        processes.pop()
        _refresh_evidence_counts(evidence, observed)
        return True
    if evidence["network_attempts"]:
        evidence["network_attempts"].pop()
        _refresh_evidence_counts(evidence, observed)
        return True
    return False


def bound_execution_evidence(
    evidence: Mapping[str, Any], *, max_bytes: int = MAX_EXECUTION_EVIDENCE_BYTES
) -> dict[str, Any]:
    bounded = deepcopy(dict(evidence))
    observed = {
        key: int(bounded["counts"][key]["observed"])
        for key in (
            "processes",
            "network_attempts",
            "correlated_workspace_file_accesses",
        )
    }
    for node in bounded["processes"]:
        _bound_argv(node)
    _refresh_evidence_counts(bounded, observed)
    while serialized_bytes(bounded) > max_bytes:
        if not _shrink_execution_evidence(bounded, observed):
            raise ValueError("fixed execution evidence exceeds size budget")
    return bounded


def build_execution_record(
    record: Mapping[str, Any],
    *,
    repo_root: str = "/testbed",
    baseline_effects: Iterable[Mapping[str, Any]] | None = None,
    baseline_status: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Attach bounded execution evidence to an unchanged effect candidate."""

    baseline = list(baseline_effects or [])
    candidate = build_candidate_effect(
        record,
        repo_root=repo_root,
        baseline_effects=baseline,
        baseline_status=baseline_status,
        metadata=metadata,
    )
    candidate["schema_version"] = "execution-record/1.0"
    evidence = build_execution_evidence(
        record, repo_root=repo_root, baseline_effects=baseline
    )
    candidate["execution_evidence"] = bound_execution_evidence(evidence)
    while serialized_bytes(candidate) > MAX_EXECUTION_RECORD_BYTES and _drop_detail_tier(candidate):
        candidate["summary_detail_truncated"] = True
    observed = {
        key: value["observed"]
        for key, value in candidate["execution_evidence"]["counts"].items()
    }
    while serialized_bytes(candidate) > MAX_EXECUTION_RECORD_BYTES:
        if not _shrink_execution_evidence(candidate["execution_evidence"], observed):
            raise ValueError("fixed execution-record fields exceed 16 KiB")
        candidate["summary_detail_truncated"] = True
    if any(
        counts["included"] + counts["omitted"] != counts["observed"]
        for counts in candidate["execution_evidence"]["counts"].values()
    ):
        raise ValueError("execution evidence count mismatch")
    return candidate

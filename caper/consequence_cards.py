"""Compact, policy-free consequence cards derived from observed action effects."""

from __future__ import annotations

import json
import posixpath
from collections import defaultdict
from copy import deepcopy
from typing import Any, Iterable, Mapping

from .observed_facts import extract_canonical_observed_facts
from .effect_summary import classify_path


SCHEMA_VERSION = "consequence-cards/1.0"
TARGET_BYTES = 4 * 1024
MAX_BYTES = 8 * 1024
_READ_OPERATIONS = {"open_read", "open_readwrite", "read"}
_RUNTIME_NOISE_PREFIXES = (
    "/lib/",
    "/usr/lib/",
    "/usr/local/lib/",
    "/usr/share/locale/",
    "/proc/",
    "/dev/",
)
_RUNTIME_NOISE_PATHS = {"/etc/ld.so.cache", "/usr/share/locale/locale.alias"}
_CREDENTIAL_PARTS = {".aws", ".docker", ".gnupg", ".kube", ".ssh"}


def _encoded(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _at(value: Mapping[str, Any], fallback: int = 0) -> float:
    raw = value.get("first_seen", value.get("timestamp", fallback))
    return float(raw) if isinstance(raw, (int, float)) else float(fallback)


def _output_events(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    effects = record.get("effects")
    raw = effects if isinstance(effects, list) else []
    result: list[dict[str, Any]] = []
    for ordinal, effect in enumerate(raw, 1):
        if not isinstance(effect, Mapping):
            continue
        channel = effect.get("channel")
        if (
            effect.get("category") != "io"
            or effect.get("operation") != "write_output"
            or effect.get("success") is not True
            or effect.get("pid") == 0
            or channel not in {"stdout", "stderr"}
        ):
            continue
        result.append(
            {
                "pid": effect.get("pid"),
                "channel": str(channel),
                "bytes": int(effect.get("bytes") or 0),
                "event_count": int(effect.get("count", 1)),
                "observed_at": _at(effect, ordinal),
            }
        )
    return result


def _actor_for_pid(
    pid: object,
    at: float,
    processes: list[Mapping[str, Any]],
    parent_by_pid: Mapping[int, int],
) -> Mapping[str, Any] | None:
    if not isinstance(pid, int):
        return None
    current = pid
    seen: set[int] = set()
    while current not in seen:
        seen.add(current)
        candidates = [
            item
            for item in processes
            if item.get("pid") == current
            and float(item.get("observed_at", 0)) <= at
        ]
        actor = max(
            candidates,
            key=lambda item: float(item.get("observed_at", 0)),
            default=None,
        )
        if actor is not None:
            return actor
        parent = parent_by_pid.get(current)
        if parent is None:
            return None
        current = parent
    return None


def resource_traits(path: str) -> list[str]:
    normalized = posixpath.normpath(path).lower()
    basename = posixpath.basename(normalized)
    parts = set(normalized.split("/"))
    traits: set[str] = set()
    if basename == ".env" or basename.startswith(".env.") or basename.endswith(".env"):
        traits.add("dotenv")
    if parts.intersection(_CREDENTIAL_PARTS):
        traits.add("credential_store")
    if (basename.startswith("id_") and not basename.endswith(".pub")) or basename.endswith(
        ".key"
    ):
        traits.add("private_key_candidate")
    return sorted(traits)


def is_runtime_noise(path: str) -> bool:
    normalized = posixpath.normpath(path)
    return normalized in _RUNTIME_NOISE_PATHS or normalized.startswith(
        _RUNTIME_NOISE_PREFIXES
    )


def _source_is_relevant(
    source: Mapping[str, Any], *, consequence_actor_ref: str | None
) -> bool:
    path = str(source.get("path") or "")
    traits = resource_traits(path)
    if source.get("success") is not True:
        return False
    if consequence_actor_ref is None or source.get("actor_ref") != consequence_actor_ref:
        return False
    return bool(
        source.get("scope") in {"repo", "credentials"}
        or traits
        or (source.get("scope") == "system" and not is_runtime_noise(path))
    )


def _public_source(source: Mapping[str, Any]) -> dict[str, Any]:
    path = str(source.get("path") or "")
    return {
        "path": path,
        "scope": source.get("scope"),
        "operation": source.get("operation"),
        "resource_traits": resource_traits(path),
        "basis": "same_actor_read_before_consequence",
    }


def _relevant_sources(
    canonical: Mapping[str, Any], *, actor_ref: str | None, observed_at: float
) -> list[dict[str, Any]]:
    selected: dict[tuple[Any, ...], dict[str, Any]] = {}
    for source in canonical.get("file_facts", []):
        if (
            source.get("operation") not in _READ_OPERATIONS
            or float(source.get("observed_at", 0)) > observed_at
            or not _source_is_relevant(
                source, consequence_actor_ref=actor_ref
            )
        ):
            continue
        public = _public_source(source)
        key = (
            public["path"],
            public["scope"],
            public["operation"],
            tuple(public["resource_traits"]),
        )
        selected[key] = public
    return [selected[key] for key in sorted(selected)]


def _aggregate_output_writes(
    record: Mapping[str, Any], canonical: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Aggregate observable stdout/stderr writes without retaining payload text."""

    events = _output_events(record)
    totals: dict[str, dict[str, int]] = defaultdict(
        lambda: {"bytes": 0, "event_count": 0}
    )
    relevant: dict[tuple[Any, ...], dict[str, Any]] = {}
    processes = [
        item for item in canonical.get("processes", []) if item.get("pid") != 0
    ]
    parent_by_pid = canonical.get("parent_by_pid") or {}
    for event in events:
        channel = event["channel"]
        totals[channel]["bytes"] += event["bytes"]
        totals[channel]["event_count"] += event["event_count"]
        actor = _actor_for_pid(
            event.get("pid"), event["observed_at"], processes, parent_by_pid
        )
        actor_ref = str(actor["fact_id"]) if actor is not None else None
        for source in _relevant_sources(
            canonical, actor_ref=actor_ref, observed_at=event["observed_at"]
        ):
            key = (
                source["path"],
                source["scope"],
                source["operation"],
                tuple(source["resource_traits"]),
            )
            relevant[key] = source

    if not totals:
        return []
    channels = sorted(totals)
    return [
        {
            "type": "user_output",
            "status": "observed",
            "channels": channels,
            "bytes": sum(totals[channel]["bytes"] for channel in channels),
            "event_count": sum(
                totals[channel]["event_count"] for channel in channels
            ),
            "relevant_sources": [relevant[key] for key in sorted(relevant)],
        }
    ]


def _actor_summary(
    canonical: Mapping[str, Any], actor_ref: object
) -> dict[str, Any] | None:
    if not isinstance(actor_ref, str):
        return None
    actor = next(
        (
            item
            for item in canonical.get("processes", [])
            if item.get("fact_id") == actor_ref
        ),
        None,
    )
    if actor is None:
        return None
    result: dict[str, Any] = {}
    if actor.get("executable"):
        result["executable"] = actor["executable"]
    if actor.get("argv"):
        result["argv"] = list(actor["argv"])
    return result or None


def _endpoint_kind(remote_ip: object, scope: object) -> str:
    if remote_ip in {None, "", "0.0.0.0", "::", "::0"}:
        return "unspecified"
    if scope == "loopback":
        return "loopback"
    if scope == "private":
        return "private"
    if scope == "external":
        return "external"
    return "unknown"


def _network_cards(canonical: Mapping[str, Any]) -> list[dict[str, Any]]:
    cards: list[dict[str, Any]] = []
    for network in canonical.get("network_attempts", []):
        actor_ref = network.get("actor_ref")
        relevant_sources = _relevant_sources(
            canonical,
            actor_ref=str(actor_ref) if actor_ref is not None else None,
            observed_at=float(network.get("observed_at", 0)),
        )
        actor = _actor_summary(canonical, actor_ref)
        target = {
            "address_family": network.get("address_family"),
            "ip": network.get("remote_ip"),
            "port": network.get("remote_port"),
            "scope": network.get("scope"),
            "endpoint_kind": _endpoint_kind(
                network.get("remote_ip"), network.get("scope")
            ),
        }
        cards.append(
            {
                "type": "network_attempt",
                "status": "observed" if network.get("success") is True else "failed",
                "operation": "connect",
                **({"actor": actor} if actor is not None else {}),
                "target": target,
                **(
                    {"errno": network.get("errno")}
                    if network.get("errno") is not None
                    else {}
                ),
                "event_count": int(network.get("event_count", 1)),
                "relevant_sources": relevant_sources,
                "source_coverage": (
                    "observed_partial"
                    if relevant_sources
                    else "not_observed_before_failure"
                    if network.get("success") is False
                    else "none_observed"
                ),
            }
        )
    return cards


def _attempted_network_cards(canonical: Mapping[str, Any]) -> list[dict[str, Any]]:
    cards: list[dict[str, Any]] = []
    for attempted in canonical.get("attempted_effects", []):
        if attempted.get("category") != "network":
            continue
        cards.append(
            {
                "type": "network_attempt",
                "status": "simulated_not_executed",
                "operation": attempted.get("operation") or "network_command",
                "observed": attempted.get("observed") is True,
                "simulated_by": attempted.get("simulated_by"),
                "relevant_sources": [],
                "source_coverage": "unobservable_due_to_mock",
            }
        )
    return cards


def _execution_summary(
    record: Mapping[str, Any], consequences: list[Mapping[str, Any]]
) -> dict[str, Any]:
    coverage = record.get("coverage")
    coverage_record = coverage if isinstance(coverage, Mapping) else {}
    if any(card.get("status") == "failed" for card in consequences):
        status = "partial_failure" if record.get("returncode") == 0 else "failed"
    else:
        status = (
            "complete"
            if record.get("completeness") == "complete"
            else str(record.get("completeness") or "unknown")
        )
    return {
        "status": status,
        "wrapper_returncode": record.get("returncode"),
        "mode": record.get(
            "execution_mode", coverage_record.get("execution_mode", "unknown")
        ),
        "observed": record.get(
            "observed_execution", coverage_record.get("observed_execution")
        ),
    }


def _uncertainties(
    consequences: list[Mapping[str, Any]],
    persistent_transitions: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for card in consequences:
        if (
            card.get("type") == "network_attempt"
            and card.get("status") == "failed"
            and not card.get("relevant_sources")
            and not persistent_transitions
        ):
            result.append(
                {
                    "subject": "downstream_effects",
                    "reason": "network_attempt_failed_before_later_effects_were_observable",
                }
            )
        elif (
            card.get("type") == "network_attempt"
            and card.get("status") == "simulated_not_executed"
        ):
            result.append(
                {
                    "subject": "downstream_effects",
                    "reason": "network_command_was_mocked_so_runtime_effects_were_not_observable",
                }
            )
    for transition in persistent_transitions:
        if transition.get("status") == "observed_details_omitted":
            result.append(
                {
                    "subject": "persistent_transition_details",
                    "reason": "semantic_delta_omitted_observed_changes",
                    "omitted_count": int(transition.get("count", 1)),
                }
            )
    unique = {
        (item["subject"], item["reason"], item.get("omitted_count")): item
        for item in result
    }
    return [
        unique[key]
        for key in sorted(unique, key=lambda item: tuple(str(value) for value in item))
    ]


def _snapshot(value: Any) -> dict[str, Any]:
    source = value if isinstance(value, Mapping) else {}
    result: dict[str, Any] = {}
    if source.get("kind") is not None:
        result["kind"] = source["kind"]
    elif source.get("type") is not None:
        result["kind"] = source["type"]
    if source.get("size") is not None:
        result["bytes"] = source["size"]
    elif source.get("bytes") is not None:
        result["bytes"] = source["bytes"]
    if source.get("mode") is not None:
        result["mode"] = source["mode"]
    return result


def reclassify_persistent_transition(
    operation: str, before: Mapping[str, Any], after: Mapping[str, Any]
) -> str:
    if operation in {"create_new", "delete_existing"}:
        return operation
    before_kind = str(before.get("kind") or "unknown")
    after_kind = str(after.get("kind") or "unknown")
    kinds = {before_kind, after_kind} - {"unknown"}

    if kinds == {"directory"}:
        if before.get("mode") != after.get("mode"):
            return "modify_existing"
        return "directory_metadata_changed"

    regular_file_kinds = {"file", "regular_file"}
    if kinds and kinds.issubset(regular_file_kinds):
        if int(before.get("bytes") or 0) > 0 and after.get("bytes") == 0:
            return "truncate_existing"
    return str(operation or "state_change")


def _transition_operation(
    operation: str, before: Mapping[str, Any], after: Mapping[str, Any]
) -> str:
    if operation == "create" and not before and after:
        return "create_new"
    if operation == "delete" and before and not after:
        return "delete_existing"
    if operation in {"modify", "write"} and before and after:
        operation = "modify_existing"
    return reclassify_persistent_transition(operation, before, after)


def _semantic_transitions(
    semantic_delta: Mapping[str, Any] | None, *, repo_root: str
) -> list[dict[str, Any]]:
    semantic = semantic_delta if isinstance(semantic_delta, Mapping) else {}
    result: list[dict[str, Any]] = []
    changes = semantic.get("changes")
    raw_changes = changes if isinstance(changes, list) else []
    for change in raw_changes:
        if not isinstance(change, Mapping):
            continue
        raw_path = str(change.get("path") or "")
        if not raw_path:
            continue
        path = posixpath.normpath(
            raw_path
            if raw_path.startswith("/")
            else posixpath.join(repo_root, raw_path)
        )
        before = _snapshot(change.get("before"))
        after = _snapshot(change.get("after"))
        if not before:
            before = _snapshot(
                {
                    "size": change.get("before_size"),
                    "type": change.get("before_type"),
                    "mode": change.get("before_mode"),
                }
            )
        if not after:
            after = _snapshot(
                {
                    "size": change.get("after_size"),
                    "type": change.get("after_type"),
                    "mode": change.get("after_mode"),
                }
            )
        scope, _ = classify_path(path, repo_root)
        traits = resource_traits(path)
        transition = {
            "type": (
                "protected_control_transition" if traits else "file_transition"
            ),
            "status": "observed",
            "operation": _transition_operation(
                str(change.get("operation") or ""), before, after
            ),
            "path": path,
            "scope": scope,
            "resource_traits": traits,
            "before": before,
            "after": after,
        }
        if change.get("content_status") is not None:
            transition["content_status"] = change["content_status"]
        result.append(transition)
    counts = semantic.get("counts")
    count_record = counts if isinstance(counts, Mapping) else {}
    omitted = count_record.get("omitted")
    omitted_count = int(omitted) if isinstance(omitted, int) and omitted > 0 else 0
    if omitted_count:
        result.append(
            {
                "type": "persistent_transition",
                "status": "observed_details_omitted",
                "operation": "unknown",
                "scope": "unknown",
                "resource_traits": [],
                "count": omitted_count,
                "detail": "semantic_delta_budget_omitted",
            }
        )
    result.sort(
        key=lambda item: (str(item.get("path") or ""), str(item["operation"]))
    )
    return result


def _complete_transition_delta(
    record: Mapping[str, Any], semantic_delta: Mapping[str, Any] | None
) -> Mapping[str, Any] | None:
    raw_persistent = record.get("persistent_diff")
    persistent = (
        [item for item in raw_persistent if isinstance(item, Mapping)]
        if isinstance(raw_persistent, list)
        else []
    )
    if not persistent:
        return semantic_delta

    semantic = semantic_delta if isinstance(semantic_delta, Mapping) else {}
    semantic_changes = semantic.get("changes")
    semantic_rows = semantic_changes if isinstance(semantic_changes, list) else []
    content_status_by_path = {
        posixpath.normpath(str(item.get("path") or "")): item.get("content_status")
        for item in semantic_rows
        if isinstance(item, Mapping)
        and item.get("path")
        and item.get("content_status") is not None
    }
    changes: list[dict[str, Any]] = []
    for item in persistent:
        change = dict(item)
        status = content_status_by_path.get(
            posixpath.normpath(str(change.get("path") or ""))
        )
        if status is not None:
            change["content_status"] = status
        changes.append(change)
    return {
        "changes": changes,
        "counts": {
            "observed": len(changes),
            "included": len(changes),
            "omitted": 0,
        },
    }


def _coverage(
    record: Mapping[str, Any],
    canonical: Mapping[str, Any],
    consequences: list[Mapping[str, Any]],
) -> dict[str, Any]:
    coverage = record.get("coverage")
    coverage_record = coverage if isinstance(coverage, Mapping) else {}
    retained_paths = {
        str(source.get("path"))
        for card in consequences
        if isinstance(card, Mapping)
        for source in (card.get("relevant_sources") or [])
        if isinstance(source, Mapping) and source.get("path")
    }
    filtered_items = sum(
        int(item.get("event_count", 1))
        for item in canonical.get("file_facts", [])
        if item.get("success") is True
        and item.get("operation") in _READ_OPERATIONS
        and str(item.get("path") or "") not in retained_paths
    )
    return {
        "observed": {
            **dict(canonical.get("counts") or {}),
            "consequences": len(consequences),
        },
        "filtered_items": filtered_items,
        "aggregated_items": 0,
        "capture_failed": {
            "raw_trace": coverage_record.get("raw_trace_complete") is False,
            "effect_detail": coverage_record.get("effect_detail_complete") is False,
        },
    }


def _source_root(source: Mapping[str, Any], *, repo_root: str) -> str:
    path = posixpath.normpath(str(source.get("path") or "/"))
    traits = set(source.get("resource_traits") or [])
    parts = path.split("/")
    if traits:
        for index, part in enumerate(parts):
            if part.lower() in _CREDENTIAL_PARTS:
                return posixpath.normpath("/".join(parts[: index + 1]) or "/")
    normalized_root = posixpath.normpath(repo_root)
    if path == normalized_root:
        return normalized_root
    prefix = normalized_root.rstrip("/") + "/"
    if path.startswith(prefix):
        relative = path[len(prefix) :]
        first = relative.split("/", 1)[0]
        return posixpath.join(normalized_root, first)
    return posixpath.dirname(path)


def _aggregate_card_sources(
    card: dict[str, Any], *, repo_root: str
) -> int:
    sources = card.get("relevant_sources")
    if not isinstance(sources, list) or len(sources) < 2:
        return 0
    grouped: dict[tuple[Any, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for source in sources:
        if not isinstance(source, Mapping):
            continue
        traits = tuple(source.get("resource_traits") or [])
        key = (
            _source_root(source, repo_root=repo_root),
            source.get("scope"),
            source.get("operation"),
            traits,
            source.get("basis"),
        )
        grouped[key].append(source)

    compacted: list[dict[str, Any]] = []
    aggregated = 0
    for key in sorted(grouped, key=lambda item: tuple(str(value) for value in item)):
        root, scope, operation, traits, basis = key
        values = grouped[key]
        if len(values) == 1:
            compacted.append(dict(values[0]))
            continue
        compacted.append(
            {
                "root": root,
                "scope": scope,
                "operation": operation,
                "resource_traits": list(traits),
                "count": len(values),
                "basis": (
                    "same_actor_reads_before_consequence"
                    if basis == "same_actor_read_before_consequence"
                    else basis
                ),
            }
        )
        aggregated += len(values) - 1
    card["relevant_sources"] = compacted
    return aggregated


def _summarize_card_sources(card: dict[str, Any]) -> int:
    sources = card.get("relevant_sources")
    if not isinstance(sources, list) or not sources:
        return 0
    grouped: dict[tuple[Any, ...], int] = defaultdict(int)
    expanded_count = 0
    for source in sources:
        if not isinstance(source, Mapping):
            continue
        count = int(source.get("count", 1))
        expanded_count += count
        key = (
            source.get("scope"),
            tuple(source.get("resource_traits") or []),
        )
        grouped[key] += count
    card["relevant_sources"] = [
        {
            "scope": scope,
            "resource_traits": list(traits),
            "count": count,
        }
        for (scope, traits), count in sorted(
            grouped.items(), key=lambda item: (str(item[0][0]), item[0][1])
        )
    ]
    return max(0, expanded_count - len(card["relevant_sources"]))


def _bytes_relation(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> str:
    before_bytes = before.get("bytes")
    after_bytes = after.get("bytes")
    if before_bytes is None or after_bytes is None:
        return "unknown"
    return "unchanged" if before_bytes == after_bytes else "changed"


def _transition_state_summary(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value[key]
        for key in ("kind", "mode")
        if value.get(key) is not None
    }


def _aggregate_persistent_transitions(
    transitions: list[Mapping[str, Any]], *, repo_root: str
) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for transition in transitions:
        before = transition.get("before")
        before_state = before if isinstance(before, Mapping) else {}
        after = transition.get("after")
        after_state = after if isinstance(after, Mapping) else {}
        traits = tuple(transition.get("resource_traits") or [])
        key = (
            _source_root(transition, repo_root=repo_root),
            transition.get("type"),
            transition.get("status"),
            transition.get("operation"),
            transition.get("scope"),
            traits,
            tuple(sorted(_transition_state_summary(before_state).items())),
            tuple(sorted(_transition_state_summary(after_state).items())),
            _bytes_relation(before_state, after_state),
        )
        grouped[key].append(transition)

    result: list[dict[str, Any]] = []
    for key in sorted(grouped, key=lambda item: tuple(str(value) for value in item)):
        (
            root,
            transition_type,
            status,
            operation,
            scope,
            traits,
            before_items,
            after_items,
            bytes_relation,
        ) = key
        values = grouped[key]
        if len(values) == 1:
            result.append(dict(values[0]))
            continue
        item: dict[str, Any] = {
            "type": transition_type,
            "status": status,
            "operation": operation,
            "root": root,
            "scope": scope,
            "resource_traits": list(traits),
            "count": sum(int(value.get("count", 1)) for value in values),
            "before": dict(before_items),
            "after": dict(after_items),
            "bytes_relation": bytes_relation,
        }
        content_statuses = sorted(
            {
                str(value["content_status"])
                for value in values
                if value.get("content_status") is not None
            }
        )
        if len(content_statuses) == 1:
            item["content_status"] = content_statuses[0]
        elif content_statuses:
            item["content_statuses"] = content_statuses
        if any(value.get("content_status") is None for value in values):
            item["content_status_coverage"] = "partial"
        result.append(item)
    return result


def _summarize_persistent_transitions(
    transitions: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], int] = defaultdict(int)
    for transition in transitions:
        key = (
            transition.get("type"),
            transition.get("status"),
            transition.get("operation"),
            transition.get("scope"),
            tuple(transition.get("resource_traits") or []),
        )
        grouped[key] += int(transition.get("count", 1))
    return [
        {
            "type": transition_type,
            "status": status,
            "operation": operation,
            "scope": scope,
            "resource_traits": list(traits),
            "count": count,
            "detail": "aggregated_due_to_budget",
        }
        for (
            transition_type,
            status,
            operation,
            scope,
            traits,
        ), count in sorted(
            grouped.items(), key=lambda item: tuple(str(value) for value in item[0])
        )
    ]


def _collapsed_item_count(result: Mapping[str, Any]) -> int:
    collapsed = 0
    for card in result.get("consequences", []):
        sources = card.get("relevant_sources") if isinstance(card, Mapping) else []
        if not isinstance(sources, list):
            continue
        collapsed += max(
            0,
            sum(
                int(source.get("count", 1))
                for source in sources
                if isinstance(source, Mapping)
            )
            - len(sources),
        )
    transitions = result.get("persistent_transitions")
    transition_rows = transitions if isinstance(transitions, list) else []
    collapsed += max(
        0,
        sum(
            int(transition.get("count", 1))
            for transition in transition_rows
            if isinstance(transition, Mapping)
        )
        - len(transition_rows),
    )
    return collapsed


def _fit_to_budget(
    result: dict[str, Any], *, repo_root: str, max_bytes: int
) -> dict[str, Any]:
    fitted = deepcopy(result)
    target = min(TARGET_BYTES, max_bytes)
    if len(_encoded(fitted)) > target:
        sum(
            _aggregate_card_sources(card, repo_root=repo_root)
            for card in fitted["consequences"]
        )
        fitted["persistent_transitions"] = _aggregate_persistent_transitions(
            fitted["persistent_transitions"], repo_root=repo_root
        )
        fitted["coverage"]["aggregated_items"] = _collapsed_item_count(fitted)
    if len(_encoded(fitted)) > target:
        sum(
            _summarize_card_sources(card) for card in fitted["consequences"]
        )
        fitted["coverage"]["aggregated_items"] = _collapsed_item_count(fitted)
    if len(_encoded(fitted)) > max_bytes:
        fitted["persistent_transitions"] = _summarize_persistent_transitions(
            fitted["persistent_transitions"]
        )
        fitted["coverage"]["aggregated_items"] = _collapsed_item_count(fitted)
    if len(_encoded(fitted)) > max_bytes:
        raise ValueError("mandatory consequence-card evidence exceeds the hard budget")
    return fitted


def _set_serialized_size(result: dict[str, Any]) -> None:
    previous = None
    for _ in range(4):
        size = len(_encoded(result))
        result["budget"]["serialized_bytes"] = size
        if size == previous:
            break
        previous = size


def build_consequence_cards(
    record: Mapping[str, Any],
    *,
    repo_root: str,
    baseline_effects: Iterable[Mapping[str, Any]] = (),
    semantic_delta: Mapping[str, Any] | None = None,
    max_bytes: int = MAX_BYTES,
) -> dict[str, Any]:
    """Build a bounded approval view from observed effects only."""

    canonical = extract_canonical_observed_facts(
        record,
        repo_root=repo_root,
        baseline_effects=[
            item
            for item in baseline_effects
            if item.get("category") not in {"process", "io"}
        ],
    )
    outputs = _aggregate_output_writes(record, canonical)
    persistent_transitions = _semantic_transitions(
        _complete_transition_delta(record, semantic_delta), repo_root=repo_root
    )
    consequences = outputs + _network_cards(canonical) + _attempted_network_cards(canonical)
    coverage = _coverage(record, canonical, consequences)
    coverage["observed"]["persistent_transitions"] = sum(
        int(transition.get("count", 1)) for transition in persistent_transitions
    )
    result = {
        "schema_version": SCHEMA_VERSION,
        "action_id": record.get("action_id"),
        "action_index": record.get("action_index"),
        "execution": _execution_summary(record, consequences),
        "consequences": consequences,
        "persistent_transitions": persistent_transitions,
        "uncertainties": _uncertainties(consequences, persistent_transitions),
        "coverage": coverage,
        "budget": {
            "target_bytes": TARGET_BYTES,
            "max_bytes": max_bytes,
            "serialized_bytes": 0,
        },
    }
    fitted = _fit_to_budget(result, repo_root=repo_root, max_bytes=max_bytes)
    _set_serialized_size(fitted)
    if len(_encoded(fitted)) > max_bytes:
        raise ValueError("mandatory consequence-card evidence exceeds the hard budget")
    return fitted

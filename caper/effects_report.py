"""Bounded approval evidence for observed security boundary events."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .observed_facts import extract_canonical_observed_facts
from .consequence_cards import (
    _READ_OPERATIONS,
    _encoded,
    _fit_to_budget,
    _set_serialized_size,
    build_consequence_cards,
    resource_traits,
)
from .sensitive_output import detect_sensitive_output_classes


SCHEMA_VERSION = "effects-report/1.0"


def _protected_read_cards(canonical: Mapping[str, Any]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], dict[str, Any]] = {}
    for fact in canonical.get("file_facts", []):
        if (
            not isinstance(fact, Mapping)
            or fact.get("operation") not in _READ_OPERATIONS
            or fact.get("success") is not True
        ):
            continue
        path = str(fact.get("path") or "")
        traits = resource_traits(path)
        if not path or not traits:
            continue
        key = (
            str(fact.get("operation")),
            path,
            str(fact.get("scope") or "unknown"),
            tuple(traits),
        )
        event_count = int(fact.get("event_count", 1))
        if key not in grouped:
            grouped[key] = {
                "type": "protected_read",
                "status": "observed",
                "operation": key[0],
                "path": path,
                "scope": key[2],
                "resource_traits": traits,
                "event_count": event_count,
            }
        else:
            grouped[key]["event_count"] += event_count
    return [grouped[key] for key in sorted(grouped)]


def _filtered_read_count(
    canonical: Mapping[str, Any], consequences: list[Mapping[str, Any]]
) -> int:
    retained_paths = {
        str(card.get("path"))
        for card in consequences
        if card.get("type") == "protected_read" and card.get("path")
    }
    retained_paths.update(
        str(source.get("path"))
        for card in consequences
        for source in (card.get("relevant_sources") or [])
        if isinstance(source, Mapping) and source.get("path")
    )
    return sum(
        int(fact.get("event_count", 1))
        for fact in canonical.get("file_facts", [])
        if isinstance(fact, Mapping)
        and fact.get("success") is True
        and fact.get("operation") in _READ_OPERATIONS
        and str(fact.get("path") or "") not in retained_paths
    )


def build_effects_report(
    record: Mapping[str, Any],
    *,
    repo_root: str,
    baseline_effects: Iterable[Mapping[str, Any]] = (),
    semantic_delta: Mapping[str, Any] | None = None,
    observed_output: str | None = None,
    max_bytes: int = 8 * 1024,
) -> dict[str, Any]:
    """Build a closed READ/DISCLOSE/NETWORK/PERSIST boundary representation."""

    baseline = [
        item
        for item in baseline_effects
        if item.get("category") not in {"process", "io"}
    ]
    canonical = extract_canonical_observed_facts(
        record,
        repo_root=repo_root,
        baseline_effects=baseline,
    )
    result = build_consequence_cards(
        record,
        repo_root=repo_root,
        baseline_effects=baseline_effects,
        semantic_delta=semantic_delta,
        max_bytes=max_bytes,
    )
    protected_reads = _protected_read_cards(canonical)
    result["schema_version"] = SCHEMA_VERSION
    result["consequences"] = protected_reads + list(result.get("consequences") or [])
    sensitive_classes = detect_sensitive_output_classes(observed_output)
    if sensitive_classes:
        output_card = next(
            (
                card
                for card in result["consequences"]
                if isinstance(card, dict) and card.get("type") == "user_output"
            ),
            None,
        )
        if output_card is not None:
            output_card["sensitive_data"] = {
                "classes": sensitive_classes,
                "evidence": "credential_value_pattern_in_observed_output",
                "values_retained": False,
            }
    result["coverage"]["observed"]["protected_reads"] = sum(
        int(card.get("event_count", 1)) for card in protected_reads
    )
    result["coverage"]["observed"]["consequences"] = len(result["consequences"])
    result["coverage"]["filtered_items"] = _filtered_read_count(
        canonical, result["consequences"]
    )
    result["budget"]["serialized_bytes"] = 0
    fitted = _fit_to_budget(result, repo_root=repo_root, max_bytes=max_bytes)
    _set_serialized_size(fitted)
    if len(_encoded(fitted)) > max_bytes:
        raise ValueError("mandatory effects-report evidence exceeds the hard budget")
    return fitted

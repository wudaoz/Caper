"""Deterministic, bounded content deltas for speculative repository changes."""

from __future__ import annotations

import difflib
import hashlib
import json
import posixpath
from copy import deepcopy
from typing import Any, Mapping, Sequence


MAX_CAPTURE_BYTES_PER_FILE = 64 * 1024
MAX_CHANGE_ITEMS = 32
MAX_SEMANTIC_DELTA_BYTES = 8 * 1024

_SENSITIVE_BASENAMES = {
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
}
_SENSITIVE_COMPONENTS = {".aws", ".gnupg", ".ssh"}
_SENSITIVE_SUFFIXES = {".key", ".p12", ".pfx", ".pem"}


def _serialized_bytes(value: Mapping[str, Any]) -> int:
    return len(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _normalized_relative_path(path: Any) -> str | None:
    if not isinstance(path, str) or not path or path.startswith("/"):
        return None
    normalized = posixpath.normpath(path)
    if normalized in {"", ".", ".."} or normalized.startswith("../"):
        return None
    return normalized


def is_sensitive_path(path: str) -> bool:
    """Return a high-precision content-redaction decision, not a risk label."""

    normalized = _normalized_relative_path(path)
    if normalized is None:
        return True
    components = [part.lower() for part in normalized.split("/")]
    basename = components[-1]
    return bool(
        basename == ".env"
        or basename.startswith(".env.")
        or basename in _SENSITIVE_BASENAMES
        or any(part in _SENSITIVE_COMPONENTS for part in components)
        or any(basename.endswith(suffix) for suffix in _SENSITIVE_SUFFIXES)
        or "private_key" in basename
    )


def _is_regular_file_change(change: Mapping[str, Any]) -> bool:
    return any(
        isinstance(value, Mapping) and value.get("type") == "file"
        for value in (change.get("before"), change.get("after"))
    )


def capture_paths_for_changes(
    persistent_diff: Sequence[Mapping[str, Any]],
) -> list[str]:
    paths = {
        normalized
        for change in persistent_diff
        if _is_regular_file_change(change)
        and (normalized := _normalized_relative_path(change.get("path"))) is not None
        and not is_sensitive_path(normalized)
    }
    return sorted(paths)


def _manifest_metadata(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    allowed = ("type", "size", "mode", "uid", "gid", "sha256", "target")
    return {key: deepcopy(value[key]) for key in allowed if key in value}


def _version_status(
    operation: str,
    before: Mapping[str, Any] | None,
    after: Mapping[str, Any] | None,
) -> str:
    required = []
    if operation != "create":
        required.append(before)
    if operation != "delete":
        required.append(after)
    statuses = [item.get("status") if isinstance(item, Mapping) else None for item in required]
    if statuses and all(status == "text" for status in statuses):
        return "text_diff"
    for status in ("binary", "oversized", "non_regular"):
        if status in statuses:
            return status
    return "unavailable"


def _unified_diff(
    path: str,
    operation: str,
    before: Mapping[str, Any] | None,
    after: Mapping[str, Any] | None,
) -> str:
    before_text = "" if operation == "create" else str((before or {}).get("content", ""))
    after_text = "" if operation == "delete" else str((after or {}).get("content", ""))
    before_name = "/dev/null" if operation == "create" else f"a/{path}"
    after_name = "/dev/null" if operation == "delete" else f"b/{path}"
    lines = difflib.unified_diff(
        before_text.splitlines(),
        after_text.splitlines(),
        fromfile=before_name,
        tofile=after_name,
        lineterm="",
    )
    return "\n".join(lines) + "\n"


def _change_item(
    change: Mapping[str, Any],
    before_versions: Mapping[str, Mapping[str, Any]],
    after_versions: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any] | None:
    path = _normalized_relative_path(change.get("path"))
    operation = str(change.get("operation", ""))
    if path is None or operation not in {"create", "modify", "delete"}:
        return None
    item: dict[str, Any] = {
        "operation": operation,
        "path": path,
        "before": _manifest_metadata(change.get("before")),
        "after": _manifest_metadata(change.get("after")),
    }
    if is_sensitive_path(path):
        item["content_status"] = "redacted_sensitive_target"
        return item
    if not _is_regular_file_change(change):
        item["content_status"] = "non_regular"
        return item

    before = before_versions.get(path)
    after = after_versions.get(path)
    content_status = _version_status(operation, before, after)
    item["content_status"] = content_status
    if content_status == "text_diff":
        diff = _unified_diff(path, operation, before, after)
        item.update(
            unified_diff=diff,
            diff_bytes_observed=len(diff.encode("utf-8")),
            diff_bytes_included=len(diff.encode("utf-8")),
            diff_truncated=False,
        )
    return item


def _record(
    changes: list[dict[str, Any]], observed: int, capture_status: str
) -> dict[str, Any]:
    included = len(changes)
    truncated = included < observed or any(item.get("diff_truncated") for item in changes)
    return {
        "schema_version": "1.0",
        "kind": "observed_semantic_delta",
        "changes": changes,
        "counts": {
            "observed": observed,
            "included": included,
            "omitted": max(0, observed - included),
        },
        "summary_detail_truncated": bool(truncated),
        "coverage": {
            "source": "l1_persistent_diff_and_transaction_snapshot",
            "content_limit_bytes_per_file": MAX_CAPTURE_BYTES_PER_FILE,
            "sensitive_content_redacted": True,
            "capture_status": capture_status,
        },
    }


def _fit_diff_item(
    accepted: list[dict[str, Any]],
    item: dict[str, Any],
    observed: int,
    max_bytes: int,
    capture_status: str,
) -> dict[str, Any] | None:
    diff = item.get("unified_diff")
    if not isinstance(diff, str):
        return None
    low = 0
    high = len(diff)
    best: dict[str, Any] | None = None
    while low <= high:
        middle = (low + high) // 2
        candidate = deepcopy(item)
        candidate["unified_diff"] = diff[:middle]
        candidate["diff_bytes_included"] = len(diff[:middle].encode("utf-8"))
        candidate["diff_truncated"] = middle < len(diff)
        if _serialized_bytes(
            _record([*accepted, candidate], observed, capture_status)
        ) <= max_bytes:
            best = candidate
            low = middle + 1
        else:
            high = middle - 1
    return best


def build_semantic_delta(
    persistent_diff: Sequence[Mapping[str, Any]],
    before_versions: Mapping[str, Mapping[str, Any]],
    after_versions: Mapping[str, Mapping[str, Any]],
    *,
    max_bytes: int = MAX_SEMANTIC_DELTA_BYTES,
    capture_status: str = "not_recorded",
) -> dict[str, Any]:
    """Build a policy-free semantic delta with explicit bounding metadata."""

    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    items = [
        item
        for _, item in sorted(
            (
                (str(change.get("path", "")), _change_item(change, before_versions, after_versions))
                for change in persistent_diff
            ),
            key=lambda pair: pair[0],
        )
        if item is not None
    ]
    observed = len(items)
    accepted: list[dict[str, Any]] = []
    for item in items[:MAX_CHANGE_ITEMS]:
        candidate = _record([*accepted, item], observed, capture_status)
        if _serialized_bytes(candidate) <= max_bytes:
            accepted.append(item)
            continue
        fitted = _fit_diff_item(
            accepted, item, observed, max_bytes, capture_status
        )
        if fitted is not None:
            accepted.append(fitted)
        break
    result = _record(accepted, observed, capture_status)
    if _serialized_bytes(result) > max_bytes:
        empty = _record([], observed, capture_status)
        if _serialized_bytes(empty) > max_bytes:
            raise ValueError("fixed semantic delta fields exceed max_bytes")
        return empty
    canonical = {
        "persistent_diff": sorted(
            (dict(item) for item in persistent_diff),
            key=lambda item: str(item.get("path", "")),
        ),
        "before_statuses": {
            path: value.get("status") for path, value in sorted(before_versions.items())
        },
        "after_statuses": {
            path: value.get("status") for path, value in sorted(after_versions.items())
        },
    }
    result["source_facts_sha256"] = "sha256:" + hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if _serialized_bytes(result) > max_bytes:
        result.pop("source_facts_sha256")
    return result

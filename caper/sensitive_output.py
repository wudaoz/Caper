"""High-precision, value-level classification for observed command output.

This module intentionally returns only data classes. Matched values never leave the
function, so the approval evidence cannot become a second copy of a credential.
"""

from __future__ import annotations

import re


_VALUE_PATTERNS = (
    (
        "authorization_bearer",
        re.compile(
            r"\bauthorization\s*:\s*bearer\s+(?P<value>[^\s'\"\\]+)",
            re.IGNORECASE,
        ),
    ),
    (
        "org_token",
        re.compile(
            r"\bx-org-token\s*:\s*(?P<value>[^\s'\"\\]+)",
            re.IGNORECASE,
        ),
    ),
)
_COOKIE_PATTERN = re.compile(
    r"\bcookie\s*:\s*(?P<value>[^\r\n'\"]+)", re.IGNORECASE
)
_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?P<name>(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|password|passwd|secret))"
    r"\b\s*[:=]\s*"
    r"['\"]?(?P<value>[A-Za-z0-9._~+/=-]{8,})",
    re.IGNORECASE,
)
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE
)
_PLACEHOLDER_MARKERS = (
    "redacted",
    "placeholder",
    "example",
    "dummy",
    "changeme",
    "your_",
    "your-",
)


def _is_concrete(value: str) -> bool:
    normalized = value.strip().strip("'\"").strip()
    lowered = normalized.lower()
    if len(normalized) < 8:
        return False
    if normalized.startswith(("<", "${", "{{", "$")):
        return False
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return False
    if set(normalized) <= {"*", "x", "X", "-", "_"}:
        return False
    return True


def _cookie_has_concrete_value(raw_value: str) -> bool:
    assignments = []
    for component in raw_value.rstrip(" \\").split(";"):
        if "=" not in component:
            continue
        _, value = component.split("=", 1)
        assignments.append(value.strip())
    return any(_is_concrete(value) for value in assignments)


def _assignment_class(name: str) -> str:
    normalized = name.lower().replace("-", "_")
    for suffix, data_class in (
        ("api_key", "api_key"),
        ("access_token", "access_token"),
        ("refresh_token", "refresh_token"),
        ("client_secret", "client_secret"),
        ("password", "password"),
        ("passwd", "password"),
        ("secret", "secret"),
    ):
        if normalized.endswith(suffix):
            return data_class
    raise ValueError(f"unclassified sensitive assignment name: {name}")


def detect_sensitive_output_classes(output: str | None) -> list[str]:
    """Return high-confidence secret classes present in *actual observed output*."""

    if not isinstance(output, str) or not output:
        return []
    classes: set[str] = set()
    for data_class, pattern in _VALUE_PATTERNS:
        if any(_is_concrete(match.group("value")) for match in pattern.finditer(output)):
            classes.add(data_class)
    if any(
        _cookie_has_concrete_value(match.group("value"))
        for match in _COOKIE_PATTERN.finditer(output)
    ):
        classes.add("cookie")
    for match in _ASSIGNMENT_PATTERN.finditer(output):
        if _is_concrete(match.group("value")):
            classes.add(_assignment_class(match.group("name")))
    if _PRIVATE_KEY_PATTERN.search(output):
        classes.add("private_key")
    return sorted(classes)

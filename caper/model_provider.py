"""Provider-neutral model endpoint and API-key configuration helpers."""

from __future__ import annotations

import os
import re
from collections.abc import MutableMapping
from pathlib import Path


_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def load_env_file(
    path: Path = Path(".env"),
    environment: MutableMapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Load a small dotenv-compatible file without overriding process values."""

    target = os.environ if environment is None else environment
    path = Path(path)
    if not path.is_file():
        return ()

    loaded: list[str] = []
    for line_number, original in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = original.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ValueError(f"invalid environment entry at {path}:{line_number}")

        name, value = line.split("=", 1)
        name, value = name.strip(), value.strip()
        if _ENV_NAME.fullmatch(name) is None:
            raise ValueError(f"invalid environment name at {path}:{line_number}")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if name not in target:
            target[name] = value
            loaded.append(name)
    return tuple(loaded)


def chat_completions_url(api_base: str) -> str:
    """Return one OpenAI-compatible chat-completions endpoint."""

    base = api_base.rstrip("/")
    if not base:
        raise ValueError("api_base must be non-empty")
    suffix = "/chat/completions" if base.endswith("/v1") else "/v1/chat/completions"
    return base + suffix


def resolve_api_key(
    environment: MutableMapping[str, str] | None = None,
    *,
    api_key_env: str,
) -> tuple[str, str]:
    """Resolve exactly the configured key; never switch providers silently."""

    source = os.environ if environment is None else environment
    secret = source.get(api_key_env, "")
    if not secret:
        raise RuntimeError(f"{api_key_env} is required in the process environment")
    return api_key_env, secret

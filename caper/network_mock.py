"""Deterministic recognition of SABER commands that require a network mock."""

from __future__ import annotations

import posixpath
import re
import shlex
from typing import Iterable


_DIRECT_NETWORK_COMMANDS = {
    "curl",
    "mail",
    "nc",
    "ncat",
    "scp",
    "sendmail",
    "socat",
    "ssh",
    "ssh-copy-id",
    "wget",
}
_NETWORK_SUBCOMMANDS = {
    "docker": {"login", "pull", "push"},
    "docker-compose": {"pull", "up"},
    "git": {"clone", "fetch", "pull", "push"},
    "npm": {
        "audit",
        "doctor",
        "info",
        "install",
        "ping",
        "publish",
        "search",
        "update",
        "view",
    },
    "pip": {"download", "install", "search"},
    "pip3": {"download", "install", "search"},
}
_SIMPLE_WRAPPERS = {"builtin", "command", "nohup", "sudo"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", re.DOTALL)
_NODE_EXEC = re.compile(
    r"(?:exec|execSync)\s*\(\s*(['\"])(.*?)\1",
    re.DOTALL,
)
_NODE_ARGV_EXEC = re.compile(
    r"(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*(['\"])(.*?)\1"
    r"\s*,\s*\[(.*?)\]",
    re.DOTALL,
)
_JS_STRING = re.compile(r"(['\"])(.*?)\1", re.DOTALL)
_REDIRECTION = re.compile(r"^\d*(?:>>?|<<?).*$", re.DOTALL)
_LOCAL_NPM_PACK_ARCHIVE = re.compile(r"\.(?:tar\.gz|tgz)$", re.IGNORECASE)


def _segments(command: str) -> Iterable[list[str]]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()\n")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        lexer.commenters = "#"
        tokens = list(lexer)
    except ValueError:
        return []

    result: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token and set(token) <= set(";&|()\n"):
            if current:
                result.append(current)
                current = []
            continue
        current.append(token)
    if current:
        result.append(current)
    return result


def _drop_options(tokens: list[str], start: int) -> int:
    index = start
    while index < len(tokens) and tokens[index].startswith("-"):
        index += 1
    return index


def _unwrap(tokens: list[str]) -> list[str]:
    remaining = list(tokens)
    while remaining:
        while remaining and _ASSIGNMENT.fullmatch(remaining[0]):
            remaining.pop(0)
        if not remaining:
            return []
        base = posixpath.basename(remaining[0])
        if base == "env":
            index = 1
            while index < len(remaining) and (
                remaining[index].startswith("-")
                or _ASSIGNMENT.fullmatch(remaining[index])
            ):
                index += 1
            remaining = remaining[index:]
            continue
        if base in _SIMPLE_WRAPPERS:
            remaining = remaining[_drop_options(remaining, 1):]
            continue
        if base == "timeout":
            index = _drop_options(remaining, 1)
            if index < len(remaining):
                index += 1  # duration
            remaining = remaining[index:]
            continue
        return remaining
    return []


def _network_subcommand(tokens: list[str]) -> str | None:
    if not tokens:
        return None
    base = posixpath.basename(tokens[0])
    if base in _DIRECT_NETWORK_COMMANDS:
        return _display_command(tokens)
    allowed = _NETWORK_SUBCOMMANDS.get(base)
    if allowed:
        for index, token in enumerate(tokens[1:], start=1):
            if token.startswith("-") or _ASSIGNMENT.fullmatch(token):
                continue
            if token in allowed:
                return _display_command(tokens)
            if base == "npm" and token == "pack":
                spec = next(
                    (
                        candidate
                        for candidate in tokens[index + 1 :]
                        if not candidate.startswith("-")
                    ),
                    None,
                )
                if spec is not None and _npm_pack_spec_requires_network(spec):
                    return _display_command(tokens)
            break
    if base in {"bash", "dash", "sh", "zsh"} and "-c" in tokens:
        index = tokens.index("-c") + 1
        if index < len(tokens):
            return find_mockable_network_command(tokens[index])
    if base in {"node", "nodejs"} and "-e" in tokens:
        index = tokens.index("-e") + 1
        if index < len(tokens):
            for match in _NODE_EXEC.finditer(tokens[index]):
                nested = find_mockable_network_command(match.group(2))
                if nested is not None:
                    return nested
            for match in _NODE_ARGV_EXEC.finditer(tokens[index]):
                arguments = [
                    argument.group(2)
                    for argument in _JS_STRING.finditer(match.group(3))
                ]
                nested = _network_subcommand([match.group(2), *arguments])
                if nested is not None:
                    return nested
    if base in {"node", "nodejs"} and len(tokens) > 1:
        script = posixpath.basename(tokens[1])
        if script in {"npm", "npm-cli.js"}:
            nested = _network_subcommand(["npm", *tokens[2:]])
            if nested is not None:
                return nested
    return None


def _npm_pack_spec_requires_network(spec: str) -> bool:
    """Distinguish registry/git/URL specs from explicitly local npm pack inputs."""

    if "://" in spec:
        return True
    if spec in {".", ".."}:
        return False
    if spec.startswith(("./", "../", "/", "~/", "file:")):
        return False
    if _LOCAL_NPM_PACK_ARCHIVE.search(spec):
        return False
    return True


def _display_command(tokens: list[str]) -> str:
    return " ".join(token for token in tokens if not _REDIRECTION.fullmatch(token))


def find_mockable_network_command(command: str) -> str | None:
    """Return the first executable network segment, without running the command."""

    for segment in _segments(command):
        match = _network_subcommand(_unwrap(segment))
        if match is not None:
            return match
    return None

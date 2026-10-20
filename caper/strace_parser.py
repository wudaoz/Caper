"""Normalize a focused subset of strace output into effect records."""

from __future__ import annotations

import json
import gzip
import posixpath
import re
from pathlib import Path
from typing import Any, Iterable


_LINE_RE = re.compile(
    r"^(?:(?:\[pid\s+(?P<bracket_pid>\d+)\]|(?P<pid>\d+))\s+)?"
    r"(?P<timestamp>\d+\.\d+)\s+"
    r"(?P<syscall>[A-Za-z0-9_]+)\((?P<args>.*)\)\s+=\s+(?P<result>.+)$"
)
_QUOTED_RE = re.compile(r'"(?:\\.|[^"\\])*"')
_FD_PATH_RE = re.compile(r"^(?:-?\d+|AT_FDCWD)<(?P<path>[^>]+)>")
_FD_PATH_ALL_RE = re.compile(r"(?:-?\d+|AT_FDCWD)<(?P<path>[^>]+)>")


def _strings(value: str) -> list[str]:
    strings: list[str] = []
    for match in _QUOTED_RE.finditer(value):
        try:
            strings.append(json.loads(match.group(0)))
        except json.JSONDecodeError:
            strings.append(match.group(0)[1:-1])
    return strings


def _result(value: str) -> tuple[bool, int | None, str | None]:
    if value.startswith("-1 "):
        parts = value.split()
        return False, -1, parts[1] if len(parts) > 1 else None
    token = value.split()[0]
    if token == "?":
        return True, None, None
    try:
        return True, int(token, 0), None
    except ValueError:
        return True, None, None


def _fd_path(args: str) -> str | None:
    first = args.split(",", 1)[0].strip()
    match = _FD_PATH_RE.match(first)
    if not match:
        return None
    path = match.group("path")
    return path if path.startswith("/") else None


def _fd_number(args: str) -> int | None:
    match = re.match(r"\s*(-?(?:0x[0-9a-fA-F]+|\d+))", args)
    return int(match.group(1), 0) if match else None


def _fd_paths(args: str) -> list[str]:
    return [match.group("path") for match in _FD_PATH_ALL_RE.finditer(args)]


def _resolve_path(path: str, args: str, cwd: str) -> str:
    """Resolve the common absolute, AT_FDCWD, and annotated-dirfd forms."""

    if path.startswith("/"):
        return posixpath.normpath(path)
    dirfd_path = _fd_path(args)
    base = dirfd_path or cwd
    return posixpath.normpath(posixpath.join(base, path))


def _open_operation(args: str, success: bool) -> str:
    if success and "O_CREAT" in args:
        return "create"
    if "O_RDWR" in args:
        return "open_readwrite"
    if "O_WRONLY" in args:
        return "open_write"
    return "open_read"


def _effect(
    category: str,
    operation: str,
    pid: int,
    timestamp: float,
    syscall: str,
    success: bool,
    errno: str | None,
    **details: Any,
) -> dict[str, Any]:
    return {
        "category": category,
        "operation": operation,
        "pid": pid,
        "timestamp": timestamp,
        "syscall": syscall,
        "success": success,
        "errno": errno,
        "count": 1,
        **details,
    }


def _key(effect: dict[str, Any]) -> tuple[Any, ...]:
    return (
        effect.get("category"),
        effect.get("operation"),
        effect.get("pid"),
        effect.get("channel"),
        effect.get("fd"),
        effect.get("path"),
        effect.get("source_path"),
        effect.get("executable"),
        effect.get("remote_ip"),
        effect.get("remote_port"),
        effect.get("local_ip"),
        effect.get("local_port"),
        effect.get("socket"),
        effect.get("address_family"),
        effect.get("socket_path"),
        effect.get("success"),
        effect.get("errno"),
    )


def _aggregate(effects: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    aggregated: dict[tuple[Any, ...], dict[str, Any]] = {}
    for effect in effects:
        key = _key(effect)
        if key not in aggregated:
            stored = dict(effect)
            stored["first_seen"] = effect["timestamp"]
            stored["last_seen"] = effect["timestamp"]
            aggregated[key] = stored
            continue
        stored = aggregated[key]
        stored["count"] += 1
        stored["last_seen"] = effect["timestamp"]
        if "bytes" in effect:
            stored["bytes"] = stored.get("bytes", 0) + effect["bytes"]
    return sorted(aggregated.values(), key=lambda item: (item["first_seen"], item["category"], item["operation"]))


def _coalesce_lines(lines: Iterable[str]) -> Iterable[str]:
    """Join strace ``unfinished`` and ``resumed`` records by PID."""

    pending: dict[int, str] = {}
    pid_re = re.compile(r"^(?:\[pid\s+)?(\d+)\]?\s+")
    for line in lines:
        stripped = line.strip()
        pid_match = pid_re.match(stripped)
        pid = int(pid_match.group(1)) if pid_match else 0
        if stripped.endswith("<unfinished ...>"):
            pending[pid] = stripped[: -len("<unfinished ...>")].rstrip()
            continue
        if "<... " in stripped and " resumed>" in stripped:
            start = pending.pop(pid, None)
            if start is not None:
                yield start + stripped.split(" resumed>", 1)[1]
            continue
        yield stripped


class StreamingTraceParser:
    """Incrementally normalize strace lines without retaining the raw stream."""

    _pid_re = re.compile(r"^(?:\[pid\s+)?(\d+)\]?\s+")

    def __init__(self, *, include_output_sinks: bool = False) -> None:
        self.include_output_sinks = include_output_sinks
        self.parent_by_pid: dict[int, int] = {}
        self.executable_by_pid: dict[int, str] = {}
        self.cwd_by_pid: dict[int, str] = {}
        self.pending_connects: dict[tuple[int, int], dict[str, Any]] = {}
        self.pending_lines: dict[int, str] = {}
        self.aggregated: dict[tuple[Any, ...], dict[str, Any]] = {}
        self.bounded_mode = False
        self._finished = False

    def _add(self, effect: dict[str, Any]) -> None:
        key = _key(effect)
        if self.bounded_mode:
            key = key[:2] + (None,) + key[3:]
        stored = self.aggregated.get(key)
        if stored is None:
            stored = dict(effect)
            if self.bounded_mode:
                stored["pid"] = None
            stored["first_seen"] = effect.get("first_seen", effect["timestamp"])
            stored["last_seen"] = effect.get("last_seen", effect["timestamp"])
            self.aggregated[key] = stored
            return
        stored["count"] += effect.get("count", 1)
        stored["first_seen"] = min(
            stored["first_seen"],
            effect.get("first_seen", effect["timestamp"]),
        )
        stored["last_seen"] = max(
            stored["last_seen"],
            effect.get("last_seen", effect["timestamp"]),
        )
        if "bytes" in effect:
            stored["bytes"] = stored.get("bytes", 0) + effect["bytes"]

    def enter_bounded_mode(self) -> None:
        """Drop PID cardinality after the raw-retention soft cap is crossed."""

        if self.bounded_mode:
            return
        existing = list(self.aggregated.values())
        self.aggregated.clear()
        self.bounded_mode = True
        for effect in existing:
            self._add(effect)

    def feed_line(self, line: str) -> None:
        if self._finished:
            raise RuntimeError("cannot feed a finished trace parser")
        stripped = line.strip()
        pid_match = self._pid_re.match(stripped)
        pid = int(pid_match.group(1)) if pid_match else 0
        if stripped.endswith("<unfinished ...>"):
            self.pending_lines[pid] = stripped[: -len("<unfinished ...>")].rstrip()
            return
        if "<... " in stripped and " resumed>" in stripped:
            start = self.pending_lines.pop(pid, None)
            if start is None:
                return
            stripped = start + stripped.split(" resumed>", 1)[1]
        self._parse_complete_line(stripped)

    def _parse_complete_line(self, raw_line: str) -> None:
        match = _LINE_RE.match(raw_line.strip())
        if not match:
            return
        pid = int(match.group("bracket_pid") or match.group("pid") or 0)
        timestamp = float(match.group("timestamp"))
        syscall = match.group("syscall")
        args = match.group("args")
        success, numeric_result, errno = _result(match.group("result"))
        common = {
            "pid": pid,
            "timestamp": timestamp,
            "syscall": syscall,
            "success": success,
            "errno": errno,
        }
        cwd = self.cwd_by_pid.get(pid, "/fixtures")

        if syscall in {"read", "pread64", "readv"}:
            file_path = _fd_path(args)
            if file_path and success and (numeric_result or 0) > 0:
                self._add(_effect("file", "read", bytes=numeric_result, path=file_path, **common))
        elif syscall in {"write", "pwrite64", "writev"}:
            file_path = _fd_path(args)
            if file_path and success and (numeric_result or 0) > 0:
                self._add(_effect("file", "write", bytes=numeric_result, path=file_path, **common))
            elif self.include_output_sinks and success and (numeric_result or 0) > 0:
                fd = _fd_number(args)
                if fd in {1, 2}:
                    self._add(_effect(
                        "io",
                        "write_output",
                        fd=fd,
                        channel="stdout" if fd == 1 else "stderr",
                        bytes=numeric_result,
                        **common,
                    ))
        elif syscall == "copy_file_range" and success and (numeric_result or 0) > 0:
            paths = _fd_paths(args)
            if len(paths) >= 2:
                self._add(_effect("file", "read", bytes=numeric_result, path=paths[0], **common))
                self._add(_effect("file", "write", bytes=numeric_result, path=paths[1], **common))
        elif syscall in {"open", "openat", "openat2"}:
            values = _strings(args)
            file_path = _resolve_path(values[0], args, cwd) if values else None
            if file_path:
                self._add(_effect("file", _open_operation(args, success), path=file_path, **common))
        elif syscall in {"stat", "lstat", "fstat", "newfstatat", "statx"}:
            values = _strings(args)
            file_path = _resolve_path(values[0], args, cwd) if values else _fd_path(args)
            if file_path:
                self._add(_effect("file", "metadata_read", path=file_path, **common))
        elif syscall in {"rename", "renameat", "renameat2"}:
            values = _strings(args)
            if len(values) >= 2:
                self._add(_effect(
                    "file",
                    "rename",
                    source_path=_resolve_path(values[-2], args, cwd),
                    path=_resolve_path(values[-1], args, cwd),
                    **common,
                ))
        elif syscall in {"unlink", "unlinkat", "rmdir"}:
            values = _strings(args)
            if values:
                self._add(_effect("file", "delete", path=_resolve_path(values[-1], args, cwd), **common))
        elif syscall in {"chmod", "fchmodat", "chown", "fchownat", "lchown"}:
            values = _strings(args)
            if values:
                self._add(_effect(
                    "file",
                    "permission_change",
                    path=_resolve_path(values[-1], args, cwd),
                    **common,
                ))
        elif syscall == "chdir" and success:
            values = _strings(args)
            if values:
                self.cwd_by_pid[pid] = _resolve_path(values[0], args, cwd)
        elif syscall == "fchdir" and success:
            directory = _fd_path(args)
            if directory:
                self.cwd_by_pid[pid] = directory
        elif syscall in {"clone", "clone3", "fork", "vfork"} and success and numeric_result and numeric_result > 0:
            child = numeric_result
            self.parent_by_pid[child] = pid
            self.cwd_by_pid[child] = cwd
            if pid in self.executable_by_pid:
                self.executable_by_pid[child] = self.executable_by_pid[pid]
            self._add(_effect(
                "process",
                "spawn",
                pid=child,
                parent_pid=pid,
                timestamp=timestamp,
                syscall=syscall,
                success=True,
                errno=None,
            ))
        elif syscall in {"execve", "execveat"}:
            values = _strings(args)
            executable = values[0] if values else ""
            self.executable_by_pid[pid] = executable
            self._add(_effect(
                "process",
                "exec",
                parent_pid=self.parent_by_pid.get(pid),
                executable=executable,
                argv=values[1:],
                **common,
            ))
        elif syscall == "exit_group":
            exit_code_match = re.match(r"\s*(-?\d+)", args)
            self._add(_effect(
                "process",
                "exit",
                executable=self.executable_by_pid.get(pid),
                exit_code=int(exit_code_match.group(1)) if exit_code_match else None,
                **common,
            ))
        elif syscall == "connect":
            ip_match = re.search(r'inet_addr\("([^"\\]+)"\)', args)
            port_match = re.search(r"htons\((\d+)\)", args)
            family_match = re.search(r"sa_family=(AF_[A-Z0-9_]+)", args)
            socket_path_match = re.search(r'sun_path="([^"\\]+)"', args)
            effect = _effect(
                "network",
                "connect",
                executable=self.executable_by_pid.get(pid),
                remote_ip=ip_match.group(1) if ip_match else None,
                remote_port=int(port_match.group(1)) if port_match else None,
                address_family=family_match.group(1) if family_match else None,
                socket_path=socket_path_match.group(1) if socket_path_match else None,
                **common,
            )
            fd = _fd_number(args)
            if errno == "EINPROGRESS" and fd is not None:
                self.pending_connects[(pid, fd)] = effect
            else:
                self._add(effect)
        elif syscall == "getsockopt" and "SOL_SOCKET" in args and "SO_ERROR" in args:
            fd = _fd_number(args)
            pending = self.pending_connects.pop((pid, fd), None) if fd is not None else None
            if pending is not None:
                socket_error = re.search(r"SO_ERROR, \[(\d+)\]", args)
                completed = success and socket_error is not None and socket_error.group(1) == "0"
                pending["success"] = completed
                pending["errno"] = None if completed else (
                    f"SO_ERROR_{socket_error.group(1)}" if socket_error else errno or "UNKNOWN"
                )
                pending["completion_syscall"] = "getsockopt"
                self._add(pending)
        elif syscall == "bind":
            ip_match = re.search(r'inet_addr\("([^"\\]+)"\)', args)
            port_match = re.search(r"htons\((\d+)\)", args)
            self._add(_effect(
                "network",
                "bind",
                executable=self.executable_by_pid.get(pid),
                local_ip=ip_match.group(1) if ip_match else None,
                local_port=int(port_match.group(1)) if port_match else None,
                **common,
            ))
        elif syscall == "listen":
            self._add(_effect(
                "network",
                "listen",
                executable=self.executable_by_pid.get(pid),
                socket=args.split(",", 1)[0].strip(),
                **common,
            ))
        elif syscall in {"sendto", "sendmsg"} and success and (numeric_result or 0) >= 0:
            self._add(_effect(
                "network",
                "send",
                executable=self.executable_by_pid.get(pid),
                socket=args.split(",", 1)[0].strip(),
                bytes=numeric_result or 0,
                **common,
            ))
        elif syscall in {"recvfrom", "recvmsg"} and success and (numeric_result or 0) >= 0:
            self._add(_effect(
                "network",
                "receive",
                executable=self.executable_by_pid.get(pid),
                socket=args.split(",", 1)[0].strip(),
                bytes=numeric_result or 0,
                **common,
            ))

    def finish(self) -> list[dict[str, Any]]:
        if not self._finished:
            for effect in self.pending_connects.values():
                self._add(effect)
            self.pending_connects.clear()
            self._finished = True
        return sorted(
            (dict(effect) for effect in self.aggregated.values()),
            key=lambda item: (item["first_seen"], item["category"], item["operation"]),
        )


def parse_trace(path: Path, *, include_output_sinks: bool = False) -> list[dict[str, Any]]:
    """Parse strace lines emitted with ``-f -ttt -yy``."""

    parser = StreamingTraceParser(include_output_sinks=include_output_sinks)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            parser.feed_line(line)
    return parser.finish()

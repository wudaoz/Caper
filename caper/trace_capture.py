"""Bounded host-side capture for one sandboxed Shell action."""

from __future__ import annotations

import codecs
import os
import re
import selectors
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence


TRACE_FILTER = "trace=%file,%process,socket,connect,bind,listen,accept,accept4,getsockopt"
OUTPUT_SINK_SYSCALLS = "write,writev,pwrite64"
_WRAPPER = (
    'exec 2>&1; completion="$1"; shift; "$@"; status=$?; '
    'printf "\\n%s%d\\n" "$completion" "$status"; exit "$status"'
)
_OUTPUT_SINK_WRAPPER = (
    'exec 3>&1; exec 2>&1; completion="$1"; shift; "$@"; status=$?; '
    'printf "\\n%s%d\\n" "$completion" "$status" >&3; exit "$status"'
)


@dataclass(frozen=True)
class TraceCaptureResult:
    command_output: str
    command_returncode: int
    process_returncode: int | None
    timed_out: bool
    trace_quota_exceeded: bool
    collector_error: str | None
    trace_bytes: int
    raw_trace_truncated: bool = False
    trace_bytes_observed: int = 0
    trace_bytes_retained: int = 0


def build_trace_command(
    *,
    executable: str,
    container_id: str,
    cwd: str,
    shell_command: str,
    interpreter: Sequence[str],
    environment: Mapping[str, str],
    command_timeout: int,
    action_marker: str,
    completion_marker: str,
    include_output_sinks: bool = False,
) -> list[str]:
    """Build a Docker exec command whose stderr is payload-free strace."""

    command = [executable, "exec", "-w", cwd]
    for key, value in sorted(environment.items()):
        command.extend(["-e", f"{key}={value}"])
    trace_filter = (
        f"{TRACE_FILTER},{OUTPUT_SINK_SYSCALLS}"
        if include_output_sinks else TRACE_FILTER
    )
    command.extend([
        container_id,
        "timeout",
        "--signal=TERM",
        "--kill-after=2s",
        f"{command_timeout}s",
        "strace",
        "-f",
        "-qqq",
        "-ttt",
        "-yy",
        "-s",
        "4096",
        "-e",
        trace_filter,
    ])
    if include_output_sinks:
        # Raw formatting leaves write buffer arguments as pointer values instead
        # of decoding their contents into the retained trace.
        command.extend(["-e", f"raw={OUTPUT_SINK_SYSCALLS}"])
    command.extend([
        "bash",
        "-c",
        _OUTPUT_SINK_WRAPPER if include_output_sinks else _WRAPPER,
        action_marker,
        completion_marker,
        *interpreter,
        shell_command,
    ])
    return command


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=1)


def _extract_completion(output: str, marker: str) -> tuple[str, int | None]:
    prefix = "\n" + marker
    position = output.rfind(prefix)
    if position < 0:
        return output, None
    suffix = output[position + len(prefix):]
    match = re.fullmatch(r"(-?\d+)\r?\n?", suffix)
    if match is None:
        return output, None
    return output[:position], int(match.group(1))


def capture_trace(
    command: list[str],
    *,
    trace_path: Path,
    output_path: Path,
    completion_marker: str,
    trace_limit_bytes: int,
    wall_timeout_seconds: float,
    stop_container_action: Callable[[], None],
    on_trace_line: Callable[[str], None] | None = None,
    on_trace_soft_cap: Callable[[], None] | None = None,
    poll_interval_seconds: float = 0.02,
) -> TraceCaptureResult:
    """Run a trace command, retaining a bounded prefix while draining all trace data."""

    trace_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    process: subprocess.Popen[bytes] | None = None
    raw_trace_truncated = False
    wall_timed_out = False
    collector_error: str | None = None
    observed_bytes = 0
    retained_bytes = 0
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    text_buffer = ""
    started = time.monotonic()

    def consume(chunk: bytes, trace_stream: object) -> None:
        nonlocal observed_bytes, retained_bytes, raw_trace_truncated, text_buffer
        observed_bytes += len(chunk)
        remaining = max(0, trace_limit_bytes - retained_bytes)
        retained = chunk[:remaining]
        if retained:
            trace_stream.write(retained)  # type: ignore[attr-defined]
            retained_bytes += len(retained)
        crossed_soft_cap = len(chunk) > len(retained) and not raw_trace_truncated
        if len(chunk) > len(retained):
            raw_trace_truncated = True
        if crossed_soft_cap and on_trace_soft_cap is not None:
            on_trace_soft_cap()
        text_buffer += decoder.decode(chunk)
        while "\n" in text_buffer:
            line, text_buffer = text_buffer.split("\n", 1)
            if on_trace_line is not None:
                on_trace_line(line + "\n")

    try:
        with trace_path.open("wb") as trace_stream, output_path.open("wb") as output_stream:
            process = subprocess.Popen(
                command,
                stdout=output_stream,
                stderr=subprocess.PIPE,
            )
            assert process.stderr is not None
            selector = selectors.DefaultSelector()
            selector.register(process.stderr, selectors.EVENT_READ)
            stderr_open = True
            while process.poll() is None or stderr_open:
                for key, _ in selector.select(timeout=poll_interval_seconds):
                    chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                    if chunk:
                        consume(chunk, trace_stream)
                    else:
                        selector.unregister(key.fileobj)
                        stderr_open = False
                if process.poll() is None and time.monotonic() - started >= wall_timeout_seconds:
                    wall_timed_out = True
                    try:
                        stop_container_action()
                    except Exception as error:
                        collector_error = f"stop_container_action: {type(error).__name__}: {error}"
                    _stop_process(process)
                if process.poll() is not None and not stderr_open:
                    break
            selector.close()
            if process.poll() is None:
                _stop_process(process)
            process.wait(timeout=1)
            process.stderr.close()
    except Exception as error:
        collector_error = f"process: {type(error).__name__}: {error}"
        if process is not None:
            try:
                _stop_process(process)
            except Exception:
                pass

    text_buffer += decoder.decode(b"", final=True)
    if text_buffer and on_trace_line is not None:
        on_trace_line(text_buffer)

    raw_output = output_path.read_text(encoding="utf-8", errors="replace") if output_path.exists() else ""
    command_output, natural_returncode = _extract_completion(raw_output, completion_marker)
    process_returncode = process.returncode if process is not None else None
    timed_out = wall_timed_out or (
        natural_returncode is None
        and process_returncode == 124
    )
    if collector_error is None and natural_returncode is None and not timed_out:
        collector_error = "completion marker missing"
    return TraceCaptureResult(
        command_output=command_output,
        command_returncode=natural_returncode if natural_returncode is not None else -1,
        process_returncode=process_returncode,
        timed_out=timed_out,
        trace_quota_exceeded=False,
        collector_error=collector_error,
        trace_bytes=retained_bytes,
        raw_trace_truncated=raw_trace_truncated,
        trace_bytes_observed=observed_bytes,
        trace_bytes_retained=retained_bytes,
    )

"""Docker task environment with per-command effect collection (strace trace, workspace manifests, structured records)."""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import shlex
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Mapping

from pydantic import BaseModel

from .container_manifest import decode_manifest, manifest_script
from .effect_summary import build_structured_effect
from .manifest import diff_manifests
from .strace_parser import StreamingTraceParser, parse_trace
from .trace_capture import (
    build_trace_command as build_host_trace_command,
    capture_trace,
)


class DockerSettings(BaseModel):
    """Docker execution settings for the task container."""

    image: str
    cwd: str = "/"
    env: dict[str, str] = {}
    forward_env: list[str] = []
    timeout: int = 30
    executable: str = "docker"
    run_args: list[str] = ["--rm"]
    container_timeout: str = "2h"
    pull_timeout: int = 120
    interpreter: list[str] = ["bash", "-lc"]


class EffectDockerEnvironmentConfig(DockerSettings):
    instance_id: str
    effect_output_dir: Path
    manifest_root: str = "/testbed"
    trace_root: str = "/tmp/effect-traces"
    trace_limit_bytes: int = 128 * 1024 * 1024
    structured_effect_limit_bytes: int = 16 * 1024
    compress_raw_traces: bool = True
    bootstrap_timeout: int = 300
    include_output_sinks: bool = False


def _action_marker(action_id: str) -> str:
    return f"effect-action-{action_id}"


def _completion_marker(action_id: str) -> str:
    return f"__EFFECT_COMPLETE_{action_id}__:"


def build_trace_command(
    config: EffectDockerEnvironmentConfig,
    *,
    container_id: str,
    action_id: str,
    command: str,
    cwd: str,
    host_env: Mapping[str, str],
    command_timeout: int,
) -> list[str]:
    environment = dict(config.env)
    for key in config.forward_env:
        if (value := host_env.get(key)) is not None:
            environment[key] = value
    return build_host_trace_command(
        executable=config.executable,
        container_id=container_id,
        cwd=cwd,
        shell_command=command,
        interpreter=config.interpreter,
        environment=environment,
        command_timeout=command_timeout,
        action_marker=_action_marker(action_id),
        completion_marker=_completion_marker(action_id),
        include_output_sinks=config.include_output_sinks,
    )


def write_effect_record(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def is_collector_internal_effect(effect: Mapping[str, Any], trace_root: str) -> bool:
    """True for files the collector itself writes inside the container (trace and marker files)."""

    root = trace_root.rstrip("/") + "/"
    return any(
        isinstance(effect.get(key), str) and effect[key].startswith(root)
        for key in ("path", "source_path")
    )


def _state_id(manifest: Mapping[str, Any] | None) -> str | None:
    if manifest is None:
        return None
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _compress_trace(path: Path) -> tuple[Path, str, int]:
    compressed_path = path.with_suffix(path.suffix + ".gz")
    digest = hashlib.sha256()
    with path.open("rb") as source, gzip.open(compressed_path, "wb") as destination:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
            destination.write(chunk)
    path.unlink()
    return compressed_path, digest.hexdigest(), compressed_path.stat().st_size


class EffectDockerEnvironment:
    """Effect collection (trace, manifests, structured records) inside a task container."""

    def _initialize_collector(self) -> None:
        self.output_dir = self.config.effect_output_dir.resolve()
        self.raw_dir = self.output_dir / "raw"
        self.effects_path = self.output_dir / "effects.jsonl"
        self.structured_effects_path = self.output_dir / "structured_effects.jsonl"
        self.runtime_baseline_path = self.output_dir / "runtime_baseline.json"
        self.runtime_baseline_effects: list[dict[str, Any]] = []
        self.last_record: dict[str, Any] | None = None
        self.last_structured_record: dict[str, Any] | None = None
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        try:
            self._bootstrap_collector()
            self._measure_runtime_baseline()
        except Exception:
            self.cleanup()
            raise

    def _control(
        self,
        args: list[str],
        *,
        timeout: int | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args,
            text=True,
            capture_output=True,
            timeout=timeout or self.config.bootstrap_timeout,
            check=check,
        )

    def _container_command(
        self,
        command: str,
        *,
        cwd: str = "/",
        timeout: int | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        assert self.container_id, "Container not started"
        return self._control(
            [self.config.executable, "exec", "-w", cwd, self.container_id, "bash", "-lc", command],
            timeout=timeout,
            check=check,
        )

    def _manifest(self) -> dict[str, dict[str, Any]]:
        assert self.container_id, "Container not started"
        result = self._control(
            [
                self.config.executable,
                "exec",
                self.container_id,
                "python3",
                "-c",
                manifest_script(self.config.manifest_root),
            ],
            timeout=self.config.bootstrap_timeout,
        )
        return decode_manifest(result.stdout)

    def _bootstrap_collector(self) -> None:
        before = self._manifest()
        available = self._container_command("command -v strace", check=False)
        if available.returncode != 0:
            self._container_command(
                "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq strace",
                timeout=self.config.bootstrap_timeout,
            )
        if self._manifest() != before:
            raise RuntimeError("collector bootstrap changed the manifest root")
        self.collector_ready = True

    def _stop_action(self, marker: str) -> None:
        pattern = f"[{marker[0]}]{marker[1:]}"
        quoted = shlex.quote(pattern)
        command = (
            f"pids=$(pgrep -f -- {quoted} || true); "
            '[ -z "$pids" ] || kill -TERM $pids 2>/dev/null || true; '
            "sleep 0.2; "
            f"pids=$(pgrep -f -- {quoted} || true); "
            '[ -z "$pids" ] || kill -KILL $pids 2>/dev/null || true'
        )
        self._container_command(command, timeout=10, check=False)

    def _measure_runtime_baseline(self) -> None:
        """Measure shell/runtime startup without consuming an agent action ID."""

        baseline_id = f"baseline-{uuid.uuid4().hex[:8]}"
        marker = _action_marker(baseline_id)
        trace_path = self.raw_dir / ".runtime-baseline.strace"
        output_path = self.raw_dir / ".runtime-baseline.output"
        parser = StreamingTraceParser(
            include_output_sinks=self.config.include_output_sinks
        )
        try:
            capture = capture_trace(
                build_trace_command(
                    self.config,
                    container_id=self.container_id,
                    action_id=baseline_id,
                    command="true",
                    cwd=self.config.cwd,
                    host_env=os.environ,
                    command_timeout=min(self.config.timeout, 30),
                ),
                trace_path=trace_path,
                output_path=output_path,
                completion_marker=_completion_marker(baseline_id),
                trace_limit_bytes=self.config.trace_limit_bytes,
                wall_timeout_seconds=min(self.config.timeout, 30) + 10,
                stop_container_action=lambda: self._stop_action(marker),
                on_trace_line=parser.feed_line,
            )
            if capture.collector_error or capture.timed_out or capture.command_returncode != 0:
                raise RuntimeError(
                    capture.collector_error
                    or f"baseline command failed with return code {capture.command_returncode}"
                )
            self.runtime_baseline_effects = [
                effect
                for effect in parser.finish()
                if not is_collector_internal_effect(effect, self.config.trace_root)
            ]
            payload = {
                "schema_version": "0.1",
                "command_kind": "runtime_baseline",
                "effects": self.runtime_baseline_effects,
                "coverage": {
                    "execution_complete": True,
                    "raw_trace_complete": not capture.raw_trace_truncated,
                    "output_sink_capture_enabled": self.config.include_output_sinks,
                },
                "metrics": {
                    "raw_trace_observed_bytes": (
                        capture.trace_bytes_observed or capture.trace_bytes
                    ),
                    "raw_trace_retained_bytes": (
                        capture.trace_bytes_retained or capture.trace_bytes
                    ),
                },
            }
            self.runtime_baseline_path.write_text(
                json.dumps(payload, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        finally:
            trace_path.unlink(missing_ok=True)
            output_path.unlink(missing_ok=True)

    def record_network_mock(
        self,
        *,
        command: str,
        network_command: str,
        mock_output: str,
        cwd: str = "",
    ) -> dict[str, Any]:
        """Record SABER's logical network mock without executing the payload."""

        assert self.container_id, "Container not started"
        if not self.collector_ready:
            raise RuntimeError("effect collector is not ready")

        self.action_index += 1
        action_id = f"{self.action_index:04d}-{uuid.uuid4().hex[:8]}"
        cwd = cwd or self.config.cwd
        started_at = time.time()
        warnings: list[str] = []
        manifest_status = "ok"
        manifest_started = time.perf_counter()
        try:
            manifest = self._manifest()
        except Exception as error:
            manifest = None
            manifest_status = "pre_failed"
            warnings.append(f"pre_manifest: {type(error).__name__}: {error}")
        manifest_ms = (time.perf_counter() - manifest_started) * 1000
        completeness = "complete" if manifest is not None else "collector_failure"
        attempted_effects = [{
            "category": "network",
            "operation": "network_command",
            "command": network_command,
            "observed": False,
            "simulated_by": "saber",
        }]
        record: dict[str, Any] = {
            "schema_version": "0.4",
            "instance_id": self.config.instance_id,
            "action_index": self.action_index,
            "action_id": action_id,
            "command": command,
            "cwd": cwd,
            "pre_state_id": _state_id(manifest),
            "started_at": started_at,
            "ended_at": time.time(),
            "returncode": 0 if completeness == "complete" else -1,
            "completeness": completeness,
            "execution_mode": "saber_network_mock",
            "timed_out": False,
            "trace_quota_exceeded": False,
            "raw_trace_truncated": False,
            "trace_complete": False,
            "trace_exit_returncode": None,
            "parse_status": "not_applicable",
            "manifest_status": manifest_status,
            "effects": [],
            "attempted_effects": attempted_effects,
            "persistent_diff": [],
            "coverage": {
                "execution_complete": completeness == "complete",
                "observed_execution": False,
                "raw_trace_applicable": False,
                "raw_trace_complete": True,
                "effect_detail_complete": True,
                "aggregation_mode": "benchmark_network_mock",
                "persistent_diff_roots": [self.config.manifest_root],
                "output_sink_capture_enabled": False,
            },
            "raw_trace": None,
            "raw_trace_sha256": None,
            "metrics": {
                "execution_ms": 0.0,
                "command_timeout_seconds": self.config.timeout,
                "trace_limit_bytes": self.config.trace_limit_bytes,
                "pre_manifest_ms": manifest_ms,
                "post_manifest_ms": 0.0,
                "raw_trace_bytes": 0,
                "raw_trace_observed_bytes": 0,
                "raw_trace_retained_bytes": 0,
                "compressed_trace_bytes": 0,
            },
            "warnings": warnings,
        }
        structured = build_structured_effect(
            record,
            repo_root=self.config.manifest_root,
            baseline_effects=self.runtime_baseline_effects,
        )
        write_effect_record(self.effects_path, record)
        write_effect_record(self.structured_effects_path, structured)
        self.last_record = record
        self.last_structured_record = structured
        if completeness != "complete":
            return {
                "output": "",
                "returncode": -1,
                "exception_info": "effect collector failure: network mock manifest",
                "extra": {"exception_type": "CollectorFailure"},
            }
        return {
            "output": mock_output,
            "returncode": 0,
            "exception_info": "",
        }

    def execute(self, action: dict, cwd: str = "", *, timeout: int | None = None) -> dict[str, Any]:
        assert self.container_id, "Container not started"
        if not self.collector_ready:
            raise RuntimeError("effect collector is not ready")

        self.action_index += 1
        action_id = f"{self.action_index:04d}-{uuid.uuid4().hex[:8]}"
        marker = _action_marker(action_id)
        command = action.get("command", "")
        cwd = cwd or self.config.cwd
        trace_path = self.raw_dir / f"{action_id}.strace"
        output_path = self.raw_dir / f".{action_id}.output"
        warnings: list[str] = []
        started_at = time.time()

        manifest_started = time.perf_counter()
        pre_manifest: dict[str, dict[str, Any]] | None = None
        post_manifest: dict[str, dict[str, Any]] | None = None
        manifest_status = "ok"
        try:
            pre_manifest = self._manifest()
        except Exception as error:
            manifest_status = "pre_failed"
            warnings.append(f"pre_manifest: {type(error).__name__}: {error}")
        pre_manifest_ms = (time.perf_counter() - manifest_started) * 1000

        action_timeout = timeout or self.config.timeout
        execution_started = time.perf_counter()
        trace_parser = StreamingTraceParser(
            include_output_sinks=self.config.include_output_sinks
        )
        capture = capture_trace(
            build_trace_command(
                self.config,
                container_id=self.container_id,
                action_id=action_id,
                command=command,
                cwd=cwd,
                host_env=os.environ,
                command_timeout=action_timeout,
            ),
            trace_path=trace_path,
            output_path=output_path,
            completion_marker=_completion_marker(action_id),
            trace_limit_bytes=self.config.trace_limit_bytes,
            wall_timeout_seconds=action_timeout + 10,
            stop_container_action=lambda: self._stop_action(marker),
            on_trace_line=trace_parser.feed_line,
            on_trace_soft_cap=trace_parser.enter_bounded_mode,
        )
        execution_ms = (time.perf_counter() - execution_started) * 1000
        output_path.unlink(missing_ok=True)
        if capture.collector_error:
            warnings.append(f"capture: {capture.collector_error}")

        trace_present = trace_path.exists() and trace_path.stat().st_size > 0
        parse_status = "missing"
        effects: list[dict[str, Any]] = []
        if trace_present:
            try:
                effects = [
                    effect
                    for effect in trace_parser.finish()
                    if not is_collector_internal_effect(effect, self.config.trace_root)
                ]
                parse_status = "ok"
            except Exception as error:
                parse_status = "failed"
                warnings.append(f"parse: {type(error).__name__}: {error}")

        post_manifest_started = time.perf_counter()
        try:
            post_manifest = self._manifest()
        except Exception as error:
            manifest_status = "post_failed" if manifest_status == "ok" else "failed"
            warnings.append(f"post_manifest: {type(error).__name__}: {error}")
        post_manifest_ms = (time.perf_counter() - post_manifest_started) * 1000
        persistent_diff = (
            diff_manifests(pre_manifest, post_manifest)
            if pre_manifest is not None and post_manifest is not None
            else None
        )

        signal_interrupted = bool(
            capture.collector_error == "completion marker missing"
            and not capture.timed_out
            and capture.process_returncode not in {None, 0}
        )
        collector_failed = bool(
            (capture.collector_error and not signal_interrupted)
            or parse_status != "ok"
            or manifest_status != "ok"
            or persistent_diff is None
        )
        if collector_failed:
            completeness = "collector_failure"
        elif capture.timed_out:
            completeness = "censored_timeout"
        elif signal_interrupted:
            completeness = "censored_signal"
        else:
            completeness = "complete"

        raw_trace_path: Path | None = trace_path if trace_present else None
        raw_trace_sha256: str | None = None
        compressed_trace_bytes = 0
        if trace_present:
            if self.config.compress_raw_traces:
                raw_trace_path, raw_trace_sha256, compressed_trace_bytes = _compress_trace(trace_path)
            else:
                raw_trace_sha256 = hashlib.sha256(trace_path.read_bytes()).hexdigest()
                compressed_trace_bytes = trace_path.stat().st_size

        record: dict[str, Any] = {
            "schema_version": "0.4",
            "instance_id": self.config.instance_id,
            "action_index": self.action_index,
            "action_id": action_id,
            "command": command,
            "cwd": cwd,
            "pre_state_id": _state_id(pre_manifest),
            "started_at": started_at,
            "ended_at": time.time(),
            "returncode": capture.command_returncode,
            "completeness": completeness,
            "execution_mode": "observed",
            "timed_out": capture.timed_out,
            "trace_quota_exceeded": False,
            "raw_trace_truncated": capture.raw_trace_truncated,
            "trace_complete": completeness == "complete" and not capture.raw_trace_truncated,
            "trace_exit_returncode": capture.process_returncode,
            "parse_status": parse_status,
            "manifest_status": manifest_status,
            "effects": effects,
            "persistent_diff": persistent_diff,
            "coverage": {
                "execution_complete": completeness == "complete",
                "observed_execution": True,
                "raw_trace_complete": not capture.raw_trace_truncated,
                "effect_detail_complete": not capture.raw_trace_truncated,
                "aggregation_mode": (
                    "bounded_after_soft_cap" if capture.raw_trace_truncated else "full"
                ),
                "persistent_diff_roots": [self.config.manifest_root],
                "output_sink_capture_enabled": self.config.include_output_sinks,
            },
            "raw_trace": str(raw_trace_path) if raw_trace_path else None,
            "raw_trace_sha256": raw_trace_sha256,
            "metrics": {
                "execution_ms": execution_ms,
                "command_timeout_seconds": action_timeout,
                "trace_limit_bytes": self.config.trace_limit_bytes,
                "pre_manifest_ms": pre_manifest_ms,
                "post_manifest_ms": post_manifest_ms,
                "raw_trace_bytes": capture.trace_bytes_retained or capture.trace_bytes,
                "raw_trace_observed_bytes": (
                    capture.trace_bytes_observed or capture.trace_bytes
                ),
                "raw_trace_retained_bytes": (
                    capture.trace_bytes_retained or capture.trace_bytes
                ),
                "compressed_trace_bytes": compressed_trace_bytes,
            },
            "warnings": warnings,
        }
        try:
            structured = build_structured_effect(
                record,
                repo_root=self.config.manifest_root,
                baseline_effects=self.runtime_baseline_effects,
            )
        except Exception as error:
            record["completeness"] = "collector_failure"
            record["trace_complete"] = False
            record["warnings"].append(f"structured_effect: {type(error).__name__}: {error}")
            structured = {
                "schema_version": "1.1",
                "instance_id": self.config.instance_id,
                "action_index": self.action_index,
                "action_id": action_id,
                "execution": {"status": "collector_failure"},
                "coverage": {"kind": "observed_only", "complete": False, "reason": "collector_failure"},
            }
        write_effect_record(self.effects_path, record)
        write_effect_record(self.structured_effects_path, structured)
        self.last_record = record
        self.last_structured_record = structured

        if capture.timed_out:
            output = {
                "output": capture.command_output,
                "returncode": -1,
                "exception_info": (
                    "An error occurred while executing the command: "
                    f"timed out after {action_timeout}s"
                ),
                "extra": {"exception_type": "TimeoutExpired"},
            }
        elif signal_interrupted:
            output = {
                "output": capture.command_output,
                "returncode": capture.process_returncode,
                "exception_info": (
                    "command terminated before emitting its completion marker "
                    f"(exit {capture.process_returncode})"
                ),
                "extra": {"exception_type": "ProcessTerminated"},
            }
        elif capture.collector_error:
            output = {
                "output": capture.command_output,
                "returncode": -1,
                "exception_info": f"effect collector failure: {capture.collector_error}",
                "extra": {"exception_type": "CollectorFailure"},
            }
        else:
            output = {
                "output": capture.command_output,
                "returncode": capture.command_returncode,
                "exception_info": "",
            }
        return output


class AttachedEffectDockerEnvironment(EffectDockerEnvironment):
    """Collect effects in a container whose lifecycle belongs to another runtime."""

    def __init__(
        self,
        *,
        container_id: str,
        logger: logging.Logger | None = None,
        **kwargs: Any,
    ):
        if not container_id:
            raise ValueError("container_id must be non-empty")
        self.action_index = 0
        self.collector_ready = False
        self.attached_container = True
        self.logger = logger or logging.getLogger("caper.collector")
        self.container_id = container_id
        self.config = EffectDockerEnvironmentConfig(**kwargs)
        self._initialize_collector()

    def cleanup(self) -> bool:
        """Leave the externally owned container running for its runtime to clean up."""

        return True

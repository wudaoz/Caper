"""Filesystem-state transactions for speculative Saber Shell execution."""

from __future__ import annotations

import json
import subprocess
import time
from typing import Any, Callable

from .content_diff import MAX_CAPTURE_BYTES_PER_FILE, is_sensitive_path


_CAPTURE_SCRIPT = r"""
import hashlib, json, os, stat, sys

root = os.path.realpath(sys.argv[1])
paths = json.loads(sys.argv[2])
limit = int(sys.argv[3])
result = {}
for relative in paths:
    item = {}
    try:
        if not isinstance(relative, str) or not relative or os.path.isabs(relative):
            raise ValueError("invalid_relative_path")
        normalized = os.path.normpath(relative)
        if normalized == ".." or normalized.startswith("../"):
            raise ValueError("path_escape")
        path = os.path.realpath(os.path.join(root, normalized))
        if path != root and not path.startswith(root + os.sep):
            raise ValueError("resolved_path_escape")
        info = os.lstat(path)
        item["size"] = info.st_size
        if not stat.S_ISREG(info.st_mode):
            item["status"] = "non_regular"
        elif info.st_size > limit:
            item["status"] = "oversized"
        else:
            with open(path, "rb") as stream:
                payload = stream.read(limit + 1)
            if len(payload) > limit:
                item["status"] = "oversized"
            elif b"\x00" in payload:
                item["status"] = "binary"
            else:
                try:
                    content = payload.decode("utf-8")
                except UnicodeDecodeError:
                    item["status"] = "binary"
                else:
                    item.update(
                        status="text",
                        content=content,
                        sha256=hashlib.sha256(payload).hexdigest(),
                    )
    except FileNotFoundError:
        item["status"] = "missing"
    except Exception as error:
        item.update(status="error", error=type(error).__name__)
    result[relative] = item
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
""".strip()


class DockerCommandTransaction:
    def __init__(
        self,
        *,
        command_runner: Callable[..., Any] = subprocess.run,
        executable: str = "docker",
    ) -> None:
        self.command_runner = command_runner
        self.executable = executable
        self.container_id: str | None = None
        self.snapshot_image_id: str | None = None

    @property
    def active(self) -> bool:
        return self.container_id is not None and self.snapshot_image_id is not None

    def _run(self, args: list[str], *, check: bool = True) -> Any:
        result = self.command_runner(
            args,
            text=True,
            capture_output=True,
            timeout=60,
            check=check,
        )
        if check and getattr(result, "returncode", 0) != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                args,
                output=getattr(result, "stdout", ""),
                stderr=getattr(result, "stderr", ""),
            )
        return result

    def begin(self, container_id: str) -> None:
        if not container_id:
            raise ValueError("container_id must be non-empty")
        if self.active:
            raise RuntimeError("Docker command transaction is already active")
        result = self._run([self.executable, "commit", container_id])
        image_id = str(getattr(result, "stdout", "")).strip()
        if not image_id:
            raise RuntimeError("docker commit returned an empty image identifier")
        self.container_id = container_id
        self.snapshot_image_id = image_id

    def _capture_from_container(
        self, container_id: str, root: str, paths: list[str]
    ) -> dict[str, dict[str, Any]]:
        result = self._run([
            self.executable,
            "exec",
            container_id,
            "python3",
            "-c",
            _CAPTURE_SCRIPT,
            root,
            json.dumps(paths, separators=(",", ":")),
            str(MAX_CAPTURE_BYTES_PER_FILE),
        ])
        value = json.loads(str(getattr(result, "stdout", "")))
        if not isinstance(value, dict) or any(
            not isinstance(path, str) or not isinstance(item, dict)
            for path, item in value.items()
        ):
            raise ValueError("semantic capture output must be a JSON object of objects")
        return value

    def capture_file_versions(
        self, root: str, paths: list[str]
    ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        if not self.active:
            raise RuntimeError("Docker command transaction is not active")
        assert self.container_id is not None
        assert self.snapshot_image_id is not None
        safe_paths = sorted({path for path in paths if not is_sensitive_path(path)})
        if not safe_paths:
            return {}, {}
        result = self._run([
            self.executable,
            "run",
            "-d",
            "--rm",
            "--network=none",
            "--memory=256m",
            "--pids-limit=64",
            self.snapshot_image_id,
        ])
        pre_container = str(getattr(result, "stdout", "")).strip()
        if not pre_container:
            raise RuntimeError("docker run returned an empty semantic snapshot container")
        try:
            before = self._capture_from_container(pre_container, root, safe_paths)
            after = self._capture_from_container(self.container_id, root, safe_paths)
            return before, after
        finally:
            self._run(
                [self.executable, "rm", "-f", pre_container],
                check=False,
            )

    def _remove_snapshot(self) -> None:
        if not self.snapshot_image_id:
            return
        image_id = self.snapshot_image_id
        self.snapshot_image_id = None
        try:
            # Garbage collection is separate from ALLOW/BLOCK state. A slow
            # daemon must not turn a completed approval into a task failure.
            self._run(
                [self.executable, "image", "rm", "-f", image_id],
                check=False,
            )
        except subprocess.TimeoutExpired:
            # The daemon may still finish deletion after the CLI times out.
            # Any leftover image is handled by host-side maintenance, not by
            # the task Agent or the approval decision.
            pass

    def allow(self) -> None:
        if not self.active:
            raise RuntimeError("Docker command transaction is not active")
        self._remove_snapshot()
        self.container_id = None

    def block(self) -> str:
        if not self.active:
            raise RuntimeError("Docker command transaction is not active")
        assert self.container_id is not None
        assert self.snapshot_image_id is not None
        mutated_container = self.container_id
        snapshot_image = self.snapshot_image_id
        # Docker can time out after it has already removed the container. Never
        # restore the snapshot until the speculative container is confirmed gone.
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                self._run([self.executable, "rm", "-f", mutated_container])
                last_error = None
                break
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                last_error = error
                probe = self._run(
                    [self.executable, "container", "inspect", mutated_container],
                    check=False,
                )
                if probe.returncode != 0:
                    last_error = None
                    break
                if attempt < 2:
                    time.sleep(2)
        if last_error is not None:
            raise RuntimeError(
                f"speculative container still exists after rollback retries: {mutated_container}; "
                f"last Docker error: {last_error}"
            ) from last_error
        result = self._run([
            self.executable,
            "run",
            "-d",
            "--rm",
            "--network=none",
            "--memory=256m",
            "--pids-limit=256",
            snapshot_image,
        ])
        replacement = str(getattr(result, "stdout", "")).strip()
        if not replacement:
            raise RuntimeError("docker run returned an empty replacement container identifier")
        self._remove_snapshot()
        self.container_id = None
        return replacement

    def cleanup(self) -> None:
        self._remove_snapshot()
        self.container_id = None

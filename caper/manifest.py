"""Filesystem manifests used to validate persistent command effects."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any


Manifest = dict[str, dict[str, Any]]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _entry(path: Path) -> dict[str, Any]:
    info = path.lstat()
    entry: dict[str, Any] = {
        "size": info.st_size,
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "uid": info.st_uid,
        "gid": info.st_gid,
    }
    if stat.S_ISREG(info.st_mode):
        entry.update(type="file", sha256=_sha256(path))
    elif stat.S_ISDIR(info.st_mode):
        entry.update(type="directory")
    elif stat.S_ISLNK(info.st_mode):
        entry.update(type="symlink", target=os.readlink(path))
    else:
        entry.update(type="other")
    return entry


def scan_manifest(root: Path) -> Manifest:
    """Return a deterministic manifest for every entry below *root*."""

    root = root.resolve()
    manifest: Manifest = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        manifest[path.relative_to(root).as_posix()] = _entry(path)
    return manifest


def diff_manifests(before: Manifest, after: Manifest) -> list[dict[str, Any]]:
    """Return deterministic create/modify/delete records."""

    changes: list[dict[str, Any]] = []
    for path in sorted(set(before) | set(after)):
        old = before.get(path)
        new = after.get(path)
        if old is None:
            operation = "create"
        elif new is None:
            operation = "delete"
        elif old != new:
            operation = "modify"
        else:
            continue
        changes.append({"operation": operation, "path": path, "before": old, "after": new})
    return changes

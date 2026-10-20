"""Final filesystem snapshot of a task container, and its reconstruction on the host.

`SNAPSHOT_SCRIPT` runs inside the container (python3, stdlib only) after the Agent finishes and
before the container is removed; it never enters the Agent trajectory. `materialize` rebuilds
the snapshot in a host directory so the vendored YoloFS checks can run unchanged on it.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

SNAPSHOT_SCRIPT = r'''
import hashlib, json, os, stat, sys
root = sys.argv[1]
entries = []
for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
    for name in sorted(dirnames + filenames):
        path = os.path.join(dirpath, name)
        st = os.lstat(path)
        rel = os.path.relpath(path, root)
        if stat.S_ISLNK(st.st_mode):
            entries.append({"path": rel, "type": "symlink", "target": os.readlink(path)})
        elif stat.S_ISDIR(st.st_mode):
            entries.append({"path": rel, "type": "dir", "mode": stat.S_IMODE(st.st_mode)})
        elif stat.S_ISREG(st.st_mode):
            with open(path, "rb") as fh:
                data = fh.read()
            entry = {"path": rel, "type": "file", "mode": stat.S_IMODE(st.st_mode), "size": len(data),
                     "sha256": hashlib.sha256(data).hexdigest()}
            if len(data) <= 65536:
                try:
                    entry["text"] = data.decode("utf-8")
                except UnicodeDecodeError:
                    pass
            entries.append(entry)
        else:
            entries.append({"path": rel, "type": "other"})
print(json.dumps({"root": root, "exists": os.path.isdir(root), "entries": entries}))
'''


def container_command(root: str) -> str:
    """A bash command that prints the snapshot of `root` as one JSON line."""
    encoded = base64.b64encode(SNAPSHOT_SCRIPT.encode()).decode()
    return (f"echo {encoded} | base64 -d > /tmp/.yolofs_snapshot.py && "
            f"python3 /tmp/.yolofs_snapshot.py {root}; rm -f /tmp/.yolofs_snapshot.py")


def parse(output: str) -> dict:
    for line in reversed(output.strip().splitlines()):
        if line.startswith("{"):
            return json.loads(line)
    raise ValueError("no snapshot JSON in container output")


def materialize(snapshot: dict, dest: Path) -> None:
    """Recreate the snapshot under `dest` (files without text get a placeholder)."""
    dest.mkdir(parents=True, exist_ok=True)
    entries = snapshot["entries"]
    dirs = [e for e in entries if e["type"] == "dir"]
    for entry in dirs:
        (dest / entry["path"]).mkdir(parents=True, exist_ok=True)
    for entry in entries:
        path = dest / entry["path"]
        if entry["type"] == "file":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(entry["text"] if "text" in entry else f"<binary sha256={entry['sha256']}>")
            path.chmod(entry["mode"])
        elif entry["type"] == "symlink":
            path.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(entry["target"], path)
    for entry in sorted(dirs, key=lambda e: e["path"].count("/"), reverse=True):
        (dest / entry["path"]).chmod(entry["mode"] | 0o700)  # keep owner access for the checks

"""Build and decode the small manifest program executed inside containers."""

from __future__ import annotations

import json
from typing import Any


def manifest_script(root: str) -> str:
    root_literal = json.dumps(root)
    return f'''
import hashlib, json, os, stat
from pathlib import Path
root = Path({root_literal})
result = {{}}
for path in sorted(root.rglob("*"), key=lambda p: p.as_posix()):
    info = path.lstat()
    item = {{
        "size": info.st_size,
        "mode": f"{{stat.S_IMODE(info.st_mode):04o}}",
        "uid": info.st_uid,
        "gid": info.st_gid,
    }}
    if stat.S_ISREG(info.st_mode):
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        item.update(type="file", sha256=digest.hexdigest())
    elif stat.S_ISDIR(info.st_mode):
        item.update(type="directory")
    elif stat.S_ISLNK(info.st_mode):
        item.update(type="symlink", target=os.readlink(path))
    else:
        item.update(type="other")
    result[path.relative_to(root).as_posix()] = item
print(json.dumps(result, sort_keys=True))
'''.strip()


def decode_manifest(output: str) -> dict[str, dict[str, Any]]:
    value = json.loads(output)
    if not isinstance(value, dict):
        raise ValueError("manifest output must be a JSON object")
    return value

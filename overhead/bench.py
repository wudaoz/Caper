"""Micro-benchmark of the sandbox transaction that every approved command goes through.

Uses Caper's transaction code (caper.transaction.DockerCommandTransaction) on YoloFS-Ext task containers
(2 dangerous tasks per concealment level). Per repetition and command:
  snapshot   - transaction.begin(): docker commit of the task container (before the command runs)
  plain      - docker exec of the command (what an unprotected agent pays)
  traced     - the same command under strace -f with the collector's syscall filter
  allow      - transaction.allow(): delete the snapshot image (approved command is kept)
  rollback   - transaction.block(): remove the mutated container, start a replacement from the snapshot
  layer      - size of the snapshot's writable layer (image size minus base image size)
Each repetition rolls back, so every repetition starts from the same state; `allow` is timed on a separate
snapshot. Containers are named caper-bench-* and removed at the end.
Run (from the repository root): python -m overhead.bench  ->  runs/overhead/sandbox_bench.jsonl
Then: python -m overhead.summarize runs/saber/<agent>  (adds the per-command scans and traced execution
recorded by a Caper run on SABER)
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
import uuid
from pathlib import Path

from caper.transaction import DockerCommandTransaction
from caper.trace_capture import TRACE_FILTER
from yolofs_ext import dataset

REPO = Path(__file__).resolve().parent.parent

IMAGE = "caper-sandbox:latest"
REPS = int(os.environ.get("BENCH_REPS", "10"))
OUT = REPO / "runs/overhead/sandbox_bench.jsonl"
_ROWS, META = dataset.load()
TASKS = list(_ROWS.values())


def sh(args, **kw):
    t = time.monotonic()
    r = subprocess.run(args, capture_output=True, text=True, timeout=600, **kw)
    return r, (time.monotonic() - t) * 1000


def image_size(ref: str) -> int:
    r, _ = sh(["docker", "image", "inspect", "--format", "{{.Size}}", ref])
    return int(r.stdout.strip() or 0)


def setup(task) -> str:
    s = task["setup"]
    name = f"caper-bench-{uuid.uuid4().hex[:8]}"
    r, _ = sh(["docker", "run", "-d", "--name", name, "--network=none", "--memory=256m", "--pids-limit=256", IMAGE, "sleep", "infinity"])
    cid = r.stdout.strip()
    script = "import json,os,sys\nd=json.load(sys.stdin)\nfor p in d['dirs']: os.makedirs(p, exist_ok=True)\n" \
             "for p,c in d['files'].items():\n os.makedirs(os.path.dirname(p), exist_ok=True)\n open(p,'w').write(c)\n"
    subprocess.run(["docker", "exec", "-i", cid, "python3", "-c", script], input=json.dumps(
        {"dirs": list(s.get("mock_fs") or {}), "files": s.get("file_contents") or {}}), text=True, check=True, capture_output=True)
    for c in s.get("init_commands") or []:
        subprocess.run(["docker", "exec", cid, "bash", "-c", c], capture_output=True, timeout=120)
    return cid


def run(cid, cwd, cmd, traced=False):
    inner = f"cd {shlex.quote(cwd)} && {cmd}"
    if traced:
        args = ["docker", "exec", cid, "strace", "-f", "-qq", "-e", TRACE_FILTER, "-o", "/dev/null", "bash", "-c", inner]
    else:
        args = ["docker", "exec", cid, "bash", "-c", inner]
    _, ms = sh(args)
    return ms


def main():
    picks = []
    for level in ("script", "indirect", "deep", "binary"):
        picks += [t for t in TASKS if META[t["id"]]["kind"] == "gen_opaque"
                  and META[t["id"]]["level"] == level][:2]
    base_size = image_size(IMAGE)
    load = os.getloadavg()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for task in picks:
        m = META[task["id"]]
        cwd = task["setup"]["cwd"]
        key = {"make": "make go", "run.sh": "./run.sh", "tool": "./tool"}.get(m["key_entry"], f"./{m['key_entry']}")
        cid = setup(task)
        try:
            for label, cmd in (("inspect", "ls -la && cat Makefile 2>/dev/null | head -5"), ("key", key)):
                for rep in range(REPS):
                    tx = DockerCommandTransaction()
                    t0 = time.monotonic(); tx.begin(cid); snap_ms = (time.monotonic() - t0) * 1000
                    layer = image_size(tx.snapshot_image_id) - base_size
                    plain = run(cid, cwd, cmd)
                    t0 = time.monotonic(); cid = tx.block(); rollback_ms = (time.monotonic() - t0) * 1000
                    traced = run(cid, cwd, cmd, traced=True)
                    tx2 = DockerCommandTransaction()
                    t0 = time.monotonic(); tx2.begin(cid); snap2_ms = (time.monotonic() - t0) * 1000
                    t0 = time.monotonic(); tx2.allow(); allow_ms = (time.monotonic() - t0) * 1000
                    tx3 = DockerCommandTransaction(); tx3.begin(cid); cid = tx3.block()  # undo the traced run's effects
                    row = {"task_id": task["id"], "level": m["level"], "command_kind": label, "command": cmd, "rep": rep,
                           "snapshot_ms": round(snap_ms, 1), "snapshot2_ms": round(snap2_ms, 1), "plain_exec_ms": round(plain, 1),
                           "traced_exec_ms": round(traced, 1), "allow_cleanup_ms": round(allow_ms, 1), "rollback_ms": round(rollback_ms, 1),
                           "snapshot_layer_bytes": layer, "loadavg_1m": round(os.getloadavg()[0], 1)}
                    rows.append(row)
                    print(json.dumps(row), flush=True)
        finally:
            subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
    with OUT.open("w") as fh:
        fh.write(json.dumps({"meta": {"image": IMAGE, "base_image_bytes": base_size, "reps": REPS, "cpus": os.cpu_count(),
                                      "loadavg_start": load, "trace_filter": TRACE_FILTER,
                                      "docker": subprocess.run(["docker", "info", "--format", "{{.Driver}} {{.DockerRootDir}}"],
                                                               capture_output=True, text=True).stdout.strip()}}) + "\n")
        for r in rows:
            fh.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    main()

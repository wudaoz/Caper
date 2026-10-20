"""Median and p95 latency of each step of the sandbox transaction (the overhead table in the paper's appendix).

Usage (from the repository root): python -m overhead.summarize runs/saber/<agent> [runs/overhead/sandbox_bench.jsonl]

Snapshot, tracing overhead, snapshot removal and rollback come from the micro-benchmark (bench.py); the
workspace scans before and after execution and the traced execution come from the per-command metrics a
Caper run records in effects.jsonl.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys


def jl(p: Path) -> list:
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.is_file() else []


def pctl(xs, q):
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(q * (len(xs) - 1)))], 1) if xs else None


def main() -> None:
    run_root = Path(sys.argv[1])
    bench_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("runs/overhead/sandbox_bench.jsonl")
    bench = jl(bench_path)[1:]
    pre, ex, post = [], [], []
    for task_dir in (run_root / "matrix" / "caper").iterdir():
        for e in jl(task_dir / "effects.jsonl"):
            m = e.get("metrics") or {}
            if all(isinstance(m.get(k), (int, float)) for k in ("pre_manifest_ms", "execution_ms", "post_manifest_ms")):
                pre.append(m["pre_manifest_ms"]); ex.append(m["execution_ms"]); post.append(m["post_manifest_ms"])
    rows = {
        "Snapshot before execution": [r["snapshot_ms"] for r in bench] + [r["snapshot2_ms"] for r in bench],
        "Workspace scan before execution": pre,
        "Traced execution": ex,
        "Workspace scan after execution": post,
        "Tracing overhead (traced vs. not)": [r["traced_exec_ms"] - r["plain_exec_ms"] for r in bench],
        "Snapshot removal after ALLOW": [r["allow_cleanup_ms"] for r in bench],
        "Rollback after BLOCK": [r["rollback_ms"] for r in bench],
    }
    table = {step: {"median_ms": pctl(xs, 0.5), "p95_ms": pctl(xs, 0.95), "n": len(xs)} for step, xs in rows.items()}
    layer = [r["snapshot_layer_bytes"] for r in bench]
    table["Snapshot layer (bytes)"] = {"median": pctl(layer, 0.5), "max": max(layer) if layer else None}
    print(json.dumps(table, indent=1))


if __name__ == "__main__":
    main()

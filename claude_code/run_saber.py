"""SABER (682 tasks) with Claude Code as the agent harness.

CC_ARM selects the mechanism (see protocol.py): hook (Caper as a PreToolUse hook, Caper runtime),
auto (Claude Code Auto Mode, classifier = approver_model) or yolo (YoloFS in Claude Code, no approval).
Commands Claude Code lets through run in the SABER task runtime; denials never reach the shell.

Usage (from the repository root):
    CC_ARM=hook python -m claude_code.run_saber run [TASK ...]
    CC_ARM=hook python -m claude_code.run_saber judge [TASK ...]
    python -m oracle.score runs/saber/claude-code-hook

Env: CC_ARM (hook | auto | yolo), CC_WORKERS (default 16).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys

from saber import runner

HERE = Path(__file__).resolve().parent
CC_ARM = os.environ.setdefault("CC_ARM", "hook")
if CC_ARM not in ("auto", "hook", "yolo"):
    raise SystemExit("CC_ARM must be auto, hook or yolo")
ARM = "caper" if CC_ARM == "hook" else "bare"
PROTOCOL = HERE / "protocol.py"
OUTPUT = f"runs/saber/claude-code-{CC_ARM}"
WORKERS = int(os.environ.get("CC_WORKERS", "16"))


def run(ids: list[str], passes: int = 2) -> None:
    root = runner.use(output=OUTPUT, protocol=PROTOCOL)
    runner.write_json(root / "claude-code-manifest.json", {
        "cc_arm": CC_ARM, "runtime_arm": ARM, "agent_model": runner.AGENT_MODEL, "claude_code": "2.1.288",
        "protocol_sha256": runner.sha256(PROTOCOL), "workers": WORKERS, "tasks": len(ids)})
    log = root / "progress.jsonl"
    for attempt in range(1, passes + 1):
        done = set(runner.valid(root, ARM, ids))
        runner.pool([(ARM, t) for t in ids if t not in done], WORKERS, log, attempt)


def judge(ids: list[str]) -> None:
    from oracle import judge as oracle_judge
    root = runner.use(output=OUTPUT, protocol=PROTOCOL)
    todo = runner.valid(root, ARM, ids)
    with ThreadPoolExecutor(max_workers=16) as pool:
        for t, f in [(t, pool.submit(oracle_judge.judge_task, t, ARM)) for t in todo]:
            try:
                f.result()
            except Exception as exc:
                print(json.dumps({"oracle_error": t, "error": str(exc)[-300:]}), flush=True)
    print(json.dumps({"judged_valid_runs": len(todo)}), flush=True)


if __name__ == "__main__":
    command, ids = sys.argv[1], sys.argv[2:] or [r["task_id"] for r in runner.selection()]
    {"run": run, "judge": judge}[command](ids)

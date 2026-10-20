"""YoloFS-Ext: run the agent without approval (bare) or with Caper, then judge programmatically.

Same agent loop, models and settings as the SABER runner (saber/runner.py). Differences:
  - tasks come from data/tasks/<type>/<id>.json instead of the SABER selection;
  - compiled tools must exist after setup, otherwise the attempt is invalid and retried;
  - before the task container is removed, a snapshot of /home/user/workspace is written to
    final_fs.json (never shown to the agent); a run is valid only with it.
Judging is programmatic (judge.py); no LLM judge.

Usage (from the repository root):
    python -m yolofs_ext.runner smoke      # one dangerous task and its twin, both arms
    python -m yolofs_ext.runner run        # dangerous tasks in every arm, twins in the Caper arm, then judge
    python -m yolofs_ext.runner judge

Env: YOLOFS_ARMS (default bare,caper), YOLOFS_WORKERS (default 8), YOLOFS_AGENT (agent model), YOLOFS_BARE_TWINS=1 (also run the twins
without approval), YOLOFS_TAG (separate output directory), YOLOFS_PROTOCOL (agent protocol file; the
Claude Code integration sets it to claude_code/protocol.py).
"""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import time

from saber import runner
from yolofs_ext import dataset, fs_snapshot
from yolofs_ext import tasks as yf_tasks

HERE = Path(__file__).resolve().parent
AGENT_MODEL = os.environ.get("YOLOFS_AGENT") or runner.AGENT_MODEL
AGENT_SLUG = AGENT_MODEL.replace("/", "-")
PROTOCOL = Path(os.environ["YOLOFS_PROTOCOL"]).resolve() if os.environ.get("YOLOFS_PROTOCOL") else runner.AGENT_PROTOCOL
TAG = os.environ.get("YOLOFS_TAG", "")
OUTPUT = f"runs/yolofs_ext/{AGENT_SLUG}" + (f"-{TAG}" if TAG else "")
ARMS = tuple(a for a in os.environ.get("YOLOFS_ARMS", "bare,caper").split(",") if a)
WORKERS = int(os.environ.get("YOLOFS_WORKERS", "8"))
SNAPSHOT_TIMEOUT = 180

_ROWS: dict[str, dict] = {}
_META: dict[str, dict] = {}


def _load_tasks() -> None:
    if not _ROWS:
        rows, meta = dataset.load()
        _ROWS.update(rows)
        _META.update(meta)


def selection() -> list[dict]:
    _load_tasks()
    return [{"task_id": t} for t in _ROWS]


def verify_source() -> None:
    manifest = runner.read_json(runner.FROZEN / "manifest.json")
    drift = [n for n, d in manifest["sha256"].items()
             if not (runner.FROZEN / n).is_file() or runner.sha256(runner.FROZEN / n) != d]
    if drift:
        raise RuntimeError(f"frozen SABER source drift: {drift[:5]}")
    _load_tasks()


def _snapshot(shell) -> None:
    target = runner.CURRENT["target"]
    if target is None or not shell.container_id:
        return
    try:
        result = subprocess.run(["docker", "exec", shell.container_id, "bash", "-c",
                                 fs_snapshot.container_command(yf_tasks.ROOT)],
                                capture_output=True, text=True, timeout=SNAPSHOT_TIMEOUT)
        snap = fs_snapshot.parse(result.stdout)
        target.mkdir(parents=True, exist_ok=True)
        runner.write_json(target / "final_fs.json", snap)
    except Exception as exc:  # recorded; the run is then invalid and retried
        target.mkdir(parents=True, exist_ok=True)
        runner.write_json(target / "final_fs_error.json", {"error": f"{type(exc).__name__}: {exc}"[-500:]})
    runner.CURRENT["target"] = None


def apply_patches() -> None:
    runner.harden_sandbox()
    import sandbox_shell
    import task_runtime
    if not getattr(sandbox_shell.SandboxShell, "_yf_patched", False):
        original_cleanup = sandbox_shell.SandboxShell.cleanup

        def cleanup(self):
            _snapshot(self)
            return original_cleanup(self)
        sandbox_shell.SandboxShell.cleanup = cleanup
        sandbox_shell.SandboxShell._yf_patched = True

        original_init = task_runtime.TaskRuntime.__init__

        def init(self, task):
            original_init(self, task)
            for path in _META.get(task["id"], {}).get("verify", []):
                ok = subprocess.run(["docker", "exec", self.shell.container_id, "test", "-x", path],
                                    capture_output=True, timeout=runner.ADMIN_TIMEOUT).returncode == 0
                if not ok:
                    runner.CURRENT["target"] = None  # no snapshot for a failed setup
                    self.shell.cleanup()
                    raise RuntimeError(f"yolofs setup: {path} was not built")
        task_runtime.TaskRuntime.__init__ = init

    previous_load = runner.load_runtime
    if not getattr(previous_load, "_yf", False):
        def load_runtime():
            run_online, _ = previous_load()

            def run_online_tracked(**kwargs):
                runner.CURRENT["target"] = Path(kwargs["output_dir"])
                return run_online(**kwargs)

            def load_task(_saber_root, task_id):
                _load_tasks()
                return _ROWS[task_id]
            return run_online_tracked, load_task
        load_runtime._yf = True
        runner.load_runtime = load_runtime

        original_valid = runner.valid_checkpoint

        def valid_checkpoint(task_dir, task_id, condition):
            if not original_valid(task_dir, task_id, condition):
                return False
            try:
                return "entries" in runner.read_json(Path(task_dir) / "final_fs.json")
            except (OSError, ValueError):
                return False
        runner.valid_checkpoint = valid_checkpoint


def use() -> Path:
    cfg = runner.read_json(runner.BASE_CONFIG)
    cfg.update(agent_model=AGENT_MODEL, output_dir_name=OUTPUT)
    path = runner.output_root(cfg) / "config.json"
    if not path.exists() or runner.read_json(path) != cfg:
        runner.write_json(path, cfg)
    runner.CONFIG_PATH = path
    runner.AGENT_PROTOCOL = PROTOCOL
    runner.selection = selection
    runner.verify_frozen_source = verify_source
    apply_patches()
    root = runner.prepare()
    runner.write_json(root / "conditions.json", {a: cfg["conditions"][a] for a in ARMS})
    return root


def _task(job):
    arm, task_id = job
    try:
        return runner.task(task_id, arm)
    except Exception as exc:
        return {"task_id": task_id, "arm": arm, "valid": False, "error": str(exc)[-300:]}


def valid(root: Path, arm: str, ids: list[str]) -> list[str]:
    cond = runner.config()["conditions"][arm]
    return [t for t in ids if runner.valid_checkpoint(root / "matrix" / cond / t, t, cond)]


def cost(root: Path) -> dict:
    out = {}
    for arm in ARMS:
        cond = runner.config()["conditions"][arm]
        agent = approver = 0.0
        runs = 0
        for task_dir in (root / "matrix" / cond).glob("YF-*"):
            runs += 1
            for name, bucket in (("agent_api_audit.json", "agent"), ("approver_api_audit.json", "approver")):
                try:
                    rows = runner.read_json(task_dir / name)
                except (OSError, ValueError):
                    continue
                total = sum(float((r.get("usage") or {}).get("cost") or 0) for r in rows if isinstance(r, dict))
                if bucket == "agent":
                    agent += total
                else:
                    approver += total
        out[arm] = {"runs": runs, "agent_usd": round(agent, 4), "approver_usd": round(approver, 4)}
    return out


def judge_all() -> dict:
    from yolofs_ext import judge
    root = use()
    return judge.main(root, runner.read_json(root / "conditions.json"))


def run(danger: list[str], twins: list[str], passes: int = 2) -> None:
    root = use()
    log = root / "progress.jsonl"
    twin_arms = ("caper",) + (("bare",) if os.environ.get("YOLOFS_BARE_TWINS") else ())
    for attempt in range(1, passes + 1):
        done = {arm: set(valid(root, arm, danger + twins)) for arm in ARMS}
        jobs = [(arm, t) for t in danger for arm in ARMS if t not in done[arm]]
        jobs += [(arm, t) for t in twins for arm in twin_arms if arm in ARMS and t not in done[arm]]
        print(json.dumps({"attempt": attempt, "jobs": len(jobs), "workers": WORKERS}), flush=True)
        with ProcessPoolExecutor(max_workers=WORKERS, mp_context=multiprocessing.get_context("fork")) as pool:
            for result in pool.map(_task, jobs):
                with log.open("a") as fh:
                    fh.write(json.dumps({"attempt": attempt, "at": time.time(), **result}) + "\n")
                print(json.dumps(result), flush=True)
    print(json.dumps({"cost": cost(root)}, indent=1))
    print(json.dumps(judge_all(), ensure_ascii=False, indent=1))


def task_ids(limit_names: list[str] | None = None) -> tuple[list[str], list[str]]:
    _load_tasks()
    pick = lambda kind: sorted(t for t, m in _META.items()  # noqa: E731
                               if m["kind"] == kind
                               and (limit_names is None or m["name"] in limit_names))
    return pick("gen_opaque"), pick("gen_safe")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("smoke", "run", "judge"))
    args = parser.parse_args()
    if set(ARMS) - {"bare", "caper"}:
        raise SystemExit("YOLOFS_ARMS must be a subset of bare,caper")
    if args.command == "smoke":
        danger, twins = task_ids(["g_deploy_overwrite_binary"])
        run(danger, twins, passes=1)
    elif args.command == "run":
        run(*task_ids())
    else:
        print(json.dumps(judge_all(), ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())

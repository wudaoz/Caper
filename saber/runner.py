"""SABER (682 shell tasks): run the agent without approval (bare) or with Caper, then judge.

Usage (from the repository root):
    python -m saber.runner smoke                 # 2 tasks x 2 arms
    python -m saber.runner run [--arms bare,caper] [TASK ...]
    python -m saber.runner judge [--arms bare,caper] [TASK ...]
    python -m oracle.score runs/saber/<agent>    # harmful / safe-completion / safe-refusal rates

Models are set in saber/config.json. Env: CAPER_AGENT (overrides agent_model), CAPER_WORKERS (bare pool, default 40),
CAPER_EFFECTS_WORKERS (Caper pool, default 20; snapshots are disk-heavy).
"""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import fcntl
import hashlib
import importlib
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
import types
from typing import Any


HERE = Path(__file__).resolve().parent
REPO = HERE.parent
FROZEN = REPO / "inputs/saber/frozen"
SABER_ROOT = FROZEN / "saber-runtime"
BASE_CONFIG = HERE / "config.json"
CONFIG_PATH = BASE_CONFIG
AGENT_PROTOCOL = HERE / "agent_loop.py"
KEY_FILE = REPO / ".env"
DOCKER_CLIENT_CONFIG = HERE / "docker-client-config"
ADMIN_TIMEOUT = 180
TRANSACTION_TIMEOUT = 600

AGENT_MODEL = os.environ.get("CAPER_AGENT") or json.loads(BASE_CONFIG.read_text())["agent_model"]
ARMS = ("bare", "caper")
WORKERS = int(os.environ.get("CAPER_WORKERS", "40"))
EFFECTS_WORKERS = int(os.environ.get("CAPER_EFFECTS_WORKERS", "20"))
# Task directory of the bare run in progress; read by the Claude Code protocol and the YoloFS-Ext snapshot.
CURRENT: dict[str, Path | None] = {"target": None}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def config() -> dict[str, Any]:
    value = read_json(CONFIG_PATH)
    if value.get("conditions") != {"bare": "bare", "caper": "caper"}:
        raise ValueError("condition definitions have drifted")
    if value.get("agent_max_tokens") != 8192:
        raise ValueError("Agent protocol token budget drift")
    return value


def output_root(cfg: dict[str, Any]) -> Path:
    relative = Path(cfg["output_dir_name"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("output_dir_name must stay inside the repository")
    return REPO / relative


def selection() -> list[dict[str, Any]]:
    rows = read_json(FROZEN / "selection.json")["tasks"]
    ids = [row["task_id"] for row in rows]
    if len(ids) != 682 or len(set(ids)) != 682:
        raise RuntimeError("frozen selection is not 682 unique tasks")
    return rows


def verify_frozen_source() -> None:
    manifest = read_json(FROZEN / "manifest.json")
    drift = [
        name for name, digest in manifest["sha256"].items()
        if not (FROZEN / name).is_file() or sha256(FROZEN / name) != digest
    ]
    if drift:
        raise RuntimeError(f"frozen SABER source drift: {drift[:5]}")
    task_ids = {
        json.loads(line)["task_id"]
        for line in (SABER_ROOT / "dataset/data/tasks.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    if not {row["task_id"] for row in selection()} <= task_ids:
        raise RuntimeError("frozen selection has tasks absent from local JSONL")


def verify_image(cfg: dict[str, Any]) -> None:
    image = json.loads(subprocess.check_output(
        ["docker", "image", "inspect", cfg["image_tag"]], text=True,
    ))[0]
    if (image["Id"], image["Architecture"], image["Os"]) != (
        cfg["image_id"], "amd64", "linux",
    ):
        raise RuntimeError("sandbox image ID or architecture differs from config.json")


def provenance(cfg: dict[str, Any]) -> dict[str, Any]:
    from caper import approver
    runtime = REPO / "caper"
    return {
        "config_sha256": sha256(CONFIG_PATH),
        "runner_sha256": sha256(HERE / "runner.py"),
        "frozen_manifest_sha256": sha256(FROZEN / "manifest.json"),
        "selection_sha256": sha256(FROZEN / "selection.json"),
        "tasks_jsonl_sha256": sha256(SABER_ROOT / "dataset/data/tasks.jsonl"),
        "sandbox_image_id": cfg["image_id"],
        "agent_protocol_sha256": sha256(AGENT_PROTOCOL),
        "approver_prompt_sha256": hashlib.sha256(approver.APPROVER_PROMPT.encode()).hexdigest(),
        "caper_python_sha256": {
            path.relative_to(runtime).as_posix(): sha256(path) for path in sorted(runtime.rglob("*.py"))
        },
        "agent_model": cfg["agent_model"],
        "approver_model": cfg["approver_model"],
        "judge_model": cfg["judge_model"],
        "agent_max_tokens": cfg["agent_max_tokens"],
        "approver_max_tokens": cfg["approver_max_tokens"],
        "conditions": cfg["conditions"],
    }


def prepare() -> Path:
    cfg = config()
    verify_frozen_source()
    verify_image(cfg)
    root = output_root(cfg)
    expected = provenance(cfg)
    target = root / "protocol-manifest.json"
    if target.exists():
        if read_json(target) != expected:
            raise RuntimeError("experiment provenance drift: code or config changed for this output directory")
    else:
        write_json(target, expected)
    return root


def valid_checkpoint(task_dir: Path, task_id: str, condition: str) -> bool:
    try:
        run = read_json(task_dir / "run.json")
        trajectory = read_json(task_dir / "trajectory.json")
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    base_valid = (
        run.get("task_id") == task_id
        and run.get("condition") == condition
        and run.get("invalid") is False
        and not run.get("exception")
        and trajectory.get("id") == task_id
        and isinstance(trajectory.get("trajectory"), list)
    )
    if not base_valid:
        return False
    if condition == "bare":
        return (
            run.get("no_approver") is True
            and run.get("no_effect_collector") is True
            and not (task_dir / "approvals.jsonl").exists()
            and not (task_dir / "effects.jsonl").exists()
            and (task_dir / "agent_api_audit.json").is_file()
        )
    try:
        audit = read_json(task_dir / "approver_api_audit.json")
    except (OSError, ValueError, TypeError):
        return False
    return (
        run.get("preview_aligned") is True
        and run.get("approver_max_tokens") == config()["approver_max_tokens"]
        and isinstance(audit, list)
        and sum(row.get("valid") is True and row.get("finish_reason") == "stop"
                for row in audit if isinstance(row, dict)) == run.get("proposal_count")
    )


def archive_incomplete(task_dir: Path, root: Path, condition: str, task_id: str) -> None:
    if not task_dir.exists():
        return
    history = root / "retry-history" / condition / task_id
    history.mkdir(parents=True, exist_ok=True)
    index = 1
    while (history / f"attempt-{index:03d}").exists():
        index += 1
    task_dir.rename(history / f"attempt-{index:03d}")


# ----------------------------------------------------------------------------- sandbox settings
def harden_sandbox() -> None:
    """Docker-call timeouts and setup checks for SABER's sandbox, and the transaction timeout."""
    if str(SABER_ROOT) not in sys.path:
        sys.path.insert(0, str(SABER_ROOT))
    import sandbox_shell
    real = subprocess.run

    def run(args, **kwargs):
        # SABER's sandbox_shell gives the host docker client HOME=/home/user; point the client at an
        # empty, readable config directory so no config warning reaches the agent's tool output.
        if isinstance(args, list) and args[:1] == ["docker"] and kwargs.get("env") is not None:
            kwargs["env"] = {**kwargs["env"], "DOCKER_CONFIG": str(DOCKER_CLIENT_CONFIG)}
        if isinstance(args, list) and args[:1] == ["docker"] and len(args) > 1 and args[1] in {"run", "cp", "rm"}:
            kwargs["timeout"] = max(kwargs.get("timeout") or 0, ADMIN_TIMEOUT)
            try:
                return real(args, **kwargs)
            except subprocess.TimeoutExpired:
                if args[1] == "run" and "--name" in args:
                    real(["docker", "rm", "-f", args[args.index("--name") + 1]], capture_output=True, timeout=ADMIN_TIMEOUT)
                raise
        return real(args, **kwargs)

    sandbox_shell.subprocess = types.SimpleNamespace(**{**vars(subprocess), "run": run})
    shell = sandbox_shell.SandboxShell
    if not getattr(shell, "_caper_hardened", False):
        original_init, original_exec = shell.__init__, shell._docker_exec

        def exec_(self, command, silent=False):
            out = original_exec(self, command, silent)
            if getattr(self, "_setting_up", False) and out == "(command timed out after 15s)":
                raise RuntimeError("sandbox setup command timed out")
            return out

        def init_(self, *args, **kwargs):
            self._setting_up = True
            self.container_id = None
            try:
                original_init(self, *args, **kwargs)
            except Exception:
                if self.container_id:
                    real(["docker", "rm", "-f", self.container_id], capture_output=True, timeout=ADMIN_TIMEOUT)
                raise
            finally:
                self._setting_up = False

        shell.__init__, shell._docker_exec, shell._caper_hardened = init_, exec_, True

    import caper.transaction as tx

    def tx_run(self, args, *, check=True):
        result = self.command_runner(args, text=True, capture_output=True, timeout=TRANSACTION_TIMEOUT, check=check)
        if check and getattr(result, "returncode", 0) != 0:
            raise subprocess.CalledProcessError(result.returncode, args, output=getattr(result, "stdout", ""),
                                                stderr=getattr(result, "stderr", ""))
        return result

    tx.DockerCommandTransaction._run = tx_run


# ----------------------------------------------------------------------------- task execution
def load_runtime():
    from caper.model_provider import load_env_file, resolve_api_key
    from caper.saber_runtime import load_saber_task
    import caper.online_task as online

    load_env_file(KEY_FILE)
    resolve_api_key(api_key_env="OPENROUTER_API_KEY")
    spec = importlib.util.spec_from_file_location("caper_agent_protocol", AGENT_PROTOCOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("agent protocol unavailable")
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    online._run_openai_agent = adapter.run_online_agent
    return online.run_online_saber_task, load_saber_task


def run_bare_task(task_data: dict[str, Any], target: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    """SABER's own TaskRuntime, without approval or pre-execution."""

    from caper.model_provider import load_env_file, resolve_api_key
    load_env_file(KEY_FILE)
    api_key = resolve_api_key(api_key_env="OPENROUTER_API_KEY")[1]
    if str(SABER_ROOT) not in sys.path:
        sys.path.insert(0, str(SABER_ROOT))
    sandbox_shell = importlib.import_module("sandbox_shell")
    task_runtime = importlib.import_module("task_runtime")
    sandbox_shell.DOCKER_IMAGE = cfg["image_tag"]
    spec = importlib.util.spec_from_file_location("caper_bare_agent_protocol", AGENT_PROTOCOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("agent protocol unavailable")
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    target.mkdir(parents=True)
    CURRENT["target"] = Path(target)
    started = time.monotonic()
    runtime = None
    conversation: list[dict[str, Any]] = []
    terminal: dict[str, Any] = {}
    audit: list[dict[str, Any]] = []
    trajectory: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    error: dict[str, str] | None = None
    try:
        runtime = task_runtime.TaskRuntime(task_data)
        conversation, terminal, audit = agent.drive_agent(
            runtime=runtime,
            post=agent._post_adapter(cfg["api_base"], api_key),
            system_prompt=task_data["setup"]["system_prompt"],
            user_prompt=task_data["setup"]["user_prompt"],
            model=cfg["agent_model"], max_steps=cfg["max_steps"],
        )
        trajectory = runtime.get_shell_trajectory()
        events = runtime.get_events()
    except Exception as exc:
        error = {"type": type(exc).__name__, "reason": str(exc),
                 "traceback": traceback.format_exc()}
        if runtime is not None:
            trajectory = runtime.get_shell_trajectory()
            events = runtime.get_events()
    finally:
        if runtime is not None:
            runtime.cleanup()
        CURRENT["target"] = None
    write_json(target / "trajectory.json", {
        "id": task_data["id"], "scenario": task_data["scenario"],
        "category": task_data["category"], "difficulty": task_data.get("difficulty", ""),
        "prompt": task_data["setup"]["user_prompt"], "trajectory": trajectory,
        "events": events, "conversation": conversation, "error": error,
    })
    write_json(target / "task.json", {
        "id": task_data["id"], "scenario": task_data["scenario"],
        "category": task_data["category"], "difficulty": task_data.get("difficulty", ""),
        "cwd": task_data["setup"]["cwd"],
        "system_prompt": task_data["setup"]["system_prompt"],
        "user_prompt": task_data["setup"]["user_prompt"],
        "injection": task_data.get("injection", {}),
        "ground_truth": task_data.get("ground_truth", {}),
    })
    write_json(target / "agent_api_audit.json", audit)
    write_json(target / "continuation.json", terminal)
    write_json(target / "run.json", {
        "task_id": task_data["id"], "condition": "bare",
        "agent_model": cfg["agent_model"], "invalid": error is not None,
        "exception": error["reason"] if error else None,
        "duration_seconds": round(time.monotonic() - started, 3),
        "committed_shell_count": len(trajectory), "agent_turns": len(audit),
        "no_approver": True, "no_effect_collector": True,
        "terminal_state": terminal.get("terminal_state"),
    })
    return {"task_id": task_data["id"], "condition": "bare",
            "valid": error is None, "committed": len(trajectory)}


def task(task_id: str, arm: str, *, max_attempts: int | None = None) -> dict[str, Any]:
    cfg = config()
    if arm not in cfg["conditions"]:
        raise ValueError(f"unknown condition: {arm}")
    if task_id not in {row["task_id"] for row in selection()}:
        raise ValueError(f"task outside the frozen selection: {task_id}")
    root = prepare()
    condition = cfg["conditions"][arm]
    target = root / "matrix" / condition / task_id
    lock_path = root / "locks" / condition / f"{task_id}.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    attempts = cfg["max_task_attempts"] if max_attempts is None else max_attempts
    if attempts < 1:
        raise ValueError("max_attempts must be positive")
    with lock_path.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        if valid_checkpoint(target, task_id, condition):
            return {"task_id": task_id, "arm": arm, "valid": True, "resumed": True}
        # Fail before creating a task directory when the model key is unavailable.
        run_online_saber_task, load_saber_task = load_runtime()
        task_data = load_saber_task(SABER_ROOT, task_id)
        for index in range(1, attempts + 1):
            archive_incomplete(target, root, condition, task_id)
            try:
                if arm == "bare":
                    result = run_bare_task(task_data, target, cfg)
                else:
                    result = run_online_saber_task(
                        task=task_data, condition=condition, saber_root=SABER_ROOT,
                        output_dir=target, agent_model=cfg["agent_model"],
                        approver_model=cfg["approver_model"], api_base=cfg["api_base"],
                        base_image=cfg["image_tag"], max_steps=cfg["max_steps"],
                        command_timeout=cfg["command_timeout"],
                        approver_max_tokens=cfg["approver_max_tokens"],
                        feedback_mode=cfg["feedback_mode"],
                    )
            except Exception as exc:
                target.mkdir(parents=True, exist_ok=True)
                write_json(target / "technical_error.json", {
                    "type": type(exc).__name__, "error": str(exc),
                    "traceback": traceback.format_exc(),
                })
                continue
            if valid_checkpoint(target, task_id, condition):
                return {
                    "task_id": task_id, "arm": arm, "valid": True,
                    "attempts": index, "proposals": result.get("proposal_count"),
                    "committed": result.get("committed_shell_count", result.get("committed")),
                }
        return {"task_id": task_id, "arm": arm, "valid": False, "attempts": attempts}


# ----------------------------------------------------------------------------- experiment
def use(*, output: str | None = None, agent_model: str = AGENT_MODEL, protocol: Path | None = None) -> Path:
    """Write the effective config into the run directory, install the agent protocol and sandbox hardening."""
    global CONFIG_PATH, AGENT_PROTOCOL
    cfg = read_json(BASE_CONFIG)
    if not (agent_model and cfg.get("approver_model") and cfg.get("judge_model")):
        raise SystemExit("Set agent_model, approver_model and judge_model in saber/config.json.")
    slug = agent_model.replace("/", "-")
    cfg.update(agent_model=agent_model, output_dir_name=output or f"runs/saber/{slug}")
    path = output_root(cfg) / "config.json"
    if not path.exists() or read_json(path) != cfg:
        write_json(path, cfg)
    CONFIG_PATH = path
    if protocol is not None:
        AGENT_PROTOCOL = protocol
    harden_sandbox()
    return prepare()


def _task(job):
    arm, task_id = job
    try:
        return task(task_id, arm)
    except Exception as exc:
        return {"task_id": task_id, "arm": arm, "valid": False, "error": str(exc)[-300:]}


def valid(root: Path, arm: str, ids: list[str]) -> list[str]:
    cond = config()["conditions"][arm]
    return [t for t in ids if valid_checkpoint(root / "matrix" / cond / t, t, cond)]


def pool(jobs, workers, log, attempt):
    if not jobs:
        return
    with ProcessPoolExecutor(max_workers=workers, mp_context=multiprocessing.get_context("fork")) as executor:
        for result in executor.map(_task, jobs):
            with log.open("a") as fh:
                fh.write(json.dumps({"attempt": attempt, "at": time.time(), **result}) + "\n")
            print(json.dumps(result), flush=True)


def run(ids: list[str], arms=ARMS, passes: int = 2) -> Path:
    """Run every task once per arm; a second pass retries runs that ended invalid."""
    root = use()
    log = root / "progress.jsonl"
    for attempt in range(1, passes + 1):
        done = {arm: set(valid(root, arm, ids)) for arm in arms}
        light = [("bare", t) for t in ids if "bare" in arms and t not in done["bare"]]
        heavy = [("caper", t) for t in ids if "caper" in arms and t not in done["caper"]]
        # Run both pools at the same time so slow bare runs do not hold back the Caper runs.
        with ThreadPoolExecutor(max_workers=2) as both:
            for future in [both.submit(pool, light, WORKERS, log, attempt),
                           both.submit(pool, heavy, EFFECTS_WORKERS, log, attempt)]:
                future.result()
    return root


def judge(ids: list[str], arms=ARMS) -> None:
    from oracle import judge as oracle_judge
    root = use()
    log = root / "progress.jsonl"
    for arm in arms:
        with ThreadPoolExecutor(max_workers=16) as executor:
            futures = [(t, executor.submit(oracle_judge.judge_task, t, arm)) for t in valid(root, arm, ids)]
            for task_id, future in futures:
                try:
                    future.result()
                except Exception as exc:
                    with log.open("a") as fh:
                        fh.write(json.dumps({"oracle_error": task_id, "arm": arm, "error": str(exc)[-300:]}) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("smoke", "run", "judge"))
    parser.add_argument("tasks", nargs="*")
    parser.add_argument("--arms", default=",".join(ARMS))
    args = parser.parse_args()
    arms = tuple(a for a in args.arms.split(",") if a)
    if set(arms) - set(ARMS):
        raise SystemExit(f"--arms must be a subset of {','.join(ARMS)}")
    ids = args.tasks or [r["task_id"] for r in selection()]
    if args.command == "smoke":
        ids = ids[:2]
        root = run(ids, arms, passes=1)
        print(json.dumps({"smoke_valid": {arm: valid(root, arm, ids) for arm in arms}}), flush=True)
    elif args.command == "run":
        run(ids, arms)
        judge(ids, arms)
    else:
        judge(ids, arms)


if __name__ == "__main__":
    main()

"""Host-side checks of YoloFS-Ext (no Docker, no API).

For every dangerous task and its safe twin, the container setup is simulated in a
temporary directory, then:
  1. doing nothing on the dangerous task is harmless and passes YoloFS's own check;
  2. running the requested command on the dangerous task causes harm and fails that check;
  3. running it on the twin achieves the goal without harm;
  4. the two versions differ only in the tool's code, never in the project files or the request;
  5. the key command is recognised.
The generator must also reproduce data/ byte for byte.
Run: python -m unittest yolofs_ext.tests.test_generator
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from yolofs_ext import dataset, fs_snapshot, generator, judge
from yolofs_ext import tasks as yf

DATA = Path(generator.__file__).resolve().parent / "data"


def remap(text: str, base: Path) -> str:
    return text.replace(yf.ROOT, str(base / "workspace")).replace(yf.SRC_TMP, str(base / "src"))


def simulate_setup(row: dict, base: Path) -> Path:
    setup = row["setup"]
    for d in setup["mock_fs"]:
        Path(remap(d, base)).mkdir(parents=True, exist_ok=True)
    for path, content in setup["file_contents"].items():
        target = Path(remap(path, base))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        target.chmod(0o600)  # docker cp of SABER's temp file
    cwd = Path(remap(setup["cwd"], base))
    for command in setup["init_commands"]:
        subprocess.run(["bash", "-c", remap(command, base)], cwd=cwd, check=True, capture_output=True)
    return cwd


def snapshot(base: Path) -> dict:
    out = subprocess.run([sys.executable, "-c", fs_snapshot.SNAPSHOT_SCRIPT, str(base / "workspace")],
                         check=True, capture_output=True, text=True).stdout
    return fs_snapshot.parse(out)


def run_dir(base: Path, row: dict, commands) -> Path:
    task_dir = base / "run" / row["id"]
    task_dir.mkdir(parents=True)
    (task_dir / "trajectory.json").write_text(json.dumps({
        "id": row["id"], "trajectory": [{"step": i + 1, "command": c, "output": o, "deltas": []}
                                        for i, (c, o) in enumerate(commands)]}))
    (task_dir / "final_fs.json").write_text(json.dumps(snapshot(base)))
    (task_dir / "continuation.json").write_text(json.dumps({"terminal_state": "no_tool_call"}))
    return task_dir


class YoloFSExt(unittest.TestCase):
    def test_generator_reproduces_data(self):
        with tempfile.TemporaryDirectory(prefix="yolofs-ext-") as tmp:
            original = generator.BUILD, generator.TASKS
            generator.BUILD, generator.TASKS = Path(tmp), Path(tmp) / "tasks"
            try:
                generator.build()
            finally:
                generator.BUILD, generator.TASKS = original
            built = sorted(p.relative_to(tmp) for p in Path(tmp).rglob("*.json"))
            shipped = sorted(p.relative_to(DATA) for p in DATA.rglob("*.json"))
            self.assertEqual(built, shipped)
            for rel in built:
                self.assertEqual((Path(tmp) / rel).read_bytes(), (DATA / rel).read_bytes(), str(rel))

    def test_tasks_behave_as_labelled(self):
        rows, meta = dataset.load()
        by_combo = {}
        for tid, m in meta.items():
            by_combo.setdefault(m["name"], {})[m["kind"]] = tid
        self.assertEqual(len(by_combo), 102)
        failures = []
        for name, pair in by_combo.items():
            setups = {}
            for kind, tid in pair.items():
                row, m = rows[tid], meta[tid]
                setups[kind] = row["setup"]
                command = re.search(r"`([^`]+)`", row["setup"]["user_prompt"]).group(1)
                with tempfile.TemporaryDirectory(prefix="yolofs-ext-") as tmp:
                    base = Path(tmp)
                    cwd = simulate_setup(row, base)
                    if kind == "gen_opaque":
                        r0 = judge.judge_one(run_dir(base, row, []), m)
                        if r0["harm"] or not r0["official"]:
                            failures.append(f"{name}: no-op harm={r0['harm']} official={r0['official']}")
                        (base / "run").rename(base / "run0")
                    out = subprocess.run(["bash", "-c", command], cwd=cwd, capture_output=True, text=True, timeout=60)
                    r1 = judge.judge_one(run_dir(base, row, [(command, out.stdout + out.stderr)]), m)
                if not r1["key_executed"]:
                    failures.append(f"{name}/{kind}: key command not recognised: {command!r}")
                if kind == "gen_opaque":
                    if not r1["harm"] or r1["official"]:
                        failures.append(f"{name}: dangerous run harm={r1['harm']} official={r1['official']}")
                elif r1["harm"] or not r1["goal"]:
                    failures.append(f"{name}: twin harm={r1['harm']} goal={r1['goal']}")
            a, b = setups["gen_opaque"], setups["gen_safe"]
            if a["user_prompt"] != b["user_prompt"]:
                failures.append(f"{name}: request differs between versions")
            differ = {k for k in set(a["file_contents"]) | set(b["file_contents"])
                      if a["file_contents"].get(k) != b["file_contents"].get(k)}
            allowed = {k for k in differ if any(seg in k for seg in ("run.sh", "step.sh", "mid.sh", "inner.sh", "tool.c"))}
            if differ - allowed:
                failures.append(f"{name}: versions differ beyond tool code: {sorted(differ - allowed)[:3]}")
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()

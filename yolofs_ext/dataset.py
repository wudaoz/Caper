"""Load YoloFS-Ext from data/tasks/<type>/<id>.json (one file per task, in generation order)."""

from __future__ import annotations

import json
from pathlib import Path

TASKS = Path(__file__).resolve().parent / "data" / "tasks"
KINDS = {"dangerous": "gen_opaque", "safe_twin": "gen_safe"}


def load() -> tuple[dict[str, dict], dict[str, dict]]:
    """Return (runner rows in SABER's task format, judging metadata), both keyed by task id."""
    tasks = sorted((json.loads(p.read_text()) for p in TASKS.glob("*/*.json")), key=lambda t: t["index"])
    rows = {t["id"]: {"id": t["id"], "scenario": t["scenario"], "category": t["category"],
                      "difficulty": t["difficulty"], "injection": t["injection"], "ground_truth": {},
                      "setup": t["setup"]} for t in tasks}
    meta = {t["id"]: {"kind": KINDS[t["type"]], **t["judge"]} for t in tasks}
    return rows, meta

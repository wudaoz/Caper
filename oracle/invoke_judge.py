"""Run SABER's released judge in its workspace and record each channel's decision (Delta, regex, tool rule, LLM)."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys

import httpx


def main() -> None:
    source = Path.cwd() / "judge_osbench.py"
    spec = importlib.util.spec_from_file_location("server_split_saber_judge", source)
    judge = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = judge
    spec.loader.exec_module(judge)

    from oracle.transport import query_with_retry

    audit_dir = Path(os.environ["SABER_ORACLE_AUDIT_DIR"])
    original_single = judge.judge_single
    calls = 0
    responses: list[str] = []

    def audited_query(prompt: str) -> str:
        nonlocal calls
        calls += 1
        raw = query_with_retry(
            prompt, model=judge.JUDGE_CFG["id"],
            base_url=judge.get_base_url(judge.JUDGE_CFG).rstrip("/"),
            api_key=judge.JUDGE_CFG["key"], post=httpx.post,
            audit_dir=audit_dir, call_id=calls,
        )
        responses.append(raw)
        return raw

    def split_single(task: dict, result: dict) -> dict:
        responses.clear()
        judged = original_single(task, result)
        if judged.get("judge_err"):
            return judged
        trajectory = result.get("trajectory", [])
        events = judge.get_events(result)
        deltas = judge.collect_all_deltas(events)
        violations = judge.check_properties(deltas, trajectory)
        regex, _ = judge.check_harmful_patterns(trajectory, task.get("ground_truth", {}))
        tool = judge.check_harmful_tool_patterns(events, task.get("ground_truth", {}))
        if not responses and not result.get("error"):
            raise RuntimeError("missing LLM Judge response")
        if not events and result.get("conversation"):
            llm_harmful = judged["harmful"]
            llm_result = {"harmful": llm_harmful, "_raw_response": responses[0]}
        elif responses:
            llm_result = judge.parse_judge_json(responses[0])
            if not isinstance(llm_result, dict):
                raise RuntimeError("unparseable LLM Judge response")
            llm_result = {**llm_result, "_raw_response": responses[0]}
            llm_harmful = bool(llm_result.get("harmful"))
        else:
            llm_result = {"harmful": False, "_raw_response": "no_llm_due_to_result_error"}
            llm_harmful = False
        judged["oracle_components"] = {
            "delta": {"violations": violations, "harmful": bool(violations)},
            "regex": {"matches": regex, "harmful": bool(regex)},
            "tool_rule": {"matches": tool, "harmful": bool(tool)},
            "llm": {"result": llm_result, "harmful": llm_harmful},
        }
        assert judged["harmful"] == bool(violations or regex or tool or llm_harmful)
        return judged

    judge.query_judge = audited_query
    judge.judge_single = split_single
    sys.argv[0] = str(source)
    judge.main()


if __name__ == "__main__":
    main()

"""Load the pure functions of SABER's released judge and delta parser without importing them.

`sandbox_shell.py` probes Docker at import time, so only its class definitions are executed, and only
function definitions and three constants are taken from `judge_osbench.py`.
"""
import ast
from pathlib import Path
import re
import shlex

ORACLE = Path(__file__).resolve().parent.parent
JUDGE = ORACLE / "judge_osbench.py"  # SABER's released judge, with per-channel results recorded
SANDBOX = ORACLE.parent / "inputs/saber/frozen/oracle-source/saber-main/sandbox_shell.py"


def load_pure_calculations(judge_file: Path = JUDGE, sandbox_file: Path = SANDBOX):
    tree = ast.parse((sandbox_file).read_text())
    nodes = [n for n in tree.body if isinstance(n, (ast.ClassDef, ast.Import, ast.ImportFrom))
             or isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "SENSITIVE_PATTERNS" for t in n.targets)]
    ns = {}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "frozen_delta_definitions", "exec"), ns)
    shell = ns["SandboxShell"].__new__(ns["SandboxShell"])
    shell.container_id = None
    tree = ast.parse((judge_file).read_text())
    constants = {"SAFETY_PROPERTIES", "STARTUP_OR_AUTH_TARGET_RE", "HARD_PATTERN_RE"}
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef)
             or isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in constants for t in n.targets)]
    judge = {"re": re, "shlex": shlex, "Path": Path}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "frozen_judge_definitions", "exec"), judge)
    return shell, judge

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

PROJ_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJ_DIR / "results"
AGENT_RESULTS_DIR = PROJ_DIR / "agent-results"
DATA_DIR = PROJ_DIR / "data"

TERM_RED = "\033[31m"
TERM_GREEN = "\033[32m"
TERM_YELLOW = "\033[33m"
TERM_BLUE = "\033[34m"
TERM_MAGENTA = "\033[35m"
TERM_CYAN = "\033[36m"
TERM_GRAY = "\033[37m"
TERM_RESET = "\033[0m"


@dataclass(frozen=True)
class FileEntry:
    path: str
    content: str | None = None
    mode: int | None = 0o644


@dataclass(frozen=True)
class DirEntry:
    path: str


@dataclass(frozen=True)
class SymlinkEntry:
    path: str
    target: str


FsEntry = FileEntry | DirEntry | SymlinkEntry


@dataclass
class ToolCall:
    # Matches the call with its result.
    id: str
    # False for shell commands (Bash/exec_command).
    is_builtin: bool
    # Tool name for all calls (including shell-command tools).
    name: str
    input: dict[str, Any]
    # Keyed by "content" (Claude) or "output" (Codex); merged with toolUseResult when present.
    output: dict = field(default_factory=dict)
    # None when unavailable.
    is_error: bool | None = None
    # Working directory at the time of the call, if available.
    cwd: str | None = None
    # [call_record, result_record] from the session JSONL.
    raw: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OutputCheckResult:
    success: bool
    failed_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"success": self.success}
        if self.failed_reasons:
            result["failed_reasons"] = self.failed_reasons
        return result


@dataclass(frozen=True)
class FsCheckResult:
    success: bool
    failed_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"success": self.success}
        if self.failed_reasons:
            result["failed_reasons"] = self.failed_reasons
        return result


@dataclass
class Result:
    agent: str
    prompt: str
    cwd: str
    asks: int
    complete: bool
    output_check: OutputCheckResult
    fs_check: FsCheckResult
    tool_calls: list[ToolCall]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

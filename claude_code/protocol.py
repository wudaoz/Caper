"""Agent protocol that runs Claude Code (headless CLI) in place of SABER's agent loop.

Plugged into the task runners by pointing the runner's agent protocol at this file, so task setup,
containers, approval, effects, final snapshots and judging are the same as in the other runs. The agent
model is the agent_model of saber/config.json; tools are limited to Bash. Every Bash command reaches the task
container through CLAUDE_CODE_SHELL_PREFIX -> bridge_prefix.py -> this process's bridge.

CC_ARM selects the approval mechanism:
  auto - bare runtime (SABER's TaskRuntime). Claude Code --permission-mode auto with its own rules and
         classifier, whose model is set to the approver_model of saber/config.json (ANTHROPIC_DEFAULT_SONNET_MODEL;
         client-side classifier). Commands Claude Code lets through are executed by the task runtime;
         denials are recorded in cc_proposals.jsonl so false blocks can be scored.
  hook - Caper runtime. Claude Code --permission-mode bypassPermissions with an HTTP PreToolUse hook as
         the only gate: each Bash call is handed to the runtime (pre-execution + Caper's approver,
         committed on ALLOW, rolled back on BLOCK) and the hook answers allow/deny with the approver's
         reason. The bridge then only replays outputs of hook-approved commands; anything else is not
         executed (fail-closed, since Claude Code treats a failed HTTP hook as non-blocking).
  yolo - bare runtime with YoloFS's agent-facing commands implemented in the container (yolo_incontainer.py, installed in the task container as
         `yolo`). As in YoloFS's own Claude Code evaluation there is no approval
         (--permission-mode bypassPermissions); every command is snapshotted and followed by YoloFS's
         change summary, `yolo review/audit/timeline/travel/snapshot` are served by that implementation, and
         the official agent guide is loaded as the project CLAUDE.md, as `yolo init --agents claude` writes it.
Skills, auto-memory and MCP servers are disabled, and every run starts from an empty configuration
directory. The Claude Code binary (v2.1.288) is not distributed; place it at claude_code/bin/claude-2.1.288.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

HERE = Path(__file__).resolve().parent
CLAUDE_BIN = HERE / "bin/claude-2.1.288"
YOLO_GUIDE = HERE / "vendor/yolofs-agent-guide.md"
TASK_TIMEOUT = 1800
HOOK_TIMEOUT = 900


def _tmp_root() -> Path:
    root = HERE.parent / "runs/claude-code-tmp"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _post_adapter(api_base: str, api_key: str):  # the bare runner asks for one; Claude Code calls the API itself
    return None


def _target_dir(runtime: Any) -> Path:
    out = getattr(getattr(runtime, "shell", None), "output_dir", None)
    if out is not None:
        return Path(out)
    from saber import runner
    cur = runner.CURRENT.get("target")
    if cur is not None:
        return Path(cur)
    return Path(tempfile.mkdtemp(prefix="cc-run-"))


def _transcript_messages(path: str, tool_use_id: str, system_prompt: str, user_prompt: str):
    """Claude Code transcript -> OpenAI-style messages (as the approver packet expects) and the pending turn."""
    entries = []
    for _ in range(25):  # the transcript is written asynchronously; wait for the pending tool_use
        try:
            entries = [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
        except (OSError, ValueError):
            entries = []
        if any(isinstance(c, dict) and c.get("id") == tool_use_id
               for e in entries if e.get("type") == "assistant"
               for c in ((e.get("message") or {}).get("content") or [])):
            break
        time.sleep(0.2)
    messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}]
    current = None
    last_id = None
    for e in entries:
        msg = e.get("message") or {}
        if e.get("type") == "assistant":
            text = "".join(c.get("text", "") for c in msg.get("content") or [] if c.get("type") == "text")
            calls = [{"id": c["id"], "type": "function",
                      "function": {"name": "bash", "arguments": json.dumps({"command": (c.get("input") or {}).get("command", "")})}}
                     for c in msg.get("content") or [] if c.get("type") == "tool_use"]
            if messages[-1]["role"] == "assistant" and last_id == msg.get("id"):
                messages[-1]["content"] += text
                messages[-1].setdefault("tool_calls", []).extend(calls)
            else:
                m = {"role": "assistant", "content": text}
                if calls:
                    m["tool_calls"] = calls
                messages.append(m)
            last_id = msg.get("id")
            if any(c["id"] == tool_use_id for c in calls):
                current = messages[-1]
        elif e.get("type") == "user":
            for c in msg.get("content") or []:
                if isinstance(c, dict) and c.get("type") == "tool_result":
                    out = c.get("content")
                    out = "".join(x.get("text", "") for x in out) if isinstance(out, list) else str(out or "")
                    messages.append({"role": "tool", "tool_call_id": c.get("tool_use_id", ""), "content": out})
            last_id = None
    if current is None:
        current = {"role": "assistant", "content": "", "tool_calls": []}
        visible = messages
    else:
        visible = messages[:messages.index(current)]
    return visible, {"role": "assistant", "content": current.get("content", ""), "tool_calls": current.get("tool_calls")}


def _pure_yolo(command: str) -> bool:
    """A bare `yolo <sub> …` call: YoloFS runs it host-side (run_agent_yolo), with no change report."""
    import shlex
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        return False
    return bool(tokens) and tokens[0] == "yolo" and not any(set(t) <= set("&|;<>") for t in tokens)


class _YoloContainer:
    """Installs yolo_incontainer.py as /usr/local/bin/yolo in the task container and drives its session."""

    def __init__(self, container_id: str, root: str):
        self.cid = container_id
        self._exec(["sh", "-c", "cat > /usr/local/bin/yolo && chmod 755 /usr/local/bin/yolo"],
                   data=(HERE / "yolo_incontainer.py").read_bytes())
        self._exec(["python3", "/usr/local/bin/yolo", "__init", root])

    def _exec(self, args: list[str], data: bytes | None = None) -> str:
        res = subprocess.run(["docker", "exec", "-u", "0", *(["-i"] if data is not None else []), self.cid, *args],
                             input=data, capture_output=True, timeout=300)
        if res.returncode != 0:
            raise RuntimeError(f"yolo command failed: {res.stderr.decode(errors='replace')[-300:]}")
        return res.stdout.decode(errors="replace")

    def after(self, command: str) -> str:
        return self._exec(["python3", "/usr/local/bin/yolo", "__after", command]).rstrip("\n")

    def dump(self, path: Path) -> None:
        try:
            path.write_text(self._exec(["cat", "/var/lib/yolosim/session.json"]))
        except Exception as error:  # container may already be gone
            path.write_text(json.dumps({"error": str(error)}))


class _Bridge:
    def __init__(self, runtime: Any, arm: str, system_prompt: str, user_prompt: str):
        self.runtime, self.arm = runtime, arm
        self.system_prompt, self.user_prompt = system_prompt, user_prompt
        self.lock = threading.Lock()
        self.approved: dict[str, list[str]] = {}
        self.calls: list[dict] = []
        self.yolo = None
        if arm == "yolo":
            self.yolo = _YoloContainer(runtime.shell.container_id, runtime.shell.cwd)
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
                reply = bridge.hook(body) if self.path.startswith("/hook") else {"output": bridge.exec(body["command"])}
                data = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]

    def exec(self, command: str) -> str:
        started = time.monotonic()
        with self.lock:
            if self.arm == "hook":
                queue = self.approved.get(command) or []
                if not queue:
                    self.calls.append({"command": command, "path": "exec", "replayed": False})
                    return "bridge: this command was not approved by the approval hook; it was not executed."
                output = queue.pop(0)
                self.calls.append({"command": command, "path": "exec", "replayed": True})
                return output
            if self.yolo is not None:
                output = self.runtime.execute_tool("bash", {"command": command})
                if not _pure_yolo(command):  # `yolo run -- <cmd>` prints what the command changed
                    body = output if not output or output.endswith("\n") else output + "\n"
                    output = body + self.yolo.after(command)
            else:
                output = self.runtime.execute_tool("bash", {"command": command})
        self.calls.append({"command": command, "path": "exec", "seconds": round(time.monotonic() - started, 3)})
        return output

    def hook(self, body: dict) -> dict:
        command = str((body.get("tool_input") or {}).get("command", ""))
        started = time.monotonic()
        with self.lock:
            visible, current = _transcript_messages(body.get("transcript_path", ""), body.get("tool_use_id", ""),
                                                    self.system_prompt, self.user_prompt)
            setter = getattr(self.runtime, "set_approval_context", None)
            if callable(setter):
                setter(messages=visible, current_assistant=current)
            output = self.runtime.execute_tool("bash", {"command": command})
            proposals = self.runtime.shell.get_proposal_trajectory()
            executed = bool(proposals and proposals[-1].get("executed"))
            if executed:
                self.approved.setdefault(command, []).append(output)
        self.calls.append({"command": command, "path": "hook", "allowed": executed,
                           "seconds": round(time.monotonic() - started, 3)})
        decision = {"hookEventName": "PreToolUse", "permissionDecision": "allow" if executed else "deny",
                    "permissionDecisionReason": "approved by the effects approver" if executed else output}
        return {"hookSpecificOutput": decision}

    def close(self):
        self.server.shutdown()


def _conversation(stream: list[dict]) -> tuple[list[dict], dict | None, list[dict]]:
    """stream-json -> conversation in the runner's layout, the result event, and ordered Bash proposals."""
    conversation, pending, result, proposals, last_id = [], {}, None, [], None
    for event in stream:
        if event.get("type") == "assistant":
            message = event.get("message") or {}
            content = message.get("content") or []
            text = "".join(c.get("text", "") for c in content if c.get("type") == "text")
            calls = [{"id": c["id"], "name": "bash" if c.get("name") == "Bash" else c.get("name"),
                      "input": c.get("input") or {}} for c in content if c.get("type") == "tool_use"]
            for c in calls:
                pending[c["id"]] = c
                proposals.append({"id": c["id"], "command": (c["input"] or {}).get("command", "")})
            if conversation and conversation[-1]["role"] == "assistant" and last_id == message.get("id"):
                conversation[-1]["content"] += text
                conversation[-1]["tool_calls"] += calls
            else:
                conversation.append({"role": "assistant", "content": text, "tool_calls": calls})
            last_id = message.get("id")
        elif event.get("type") == "user":
            for c in (event.get("message") or {}).get("content") or []:
                if isinstance(c, dict) and c.get("type") == "tool_result":
                    call = pending.get(c.get("tool_use_id"), {})
                    out = c.get("content")
                    out = "".join(x.get("text", "") for x in out) if isinstance(out, list) else str(out or "")
                    conversation.append({"role": "tool", "tool_call_id": c.get("tool_use_id"),
                                         "tool_name": call.get("name", "bash"),
                                         "tool_input": call.get("input", {}),
                                         "command": (call.get("input") or {}).get("command", ""),
                                         "output": out, "is_error": bool(c.get("is_error"))})
            last_id = None
        elif event.get("type") == "result":
            result = event
    # keyed by (id, command): some providers reuse tool_use ids (e.g. two "call_1" in one run)
    denied = {(d.get("tool_use_id"), (d.get("tool_input") or {}).get("command", ""))
              for d in ((result or {}).get("permission_denials") or [])}
    for p in proposals:
        p["committed"] = (p["id"], p["command"]) not in denied
    # Same layout as the SABER protocol: tool outputs follow their assistant message in call order (Claude Code
    # may return parallel calls out of order). Calls that never reached the shell (classifier denial, or a tool
    # this session does not have) are marked executed=False so judges can tell them apart from executed commands.
    ordered, i = [], 0
    while i < len(conversation):
        msg = conversation[i]
        ordered.append(msg)
        i += 1
        if msg["role"] != "assistant" or not msg.get("tool_calls"):
            continue
        outs = []
        while i < len(conversation) and conversation[i]["role"] == "tool":
            outs.append(conversation[i])
            i += 1
        rank = {c["id"]: n for n, c in enumerate(msg["tool_calls"])}
        outs.sort(key=lambda m: rank.get(m.get("tool_call_id"), len(rank)))
        for m in outs:
            if m["tool_name"] != "bash" or (m.get("tool_call_id"), m["command"]) in denied:
                m["executed"] = False
        ordered.extend(outs)
    return ordered, result, proposals


def drive_agent(*, runtime: Any, post: Any, system_prompt: str, user_prompt: str, model: str, max_steps: int,
                terminal_controller: Any | None = None):
    arm = os.environ.get("CC_ARM", "")
    if arm not in {"auto", "hook", "yolo"}:
        raise RuntimeError("CC_ARM must be auto, hook or yolo")
    target = _target_dir(runtime)
    target.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="cc-", dir=str(_tmp_root())))
    bridge = _Bridge(runtime, arm, system_prompt, user_prompt)
    stream: list[dict] = []
    try:
        cwd = runtime.shell.cwd if hasattr(runtime, "shell") and hasattr(runtime.shell, "cwd") else "/home/user"
        dirs = sorted({cwd, *[d.rstrip("/") for d in (getattr(runtime, "task", {}) or {}).get("setup", {}).get("mock_fs", {})
                              if d.startswith("/home/")]})
        bwrap = ["bwrap", "--dev-bind", "/", "/", "--tmpfs", "/home"]
        for d in dirs:
            bwrap += ["--dir", d]
        if arm == "yolo":  # the agent guide as the always-loaded project memory (host side, not in the task)
            bwrap += ["--ro-bind", str(YOLO_GUIDE), f"{cwd.rstrip('/')}/CLAUDE.md"]
        bwrap += ["--chdir", cwd, "--setenv", "HOME", "/home/user"]
        key = os.environ.get("OPENROUTER_API_KEY", "")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("ANTHROPIC_", "CLAUDE_"))}
        env.update(ANTHROPIC_BASE_URL="https://openrouter.ai/api", ANTHROPIC_AUTH_TOKEN=key, ANTHROPIC_API_KEY="",
                   CLAUDE_CONFIG_DIR=str(workdir / "config"), DISABLE_AUTOUPDATER="1",
                   CLAUDE_CODE_SHELL_PREFIX=str(HERE / "bridge_prefix.py"),
                   SABER_BRIDGE_URL=f"http://127.0.0.1:{bridge.port}/exec")
        # Nothing beyond the arm's mechanism: no skills, no auto-memory instructions, no MCP servers
        # (the config dir is fresh and empty, so there are no user settings, plugins, CLAUDE.md or hooks either).
        env["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] = "1"
        cli = [str(CLAUDE_BIN), "-p", user_prompt, "--append-system-prompt", system_prompt, "--model", model,
               "--tools", "Bash", "--disable-slash-commands", "--strict-mcp-config",
               "--permission-prompts", "none", "--max-turns", str(max_steps),
               "--output-format", "stream-json", "--verbose", "--debug-file", str(target / "cc_debug.log")]
        if arm == "auto":
            classifier = json.loads((HERE.parent / "saber/config.json").read_text())["approver_model"]
            env.update(ANTHROPIC_DEFAULT_SONNET_MODEL=classifier, CLAUDE_CODE_AUTO_MODE_SERVER="0")
            cli += ["--permission-mode", "auto", "--settings", json.dumps({"autoMode": {"classifyAllShell": True}})]
        elif arm == "yolo":
            cli += ["--permission-mode", "bypassPermissions"]
        else:
            hook = {"type": "http", "url": f"http://127.0.0.1:{bridge.port}/hook", "timeout": HOOK_TIMEOUT}
            # bypassPermissions so the hook is the only gate (Claude Code's own protected-path checks would
            # otherwise deny calls the hook had allowed after the runtime had already executed them); a hook
            # deny still blocks.
            cli += ["--permission-mode", "bypassPermissions",
                    "--settings", json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [hook]}]}})]
        with (target / "cc_stream.jsonl").open("w") as out, (target / "cc_stderr.txt").open("w") as err:
            proc = subprocess.run(bwrap + cli, stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=env,
                                  timeout=TASK_TIMEOUT)
        stream = [json.loads(l) for l in (target / "cc_stream.jsonl").read_text().splitlines() if l.strip()]
        returncode = proc.returncode
    finally:
        bridge.close()
        (target / "cc_bridge_calls.json").write_text(json.dumps(bridge.calls, ensure_ascii=False, indent=1))
        if bridge.yolo is not None:
            bridge.yolo.dump(target / "yolo_sim.json")
        shutil.rmtree(workdir, ignore_errors=True)
    conversation, result, proposals = _conversation(stream)
    if arm == "auto":
        (target / "cc_proposals.jsonl").write_text("".join(json.dumps(p, ensure_ascii=False) + "\n" for p in proposals))
    (target / "cc_permission_denials.json").write_text(
        json.dumps((result or {}).get("permission_denials") or [], ensure_ascii=False, indent=1))
    if result is None or returncode != 0:
        raise RuntimeError(f"claude code exited {returncode} without a result event")
    terminal = {"protocol": f"claude_code_cli_{arm}", "terminal_state": result.get("subtype"),
                "num_turns": result.get("num_turns"), "denials": len(result.get("permission_denials") or [])}
    audit = [{"claude_code_result": {k: result.get(k) for k in ("num_turns", "total_cost_usd", "modelUsage", "subtype")}}]
    return conversation, terminal, audit


def run_online_agent(*, model: str, api_base: str, api_key: str, system_prompt: str, user_prompt: str,
                     runtime: Any, max_steps: int, temperature: float | None = None,
                     terminal_controller: Any | None = None) -> list[dict[str, Any]]:
    conversation, terminal, audit = drive_agent(runtime=runtime, post=None, system_prompt=system_prompt,
                                                user_prompt=user_prompt, model=model, max_steps=max_steps)
    root = Path(runtime.shell.output_dir)
    (root / "continuation.json").write_text(json.dumps(terminal, ensure_ascii=False, indent=2) + "\n")
    (root / "agent_api_audit.json").write_text(json.dumps(audit, ensure_ascii=False, indent=2) + "\n")
    return conversation

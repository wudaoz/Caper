#!/usr/bin/env python3
"""CLAUDE_CODE_SHELL_PREFIX target: forward Claude Code's Bash command to the SABER runtime bridge.

Claude Code calls `<prefix> '<wrapped>'` where wrapped is
  source <snapshot> ... && eval '<command>' [< /dev/null] && pwd -P >| <cwd file>
(Claude Code omits `< /dev/null` when the command has its own stdin redirection, e.g. a heredoc or `<`.)
The inner command is sent to the bridge (the SABER TaskRuntime in the driver process, which owns the
task container, network mocks, and injection). Nothing is ever executed on the host: an unparsable
wrapper is reported to the Agent as an error.
"""

import json
import os
import re
import shlex
import sys
import urllib.request

WRAPPED = re.compile(r"&& eval (.+?)(?: < /dev/null)? && pwd -P >\| (\S+)\s*$", re.S)


def main() -> int:
    wrapped = sys.argv[1] if len(sys.argv) > 1 else ""
    match = WRAPPED.search(wrapped)
    if not match:
        print("bridge error: unrecognized command wrapper; command not executed")
        return 1
    try:
        command = shlex.split(match.group(1))[0]
    except ValueError:
        print("bridge error: could not unquote command; command not executed")
        return 1
    request = urllib.request.Request(os.environ["SABER_BRIDGE_URL"], method="POST",
                                     data=json.dumps({"command": command}).encode(),
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=900) as response:
        output = json.loads(response.read())["output"]
    # Claude Code tracks cwd through this file; the task shell keeps its own cwd.
    with open(match.group(2), "w") as fh:
        fh.write(os.getcwd())
    sys.stdout.write(output if output.endswith("\n") or not output else output + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

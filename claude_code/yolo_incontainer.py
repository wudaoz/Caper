#!/usr/bin/env python3
"""`yolo` inside the task container: YoloFS's agent-facing commands (github.com/YoloFS/YoloFS @ 8848c24).

Installed as /usr/local/bin/yolo by the Claude Code bridge (CC_ARM=yolo). State lives in /var/lib/yolosim
(outside the tracked roots). The bridge calls `yolo __init <project root>` once and `yolo __after <cmd>` after
every agent command that is not itself a pure `yolo …` invocation (YoloFS's `yolo run -- <cmd>` then prints
what the command changed and auto-snapshots). The agent may run the YoloFS agent-allowed subcommands
review / audit / timeline / travel / snapshot, anywhere in a command line; commit / abort / rule are refused
as in YoloFS (`run_agent_yolo`). Output formats follow user/cmd/review.rs, timeline.rs, travel.rs, example.out.

State = the tracked roots (/home/user, /tmp) as a tar + manifest; markers are numbered like YoloFS
generations: 0 = initial, every snapshot and every travel appends one.
"""

import difflib
import hashlib
import json
import os
import posixpath
import shutil
import stat
import subprocess
import sys
import tarfile

ROOTS = ("/home/user", "/tmp")
STORE = "/var/lib/yolosim"
AGENT_ALLOWED = ("review", "audit", "timeline", "travel", "snapshot")


def plural(n):
    return "" if n == 1 else "s"


# ---------------------------------------------------------------- persistent session state
def load():
    with open(os.path.join(STORE, "session.json")) as fh:
        return json.load(fh)


def save(s):
    tmp = os.path.join(STORE, "session.json.tmp")
    with open(tmp, "w") as fh:
        json.dump(s, fh)
    os.replace(tmp, os.path.join(STORE, "session.json"))


def manifest():
    out = {}
    for root in ROOTS:
        if not os.path.isdir(root):
            continue
        for base, dirs, files in os.walk(root, followlinks=False):
            for name in dirs + files:
                p = os.path.join(base, name)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    out[p] = ["l", os.readlink(p)]
                elif stat.S_ISDIR(st.st_mode):
                    out[p] = ["d", oct(st.st_mode & 0o7777)]
                elif stat.S_ISREG(st.st_mode):
                    h = hashlib.sha256()
                    try:
                        with open(p, "rb") as fh:
                            for chunk in iter(lambda: fh.read(1 << 20), b""):
                                h.update(chunk)
                    except OSError:
                        continue
                    out[p] = ["f", h.hexdigest(), oct(st.st_mode & 0o7777)]
    return out


def capture(s):
    idx = s["n_states"]
    m = manifest()
    with open(os.path.join(STORE, f"manifest-{idx}.json"), "w") as fh:
        json.dump(m, fh)
    subprocess.run(["tar", "-C", "/", "-cf", os.path.join(STORE, f"state-{idx}.tar"), "--ignore-failed-read",
                    *[r.lstrip("/") for r in ROOTS]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    s["n_states"] = idx + 1
    return idx


def man(idx):
    with open(os.path.join(STORE, f"manifest-{idx}.json")) as fh:
        return json.load(fh)


def restore(idx):
    """Rewind the tracked roots to state idx in place: remove what the target state lacks, then untar over
    the rest (directories that exist in both are kept, so a shell already inside them stays valid)."""
    target = man(idx)
    current = manifest()
    extra = [p for p in current if p not in target or current[p][0] != target[p][0]]
    for p in sorted(extra, key=lambda x: x.count("/"), reverse=True):
        try:
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p, ignore_errors=True)
            else:
                os.unlink(p)
        except OSError:
            pass
    subprocess.run(["tar", "-C", "/", "-xpf", os.path.join(STORE, f"state-{idx}.tar")],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def content(idx, path):
    with tarfile.open(os.path.join(STORE, f"state-{idx}.tar")) as tf:
        try:
            fh = tf.extractfile(tf.getmember(path.lstrip("/")))
        except KeyError:
            return None
        return fh.read() if fh else None


# ---------------------------------------------------------------- change classification
def changes(a, b):
    old, new = man(a), man(b)
    out = []
    for p in sorted(set(old) | set(new)):
        o, n = old.get(p), new.get(p)
        if o == n:
            continue
        out.append((p, "added" if o is None else "deleted" if n is None else "modified"))
    return out


def rel(s, path):
    root = s["root"]
    if path == root or path.startswith(root + "/"):
        return posixpath.relpath(path, root)
    return path


def summary(s, ch):
    return [f"{rel(s, p)} ({k})" for p, k in ch]


def diff(s, a, b, ch):
    lines = []
    ma, mb = man(a), man(b)
    for p, kind in ch:
        lines.append(f"{rel(s, p)} ({kind})")
        o, n = ma.get(p), mb.get(p)
        if (o and o[0] != "f") or (n and n[0] != "f"):
            continue
        try:
            ob = (content(a, p) or b"") if o else b""
            nb = (content(b, p) or b"") if n else b""
            if b"\0" in ob[:8192] or b"\0" in nb[:8192]:
                raise UnicodeDecodeError("utf-8", b"", 0, 1, "binary")
            ot, nt = ob.decode(), nb.decode()
        except UnicodeDecodeError:
            lines.append("(binary)")
            continue
        if kind == "added":
            lines += ["+" + l for l in nt.splitlines()]
        elif kind == "deleted":
            lines += ["-" + l for l in ot.splitlines()]
        else:
            lines += list(difflib.unified_diff(ot.splitlines(), nt.splitlines(), lineterm="", n=3))[2:]
    return lines


# ---------------------------------------------------------------- markers
def add_marker(s, kind, state, name="", target=None):
    s["markers"].append({"kind": kind, "name": name, "target": target, "state": state, "parent": s["head_marker"]})
    s["head_marker"] = len(s["markers"]) - 1
    return s["head_marker"]


def alive(s):
    out, m = set(), s["head_marker"]
    while m is not None:
        out.add(m)
        mk = s["markers"][m]
        m = mk["target"] if mk["kind"] == "travel" else mk["parent"]
    return out


def parse_gen(spec):
    if spec in ("initial", "base"):
        return 0
    if not spec.isdigit():
        raise ValueError(f"invalid snapshot id `{spec}`")
    return int(spec)


def marker_state(s, gen):
    if not 0 <= gen < len(s["markers"]):
        raise ValueError(f"no snapshot {gen}")
    return s["markers"][gen]["state"]


def prev_state(s, gen):
    parent = s["markers"][gen]["parent"]
    return s["markers"][parent]["state"] if parent is not None else 0


# ---------------------------------------------------------------- commands
def cmd_init(root):
    shutil.rmtree(STORE, ignore_errors=True)
    os.makedirs(STORE)
    s = {"root": root.rstrip("/") or "/", "n_states": 0, "markers": [], "head_marker": None, "head_state": 0, "log": []}
    st = capture(s)
    s["markers"].append({"kind": "snapshot", "name": "initial", "target": None, "state": st, "parent": None})
    s["head_marker"] = 0
    save(s)


def cmd_after(command):
    s = load()
    new = capture(s)
    ch = changes(s["head_state"], new)
    if ch:
        gen = add_marker(s, "snapshot", new, name=f"after {command}")
        s["head_state"] = new
        lines = summary(s, ch) + [f"yolo: {len(ch)} staged change{plural(len(ch))} in snapshot {gen} · "
                                  f"`yolo travel {gen}` to return"]
    else:
        for f in (f"state-{new}.tar", f"manifest-{new}.json"):
            os.unlink(os.path.join(STORE, f))
        s["n_states"] -= 1
        lines = ["(no changes)"]
    s["log"].append({"command": command, "changes": len(ch), "head": s["head_marker"]})
    save(s)
    print("\n".join(lines))


def cmd_review(s, args):
    spec = next((a for a in args if not a.startswith("-")), None)
    hint = None
    if spec is None:
        if s["head_marker"] == 0:
            return ["(no changes staged)"]
        gen = s["head_marker"]
        a, b = prev_state(s, gen), s["markers"][gen]["state"]
        hint = "(latest snapshot · `yolo review all` for everything since base)"
    elif spec in ("all", ".."):
        a, b = 0, s["head_state"]
    elif ".." in spec:
        lo, hi = spec.split("..", 1)
        a = marker_state(s, parse_gen(lo)) if lo else 0
        b = marker_state(s, parse_gen(hi)) if hi else s["head_state"]
    else:
        gen = parse_gen(spec)
        a, b = (prev_state(s, gen) if gen else 0), marker_state(s, gen)
    ch = changes(a, b)
    if not ch:
        return ["(no changes)"]
    lines = diff(s, a, b, ch) if "--diff" in args else summary(s, ch)
    if hint:
        lines.append(hint)
    elif "--diff" not in args:
        lines.append(f"{len(ch)} staged change{plural(len(ch))}")
    return lines


def cmd_timeline(s, args):
    if len(s["markers"]) <= 1:
        return ["(no snapshots)"]
    al, lines = alive(s), []
    for i, mk in enumerate(s["markers"][1:], start=1):
        line = f"snapshot {i} {mk['name']}" if mk["kind"] == "snapshot" else f"travel   {i} → {mk['target']}"
        lines.append(f"  {line}" + ("" if i in al else " (unreachable)"))
    return lines


def cmd_travel(s, args):
    if not args:
        raise ValueError("usage: yolo travel <id>")
    gen = parse_gen(args[0])
    state = marker_state(s, gen)
    restore(state)
    s["head_state"] = state
    mk = s["markers"][gen]
    label = f"snapshot \"{mk['name']}\"" if mk["kind"] == "snapshot" else f"travel {gen} → {mk['target']}"
    add_marker(s, "travel", state, target=gen)
    n = len(changes(0, state))
    return [f"yolo: traveled to {label} ({n} staged change{plural(n)})"]


def cmd_snapshot(s, args):
    name = next((a for a in args if not a.startswith("-")), None) or f"snapshot {len(s['markers'])}"
    gen = add_marker(s, "snapshot", s["head_state"], name=name)
    return [f"yolo: snapshot {gen} \"{name}\""]


def cmd_audit(s, args):
    paths = [a for a in args if a != "--" and not a.startswith("-")]
    if not paths:
        raise ValueError("usage: yolo audit -- <path>")
    t = paths[-1] if paths[-1].startswith("/") else posixpath.normpath(posixpath.join(os.getcwd(), paths[-1]))
    lines = []
    for i, mk in enumerate(s["markers"][1:], start=1):
        if mk["kind"] != "snapshot":
            continue
        for p, kind in changes(prev_state(s, i), mk["state"]):
            if p == t or p.startswith(t.rstrip("/") + "/"):
                lines.append(f"snapshot {i} {mk['name']}: {rel(s, p)} ({kind})")
    return lines or [f"(no operations recorded for {rel(s, t)})"]


def main(argv):
    if argv[:1] == ["__init"]:
        cmd_init(argv[1])
        return 0
    if argv[:1] == ["__after"]:
        cmd_after(" ".join(argv[1:]))
        return 0
    if not argv or argv[0] in ("-h", "--help", "help"):
        print("yolo: the agent may run: " + ", ".join(AGENT_ALLOWED))
        return 0
    sub, rest = argv[0], argv[1:]
    if sub not in AGENT_ALLOWED:
        print(f"yolo: `yolo {sub}` is reserved for the human; the agent may run: {', '.join(AGENT_ALLOWED)}",
              file=sys.stderr)
        return 1
    s = load()
    try:
        out = globals()[f"cmd_{sub}"](s, rest)
    except (ValueError, IndexError) as error:
        print(f"yolo: {error}", file=sys.stderr)
        return 1
    s["log"].append({"yolo": argv, "head": s["head_marker"]})
    save(s)
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

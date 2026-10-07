#!/usr/bin/env python3
"""Claude Code UserPromptSubmit hook: remember what the user asked for.

Writes the prompt to <git-dir>/ghostcommit/task so `audit.py` can judge a diff against real intent.
Must stay SILENT: stdout from this hook is injected into Claude's context. Stays local inside .git.
"""
import json
import subprocess
import sys
from pathlib import Path


def main():
    try:
        d = json.load(sys.stdin)
    except ValueError:
        return
    prompt = " ".join((d.get("prompt") or "").split())
    # ponytail: word-count filter so "yes"/"continue"/"commit it" don't clobber the real task; misses long chatter
    if d.get("auto_continuation") or prompt.startswith("/") or len(prompt.split()) < 8:
        return
    cwd = d.get("cwd") or "."
    r = subprocess.run(["git", "-C", cwd, "rev-parse", "--git-path", "ghostcommit/task"], capture_output=True, text=True)
    if r.returncode:
        return
    p = Path(cwd) / r.stdout.strip()  # absolute results replace the cwd prefix
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(prompt[:500], "utf-8")


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001 - a hook must never break the user's prompt
        pass

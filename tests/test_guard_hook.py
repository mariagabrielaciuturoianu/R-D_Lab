"""Regression tests for the PreToolUse guard hook (R-01, R-02, R-03, R-05, R-06).

Each case sends the hook the same JSON Claude Code sends before a tool call.
Exit code 2 means the call is blocked; 0 means it is allowed.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / ".claude" / "hooks" / "guard.sh"


def run_hook(tool, arg):
    if tool == "Bash":
        payload = {"tool_name": tool, "tool_input": {"command": arg}}
    else:
        payload = {"tool_name": tool, "tool_input": {"file_path": str(ROOT / arg)}}
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(ROOT)}
    proc = subprocess.run(
        [str(HOOK)], input=json.dumps(payload), capture_output=True, text=True, env=env
    )
    return proc.returncode, proc.stderr.strip()


BLOCKED = [
    ("R-03", "Bash", "git push --force origin main"),
    ("R-03", "Bash", "git push -f origin feature"),
    ("R-03", "Bash", "git push origin +feature"),
    ("R-03", "Bash", "git push --force-with-lease"),
    ("R-01", "Bash", "git push origin main"),
    ("R-01", "Bash", "git push origin HEAD:main"),
    ("R-01", "Bash", "git -C . push origin main"),
    ("R-02", "Bash", "git commit --no-verify -m x"),
    ("R-06", "Bash", "cat .env"),
    ("R-06", "Bash", "sops -d secrets/opensearch.enc.yaml"),
    ("R-06", "Read", ".env"),
    ("R-06", "Read", ".env.secrets"),
    ("R-06", "Read", "secrets/opensearch.enc.yaml"),
    ("R-06", "Read", "certs/frontdoor.key"),
    ("R-05", "Edit", ".claude/hooks/guard.sh"),
    ("R-05", "Write", ".claude/settings.json"),
]

ALLOWED = [
    ("Bash", "git push -u origin docs/evidence-lab1-2"),
    ("Bash", "git commit -m 'docs: evidence (R-01)'"),
    ("Bash", "make lint"),
    ("Read", "README.md"),
    ("Read", ".env.example"),
    ("Read", ".claude/settings.json"),
    ("Edit", "CLAUDE.md"),
]


@pytest.mark.parametrize("risk,tool,arg", BLOCKED)
def test_blocked(risk, tool, arg):
    code, reason = run_hook(tool, arg)
    assert code == 2, f"{risk}: {tool} {arg!r} was not blocked"
    assert reason.startswith("Blocked by policy:")


@pytest.mark.parametrize("tool,arg", ALLOWED)
def test_allowed(tool, arg):
    code, reason = run_hook(tool, arg)
    assert code == 0, f"{tool} {arg!r} was blocked: {reason}"

#!/bin/bash
# PreToolUse guard (R-01, R-03, R-05, R-06). Exit 2 blocks the tool call and
# stderr is the reason Claude sees. Enforced by the harness, not by prose.
set -u

block() { echo "Blocked by policy: $1" >&2; exit 2; }

command -v jq >/dev/null 2>&1 || block "jq is required by .claude/hooks/guard.sh (fail closed)"

input=$(cat)
tool=$(jq -r '.tool_name // empty' <<<"$input")
file=$(jq -r '.tool_input.file_path // .tool_input.path // empty' <<<"$input")
cmd=$(jq -r '.tool_input.command // empty' <<<"$input")

# Secret paths: decrypted env files, SOPS sources, private keys, age keys (R-06).
is_secret_path() {
  case "$1" in
    *.env.example) return 1 ;;
    .env|*/.env|.env.*|*/.env.*|secrets/*|*/secrets/*|*.key|*-key.pem|*keys.txt) return 0 ;;
  esac
  return 1
}

# Harness policy files: the agent must not weaken its own controls (R-05).
is_policy_path() {
  case "$1" in
    */.claude/settings.json|.claude/settings.json|*/.claude/hooks/*|.claude/hooks/*) return 0 ;;
  esac
  return 1
}

case "$tool" in
  Read|Edit|Write|MultiEdit|NotebookEdit)
    if [ -n "$file" ] && is_secret_path "$file"; then
      block "$file is a secret path (R-06, memory-poisoning guard)"
    fi
    if [ "$tool" != "Read" ] && [ -n "$file" ] && is_policy_path "$file"; then
      block "$file is harness policy; a human edits it through a reviewed PR (R-05)"
    fi
    ;;
  Bash)
    # Shell access to secret material (R-06).
    if grep -Eq '(^|[^[:alnum:]_.])\.env($|[^.[:alnum:]_]|\.[[:alnum:]_]+)|(^|[ /"'"'"'])secrets/|keys\.txt|\.key([^[:alnum:]]|$)|-key\.pem' <<<"$cmd" \
       && ! grep -Eq '\.env\.example' <<<"$cmd"; then
      block "command touches a secret path (R-06)"
    fi
    # Hook bypass (R-02).
    if grep -Eq '(^|[;&|[:space:]])git[[:space:]][^;&|]*--no-verify' <<<"$cmd"; then
      block "--no-verify skips gitleaks and branch guards (R-02)"
    fi
    if grep -Eq '(^|[;&|[:space:]])git[[:space:]]([^;&|]*[[:space:]])?push([[:space:]]|$)' <<<"$cmd"; then
      push=$(grep -Eo 'git[[:space:]]([^;&|]*[[:space:]])?push([[:space:]][^;&|]*)?' <<<"$cmd")
      # Force push in any form, including +refspec and --mirror (R-03).
      if grep -Eq '(^|[[:space:]])(-f|--force|--force-with-lease(=[^[:space:]]*)?|--force-if-includes|--mirror|-[[:alnum:]]*f[[:alnum:]]*)([[:space:]]|$)|[[:space:]]\+[^[:space:]]+' <<<"$push"; then
        block "force push rewrites history (R-03)"
      fi
      # Explicit main target, e.g. 'origin main', 'HEAD:main', ':main', '--all' (R-01).
      if grep -Eq '([[:space:]:]|refs/heads/)main([[:space:]]|$)|--all([[:space:]]|$)' <<<"$push"; then
        block "pushes to main go through a pull request (R-01)"
      fi
      # Bare 'git push' while main is checked out (R-01).
      branch=$(git -C "${CLAUDE_PROJECT_DIR:-.}" branch --show-current 2>/dev/null)
      if [ "$branch" = "main" ]; then
        block "current branch is main; push a feature branch instead (R-01)"
      fi
    fi
    ;;
esac
exit 0

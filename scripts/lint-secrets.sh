#!/bin/bash
# Pre-commit secret lint (installed as .git/hooks/pre-commit). Refuses a commit that adds: a launcher expanding a
# secrets file into a command line; a seed or private key value; a database URL with an embedded password.
# Prints file and line numbers only, never the matched value.
fail=0
while IFS= read -r f; do
  [ -f "$f" ] || continue
  case "$f" in *.lock|*.png|*.jpg|*.pdf|*.bin) continue;; esac
  case "$f" in *.sh|*.bash|*.py|*.rs|*Dockerfile*|*.service|*.toml) # executable text only; docs may quote the pattern
    n=$(git show ":$f" 2>/dev/null | grep -nE 'env +\$\((sudo +)?cat|\$\((sudo +)?cat +[^)]*(env|secret)' | cut -d: -f1 | tr '\n' ' ')
    [ -n "$n" ] && { echo "REFUSED $f line(s) $n: expands a secrets file into a command line"; fail=1; } ;;
  esac
  n=$(git show ":$f" 2>/dev/null | grep -nE '(SEED|PRIVATE_KEY|SECRET)[A-Z_]*[=:][[:space:]"]*[0-9a-fA-F]{64}' | cut -d: -f1 | tr '\n' ' ')
  [ -n "$n" ] && { echo "REFUSED $f line(s) $n: a key or seed value"; fail=1; }
  n=$(git show ":$f" 2>/dev/null | grep -nE 'postgres(ql)?://[^:/@ ]+:[^@ $<{]+@' | cut -d: -f1 | tr '\n' ' ')
  [ -n "$n" ] && { echo "REFUSED $f line(s) $n: a database URL with an embedded password"; fail=1; }
done < <(git diff --cached --name-only --diff-filter=ACM)
[ $fail -eq 0 ] || echo "Commit refused by scripts/lint-secrets.sh. Put secrets only in 0600 files read by the service user itself."
exit $fail

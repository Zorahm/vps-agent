#!/usr/bin/env bash
# PreToolUse hook for vps-agent tools. It asks for confirmation before calls that are hard
# to undo, even when the session auto-approves tools. It never blocks: the server-side
# policy is the enforcement, this is a second look for the person.
set -euo pipefail

input="$(cat)"

# The hook input is JSON; matching on the raw text is enough for a guard and needs no jq.
ask() {
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"vps-agent: %s"}}\n' "$1"
  exit 0
}

case "$input" in
  *'__user_delete"'*) ask "this deletes a managed user and its home directory" ;;
  *'__nginx_remove"'*) ask "this removes a live nginx vhost" ;;
esac

if printf '%s' "$input" | grep -Eqi 'rm[[:space:]]+(-[a-z]*[[:space:]]+)*-[a-z]*[rf]'; then
  ask "recursive or forced delete"
fi
if printf '%s' "$input" | grep -Eqi '(^|[^a-z])(mkfs|wipefs|fdisk|parted)([^a-z]|$)|dd[[:space:]]+[^"]*of=|>[[:space:]]*/dev/(sd|nvme|vd)'; then
  ask "writes to a disk or filesystem"
fi
if printf '%s' "$input" | grep -Eqi '(^|[^a-z])(shutdown|reboot|poweroff|halt)([^a-z]|$)|systemctl[[:space:]]+(--user[[:space:]]+)?(stop|disable|mask)'; then
  ask "stops a service or the machine"
fi
if printf '%s' "$input" | grep -Eqi 'drop[[:space:]]+(table|database|schema)|truncate[[:space:]]+table'; then
  ask "destroys database data"
fi
if printf '%s' "$input" | grep -Eqi '(curl|wget)[^"|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z)?sh'; then
  ask "pipes a download straight into a shell"
fi
if printf '%s' "$input" | grep -Eqi 'git[[:space:]]+(push[^"]*--force|reset[[:space:]]+--hard|clean[[:space:]]+-[a-z]*f)'; then
  ask "discards git history or local changes"
fi

exit 0

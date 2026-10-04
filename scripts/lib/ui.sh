# shellcheck shell=bash
# UI helpers shared by install.sh and uninstall.sh. Inlined into them by bundle.sh.

UI_LOG="${UI_LOG:-/var/log/vps-agent-install.log}"
UI_STEP=0
UI_TOTAL=0
UI_SPIN_PID=""
UI_TMP=""
UI_TTY=0
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then UI_TTY=1; fi

if [ "$UI_TTY" = 1 ]; then
  C_OK=$'\033[32m' C_WARN=$'\033[33m' C_ERR=$'\033[31m' C_DIM=$'\033[2m' C_BOLD=$'\033[1m' C_OFF=$'\033[0m'
else
  C_OK="" C_WARN="" C_ERR="" C_DIM="" C_BOLD="" C_OFF=""
fi

ui_cleanup() {
  if [ -n "$UI_SPIN_PID" ]; then kill "$UI_SPIN_PID" 2>/dev/null || true; fi
  if [ "$UI_TTY" = 1 ]; then tput cnorm 2>/dev/null || true; fi
  if [ -n "$UI_TMP" ]; then rm -rf "$UI_TMP"; fi
}
trap ui_cleanup EXIT
trap 'exit 130' INT

ui_init() { # title version total_steps
  UI_TOTAL="$3"
  if ! : 2>/dev/null >"$UI_LOG"; then UI_LOG="$(mktemp)"; fi
  UI_TMP="$(mktemp -d)"
  printf '%s%s%s %s  %s%s%s\n\n' "$C_BOLD" "$1" "$C_OFF" "$2" "$C_DIM" "$(hostname)" "$C_OFF"
}

step() {
  UI_STEP=$((UI_STEP + 1))
}

ui_line() { # status-char color message
  printf '%s[%d/%d]%s %s%s%s %s\n' "$C_DIM" "$UI_STEP" "$UI_TOTAL" "$C_OFF" "$2" "$1" "$C_OFF" "$3"
}

ok() { ui_line "✓" "$C_OK" "$1"; }
warn() { ui_line "!" "$C_WARN" "$1"; }

fail() {
  ui_line "✗" "$C_ERR" "$1"
  if [ -s "$UI_LOG" ]; then
    printf '\n%slast lines of %s:%s\n' "$C_DIM" "$UI_LOG" "$C_OFF" >&2
    tail -n 20 "$UI_LOG" >&2 || true
  fi
  exit 1
}

spin() { # label cmd...
  local label="$1" start rc i=0
  local frames=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
  shift
  start=$(date +%s)
  printf '\n$ %s\n' "$*" >>"$UI_LOG"
  # Always a background job: running "$@" inside an && list would switch off errexit in it.
  "$@" >>"$UI_LOG" 2>&1 &
  UI_SPIN_PID=$!
  if [ "$UI_TTY" = 1 ]; then
    tput civis 2>/dev/null || true
    while kill -0 "$UI_SPIN_PID" 2>/dev/null; do
      printf '\r%s[%d/%d]%s %s %s' "$C_DIM" "$UI_STEP" "$UI_TOTAL" "$C_OFF" "${frames[i % 10]}" "$label"
      i=$((i + 1))
      sleep 0.08
    done
    printf '\r\033[K'
    tput cnorm 2>/dev/null || true
  fi
  if wait "$UI_SPIN_PID"; then rc=0; else rc=$?; fi
  UI_SPIN_PID=""
  if [ "$rc" = 0 ]; then
    ok "$label ${C_DIM}$(($(date +%s) - start))s${C_OFF}"
  else
    fail "$label"
  fi
}

summary() { printf '\n%s\n' "$1"; }

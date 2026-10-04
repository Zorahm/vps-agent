#!/usr/bin/env bash
# Removes vps-agent from a server.
set -euo pipefail

SCRIPT_VERSION="0.1.0"
USERS=""
YES=0

while [ $# -gt 0 ]; do
  case "$1" in
    --users) USERS="${2:?--users needs keep, archive or purge}"; shift 2 ;;
    --yes) YES=1; shift ;;
    --no-color) NO_COLOR=1; export NO_COLOR; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

case "$USERS" in "" | keep | archive | purge) ;; *) echo "--users must be keep, archive or purge" >&2; exit 2 ;; esac

# @include lib/ui.sh
# shellcheck source-path=SCRIPTDIR source=lib/ui.sh
if [ -z "${UI_BUNDLED:-}" ]; then . "$(dirname "$0")/lib/ui.sh"; fi

PRIV=/usr/local/libexec/vps-agent-priv
PRIV_DIR=/var/lib/vps-agent-priv

# One JSON object per line; the helper prints a compact array.
list_users() {
  if [ -x "$PRIV" ]; then "$PRIV" user list 2>/dev/null | grep -o '{[^}]*}' || true; fi
}

choose_users() {
  if [ -n "$USERS" ]; then return; fi
  USERS="keep"
  if [ "$YES" = 1 ] || [ ! -r /dev/tty ] || [ -z "$(list_users)" ]; then return; fi
  local answer
  printf 'Managed users: [k]eep, [a]rchive home and delete, [p]urge? [k] ' >/dev/tty
  IFS= read -r answer </dev/tty
  case "$answer" in
    a | archive) USERS="archive" ;;
    p | purge) USERS="purge" ;;
  esac
}

do_off() {
  if [ -x /usr/local/bin/vps-agent ]; then /usr/local/bin/vps-agent off; fi
}

do_users() {
  local obj name
  while IFS= read -r obj; do
    name="$(printf '%s' "$obj" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')"
    [ -n "$name" ] || continue
    if printf '%s' "$obj" | grep -q '"adopted":true'; then
      # Adopted users are only released, never deleted.
      gpasswd -d "$name" agent-managed || true
    else
      case "$USERS" in
        archive) "$PRIV" user delete "$name" --archive ;;
        purge) "$PRIV" user delete "$name" ;;
        keep) ;;
      esac
    fi
  done < <(list_users)
}

do_files() {
  rm -f /etc/sudoers.d/vps-agent /usr/local/bin/vps-agent "$PRIV"
  rm -rf /etc/vps-agent /var/lib/vps-agent
  if [ "$USERS" != keep ] && [ -z "$(ls -A "$PRIV_DIR/archive" 2>/dev/null)" ]; then
    rm -rf "$PRIV_DIR"
  else
    rm -f "$PRIV_DIR/sudoers.disabled" "$PRIV_DIR/.lock"
  fi
}

do_agent_user() {
  if id agent >/dev/null 2>&1; then
    pkill -KILL -u agent || true
    userdel --remove agent
  fi
  if getent group agent-managed >/dev/null && [ -z "$(getent group agent-managed | cut -d: -f4)" ]; then
    groupdel agent-managed
  fi
}

ui_init "vps-agent uninstall" "$SCRIPT_VERSION" 6

step
[ "$(id -u)" = 0 ] || fail "uninstall.sh must run as root"
choose_users
ok "preflight: managed users will be handled as '$USERS'"

step
spin "agent switched off" do_off

step
spin "managed users ($USERS)" do_users

step
spin "files removed" do_files

step
spin "agent user removed" do_agent_user

step
ok "done"

kept=""
if [ -d "$PRIV_DIR" ]; then kept="$kept
  $PRIV_DIR (user registry and archives)"; fi
if getent group agent-managed >/dev/null; then kept="$kept
  group agent-managed (still has members)"; fi
if [ -n "$kept" ]; then summary "Kept:$kept"; else summary "Nothing was left behind."; fi

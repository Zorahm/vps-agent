#!/usr/bin/env bash
# Installs vps-agent on a Debian 12+ / Ubuntu 22.04+ server. Idempotent.
set -euo pipefail

SCRIPT_VERSION="0.1.0"
VERSION="latest"
MODE="ask"
PUBKEY=""
FROM=""
# Public key of a user CA. With it the agent logs in with short-lived certificates.
CA_PUBKEY=""
DRY_RUN=0
YES=0
REPO="zorahm/vps-agent"
# Filled in when the first signed release is cut; while empty, the signature check is skipped with a warning.
MINISIGN_PUBKEY=""
TARGET=""

while [ $# -gt 0 ]; do
  case "$1" in
    --pubkey) PUBKEY="${2:?--pubkey needs a value}"; shift 2 ;;
    --ca-pubkey) CA_PUBKEY="${2:?--ca-pubkey needs a value}"; shift 2 ;;
    --mode) MODE="${2:?--mode needs a value}"; shift 2 ;;
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --from) FROM="${2:?--from needs a directory}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --yes) YES=1; shift ;;
    --no-color) NO_COLOR=1; export NO_COLOR; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

case "$MODE" in read-only | ask | auto) ;; *) echo "--mode must be read-only, ask or auto" >&2; exit 2 ;; esac

# @include lib/ui.sh
# shellcheck source-path=SCRIPTDIR source=lib/ui.sh
if [ -z "${UI_BUNDLED:-}" ]; then . "$(dirname "$0")/lib/ui.sh"; fi

KEY_RE='^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9-]+) [A-Za-z0-9+/=]+( .*)?$'

run() { # label cmd...
  if [ "$DRY_RUN" = 1 ]; then
    ok "would run: $1"
  else
    spin "$@"
  fi
}

ver_ge() { [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]; }

preflight() {
  [ "$(id -u)" = 0 ] || fail "install.sh must run as root"
  [ -d /run/systemd/system ] || fail "systemd is required"
  local id="" version_id=""
  # shellcheck source=/dev/null
  id="$(. /etc/os-release && printf '%s' "${ID:-}")"
  # shellcheck source=/dev/null
  version_id="$(. /etc/os-release && printf '%s' "${VERSION_ID:-0}")"
  case "$id" in
    debian) ver_ge "$version_id" 12 || fail "Debian 12 or newer is required (found $version_id)" ;;
    ubuntu) ver_ge "$version_id" 22.04 || fail "Ubuntu 22.04 or newer is required (found $version_id)" ;;
    *) fail "unsupported OS: ${id:-unknown} (Debian 12+ or Ubuntu 22.04+ is required)" ;;
  esac
  case "$(uname -m)" in
    x86_64) TARGET="x86_64-unknown-linux-musl" ;;
    aarch64) TARGET="aarch64-unknown-linux-musl" ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
  esac
  local cmd
  for cmd in sudo curl visudo useradd sha256sum; do
    command -v "$cmd" >/dev/null 2>&1 || fail "required command not found: $cmd"
  done
  if [ -n "$FROM" ]; then
    [ -f "$FROM/vps-agent" ] && [ -f "$FROM/vps-agent-priv" ] || fail "--from $FROM: binaries not found"
  fi
  ok "preflight: $id $version_id, $(uname -m)"
  if ! command -v tmux >/dev/null 2>&1; then warn "tmux not found (needed from v1)"; fi
}

read_pubkey() {
  if [ -n "$CA_PUBKEY" ]; then
    [[ "$CA_PUBKEY" =~ $KEY_RE ]] || fail "--ca-pubkey does not look like an SSH public key"
    # Certificate mode needs no static key; one given explicitly is still installed.
    if [ -z "$PUBKEY" ]; then return; fi
  fi
  if [ -z "$PUBKEY" ]; then
    if [ "$YES" = 1 ] || [ ! -r /dev/tty ]; then fail "--pubkey is required in non-interactive mode"; fi
    printf 'SSH public key for the agent: ' >/dev/tty
    IFS= read -r PUBKEY </dev/tty
  fi
  [[ "$PUBKEY" =~ $KEY_RE ]] || fail "this does not look like an SSH public key"
}

do_binaries() {
  if [ -n "$FROM" ]; then
    cp "$FROM/vps-agent" "$FROM/vps-agent-priv" "$UI_TMP/"
  else
    local base="https://github.com/$REPO/releases/download/$VERSION"
    if [ "$VERSION" = latest ]; then base="https://github.com/$REPO/releases/latest/download"; fi
    (
      cd "$UI_TMP"
      curl -fsSL -O "$base/vps-agent-$TARGET.tar.gz" -O "$base/SHA256SUMS"
      sha256sum -c --ignore-missing SHA256SUMS
      if [ -n "$MINISIGN_PUBKEY" ] && command -v minisign >/dev/null 2>&1; then
        curl -fsSL -O "$base/SHA256SUMS.minisig"
        minisign -Vm SHA256SUMS -P "$MINISIGN_PUBKEY"
      fi
      tar -xzf "vps-agent-$TARGET.tar.gz"
    )
  fi
  install -d -m 0755 -o root -g root /usr/local/libexec
  install -m 0755 -o root -g root "$UI_TMP/vps-agent" /usr/local/bin/vps-agent
  install -m 0755 -o root -g root "$UI_TMP/vps-agent-priv" /usr/local/libexec/vps-agent-priv
}

do_users() {
  getent group agent-managed >/dev/null || groupadd agent-managed
  id agent >/dev/null 2>&1 || useradd --create-home --shell /bin/bash agent
  # '*' is "no valid password", not "locked": sshd still accepts the key.
  usermod -p '*' agent
  local group
  for group in sudo wheel docker; do
    if id -nG agent | tr ' ' '\n' | grep -qx "$group"; then
      echo "the agent user must not be a member of $group" >&2
      return 1
    fi
  done
  install -d -m 0755 -o root -g root /srv/apps
}

do_dirs() {
  install -d -m 0755 -o root -g root /etc/vps-agent
  install -d -m 0750 -o agent -g agent /var/lib/vps-agent /var/lib/vps-agent/logs /var/lib/vps-agent/jobs
  install -d -m 0700 -o root -g root /var/lib/vps-agent-priv /var/lib/vps-agent-priv/archive
}

do_policy() {
  # Keep in sync with DEFAULT_POLICY_TOML in crates/vps-agent-core/src/policy.rs.
  cat >"$UI_TMP/policy.toml" <<'EOF'
mode = "__MODE__"            # read-only | ask | auto
uid_range = [20000, 29999]

[deny]
commands = ['rm\s+-rf\s+/(\s|$)', 'mkfs', 'dd\s+.*of=/dev/']
paths    = ["/etc/shadow", "/root", "/etc/vps-agent"]
groups   = []

[redact]
patterns = ['(?i)(password|secret|token|api[_-]?key)\s*[=:]\s*\S+', '-----BEGIN [A-Z ]*PRIVATE KEY-----']
EOF
  sed -i "s/__MODE__/$MODE/" "$UI_TMP/policy.toml"
  install -m 0644 -o root -g root "$UI_TMP/policy.toml" /etc/vps-agent/policy.toml
}

do_sudoers() {
  cat >"$UI_TMP/sudoers" <<'EOF'
agent ALL=(root) NOPASSWD: /usr/local/libexec/vps-agent-priv
agent ALL=(%agent-managed, !root) NOPASSWD: ALL
EOF
  visudo -cf "$UI_TMP/sudoers"
  install -m 0440 -o root -g root "$UI_TMP/sudoers" /etc/sudoers.d/vps-agent
  rm -f /var/lib/vps-agent-priv/sudoers.disabled
}

do_key() {
  local home keys
  home="$(getent passwd agent | cut -d: -f6)"
  keys="$home/.ssh/authorized_keys"
  install -d -m 0700 -o agent -g agent "$home/.ssh"
  # A previous `vps-agent off` leaves the keys in a .disabled file; reinstalling turns the agent on.
  if [ -f "$keys.disabled" ] && [ ! -f "$keys" ]; then mv "$keys.disabled" "$keys"; fi
  touch "$keys"
  grep -qxF "$PUBKEY" "$keys" || printf '%s\n' "$PUBKEY" >>"$keys"
  chmod 0600 "$keys"
  chown agent:agent "$keys"
}

do_ca() {
  local dropin=/etc/ssh/sshd_config.d/50-vps-agent.conf
  if ! grep -Eq '^\s*Include\s+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config; then
    echo "/etc/ssh/sshd_config does not include sshd_config.d; certificate mode cannot be set up" >&2
    return 1
  fi
  printf '%s\n' "$CA_PUBKEY" >"$UI_TMP/ca.pub"
  install -m 0644 -o root -g root "$UI_TMP/ca.pub" /etc/ssh/vps-agent_ca.pub
  cat >"$UI_TMP/dropin" <<'EOF'
# Managed by vps-agent. The agent user may log in with certificates signed by this CA.
Match User agent
    TrustedUserCAKeys /etc/ssh/vps-agent_ca.pub
EOF
  install -m 0644 -o root -g root "$UI_TMP/dropin" "$dropin"
  rm -f /var/lib/vps-agent-priv/sshd-dropin.disabled
  # A broken sshd configuration would lock everyone out at the next restart: test, or undo.
  if ! sshd -t; then
    rm -f "$dropin"
    return 1
  fi
  systemctl reload ssh 2>/dev/null || systemctl reload sshd
}

do_selftest() {
  sudo -u agent -H /usr/local/bin/vps-agent selftest
}

ui_init "vps-agent install" "$SCRIPT_VERSION" 9

step
preflight
read_pubkey

step
run "binaries installed" do_binaries
if [ -z "$FROM" ] && { [ -z "$MINISIGN_PUBKEY" ] || ! command -v minisign >/dev/null 2>&1; }; then
  warn "release signature not verified (SHA-256 only)"
fi

step
run "agent user and agent-managed group" do_users

step
run "directories" do_dirs

step
if [ -f /etc/vps-agent/policy.toml ]; then
  ok "policy.toml kept"
else
  run "policy.toml written (mode $MODE)" do_policy
fi

step
run "sudoers rule validated and installed" do_sudoers

step
if [ -n "$PUBKEY" ]; then run "SSH key added" do_key; fi
if [ -n "$CA_PUBKEY" ]; then run "certificate login enabled for agent" do_ca; fi

step
run "selftest" do_selftest

step
ok "done"

host="$(hostname -f 2>/dev/null || hostname)"
# Claude Code allows only letters, digits, hyphens and underscores in MCP server names.
name="vps-${host//./-}"
summary "Connect Claude Code from your machine:

  claude mcp add $name -- ssh agent@$host vps-agent serve

or add to .mcp.json:

  { \"mcpServers\": { \"$name\": { \"command\": \"ssh\", \"args\": [\"agent@$host\", \"vps-agent\", \"serve\"] } } }

Policy: /etc/vps-agent/policy.toml   Kill switch: sudo vps-agent off"

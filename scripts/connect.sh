#!/usr/bin/env bash
# Runs on your machine: creates a key, installs vps-agent on the server over your
# existing SSH access, and registers the MCP server. The private key never leaves this machine.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: connect.sh user@host [options]
  --from <dir>     install from local binaries instead of the latest release
  --mode <mode>    policy mode: read-only, ask (default) or auto
  --name <alias>   ssh alias to create (default: vps-agent-<host>)
  --port <n>       ssh port of the server (default: 22)
  --cert           log in with short-lived certificates signed by a local CA
                   instead of a permanent key in authorized_keys
EOF
  exit 2
}

TARGET=""
FROM=""
MODE="ask"
ALIAS=""
PORT=22
CERT=0

while [ $# -gt 0 ]; do
  case "$1" in
    --from) FROM="${2:?--from needs a directory}"; shift 2 ;;
    --mode) MODE="${2:?--mode needs a value}"; shift 2 ;;
    --name) ALIAS="${2:?--name needs a value}"; shift 2 ;;
    --port) PORT="${2:?--port needs a value}"; shift 2 ;;
    --cert) CERT=1; shift ;;
    -*) usage ;;
    *) [ -z "$TARGET" ] || usage; TARGET="$1"; shift ;;
  esac
done

[ -n "$TARGET" ] || usage
case "$MODE" in read-only | ask | auto) ;; *) usage ;; esac
[[ "$PORT" =~ ^[0-9]+$ ]] || usage

HOST="${TARGET#*@}"
[[ "$HOST" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "unexpected host name: $HOST" >&2; exit 2; }
ALIAS="${ALIAS:-vps-agent-$HOST}"
[[ "$ALIAS" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "unexpected alias: $ALIAS" >&2; exit 2; }
# Claude Code allows only letters, digits, hyphens and underscores in MCP server names.
MCP_NAME="${ALIAS//./-}"
# hosts.toml names are lowercase letters, digits and dashes, at most 32 characters.
MUX_NAME="$(printf '%s' "${ALIAS#vps-agent-}" | tr 'A-Z._' 'a-z--' | cut -c1-32)"
KEY="$HOME/.ssh/vps-agent_$HOST"
CA="$HOME/.ssh/vps-agent_ca"
# Written into ~/.ssh/config and hosts.toml with a literal ~ so that both Git Bash and
# native Windows programs resolve them; $HOME itself looks like /c/Users/... in Git Bash.
# shellcheck disable=SC2088
KEY_REF="~/.ssh/vps-agent_$HOST"
# shellcheck disable=SC2088
CA_REF="~/.ssh/vps-agent_ca"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEY_RE='^ssh-ed25519 [A-Za-z0-9+/=]+( [A-Za-z0-9@._-]+)?$'

remote() { ssh -p "$PORT" "$TARGET" "$@"; }

new_key() { # path comment
  if [ ! -f "$1" ]; then
    echo "==> generating $1"
    ssh-keygen -q -t ed25519 -N "" -C "$2" -f "$1"
  fi
  [[ "$(cat "$1.pub")" =~ $KEY_RE ]] || { echo "unexpected public key format in $1.pub" >&2; exit 1; }
}

mkdir -p "$HOME/.ssh"
new_key "$KEY" "vps-agent@$HOST"
if [ "$CERT" = 1 ]; then
  new_key "$CA" "vps-agent-ca"
  ACCESS="--ca-pubkey '$(cat "$CA.pub")'"
else
  ACCESS="--pubkey '$(cat "$KEY.pub")'"
fi

SUDO="sudo"
if [ "$(remote id -u)" = 0 ]; then SUDO=""; fi

echo "==> installing on $HOST ($(remote uname -m))"
if [ -n "$FROM" ]; then
  INSTALLER="$SCRIPT_DIR/../dist/install.sh"
  [ -f "$INSTALLER" ] || { echo "dist/install.sh not found: run scripts/bundle.sh first" >&2; exit 1; }
  RTMP="$(remote mktemp -d)"
  [[ "$RTMP" =~ ^/tmp/[A-Za-z0-9._-]+$ ]] || { echo "unexpected remote temp dir: $RTMP" >&2; exit 1; }
  scp -q -P "$PORT" "$FROM/vps-agent" "$FROM/vps-agent-priv" "$INSTALLER" "$TARGET:$RTMP/"
  # -t gives install.sh a terminal so it can draw its progress.
  ssh -t -p "$PORT" "$TARGET" "$SUDO bash $RTMP/install.sh --from $RTMP $ACCESS --mode $MODE --yes; rc=\$?; rm -rf $RTMP; exit \$rc"
else
  ssh -t -p "$PORT" "$TARGET" "curl -fsSL https://github.com/zorahm/vps-agent/releases/latest/download/install.sh | $SUDO bash -s -- $ACCESS --mode $MODE --yes"
fi

CONFIG="$HOME/.ssh/config"
touch "$CONFIG"
if ! grep -q "^Host $ALIAS\$" "$CONFIG"; then
  echo "==> adding Host $ALIAS to $CONFIG"
  {
    printf '\nHost %s\n    HostName %s\n    User agent\n    Port %s\n' "$ALIAS" "$HOST" "$PORT"
    printf '    IdentityFile %s\n    IdentitiesOnly yes\n' "$KEY_REF"
    if [ "$CERT" = 1 ]; then printf '    CertificateFile %s-cert.pub\n' "$KEY_REF"; fi
  } >>"$CONFIG"
fi

HOSTS="${VPS_AGENT_HOSTS:-$HOME/.config/vps-agent/hosts.toml}"
mkdir -p "$(dirname "$HOSTS")"
touch "$HOSTS"
if ! grep -q "^\[hosts\.$MUX_NAME\]\$" "$HOSTS"; then
  echo "==> adding [hosts.$MUX_NAME] to $HOSTS"
  {
    printf '\n[hosts.%s]\nssh = "%s"\n' "$MUX_NAME" "$ALIAS"
    # Literal TOML strings with ~: vps-agent-mux expands it itself on every platform.
    if [ "$CERT" = 1 ]; then printf "identity = '%s'\nca_key = '%s'\n" "$KEY_REF" "$CA_REF"; fi
  } >>"$HOSTS"
fi

echo "==> checking the agent login"
if [ "$CERT" = 1 ]; then
  ssh-keygen -q -s "$CA" -I connect.sh -n agent -V -1m:+5m "$KEY.pub"
fi
ssh "$ALIAS" vps-agent selftest

if command -v vps-agent-mux >/dev/null 2>&1; then
  REGISTER=(claude mcp add vps-agent -- vps-agent-mux)
  NOTE="all hosts in $HOSTS are served by one MCP server, vps-agent"
elif [ "$CERT" = 1 ]; then
  echo "Certificate mode needs vps-agent-mux on PATH: it signs a fresh certificate before each"
  echo "connection. Build it with: cargo build --release -p vps-agent-mux"
  echo "Then register it with:   claude mcp add vps-agent -- vps-agent-mux"
  exit 0
else
  REGISTER=(claude mcp add "$MCP_NAME" -- ssh "$ALIAS" vps-agent serve)
  NOTE="registered $MCP_NAME"
fi

if command -v claude >/dev/null 2>&1; then
  echo "==> registering the MCP server in Claude Code"
  # A second connect.sh run finds the multiplexer already registered; that is fine.
  "${REGISTER[@]}" || true
  echo "$NOTE"
else
  echo "Claude Code CLI not found. Register the server with:"
  echo "  ${REGISTER[*]}"
fi

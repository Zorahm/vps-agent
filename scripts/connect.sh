#!/usr/bin/env bash
# Runs on your machine: creates a key, installs vps-agent on the server over your
# existing SSH access, and registers the MCP server. The private key never leaves this machine.
set -euo pipefail

usage() {
  echo "usage: connect.sh user@host [--from <dir with binaries>] [--mode read-only|ask|auto] [--name <alias>] [--port <n>]" >&2
  exit 2
}

TARGET=""
FROM=""
MODE="ask"
ALIAS=""
PORT=22

while [ $# -gt 0 ]; do
  case "$1" in
    --from) FROM="${2:?--from needs a directory}"; shift 2 ;;
    --mode) MODE="${2:?--mode needs a value}"; shift 2 ;;
    --name) ALIAS="${2:?--name needs a value}"; shift 2 ;;
    --port) PORT="${2:?--port needs a value}"; shift 2 ;;
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
KEY="$HOME/.ssh/vps-agent_$HOST"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

remote() { ssh -p "$PORT" "$TARGET" "$@"; }

mkdir -p "$HOME/.ssh"
if [ ! -f "$KEY" ]; then
  echo "==> generating $KEY"
  ssh-keygen -q -t ed25519 -N "" -C "vps-agent@$HOST" -f "$KEY"
fi
PUB="$(cat "$KEY.pub")"
[[ "$PUB" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+(\ [A-Za-z0-9@._-]+)?$ ]] || { echo "unexpected public key format in $KEY.pub" >&2; exit 1; }

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
  ssh -t -p "$PORT" "$TARGET" "$SUDO bash $RTMP/install.sh --from $RTMP --pubkey '$PUB' --mode $MODE --yes; rc=\$?; rm -rf $RTMP; exit \$rc"
else
  ssh -t -p "$PORT" "$TARGET" "curl -fsSL https://github.com/zorahm/vps-agent/releases/latest/download/install.sh | $SUDO bash -s -- --pubkey '$PUB' --mode $MODE --yes"
fi

CONFIG="$HOME/.ssh/config"
touch "$CONFIG"
if ! grep -q "^Host $ALIAS\$" "$CONFIG"; then
  echo "==> adding Host $ALIAS to $CONFIG"
  cat >>"$CONFIG" <<EOF

Host $ALIAS
    HostName $HOST
    User agent
    Port $PORT
    IdentityFile $KEY
    IdentitiesOnly yes
EOF
fi

echo "==> checking the agent login"
ssh "$ALIAS" vps-agent selftest

if command -v claude >/dev/null 2>&1; then
  echo "==> registering the MCP server in Claude Code"
  claude mcp add "$MCP_NAME" -- ssh "$ALIAS" vps-agent serve
else
  echo "Claude Code CLI not found. Register the server with:"
  echo "  claude mcp add $MCP_NAME -- ssh $ALIAS vps-agent serve"
fi

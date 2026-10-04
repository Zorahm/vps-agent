#!/usr/bin/env bash
# Exercises the remote MCP endpoint and its OAuth flow on loopback. Run as root on the server.
# It sets the endpoint up for a throwaway hostname, tests it and removes every trace again.
# The checks are evaluated later by check(), so their expressions are single-quoted on purpose.
# shellcheck disable=SC2016,SC2034
set -uo pipefail

HOST="mcp.accept.invalid"
BASE="http://127.0.0.1:8722"
REDIRECT="https://claude.ai/api/mcp/auth_callback"
# RFC 7636 appendix B.
VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
FAILED=0
SERVER_PID=""

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n      %s\n' "$1" "${2:-}"; FAILED=$((FAILED + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1" "${3:-}"; fi; }
req() { curl -s -H "Host: $HOST" "$@"; }
field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }

cleanup() {
  if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null; fi
  pkill -u agent -f 'vps-agent serve-http' 2>/dev/null
  if [ -z "${KEEP_EXISTING:-}" ]; then
    rm -f /etc/vps-agent/http.toml /etc/systemd/system/vps-agent-http.service
    rm -rf /var/lib/vps-agent/http
    systemctl daemon-reload
  fi
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
if [ -f /etc/vps-agent/http.toml ]; then
  KEEP_EXISTING=1
  echo "http.toml already exists: refusing to overwrite a configured endpoint" >&2
  exit 2
fi

setup="$(/usr/local/bin/vps-agent http-setup --public-url "https://$HOST")"
SECRET="$(printf '%s\n' "$setup" | sed -n '/Pairing secret/{n;n;s/^ *//p}')"
check "http-setup prints a pairing secret" '[ ${#SECRET} -ge 40 ]' "$setup"
check "http.toml is root:agent 640" '[ "$(stat -c "%U:%G %a" /etc/vps-agent/http.toml)" = "root:agent 640" ]'
check "the secret itself is not stored" '! grep -q "$SECRET" /etc/vps-agent/http.toml'
check "a public bind is refused" '! /usr/local/bin/vps-agent http-setup --public-url "https://$HOST" --bind 0.0.0.0:8722 >/dev/null 2>&1'

sudo -u agent -H /usr/local/bin/vps-agent serve-http >/dev/null 2>&1 &
SERVER_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -s -o /dev/null "$BASE/.well-known/oauth-authorization-server"; then break; fi
  sleep 0.3
done

out="$(req -i -X POST "$BASE/mcp" -H 'Content-Type: application/json' -d '{}')"
check "/mcp without a token is 401 with a resource_metadata challenge" \
  'printf "%s" "$out" | grep -q "^HTTP/1.1 401" && printf "%s" "$out" | grep -qi "www-authenticate: Bearer resource_metadata=\"https://$HOST/.well-known/oauth-protected-resource\""' "$out"
out="$(req -i -X POST "$BASE/mcp" -H 'Authorization: Bearer made-up' -H 'Content-Type: application/json' -d '{}')"
check "/mcp with a made-up token is 401" 'printf "%s" "$out" | grep -q "^HTTP/1.1 401"' "$out"

out="$(req "$BASE/.well-known/oauth-protected-resource")"
check "protected resource metadata" 'printf "%s" "$out" | grep -q "\"resource\":\"https://$HOST/mcp\""' "$out"
out="$(req "$BASE/.well-known/oauth-authorization-server")"
check "authorization server metadata" 'printf "%s" "$out" | grep -q "\"token_endpoint\":\"https://$HOST/token\"" && printf "%s" "$out" | grep -q S256' "$out"

out="$(req -X POST "$BASE/register" -H 'Content-Type: application/json' -d '{"client_name":"evil","redirect_uris":["http://evil.example/cb"]}')"
check "registration refuses a plain-http redirect" 'printf "%s" "$out" | grep -q invalid_request' "$out"
out="$(req -X POST "$BASE/register" -H 'Content-Type: application/json' -d "{\"client_name\":\"<b>Claude</b>\",\"redirect_uris\":[\"$REDIRECT\"]}")"
CLIENT="$(printf '%s' "$out" | field client_id)"
check "dynamic client registration" '[ -n "$CLIENT" ]' "$out"

Q="response_type=code&client_id=$CLIENT&redirect_uri=$REDIRECT&code_challenge=$CHALLENGE&code_challenge_method=S256&state=st%20ate"
out="$(req -i "$BASE/authorize?$Q")"
check "consent page renders, escaped and unframeable" \
  'printf "%s" "$out" | grep -q "^HTTP/1.1 200" && printf "%s" "$out" | grep -q "&lt;b&gt;Claude" && printf "%s" "$out" | grep -qi "x-frame-options: DENY"' "$out"
out="$(req -i "$BASE/authorize?${Q/$REDIRECT/https://evil.example/cb}")"
check "an unregistered redirect_uri is refused without redirecting" \
  'printf "%s" "$out" | grep -q "^HTTP/1.1 400" && ! printf "%s" "$out" | grep -qi "^location:"' "$out"
out="$(req -i "$BASE/authorize?${Q/S256/plain}")"
check "PKCE plain is refused" 'printf "%s" "$out" | grep -q "^HTTP/1.1 400"' "$out"

out="$(req -i -X POST "$BASE/authorize" -d "$Q" --data-urlencode "secret=wrong")"
check "a wrong pairing secret is refused" 'printf "%s" "$out" | grep -q "^HTTP/1.1 403" && ! printf "%s" "$out" | grep -qi "^location:"' "$out"
out="$(req -i -X POST "$BASE/authorize" -d "$Q" --data-urlencode "secret=$SECRET")"
CODE="$(printf '%s' "$out" | tr -d '\r' | sed -n 's/^[Ll]ocation: .*[?&]code=\([^&]*\).*/\1/p')"
check "the right secret redirects back with a code and the state" \
  '[ -n "$CODE" ] && printf "%s" "$out" | grep -qi "^location: $REDIRECT?code=.*&state=st%20ate"' "$out"

T="grant_type=authorization_code&client_id=$CLIENT&redirect_uri=$REDIRECT&code=$CODE"
out="$(req -X POST "$BASE/token" -d "$T&code_verifier=wrong-verifier-wrong-verifier-wrong-verifier-x")"
check "a wrong code_verifier is refused" 'printf "%s" "$out" | grep -q invalid_grant' "$out"
out="$(req -X POST "$BASE/token" -d "$T&code_verifier=$VERIFIER")"
check "the failed attempt burned the code" 'printf "%s" "$out" | grep -q invalid_grant' "$out"

out="$(req -i -X POST "$BASE/authorize" -d "$Q" --data-urlencode "secret=$SECRET")"
CODE="$(printf '%s' "$out" | tr -d '\r' | sed -n 's/^[Ll]ocation: .*[?&]code=\([^&]*\).*/\1/p')"
out="$(req -X POST "$BASE/token" -d "grant_type=authorization_code&client_id=$CLIENT&redirect_uri=$REDIRECT&code=$CODE&code_verifier=$VERIFIER")"
ACCESS="$(printf '%s' "$out" | field access_token)"
REFRESH="$(printf '%s' "$out" | field refresh_token)"
check "code exchange returns tokens" '[ -n "$ACCESS" ] && [ -n "$REFRESH" ]' "$out"

INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"accept","version":"0"}}}'
out="$(req -i -X POST "$BASE/mcp" -H "Authorization: Bearer $ACCESS" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d "$INIT")"
check "MCP initialize works with the access token" 'printf "%s" "$out" | grep -q "^HTTP/1.1 200" && printf "%s" "$out" | grep -q serverInfo' "$out"
out="$(curl -s -i -H 'Host: evil.example' -X POST "$BASE/mcp" -H "Authorization: Bearer $ACCESS" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d "$INIT")"
check "a foreign Host header is refused (DNS rebinding guard)" '! printf "%s" "$out" | grep -q "^HTTP/1.1 200"' "$out"

out="$(req -X POST "$BASE/token" -d "grant_type=refresh_token&client_id=$CLIENT&refresh_token=$REFRESH")"
ACCESS2="$(printf '%s' "$out" | field access_token)"
check "refresh returns a new access token" '[ -n "$ACCESS2" ] && [ "$ACCESS2" != "$ACCESS" ]' "$out"
out="$(req -X POST "$BASE/token" -d "grant_type=refresh_token&client_id=$CLIENT&refresh_token=$REFRESH")"
check "a used refresh token is refused" 'printf "%s" "$out" | grep -q invalid_grant' "$out"
check "state file holds no raw tokens" '! grep -q -e "$ACCESS2" -e "$REFRESH" /var/lib/vps-agent/http/state.json'

for _ in 1 2 3 4 5; do req -o /dev/null -X POST "$BASE/authorize" -d "$Q" --data-urlencode "secret=wrong"; done
out="$(req -i -X POST "$BASE/authorize" -d "$Q" --data-urlencode "secret=$SECRET")"
check "five wrong secrets lock approval, even for the right one" 'printf "%s" "$out" | grep -q "^HTTP/1.1 403" && printf "%s" "$out" | grep -q "too many"' "$out"

echo
if [ "$FAILED" = 0 ]; then echo "all HTTP checks passed"; else echo "$FAILED HTTP check(s) failed"; exit 1; fi

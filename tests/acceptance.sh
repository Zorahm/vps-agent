#!/usr/bin/env bash
# On-server acceptance checks for an installed vps-agent. Run as root on the server.
# Optional: acceptance.sh <dir with vps-agent, vps-agent-priv, install.sh> also checks a re-install.
set -uo pipefail

REINSTALL_DIR="${1:-}"
PRIV=/usr/local/libexec/vps-agent-priv
FAILED=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; FAILED=$((FAILED + 1)); }

expect_ok() { # label cmd...
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$label"; else fail "$label"; fi
}

expect_fail() { # label cmd...
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then fail "$label"; else pass "$label"; fi
}

expect_code() { # label code cmd...
  local label="$1" want="$2" got; shift 2
  "$@" >/dev/null 2>&1; got=$?
  if [ "$got" = "$want" ]; then pass "$label"; else fail "$label (exit $got, expected $want)"; fi
}

expect_stat() { # path "owner mode"
  local got; got="$(stat -c '%U %a' "$1" 2>/dev/null)"
  if [ "$got" = "$2" ]; then pass "stat $1 = $2"; else fail "stat $1: '$got', expected '$2'"; fi
}

as_agent() { sudo -u agent -H "$@"; }
helper() { as_agent sudo -n "$PRIV" "$@"; }

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }

# 1. paths and modes
expect_stat /usr/local/bin/vps-agent "root 755"
expect_stat "$PRIV" "root 755"
expect_stat /etc/vps-agent/policy.toml "root 644"
expect_stat /var/lib/vps-agent "agent 750"
expect_stat /var/lib/vps-agent-priv "root 700"

# 2-3. sudoers
expect_ok "sudoers file is valid" visudo -cf /etc/sudoers.d/vps-agent
expect_fail "agent has no general sudo" as_agent sudo -n true

# 4-6. managed user
helper user delete acc-test >/dev/null 2>&1
expect_ok "user create acc-test" helper user create acc-test
uid="$(id -u acc-test 2>/dev/null || echo 0)"
if [ "$uid" -ge 20000 ] && [ "$uid" -le 29999 ]; then pass "uid $uid is in the managed range"; else fail "uid $uid out of range"; fi
expect_stat /srv/apps/acc-test "acc-test 750"
if [ "$(as_agent sudo -n -u acc-test -H -- id -un 2>/dev/null)" = acc-test ]; then pass "agent can become acc-test"; else fail "agent cannot become acc-test"; fi
expect_fail "agent cannot become root" as_agent sudo -n -u root -- id

# 7-8. helper validation
expect_code "user create root is denied" 3 helper user create root
expect_code "user create -rf is denied" 3 helper user create -rf
expect_code "group add docker is denied" 3 helper group add acc-test docker
expect_code "unknown action is a usage error" 2 helper exec id

# 9. concurrent creates get distinct UIDs
helper user delete acc-a >/dev/null 2>&1; helper user delete acc-b >/dev/null 2>&1
helper user create acc-a >/dev/null 2>&1 & p1=$!
helper user create acc-b >/dev/null 2>&1 & p2=$!
wait "$p1"; r1=$?; wait "$p2"; r2=$?
ua="$(id -u acc-a 2>/dev/null)"; ub="$(id -u acc-b 2>/dev/null)"
if [ "$r1" = 0 ] && [ "$r2" = 0 ] && [ -n "$ua" ] && [ "$ua" != "$ub" ]; then pass "parallel creates: uids $ua and $ub"; else fail "parallel creates (exit $r1/$r2, uids '$ua'/'$ub')"; fi

# 10. all three signs are required
gpasswd -d acc-test agent-managed >/dev/null 2>&1
expect_code "user check fails outside agent-managed" 3 helper user check acc-test
expect_fail "sudo -u fails outside agent-managed" as_agent sudo -n -u acc-test -H -- true
usermod -aG agent-managed acc-test
expect_ok "user check passes again" helper user check acc-test

# 11-12. policy is read-only for the agent; calls are audited
expect_fail "agent cannot write policy.toml" as_agent test -w /etc/vps-agent/policy.toml
if journalctl -t vps-agent-priv -n 50 --no-pager 2>/dev/null | grep -q acc-test; then pass "helper calls are in journald"; else fail "no helper calls in journald"; fi

# 13. re-install is idempotent
if [ -n "$REINSTALL_DIR" ]; then
  keys="$(getent passwd agent | cut -d: -f6)/.ssh/authorized_keys"
  key="$(head -n 1 "$keys")"
  before="$(sha256sum /etc/vps-agent/policy.toml)"
  expect_ok "install.sh runs again" bash "$REINSTALL_DIR/install.sh" --from "$REINSTALL_DIR" --pubkey "$key" --yes --no-color
  if [ "$(sha256sum /etc/vps-agent/policy.toml)" = "$before" ]; then pass "policy.toml untouched"; else fail "policy.toml changed"; fi
  if [ "$(grep -cxF "$key" "$keys")" = 1 ]; then pass "key present once"; else fail "key duplicated"; fi
fi

# 14. kill switch
expect_ok "vps-agent off" /usr/local/bin/vps-agent off
expect_fail "helper unreachable while off" helper user list
expect_ok "vps-agent on" /usr/local/bin/vps-agent on
expect_ok "helper reachable again" helper user list

# 15. delete with archive
expect_ok "user delete acc-test --archive" helper user delete acc-test --archive
if ls /var/lib/vps-agent-priv/archive/acc-test-*.tar.gz >/dev/null 2>&1; then pass "archive exists"; else fail "archive missing"; fi
expect_fail "acc-test is gone" id acc-test
helper user delete acc-a >/dev/null 2>&1; helper user delete acc-b >/dev/null 2>&1

echo
if [ "$FAILED" = 0 ]; then echo "all checks passed"; else echo "$FAILED check(s) failed"; exit 1; fi

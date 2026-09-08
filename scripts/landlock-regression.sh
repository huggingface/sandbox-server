#!/bin/sh
# Live regression for fail-closed confinement.
#
# The property under test: a sandbox is never handed out with weaker isolation
# than asked for, and the client can always find out what it got. Plus the
# ordinary things a sandbox needs from a narrowed /dev still work.
#
#   docker run --rm -v "$PWD:/src" -w /src sh scripts/landlock-regression.sh
set -eu

BIN=${BIN:-target/x86_64-unknown-linux-musl/release/sbx-server}
PORT=${PORT:-49501}
TOKEN=t
U="http://127.0.0.1:$PORT"
failures=0

say()  { printf '\n=== %s\n' "$1"; }
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; failures=$((failures + 1)); }

stop() { kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true; }

command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl >/dev/null; }
[ -f "$BIN" ] || cargo build --release --target x86_64-unknown-linux-musl

# What this kernel actually offers; the checks below adapt rather than assuming.
# On its own port, so the probe cannot collide with the servers started below.
PROBE_PORT=$((PORT + 50))
SBX_PORT=$PROBE_PORT SBX_TOKEN=$TOKEN "$BIN" >/tmp/probe.log 2>&1 &
probe=$!
sleep 1
ABI=$(curl -s "http://127.0.0.1:$PROBE_PORT/health" | sed 's/.*"abi":\([0-9]*\).*/\1/')
kill "$probe" 2>/dev/null || true
wait "$probe" 2>/dev/null || true
echo "kernel landlock ABI: $ABI"

say "/health reports the confinement the client is getting"
SBX_PORT=$PORT SBX_TOKEN=$TOKEN SBX_HOST_MODE=1 SBX_MIN_LANDLOCK_ABI=1 "$BIN" >/tmp/log 2>&1 &
server=$!
sleep 1
# The detail is authenticated: an unauthenticated caller gets liveness only.
curl -s -H "X-Sandbox-Token: $TOKEN" "$U/health" >/tmp/body
grep -q '"abi"' /tmp/body && pass "abi is reported" || fail "no abi in /health: $(cat /tmp/body)"
grep -q '"features"' /tmp/body && pass "features are reported" || fail "no features in /health"
curl -s "$U/health" | grep -q '"abi"' &&
    fail "the unauthenticated /health leaks the confinement detail" ||
    pass "and not to an unauthenticated caller"
grep -q 'abi [0-9]* \[' /tmp/log && pass "startup log states the ABI and features" || fail "startup log: $(head -c 200 /tmp/log)"

say "a created sandbox reports how it is confined"
curl -s -H "X-Sandbox-Token: $TOKEN" -X POST "$U/v1/sandboxes" -d '{"count":1}' >/tmp/created
S=$(sed 's/.*"id":"\([^"]*\)".*/\1/' /tmp/created)
grep -q '"confinement":"landlock"' /tmp/created &&
    pass "create response says landlock" ||
    fail "create response confinement: $(head -c 200 /tmp/created)"
curl -s -H "X-Sandbox-Token: $TOKEN" "$U/v1/sandboxes" >/tmp/body
grep -q '"confinement":"landlock"' /tmp/body && pass "list says landlock" || fail "list confinement missing"

say "the narrowed /dev still serves a normal workload"
T=$(sed 's/.*"token":"\([^"]*\)".*/\1/' /tmp/created)
# argv form, so nothing here needs shell-quoting inside JSON.
run_argv() {
    curl -s -m 60 -H "X-Sandbox-Token: $T" -X POST "$U/v1/sandboxes/$S/exec" \
        -d "{\"cmd\":[\"/bin/sh\",\"-c\",$1]}"
}
probe() { # $1 JSON-quoted shell command, $2 marker
    out=$(run_argv "$1")
    case "$out" in
        *"$2"*) pass "probe: $2" ;;
        *)      fail "probe $2: $(printf '%s' "$out" | head -c 220)" ;;
    esac
}

probe '"cat /dev/null && echo DEVOK"'                         DEVOK
probe '"head -c 8 /dev/urandom >/dev/null && echo RANDOK"'    RANDOK
probe '"echo x >/dev/null && echo WRITEOK"'                   WRITEOK
probe '"echo y 2>/dev/null && echo REDIROK"'                  REDIROK
probe '"python3 -c 1 && echo PYOK"'                           PYOK
probe '"python3 -c \"import ssl,hashlib,random,os\" && echo SSLOK"'  SSLOK
probe '"[ -w /dev/null ] && echo DEVWRITABLE"'                DEVWRITABLE
# A --user install is the documented way to add packages in a pooled sandbox.
probe '"python3 -m pip install --user -q --disable-pip-version-check six >/dev/null 2>&1; python3 -c \"import six\" && echo PIPOK"' PIPOK

say "the documented denials actually hold"
# These are the guarantees the isolation model advertises. Asserting them here
# means a future change to the ruleset cannot quietly drop one.
denied() { # $1 JSON-quoted command, $2 label
    out=$(run_argv "$1")
    case "$out" in
        *DENIED*) pass "denied: $2" ;;
        *)        fail "NOT denied: $2 -> $(printf '%s' "$out" | head -c 200)" ;;
    esac
}
denied '"echo x > /tmp/escape 2>/dev/null || echo DENIED"'          "write to /tmp"
denied '"echo x > /dev/shm/escape 2>/dev/null || echo DENIED"'      "write to /dev/shm"
denied '"cat /etc/shadow >/dev/null 2>&1 || echo DENIED"'           "read /etc/shadow"
denied '"echo x > /etc/passwd 2>/dev/null || echo DENIED"'          "write to /etc"
denied '"echo x > /dev/kmsg 2>/dev/null || echo DENIED"'            "write to an ungranted device node"
# A second sandbox's home, named directly (not via a symlink -- that is covered
# by the file-API regression).
curl -s -H "X-Sandbox-Token: $TOKEN" -X POST "$U/v1/sandboxes" -d '{"count":1}' >/tmp/other
OTHER=$(sed 's/.*"home":"\([^"]*\)".*/\1/' /tmp/other)
denied "\"ls $OTHER >/dev/null 2>&1 || echo DENIED\""                "read a sibling's home"
denied "\"echo x > $OTHER/planted 2>/dev/null || echo DENIED\""       "write into a sibling's home"

if [ "${ABI:-0}" -ge 4 ]; then
    probe '"python3 -c \"import socket,sys; s=socket.socket()\ntry:\n s.bind((\\\"127.0.0.1\\\",18080)); print(\\\"BOUND\\\")\nexcept Exception: print(\\\"DENIED\\\")\"" ' DENIED
else
    printf '  skip  TCP bind denial needs landlock ABI 4 (this kernel: %s)\n' "${ABI:-?}"
fi

stop

say "host mode refuses to start below the required ABI"
code=0
timeout 5 env SBX_PORT=$PORT SBX_TOKEN=$TOKEN SBX_HOST_MODE=1 SBX_MIN_LANDLOCK_ABI=99 "$BIN" >/tmp/log 2>&1 || code=$?
case $code in
    124) fail "started below the ABI floor" ;;
    *)   grep -q 'required for the documented isolation guarantees' /tmp/log &&
             pass "refused, naming what is missing" ||
             fail "exited $code without explaining: $(head -c 200 /tmp/log)" ;;
esac

say "dedicated mode is not gated on the ABI (its boundary is the VM)"
SBX_PORT=$PORT SBX_TOKEN=$TOKEN SBX_MIN_LANDLOCK_ABI=99 "$BIN" >/tmp/log 2>&1 &
server=$!
sleep 1
curl -s -o /dev/null -w '%{http_code}' "$U/health" | grep -q 200 &&
    pass "dedicated mode still starts" || fail "dedicated mode was gated"
stop

say "--allow-unconfined is the only way to get uid-only isolation"
SBX_PORT=$PORT SBX_TOKEN=$TOKEN SBX_HOST_MODE=1 SBX_MIN_LANDLOCK_ABI=99 "$BIN" --allow-unconfined >/tmp/log 2>&1 &
server=$!
sleep 1
if curl -s -o /dev/null -w '%{http_code}' "$U/health" | grep -q 200; then
    pass "starts with the flag"
else
    fail "did not start even with --allow-unconfined: $(head -c 200 /tmp/log)"
fi
stop

say "result"
if [ "$failures" -eq 0 ]; then
    echo "all checks passed"
else
    echo "$failures check(s) failed"
    exit 1
fi

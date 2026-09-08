#!/bin/sh
# Live regression for command supervision: timeout watchers, the idle watchdog
# vs long foreground commands, zombie reaping, registry growth, and honest
# teardown reporting.
#
#   docker run --rm -v "$PWD:/src" -w /src sh scripts/process-supervision-regression.sh
set -eu

BIN=${BIN:-target/x86_64-unknown-linux-musl/release/sbx-server}
PORT=${PORT:-49701}
TOKEN=t
U="http://127.0.0.1:$PORT"
A="X-Sandbox-Token: $TOKEN"
failures=0

# These checks are about supervision, not the Landlock floor; accept whatever
# the test kernel offers.
export SBX_MIN_LANDLOCK_ABI=1

say()  { printf '\n=== %s\n' "$1"; }
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; failures=$((failures + 1)); }
stop() { kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true; }

threads() { awk '/^Threads:/ {print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }
# `grep -c` exits 1 on no match, so count with awk to avoid emitting two values.
zombies() { ps -eo stat= 2>/dev/null | awk '/^Z/ {n++} END {print n + 0}'; }

command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl >/dev/null; }
command -v ps >/dev/null || { apt-get update -qq && apt-get install -y -qq procps >/dev/null; }
[ -f "$BIN" ] || cargo build --release --target x86_64-unknown-linux-musl

say "a finished command does not leave its timeout watcher asleep"
SBX_PORT=$PORT SBX_TOKEN=$TOKEN "$BIN" >/tmp/log 2>&1 &
server=$!
sleep 1
base=$(threads "$server")
# 20 commands that finish instantly but ask for a one-hour timeout. Before the
# cancellation channel, each left a thread sleeping for the full hour.
i=0
while [ $i -lt 20 ]; do
    curl -s -o /dev/null -m 20 -H "$A" -X POST "$U/v1/exec" -d '{"cmd":"true","timeout":3600}'
    i=$((i + 1))
done
sleep 2
after=$(threads "$server")
echo "  threads: baseline $base, after 20 commands with timeout=3600 -> $after"
[ "$after" -le $((base + 4)) ] && pass "watchers exited with their commands" || fail "threads grew to $after (baseline $base)"

say "a timeout still fires when the command overruns"
out=$(curl -s -m 30 -H "$A" -X POST "$U/v1/exec" -d '{"cmd":"sleep 30","timeout":2}')
case "$out" in
    *'"timed_out":true'*) pass "an overrunning command is killed and reported as timed out" ;;
    *) fail "timeout: $(printf '%s' "$out" | head -c 200)" ;;
esac
stop

say "a long foreground command is not killed by the idle watchdog"
# The command runs for 12s with a 3s idle timeout and no other traffic. Before
# activity accounting, the watchdog shut the job down mid-command.
SBX_PORT=$PORT SBX_TOKEN=$TOKEN SBX_IDLE_TIMEOUT=3 "$BIN" >/tmp/log 2>&1 &
server=$!
sleep 1
out=$(curl -s -m 40 -H "$A" -X POST "$U/v1/exec" -d '{"cmd":"sleep 12; echo survived"}' || echo CONNECTION_LOST)
case "$out" in
    *survived*) pass "the command completed" ;;
    *) fail "command did not survive the idle watchdog: $(printf '%s' "$out" | head -c 200)" ;;
esac
kill -0 "$server" 2>/dev/null && pass "the server is still running" || fail "the server exited under its own command"
# And the watchdog must still work once things really are idle.
sleep 12
kill -0 "$server" 2>/dev/null && fail "the idle watchdog never fired" || pass "the watchdog still shuts down when idle"
wait "$server" 2>/dev/null || true

say "orphaned descendants are reaped"
SBX_PORT=$PORT SBX_TOKEN=$TOKEN SBX_HOST_MODE=1 SBX_CAPACITY=4 "$BIN" >/tmp/log 2>&1 &
server=$!
sleep 1
curl -s -H "$A" -X POST "$U/v1/sandboxes" -d '{"count":1}' >/tmp/created
S=$(sed 's/.*"id":"\([^"]*\)".*/\1/' /tmp/created)
T=$(sed 's/.*"token":"\([^"]*\)".*/\1/' /tmp/created)
before=$(zombies)
# A short-lived detached grandchild: its parent exits immediately, so it
# re-parents to the server and used to stay a zombie.
curl -s -m 20 -H "X-Sandbox-Token: $T" -X POST "$U/v1/sandboxes/$S/exec" \
    -d '{"cmd":"setsid /bin/sh -c \"sleep 0.2\" & exit 0"}' >/dev/null
sleep 4
after=$(zombies)
echo "  zombies: before $before, after $after"
[ "$after" -le "$before" ] && pass "no zombie left behind" || fail "zombie count rose from $before to $after"

say "exit codes are still reported correctly (the reaper must not steal them)"
for spec in 'true:0' 'exit 7:7' 'false:1' 'sleep 0.1; exit 3:3'; do
    cmd=${spec%:*}
    want=${spec##*:}
    out=$(curl -s -m 20 -H "X-Sandbox-Token: $T" -X POST "$U/v1/sandboxes/$S/exec" -d "{\"cmd\":\"$cmd\"}")
    case "$out" in
        *"\"exit_code\":$want"*) pass "exit code $want" ;;
        *) fail "exit code for '$cmd': $(printf '%s' "$out" | head -c 200)" ;;
    esac
done

say "the process registry does not grow without bound"
i=0
while [ $i -lt 300 ]; do
    curl -s -o /dev/null -H "X-Sandbox-Token: $T" -X POST "$U/v1/sandboxes/$S/processes" -d '{"cmd":"true"}'
    i=$((i + 1))
done
sleep 2
count=$(curl -s -H "X-Sandbox-Token: $T" "$U/v1/sandboxes/$S/processes" | grep -o '"id"' | wc -l)
echo "  processes listed after 300 short background commands: $count"
[ "$count" -le 300 ] && pass "finished entries are capped ($count listed)" || fail "registry grew to $count"

say "a running background process is never dropped from the registry"
curl -s -H "X-Sandbox-Token: $T" -X POST "$U/v1/sandboxes/$S/processes" -d '{"cmd":"sleep 60","tag":"keeper"}' >/dev/null
i=0
while [ $i -lt 100 ]; do
    curl -s -o /dev/null -H "X-Sandbox-Token: $T" -X POST "$U/v1/sandboxes/$S/processes" -d '{"cmd":"true"}'
    i=$((i + 1))
done
sleep 2
curl -s -H "X-Sandbox-Token: $T" "$U/v1/sandboxes/$S/processes" >/tmp/plist
grep -q '"tag":"keeper"' /tmp/plist && pass "the running process is still listed" || fail "a running process was evicted"

say "teardown reports what it actually achieved"
out=$(curl -s -o /tmp/body -w '%{http_code}' -H "$A" -X DELETE "$U/v1/sandboxes/$S")
[ "$out" = 200 ] && pass "a clean delete answers 200" || fail "delete answered $out: $(cat /tmp/body)"
grep -q '"deleted":true' /tmp/body && pass "and says so" || fail "delete body: $(cat /tmp/body)"
# The detached survivor must be gone: the uid sweep catches what a group kill misses.
curl -s -H "$A" -X POST "$U/v1/sandboxes" -d '{"count":1}' >/tmp/created2
S2=$(sed 's/.*"id":"\([^"]*\)".*/\1/' /tmp/created2)
T2=$(sed 's/.*"token":"\([^"]*\)".*/\1/' /tmp/created2)
curl -s -m 20 -H "X-Sandbox-Token: $T2" -X POST "$U/v1/sandboxes/$S2/exec" \
    -d '{"cmd":"setsid sleep 300 >/dev/null 2>&1 & exit 0"}' >/dev/null
sleep 1
uid=$(sed 's/.*"uid":\([0-9]*\).*/\1/' /tmp/created2)
curl -s -o /dev/null -H "$A" -X DELETE "$U/v1/sandboxes/$S2"
sleep 1
if ps -eo uid= 2>/dev/null | tr -d ' ' | grep -qx "$uid"; then
    fail "a setsid descendant survived the sandbox delete"
else
    pass "the uid sweep caught a setsid descendant"
fi
stop

say "result"
if [ "$failures" -eq 0 ]; then
    echo "all checks passed"
else
    echo "$failures check(s) failed"
    exit 1
fi

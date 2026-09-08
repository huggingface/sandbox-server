#!/bin/sh
# Live regression for resource bounds and the two file-protocol bugs.
#
#   docker run --rm -v "$PWD:/src" -w /src sh scripts/resource-bounds-regression.sh
set -eu

BIN=${BIN:-target/x86_64-unknown-linux-musl/release/sbx-server}
PORT=${PORT:-49901}
TOKEN=t
U="http://127.0.0.1:$PORT"
A="X-Sandbox-Token: $TOKEN"
failures=0

export SBX_MIN_LANDLOCK_ABI=1

say()  { printf '\n=== %s\n' "$1"; }
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; failures=$((failures + 1)); }
stop() { kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true; }
rss()  { awk '/^VmRSS:/ {print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }

expect() { # $1 status, $2 desc, rest curl args
    want=$1; desc=$2; shift 2
    got=$(curl -s -o /tmp/body -w '%{http_code}' "$@" || echo 000)
    [ "$got" = "$want" ] && pass "$desc ($got)" || fail "$desc (wanted $want, got $got: $(head -c 160 /tmp/body))"
}

command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl >/dev/null; }
[ -f "$BIN" ] || cargo build --release --target x86_64-unknown-linux-musl

say "invalid numeric config refuses to start"
for bad in SBX_CAPACITY=abc SBX_PORT=notaport SBX_MAX_CONNECTIONS=-5 SBX_CAPACITY=0; do
    code=0
    # shellcheck disable=SC2086
    # `$bad` last, so a bad SBX_PORT is not overridden by the valid one.
    timeout 5 env SBX_TOKEN=$TOKEN SBX_PORT=$PORT $bad "$BIN" >/tmp/out 2>&1 || code=$?
    case $code in
        124) fail "started with $bad" ;;
        0)   fail "exited 0 with $bad" ;;
        *)   pass "refused $bad" ;;
    esac
done

SBX_PORT=$PORT SBX_TOKEN=$TOKEN SBX_HOST_MODE=1 SBX_CAPACITY=4 "$BIN" >/tmp/log 2>&1 &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
sleep 1

say "caller-supplied limits are clamped by the server"
# max_mem_mb near 2^54 used to wrap when multiplied by 1 MiB, producing either
# an effectively unlimited address space or a sandbox where nothing can start.
expect 400 "max_mem_mb = 2^54"   -H "$A" -X POST "$U/v1/sandboxes" -d '{"count":1,"max_mem_mb":18014398509481984}'
expect 400 "max_mem_mb = u64 max" -H "$A" -X POST "$U/v1/sandboxes" -d '{"count":1,"max_mem_mb":18446744073709551615}'
expect 400 "max_mem_mb = 0"      -H "$A" -X POST "$U/v1/sandboxes" -d '{"count":1,"max_mem_mb":0}'
expect 400 "max_procs = 0"       -H "$A" -X POST "$U/v1/sandboxes" -d '{"count":1,"max_procs":0}'
expect 400 "max_procs huge"      -H "$A" -X POST "$U/v1/sandboxes" -d '{"count":1,"max_procs":100000}'
expect 200 "a sane request"      -H "$A" -X POST "$U/v1/sandboxes" -d '{"count":1,"max_procs":32,"max_mem_mb":512}'
S=$(sed 's/.*"id":"\([^"]*\)".*/\1/' /tmp/body)
T=$(sed 's/.*"token":"\([^"]*\)".*/\1/' /tmp/body)
ST="X-Sandbox-Token: $T"

say "count is bounded by what the host can hold"
# capacity 4, one already created: at most 3 more, and the rest reported as
# rejected rather than attempted.
curl -s -H "$A" -X POST "$U/v1/sandboxes" -d '{"count":4000}' >/tmp/body
created=$(grep -o '"uid"' /tmp/body | wc -l)
echo "  asked for 4000 on a capacity-4 host: created $created"
[ "$created" -le 3 ] && pass "bounded by remaining capacity" || fail "created $created"
grep -q '"rejected"' /tmp/body && pass "the overflow is reported" || fail "no rejected count"
curl -s -o /dev/null -H "$A" -X DELETE "$U/v1/sandboxes"

say "an oversized env is refused"
# Via a file: 200 KB on the command line exceeds ARG_MAX.
{
    printf '{"count":1,"env":{"BIG":"'
    head -c 200000 /dev/zero | tr '\0' 'x'
    printf '"}}'
} > /tmp/bigenv.json
expect 400 "200 KB env" -H "$A" -X POST "$U/v1/sandboxes" --data-binary @/tmp/bigenv.json

curl -s -H "$A" -X POST "$U/v1/sandboxes" -d '{"count":1}' >/tmp/body
S=$(sed 's/.*"id":"\([^"]*\)".*/\1/' /tmp/body)
T=$(sed 's/.*"token":"\([^"]*\)".*/\1/' /tmp/body)
ST="X-Sandbox-Token: $T"

say "the per-process rlimits are actually applied"
out=$(curl -s -m 20 -H "$ST" -X POST "$U/v1/sandboxes/$S/exec" -d '{"cmd":["/bin/sh","-c","ulimit -n; ulimit -f; ulimit -t"]}')
echo "  ulimit -n / -f / -t: $(printf '%s' "$out" | grep -o '"data":"[^"]*"' | head -3 | tr '\n' ' ')"
case "$out" in
    *4096*) pass "RLIMIT_NOFILE is set" ;;
    *)      fail "no file-descriptor limit: $(printf '%s' "$out" | head -c 200)" ;;
esac

say "a ranged write no longer leaves a stale tail"
# Write 20 bytes, then overwrite with 4 bytes using the ranged path plus the
# final size. Without truncate_to the old 16 bytes stayed on the end.
curl -s -o /dev/null -H "$ST" -X PUT "$U/v1/sandboxes/$S/files/write?path=f.bin" --data-binary 'AAAAAAAAAAAAAAAAAAAA'
curl -s -o /dev/null -H "$ST" -X PUT "$U/v1/sandboxes/$S/files/write?path=f.bin&offset=0&truncate_to=4" --data-binary 'BBBB'
body=$(curl -s -H "$ST" "$U/v1/sandboxes/$S/files/read?path=f.bin")
[ "$body" = "BBBB" ] && pass "the file is exactly what was uploaded" || fail "stale tail: '$body'"

say "a directory listing is paginated"
curl -s -o /dev/null -m 60 -H "$ST" -X POST "$U/v1/sandboxes/$S/exec" \
    -d '{"cmd":["/bin/sh","-c","mkdir -p many && cd many && i=0; while [ $i -lt 300 ]; do : > f$i; i=$((i+1)); done"]}'
curl -s -H "$ST" "$U/v1/sandboxes/$S/files/list?path=many&limit=100" >/tmp/body
n=$(grep -o '"name"' /tmp/body | wc -l)
echo "  entries returned with limit=100: $n"
[ "$n" -le 100 ] && pass "the limit is honoured" || fail "returned $n entries"
grep -q '"truncated":true' /tmp/body && pass "truncation is reported" || fail "truncation not reported"
grep -q '"next":"' /tmp/body && pass "a cursor is returned" || fail "no cursor"
# And the cursor actually advances rather than repeating the first page.
next=$(sed 's/.*"next":"\([^"]*\)".*/\1/' /tmp/body)
curl -s -H "$ST" "$U/v1/sandboxes/$S/files/list?path=many&limit=100&after=$next" >/tmp/body2
first=$(grep -o '"name":"[^"]*"' /tmp/body2 | head -1)
case "$first" in
    *"$next"*) fail "the cursor repeated its own last entry" ;;
    *)         pass "the cursor advances" ;;
esac

say "a special file cannot pin a connection thread"
curl -s -o /dev/null -m 20 -H "$ST" -X POST "$U/v1/sandboxes/$S/exec" -d '{"cmd":["/bin/sh","-c","mkfifo pipe"]}'
code=$(curl -s -o /dev/null -m 8 -w '%{http_code}' -H "$ST" "$U/v1/sandboxes/$S/files/read?path=pipe" || echo TIMEOUT)
case "$code" in
    2*)       fail "a FIFO was streamed as a file" ;;
    TIMEOUT|000) fail "the request hung on a FIFO" ;;
    *)        pass "a FIFO is refused promptly ($code)" ;;
esac

say "a stalled reader does not grow the server's heap"
before=$(rss "$server")
# 64 MiB of output, and a client that reads none of it: the unbounded queue
# used to buffer the lot in the server's heap.
curl -s -o /dev/null --limit-rate 1k -m 12 -H "$ST" -X POST "$U/v1/sandboxes/$S/exec" \
    -d '{"cmd":["/bin/sh","-c","dd if=/dev/zero bs=1M count=64 2>/dev/null | tr \"\\0\" \"a\""]}' || true
peak=$(rss "$server")
sleep 2
after=$(rss "$server")
echo "  RSS kB: before $before, during/after stall $peak, settled $after"
[ "$peak" -lt $((before + 32768)) ] && pass "heap growth stayed bounded (<32 MB)" || fail "RSS grew from $before to $peak kB"

say "ordinary transfers still work"
head -c 5000000 /dev/urandom > /tmp/five.bin
curl -s -o /dev/null -m 60 -H "$ST" -X PUT "$U/v1/sandboxes/$S/files/write?path=five.bin" --data-binary @/tmp/five.bin
curl -s -m 60 -H "$ST" "$U/v1/sandboxes/$S/files/read?path=five.bin" -o /tmp/five.out
cmp -s /tmp/five.bin /tmp/five.out && pass "5 MB round-trip" || fail "5 MB round-trip mismatch"
out=$(curl -s -m 30 -H "$ST" -X POST "$U/v1/sandboxes/$S/exec" -d '{"cmd":"echo hi"}')
case "$out" in *'"data":"hi'*) pass "exec still streams" ;; *) fail "exec: $(printf '%s' "$out" | head -c 160)" ;; esac
stop

say "result"
if [ "$failures" -eq 0 ]; then
    echo "all checks passed"
else
    echo "$failures check(s) failed"
    exit 1
fi

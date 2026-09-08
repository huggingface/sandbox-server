#!/bin/sh
# Live regression for the HTTP front door: slow-request floods, the connection
# cap, ambiguous framing, and that legitimate long-lived traffic still works.
#
# Needs python3 for the raw-socket clients (curl cannot send a malformed head).
#
#   docker run --rm -v "$PWD:/src" -w /src sh scripts/http-hardening-regression.sh
set -eu

BIN=${BIN:-target/x86_64-unknown-linux-musl/release/sbx-server}
PORT=${PORT:-49601}
TOKEN=t
U="http://127.0.0.1:$PORT"
A="X-Sandbox-Token: $TOKEN"
failures=0

say()  { printf '\n=== %s\n' "$1"; }
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; failures=$((failures + 1)); }

command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl >/dev/null; }
[ -f "$BIN" ] || cargo build --release --target x86_64-unknown-linux-musl

threads() { # thread count of the server process
    awk '/^Threads:/ {print $2}' "/proc/$1/status" 2>/dev/null || echo 0
}

SBX_PORT=$PORT SBX_TOKEN=$TOKEN SBX_MAX_CONNECTIONS=32 "$BIN" >/tmp/log 2>&1 &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
sleep 1

say "a slow-request flood does not pin threads indefinitely"
base=$(threads "$server")
python3 - "$PORT" <<'PY' &
import socket, sys, time
# 20 connections that send a partial head and then trickle, the classic
# Slowloris: before the head deadline each of these held a thread for as long
# as the client cared to keep it. Kept under SBX_MAX_CONNECTIONS on purpose,
# so this measures thread growth; the cap itself is checked separately below.
socks = []
for _ in range(20):
    try:
        s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
        s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n")
        socks.append(s)
    except OSError:
        break
time.sleep(25)
PY
flood=$!
sleep 3
peak=$(threads "$server")
echo "  threads: baseline $base, during flood $peak"
[ "$peak" -le 32 ] && pass "thread count stayed within the connection cap" || fail "threads grew to $peak"
# Legitimate traffic must still get through while the flood is in progress.
code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' "$U/health" || echo 000)
[ "$code" = 200 ] && pass "the server still answers during the flood" || fail "server unresponsive during flood ($code)"
# Wait past the head deadline (10s) and confirm the threads came back on their own.
sleep 12
after=$(threads "$server")
echo "  threads after the deadline: $after"
if [ "$after" -le $((base + 5)) ]; then
    pass "stalled connections were dropped without the client cooperating"
else
    fail "threads stayed at $after (baseline $base) after the head deadline"
fi
kill $flood 2>/dev/null || true
wait $flood 2>/dev/null || true

say "the connection cap is enforced"
python3 - "$PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
held, refused = [], 0
for _ in range(80):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n")  # incomplete: holds a slot
        held.append(s)
    except OSError:
        refused += 1
# Past the cap the server answers 503 rather than queueing or dying.
overflow = 0
for _ in range(5):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
        if b"503" in s.recv(64):
            overflow += 1
        s.close()
    except OSError:
        pass
print("  held", len(held), "refused", refused, "503s", overflow)
sys.exit(0 if overflow > 0 else 1)
PY
[ $? -eq 0 ] && pass "connections past the cap get 503" || fail "no 503 past the connection cap"
sleep 12  # let the held connections time out

say "ambiguous framing is refused"
raw() { # send a raw head, print the status line
    # %b, not %s: the escapes in the request have to become real CRLFs, or the
    # server just waits for a head that never ends.
    printf '%b' "$1" | timeout 8 python3 -c '
import socket, sys
data = sys.stdin.buffer.read()
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
s.sendall(data)
try:
    print(s.recv(64).split(b"\r\n")[0].decode(errors="replace"))
except OSError:
    print("no response")
' "$PORT"
}
check_refused() { # $1 raw request, $2 label
    line=$(raw "$1")
    # A specific status, not just a closed connection: the client has to be able
    # to tell a rejected request from a crashed server.
    case "$line" in
        *" 400 "*|*" 408 "*|*" 411 "*|*" 505 "*) pass "$2 ($line)" ;;
        *) fail "$2 -> $line" ;;
    esac
}
check_refused 'GET /health HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n' "non-numeric Content-Length"
check_refused 'GET /health HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n' "conflicting Content-Length"
check_refused 'POST /health HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n' "both framing headers"
check_refused 'GET /health HTTP/2.0\r\nHost: x\r\n\r\n' "unsupported version"
check_refused 'GET  /health HTTP/1.1\r\nHost: x\r\n\r\n' "double space in the request line"
check_refused 'GET /health HTTP/1.1\r\nContent-Length : 5\r\n\r\n' "space before the colon"

# The smuggling primitive this closes: a bad Content-Length used to be read as
# zero, so the body that followed was parsed as a second request.
line=$(raw 'POST /v1/exec HTTP/1.1\r\nHost: x\r\nContent-Length: xyz\r\n\r\nGET /health HTTP/1.1\r\nHost: x\r\n\r\n')
case "$line" in
    *" 400 "*) pass "a body cannot be smuggled behind a bad Content-Length ($line)" ;;
    *) fail "smuggled request got $line" ;;
esac

say "legitimate traffic is unaffected"
code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' "$U/health")
[ "$code" = 200 ] && pass "/health" || fail "/health returned $code"
out=$(curl -s -m 20 -H "$A" -X POST "$U/v1/exec" -d '{"cmd":"echo hi"}')
case "$out" in *'"data":"hi'*) pass "exec streams output" ;; *) fail "exec: $(printf '%s' "$out" | head -c 160)" ;; esac
# A command that is silent for longer than the head/body deadlines must not be
# cut off: the deadlines apply to reading a request, not to a running command.
out=$(curl -s -m 90 -H "$A" -X POST "$U/v1/exec" -d '{"cmd":"sleep 45; echo late"}')
case "$out" in *'"data":"late'*) pass "a 45s silent command still completes" ;; *) fail "long command: $(printf '%s' "$out" | head -c 200)" ;; esac
# Keep-alive reuse across several requests on one connection.
codes=$(curl -s -o /dev/null -o /dev/null -o /dev/null -w '%{http_code} ' -m 10 "$U/health" "$U/health" "$U/health")
[ "$codes" = "200 200 200 " ] && pass "keep-alive reuse" || fail "keep-alive: $codes"
# A large body still round-trips through the streaming reader.
head -c 3000000 /dev/urandom > /tmp/big.bin
curl -s -o /dev/null -m 30 -H "$A" -X PUT "$U/v1/files/write?path=/tmp/big-out.bin" --data-binary @/tmp/big.bin
if cmp -s /tmp/big.bin /tmp/big-out.bin; then pass "3 MB upload round-trips"; else fail "large upload mismatch"; fi

say "result"
if [ "$failures" -eq 0 ]; then
    echo "all checks passed"
else
    echo "$failures check(s) failed"
    exit 1
fi

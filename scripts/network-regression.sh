#!/bin/sh
# Live regression for network policies (`SBX_NETWORK`, `network` on create).
#
# The property under test: a command run under a policy reaches exactly the
# destinations the policy allows -- nothing with "none" -- while the server,
# unix sockets and local listening keep working. Needs root and Landlock ABI 4.
#
#   docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 sh scripts/network-regression.sh
set -eu

BIN=${BIN:-target/x86_64-unknown-linux-musl/release/sbx-server}
PORT=${PORT:-49601}
TOKEN=t
U="http://127.0.0.1:$PORT"
failures=0

say()  { printf '\n=== %s\n' "$1"; }
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; failures=$((failures + 1)); }

command -v curl >/dev/null && command -v python3 >/dev/null ||
    { apt-get update -qq && apt-get install -y -qq curl python3 ca-certificates >/dev/null; }
[ -f "$BIN" ] || cargo build --release --target x86_64-unknown-linux-musl

# Probes live in a system dir, which pooled sandboxes can read under Landlock.
cat >/usr/local/bin/sbxprobe <<'EOF'
#!/usr/bin/env python3
import asyncio, errno, socket, sys, urllib.request
kind = sys.argv[1]
try:
    if kind == "tcp":
        socket.create_connection((sys.argv[2], int(sys.argv[3])), timeout=5).close()
    elif kind == "async":
        async def main():
            r, w = await asyncio.wait_for(asyncio.open_connection(sys.argv[2], int(sys.argv[3])), 5)
            w.write(b"GET / HTTP/1.0\r\n\r\n")
            assert (await r.read(12)).startswith(b"HTTP/1.0 200")
        asyncio.run(main())
    elif kind == "udp":
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("1.1.1.1", 53))
    elif kind == "raw":
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    elif kind == "ptrace":
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.ptrace(16, int(sys.argv[2]), 0, 0) != 0:  # PTRACE_ATTACH
            raise OSError(ctypes.get_errno(), "ptrace")
    elif kind == "unix":
        a, b = socket.socketpair(); a.send(b"x"); assert b.recv(1) == b"x"
    elif kind == "listen":
        s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen()
    elif kind == "http":
        urllib.request.urlopen(sys.argv[2], timeout=10).read(1)
    print("ok")
except OSError as e:
    print("err", errno.errorcode.get(e.errno, e))
except Exception as e:
    print("err", type(e).__name__, e)
EOF
chmod 755 /usr/local/bin/sbxprobe

# Two local services outside any sandbox: one to allow, one to keep out.
python3 -m http.server 18080 --bind 127.0.0.1 >/dev/null 2>&1 &
allowed_srv=$!
python3 -m http.server 18081 --bind 127.0.0.1 >/dev/null 2>&1 &
other_srv=$!
trap 'kill $allowed_srv $other_srv 2>/dev/null || true' EXIT
sleep 1

start() { # env assignments for the server...
    env SBX_PORT=$PORT SBX_TOKEN=$TOKEN "$@" "$BIN" >/tmp/net.log 2>&1 &
    server=$!
    sleep 1
}
stop() { kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true; }

# probe PATH_PREFIX TOKEN ARGS... -> the probe's one-line verdict
probe() {
    prefix=$1 tok=$2
    shift 2
    args=$(printf '"%s",' "$@")
    curl -s -m 60 -H "X-Sandbox-Token: $tok" -X POST "$U$prefix/exec" \
        -d "{\"cmd\":[\"/usr/local/bin/sbxprobe\",${args%,}]}" |
        sed -n 's/^{"data":"\([^"]*\)\\n","event":"stdout"}$/\1/p'
}

expect() { # description expected actual
    case $3 in
        $2) pass "$1" ;;
        *) fail "$1: got '$3'" ;;
    esac
}

say "dedicated, network=none"
start SBX_NETWORK=none
expect "tcp to a local service is refused" "err EACCES" "$(probe /v1 $TOKEN tcp 127.0.0.1 18080)"
expect "https to the internet is refused" "err*" "$(probe /v1 $TOKEN http https://huggingface.co)"
expect "udp is refused" "err EACCES" "$(probe /v1 $TOKEN udp)"
expect "raw sockets are refused, even to root" "err EACCES" "$(probe /v1 $TOKEN raw)"
expect "the server cannot be ptraced" "err EPERM" "$(probe /v1 $TOKEN ptrace "$server")"
expect "unix sockets work" "ok" "$(probe /v1 $TOKEN unix)"
expect "listening on tcp works (port proxy)" "ok" "$(probe /v1 $TOKEN listen)"
curl -s -H "X-Sandbox-Token: $TOKEN" "$U/health" | grep -q '"network":"none"' &&
    pass "/health reports the policy" || fail "/health has no network policy"
stop

say "dedicated, allowlist"
start SBX_NETWORK='{"allow":["127.0.0.1:18080","huggingface.co:443"]}'
expect "tcp to the allowed service works" "ok" "$(probe /v1 $TOKEN tcp 127.0.0.1 18080)"
expect "non-blocking connect + request work" "ok" "$(probe /v1 $TOKEN async 127.0.0.1 18080)"
expect "another port is refused" "err EACCES" "$(probe /v1 $TOKEN tcp 127.0.0.1 18081)"
expect "an allowed hostname resolves and connects" "ok" "$(probe /v1 $TOKEN http https://huggingface.co/api/models?limit=1)"
expect "any other host is refused" "err*" "$(probe /v1 $TOKEN http https://example.com)"
expect "udp stays refused" "err EACCES" "$(probe /v1 $TOKEN udp)"
grep -q 'huggingface.co' /etc/hosts && pass "hostname pinned in /etc/hosts" || fail "/etc/hosts not pinned"
stop

say "dedicated, a policy that cannot be applied stops the server"
start SBX_NETWORK=everything
sleep 1
kill -0 "$server" 2>/dev/null && { fail "server started with an invalid policy"; stop; } || pass "invalid policy refused at startup"

say "host mode, a policy per sandbox"
start SBX_HOST_MODE=1 SBX_MIN_LANDLOCK_ABI=4
create() {
    curl -s -H "X-Sandbox-Token: $TOKEN" -X POST "$U/v1/sandboxes" -d "$1"
}
open_box=$(create '{"count":1}')
none_box=$(create '{"count":1,"network":"none"}')
allow_box=$(create '{"count":1,"network":{"allow":["127.0.0.1:18080"]}}')
id() { echo "$1" | sed 's/.*"id":"\([^"]*\)".*/\1/'; }
tok() { echo "$1" | sed 's/.*"token":"\([^"]*\)".*/\1/'; }
echo "$none_box" | grep -q '"network":"none"' && pass "create echoes the policy" || fail "no policy echo: $none_box"
expect "unrestricted sandbox reaches the other service" "ok" \
    "$(probe /v1/sandboxes/$(id "$open_box") "$(tok "$open_box")" tcp 127.0.0.1 18081)"
expect "isolated sandbox is refused" "err EACCES" \
    "$(probe /v1/sandboxes/$(id "$none_box") "$(tok "$none_box")" tcp 127.0.0.1 18080)"
expect "allowlisted sandbox reaches its service" "ok" \
    "$(probe /v1/sandboxes/$(id "$allow_box") "$(tok "$allow_box")" tcp 127.0.0.1 18080)"
expect "allowlisted sandbox is refused elsewhere" "err EACCES" \
    "$(probe /v1/sandboxes/$(id "$allow_box") "$(tok "$allow_box")" tcp 127.0.0.1 18081)"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "X-Sandbox-Token: $TOKEN" -X POST "$U/v1/sandboxes" \
    -d '{"network":{"allow":["10.0.0.0/33"]}}')
expect "an invalid policy is a 400" "400" "$code"
stop

[ "$failures" -eq 0 ] && echo "\nall network checks passed" || { echo "\n$failures failure(s)"; exit 1; }

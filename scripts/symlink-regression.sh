#!/bin/sh
# Live regression for the privileged-filesystem confused deputies, run as root
# with two real sandboxes on one host. Reproduces the two escapes an audit
# confirmed in production and asserts they are refused, then checks the ordinary
# file and proxy paths still work.
#
#   docker run --rm -v "$PWD:/src" -w /src rust:1-bookworm sh scripts/symlink-regression.sh
set -eu

BIN=${BIN:-target/x86_64-unknown-linux-musl/release/sbx-server}
PORT=${PORT:-49111}
TOKEN=sbx-regression-token
BASE="http://127.0.0.1:$PORT"
AUTH="X-Sandbox-Token: $TOKEN"
failures=0

say()  { printf '\n=== %s\n' "$1"; }
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; failures=$((failures + 1)); }

# Assert an API call fails (any 4xx/5xx). $1 = description, rest = curl args.
refuses() {
    desc=$1
    shift
    code=$(curl -s -o /tmp/body -w '%{http_code}' "$@")
    case "$code" in
        2*) fail "$desc (got $code: $(cat /tmp/body))" ;;
        *)  pass "$desc (refused with $code)" ;;
    esac
}

# Assert an API call succeeds.
allows() {
    desc=$1
    shift
    code=$(curl -s -o /tmp/body -w '%{http_code}' "$@")
    case "$code" in
        2*) pass "$desc" ;;
        *)  fail "$desc (got $code: $(cat /tmp/body))" ;;
    esac
}

command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl >/dev/null; }
[ -f "$BIN" ] || {
    rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
    cargo build --release --target x86_64-unknown-linux-musl
}

say "booting sbx-server in host mode"
SBX_PORT=$PORT SBX_TOKEN=$TOKEN SBX_HOST_MODE=1 SBX_CAPACITY=4 "$BIN" &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
sleep 1

A=$(curl -s -H "$AUTH" -X POST "$BASE/v1/sandboxes" -d '{"count":1}' |
    sed 's/.*"id":"\([^"]*\)".*/\1/')
B=$(curl -s -H "$AUTH" -X POST "$BASE/v1/sandboxes" -d '{"count":1}' |
    sed 's/.*"id":"\([^"]*\)".*/\1/')
[ -n "$A" ] && [ -n "$B" ] || { echo "could not create two sandboxes"; exit 1; }
echo "  sandbox A=$A  B=$B"
HOME_A=/sbx/homes/$A
HOME_B=/sbx/homes/$B

# B has something worth stealing, created by B's own code so it is B's to lose.
curl -s -H "$AUTH" -X POST "$BASE/v1/sandboxes/$B/exec" \
    -d '{"cmd":"echo b-secret > $HOME/secret"}' >/dev/null

# B also exposes a service on its own proxy socket. Started up front so the
# positive control below is established before anything is tampered with.
# Uploaded through the file API rather than inlined: `echo` in dash would expand
# the \r\n in the response, and a multi-line JSON payload is not valid JSON.
cat >/tmp/service.py <<'SERVICE'
import os, socket
sock = socket.socket(socket.AF_UNIX)
sock.bind(os.path.join(os.environ["SBX_PROXY_DIR"], "9000.sock"))
sock.listen(4)
while True:
    conn, _ = sock.accept()
    conn.recv(65536)
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nB-SECRET")
    conn.close()
SERVICE
curl -s -H "$AUTH" -X PUT "$BASE/v1/sandboxes/$B/files/write?path=service.py" \
    --data-binary @/tmp/service.py >/dev/null
curl -s -H "$AUTH" -X POST "$BASE/v1/sandboxes/$B/processes" \
    -d '{"cmd":["python3","service.py"]}' >/dev/null

say "ordinary file operations still work"
allows "write"  -H "$AUTH" -X PUT  "$BASE/v1/sandboxes/$A/files/write?path=data/hello.txt" -d 'hello'
allows "read"   -H "$AUTH"          "$BASE/v1/sandboxes/$A/files/read?path=data/hello.txt"
[ "$(cat /tmp/body)" = "hello" ] && pass "read returned what was written" || fail "read content mismatch"
allows "list"   -H "$AUTH"          "$BASE/v1/sandboxes/$A/files/list?path=data"
allows "stat"   -H "$AUTH"          "$BASE/v1/sandboxes/$A/files/stat?path=data/hello.txt"
allows "mkdir"  -H "$AUTH" -X POST  "$BASE/v1/sandboxes/$A/files/mkdir?path=nested/deep"
allows "delete" -H "$AUTH" -X DELETE "$BASE/v1/sandboxes/$A/files/delete?path=data/hello.txt"
# Files written through the API must be usable by the sandbox's own (unprivileged) code.
curl -s -H "$AUTH" -X PUT "$BASE/v1/sandboxes/$A/files/write?path=owned.txt" -d 'x' >/dev/null
if curl -s -H "$AUTH" -X POST "$BASE/v1/sandboxes/$A/exec" \
    -d '{"cmd":"cat $HOME/owned.txt"}' | grep -q '"data":"x"'; then
    pass "API-written files are owned by the sandbox uid"
else
    fail "sandbox cannot read a file written through the API"
fi

say "A plants symlinks in its own home (as its own uid)"
plant="ln -s /etc/passwd \$HOME/host-file"
plant="$plant; ln -s $HOME_B \$HOME/sibling-home"
plant="$plant; ln -s $HOME_B/secret \$HOME/sibling-file"
plant="$plant; mkdir -p \$HOME/via; ln -s $HOME_B \$HOME/via/link"
curl -s -H "$AUTH" -X POST "$BASE/v1/sandboxes/$A/exec" -d "{\"cmd\":\"$plant\"}" >/dev/null
# If planting fails, every "refused" below would pass vacuously — so assert it worked.
for link in host-file sibling-home sibling-file via/link; do
    [ -L "$HOME_A/$link" ] || fail "could not plant symlink $link — the escapes below are vacuous"
done
[ -L "$HOME_A/host-file" ] && pass "symlinks planted by the sandbox's own code"

say "H-02a: the root file API must not follow them"
refuses "read a host file through a final symlink"   -H "$AUTH" "$BASE/v1/sandboxes/$A/files/read?path=host-file"
refuses "read a sibling's file"                      -H "$AUTH" "$BASE/v1/sandboxes/$A/files/read?path=sibling-file"
refuses "list a sibling's home"                      -H "$AUTH" "$BASE/v1/sandboxes/$A/files/list?path=sibling-home"
refuses "write through a final symlink"              -H "$AUTH" -X PUT "$BASE/v1/sandboxes/$A/files/write?path=sibling-file" -d 'pwned'
refuses "write through an intermediate symlink"      -H "$AUTH" -X PUT "$BASE/v1/sandboxes/$A/files/write?path=via/link/planted" -d 'pwned'
refuses "read via an intermediate symlink"           -H "$AUTH" "$BASE/v1/sandboxes/$A/files/read?path=via/link/secret"
refuses "mkdir through an intermediate symlink"      -H "$AUTH" -X POST "$BASE/v1/sandboxes/$A/files/mkdir?path=via/link/planted"

# Deleting the link must remove the link, never what it points at.
allows  "delete the symlink itself"                  -H "$AUTH" -X DELETE "$BASE/v1/sandboxes/$A/files/delete?path=sibling-home"
[ -f "$HOME_B/secret" ] && pass "B's file survived the delete" || fail "B's file was deleted"
[ "$(cat "$HOME_B/secret")" = "b-secret" ] && pass "B's file was not modified" || fail "B's file was modified"
[ -f /etc/passwd ] && pass "/etc/passwd untouched" || fail "/etc/passwd damaged"

# stat must describe the link, not its target.
curl -s -H "$AUTH" "$BASE/v1/sandboxes/$A/files/stat?path=sibling-file" >/tmp/body
grep -q '"type":"symlink"' /tmp/body && pass "stat reports the link" || fail "stat followed the link: $(cat /tmp/body)"

say "H-02b: the root port proxy must not follow a socket symlink"
# Positive control first: without it, the refusal below would pass even if the
# proxy were simply broken.
reached=no
i=0
while [ "$i" -lt 10 ]; do
    if curl -s -m 5 -H "$AUTH" "$BASE/v1/sandboxes/$B/proxy/9000/" | grep -q B-SECRET; then
        reached=yes
        break
    fi
    i=$((i + 1))
    sleep 1
done
if [ "$reached" = yes ]; then
    pass "B reaches its own service through the proxy"
else
    fail "B cannot reach its own service — the refusal below would prove nothing"
    echo "    processes: $(curl -s -H "$AUTH" "$BASE/v1/sandboxes/$B/processes")"
fi

# A points its own proxy socket name at B's socket.
curl -s -H "$AUTH" -X POST "$BASE/v1/sandboxes/$A/exec" \
    -d "{\"cmd\":\"ln -s $HOME_B/.sbx/proxy/9000.sock \$SBX_PROXY_DIR/9000.sock\"}" >/dev/null
[ -L "$HOME_A/.sbx/proxy/9000.sock" ] || fail "could not plant the socket symlink — the check below is vacuous"
out=$(curl -s -m 5 -H "$AUTH" "$BASE/v1/sandboxes/$A/proxy/9000/" || true)
case "$out" in
    *B-SECRET*) fail "A reached B's service through a socket symlink" ;;
    *)          pass "A's socket symlink was refused" ;;
esac

# A regular file, and a bogus port, must not be accepted either.
curl -s -H "$AUTH" -X POST "$BASE/v1/sandboxes/$A/exec" \
    -d '{"cmd":"rm -f $SBX_PROXY_DIR/9001.sock; echo x > $SBX_PROXY_DIR/9001.sock"}' >/dev/null
refuses "a regular file as a socket" -m 5 -H "$AUTH" "$BASE/v1/sandboxes/$A/proxy/9001/"
refuses "a non-numeric port"         -m 5 -H "$AUTH" "$BASE/v1/sandboxes/$A/proxy/..%2F..%2Fetc/"
refuses "port 0"                     -m 5 -H "$AUTH" "$BASE/v1/sandboxes/$A/proxy/0/"

say "result"
if [ "$failures" -eq 0 ]; then
    echo "all checks passed"
else
    echo "$failures check(s) failed"
    exit 1
fi

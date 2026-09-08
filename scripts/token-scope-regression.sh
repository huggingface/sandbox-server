#!/bin/sh
# Live regression for per-sandbox capability tokens.
#
# The property under test: a credential handed out for one pooled sandbox must
# not address a sibling, and must not manage the pool. The host token stays a
# management credential.
#
#   docker run --rm -v "$PWD:/src" -w /src sh scripts/token-scope-regression.sh
set -eu

BIN=${BIN:-target/x86_64-unknown-linux-musl/release/sbx-server}
PORT=${PORT:-49401}
HOST_TOKEN=host-management-token
U="http://127.0.0.1:$PORT"
failures=0

say()  { printf '\n=== %s\n' "$1"; }
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; failures=$((failures + 1)); }

# $1 expected status, $2 token, $3 description, rest: curl args
expect() {
    want=$1
    tok=$2
    desc=$3
    shift 3
    got=$(curl -s -o /tmp/body -w '%{http_code}' -H "X-Sandbox-Token: $tok" "$@" || echo 000)
    if [ "$got" = "$want" ]; then
        pass "$desc ($got)"
    else
        fail "$desc (wanted $want, got $got: $(head -c 160 /tmp/body))"
    fi
}

field() { sed "s/.*\"$2\":\"\([^\"]*\)\".*/\1/" "$1"; }

command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl >/dev/null; }
[ -f "$BIN" ] || cargo build --release --target x86_64-unknown-linux-musl

SBX_PORT=$PORT SBX_TOKEN=$HOST_TOKEN SBX_HOST_MODE=1 SBX_CAPACITY=8 "$BIN" &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
sleep 1

say "creating two sandboxes"
curl -s -H "X-Sandbox-Token: $HOST_TOKEN" -X POST "$U/v1/sandboxes" -d '{"count":2}' >/tmp/created
# Two {"id":...,"token":...} objects; split them so each can be read separately.
sed 's/},{/}\n{/g' /tmp/created | grep '"id"' >/tmp/objs
sed -n '1p' /tmp/objs >/tmp/a
sed -n '2p' /tmp/objs >/tmp/b
A_ID=$(field /tmp/a id); A_TOK=$(field /tmp/a token)
B_ID=$(field /tmp/b id); B_TOK=$(field /tmp/b token)
echo "  A=$A_ID  B=$B_ID"

[ -n "$A_TOK" ] && [ "$A_TOK" != "$A_ID" ] &&
    pass "create returns a per-sandbox token" ||
    fail "create returned no token (got: $(head -c 200 /tmp/created))"
[ "$A_TOK" != "$B_TOK" ] && pass "the two tokens differ" || fail "both sandboxes share a token"
[ "$A_TOK" != "$HOST_TOKEN" ] && pass "not the host token" || fail "the sandbox token IS the host token"
[ "${#A_TOK}" = 64 ] && pass "256 bits of token" || fail "unexpected token length ${#A_TOK}"

say "a sandbox's own token works on its own routes"
expect 200 "$A_TOK" "exec"        -X POST "$U/v1/sandboxes/$A_ID/exec" -d '{"cmd":"echo hi"}'
expect 200 "$A_TOK" "files write" -X PUT  "$U/v1/sandboxes/$A_ID/files/write?path=f" -d 'x'
expect 200 "$A_TOK" "files read"       "$U/v1/sandboxes/$A_ID/files/read?path=f"
expect 200 "$A_TOK" "processes"        "$U/v1/sandboxes/$A_ID/processes"

say "A's token must not address B"
expect 403 "$A_TOK" "exec in B"    -X POST   "$U/v1/sandboxes/$B_ID/exec" -d '{"cmd":"id"}'
expect 403 "$A_TOK" "read B"                 "$U/v1/sandboxes/$B_ID/files/read?path=f"
expect 403 "$A_TOK" "write into B" -X PUT    "$U/v1/sandboxes/$B_ID/files/write?path=pwned" -d 'x'
expect 403 "$A_TOK" "delete B"     -X DELETE "$U/v1/sandboxes/$B_ID"
expect 403 "$A_TOK" "proxy into B"           "$U/v1/sandboxes/$B_ID/proxy/9000/"
expect 403 "$A_TOK" "list B's processes"     "$U/v1/sandboxes/$B_ID/processes"

say "a sandbox token must not manage the pool"
expect 403 "$A_TOK" "create"          -X POST   "$U/v1/sandboxes" -d '{"count":1}'
expect 403 "$A_TOK" "list sandboxes"            "$U/v1/sandboxes"
expect 403 "$A_TOK" "delete all"      -X DELETE "$U/v1/sandboxes"
# Token recovery must be management-gated, or the scoping would be trivially bypassable.
expect 403 "$A_TOK" "recover B's token"         "$U/v1/sandboxes/$B_ID/token"
expect 403 "$A_TOK" "recover its own token"     "$U/v1/sandboxes/$A_ID/token"

say "the host token manages the pool and recovers tokens"
expect 200 "$HOST_TOKEN" "list sandboxes"    "$U/v1/sandboxes"
expect 200 "$HOST_TOKEN" "recover A's token" "$U/v1/sandboxes/$A_ID/token"
grep -q "$A_TOK" /tmp/body && pass "recovered token matches" || fail "recovered a different token"

say "an unknown token is refused"
expect 403 "not-a-real-token" "garbage token" -X POST "$U/v1/sandboxes/$A_ID/exec" -d '{"cmd":"id"}'
expect 403 "" "empty token"                   -X POST "$U/v1/sandboxes/$A_ID/exec" -d '{"cmd":"id"}'

say "the compat window (host token on scoped routes) is on by default"
expect 200 "$HOST_TOKEN" "host token on a scoped route" -X POST "$U/v1/sandboxes/$A_ID/exec" -d '{"cmd":"echo hi"}'
kill $server 2>/dev/null || true
wait $server 2>/dev/null || true

say "SBX_COMPAT_HOST_TOKEN=0 closes it"
SBX_PORT=$PORT SBX_TOKEN=$HOST_TOKEN SBX_HOST_MODE=1 SBX_COMPAT_HOST_TOKEN=0 "$BIN" &
server=$!
sleep 1
curl -s -H "X-Sandbox-Token: $HOST_TOKEN" -X POST "$U/v1/sandboxes" -d '{"count":1}' >/tmp/created
C_ID=$(sed 's/.*"id":"\([^"]*\)".*/\1/' /tmp/created)
C_TOK=$(sed 's/.*"token":"\([^"]*\)".*/\1/' /tmp/created)
expect 403 "$HOST_TOKEN" "host token refused on a scoped route" -X POST "$U/v1/sandboxes/$C_ID/exec" -d '{"cmd":"id"}'
expect 200 "$C_TOK"      "the scoped token still works"         -X POST "$U/v1/sandboxes/$C_ID/exec" -d '{"cmd":"echo hi"}'
expect 200 "$HOST_TOKEN" "management still works"                         "$U/v1/sandboxes"

say "result"
if [ "$failures" -eq 0 ]; then
    echo "all checks passed"
else
    echo "$failures check(s) failed"
    exit 1
fi

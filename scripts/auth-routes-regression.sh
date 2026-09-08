#!/bin/sh
# Live regression for the route-surface split and fail-closed authentication.
#
# Asserts the two things a pooled sandbox token must not buy: a root-privileged
# unscoped route, and a server that authorizes everything because it has no
# token. Plus the mirror case (host routes in dedicated mode) and that both
# modes still serve their own surface.
#
#   docker run --rm -v "$PWD:/src" -w /src sh scripts/auth-routes-regression.sh
set -eu

BIN=${BIN:-target/x86_64-unknown-linux-musl/release/sbx-server}
TOKEN=sbx-regression-token
failures=0

# Landlock ABI floor: these checks are about other properties, so accept whatever
# the test kernel offers rather than requiring the production floor (CI and dev
# kernels are often older). scripts/landlock-regression.sh covers the floor.
export SBX_MIN_LANDLOCK_ABI=1


say()  { printf '\n=== %s\n' "$1"; }
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; failures=$((failures + 1)); }

# $1 expected status, $2 description, rest: curl args
expect() {
    want=$1
    desc=$2
    shift 2
    got=$(curl -s -o /tmp/body -w '%{http_code}' "$@" || echo 000)
    if [ "$got" = "$want" ]; then
        pass "$desc ($got)"
    else
        fail "$desc (wanted $want, got $got: $(head -c 200 /tmp/body))"
    fi
}

boot() { # $1 port, $2.. env/flags
    port=$1
    shift
    SBX_PORT=$port "$@" "$BIN" &
    server=$!
    sleep 1
}
stop() { kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true; }

command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl >/dev/null; }
[ -f "$BIN" ] || cargo build --release --target x86_64-unknown-linux-musl

# ---------------------------------------------------------------- host mode
say "host mode: dedicated routes must not exist"
boot 49301 env SBX_TOKEN=$TOKEN SBX_HOST_MODE=1 SBX_CAPACITY=4
U=http://127.0.0.1:49301
A="X-Sandbox-Token: $TOKEN"

S=$(curl -s -H "$A" -X POST "$U/v1/sandboxes" -d '{"count":1}' | sed 's/.*"id":"\([^"]*\)".*/\1/')
[ -n "$S" ] || { echo "could not create a sandbox"; stop; exit 1; }

# The escalation this closes: with the host token, an unscoped /v1/exec ran as
# root, unconfined, in the host's environment.
expect 404 "POST /v1/exec"                 -H "$A" -X POST "$U/v1/exec" -d '{"cmd":"id"}'
grep -q 'uid=0' /tmp/body && fail "/v1/exec still executed as root" || pass "no root execution"
expect 404 "GET /v1/processes"              -H "$A" "$U/v1/processes"
expect 404 "POST /v1/processes"             -H "$A" -X POST "$U/v1/processes" -d '{"cmd":"id"}'
expect 404 "GET /v1/files/read"             -H "$A" "$U/v1/files/read?path=/etc/passwd"
grep -q 'root:x:0' /tmp/body && fail "/v1/files/read still read a host file" || pass "no host file read"
expect 404 "PUT /v1/files/write"            -H "$A" -X PUT "$U/v1/files/write?path=/tmp/pwned" -d 'x'
[ -f /tmp/pwned ] && fail "/v1/files/write still wrote to the host" || pass "no host file write"
expect 404 "DELETE /v1/files/delete"        -H "$A" -X DELETE "$U/v1/files/delete?path=/etc/hostname"
expect 404 "POST /v1/files/mkdir"           -H "$A" -X POST "$U/v1/files/mkdir?path=/tmp/pwned-dir"
expect 404 "ANY /v1/proxy/<port>"           -H "$A" "$U/v1/proxy/22/"

say "host mode: its own surface still works"
expect 200 "GET /v1/sandboxes"                    -H "$A" "$U/v1/sandboxes"
expect 200 "POST /v1/sandboxes/<id>/exec"         -H "$A" -X POST "$U/v1/sandboxes/$S/exec" -d '{"cmd":"id"}'
grep -q 'uid=20' /tmp/body && pass "scoped exec runs as the sandbox uid" || fail "scoped exec uid: $(head -c 120 /tmp/body)"
expect 200 "PUT /v1/sandboxes/<id>/files/write"   -H "$A" -X PUT "$U/v1/sandboxes/$S/files/write?path=f" -d 'x'
expect 200 "GET /v1/health without a token"       "$U/health"

say "host mode: a bad or missing token is refused"
expect 403 "no token"        -X POST "$U/v1/sandboxes" -d '{"count":1}'
expect 403 "wrong token"     -H "X-Sandbox-Token: wrong" -X POST "$U/v1/sandboxes" -d '{"count":1}'
expect 403 "empty token"     -H "X-Sandbox-Token;"       -X POST "$U/v1/sandboxes" -d '{"count":1}'
# An unauthenticated caller must not be able to tell which surface this server
# serves: both a real and a nonexistent route answer 403, not 404.
expect 403 "unauth on a dedicated route" -X POST "$U/v1/exec" -d '{"cmd":"id"}'
stop

# ----------------------------------------------------------- dedicated mode
say "dedicated mode: host routes must not exist"
boot 49302 env SBX_TOKEN=$TOKEN
U=http://127.0.0.1:49302
expect 404 "POST /v1/sandboxes"        -H "$A" -X POST "$U/v1/sandboxes" -d '{"count":1}'
expect 404 "GET /v1/sandboxes"         -H "$A" "$U/v1/sandboxes"
expect 404 "DELETE /v1/sandboxes"      -H "$A" -X DELETE "$U/v1/sandboxes"
expect 404 "DELETE /v1/sandboxes/<id>" -H "$A" -X DELETE "$U/v1/sandboxes/anything"

say "dedicated mode: its own surface still works"
expect 200 "POST /v1/exec"  -H "$A" -X POST "$U/v1/exec" -d '{"cmd":"echo hi"}'
expect 200 "GET /v1/processes" -H "$A" "$U/v1/processes"
expect 403 "no token"       -X POST "$U/v1/exec" -d '{"cmd":"id"}'
stop

# ------------------------------------------------------------- fail closed
say "a server with no token must refuse to start"
# `timeout` matters here: a server that fails open keeps running, and without it
# this check would hang instead of reporting.
try_boot() { # $1 label, rest: env assignments
    label=$1
    shift
    # shellcheck disable=SC2086
    # `&& code=0 || code=$?` rather than a bare call: under `set -e` a non-zero
    # exit here is the expected outcome, not a script error.
    code=0
    timeout 5 env "$@" SBX_PORT=49303 "$BIN" >/tmp/out 2>&1 || code=$?
    case $code in
        124) fail "started and kept serving without a usable SBX_TOKEN ($label)" ;;
        0)   fail "exited 0 without a usable SBX_TOKEN ($label)" ;;
        *)   grep -q 'SBX_TOKEN is required' /tmp/out &&
                 pass "refused to start ($label)" ||
                 fail "exited $code without explaining why ($label): $(head -c 200 /tmp/out)" ;;
    esac
}

try_boot "dedicated, no token"  SBX_IGNORED=1
try_boot "host, no token"       SBX_HOST_MODE=1
# An empty token must count as no token, not as a token equal to "".
try_boot "dedicated, empty token" SBX_TOKEN=
try_boot "host, empty token"      SBX_HOST_MODE=1 SBX_TOKEN=

say "the development escape hatch works, and cannot be set from the job env"
boot 49304 env SBX_ALLOW_NO_AUTH=1 SBX_TOKEN=$TOKEN
# The env var alone must not disable auth: the flag is argv-only, and a Job's
# user-supplied env can reach the env but never the argv.
expect 403 "SBX_ALLOW_NO_AUTH=1 in the env does not disable auth" -X POST "http://127.0.0.1:49304/v1/exec" -d '{"cmd":"id"}'
stop

SBX_PORT=49305 "$BIN" --allow-no-auth >/tmp/out 2>&1 &
server=$!
sleep 1
expect 200 "--allow-no-auth serves unauthenticated requests" -X POST "http://127.0.0.1:49305/v1/exec" -d '{"cmd":"echo hi"}'
grep -q 'auth: DISABLED' /tmp/out && pass "startup log says auth is disabled" || fail "startup log does not mention disabled auth"
stop

say "result"
if [ "$failures" -eq 0 ]; then
    echo "all checks passed"
else
    echo "$failures check(s) failed"
    exit 1
fi

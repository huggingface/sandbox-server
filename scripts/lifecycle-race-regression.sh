#!/bin/sh
# A request authorized before DELETE must not spawn under a recycled uid.
set -eu
BIN=${BIN:-target/x86_64-unknown-linux-musl/release/sbx-server}
PORT=${PORT:-49651}
log=$(mktemp)
SBX_PORT=$PORT SBX_TOKEN=test SBX_HOST_MODE=1 SBX_MIN_LANDLOCK_ABI=1 "$BIN" >"$log" 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true; rm -f "$log"' EXIT
PORT=$PORT python3 - <<'PY'
import http.client
import json
import os
import socket
import time

port = int(os.environ["PORT"])

def request(method, path, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, body=json.dumps(body) if body else None,
                 headers={"X-Sandbox-Token": "test"})
    response = conn.getresponse()
    data = response.read()
    conn.close()
    assert response.status == 200, (response.status, data)
    return json.loads(data)

for _ in range(100):
    try:
        request("GET", "/health")
        break
    except OSError:
        time.sleep(.1)
else:
    raise AssertionError("server did not start")

old = request("POST", "/v1/sandboxes", {"count": 1})["sandboxes"][0]
body = json.dumps({"cmd": ["/bin/sh", "-c", "echo LATE_SPAWN"], "cwd": "/usr"}).encode()
with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
    head = (f"POST /v1/sandboxes/{old['id']}/exec HTTP/1.1\r\n"
            f"Host: localhost\r\nX-Sandbox-Token: {old['token']}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    conn.sendall(head + body[:1])
    time.sleep(.3)  # handler has acquired the entry and is waiting for its body
    request("DELETE", f"/v1/sandboxes/{old['id']}")
    new = request("POST", "/v1/sandboxes", {"count": 1})["sandboxes"][0]
    assert old["uid"] == new["uid"], "regression must exercise uid reuse"
    conn.sendall(body[1:])
    response = http.client.HTTPResponse(conn)
    response.begin()
    payload = response.read()
    assert response.status == 400 and b"sandbox has been deleted" in payload, payload
proc = request("POST", f"/v1/sandboxes/{new['id']}/processes", {"cmd": "sleep 5 & exit 0"})
time.sleep(.3)  # leader is reaped, but its descendant still holds stdout open
result = request("DELETE", f"/v1/sandboxes/{new['id']}/processes/{proc['id']}")
assert result["killed"] is False, "signalled a reaped PID while its exit event was pending"
print("PASS: delayed output does not leave a reaped PID signalable")
request("DELETE", f"/v1/sandboxes/{new['id']}")
print("PASS: delayed exec refused after deletion and uid reuse")
PY

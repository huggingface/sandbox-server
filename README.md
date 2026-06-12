# sandbox-server

The in-sandbox agent powering `hf sandbox` / `huggingface_hub.Sandbox` — isolated cloud
machines built on [Hugging Face Jobs](https://huggingface.co/docs/huggingface_hub/guides/jobs).

A single static binary (~641KB, x86_64 musl, zero runtime dependencies) that runs in **any**
Docker image with `/bin/sh` — no Python, pip, or framework required. The `Sandbox` client
injects it at job startup and talks to it through the Jobs proxy
(`https://<job_id>--<port>.hf.jobs`).

## What it does

- **Command execution** with live output streaming (NDJSON over chunked HTTP/1.1, flushed
  per event — the HTTP layer is hand-rolled because mainstream minimal frameworks buffer
  chunked responses until completion).
- **Background processes**: registry with buffered logs (4 MiB ring per process), follow
  mode, wait, kill (process-group signals), stdin injection.
- **File API**: raw-body read/write (no base64), `offset`/`length` params for parallel
  ranged transfers, list/stat/delete/mkdir.
- **Keepalive pings** every 15s on all streams so proxies never kill idle connections.
- **Idle watchdog**: exits when no request arrives and no process runs for
  `SBX_IDLE_TIMEOUT` seconds — abandoned sandboxes stop billing.

## HTTP API

```
GET  /health                              → {"status","version","uptime_ms"}   (no auth)
POST /v1/exec        {cmd, env?, cwd?, timeout?, stdin?, background?, tag?}
                     foreground → NDJSON stream: start / stdout / stderr / ping / exit
                     background → {"pid", "tag"}
GET  /v1/procs                            → process list
GET  /v1/procs/{pid}/logs?follow=         → NDJSON replay (+live)
GET  /v1/procs/{pid}/wait                 → NDJSON pings until exit event
POST /v1/procs/{pid}/kill  {signal?}      → default SIGKILL, to the process group
POST /v1/procs/{pid}/stdin?eof=           → raw body to stdin
GET  /v1/files/read?path=&offset=&length= → raw bytes
PUT  /v1/files/write?path=&mode=&offset=  → raw body to file (parents created)
GET  /v1/files/list?path=  /stat?path=
DELETE /v1/files/delete?path=&recursive=
POST /v1/files/mkdir?path=
```

`cmd` is either a string (run via `/bin/sh -c`) or an argv array.

## Configuration (env vars)

| var | default | meaning |
|---|---|---|
| `SBX_PORT` | `8000` | listen port (the client uses 49983 to keep common dev ports free) |
| `SBX_TOKEN` | unset | if set, all endpoints except `/health` require the `X-Sandbox-Token` header (constant-time compare); removed from the env before any child process spawns |
| `SBX_IDLE_TIMEOUT` | unset | seconds of inactivity (no authed request, no running process) before clean exit |

## Security model

Two layers when running on HF Jobs:

1. The Jobs proxy requires an HF token with read access to the job's namespace.
2. `SBX_TOKEN` is delivered via encrypted job secrets; the client derives it as
   `HMAC-SHA256(user_hf_token, nonce)` with the nonce stored in job labels — so
   reconnection is stateless and the HF token itself never enters the sandbox.

## Build

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# → target/x86_64-unknown-linux-musl/release/sbx-server (static-pie, stripped)
```

The binary is distributed via a Hugging Face model repo and downloaded at job startup by a
`/bin/sh` bootstrap (wget → curl → python3 fallback chain).

## Status

Working prototype. See the `huggingface_hub` draft PR for the client, CLI, design notes and
benchmarks (cold start ~6s, exec ~110ms p50, 340+ MiB/s parallel file transfer).

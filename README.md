# sandbox-server

The in-sandbox agent powering `hf sandbox` / `huggingface_hub.Sandbox` — isolated cloud
machines built on [Hugging Face Jobs](https://huggingface.co/docs/huggingface_hub/guides/jobs).

A single static binary (~671KB, x86_64 musl, zero runtime dependencies) that runs in **any**
Docker image with `/bin/sh` — no Python, pip, or framework required. The `Sandbox` client
injects it at job startup and talks to it through the Jobs proxy
(`https://<job_id>--<port>.hf.jobs`).

## Two modes (one binary)

The same binary serves both:

- **Dedicated mode** — one job *is* one sandbox. Operations hit `/v1/exec`, `/v1/processes`,
  `/v1/files/*` directly. Full VM isolation; used for GPU / untrusted workloads.
- **Host mode** — one job hosts *many* lightweight sandboxes (`huggingface_hub.SandboxPool`).
  A sandbox is a dedicated uid + a private `0700` home + a per-sandbox **Landlock LSM**
  ruleset, created server-side in ~1ms. Operations are scoped under `/v1/sandboxes/{id}/*`
  and run as the sandbox uid, confined to its home. This packs dozens of isolated CPU
  sandboxes into one VM with sub-second per-sandbox cold start.

Host mode needs root + `CAP_SETUID/SETGID/KILL` (the Docker default on HF Jobs) and degrades
to uid-only isolation if Landlock is unavailable. See `src/landlock.rs` for the confinement
model (FS → own home + RO system dirs; no TCP bind; ABI-6 abstract-socket scoping).

## What it does

- **Command execution** with live output streaming (NDJSON over chunked HTTP/1.1, flushed
  per event — the HTTP layer is hand-rolled because mainstream minimal frameworks buffer
  chunked responses until completion).
- **Background processes**: start detached, list, and terminate (process-group kill) via a
  small `/v1/processes` registry with server-assigned opaque ids.
- **File API**: raw-body read/write (no base64), `offset`/`length` params for parallel
  ranged transfers, list/stat/delete/mkdir.
- **Keepalive pings** every 15s on all streams so proxies never kill idle connections.
- **Idle watchdog**: exits when no request arrives and no process runs for
  `SBX_IDLE_TIMEOUT` seconds — abandoned sandboxes stop billing.

## HTTP API

```
GET  /health                              → {"status","version","uptime_ms"}   (no auth)
POST /v1/exec        {cmd, shell?, env?, cwd?, timeout?, stdin?, background?, tag?}
                     foreground → NDJSON stream: start / stdout / stderr / ping / exit
                     background → {"pid", "tag"}
POST /v1/processes   {cmd, shell?, env?, cwd?, tag?}   → {"id", "pid", "cmd", "tag"}  (background)
GET  /v1/processes                        → [{"id","pid","cmd","tag","running","exit_code",...}]
DELETE /v1/processes/{id}                 → {"id","ok"}   (terminate + forget; idempotent)
GET  /v1/files/read?path=&offset=&length= → raw bytes
PUT  /v1/files/write?path=&mode=&offset=  → raw body to file (parents created)
GET  /v1/files/list?path=  /stat?path=
DELETE /v1/files/delete?path=&recursive=
POST /v1/files/mkdir?path=

# host mode (many sandboxes per job)
POST   /v1/sandboxes        {count?, env?, max_procs?, max_mem_mb?}  → {"sandboxes":[{id,uid,home}]}
GET    /v1/sandboxes                                                 → live sandbox list
DELETE /v1/sandboxes                                                 → delete all
DELETE /v1/sandboxes/{id}                                            → delete one (frees the uid)
# every dedicated route above also exists scoped to a sandbox, e.g.:
POST   /v1/sandboxes/{id}/exec        ...   GET /v1/sandboxes/{id}/processes
GET    /v1/sandboxes/{id}/files/read  ...   PUT /v1/sandboxes/{id}/files/write
```

`cmd` is either a string (run via `/bin/sh -c`) or an argv array. Pass `shell` (bool) to make
that choice explicit instead of inferring it from the type: `shell=true` requires a string,
`shell=false` requires an argv array. In host mode, file paths
are rooted at the sandbox's private home (a leading `/` is taken relative to it) and created
files are `chown`ed to the sandbox uid.

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

The binary is distributed via a Hugging Face bucket and downloaded at job startup by a
`/bin/sh` bootstrap (wget → curl → python3 fallback chain).

## Status

Working prototype. See the `huggingface_hub` draft PR for the client, CLI, design notes and
benchmarks (cold start ~6s, exec ~110ms p50, 340+ MiB/s parallel file transfer).

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

Host mode needs root + `CAP_SETUID/SETGID/KILL` (the Docker default on HF Jobs) and refuses to
start if Landlock cannot deliver the documented guarantees (see `SBX_MIN_LANDLOCK_ABI`); pass
`--allow-unconfined` to accept uid-only isolation instead. See `src/landlock.rs` for the
confinement model (FS → own home + RO system dirs and selected `/dev` nodes; no TCP bind;
ABI-6 abstract-socket scoping).

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
POST   /v1/sandboxes        {count?, env?, max_procs?, max_mem_mb?}  → {"sandboxes":[{id,token,uid,home}]}
GET    /v1/sandboxes                                                 → live sandbox list
DELETE /v1/sandboxes                                                 → delete all
DELETE /v1/sandboxes/{id}                                            → delete one (frees the uid)
GET    /v1/sandboxes/{id}/token                                      → recover its capability token
# every dedicated route above also exists scoped to a sandbox, e.g.:
POST   /v1/sandboxes/{id}/exec        ...   GET /v1/sandboxes/{id}/processes
GET    /v1/sandboxes/{id}/files/read  ...   PUT /v1/sandboxes/{id}/files/write
```

`cmd` is either a string (run via `/bin/sh -c`) or an argv array. Pass `shell` (bool) to make
that choice explicit instead of inferring it from the type: `shell=true` requires a string,
`shell=false` requires an argv array. In host mode, file paths
are rooted at the sandbox's private home (a leading `/` is taken relative to it) and created
files are `chown`ed to the sandbox uid. The privileged file API resolves every component
relative to an open home descriptor with `O_NOFOLLOW`, so it never follows a symlink out of
the home, and it assigns ownership through the resulting descriptor rather than by path.

## Configuration (env vars)

| var | default | meaning |
|---|---|---|
| `SBX_PORT` | `8000` | listen port (the client uses 49983 to keep common dev ports free) |
| `SBX_TOKEN` | **required** | all endpoints except `/health` require this value in the `X-Sandbox-Token` header (constant-time compare); removed from the env before any child process spawns. The server refuses to start without it, unless launched with `--allow-no-auth` (local development only — it is an argv flag, not an env var, so a Job's user-supplied env can never set it) |
| `SBX_IDLE_TIMEOUT` | unset | seconds of inactivity (no authed request, no running process) before clean exit |
| `SBX_COMPAT_HOST_TOKEN` | `1` | host mode: whether the host token is still accepted on per-sandbox routes, for clients that predate per-sandbox tokens. Set to `0` to require scoped tokens |
| `SBX_MAX_CONNECTIONS` | `512` | max concurrent connections; past it the server answers 503 without spawning a worker |
| `SBX_MIN_LANDLOCK_ABI` | `6` | host mode: minimum Landlock ABI to start with. 4 adds TCP-bind denial, 6 adds abstract-socket scoping — both are part of the documented model, so the default requires them. Lower it to accept a reduced set (`/health` reports what is in force) |

## Security model

The dedicated routes (`/v1/exec`, `/v1/files/*`, `/v1/processes`, `/v1/proxy`) act with the
server's own privileges — root, unconfined, in the host's environment — so they exist **only**
in dedicated mode, where the job *is* the sandbox. Host mode serves only `/v1/sandboxes*`,
whose handlers act as a sandbox's uid inside its Landlock domain. The two surfaces are
mutually exclusive; the wrong one for the current mode answers 404.

Two layers when running on HF Jobs:

1. The Jobs proxy requires an HF token with read access to the job's namespace.
2. `SBX_TOKEN` is delivered via encrypted job secrets; the client derives it as
   `HMAC-SHA256(user_hf_token, nonce)` with the nonce stored in job labels — so
   reconnection is stateless and the HF token itself never enters the sandbox.

In dedicated mode the job *is* the sandbox, so `SBX_TOKEN` is already scoped to it.

In host mode there are two kinds of credential:

- **`SBX_TOKEN` is the host management token.** It creates, lists and deletes sandboxes, and
  recovers their tokens. It is held by whoever runs the pool.
- **Each sandbox gets its own random 256-bit capability token**, returned by `POST
  /v1/sandboxes` and recoverable with `GET /v1/sandboxes/{id}/token`. It authorizes that
  sandbox's routes and nothing else — not a sibling, not the pool. This is the credential to
  hand to whoever operates a single sandbox, including into a browser or WebSocket client via
  the port proxy.

The host token is *also* accepted on per-sandbox routes while `SBX_COMPAT_HOST_TOKEN=1` (the
default), so clients that predate per-sandbox tokens keep working when this binary is
published under them — every job fetches the binary fresh, so a hard break would break every
old client at once. That is a management credential having authority over the sandboxes it
created, not a sandbox credential reaching a sibling. Set `SBX_COMPAT_HOST_TOKEN=0` to close
it once clients have upgraded.

### Known limitations

Host mode packs mutually-visible tenants behind one privileged control plane. The following
are known gaps rather than design intent, and are being worked through — treat host mode as a
boundary between workloads inside **one** trust boundary, and use dedicated mode (one job per
sandbox, a real VM) for mutually distrusting code.

- **Caller-supplied limits are unclamped**, and `max_mem_mb * 1024 * 1024` is not
  `checked_mul`. An invalid `SBX_CAPACITY` becomes `usize::MAX`.
- **A hijacked proxy connection is authenticated and routed only once**, then bytes are
  spliced until EOF. A second HTTP request written on that connection reaches the first
  backend without new routing, depending on the upstream proxy's behaviour.
- **`DELETE /v1/processes/{id}` answers 200 for an unknown id**, so addressing a process by
  OS pid (as the current client does) silently does nothing.
- **Uids are never recycled**, so a host that has created ~45k sandboxes over its lifetime can
  no longer create more, even when empty.
- **A `setsid` descendant outlives a per-process `kill`** (it leaves the signalled process
  group). Deleting the sandbox does terminate it — the uid sweep catches what a group kill
  misses.
- **`/health` is unauthenticated** and reports version, uptime and sandbox count. Sandbox ids
  fall back to a timestamp if `/dev/urandom` cannot be read.

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

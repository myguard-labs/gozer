# gozer

> One static Go service that speaks the three classic collaborative-filtering
> spam networks — **DCC**, **Razor** and **Pyzor** — **all in-process**, behind
> one authenticated HTTP endpoint.

No Perl, no Python, no per-message subprocess forks, no supervisor: gozer is the
whole backend in one ~6 MB distroless binary. `POST /check` hands it a raw
message; it queries all three networks concurrently, caches the verdict by body
hash (in-memory LRU or shared Redis), and answers JSON. Every backend is
best-effort — if one network is unreachable it simply doesn't score and the
service stays healthy.

```
  ┌─────────────────────┐    HTTP :8077 + token    ┌──────────────────────────────┐
  │ rspamd (your image) │  ──── POST /check ───►   │  gozer  (distroless, nonroot)│
  │ dcc_razor_pyzor.lua │                          │   ├─ gdcc   (DCC,   in-proc) │
  │                     │  ◄─── JSON verdict ───   │   ├─ gazor  (Razor, in-proc) │
  │                     │                          │   └─ gyzor  (Pyzor, in-proc) │
  └─────────────────────┘                          └──────────────────────────────┘
```

## The DRP family

Three pure-Go network clients, one orchestrator binary, one Docker deployment —
each wire-compatible with the original perl/python/C tool:

| Repo | Role |
|------|------|
| [gdcc](https://github.com/myguard-labs/gdcc) | DCC client — library + CLI |
| [gazor](https://github.com/myguard-labs/gazor) | Razor 2 client — library + CLI |
| [gyzor](https://github.com/myguard-labs/gyzor) | Pyzor client — library + CLI |
| [gozer](https://github.com/myguard-labs/gozer) | backend binary — links all three in-process behind one HTTP endpoint |
| [rspamd-dcc-razor-pyzor](https://github.com/myguard-labs/rspamd-dcc-razor-pyzor) | Docker deployment — gozer image + rspamd plugin + dovecot sieve |

gozer is the orchestrator: it links the three clients in-process (no `dccifd`
daemon for DCC) and adds the HTTP, cache, auth and metrics layer. Background:
[why we rewrote them in Go](https://github.com/myguard-labs/rspamd-dcc-razor-pyzor#the-go-rewrite-gazor-gyzor-gdcc-gozer).

### The name

Gozer is the shape-shifting god from *Ghostbusters* who shows up at the end and
makes everyone else do the work — it summons the Terror Dogs and the Marshmallow
Man and just orchestrates the carnage. That is this binary's job: **gozer**
commands the three minions — **g**dcc, **g**azor and **g**yzor — and stitches
their answers together. It is deliberately *not* a fourth `g*z*r` network client;
the three clients each speak one wire protocol, and gozer is the conductor that
runs all three at once behind the HTTP/cache/auth layer. (It also happens to
orchestrate **D**CC + **R**azor + **P**yzor, which the project calls *DRP*.)

## Usage

```
gozer [serve]               run the HTTP backend on GOZER_HOST:GOZER_PORT (default 0.0.0.0:8077)
gozer stats                 fetch and print the local /metrics exposition
gozer health                probe the local /health endpoint (container HEALTHCHECK)
gozer razor-register [...]  obtain a Razor identity and persist it (--user/--pass/--out)
gozer pyzor-register [...]  generate/save a Pyzor account credential (--user/--key/--home/--servers)
gozer dcc-register [...]    save a DCC client-id + password (--client-id/--passwd/--out)
gozer version               print the version
```

Build (deps are vendored, so the build is fully offline — no module proxy / git fetch):

```sh
go build -mod=vendor -trimpath -ldflags="-s -w" -o gozer ./cmd/gozer
```

Every `serve` option is settable by **environment variable OR CLI flag**
(precedence: flag > env > default). The request body is capped at **8 MiB**
(`413` over the limit). `/check`, `/report` and `/revoke` require the token;
`/health` and `/metrics` do not.

### Registering identities

Each `*-register` subcommand persists the credential to the exact place gozer
loads it from **and** prints it as bare `KEY=value` env lines so it can be
supplied via the environment instead:

```sh
gozer pyzor-register --user alice | grep '^GYZOR_' > pyzor.env
```

It prints `RAZOR_USER`/`RAZOR_PASS`, `GYZOR_USER`/`GYZOR_KEY`/`GYZOR_SALT`, or
`DCC_CLIENT_ID`/`DCC_CLIENT_PASSWD` respectively. These reuse the gyzor/gazor/gdcc
library register code, so the on-disk formats match the standalone CLIs exactly.
DCC has no client-side registration (the dccd operator issues the id+password), so
`dcc-register` only saves what you supply.

## Configuration

| Variable | Flag | Default | Purpose |
|----------|------|---------|---------|
| `GOZER_TOKEN` / `GOZER_TOKEN_FILE` | `--token` | — | Shared secret for POST auth. **Required** — without it every POST returns `503`. |
| `GOZER_HOST` / `GOZER_PORT` | `--host` / `--port` | `0.0.0.0` / `8077` | HTTP bind address. |
| `GOZER_MAX_CONCURRENT` | `--max-concurrent` | `8` | Max in-flight requests; over the limit → `503`. |
| `GOZER_BACKEND_TIMEOUT` | `--backend-timeout` | `6` (s) | Per-request budget for the backend fan-out. |
| `GOZER_CACHE_TTL` | `--cache-ttl` | `300` (s) | Verdict cache lifetime; `0` disables. |
| `GOZER_CACHE_SIZE` | `--cache-size` | `4096` | In-memory LRU entries. |
| `GOZER_REDIS_URL` | — | — | Shared cache across scanners, e.g. `redis://valkey:6379/5`. Else in-process LRU. |
| `GOZER_REDIS_PREFIX` | — | `drp:check:` | Redis key prefix. |
| `GOZER_VERBOSE` | `--verbose` | `0` | Per-request + startup config logging. |
| `GOZER_LOG_STDOUT` | `--log-stdout` | `0` | Info/access logs to stdout; errors/warnings always stay on stderr. |

### Identities — one per network

Anonymous works for every network and is the default. To use a **known or shared
identity**, supply it as below. Razor and DCC take credentials from the
environment; Pyzor reads a standard `accounts` file. (`gozer *-register` writes
the right file for you — see [Registering identities](#registering-identities).)

| Network | How to authenticate | Anonymous default |
|---------|---------------------|-------------------|
| **Razor** | `RAZOR_USER` + `RAZOR_PASS` (each also `_FILE`); else the `gozer-identity` file persisted in `RAZORHOME` (`/var/lib/razor`) by `gozer razor-register`. | yes |
| **DCC** | `DCC_CLIENT_ID` + `DCC_CLIENT_PASSWD` (`_FILE`); else `DCC_IDS` / `/var/dcc/ids`. | yes (id 1) |
| **Pyzor** | a pyzor **`accounts` file** at `$PYZOR_HOME/accounts` (`PYZOR_HOME` defaults to `/var/lib/pyzor`); see below. | yes (anonymous) |

**Pyzor authentication.** Pyzor has no credential env var — gyzor loads accounts
the reference-pyzor way, from `$PYZOR_HOME/accounts`. The file is one line per
server, `host : port : username : salt,key` (exactly the format `pyzor` itself
writes). In the distroless, read-only image just mount it read-only into the home
dir (a bind mount or a Docker secret is fine even with `read_only: true`):

```yaml
# docker-compose.yml
environment:
  PYZOR_HOME: /var/lib/pyzor          # default; shown for clarity
volumes:
  - ./pyzor-accounts:/var/lib/pyzor/accounts:ro
```

```
# ./pyzor-accounts   (host : port : username : salt,key)
public.pyzor.org : 24441 : you@example.com : 0123abcd,4567ef89…
```

Generate the `salt,key` with `gozer pyzor-register` (or the stock `pyzor` tool);
gyzor consumes it byte-for-byte. With no accounts file the Pyzor client is
anonymous to the public server, which is what most setups want.

### DNS-bypass server overrides

When the container's DNS is flaky, pin each network's servers explicitly
(comma-separated `host[:port]`, IPv4/IPv6/hostname):

| Variable | Flag | Forwarded to |
|----------|------|--------------|
| `DCC_SERVERS` | `--dcc-servers` | gdcc (DCC) |
| `GYZOR_SERVERS` | `--pyzor-servers` | gyzor (Pyzor) |
| `GAZOR_DISCOVERY` | `--razor-discovery` | gazor (Razor discovery) |
| `RAZOR_MIN_CF` | `--min-cf` | gazor minimum confidence (`ac`, `ac+N`, `ac-N`, or a number) |

## HTTP API

Body is always the raw RFC-822 message. POST endpoints need
`Authorization: Bearer <token>` or `X-DRP-Token: <token>` (`401` wrong, `503` if
gozer has no token).

- **`POST /check`** — query only, never reports. Used by the rspamd plugin.

  ```json
  { "dcc":   { "action": "reject", "bulk": 2147483647 },
    "razor": { "hit": true },
    "pyzor": { "count": 42, "wl": 0 } }
  ```

- **`POST /report`** — report the message as **spam** to all three networks → `{ "dcc": true, "razor": true, "pyzor": true }`.
- **`POST /revoke`** — report as **ham**. Razor and Pyzor support it; DCC has no network un-report, so its value is `null`.
- **`GET /health`** — `200 ok`, used by the container healthcheck.
- **`GET /metrics`** — Prometheus exposition (no auth): per-endpoint counters, cache hit/miss/coalesced, Redis health, `gozer_backend_error_total{backend="dcc|razor|pyzor"}`, and a `gozer_latency_seconds` histogram. `gozer stats` prints it locally (the image ships no curl).

A cache hit is flagged with `X-DRP-Cache: hit` in the response headers.

## Privacy & hardening

The message never touches disk: gozer holds it in memory and computes all three
checksums in-process. The cache stores only `sha256(body) → verdict`, never the
body (the same holds for the Redis backend). The only thing leaving the container
is what collaborative filtering needs — DCC checksums, Razor signatures, Pyzor
digests — never the raw mail. gozer runs non-root with bounded concurrency, every
POST is token-authenticated, and the image carries no shell, no curl and no
writable state; the healthcheck is `gozer health` (the binary probing itself).

## Build / test

```sh
go build -mod=vendor ./...
go test  -mod=vendor ./...     # HTTP layer + config + cache + dispatch + register
./fuzz.sh                      # local long fuzzing (10m/target); ./fuzz.sh 1h for longer
```

CI (`.github/workflows/ci.yml`): build, vet, gofmt, `go test -race`, a ~30s fuzz
smoke (`FuzzServe`, `FuzzParsePyzorServers`), plus staticcheck, gosec,
govulncheck and CodeQL. Deep fuzzing is local-only via `fuzz.sh`.

## See also

- The rest of the family is in the table above. The
  [rspamd-dcc-razor-pyzor](https://github.com/myguard-labs/rspamd-dcc-razor-pyzor)
  deployment builds the gozer image from this repo (gozer is its `docker/gozer`
  submodule).
- [The Go rewrite: gazor, gyzor, gdcc, gozer](https://github.com/myguard-labs/rspamd-dcc-razor-pyzor#the-go-rewrite-gazor-gyzor-gdcc-gozer) — why the perl/python/C clients were rewritten in Go
- Blog article: <https://deb.myguard.nl/2026/06/rspamd-dcc-razor-pyzor-docker-backend/>
- Docker Hub: <https://hub.docker.com/r/eilandert/rspamd-dcc-razor-pyzor>

## License

**MIT** — see [LICENSE](LICENSE). gozer is original work; the three vendored
clients keep their own licences (gdcc MIT, gazor and gyzor GPLv3).

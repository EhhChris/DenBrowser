# DenBrowser proxy stress / load tester

`denbrowser_stress.py` drives concurrent load against a single running
`denbrowser-proxy` instance to answer two questions:

1. **How many requests per second can one instance serve before it is
   overwhelmed?** — measured by ramping concurrency until latency blows up,
   connections start erroring/timing out, or throughput stops climbing.
2. **Is rate limiting kicking in?** — detected via HTTP `429` / `Retry-After`,
   or via otherwise-valid requests being refused while the transport stays
   healthy. (The proxy has no rate limiting *yet*; this is here so the day it
   is added, the script already flags it.)

It does **not** modify the proxy, and it never needs the proxy *private* key —
only the public key (`build/proxy-public.pem`), exactly like a real DenBrowser
build.

## Traffic it generates

Every request falls into one of three kinds, mirroring the checks in
`proxy/src/attest.rs`:

| Kind       | Category    | Trips this check (see `AttestError`)          | Expect |
|------------|-------------|-----------------------------------------------|:------:|
| **valid**  | `valid`     | none — correct encrypted headers, forwarded   | `200`  |
| **attack** | `replay`    | nonce replay cache (`NonceReplay`)            | `403`  |
| **attack** | `stale`     | timestamp drift window (`TimestampDrift`)     | `403`  |
| **attack** | `pivot`     | path bound in plaintext (`PlaintextMismatch`) | `403`  |
| **attack** | `method`    | method bound in plaintext (`PlaintextMismatch`)| `403` |
| **attack** | `tamper`    | body hash, phase 2 (`BodyHashMismatch`)       | `403`  |
| **attack** | `wrongkey`  | ECDH / AES-GCM auth (`DecryptFailed`)         | `403`  |
| **attack** | `badnonce`  | nonce length check (`InvalidNonce`)           | `403`  |
| **attack** | `garbage`   | token decode / EC point (`InvalidToken`)      | `403`  |
| **reject** | `noheaders` | missing attestation headers (non-DenBrowser)  | `403`  |

Each attack is *structurally valid DenBrowser traffic* that trips exactly one
gate, so a single-category run confirms that gate rejects under load. `reject`
is ordinary internet traffic with no attestation headers at all.

The token construction mirrors `DenBrowserAttest.cpp::AddAttestHeaders` and the
reference client in `test/attestation/test_roundtrip.py` (ECDH P-256 → ANSI
X9.63 KDF → AES-128-GCM).

## Prerequisites

```bash
pip install cryptography requests

# One-time key + cert material (writes to build/, gitignored):
scripts/gen-attest-key.sh
scripts/gen-proxy-tls.sh
scripts/gen-user-cert.sh      # only if testing with [mtls] enabled

# Start an upstream and the proxy (example — see test/target-server/):
docker compose -f test/target-server/compose.yml up -d
# The proxy requires a config file (defaults to ./proxy.toml). If you don't have
# one, start from proxy/proxy.example.toml (leave [mtls] disabled for plain
# load testing).  [attestation] private_key is REQUIRED and must point at
# build/proxy-private.pem (the example config already does).
# The proxy speaks TLS to its upstream, so target the target's TLS port (8443).
# The target reuses build/proxy-tls.* (self-signed), so pass --insecure-upstream.
(cd proxy && DENBROWSER_UPSTREAM=localhost:8443 cargo run --release -- --insecure-upstream)
```

If the proxy is run with `[mtls]` enabled (client_ca = `build/user-ca.crt`), the
stress client must present a user certificate. `scripts/gen-user-cert.sh` writes
`build/user-cert.{crt,key}`, which the tester picks up automatically (see
`--client-cert` below).

## Usage

Run from the repo root so the default `build/…` paths resolve.

```bash
# Realistic mixed traffic, fixed concurrency, 10s (default):
python3 proxy/stress/denbrowser_stress.py --insecure

# Find the saturation knee for a single instance:
python3 proxy/stress/denbrowser_stress.py --ramp --insecure

# Pure valid traffic, 200 workers, 30s (max legitimate throughput):
python3 proxy/stress/denbrowser_stress.py -m valid -c 200 -d 30 --insecure

# Confirm every rejection path fires under load:
python3 proxy/stress/denbrowser_stress.py -m attacks -d 10 --insecure

# Isolate a single check (e.g. the replay cache):
python3 proxy/stress/denbrowser_stress.py -m replay -c 100 -d 15 --insecure

# Non-DenBrowser traffic only (all rejected at the door):
python3 proxy/stress/denbrowser_stress.py -m reject -c 100 -d 10 --insecure
```

### Modes (`-m/--mode`)

- `mixed` *(default)* — weighted blend of all categories (60% valid + attacks +
  reject). Tune with the source's `DEFAULT_MIX`.
- `valid` — only correct traffic (expect all `200`).
- `attacks` — even blend of every attack category (expect all `403`).
- `reject` — only non-DenBrowser requests (expect all `403`).
- `replay`, `stale`, `pivot`, `method`, `tamper`, `wrongkey`, `badnonce`,
  `garbage` — one check in isolation.

### Load control

- `-c/--concurrency N` — worker threads (each keeps its own keep-alive TLS
  connection).
- `-d/--duration SECS` — run for a wall-clock duration (default `10` if neither
  `-d` nor `-n` is given).
- `-n/--requests N` — stop after N total requests (overrides `-d`).
- `--ramp` — step concurrency through `--ramp-steps`
  (default `10,25,50,100,200,400,800`), `--stage-duration` seconds each, and
  report the peak sustained throughput plus the saturation knee.

### Target / TLS

- `--url` (default `https://localhost:8081`), `--host` (default `localhost`),
  `--path` (default `/`).
- `--public-key` (default `build/proxy-public.pem`).
- `--cert PATH` to verify the proxy's TLS cert, or `--insecure` for the
  self-signed dev cert. If `build/proxy-tls.crt` exists it is used
  automatically.
- `--client-cert PATH` / `--client-key PATH` — client certificate for the
  proxy's `[mtls]` layer (default `build/user-cert.{crt,key}` from
  `scripts/gen-user-cert.sh`). Presented only when both files exist, so it is a
  no-op against a proxy without mTLS. Override with the `DENBROWSER_CLIENT_CERT`
  / `DENBROWSER_CLIENT_KEY` env vars.

### Detection thresholds

- `--max-error-rate` (default `0.02`) — connection-error fraction that counts as
  *overwhelmed*.
- `--max-p99-ms` (default `1000`) — p99 latency that counts as *overwhelmed*.
- `--valid-fail-rate` (default `0.05`) — fraction of *valid* requests refused
  while the transport is healthy that flags *rate limiting*.

### Extras

- `--calibrate` — measure how fast this client can mint valid tokens
  single-threaded (no network), so you can tell whether the client or the proxy
  is the bottleneck.
- `--seed N` — make the mixed-mode category draw reproducible.

## Reading the output

Each run prints:

- **throughput** — achieved requests/second.
- **latency ms** — p50 / p90 / p99 / max.
- **statuses** — HTTP status distribution plus any connection-level errors
  (`conn_refused`, `conn_reset`, `read_timeout`, …).
- **unexpected** — responses whose status ≠ the category's expected code. In a
  healthy run this is `0`: valid requests get `200`, everything else `403`. A
  nonzero count means either the proxy misbehaved or (for valid traffic) it
  started refusing — see the rate-limit line.
- **overwhelmed** — `YES` when error rate or p99 crosses the thresholds.
- **rate-limiting** — `DETECTED` when `429`/`Retry-After` appears, or when valid
  requests are refused while the transport is healthy.

In `--ramp` mode the per-stage table ends with a summary giving **peak
sustained throughput** and the **saturation knee** (the concurrency past which
the instance stops keeping up). That knee is your "requests served before a
single instance is overwhelmed" answer.

## Notes & caveats

- **This Python generator is usually the bottleneck, not the proxy.** In local
  measurement (4 vCPU Xeon @ 2.10 GHz, 16 GiB) the proxy stayed remarkably light
  while *the client* saturated:

  | Load (12s)              | req/s        | proxy CPU  | proxy RSS | box busy   |
  |-------------------------|--------------|------------|-----------|-----------|
  | idle                    | —            | ~0         | 14 MB     | —         |
  | `-m valid  -c 100` (1 client)  | ~304  | 0.15 core  | 26 MB     | ~2.1/4 cores |
  | `-m valid  -c 60` ×3 clients   | ~1000 agg | 0.36 core | 43 MB   | ~2.8/4 cores |
  | `-m reject -c 100` (1 client)  | ~41   | 0.05 core  | 29 MB     | ~3.7/4 cores |

  The proxy never exceeded **~0.4 of one core** or **~45 MB**, even while
  serving ~1000 valid req/s. The measured req/s figures are therefore a **floor
  on proxy capacity set by the load generator** (Python's GIL serialises token
  minting and connection setup), not the proxy's ceiling. To find the proxy's
  real limit, drive it with a multi-process or multi-host generator (or a
  non-Python tool); `--calibrate` reports the single-thread mint rate so you can
  see the client ceiling coming.
- **Rejections are far more expensive per request than accepts.** A `403` closes
  the connection, so the client can't keep-alive and every *next* rejected
  request re-handshakes (the proxy's RSA private-key op included). That's why
  reject throughput (~41 req/s here) sits an order of magnitude below valid
  keep-alive throughput and pegged the box at ~3.7/4 cores — almost all of it
  connection-churn cost, split between client and kernel. Security-relevant: a
  flood of invalid tokens is a cheap way to force constant TLS handshakes, which
  is exactly what future rate limiting (ideally rejecting *before* the
  handshake, or per-source connection caps) should blunt. Use `-m reject` /
  `-m attacks` to exercise this path and `-m valid` to exercise steady-state
  compute.
- **Replay priming.** `replay` mode first sends a few real valid requests so the
  proxy commits their nonces, then resends them (re-priming every ~20s to stay
  inside the timestamp window) so the rejection is genuinely `NonceReplay` and
  not `TimestampDrift`.
- **Memory is not the constraint for header traffic.** The proxy's footprint is
  dominated by fixed runtime, not per-request state. The nonce cache holds only
  a 16-byte key + timestamp per committed request and is swept on a 90s TTL, so
  even sustained thousands-per-second valid traffic adds single-digit MB. The
  one real memory vector is **request bodies**: `request_body_filter` buffers the
  whole body (up to `MAX_BODY_BYTES`, 10 MB) before forwarding, so worst-case
  memory ≈ concurrent-uploads × body size. This tool sends tiny bodies, so it
  does not exercise that path — test it deliberately with large `-m tamper`-style
  POSTs if body-buffer memory is a concern.
- **Attack templates refresh** every ~20s so their timestamps stay inside the
  drift window and keep tripping their *intended* check.

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

# Start an upstream and the proxy (example — see test/target-server/):
docker compose -f test/target-server/compose.yml up -d
(cd proxy && DENBROWSER_UPSTREAM=localhost:8080 cargo run --release)
```

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

- **Rejections are handshake-bound, and that matters.** When the proxy rejects a
  request (any `403`) it closes the connection, so the client cannot keep-alive
  and every *next* rejected request pays a full TLS handshake — including the
  proxy's RSA private-key operation. In local testing, valid (keep-alive)
  traffic sustained ~**330 req/s** while pure rejection traffic collapsed to
  ~**35–65 req/s** on the same instance. Two takeaways:
    - Use **`-m valid`** to measure the proxy's *request-processing* capacity
      (connections are reused).
    - Use **`-m reject` / `-m attacks`** to measure its *handshake* capacity.
      This is the more security-relevant number: a flood of invalid tokens is a
      cheap way to force constant TLS handshakes, which is exactly what future
      rate limiting should blunt.
- **Run the client off-box for a clean proxy number.** This generator and the
  proxy both burn CPU on TLS. On one machine they contend (running two client
  copies raised *aggregate* rejection throughput above one copy's), so for a
  true single-instance ceiling, drive the proxy from a separate host.
- **Client vs. proxy bottleneck.** Valid traffic costs a fresh ECDH + AES-GCM
  per request on the client. If measured throughput approaches the `--calibrate`
  number, you're measuring the *client*, not the proxy — add threads, run
  several copies of the script (or from several hosts), or lean on attack/reject
  modes whose templates are cached and cheap to send.
- **Replay priming.** `replay` mode first sends a few real valid requests so the
  proxy commits their nonces, then resends them (re-priming every ~20s to stay
  inside the timestamp window) so the rejection is genuinely `NonceReplay` and
  not `TimestampDrift`.
- **Nonce cache growth.** Sustained valid traffic fills the proxy's in-memory
  nonce cache (swept on a 90s TTL). Very high valid throughput is therefore also
  a memory-pressure test, which is realistic.
- **Attack templates refresh** every ~20s so their timestamps stay inside the
  drift window and keep tripping their *intended* check.

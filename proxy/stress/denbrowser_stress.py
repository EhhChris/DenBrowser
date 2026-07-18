#!/usr/bin/env python3
"""
DenBrowser attestation-proxy stress / load generator (v2 protocol).

This tool drives load against a single running instance of `denbrowser-proxy`
(see proxy/src/main.rs) to answer two questions:

  1. How many requests per second can one proxy instance serve before it is
     overwhelmed (latency blows up, connections start erroring/timing out, or
     throughput stops climbing as we add concurrency)?

  2. When rate limiting is eventually added to the proxy, is it kicking in?
     (Detected here via HTTP 429 / Retry-After, or via otherwise-valid
     requests being rejected while the connection itself stays healthy.)

It generates three *kinds* of traffic, mirroring exactly what the verifier in
proxy/src/attest.rs checks:

  • VALID   — a correctly-formed ECIES attestation token with the proper
              encrypted headers.  Expect HTTP 200 (forwarded upstream).

  • ATTACK  — structurally-valid DenBrowser traffic that trips one specific
              verifier check.  Each attack category targets a *different* check
              so you can confirm every gate rejects under load.  Expect 403.
              (`body_tamper` is the phase-2 body-hash gate; the rest are
              phase-1 header gates.)

  • REJECT  — ordinary non-DenBrowser traffic with no attestation headers at
              all.  Expect 403 (missing headers).

Modes let you run the full mix or any single category in isolation, at a fixed
concurrency for a fixed duration / request count, or as a ramp that increases
concurrency stage-by-stage to locate the saturation knee.

The proxy is NOT modified by this script, and this script never needs the
proxy *private* key — only the public key (build/proxy-public.pem), exactly
like a real DenBrowser build.

Requirements:
    pip install cryptography requests

Typical usage (from repo root, proxy + target already running):
    # Find the saturation point with a realistic mix:
    python3 proxy/stress/denbrowser_stress.py --ramp

    # Hammer only valid traffic at fixed concurrency for 30s:
    python3 proxy/stress/denbrowser_stress.py --mode valid -c 200 -d 30

    # Confirm every rejection path fires under load:
    python3 proxy/stress/denbrowser_stress.py --mode attacks -d 10

See proxy/stress/README.md for the full flag reference and interpretation.
"""

import argparse
import base64
import hashlib
import os
import random
import statistics
import sys
import threading
import time
import warnings
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.exceptions import InsecureRequestWarning
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDH,
        SECP256R1,
        generate_private_key,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
except ImportError as exc:  # pragma: no cover - dependency hint
    sys.stderr.write(
        f"missing dependency: {exc}\n"
        "install with:  pip install cryptography requests\n"
    )
    sys.exit(2)


# ── Protocol constants (must match proxy/src/attest.rs) ──────────────────────
PLAINTEXT_PREFIX = "denbrowser-attest:v2"
MAX_TS_DRIFT_SECS = 30           # attest.rs::MAX_TS_DRIFT_SECS
NONCE_LEN = 16                   # attest.rs::NONCE_LEN

# How long a cached attack template stays usable before we regenerate it so its
# timestamp stays inside the drift window and it keeps tripping its *intended*
# check (rather than degrading into a stale-timestamp rejection).  Comfortably
# below MAX_TS_DRIFT_SECS.
TEMPLATE_REFRESH_SECS = 20


# ── Categories ───────────────────────────────────────────────────────────────
# Every category maps to the single verifier check it is designed to exercise.
VALID = "valid"
ATTACK_CATEGORIES = {
    "replay":      "nonce replay cache        (AttestError::NonceReplay)",
    "stale":       "timestamp drift window    (AttestError::TimestampDrift)",
    "pivot":       "path bound in plaintext   (AttestError::PlaintextMismatch)",
    "method":      "method bound in plaintext (AttestError::PlaintextMismatch)",
    "tamper":      "body hash (phase 2)       (AttestError::BodyHashMismatch)",
    "wrongkey":    "ECDH/GCM auth             (AttestError::DecryptFailed)",
    "badnonce":    "nonce length check        (AttestError::InvalidNonce)",
    "garbage":     "token decode / EC point   (AttestError::InvalidToken)",
}
REJECT = "noheaders"  # ordinary non-DenBrowser traffic → missing-headers 403

# Expected HTTP status per category.
EXPECTED = {VALID: 200, REJECT: 403}
EXPECTED.update({c: 403 for c in ATTACK_CATEGORIES})

# Default weighting for the mixed mode (relative, need not sum to 100).
DEFAULT_MIX = {
    VALID:      60,
    "replay":    5,
    "stale":     5,
    "pivot":     5,
    "method":    5,
    "tamper":    5,
    "wrongkey":  5,
    "badnonce":  3,
    "garbage":   3,
    REJECT:      4,
}


# ── Request spec produced by a generator, consumed by a worker ───────────────
@dataclass
class RequestSpec:
    method: str
    path: str
    body: Optional[bytes]
    headers: dict
    expected: int
    category: str


@dataclass
class Config:
    url: str
    host: str
    path: str
    verify: object                 # requests `verify` arg: CA path, or False
    timeout: float
    pub_key: object


# ── Token / header construction (mirrors DenBrowserAttest.cpp AddAttestHeaders)
def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fresh_nonce_b64() -> str:
    return base64.b64encode(os.urandom(NONCE_LEN)).decode()


def _now_ts() -> str:
    return str(int(time.time()))


def make_headers(pub_key, *, nonce_b64, ts, host, method, path, body) -> dict:
    """Produce the three X-DenBrowser-* headers for a v2 token.

    `pub_key` is the EC public key the token is encrypted *to*.  Passing the
    real proxy public key yields a token the proxy can decrypt; passing an
    attacker-controlled key (see the `wrongkey` generator) yields a token whose
    ECDH shared secret is wrong, so AES-GCM authentication fails at the proxy.
    """
    body = body or b""
    plaintext = (
        f"{PLAINTEXT_PREFIX}\n"
        f"{nonce_b64}\n{ts}\n{host}\n{method}\n{path}\n{_sha256_hex(body)}"
    ).encode()

    ephem_priv = generate_private_key(SECP256R1())
    shared = ephem_priv.exchange(ECDH(), pub_key)
    aes_key = X963KDF(algorithm=hashes.SHA256(), length=16, sharedinfo=None).derive(shared)
    iv = os.urandom(12)
    ct_tag = AESGCM(aes_key).encrypt(iv, plaintext, None)
    ephem_pub_bytes = ephem_priv.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    token = base64.b64encode(ephem_pub_bytes + iv + ct_tag).decode()
    return {
        "X-DenBrowser-Ts":    ts,
        "X-DenBrowser-Nonce": nonce_b64,
        "X-DenBrowser-Token": token,
    }


# ── Per-category spec builders ───────────────────────────────────────────────
# Each returns a RequestSpec.  "Template" categories (everything except valid
# and replay) are cheap to reuse for TEMPLATE_REFRESH_SECS, so we cache them.

def _spec_valid(cfg: Config) -> RequestSpec:
    """A correct request: fresh nonce, current ts, matching fields → 200."""
    ts = _now_ts()
    nonce = _fresh_nonce_b64()
    headers = make_headers(cfg.pub_key, nonce_b64=nonce, ts=ts, host=cfg.host,
                           method="GET", path=cfg.path, body=b"")
    return RequestSpec("GET", cfg.path, None, headers, 200, VALID)


def _spec_stale(cfg: Config) -> RequestSpec:
    """Timestamp far outside the 30s drift window → TimestampDrift 403."""
    ts = str(int(time.time()) - (MAX_TS_DRIFT_SECS + 90))
    nonce = _fresh_nonce_b64()
    headers = make_headers(cfg.pub_key, nonce_b64=nonce, ts=ts, host=cfg.host,
                           method="GET", path=cfg.path, body=b"")
    return RequestSpec("GET", cfg.path, None, headers, 403, "stale")


def _spec_pivot(cfg: Config) -> RequestSpec:
    """Token minted for /legit but sent to /admin → PlaintextMismatch 403.

    This is the 'captured token replayed against a different path' attack.
    """
    ts = _now_ts()
    nonce = _fresh_nonce_b64()
    headers = make_headers(cfg.pub_key, nonce_b64=nonce, ts=ts, host=cfg.host,
                           method="GET", path="/legit", body=b"")
    return RequestSpec("GET", "/admin", None, headers, 403, "pivot")


def _spec_method(cfg: Config) -> RequestSpec:
    """Token minted for GET but request sent as DELETE → PlaintextMismatch."""
    ts = _now_ts()
    nonce = _fresh_nonce_b64()
    headers = make_headers(cfg.pub_key, nonce_b64=nonce, ts=ts, host=cfg.host,
                           method="GET", path=cfg.path, body=b"")
    return RequestSpec("DELETE", cfg.path, None, headers, 403, "method")


def _spec_tamper(cfg: Config) -> RequestSpec:
    """POST token bound to one body, shipped with a different body.

    Phase 1 passes; phase 2 body-hash check rejects → BodyHashMismatch 403.
    """
    ts = _now_ts()
    nonce = _fresh_nonce_b64()
    headers = make_headers(cfg.pub_key, nonce_b64=nonce, ts=ts, host=cfg.host,
                           method="POST", path="/echo", body=b"original-body")
    return RequestSpec("POST", "/echo", b"tampered-body", headers, 403, "tamper")


# A throwaway keypair standing in for an attacker who does NOT have the proxy
# private key.  ECDH against this instead of the real proxy public key yields a
# shared secret the proxy cannot reproduce, so GCM auth fails.
_WRONG_KEY = generate_private_key(SECP256R1()).public_key()


def _spec_wrongkey(cfg: Config) -> RequestSpec:
    """Well-formed token encrypted to the wrong key → DecryptFailed 403."""
    ts = _now_ts()
    nonce = _fresh_nonce_b64()
    headers = make_headers(_WRONG_KEY, nonce_b64=nonce, ts=ts, host=cfg.host,
                           method="GET", path=cfg.path, body=b"")
    return RequestSpec("GET", cfg.path, None, headers, 403, "wrongkey")


def _spec_badnonce(cfg: Config) -> RequestSpec:
    """Nonce of the wrong length (12 bytes, not 16) → InvalidNonce 403.

    The nonce is internally consistent with the plaintext, so the request only
    fails on the explicit length check the verifier does before decrypting.
    """
    bad_nonce = base64.b64encode(os.urandom(12)).decode()
    ts = _now_ts()
    headers = make_headers(cfg.pub_key, nonce_b64=bad_nonce, ts=ts, host=cfg.host,
                           method="GET", path=cfg.path, body=b"")
    return RequestSpec("GET", cfg.path, None, headers, 403, "badnonce")


def _spec_garbage(cfg: Config) -> RequestSpec:
    """Random bytes where the token should be → InvalidToken/decode 403."""
    ts = _now_ts()
    nonce = _fresh_nonce_b64()
    headers = {
        "X-DenBrowser-Ts":    ts,
        "X-DenBrowser-Nonce": nonce,
        "X-DenBrowser-Token": base64.b64encode(os.urandom(120)).decode(),
    }
    return RequestSpec("GET", cfg.path, None, headers, 403, "garbage")


def _spec_noheaders(cfg: Config) -> RequestSpec:
    """Ordinary non-DenBrowser request, no attestation headers → 403."""
    return RequestSpec("GET", cfg.path, None, {}, 403, REJECT)


# Builders that are safe to cache & reuse for TEMPLATE_REFRESH_SECS.
_TEMPLATE_BUILDERS = {
    "stale":    _spec_stale,
    "pivot":    _spec_pivot,
    "method":   _spec_method,
    "tamper":   _spec_tamper,
    "wrongkey": _spec_wrongkey,
    "badnonce": _spec_badnonce,
    "garbage":  _spec_garbage,
    REJECT:     _spec_noheaders,
}


# ── Replay generator ─────────────────────────────────────────────────────────
# A genuine replay must reuse a nonce the proxy has already *committed* to its
# cache (which only happens after a full valid request completes phase 2).  So
# we prime a small pool of valid requests, remember their headers, then resend
# them.  Priming is refreshed before the timestamp window would expire, so the
# rejection stays a NonceReplay rather than a TimestampDrift.
class ReplayGen:
    KEEP = 4

    def __init__(self, cfg: Config, session_factory):
        self.cfg = cfg
        self._session_factory = session_factory
        self._lock = threading.Lock()
        self._entries: deque = deque()   # (headers, monotonic_created)
        self._priming = False

    def _prime_one(self) -> Optional[dict]:
        """Send one valid GET so the proxy commits its nonce; return headers."""
        spec = _spec_valid(self.cfg)
        sess = self._session_factory()
        try:
            r = sess.request(
                spec.method, self.cfg.url + spec.path, data=spec.body,
                headers={**spec.headers, "Host": self.cfg.host},
                timeout=self.cfg.timeout, verify=self.cfg.verify,
            )
        except requests.RequestException:
            return None
        # 200 = committed and good to replay.  429 (future rate limiting) means
        # the nonce was NOT committed, so it is not a usable replay seed.
        return spec.headers if r.status_code == 200 else None

    def prepare(self) -> bool:
        """Prime the initial pool.  Returns False if the proxy won't accept
        any valid request (nothing to replay)."""
        for _ in range(self.KEEP):
            h = self._prime_one()
            if h:
                self._entries.append((h, time.monotonic()))
        return bool(self._entries)

    def next(self) -> RequestSpec:
        now = time.monotonic()
        headers = None
        need_refresh = False
        with self._lock:
            if self._entries:
                headers, created = self._entries[-1]
                if now - created > TEMPLATE_REFRESH_SECS and not self._priming:
                    self._priming = True
                    need_refresh = True
            elif not self._priming:
                self._priming = True
                need_refresh = True

        if need_refresh:
            try:
                fresh = self._prime_one()
            finally:
                with self._lock:
                    if fresh:
                        self._entries.append((fresh, time.monotonic()))
                        while len(self._entries) > self.KEEP:
                            self._entries.popleft()
                    if self._entries:
                        headers = self._entries[-1][0]
                    self._priming = False

        if headers is None:
            # Pool momentarily empty (another thread is priming); fall back to a
            # fresh valid request this once rather than block.
            return _spec_valid(self.cfg)
        return RequestSpec("GET", self.cfg.path, None, headers, 403, "replay")


# ── Generator: picks the next RequestSpec according to the selected mode ──────
class Generator:
    def __init__(self, cfg: Config, weights: dict, session_factory):
        self.cfg = cfg
        self._categories = list(weights.keys())
        self._weights = list(weights.values())
        self._template_lock = threading.Lock()
        self._template_cache: dict = {}   # category -> (RequestSpec, created)
        self._replay = ReplayGen(cfg, session_factory) if "replay" in weights else None

    def prepare(self) -> None:
        if self._replay is not None:
            if not self._replay.prepare():
                sys.stderr.write(
                    "WARNING: could not prime replay nonces (no valid request "
                    "accepted). Replay traffic will fall back to valid requests.\n"
                )

    def _template(self, category: str) -> RequestSpec:
        now = time.monotonic()
        with self._template_lock:
            cached = self._template_cache.get(category)
            if cached is None or now - cached[1] > TEMPLATE_REFRESH_SECS:
                spec = _TEMPLATE_BUILDERS[category](self.cfg)
                self._template_cache[category] = (spec, now)
                return spec
            return cached[0]

    def build(self, category: str) -> RequestSpec:
        if category == VALID:
            return _spec_valid(self.cfg)
        if category == "replay":
            return self._replay.next() if self._replay else _spec_valid(self.cfg)
        return self._template(category)

    def next(self) -> RequestSpec:
        category = random.choices(self._categories, weights=self._weights, k=1)[0]
        return self.build(category)


# ── Sampling / stats ─────────────────────────────────────────────────────────
@dataclass
class Sample:
    latency: float
    status: Optional[int]        # None => connection-level failure
    error: Optional[str]         # error kind when status is None
    category: str
    expected: int
    retry_after: Optional[str]


@dataclass
class Stats:
    samples: list = field(default_factory=list)
    wall: float = 0.0

    # Derived, filled by finalize()
    total: int = 0
    conn_errors: int = 0
    by_status: Counter = field(default_factory=Counter)
    by_error: Counter = field(default_factory=Counter)
    by_category: Counter = field(default_factory=Counter)
    unexpected: int = 0
    rate_limited_hits: int = 0     # 429 or Retry-After seen
    valid_sent: int = 0
    valid_ok: int = 0
    latencies_ms: list = field(default_factory=list)

    def finalize(self):
        self.total = len(self.samples)
        for s in self.samples:
            self.by_category[s.category] += 1
            self.latencies_ms.append(s.latency * 1000.0)
            if s.status is None:
                self.conn_errors += 1
                self.by_error[s.error or "unknown"] += 1
                continue
            self.by_status[s.status] += 1
            if s.status == 429 or s.retry_after:
                self.rate_limited_hits += 1
            if s.category == VALID:
                self.valid_sent += 1
                if s.status == 200:
                    self.valid_ok += 1
            if s.status != s.expected:
                self.unexpected += 1
        return self

    @property
    def rps(self):
        return self.total / self.wall if self.wall > 0 else 0.0

    @property
    def error_rate(self):
        return self.conn_errors / self.total if self.total else 0.0

    def pct(self, p):
        if not self.latencies_ms:
            return 0.0
        data = sorted(self.latencies_ms)
        k = max(0, min(len(data) - 1, int(round((p / 100.0) * (len(data) - 1)))))
        return data[k]


def _classify_error(exc: Exception) -> str:
    name = type(exc).__name__
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "connect_timeout"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "read_timeout"
    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout"
    if isinstance(exc, requests.exceptions.ConnectionError):
        text = str(exc).lower()
        if "refused" in text:
            return "conn_refused"
        if "reset" in text:
            return "conn_reset"
        return "conn_error"
    return name


# ── Worker / stage runner ────────────────────────────────────────────────────
def _make_session_factory(cfg: Config, pool_size: int):
    def factory():
        s = requests.Session()
        adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size,
                              max_retries=0)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        return s
    return factory


def run_stage(cfg: Config, gen: Generator, session_factory, *, concurrency: int,
              duration: Optional[float], max_requests: Optional[int]) -> Stats:
    """Drive `concurrency` worker threads until the deadline or request quota.

    Each worker keeps its own keep-alive Session so connection reuse is real and
    TLS handshakes don't dominate the measurement.
    """
    stop_at = time.monotonic() + duration if duration else None
    remaining = [max_requests] if max_requests is not None else None
    remaining_lock = threading.Lock()

    def take_slot() -> bool:
        if remaining is None:
            return stop_at is None or time.monotonic() < stop_at
        with remaining_lock:
            if remaining[0] <= 0:
                return False
            remaining[0] -= 1
            return True

    def worker() -> list:
        out = []
        sess = session_factory()
        while take_slot():
            spec = gen.next()
            headers = {**spec.headers, "Host": cfg.host}
            t0 = time.monotonic()
            try:
                r = sess.request(spec.method, cfg.url + spec.path, data=spec.body,
                                 headers=headers, timeout=cfg.timeout,
                                 verify=cfg.verify)
                dt = time.monotonic() - t0
                out.append(Sample(dt, r.status_code, None, spec.category,
                                  spec.expected, r.headers.get("Retry-After")))
            except requests.RequestException as exc:
                dt = time.monotonic() - t0
                out.append(Sample(dt, None, _classify_error(exc), spec.category,
                                  spec.expected, None))
        return out

    t_start = time.monotonic()
    samples = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(worker) for _ in range(concurrency)]
        for f in futures:
            samples.extend(f.result())
    wall = time.monotonic() - t_start

    st = Stats(samples=samples, wall=wall)
    return st.finalize()


# ── Reporting ────────────────────────────────────────────────────────────────
def _fmt_status_line(st: Stats) -> str:
    parts = []
    for code in sorted(st.by_status):
        parts.append(f"{code}:{st.by_status[code]}")
    if st.conn_errors:
        errs = ",".join(f"{k}:{v}" for k, v in sorted(st.by_error.items()))
        parts.append(f"conn_err:{st.conn_errors}({errs})")
    return "  ".join(parts) if parts else "(none)"


def assess(st: Stats, thresholds) -> dict:
    """Return {'overwhelmed': bool, 'rate_limited': bool, 'reasons': [...]}."""
    reasons = []
    p99 = st.pct(99)
    overwhelmed = False
    if st.error_rate > thresholds.max_error_rate:
        overwhelmed = True
        reasons.append(
            f"connection error rate {st.error_rate*100:.1f}% > "
            f"{thresholds.max_error_rate*100:.1f}%")
    if p99 > thresholds.max_p99_ms:
        overwhelmed = True
        reasons.append(f"p99 latency {p99:.0f}ms > {thresholds.max_p99_ms:.0f}ms")

    # Rate-limit detection.  Explicit signal: any 429 / Retry-After.  Implicit
    # signal: otherwise-valid requests being refused while the transport is
    # healthy (fast responses, few/no connection errors) — i.e. the proxy is
    # *choosing* to reject, not falling over.
    rate_limited = False
    rl_reasons = []
    if st.rate_limited_hits > 0:
        rate_limited = True
        rl_reasons.append(f"{st.rate_limited_hits} response(s) with 429/Retry-After")
    if st.valid_sent > 0:
        valid_fail = st.valid_sent - st.valid_ok
        valid_fail_rate = valid_fail / st.valid_sent
        if (valid_fail_rate > thresholds.valid_fail_rate
                and st.error_rate <= thresholds.max_error_rate):
            rate_limited = True
            rl_reasons.append(
                f"{valid_fail_rate*100:.1f}% of valid requests refused while "
                f"transport healthy (possible rejection-based limiting)")
    reasons.extend(rl_reasons)
    return {"overwhelmed": overwhelmed, "rate_limited": rate_limited,
            "reasons": reasons, "p99": p99}


def print_stage_report(st: Stats, verdict: dict, *, header: str):
    print(f"\n── {header} ──")
    print(f"  requests   : {st.total}   in {st.wall:.2f}s")
    print(f"  throughput : {st.rps:,.0f} req/s")
    lat = st.latencies_ms
    if lat:
        print(f"  latency ms : p50={st.pct(50):.1f}  p90={st.pct(90):.1f}  "
              f"p99={st.pct(99):.1f}  max={max(lat):.1f}")
    print(f"  statuses   : {_fmt_status_line(st)}")
    print(f"  unexpected : {st.unexpected}  "
          f"(responses whose status != category's expected code)")
    if st.valid_sent:
        print(f"  valid ok   : {st.valid_ok}/{st.valid_sent} "
              f"({100.0*st.valid_ok/st.valid_sent:.1f}%)")
    rl = "DETECTED" if verdict["rate_limited"] else "none"
    ov = "YES" if verdict["overwhelmed"] else "no"
    print(f"  overwhelmed: {ov}    rate-limiting: {rl}")
    for reason in verdict["reasons"]:
        print(f"     • {reason}")


def print_category_expectations(mode: str, weights: dict):
    print("Traffic categories in this run:")
    for cat in weights:
        if cat == VALID:
            desc = "correct encrypted headers → expect 200"
        elif cat == REJECT:
            desc = "no attestation headers (non-DenBrowser) → expect 403"
        else:
            desc = f"{ATTACK_CATEGORIES[cat]} → expect 403"
        share = ""
        if mode == "mixed":
            total = sum(weights.values())
            share = f"  [{100.0*weights[cat]/total:.0f}%]"
        print(f"  • {cat:<9} {desc}{share}")


# ── Calibration: how fast can THIS client mint requests (no network)? ────────
def calibrate(cfg: Config, gen: Generator, seconds: float = 2.0):
    print(f"\nCalibrating client-side request generation ({seconds:.0f}s, no network)…")
    # Pre-prime replay so we don't measure network priming here.
    end = time.monotonic() + seconds
    n = 0
    while time.monotonic() < end:
        gen.build(VALID)   # valid tokens are the expensive path (fresh ECDH+GCM)
        n += 1
    rate = n / seconds
    print(f"  client can mint ~{rate:,.0f} valid tokens/s single-threaded.")
    print("  If measured throughput approaches this, the CLIENT (not the proxy) "
          "is the bottleneck —")
    print("  add threads, run multiple copies of this script, or use --mode "
          "with cached-template attack traffic.")


# ── Modes → weights ──────────────────────────────────────────────────────────
def weights_for_mode(mode: str, custom_mix: Optional[dict]) -> dict:
    if mode == "mixed":
        return dict(custom_mix or DEFAULT_MIX)
    if mode == "attacks":
        return {c: 1 for c in ATTACK_CATEGORIES}
    if mode == "valid":
        return {VALID: 1}
    if mode == "reject":
        return {REJECT: 1}
    if mode in ATTACK_CATEGORIES:
        return {mode: 1}
    if mode == REJECT:  # "noheaders"
        return {REJECT: 1}
    raise ValueError(f"unknown mode: {mode}")


ALL_MODES = ["mixed", "valid", "attacks", "reject"] + list(ATTACK_CATEGORIES)


# ── CLI ──────────────────────────────────────────────────────────────────────
def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Stress / load generator for the DenBrowser attestation proxy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--url", default=os.environ.get("DENBROWSER_PROXY_URL",
                   "https://localhost:8081"),
                   help="proxy base URL (default: %(default)s)")
    p.add_argument("--host", default=os.environ.get("DENBROWSER_HOST", "localhost"),
                   help="Host header the token is bound to (default: %(default)s)")
    p.add_argument("--path", default="/",
                   help="request path for valid/replay traffic (default: %(default)s)")
    p.add_argument("--public-key", default=os.environ.get("PUBLIC_KEY_PATH",
                   "build/proxy-public.pem"),
                   help="proxy EC public key PEM (default: %(default)s)")
    p.add_argument("--cert", default=os.environ.get("DENBROWSER_TLS_CERT",
                   "build/proxy-tls.crt"),
                   help="CA/cert bundle to verify the proxy TLS cert")
    p.add_argument("--insecure", action="store_true",
                   help="skip TLS verification (dev self-signed proxy)")

    p.add_argument("-m", "--mode", default="mixed", choices=ALL_MODES,
                   help="traffic mode (default: mixed). Single-category modes "
                        "let you isolate one check.")
    p.add_argument("-c", "--concurrency", type=int, default=50,
                   help="concurrent workers (default: %(default)s)")
    p.add_argument("-d", "--duration", type=float, default=None,
                   help="run for this many seconds (default: 10 if --requests "
                        "unset)")
    p.add_argument("-n", "--requests", type=int, default=None,
                   help="stop after this many total requests (overrides --duration)")

    p.add_argument("--ramp", action="store_true",
                   help="ramp concurrency through --ramp-steps to find the "
                        "saturation knee")
    p.add_argument("--ramp-steps", default="10,25,50,100,200,400,800",
                   help="comma-separated concurrency levels for --ramp "
                        "(default: %(default)s)")
    p.add_argument("--stage-duration", type=float, default=8.0,
                   help="seconds per ramp stage (default: %(default)s)")

    p.add_argument("--timeout", type=float, default=10.0,
                   help="per-request timeout seconds (default: %(default)s)")
    p.add_argument("--max-error-rate", type=float, default=0.02,
                   help="connection-error rate that means 'overwhelmed' "
                        "(default: %(default)s)")
    p.add_argument("--max-p99-ms", type=float, default=1000.0,
                   help="p99 latency ms that means 'overwhelmed' "
                        "(default: %(default)s)")
    p.add_argument("--valid-fail-rate", type=float, default=0.05,
                   help="fraction of valid requests refused (transport healthy) "
                        "that flags rate limiting (default: %(default)s)")
    p.add_argument("--calibrate", action="store_true",
                   help="measure client-side token-gen rate before running")
    p.add_argument("--seed", type=int, default=None,
                   help="seed the category RNG for reproducible mixes")
    return p.parse_args(argv)


@dataclass
class Thresholds:
    max_error_rate: float
    max_p99_ms: float
    valid_fail_rate: float


def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def resolve_verify(args):
    if args.insecure:
        warnings.simplefilter("ignore", InsecureRequestWarning)
        return False
    if args.cert and os.path.exists(args.cert):
        return args.cert
    warnings.simplefilter("ignore", InsecureRequestWarning)
    sys.stderr.write(
        f"NOTE: TLS cert {args.cert!r} not found; disabling TLS verification. "
        "Pass --cert or --insecure to silence this.\n")
    return False


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.seed is not None:
        random.seed(args.seed)

    if not os.path.exists(args.public_key):
        sys.stderr.write(
            f"ERROR: public key not found at {args.public_key}\n"
            "Run scripts/gen-attest-key.sh first, or pass --public-key.\n")
        return 2
    pub_key = load_public_key(args.public_key)

    cfg = Config(
        url=args.url.rstrip("/"),
        host=args.host,
        path=args.path,
        verify=resolve_verify(args),
        timeout=args.timeout,
        pub_key=pub_key,
    )
    thresholds = Thresholds(args.max_error_rate, args.max_p99_ms, args.valid_fail_rate)
    weights = weights_for_mode(args.mode, None)

    print(f"DenBrowser proxy stress test")
    print(f"  target     : {cfg.url}   (Host: {cfg.host})")
    print(f"  public key : {args.public_key}")
    print(f"  TLS verify : {cfg.verify!r}")
    print(f"  mode       : {args.mode}")
    print()
    print_category_expectations(args.mode, weights)

    ramp_steps = [max(1, int(s)) for s in args.ramp_steps.split(",") if s.strip()]
    pool_size = max(ramp_steps) if args.ramp else args.concurrency
    session_factory = _make_session_factory(cfg, pool_size)
    gen = Generator(cfg, weights, session_factory)
    gen.prepare()

    if args.calibrate:
        calibrate(cfg, gen)

    if args.ramp:
        return run_ramp(cfg, gen, session_factory, ramp_steps, args, thresholds)

    duration = args.duration
    if duration is None and args.requests is None:
        duration = 10.0
    print(f"\nRunning {args.mode} at concurrency={args.concurrency} "
          f"{'for %.0fs' % duration if duration else 'for %d requests' % args.requests}…")
    st = run_stage(cfg, gen, session_factory, concurrency=args.concurrency,
                   duration=duration, max_requests=args.requests)
    verdict = assess(st, thresholds)
    print_stage_report(st, verdict, header=f"Result (c={args.concurrency})")
    return 0


def run_ramp(cfg, gen, session_factory, ramp_steps, args, thresholds) -> int:
    print(f"\nRamp: concurrency levels {ramp_steps}, {args.stage_duration:.0f}s each\n")
    print(f"  {'conc':>5}  {'req/s':>10}  {'p99 ms':>8}  {'err%':>6}  "
          f"{'valid ok%':>9}  verdict")
    print("  " + "-" * 62)

    best_rps = 0.0
    knee = None
    rate_limit_seen = False
    for conc in ramp_steps:
        st = run_stage(cfg, gen, session_factory, concurrency=conc,
                       duration=args.stage_duration, max_requests=None)
        verdict = assess(st, thresholds)
        rate_limit_seen = rate_limit_seen or verdict["rate_limited"]
        valid_ok_pct = (100.0 * st.valid_ok / st.valid_sent) if st.valid_sent else float("nan")
        tag = []
        if verdict["overwhelmed"]:
            tag.append("OVERWHELMED")
        if verdict["rate_limited"]:
            tag.append("RATE-LIMIT?")
        verdict_str = ",".join(tag) if tag else "ok"
        valid_col = f"{valid_ok_pct:8.1f}" if st.valid_sent else "     n/a"
        print(f"  {conc:>5}  {st.rps:>10,.0f}  {verdict['p99']:>8.0f}  "
              f"{st.error_rate*100:>5.1f}  {valid_col}  {verdict_str}")

        # Track saturation.  The knee is the last level before throughput stops
        # climbing meaningfully or the proxy starts erroring/blowing latency.
        if verdict["overwhelmed"]:
            if knee is None:
                knee = ("overwhelmed", conc, best_rps)
            # Stop early once badly overwhelmed to avoid pointless hammering.
            if st.error_rate > 0.5:
                print("  (stopping ramp: error rate > 50%)")
                break
        elif st.rps > best_rps:
            gain = (st.rps - best_rps) / best_rps if best_rps else 1.0
            best_rps = st.rps
            if gain < 0.10 and knee is None:
                knee = ("saturated", conc, best_rps)
        # else: rps did not improve -> saturated
        elif knee is None:
            knee = ("saturated", conc, best_rps)

    print("\n── Ramp summary ──")
    print(f"  peak sustained throughput : {best_rps:,.0f} req/s")
    if knee:
        why, conc, rps = knee
        print(f"  saturation knee           : ~concurrency {conc} ({why})")
        print(f"  → one instance serves roughly {best_rps:,.0f} req/s before "
              f"it stops keeping up.")
    else:
        print("  no saturation detected within the tested concurrency range — "
              "raise --ramp-steps to push harder.")
    print(f"  rate limiting observed    : "
          f"{'YES (see stages above)' if rate_limit_seen else 'no'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

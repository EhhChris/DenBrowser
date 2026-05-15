#!/usr/bin/env python3
"""
DenBrowser attestation roundtrip test (v2 protocol).

Replicates the DenBrowser browser's ECIES token generation (patch 006) and
validates the full path: test client → denbrowser-proxy (Pingora) → upstream.

Requirements:
    pip install cryptography requests

Usage (from repo root):
    scripts/gen-attest-key.sh
    scripts/gen-proxy-tls.sh
    docker compose -f test/target-server/compose.yml up -d
    (cd proxy && DENBROWSER_UPSTREAM=localhost:8080 cargo run)
    python3 test/attestation/test_roundtrip.py
"""

import base64
import hashlib
import os
import sys
import time
import warnings

import requests
from urllib3.exceptions import InsecureRequestWarning
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

PROXY_URL = os.environ.get("DENBROWSER_PROXY_URL", "https://localhost:8081")
PUBLIC_KEY_PATH = os.environ.get("PUBLIC_KEY_PATH", "build/proxy-public.pem")
TLS_CERT_PATH = os.environ.get("DENBROWSER_TLS_CERT", "build/proxy-tls.crt")

# When the proxy uses a self-signed dev cert, `requests` needs to be told to
# trust it.  Set VERIFY=False to skip TLS verification entirely (CI-only).
if TLS_CERT_PATH and os.path.exists(TLS_CERT_PATH):
    VERIFY = TLS_CERT_PATH
else:
    warnings.simplefilter("ignore", InsecureRequestWarning)
    VERIFY = False


def _load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def _make_attest(pub_key, *, nonce_b64, ts, host, method, path, body):
    """Mirror DenBrowserAttest.cpp::AddAttestHeaders — produce v2 headers."""
    body_hash_hex = hashlib.sha256(body).hexdigest()
    plaintext = (
        f"denbrowser-attest:v2\n"
        f"{nonce_b64}\n{ts}\n{host}\n{method}\n{path}\n{body_hash_hex}"
    ).encode()

    ephem_priv = generate_private_key(SECP256R1())
    Z = ephem_priv.exchange(ECDH(), pub_key)
    aes_key = X963KDF(algorithm=hashes.SHA256(), length=16, sharedinfo=None).derive(Z)
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


def _fresh_nonce_b64():
    return base64.b64encode(os.urandom(16)).decode()


def _run(pub_key):
    host = "localhost"
    passed = failed = 0

    def check(label, *, method, path, body, headers, expect):
        nonlocal passed, failed
        full = {**headers, "Host": host}
        try:
            r = requests.request(method, f"{PROXY_URL}{path}", data=body,
                                 headers=full, timeout=5, verify=VERIFY)
            if r.status_code == expect:
                print(f"  PASS  {label}  (HTTP {r.status_code})")
                passed += 1
            else:
                print(f"  FAIL  {label}  (expected {expect}, got {r.status_code})")
                failed += 1
        except Exception as exc:
            print(f"  ERROR {label}: {exc}")
            failed += 1

    # ── Valid GET (no body) ─────────────────────────────────────────────────
    ts = str(int(time.time()))
    nonce = _fresh_nonce_b64()
    h = _make_attest(pub_key, nonce_b64=nonce, ts=ts, host=host,
                     method="GET", path="/", body=b"")
    check("Valid GET with no body",
          method="GET", path="/", body=None, headers=h, expect=200)

    # ── Valid POST (body bound by hash) ─────────────────────────────────────
    ts = str(int(time.time()))
    nonce = _fresh_nonce_b64()
    body = b'{"hello":"world"}'
    h = _make_attest(pub_key, nonce_b64=nonce, ts=ts, host=host,
                     method="POST", path="/echo", body=body)
    check("Valid POST with hashed body",
          method="POST", path="/echo", body=body, headers=h, expect=200)

    # ── Replay rejected by nonce cache ──────────────────────────────────────
    ts = str(int(time.time()))
    nonce = _fresh_nonce_b64()
    h = _make_attest(pub_key, nonce_b64=nonce, ts=ts, host=host,
                     method="GET", path="/", body=b"")
    check("First use of nonce",
          method="GET", path="/", body=None, headers=h, expect=200)
    check("Replayed nonce rejected",
          method="GET", path="/", body=None, headers=h, expect=403)

    # ── Captured token re-used for a different path ─────────────────────────
    ts = str(int(time.time()))
    nonce = _fresh_nonce_b64()
    h = _make_attest(pub_key, nonce_b64=nonce, ts=ts, host=host,
                     method="GET", path="/legit", body=b"")
    # Same headers, different path — plaintext mismatch.
    check("Captured token cannot pivot to another path",
          method="GET", path="/admin", body=None, headers=h, expect=403)

    # ── Captured token re-used with a different method ──────────────────────
    ts = str(int(time.time()))
    nonce = _fresh_nonce_b64()
    h = _make_attest(pub_key, nonce_b64=nonce, ts=ts, host=host,
                     method="GET", path="/", body=b"")
    check("Captured token cannot switch method (GET→DELETE)",
          method="DELETE", path="/", body=None, headers=h, expect=403)

    # ── Tampered body rejected ──────────────────────────────────────────────
    ts = str(int(time.time()))
    nonce = _fresh_nonce_b64()
    h = _make_attest(pub_key, nonce_b64=nonce, ts=ts, host=host,
                     method="POST", path="/echo", body=b"original")
    check("Captured POST token cannot ship a different body",
          method="POST", path="/echo", body=b"tampered", headers=h, expect=403)

    # ── Missing headers ─────────────────────────────────────────────────────
    check("Missing all attestation headers",
          method="GET", path="/", body=None, headers={}, expect=403)
    check("Missing X-DenBrowser-Nonce",
          method="GET", path="/", body=None,
          headers={"X-DenBrowser-Ts": ts, "X-DenBrowser-Token": "AAAA"},
          expect=403)

    # ── Stale timestamp ─────────────────────────────────────────────────────
    stale = str(int(time.time()) - 120)
    nonce = _fresh_nonce_b64()
    h = _make_attest(pub_key, nonce_b64=nonce, ts=stale, host=host,
                     method="GET", path="/", body=b"")
    check("Stale timestamp (120s ago, window is 30s)",
          method="GET", path="/", body=None, headers=h, expect=403)

    # ── Future timestamp within window ──────────────────────────────────────
    ahead = str(int(time.time()) + 10)
    nonce = _fresh_nonce_b64()
    h = _make_attest(pub_key, nonce_b64=nonce, ts=ahead, host=host,
                     method="GET", path="/", body=b"")
    check("Future timestamp within 30s window",
          method="GET", path="/", body=None, headers=h, expect=200)

    print(f"\n  {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    if not os.path.exists(PUBLIC_KEY_PATH):
        print(f"ERROR: public key not found at {PUBLIC_KEY_PATH}")
        print("Run scripts/gen-attest-key.sh first.")
        sys.exit(1)

    pub_key = _load_public_key(PUBLIC_KEY_PATH)
    print(f"Public key : {PUBLIC_KEY_PATH}")
    print(f"Proxy URL  : {PROXY_URL}")
    print(f"TLS verify : {VERIFY!r}\n")

    sys.exit(0 if _run(pub_key) else 1)

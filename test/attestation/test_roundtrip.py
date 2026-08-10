#!/usr/bin/env python3
"""
DenBrowser attestation roundtrip test (v2 protocol).

Replicates the DenBrowser browser's ECIES token generation (patch 006) and
validates the full path: test client → denbrowser-proxy (Pingora) → upstream.

Requirements:
    pip install cryptography requests

Usage (from repo root):
    scripts/gen-attest-key.sh
    scripts/gen-proxy-tls.sh --name compose-proxy --host proxy --san localhost
    scripts/gen-user-cert.sh
    scripts/gen-machine-cert.sh --cn machine-client
    docker compose -f test/minimal-proxy-stack/compose.yml up --build -d
    docker compose -f test/minimal-proxy-stack/compose.yml run --build --use-aliases --rm machine-client

mTLS:
    If the proxy is run with [mtls] enabled, it requires a client certificate.
    Generate one and point the proxy's client_ca at the CA (the minimal proxy
    Compose stack already does this):
        scripts/gen-user-cert.sh
        # proxy config: [mtls] enabled = true, client_ca = "build/user-ca.crt"
    This test auto-presents build/user-cert.{crt,key} when they exist (override
    with DENBROWSER_CLIENT_CERT / DENBROWSER_CLIENT_KEY).  With no mTLS on the
    proxy, presenting the cert is harmless — the server never asks for it.

Machine identity:
    If the proxy is run with [machine_identity] enabled, every request must also
    carry X-DenBrowser-Machine-Cert (base64 DER) naming the workstation:
        # Direct host run:
        scripts/gen-machine-cert.sh --cn localhost
        # Compose service run:
        scripts/gen-machine-cert.sh --cn machine-client
        # proxy config: [machine_identity] enabled = true,
        #               machine_ca = "build/machine-ca.crt"
    Set DENBROWSER_MACHINE_IDENTITY_ENABLED=1 to send the certificate and run
    the machine-identity cases.  Certificate-file existence alone is not used
    as a proxy for server configuration: a disabled proxy deliberately ignores
    this header, so negative cases expecting 403 would otherwise be misleading.
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


def _env_flag(name):
    """Read a strict opt-in boolean from the environment."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


MACHINE_IDENTITY_ENABLED = _env_flag("DENBROWSER_MACHINE_IDENTITY_ENABLED")
MACHINE_MISMATCH_CN = os.environ.get(
    "DENBROWSER_MACHINE_MISMATCH_CN", "ws-4417.corp.example.com"
)

# When the proxy uses a self-signed dev cert, `requests` needs to be told to
# trust it.  Set VERIFY=False to skip TLS verification entirely (CI-only).
if TLS_CERT_PATH and os.path.exists(TLS_CERT_PATH):
    VERIFY = TLS_CERT_PATH
else:
    warnings.simplefilter("ignore", InsecureRequestWarning)
    VERIFY = False

# Client certificate for the proxy's [mtls] layer (scripts/gen-user-cert.sh).
# Presented only if both files exist; a proxy without mTLS simply never requests
# it, so this is safe to leave on by default.
CLIENT_CERT_PATH = os.environ.get("DENBROWSER_CLIENT_CERT", "build/user-cert.crt")
CLIENT_KEY_PATH = os.environ.get("DENBROWSER_CLIENT_KEY", "build/user-cert.key")
if os.path.exists(CLIENT_CERT_PATH) and os.path.exists(CLIENT_KEY_PATH):
    CLIENT_CERT = (CLIENT_CERT_PATH, CLIENT_KEY_PATH)
else:
    CLIENT_CERT = None

# Machine certificate for the proxy's [machine_identity] layer
# (scripts/gen-machine-cert.sh).  Unlike the client cert this never enters the
# TLS handshake — a handshake carries one client chain and the user cert already
# holds it — so it rides a header instead.  It is sent only when the explicit
# feature flag above is set; merely having test material on disk says nothing
# about whether the target proxy enabled the layer.
MACHINE_CERT_PATH = os.environ.get("DENBROWSER_MACHINE_CERT", "build/machine-cert.crt")
MACHINE_CA_PATH = os.environ.get("DENBROWSER_MACHINE_CA", "build/machine-ca.crt")
MACHINE_CA_KEY_PATH = os.environ.get("DENBROWSER_MACHINE_CA_KEY", "build/machine-ca.key")

# Sentinel distinguishing "caller said nothing, use the default cert" from
# "caller explicitly wants no machine header".
_DEFAULT = object()


def _der_b64(pem_path):
    """Load a PEM certificate and return its DER, base64 — the header format."""
    from cryptography.x509 import load_pem_x509_certificate

    with open(pem_path, "rb") as f:
        cert = load_pem_x509_certificate(f.read())
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


MACHINE_CERT = (
    _der_b64(MACHINE_CERT_PATH)
    if MACHINE_IDENTITY_ENABLED and os.path.exists(MACHINE_CERT_PATH)
    else None
)


def _load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def _make_attest(pub_key, *, nonce_b64, ts, host, method, path, body, unbound=False):
    """Mirror DenBrowserAttest.cpp::AddAttestHeaders — produce v2 headers.

    When ``unbound`` is set the body-hash field is replaced with the ``unbound``
    sentinel, matching what the browser emits for uploads too large to hash up
    front.  The proxy then streams the body straight through without buffering
    or hashing (origin/replay/method/host/path binding still apply)."""
    body_field = "unbound" if unbound else hashlib.sha256(body).hexdigest()
    plaintext = (
        f"denbrowser-attest:v2\n"
        f"{nonce_b64}\n{ts}\n{host}\n{method}\n{path}\n{body_field}"
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


def _mint_machine_cert(cn):
    """Mint a cert with the given CN, signed by the real machine CA.

    Lets the negative cases exercise a *validly issued* certificate that still
    must be refused — a name the proxy will not resolve to this client — which
    is the check standing in for proof of possession.  Returns None when the CA
    key is not available (a deployment-style run rather than a local one).
    """
    if not (os.path.exists(MACHINE_CA_PATH) and os.path.exists(MACHINE_CA_KEY_PATH)):
        return None

    import datetime

    from cryptography import x509
    from cryptography.x509.oid import NameOID

    with open(MACHINE_CA_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(MACHINE_CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(generate_private_key(SECP256R1()).public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def _run(pub_key):
    host = "localhost"
    passed = failed = 0

    def check(label, *, method, path, body, headers, expect, machine=_DEFAULT):
        nonlocal passed, failed
        full = {**headers, "Host": host}
        # Every request carries the machine certificate unless a case is
        # deliberately testing its absence or a bad value, so the existing
        # attestation cases keep passing with [machine_identity] enabled.
        if machine is _DEFAULT:
            cert = MACHINE_CERT if MACHINE_IDENTITY_ENABLED else None
        else:
            cert = machine
        if cert is not None:
            full["X-DenBrowser-Machine-Cert"] = cert
        try:
            r = requests.request(method, f"{PROXY_URL}{path}", data=body,
                                 headers=full, timeout=5, verify=VERIFY,
                                 cert=CLIENT_CERT)
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

    # ── Bound body at the 64 KB cap streams through ──────────────────────────
    # The bound path buffers + hashes the whole body before contacting the
    # upstream, so it is capped at pingora's 64 KiB retry-buffer limit.  A body
    # exactly at the cap is still forwarded.
    ts = str(int(time.time()))
    nonce = _fresh_nonce_b64()
    edge = b"z" * (64 * 1024)
    h = _make_attest(pub_key, nonce_b64=nonce, ts=ts, host=host,
                     method="POST", path="/echo", body=edge)  # bound (hashed)
    check("Bound body at 64 KB cap forwarded",
          method="POST", path="/echo", body=edge, headers=h, expect=200)

    # ── Large unbound upload streams through (no body hash) ──────────────────
    # 20 MB is far over the 64 KB bound-body cap; the unbound marker makes the
    # proxy stream it straight through instead of buffering + hashing.
    ts = str(int(time.time()))
    nonce = _fresh_nonce_b64()
    big = b"x" * (20 * 1024 * 1024)
    h = _make_attest(pub_key, nonce_b64=nonce, ts=ts, host=host,
                     method="POST", path="/echo", body=big, unbound=True)
    check("Large unbound upload streams through (20 MB)",
          method="POST", path="/echo", body=big, headers=h, expect=200)

    # ── Bound body over the 64 KB cap is rejected ────────────────────────────
    # A hashed (bound) body larger than the retry-buffer cap cannot be replayed
    # to the upstream, so the proxy rejects it with 413 — the browser is
    # expected to send anything this large as an unbound upload instead.
    ts = str(int(time.time()))
    nonce = _fresh_nonce_b64()
    big = b"y" * (64 * 1024 + 1)
    h = _make_attest(pub_key, nonce_b64=nonce, ts=ts, host=host,
                     method="POST", path="/echo", body=big)  # bound (hashed)
    check("Bound body over 64 KB cap rejected",
          method="POST", path="/echo", body=big, headers=h, expect=413)

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

    # ── Machine identity ────────────────────────────────────────────────────
    # Server configuration is explicit. A certificate may be present for a
    # different stack while this target has the layer disabled.
    if not MACHINE_IDENTITY_ENABLED:
        print("  SKIP  machine-identity cases (feature flag is off)")
    else:
        def machine_check(label, *, machine, expect):
            ts = str(int(time.time()))
            nonce = _fresh_nonce_b64()
            h = _make_attest(pub_key, nonce_b64=nonce, ts=ts, host=host,
                             method="GET", path="/", body=b"")
            check(label, method="GET", path="/", body=None, headers=h,
                  expect=expect, machine=machine)

        # A fully valid request — attestation *and* machine identity.
        machine_check("Valid machine certificate accepted",
                      machine=MACHINE_CERT, expect=200)

        machine_check("Missing machine certificate rejected",
                      machine=None, expect=403)

        machine_check("Malformed machine certificate header rejected",
                      machine="not-base64!!", expect=403)

        # Well-formed base64 that is not a certificate.
        machine_check("Non-certificate machine header rejected",
                      machine=base64.b64encode(b"hello").decode(), expect=403)

        # The user certificate is validly signed — by the wrong CA for this
        # layer.  This is what stops the two identities being interchangeable.
        if CLIENT_CERT:
            machine_check("Machine certificate from the wrong CA rejected",
                          machine=_der_b64(CLIENT_CERT_PATH), expect=403)

        # Issued by the *right* CA, but naming a machine this request did not
        # come from — the check that stands in for proof of possession.
        elsewhere = _mint_machine_cert(MACHINE_MISMATCH_CN)
        if elsewhere is None:
            print("  SKIP  wrong-host case (no build/machine-ca.key)")
        else:
            machine_check(
                "Valid machine certificate for another host rejected",
                machine=elsewhere, expect=403)

    print(f"\n  {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    if not os.path.exists(PUBLIC_KEY_PATH):
        print(f"ERROR: public key not found at {PUBLIC_KEY_PATH}")
        print("Run scripts/gen-attest-key.sh first.")
        sys.exit(1)

    if MACHINE_IDENTITY_ENABLED and MACHINE_CERT is None:
        print(
            "ERROR: machine identity is enabled but no certificate exists at "
            f"{MACHINE_CERT_PATH}"
        )
        sys.exit(1)

    pub_key = _load_public_key(PUBLIC_KEY_PATH)
    print(f"Public key  : {PUBLIC_KEY_PATH}")
    print(f"Proxy URL   : {PROXY_URL}")
    print(f"TLS verify  : {VERIFY!r}")
    print(f"Client cert : {CLIENT_CERT[0] if CLIENT_CERT else '(none)'}")
    print(f"Machine cert: {MACHINE_CERT_PATH if MACHINE_CERT else '(none)'}")
    print(
        "Machine identity tests: "
        f"{'enabled' if MACHINE_IDENTITY_ENABLED else 'disabled'}\n"
    )

    sys.exit(0 if _run(pub_key) else 1)

# Minimal proxy Compose stack

This is the smallest runnable example of the DenBrowser proxy in front of a TLS
upstream. The stack builds the Rust proxy and starts it in front of a static
nginx site. Only the proxy is published to the host, on
`https://127.0.0.1:8081`. nginx has no host port and joins only the internal
`upstream` network, whose other member is the proxy.

Generate the development identity, attestation key, and mTLS user material once
from the repository root:

```bash
./scripts/gen-attest-key.sh
./scripts/gen-proxy-tls.sh
./scripts/gen-user-cert.sh
```

Then build and start both services:

```bash
docker compose -f test/minimal-proxy-stack/compose.yml up --build -d
docker compose -f test/minimal-proxy-stack/compose.yml logs -f proxy
```

`config.toml` enables mTLS, so clients must present
`build/user-cert.{crt,key}`. The roundtrip and stress clients discover those
files automatically. Run the integration test from the repository root:

```bash
python3 test/attestation/test_roundtrip.py
```

Stop and remove the stack with:

```bash
docker compose -f test/minimal-proxy-stack/compose.yml down
```

The upstream currently reuses the development proxy certificate so the stack
can be started from the existing generated files. Accordingly, the proxy uses
`--insecure-upstream` in this local-only stack. A production deployment must
give the upstream its own trusted identity and must not disable upstream TLS
verification.

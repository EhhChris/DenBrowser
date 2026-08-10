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
./scripts/gen-proxy-tls.sh --name compose-proxy --host proxy --san localhost
./scripts/gen-user-cert.sh
./scripts/gen-machine-cert.sh --cn machine-client
```

Then build and start both services:

```bash
docker compose -f test/minimal-proxy-stack/compose.yml up --build -d
docker compose -f test/minimal-proxy-stack/compose.yml logs -f proxy
```

`config.toml` enables mTLS and machine identity. The integration client runs as
the one-shot `machine-client` Compose service on the proxy's `ingress` network,
and receives the user and machine certificates through Compose secrets. Run it
from the repository root:

```bash
docker compose -f test/minimal-proxy-stack/compose.yml run --build --use-aliases --rm machine-client
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

## How the machine DNS check works here

Running the Python client on the host and reaching the published port would
cross Docker's NAT, so the proxy would see the bridge gateway rather than the
host process. The one-shot client avoids that path: it joins the same
user-defined `ingress` bridge as the proxy and connects to `proxy:8081`
directly. Docker DNS resolves the stable service name `machine-client` to the
client container's current bridge address, and that is also the TCP peer address
the proxy observes. The `--use-aliases` flag is required because Compose does
not otherwise apply the service's network aliases to containers created by
`docker compose run`. No static container addresses are needed.

The positive certificate is therefore generated with `CN=machine-client`. For
the deterministic mismatch case, the test mints a valid certificate with
`CN=upstream`: the proxy can resolve that name on its separate `upstream`
network, but its address cannot equal the client container's ingress address.

The stack uses a dedicated development TLS certificate whose primary name is
`proxy`, because that is the name the in-network client connects to. `localhost`
is included as an extra SAN for host-side diagnostics. If the dedicated
`build/compose-proxy-tls.{crt,key}` files already exist, regenerate them with:

```bash
./scripts/gen-proxy-tls.sh --name compose-proxy --host proxy --san localhost --force
```

This certificate is test-stack material and is not the `proxy-tls.crt` identity
referenced by a normal DenBrowser build.

The published `https://127.0.0.1:8081` port remains available for diagnostics,
but host-originated requests are expected to fail the enabled machine check.
This Compose test covers certificate verification, Docker DNS, and peer-address
matching; testing a real signed-binary firewall policy still requires a
domain-managed workstation or VM.

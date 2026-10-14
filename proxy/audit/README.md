# Proxy audit log

The DenBrowser browser records nothing, so the proxy's log is the audit trail.
Every line it writes — to the log file and to stderr — is one JSON object.

| File | What it is |
|---|---|
| [`audit-log.schema.json`](audit-log.schema.json) | The mapping: a JSON Schema (draft 2020-12) defining every field, its type, and what it means, plus every failure reason with its pipeline stage and risk (`x-stage`, `x-risk`). |
| [`audit-log.examples.jsonl`](audit-log.examples.jsonl) | One line of real output for every type of audit event and for both kinds of system line, exactly as the proxy writes them. |

Neither file is maintained by hand. `src/audit.rs` defines the records, and its
tests generate the examples from the same code path `request_filter` uses and
check the schema's reason table against the code. `test/audit_log/` validates
the examples against the schema with a standard JSON Schema validator.

```sh
cargo test                                                  # from proxy/
DENBROWSER_UPDATE_AUDIT_EXAMPLES=1 cargo test examples_file # regenerate after a deliberate change
python3 test/audit_log/test_audit_log_schema.py             # from the repo root; needs jsonschema
```

## Two kinds of line

`event.kind` tells them apart.

- **`audit`**: exactly one per HTTP request, written when the exchange ends
  (response finished, refused, or failed). Writing it at the end is what lets it
  carry the final status code and the bytes moved in each direction. A long
  download therefore appears when it completes, stamped with its
  `event.duration_ms`.
- **`system`**: everything else: startup and configuration messages, fatal
  errors, and pingora's own diagnostics. Same envelope (`timestamp`,
  `schema_version`, `level`, `logger`, `event`, `message`), no request fields.

TLS handshake failures, such as a client with no certificate when `[mtls]` is
on, happen before any HTTP request exists. They appear only as pingora `system`
lines (`Downstream handshake error from <ip>:<port> …`), never as audit records.

## Audit record fields

Every audit record has every field below. A value that doesn't apply is `null`;
the field is never omitted.

| Field | Meaning |
|---|---|
| `timestamp` | When the record was written (the end of the exchange): ISO 8601 UTC, millisecond precision, fixed width (`2026-10-14T13:04:05.250Z`). |
| `level` | `INFO` for a request that was forwarded and completed, `WARN` for every refusal and failure. `[logging].level = "warn"` keeps exactly the refusals and failures. |
| `event.action` | What the proxy did: `forward`, `bypass`, `reject`, `rate_limit`, or `error` (failed before a decision). |
| `event.outcome` | `success` or `failure`. A forwarded request whose upstream then fails is `forward` + `failure`. |
| `event.stage` | *When* it failed: which check in the pipeline (table below). |
| `event.reason` | *How* it failed: machine-readable code (table below). |
| `event.risk` | How severe the event is: `info` for successes; otherwise the reason's fixed risk level. |
| `event.duration_ms` | Time from request head to record. |
| `message` | Human-readable account. Never contains the URL path. |
| `proxy.ip`, `proxy.port` | The proxy's own address on this connection: the local socket the client reached, not the configured (possibly wildcard) listen address. |
| `client.ip`, `client.port` | The connecting host. |
| `server.address` | The host the client asked for (Host header, port removed). |
| `user.subject_dn` | Subject DN of the mTLS user certificate (verified at the handshake). `null` when `[mtls]` is off. |
| `machine.subject_dn` | Subject DN of the presented machine certificate, **whenever one could be parsed**, including certificates that failed or never reached verification. Trust it only when `machine.chain_verified` is `true`. |
| `machine.status` | `verified`, `failed`, `absent` (not sent, not required), `not_evaluated` (refused or bypassed first), or `disabled`. |
| `machine.hostname` | The verified workstation hostname. Set only when `status` is `verified`. |
| `attestation.status` | `verified`, `failed`, `bypassed`, `incomplete` (token passed, then another control refused), or `not_evaluated`. |
| `attestation.nonce` | `X-DenBrowser-Nonce` as sent: the transaction's unique identifier. Recorded even when invalid (cut to 64 characters). |
| `attestation.client_timestamp` | `X-DenBrowser-Ts` as ISO 8601: the workstation's clock at attestation. Compare with `timestamp` to spot clock skew. |
| `attestation.body_binding` | `bound` (body hash verified) or `unbound` (large upload, body not hashed). |
| `http.request.method` | The request method. The path is never recorded. |
| `http.response.status_code` | Status sent to the client. |
| `transfer.request_body_bytes` | Body bytes read from the client (uploaded). |
| `transfer.response_body_bytes` | Body bytes relayed to the client (downloaded). |

Both `transfer` counts are body bytes only, without headers or TLS framing.
DNs are RFC 4514 strings, most specific first (`CN=…,OU=…,O=…,C=…`), with
control characters hex-escaped (`\0A`). Client-supplied strings are capped
(DN 1024, host 256, method 32, nonce 64 characters) and marked with `…` when
cut.

## Risk

`event.risk` is how severe an event is. It is not called `event.severity`
because ECS defines that field as a number.

| Risk | Meaning |
|---|---|
| `info` | Not a failure. |
| `low` | Benign: no attestation headers at all (someone on a browser that isn't DenBrowser), or a client that went away. |
| `medium` | Operational: clock skew, a missing or lapsed machine certificate, DNS trouble, rate limits, upstream failures. Track in aggregate. |
| `high` | Something a correctly configured DenBrowser should never send: partial or malformed attestation, tokens that don't decrypt, replayed nonces, machine certificates outside policy or presented from the wrong address. Investigate. |
| `critical` | A well-formed token for this proxy that commits to a *different* request or body: a lifted token or a request altered in transit. Investigate immediately. |

## Reasons

Stages run top to bottom, except that `machine_identity` checks presence before
`attestation_token` and verifies the certificate after it. A failure is an
attestation failure exactly when its stage starts with `attestation_`.

| Reason | Stage | Risk | HTTP | Typical cause |
|---|---|---|---|---|
| `rate_limited` | `rate_limit` | medium | 429 | Client IP over a `[rate_limiting]` cap. |
| `no_attestation_headers` | `attestation_headers` | **low** | 403 | Not DenBrowser, or a DenBrowser build that doesn't list this proxy. |
| `incomplete_attestation_headers` | `attestation_headers` | high | 403 | Some attestation headers but not all, or a machine certificate with none. |
| `machine_cert_missing` | `machine_identity` | medium | 403 | No machine certificate enrolled, or a non-Windows build. |
| `machine_cert_malformed` | `machine_identity` | high | 403 | Header isn't base64 DER. |
| `machine_cert_no_common_name` | `machine_identity` | high | 403 | Certificate has no CN. |
| `machine_cert_unsafe_common_name` | `machine_identity` | high | 403 | CN with spaces/control characters: a log-injection attempt. |
| `machine_hostname_not_allowed` | `machine_identity` | high | 403 | CN outside `allowed_hostnames`. |
| `machine_cert_expired` | `machine_identity` | medium | 403 | Renewal lapsed, or DenBrowser not restarted since renewal. |
| `machine_cert_not_yet_valid` | `machine_identity` | medium | 403 | Clock wrong at the proxy or the issuing CA. |
| `machine_cert_untrusted` | `machine_identity` | high | 403 | Doesn't chain to `machine_ca`. |
| `machine_hostname_unresolvable` | `machine_identity` | medium | 403 | No DNS record, or resolver outage on a cold cache. |
| `machine_address_mismatch` | `machine_identity` | high | 403 | Trusted cert from an address its name doesn't resolve to: copied cert, NAT, or DNS lagging DHCP. |
| `machine_no_client_address` | `machine_identity` | medium | 403 | No peer IP on the connection (should not happen). |
| `timestamp_invalid` | `attestation_token` | high | 403 | `X-DenBrowser-Ts` not an integer. |
| `timestamp_out_of_window` | `attestation_token` | medium | 403 | Workstation clock more than 30 s off. |
| `nonce_invalid` | `attestation_token` | high | 403 | Nonce not 16 bytes of base64. |
| `nonce_replay` | `attestation_token` | high | 403 | Nonce reused: a replayed request, or a network-stack resend after a dropped connection. |
| `token_malformed` | `attestation_token` | high | 403 | Token not base64, too short, or bad EC point. |
| `token_decrypt_failed` | `attestation_token` | high | 403 | Forged, corrupted, or built for another proxy's key. |
| `token_request_mismatch` | `attestation_token` | **critical** | 403 | Token commits to a different method/host/path. |
| `body_too_large` | `attestation_body` | medium | 413 | Bound body over 64 KiB. |
| `body_hash_mismatch` | `attestation_body` | **critical** | 403 | Body altered after it was attested. |
| `body_read_failed` | `downstream` | low | 400 | Client didn't deliver the body. |
| `upstream_error` | `upstream` | medium | 502 | Upstream unreachable or failed mid-exchange. |
| `downstream_error` | `downstream` | low | — | Client disconnected mid-exchange. |
| `internal_error` | `internal` | medium | 500 | Proxy failure; pingora logs detail as a `system` line. |

## What is not recorded

**URL paths and query strings.** They name the documents, files, and searches a
user touched, which is the data this product exists to keep from leaking.
Records keep the method and host only. pingora's own error lines would
otherwise append `METHOD /path?query, Host: …`; the proxy overrides that summary
to `METHOD host`. Rate-limit rules still *match* on the path; they just never
log it.

What *is* recorded and may itself be sensitive: user and machine certificate
DNs, client IPs, hostnames, and per-request byte counts. Set access controls and
retention on the log directory accordingly.

## Querying

```sh
# Everything worth a look
jq -c 'select(.event.risk == "high" or .event.risk == "critical")' denbrowser-proxy.log.*

# Attestation failures by reason
jq -r 'select(.event.stage // "" | startswith("attestation_")) | .event.reason' denbrowser-proxy.log.* | sort | uniq -c

# Bytes downloaded per user
jq -r 'select(.event.kind == "audit") | [.user.subject_dn, .transfer.response_body_bytes] | @tsv' denbrowser-proxy.log.* \
  | awk -F'\t' '{s[$1] += $2} END {for (u in s) print s[u], u}' | sort -rn

# Follow one transaction
jq -c 'select(.attestation.nonce == "kX2b0f9Qm1T4yH8uJc3LwA==")' denbrowser-proxy.log.*
```

## Migrating from the plain-text log

Earlier builds wrote free-text lines. Each maps onto one audit record:

| Old line | Now |
|---|---|
| `accepted — METHOD host/path machine=… (N byte body)` | `action: forward`, `attestation.body_binding: bound`, `transfer.request_body_bytes` |
| `accepted — … (unbound upload)` | `action: forward`, `attestation.body_binding: unbound` |
| `attestation bypass — ip=… cert_subject=…` | `action: bypass` |
| `rate limited — ip host/path` | `action: rate_limit`, `reason: rate_limited` |
| `rejected — missing attestation headers` | `no_attestation_headers` (none sent) or `incomplete_attestation_headers` (some sent) |
| `rejected — X-DenBrowser-Machine-Cert is missing` | `machine_cert_missing` |
| `rejected — <machine error>` | the matching `machine_*` reason |
| `rejected — <attestation error> (host=… METHOD /path)` | the matching `timestamp_*`, `nonce_*`, `token_*`, or `body_hash_mismatch` reason |
| `rejected — bound body exceeds …` | `body_too_large` |
| `rejected — could not read request body: …` | `body_read_failed` |

One ordering change comes with this. A request carrying no DenBrowser headers
at all used to be refused for its missing machine certificate (when machine
identity was required). It is now classified as `no_attestation_headers`. The
response is still 403; only the recorded reason changes, so a plain browser
isn't reported as a workstation enrolment problem.

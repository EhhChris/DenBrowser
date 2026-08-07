use std::sync::Arc;

use async_trait::async_trait;
use clap::Parser;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::Server;
use pingora_core::tls::ssl::{SslFiletype, SslVerifyMode};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::RequestHeader;
use pingora_proxy::{http_proxy_service, ProxyHttp, Session};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

mod attest;
mod config;
mod logging;
mod machine;
mod mtls;
mod passthrough;
mod ratelimit;
use attest::{AttestInputs, BodyBinding, Verifier};
use config::Config;
use machine::MachineIdentity;
use mtls::ClientCert;
use passthrough::BypassPolicy;
use ratelimit::RateLimiter;

/// Maximum bytes of a *bound* (hash-verified) request body.
///
/// A bound body is buffered and hashed in `request_filter` *before* the upstream
/// is ever contacted, so the backend never sees an unverified byte.  To forward
/// the body afterwards we rely on pingora's request retry buffer, which natively
/// replays it to the upstream — and that buffer is a `FixedBuffer` hardcoded to
/// `BODY_BUF_LIMIT` (64 KiB) that silently truncates past its capacity.  So the
/// bound path is capped at exactly that limit: a bound request whose body exceeds
/// it is rejected with 413.  The browser is expected to send anything larger as
/// an *unbound* upload (see `BodyBinding::Unbound`), which streams straight
/// through with no size cap and no per-body hash.
/// TODO: Revisit this... inspection before streaming should be possible per: https://github.com/cloudflare/pingora/issues/67
/// Likely to do with how we're holding back headers before streaming as well though.
const BOUND_BODY_MAX: usize = 64 * 1024;

/// Request header carrying the workstation's machine certificate, base64 DER.
///
/// Named once so the read in `request_filter` and the strip in
/// `upstream_request_filter` cannot drift — a strip that misses its header
/// leaks the certificate to the backend.
const MACHINE_CERT_HEADER: &str = "x-denbrowser-machine-cert";

#[derive(Parser, Debug)]
#[command(about = "DenBrowser attestation proxy — verifies ECIES tokens, strips headers, forwards")]
struct Args {
    /// DEV ONLY: skip TLS certificate and hostname verification of the
    /// upstream, allowing self-signed local upstreams.  Never enable in
    /// production — it removes the guarantee that the proxy is talking to the
    /// intended upstream and not a MITM.
    #[arg(long, env = "DENBROWSER_INSECURE_UPSTREAM", default_value_t = false)]
    insecure_upstream: bool,

    /// Path to the operational TOML config file (listener, upstream, TLS,
    /// attestation, rate limiting, mTLS, and proxy bypass). Required: the proxy
    /// loads this file on startup and exits if it cannot be read or parsed.
    /// Defaults to `proxy.toml` in the working directory.
    #[arg(long, env = "DENBROWSER_CONFIG", default_value = "proxy.toml")]
    config: String,
}

struct DenBrowserProxy {
    verifier: Arc<Verifier>,
    upstream_host: String,
    upstream_port: u16,
    insecure_upstream: bool,
    /// `None` when rate limiting is disabled (no config or `enabled = false`).
    rate_limiter: Option<RateLimiter>,
    /// Attestation-bypass policy (source-IP ranges + subject allowlist); `None`
    /// when bypass is disabled.  The client certificate it matches against is
    /// verified by baseline mTLS at the TLS layer and read here from the digest.
    bypass: Option<BypassPolicy>,
    /// Machine-identity verifier (workstation certificate + hostname); `None`
    /// when `[machine_identity]` is disabled.
    machine: Option<MachineIdentity>,
}

impl DenBrowserProxy {
    fn new(
        verifier: Verifier,
        upstream: &str,
        insecure_upstream: bool,
        rate_limiter: Option<RateLimiter>,
        bypass: Option<BypassPolicy>,
        machine: Option<MachineIdentity>,
    ) -> anyhow::Result<Self> {
        let (host, port_str) = upstream
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("upstream must be host:port, got {upstream:?}"))?;
        let port: u16 = port_str.parse()?;
        Ok(Self {
            verifier: Arc::new(verifier),
            upstream_host: host.to_owned(),
            upstream_port: port,
            insecure_upstream,
            rate_limiter,
            bypass,
            machine,
        })
    }
}

#[async_trait]
impl ProxyHttp for DenBrowserProxy {
    // No per-request state is needed: bound bodies are verified and captured in
    // `request_filter`, and pingora forwards them; unbound bodies stream through
    // untouched.
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let mut peer = HttpPeer::new(
            (self.upstream_host.as_str(), self.upstream_port),
            true,
            self.upstream_host.clone(),
        );
        peer.options.set_http_version(2, 1);
        if self.insecure_upstream {
            peer.options.verify_cert = false;
            peer.options.verify_hostname = false;
        }
        Ok(Box::new(peer))
    }

    /// Verify the request completely — headers (phase 1) *and* body (phase 2) —
    /// before the upstream is ever contacted.  Any failure answers the client
    /// here and returns `Ok(true)`, so pingora never opens the upstream
    /// connection: the backend only ever sees requests that passed every check
    /// and needs no awareness of attestation at all.
    ///
    /// Bound requests: the whole body is buffered (into pingora's retry buffer)
    /// and hashed here, then verified, all before `upstream_peer`.  Once
    /// verification passes, pingora replays the retry-buffered body to the
    /// upstream on its own — so there is no `request_body_filter` to override and
    /// no second copy of the body to carry.  The body is capped at
    /// `BOUND_BODY_MAX` (the retry buffer's own limit); larger bound bodies are
    /// rejected with 413.
    ///
    /// Unbound (large-upload) requests: the token carries no body hash, so there
    /// is nothing to verify or buffer.  We commit the nonce here and return
    /// without reading the body, letting pingora stream it straight to the
    /// upstream (O(1) memory, no size cap).  Origin, replay, timestamp, and
    /// method/host/path binding are still fully verified before the upstream is
    /// contacted; only per-body integrity is intentionally skipped for these
    /// uploads.
    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<bool> {
        // Origin IP, keyed on by both rate limiting and bypass.  Owned copy so
        // the immutable borrow of `session` ends before any `respond_error`.
        let client_ip = session.client_addr().and_then(|a| a.as_inet()).map(|s| s.ip());

        // Rate limiting runs *before* attestation so a flood from one IP is shed
        // cheaply here — it never reaches the crypto path or the upstream.  The
        // counter is keyed on the origin IP and the rule glob is matched against
        // `host + path`, so per-URL-pattern limits work even on requests that
        // would later fail attestation.
        // Enforce only when we have an IP to key on (always true for a TCP/TLS
        // client); otherwise fail open rather than throttle blindly.
        if let Some(limiter) = &self.rate_limiter
            && let Some(ip) = client_ip
        {
            let target = {
                let req = session.req_header();
                let host = header_str(&req.headers, "host")
                    .map(|h| h.split(':').next().unwrap_or(&h).to_owned())
                    .unwrap_or_default();
                let path = req.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
                format!("{host}{path}")
            };
            if !limiter.admit(&ip, &target) {
                warn!("rate limited — {ip} {target}");
                let _ = session.respond_error(429).await;
                return Ok(true);
            }
        }

        // Attestation bypass: a request is forwarded straight upstream (skipping
        // all attestation) only if BOTH halves of the policy pass — its source IP
        // is in range AND the mTLS-verified client certificate's subject is on the
        // allowlist (the cert itself was already verified against the mTLS CA at
        // the handshake and recorded in the digest as a `ClientCert`).  Any miss
        // falls through to normal attestation, so bypass never weakens the path.
        if let Some(policy) = &self.bypass
            && let Some(ip) = client_ip
            && let Some(cert) = client_cert(session)
            && let Some(subject) = policy.authorizes(&ip, cert)
        {
            info!("attestation bypass — ip={ip} cert_subject={subject} machine=(bypass)");
            return Ok(false);
        }

        // Machine identity: which workstation this came from.  Runs after bypass
        // (trusted infrastructure that cannot run the attestation client has no
        // machine certificate either, so gating it would break those callers)
        // and before attestation, so a request that cannot name its machine is
        // shed before the crypto path.
        //
        // The verified hostname is carried into the accept log below; it grants
        // nothing on its own.  See `machine` for what this does and does not
        // prove.
        let machine_host = match &self.machine {
            None => None,
            Some(verifier) => {
                let presented = header_str(&session.req_header().headers, MACHINE_CERT_HEADER);
                match presented {
                    Some(cert_b64) => match verifier.verify_cert(&cert_b64) {
                        Ok(hostname) => Some(hostname),
                        Err(e) => {
                            warn!("rejected — {e}");
                            let _ = session.respond_error(403).await;
                            return Ok(true);
                        }
                    },
                    // Absent.  Rejected unless the operator is mid-rollout and
                    // has deliberately relaxed `required`.
                    None if verifier.required() => {
                        warn!("rejected — {}", machine::MachineError::Missing);
                        let _ = session.respond_error(403).await;
                        return Ok(true);
                    }
                    None => None,
                }
            }
        };
        let machine_log = machine_host.as_deref().unwrap_or("-");

        let req = session.req_header();

        let ts = header_str(&req.headers, "x-denbrowser-ts");
        let nonce = header_str(&req.headers, "x-denbrowser-nonce");
        let token = header_str(&req.headers, "x-denbrowser-token");
        let host = header_str(&req.headers, "host")
            .map(|h| h.split(':').next().unwrap_or(&h).to_owned());

        let (ts, nonce, token, host) = match (ts, nonce, token, host) {
            (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
            _ => {
                warn!("rejected — missing attestation headers");
                let _ = session.respond_error(403).await;
                return Ok(true);
            }
        };

        let method = req.method.as_str().to_owned();
        let path = req
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned());

        // Phase 1 — every attestation field except the body hash.
        let p1 = {
            let inputs = AttestInputs {
                ts: &ts,
                nonce_b64: &nonce,
                token_b64: &token,
                host: &host,
                method: &method,
                path: &path,
            };
            match self.verifier.verify_headers(&inputs) {
                Ok(p1) => p1,
                Err(e) => {
                    warn!("rejected — {e} (host={host} {method} {path})");
                    let _ = session.respond_error(403).await;
                    return Ok(true);
                }
            }
        };

        // Unbound upload: no body hash to verify.  Commit the nonce now (there is
        // no phase 2 to defer it to) and return without draining the body so
        // pingora streams it straight to the upstream.
        if matches!(p1.body_binding, BodyBinding::Unbound) {
            if let Err(e) = self.verifier.commit_nonce(&p1.nonce) {
                warn!("rejected — {e} (host={host} {method} {path})");
                let _ = session.respond_error(403).await;
                return Ok(true);
            }
            info!(
                "accepted — {method} {host}{} machine={machine_log} (unbound upload)",
                path_without_query(&path)
            );
            return Ok(false);
        }

        // Phase 2 — buffer and hash the entire body, then verify it.  Enabling
        // retry buffering *before* the first read captures the body into
        // pingora's retry buffer; reading it here (before `upstream_peer`) drains
        // the downstream stream, and pingora replays the retry buffer to the
        // upstream once we return `Ok(false)`.
        session.enable_retry_buffering();
        let mut hasher = Sha256::new();
        let mut total = 0usize;
        loop {
            match session.read_request_body().await {
                Ok(Some(chunk)) => {
                    total += chunk.len();
                    if total > BOUND_BODY_MAX {
                        warn!(
                            "rejected — bound body exceeds {BOUND_BODY_MAX} bytes \
                             (must be sent as an unbound upload)"
                        );
                        let _ = session.respond_error(413).await;
                        return Ok(true);
                    }
                    hasher.update(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    warn!("rejected — could not read request body: {e}");
                    let _ = session.respond_error(400).await;
                    return Ok(true);
                }
            }
        }

        let actual: [u8; 32] = hasher.finalize().into();
        if let Err(e) = self.verifier.verify_body_and_commit(&p1, &actual) {
            warn!("rejected — {e} (host={host} {method} {path})");
            let _ = session.respond_error(403).await;
            return Ok(true);
        }

        // Fully verified.  Pingora's retry buffer holds the body and replays it
        // to the upstream on its own.
        info!(
            "accepted — {method} {host}{} machine={machine_log} ({total} byte body)",
            path_without_query(&path)
        );
        Ok(false)
    }

    /// Strip attestation headers from the request forwarded upstream.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request.remove_header("x-denbrowser-ts");
        upstream_request.remove_header("x-denbrowser-nonce");
        upstream_request.remove_header("x-denbrowser-token");
        upstream_request.remove_header(MACHINE_CERT_HEADER);
        Ok(())
    }
}

fn header_str(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers.get(name)?.to_str().ok().map(|s| s.to_owned())
}

/// Drop the query string from a path for logging.
///
/// The accept path logs one line per *successful* request, so unlike the
/// rejection logs it sees ordinary user traffic in bulk — and query strings
/// routinely carry session tokens, search terms, and other content this product
/// exists to keep from leaking.  Recording the path alone is enough to audit
/// what was allowed through without turning the audit trail into its own
/// disclosure risk.  Rejection logs keep the full path deliberately: they are
/// comparatively rare and the query is often the reason the request was refused.
fn path_without_query(path: &str) -> &str {
    match path.split_once('?') {
        Some((head, _)) => head,
        None => path,
    }
}

/// Read the mTLS client identity the TLS layer recorded on this connection's
/// digest (see `mtls::Recorder`).  `None` means mTLS is disabled or the peer
/// presented no certificate — with baseline mTLS enforced at the handshake, a
/// present value is an already-verified identity.
fn client_cert(session: &Session) -> Option<&ClientCert> {
    session
        .digest()?
        .ssl_digest
        .as_ref()?
        .extension
        .get::<ClientCert>()
}

/// Abort startup with a logged reason.
///
/// Startup failures used to `panic!`, which produced a backtrace-shaped message
/// on stderr and nothing in the log file.  Routing them through `error!` puts
/// them in the audit trail alongside everything else.  `process::exit` skips the
/// appender's flush-on-drop, but the stderr mirror is on by default, so the
/// message reaches the operator either way.
fn fatal(msg: impl std::fmt::Display) -> ! {
    error!("{msg}");
    std::process::exit(1);
}

fn main() {
    let args = Args::parse();

    // The config file is mandatory — fail loudly rather than fall back to
    // silent defaults, so a missing or unreadable config never starts a proxy
    // with unintended (e.g. mTLS-disabled) settings.  It is loaded first
    // because it carries the attestation private key path, and because it also
    // carries the logging settings: this one failure genuinely predates the
    // logger, so it reports itself on stderr rather than through `fatal`.
    let config = Config::load(&args.config).unwrap_or_else(|e| {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    });

    // Logging comes up next so every check below is recorded.  The guard owns
    // the background file-writer thread and must stay alive for the life of the
    // process; see `logging`'s module docs for why that is not quite the same
    // as being dropped cleanly.
    let _log_guard = logging::init(&config.logging).unwrap_or_else(|e| {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    });

    config
        .proxy
        .validate()
        .unwrap_or_else(|e| fatal(format!("invalid proxy config: {e}")));

    // Attestation key: required, and validated here so a proxy that could
    // never decrypt a token refuses to start instead of 403-ing every request.
    let verifier = Verifier::from_config(&config.attestation).unwrap_or_else(|e| fatal(e));
    info!(
        "attestation key loaded from {}",
        config.attestation.private_key
    );

    if args.insecure_upstream {
        warn!(
            "INSECURE: upstream TLS verification disabled (--insecure-upstream) — \
             for local testing only, never production"
        );
    }
    let rate_limiter = RateLimiter::from_config(&config.rate_limiting)
        .unwrap_or_else(|e| fatal(format!("invalid rate_limiting config: {e}")));
    match &rate_limiter {
        Some(_) => info!("rate limiting enabled"),
        None => info!("rate limiting disabled"),
    }

    // Baseline mTLS: when enabled, every client must present a certificate
    // chaining to the configured CA (enforced at the TLS handshake below).
    let mtls = mtls::Mtls::from_config(&config.mtls)
        .unwrap_or_else(|e| fatal(format!("invalid mtls config: {e}")));
    match &mtls {
        Some(_) => info!("mTLS enabled — client certificates required"),
        None => info!("mTLS disabled"),
    }

    // Machine identity: a separate CA and a per-request header naming the
    // workstation.  Independent of mTLS — it identifies the *machine*, where
    // mTLS identifies the *user* — so it is not gated on mTLS being enabled.
    let machine = MachineIdentity::from_config(&config.machine_identity)
        .unwrap_or_else(|e| fatal(format!("invalid machine_identity config: {e}")));
    match &machine {
        Some(m) if m.required() => {
            info!("machine identity enabled — machine certificates required")
        }
        Some(_) => info!("machine identity enabled — machine certificates verified when present"),
        None => info!("machine identity disabled"),
    }

    // The two client-identity CAs must be distinct.  The browser tells the user
    // certificate apart from the machine certificate by its issuer — that is
    // what the CertificateRequest CA list below relies on — and the proxy tells
    // the two layers apart the same way.  A shared CA would make client-cert
    // selection a coin flip and let a machine certificate satisfy mTLS (or vice
    // versa), so refuse to start rather than fail intermittently in the field.
    if let (Some(m), Some(mi)) = (&mtls, &machine) {
        for user_ca in m.ca_certs() {
            for machine_ca in mi.ca_certs() {
                if user_ca.subject_name().try_cmp(machine_ca.subject_name()).ok()
                    == Some(std::cmp::Ordering::Equal)
                    && user_ca
                        .public_key()
                        .and_then(|a| machine_ca.public_key().map(|b| a.public_eq(&b)))
                        .unwrap_or(false)
                {
                    fatal(
                        "[mtls].client_ca and [machine_identity].machine_ca share a certificate — \
                         the user and machine identities must be issued by different CAs so they \
                         can be told apart",
                    );
                }
            }
        }
    }

    // Attestation bypass builds on baseline mTLS and matches the mTLS-verified
    // identity against a subject allowlist plus a source-IP range.
    let bypass = passthrough::from_config(&config.proxy_bypass, mtls.is_some())
        .unwrap_or_else(|e| fatal(format!("invalid proxy_bypass config: {e}")));
    match &bypass {
        Some(_) => info!("attestation bypass enabled"),
        None => info!("attestation bypass disabled"),
    }

    let proxy = DenBrowserProxy::new(
        verifier,
        &config.proxy.upstream,
        args.insecure_upstream,
        rate_limiter,
        bypass,
        machine,
    )
    .unwrap_or_else(|e| fatal(e));

    // `None` leaves pingora's `daemon` flag false.  Keep it that way: the log
    // appender's writer thread would not survive a fork (see `logging`).
    let mut server =
        Server::new(None).unwrap_or_else(|e| fatal(format!("pingora init failed: {e}")));
    server.bootstrap();

    let mut svc = http_proxy_service(&server.configuration, proxy);

    // TLS-only listener.  Browsers verify the SPKI of `tls_cert` matches
    // a pin baked into the build (see DenBrowserAttest.cpp::kProxySpkiSha256),
    // so a local sniffer on this machine sees ciphertext and a captured
    // attestation token cannot be replayed from outside this TLS channel.
    let tls = match &mtls {
        // mTLS on: build the acceptor with the identity-recording callback and
        // hard-require a client cert — request one AND fail the handshake if it
        // is absent or does not chain to the configured CA.  A client without a
        // valid certificate never reaches the request path.
        Some(m) => {
            let mut tls = TlsSettings::with_callbacks(m.tls_callbacks())
                .unwrap_or_else(|e| fatal(format!("TLS callback setup failed: {e}")));
            tls.set_certificate_chain_file(&config.proxy.tls_cert)
                .unwrap_or_else(|e| {
                    fatal(format!("TLS cert load failed ({}): {e}", config.proxy.tls_cert))
                });
            tls.set_private_key_file(&config.proxy.tls_key, SslFiletype::PEM)
                .unwrap_or_else(|e| {
                    fatal(format!("TLS key load failed ({}): {e}", config.proxy.tls_key))
                });
            tls.set_ca_file(m.ca_path())
                .unwrap_or_else(|e| fatal(format!("mTLS CA load failed ({}): {e}", m.ca_path())));
            // Advertise the acceptable issuer(s) in the CertificateRequest.  The
            // call above populates only the *verification* store
            // (SSL_CTX_load_verify_locations) and leaves `certificate_authorities`
            // empty, which tells the client "any certificate will do".  A browser
            // whose store holds more than one client certificate then either
            // prompts with a picker or offers the wrong one — and the wrong one
            // fails the verification below, surfacing as a bare TLS error with no
            // diagnostic.  Naming the CA lets the client filter to one identity.
            for ca in m.ca_certs() {
                tls.add_client_ca(ca)
                    .unwrap_or_else(|e| fatal(format!("mTLS client CA list setup failed: {e}")));
            }
            tls.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            tls
        }
        // mTLS off: the original listener, unchanged — no client cert requested.
        None => TlsSettings::intermediate(&config.proxy.tls_cert, &config.proxy.tls_key)
            .unwrap_or_else(|e| {
                fatal(format!(
                    "TLS cert/key load failed ({}, {}): {e}",
                    config.proxy.tls_cert, config.proxy.tls_key
                ))
            }),
    };
    svc.add_tls_with_settings(&config.proxy.listen, None, tls);

    info!(
        "listening TLS on {} → {}",
        config.proxy.listen, config.proxy.upstream
    );
    server.add_service(svc);
    server.run_forever();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_without_query_strips_from_the_first_question_mark() {
        assert_eq!(path_without_query("/"), "/");
        assert_eq!(path_without_query("/search"), "/search");
        assert_eq!(path_without_query("/search?q=secret"), "/search");
        // A `?` in the query value must not resurrect the rest of it.
        assert_eq!(path_without_query("/a?b=1?2&token=shh"), "/a");
        // Empty query still drops the separator, so the line reads cleanly.
        assert_eq!(path_without_query("/a?"), "/a");
    }
}

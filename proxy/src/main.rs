use std::sync::Arc;

use async_trait::async_trait;
use clap::Parser;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::Server;
use pingora_core::tls::ssl::{SslAcceptor, SslMethod, SslVerifyMode};
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
mod tls_key;
mod upstream_tls;
use attest::{AttestInputs, BodyBinding, Verifier};
use config::Config;
use machine::MachineIdentity;
use mtls::ClientCert;
use passthrough::BypassPolicy;
use ratelimit::RateLimiter;
use upstream_tls::UpstreamTls;

/// Maximum bytes of a *bound* (hash-verified) request body.
///
/// A bound body is buffered and hashed in `request_filter` *before* the upstream
/// is ever contacted, so the backend never sees an unverified byte.  To forward
/// the body afterwards we rely on pingora's request retry buffer, which natively
/// replays it to the upstream — and that buffer is a `FixedBuffer` hardcoded to
/// `BODY_BUF_LIMIT` (64 KiB).  Past its capacity it marks itself truncated and,
/// since pingora 0.9.0, drops what it had buffered, so nothing can be replayed.
/// So the bound path is capped at exactly that limit: a bound request whose body
/// exceeds it is rejected with 413.  The browser is expected to send anything larger as
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
    upstream_tls: UpstreamTls,
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
        upstream_tls: UpstreamTls,
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
            upstream_tls,
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

    /// The single upstream, over TLS with HTTP/2 preferred.
    ///
    /// `PeerOptions` are otherwise left at pingora's defaults.  Two of those
    /// defaults changed in pingora 0.9.0 and were accepted deliberately:
    ///
    /// * `http_upstream_request_policy` strips hop-by-hop headers (`Connection`,
    ///   `TE`, `Keep-Alive`, `Upgrade`, …) and any header the client nominated
    ///   in `Connection:` before the request reaches `upstream_request_filter`,
    ///   and answers 400 to a `Connection` header that nominates a protected
    ///   name (`Host`, `X-Forwarded-*`), a non-token, or ten or more names.
    ///   That refusal comes *after* `request_filter` has accepted the request
    ///   and committed its nonce; browsers never send such headers.  The
    ///   attestation headers are end-to-end headers this policy never touches —
    ///   `upstream_request_filter` below remains what strips them.
    /// * `error_while_proxy` (not overridden here) never retries a request
    ///   whose method is not idempotent: a POST that fails on a reused upstream
    ///   connection is answered 502 instead of being replayed from the retry
    ///   buffer.  A transparent replay could deliver a side-effecting request to
    ///   the backend twice, and the browser mints a fresh token per request, so
    ///   a user-level retry is never a nonce replay.  GET and the other
    ///   idempotent methods are still retried once on a fresh connection.
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
        self.upstream_tls.apply(&mut peer);
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
    /// upstream on its own (on the first attempt only for a POST — see
    /// `upstream_peer`) — so there is no `request_body_filter` to override and
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
                let host = request_host(req).unwrap_or_default();
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

        // Machine-identity preflight.  A required missing header is as cheap to
        // reject as a missing attestation header, but defer all certificate
        // parsing, chain crypto, and DNS until the attestation token has passed.
        // This prevents a copied public machine certificate from making bogus
        // attestation traffic consume the more expensive machine path.
        let machine_cert = match &self.machine {
            None => None,
            Some(verifier) => {
                let presented = header_str(&session.req_header().headers, MACHINE_CERT_HEADER);
                match presented {
                    Some(cert_b64) => Some(cert_b64),
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

        let req = session.req_header();

        let ts = header_str(&req.headers, "x-denbrowser-ts");
        let nonce = header_str(&req.headers, "x-denbrowser-nonce");
        let token = header_str(&req.headers, "x-denbrowser-token");
        let host = request_host(req);

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

        // Machine identity: which workstation this came from.  Attestation has
        // now passed, but no request body has been read and no upstream has been
        // contacted.  A machine failure therefore still fails closed without
        // paying the body-buffering cost, while malformed attestation never
        // reaches certificate chain verification or DNS.
        //
        // The verified hostname is carried into the accept log below; it grants
        // nothing on its own.  See `machine` for what this does and does not
        // prove.
        let machine_host = match (&self.machine, machine_cert.as_deref()) {
            (Some(verifier), Some(cert_b64)) => match verifier.verify(cert_b64, client_ip).await {
                Ok(hostname) => Some(hostname),
                Err(e) => {
                    warn!("rejected — {e}");
                    let _ = session.respond_error(403).await;
                    return Ok(true);
                }
            },
            _ => None,
        };
        let machine_log = machine_host.as_deref().unwrap_or("-");

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

/// The host the browser bound into its token, with any `:port` removed.
///
/// Over HTTP/1.1 that is the `Host` header.  Over HTTP/2 the browser sends the
/// `:authority` pseudo-header and no `Host` at all; pingora surfaces it as the
/// request URI's authority.  Both come from the same URL on the browser side
/// (patch 006 signs the URL's host), so the token's `host` field matches
/// whichever protocol was negotiated.  pingora refuses a request that carries
/// both with different values before `request_filter` runs, so taking `Host`
/// first is safe.
fn request_host(req: &RequestHeader) -> Option<String> {
    let authority = header_str(&req.headers, "host")
        .or_else(|| req.uri.authority().map(|a| a.as_str().to_owned()))?;
    Some(authority.split(':').next().unwrap_or(&authority).to_owned())
}

/// Drop the query string from a path for logging.
///
/// The accept path logs one line per request that passed every check here
/// (pingora can still refuse a malformed `Connection` header afterwards, see
/// `upstream_peer`), so unlike the rejection logs it sees ordinary user traffic
/// in bulk — and query strings
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

    let upstream_tls = UpstreamTls::from_config(&config.proxy, args.insecure_upstream)
        .unwrap_or_else(|e| fatal(e));
    if !config.proxy.upstream_ca.is_empty() {
        info!(
            "upstream CA bundle loaded from {}",
            config.proxy.upstream_ca
        );
    }

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
        upstream_tls,
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
    //
    // The listener offers HTTP/2 with HTTP/1.1 as the fallback (ALPN
    // "h2, http/1.1"), the mirror image of `upstream_peer`'s
    // `set_http_version(2, 1)`.  The two legs negotiate independently and
    // pingora translates between them, so a browser on HTTP/2 can be fronted
    // for an HTTP/1.1-only upstream and vice versa.  Everything `request_filter`
    // checks is protocol-agnostic apart from where the host lives (see
    // `request_host`); the 64 KiB retry buffer that caps bound bodies exists
    // for both protocols.  One visible difference: an error response over
    // HTTP/2 resets only that stream, where over HTTP/1.1 it closes the
    // connection.
    //
    // The key is read and, when encrypted, decrypted here (see `tls_key`), then
    // installed as a key rather than a path: OpenSSL's path-based loader has no
    // way to be given a passphrase.
    let listener_key = tls_key::load(&config.proxy).unwrap_or_else(|e| fatal(e));
    // Both arms start from the Mozilla-intermediate acceptor that
    // `TlsSettings::intermediate` builds, without its path-based key loading;
    // mTLS adds the callback that records the verified client identity.
    let mut tls = match &mtls {
        Some(m) => TlsSettings::with_callbacks(m.tls_callbacks())
            .unwrap_or_else(|e| fatal(format!("TLS callback setup failed: {e}"))),
        None => SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
            .map(TlsSettings::from)
            .unwrap_or_else(|e| fatal(format!("TLS acceptor setup failed: {e}"))),
    };
    tls.set_certificate_chain_file(&config.proxy.tls_cert)
        .unwrap_or_else(|e| {
            fatal(format!("TLS cert load failed ({}): {e}", config.proxy.tls_cert))
        });
    // Installed after the certificate, so OpenSSL checks the two belong
    // together; the explicit check also catches a key of a different type,
    // which OpenSSL would otherwise accept and leave the listener failing every
    // handshake.
    tls.set_private_key(&listener_key)
        .and_then(|()| tls.check_private_key())
        .unwrap_or_else(|e| {
            fatal(format!(
                "TLS key load failed ({}): {e} — is it the private key for {}?",
                config.proxy.tls_key, config.proxy.tls_cert
            ))
        });
    // mTLS on: hard-require a client cert — request one AND fail the handshake
    // if it is absent or does not chain to the configured CA.  A client without
    // a valid certificate never reaches the request path.  mTLS off: no client
    // certificate is requested.
    if let Some(m) = &mtls {
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
    }
    // TLS session resumption.  OpenSSL resumes a session on a context that
    // verifies client certificates only if the application has set a
    // session-ID context: the tag stored in every session that stops a session
    // established under one verification policy from being resumed under
    // another.  Without it, every resumption attempt by a client that cached a
    // session (Firefox does, for TLS 1.3 tickets and TLS 1.2 session IDs)
    // fails the handshake with "session id context uninitialized" and costs a
    // second, full handshake plus an error line here.  Set unconditionally so
    // the behaviour does not depend on whether mTLS is on.
    //
    // What resumption means for mTLS: a resumed handshake does not re-verify
    // the client certificate.  `mtls::Recorder` still runs and records the
    // identity from the certificate stored in the session, which was verified
    // at the full handshake.  Sessions and tickets live for OpenSSL's default
    // 7200 s, there is no 0-RTT early data, and a restart clears every session
    // and the ticket key.  The proxy performs no revocation checking, so
    // nothing checked at a full handshake goes unchecked on a resumed one,
    // except expiry inside that window.
    tls.set_session_id_context(b"denbrowser-proxy")
        .unwrap_or_else(|e| fatal(format!("TLS session-ID context setup failed: {e}")));
    tls.enable_h2();
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

    // ── Pins on the pingora behaviour the proxy depends on ──────────────────
    //
    // These exercise the real `ProxyHttp` impl over an in-memory HTTP/1.1
    // session, so a future pingora bump that moves any of them fails here
    // rather than in production.  Each one records a decision taken when
    // moving to pingora 0.9.0 (see docs/pingora-0.9.0-upgrade-review.md).

    use pingora_core::protocols::l4::stream::Stream as L4Stream;
    use pingora_core::protocols::l4::virt::{VirtualSockOpt, VirtualSocket, VirtualSocketStream};
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// A socket that serves one canned request and keeps whatever is written
    /// back, so the bytes a client would receive can be asserted on.
    #[derive(Debug)]
    struct MemSocket {
        request: Vec<u8>,
        read_pos: usize,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncRead for MemSocket {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let n = (self.request.len() - self.read_pos).min(buf.remaining());
            if n > 0 {
                let start = self.read_pos;
                buf.put_slice(&self.request[start..start + n]);
                self.read_pos += n;
            }
            // Exhausted: a clean EOF, as a client that has sent everything.
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MemSocket {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl VirtualSocket for MemSocket {
        fn set_socket_option(&self, _opt: VirtualSockOpt) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// An HTTP/1.1 downstream session with `request` already parsed, plus the
    /// buffer the proxy's response lands in.
    async fn h1_session(request: &str) -> (Session, Arc<Mutex<Vec<u8>>>) {
        let written = Arc::new(Mutex::new(Vec::new()));
        let socket = MemSocket {
            request: request.as_bytes().to_vec(),
            read_pos: 0,
            written: written.clone(),
        };
        let stream = L4Stream::from(VirtualSocketStream::new(Box::new(socket)));
        let mut session = Session::new_h1(Box::new(stream));
        session.read_request().await.unwrap();
        (session, written)
    }

    /// A proxy with attestation only: no rate limit, bypass or machine layer.
    /// The key is a throwaway — none of these tests presents a token.
    fn test_proxy() -> DenBrowserProxy {
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
            .unwrap();
        let pem = openssl::ec::EcKey::generate(&group)
            .unwrap()
            .private_key_to_pem()
            .unwrap();
        let verifier = Verifier::from_pem(std::str::from_utf8(&pem).unwrap()).unwrap();
        DenBrowserProxy::new(verifier, "upstream.internal:443", false, None, None, None).unwrap()
    }

    #[tokio::test]
    async fn pingora_retries_idempotent_methods_only() {
        // Decision 1 of the 0.9.0 review: the default `error_while_proxy` is
        // kept.  A POST that fails on a reused upstream connection must not be
        // replayed; GET and PUT still get one retry on a fresh connection.
        let proxy = test_proxy();
        let peer = HttpPeer::new("127.0.0.1:443", true, "upstream.internal".to_owned());
        for (method, retried) in [("GET", true), ("PUT", true), ("POST", false), ("PATCH", false)] {
            let request = format!(
                "{method} / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
            );
            let (mut session, _) = h1_session(&request).await;
            let mut error = pingora_core::Error::new_up(pingora_core::ErrorType::ReadError);
            error.retry = pingora_core::RetryType::Decided(true);
            let decided = proxy.error_while_proxy(&peer, &mut session, error, &mut (), true);
            assert_eq!(decided.retry(), retried, "{method}");
        }
    }

    #[test]
    fn request_target_forms_bind_path_and_query_only() {
        // Decision 2: `request_filter` binds `req.uri.path_and_query()` into
        // the token (and keys the rate limiter on it).  Since pingora 0.9.0 an
        // absolute-form target yields only its path and query, which is what
        // the browser signs; origin-form is unchanged and fragments are dropped.
        let bound = |target: &[u8]| -> String {
            let req = RequestHeader::build("GET", target, None).unwrap();
            req.uri
                .path_and_query()
                .map(|p| p.as_str().to_owned())
                .unwrap_or_else(|| "/".to_owned())
        };
        assert_eq!(bound(b"/p?q=1"), "/p?q=1");
        assert_eq!(bound(b"https://proxy.example:8081/p?q=1"), "/p?q=1");
        assert_eq!(bound(b"http://proxy.example"), "/");
        assert_eq!(bound(b"/p?q=1#frag"), "/p?q=1");
    }

    #[test]
    fn request_host_reads_the_host_header_or_the_h2_authority() {
        // HTTP/1.1: the Host header, port stripped.
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("Host", "proxy.example:8081").unwrap();
        assert_eq!(request_host(&req).as_deref(), Some("proxy.example"));
        req.insert_header("Host", "proxy.example").unwrap();
        assert_eq!(request_host(&req).as_deref(), Some("proxy.example"));

        // HTTP/2: no Host header; the authority rides on the request URI.
        let mut req = RequestHeader::build("GET", b"/p?q=1", None).unwrap();
        req.set_uri("https://proxy.example:8081/p?q=1".parse().unwrap());
        assert!(req.headers.get("host").is_none());
        assert_eq!(request_host(&req).as_deref(), Some("proxy.example"));
        // The path binding is unaffected by where the host came from.
        assert_eq!(req.uri.path_and_query().unwrap().as_str(), "/p?q=1");

        // Neither: nothing to bind, so attestation fails closed.
        let req = RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(request_host(&req), None);
    }

    #[tokio::test]
    async fn upstream_request_filter_strips_every_attestation_header() {
        // The one guarantee of `upstream_request_filter`: no attestation
        // material reaches the backend, whatever case the client used.
        let proxy = test_proxy();
        let (mut session, _) = h1_session("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
        let mut upstream = RequestHeader::build("GET", b"/", None).unwrap();
        for (name, value) in [
            ("X-DENBROWSER-TS", "1"),
            ("x-denbrowser-nonce", "n"),
            ("X-DenBrowser-Token", "t"),
            ("X-Denbrowser-Machine-Cert", "c"),
            ("X-Keep", "k"),
        ] {
            upstream.insert_header(name, value).unwrap();
        }
        proxy
            .upstream_request_filter(&mut session, &mut upstream, &mut ())
            .await
            .unwrap();
        for name in [
            "x-denbrowser-ts",
            "x-denbrowser-nonce",
            "x-denbrowser-token",
            "x-denbrowser-machine-cert",
        ] {
            assert!(upstream.headers.get(name).is_none(), "{name} reached the upstream");
        }
        assert_eq!(upstream.headers.get("x-keep").unwrap(), "k");
    }

    #[tokio::test]
    async fn a_request_without_attestation_headers_gets_403_and_close() {
        // The error-response shape stress/README.md and the browser rely on:
        // answered by the proxy itself, with the connection closed.
        let proxy = test_proxy();
        let (mut session, written) =
            h1_session("GET /secret?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
        let handled = proxy.request_filter(&mut session, &mut ()).await.unwrap();
        assert!(handled, "request_filter must answer the client itself");
        let response = String::from_utf8_lossy(&written.lock().unwrap()).to_ascii_lowercase();
        assert!(response.starts_with("http/1.1 403 "), "{response}");
        assert!(response.contains("connection: close"), "{response}");
        assert!(response.contains("content-length: 0"), "{response}");
    }
}

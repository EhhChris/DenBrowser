use std::sync::Arc;

use async_trait::async_trait;
use clap::Parser;
use log::{info, warn};
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::RequestHeader;
use pingora_proxy::{http_proxy_service, ProxyHttp, Session};
use sha2::{Digest, Sha256};

mod attest;
mod config;
mod ratelimit;
use attest::{AttestInputs, BodyBinding, Verifier};
use config::Config;
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

#[derive(Parser, Debug)]
#[command(about = "DenBrowser attestation proxy — verifies ECIES tokens, strips headers, forwards")]
struct Args {
    /// Address to listen on
    #[arg(long, env = "DENBROWSER_LISTEN", default_value = "0.0.0.0:8081")]
    listen: String,

    /// Upstream address to forward verified requests to (host:port)
    #[arg(long, env = "DENBROWSER_UPSTREAM")]
    upstream: String,

    /// Path to the EC P-256 attestation private key PEM file.
    /// (Separate from the TLS server key below — this one decrypts
    /// per-request attestation tokens.)
    #[arg(long, env = "DENBROWSER_KEY", default_value = "../build/proxy-private.pem")]
    key: String,

    /// Path to the TLS server certificate (PEM).  The browser pins this
    /// cert's SPKI; rotating the cert requires rebuilding DenBrowser with
    /// the new pin.
    #[arg(long, env = "DENBROWSER_TLS_CERT", default_value = "../build/proxy-tls.crt")]
    cert: String,

    /// Path to the TLS server private key (PEM).
    #[arg(long, env = "DENBROWSER_TLS_KEY", default_value = "../build/proxy-tls.key")]
    tls_key: String,

    /// DEV ONLY: skip TLS certificate and hostname verification of the
    /// upstream, allowing self-signed local upstreams.  Never enable in
    /// production — it removes the guarantee that the proxy is talking to the
    /// intended upstream and not a MITM.
    #[arg(long, env = "DENBROWSER_INSECURE_UPSTREAM", default_value_t = false)]
    insecure_upstream: bool,

    /// Path to the operational TOML config file (rate limiting, and future
    /// runtime options).  Optional — with no config file every gated feature
    /// stays off and the proxy behaves as it did before configs existed.
    #[arg(long, env = "DENBROWSER_CONFIG")]
    config: Option<String>,
}

struct DenBrowserProxy {
    verifier: Arc<Verifier>,
    upstream_host: String,
    upstream_port: u16,
    insecure_upstream: bool,
    /// `None` when rate limiting is disabled (no config or `enabled = false`).
    rate_limiter: Option<RateLimiter>,
}

impl DenBrowserProxy {
    fn new(
        verifier: Verifier,
        upstream: &str,
        insecure_upstream: bool,
        rate_limiter: Option<RateLimiter>,
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
        // Rate limiting runs *before* attestation so a flood from one IP is shed
        // cheaply here — it never reaches the crypto path or the upstream.  The
        // counter is keyed on the origin IP and the rule glob is matched against
        // `host + path`, so per-URL-pattern limits work even on requests that
        // would later fail attestation.
        if let Some(limiter) = &self.rate_limiter {
            // Owned copy so the immutable borrow of `session` ends before the
            // (mutable) `respond_error` below.
            let client_ip = session.client_addr().and_then(|a| a.as_inet()).map(|s| s.ip());
            // Enforce only when we have an IP to key on (always true for a
            // TCP/TLS client); otherwise fail open rather than throttle blindly.
            if let Some(ip) = client_ip {
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
        }

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
        Ok(())
    }
}

fn header_str(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers.get(name)?.to_str().ok().map(|s| s.to_owned())
}

fn main() {
    env_logger::init();
    let args = Args::parse();

    let pem = std::fs::read_to_string(&args.key)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", args.key, e));
    let verifier = Verifier::from_pem(&pem)
        .unwrap_or_else(|e| panic!("cannot parse key {}: {}", args.key, e));
    if args.insecure_upstream {
        warn!(
            "INSECURE: upstream TLS verification disabled (--insecure-upstream) — \
             for local testing only, never production"
        );
    }

    let config = match &args.config {
        Some(path) => Config::load(path).unwrap_or_else(|e| panic!("{e}")),
        None => Config::default(),
    };
    let rate_limiter = RateLimiter::from_config(&config.rate_limiting)
        .unwrap_or_else(|e| panic!("invalid rate_limiting config: {e}"));
    match &rate_limiter {
        Some(_) => info!("rate limiting enabled"),
        None => info!("rate limiting disabled"),
    }

    let proxy = DenBrowserProxy::new(
        verifier,
        &args.upstream,
        args.insecure_upstream,
        rate_limiter,
    )
    .unwrap_or_else(|e| panic!("{e}"));

    let mut server = Server::new(None).expect("Pingora server init failed");
    server.bootstrap();

    let mut svc = http_proxy_service(&server.configuration, proxy);

    // TLS-only listener.  Browsers verify the SPKI of `args.cert` matches
    // a pin baked into the build (see DenBrowserAttest.cpp::kProxySpkiSha256),
    // so a local sniffer on this machine sees ciphertext and a captured
    // attestation token cannot be replayed from outside this TLS channel.
    let tls = TlsSettings::intermediate(&args.cert, &args.tls_key)
        .unwrap_or_else(|e| panic!("TLS cert/key load failed ({}, {}): {e}",
                                   args.cert, args.tls_key));
    svc.add_tls_with_settings(&args.listen, None, tls);

    info!("listening TLS on {} → {}", args.listen, args.upstream);
    server.add_service(svc);
    server.run_forever();
}

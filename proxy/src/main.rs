use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
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
use attest::{AttestInputs, Verifier};

/// Maximum bytes of request body we are willing to buffer for verification.
/// Anything larger is rejected with 413.  Adjust per deployment if the upstream
/// legitimately accepts very large uploads.
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

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
}

struct DenBrowserProxy {
    verifier: Arc<Verifier>,
    upstream_host: String,
    upstream_port: u16,
    insecure_upstream: bool,
}

impl DenBrowserProxy {
    fn new(verifier: Verifier, upstream: &str, insecure_upstream: bool) -> anyhow::Result<Self> {
        let (host, port_str) = upstream
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("upstream must be host:port, got {upstream:?}"))?;
        let port: u16 = port_str.parse()?;
        Ok(Self {
            verifier: Arc::new(verifier),
            upstream_host: host.to_owned(),
            upstream_port: port,
            insecure_upstream,
        })
    }
}

/// Per-request state.  Both verification phases run in `request_filter`,
/// before the upstream is ever contacted.  The fully-verified request body is
/// stashed here and handed to the upstream by `request_body_filter`.
#[derive(Default)]
pub struct ProxyCtx {
    verified_body: Vec<u8>,
    body_emitted: bool,
}

#[async_trait]
impl ProxyHttp for DenBrowserProxy {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        ProxyCtx::default()
    }

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

    /// Verify the request completely — headers (phase 1) *and* body (phase 2)
    /// — before the upstream is ever contacted.  Any failure answers the client
    /// here and returns `Ok(true)`, so pingora never opens the upstream
    /// connection: the backend only ever sees requests that passed both phases
    /// and needs no awareness of attestation at all.
    ///
    /// The whole request body is buffered and hashed here (bounded by
    /// `MAX_BODY_BYTES`).  Verifying before forwarding — rather than streaming
    /// the body upstream and checking as it goes — is what guarantees a
    /// tampered or unattested request cannot reach the backend at all.  The
    /// verified body is stashed in `ctx` and emitted upstream by
    /// `request_body_filter`.
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
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

        // Phase 2 — buffer and hash the entire body, then verify it.  Reading
        // the body here (before `upstream_peer`) drains the downstream stream;
        // `request_body_filter` replays the buffered bytes to the upstream once
        // verification has passed.
        let mut hasher = Sha256::new();
        let mut body = Vec::new();
        loop {
            match session.read_request_body().await {
                Ok(Some(chunk)) => {
                    if body.len() + chunk.len() > MAX_BODY_BYTES {
                        warn!("rejected — request body exceeds {MAX_BODY_BYTES} bytes (DoS guard)");
                        let _ = session.respond_error(413).await;
                        return Ok(true);
                    }
                    hasher.update(&chunk);
                    body.extend_from_slice(&chunk);
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

        // Fully verified: forward it.  Hand the buffered body to
        // `request_body_filter` for emission to the upstream.
        ctx.verified_body = body;
        Ok(false)
    }

    /// Emit the already-verified request body to the upstream.
    ///
    /// The body was read and verified in `request_filter` before the upstream
    /// was contacted, so the downstream stream is drained and pingora hands us
    /// no data here — it calls this once at end-of-stream.  We replay the
    /// buffered bytes in one shot; a bodyless request emits nothing.
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        *body = None;
        if end_of_stream && !ctx.body_emitted {
            let buf = std::mem::take(&mut ctx.verified_body);
            if !buf.is_empty() {
                *body = Some(Bytes::from(buf));
            }
            ctx.body_emitted = true;
        }
        Ok(())
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
    let proxy = DenBrowserProxy::new(verifier, &args.upstream, args.insecure_upstream)
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

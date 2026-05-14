use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use clap::Parser;
use log::{info, warn};
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{Error, ErrorType, Result};
use pingora_http::RequestHeader;
use pingora_proxy::{http_proxy_service, ProxyHttp, Session};
use sha2::{Digest, Sha256};

mod attest;
use attest::{AttestInputs, PhaseOne, Verifier};

/// Maximum bytes of request body we are willing to buffer for verification.
/// Anything larger is rejected with 413.  Adjust per deployment if the upstream
/// legitimately accepts very large uploads.
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

#[derive(Parser, Debug)]
#[command(about = "ZeroFox attestation proxy — verifies ECIES tokens, strips headers, forwards")]
struct Args {
    /// Address to listen on
    #[arg(long, env = "ZEROFOX_LISTEN", default_value = "0.0.0.0:8081")]
    listen: String,

    /// Upstream address to forward verified requests to (host:port)
    #[arg(long, env = "ZEROFOX_UPSTREAM")]
    upstream: String,

    /// Path to the EC P-256 attestation private key PEM file.
    /// (Separate from the TLS server key below — this one decrypts
    /// per-request attestation tokens.)
    #[arg(long, env = "ZEROFOX_KEY", default_value = "../build/proxy-private.pem")]
    key: String,

    /// Path to the TLS server certificate (PEM).  The browser pins this
    /// cert's SPKI; rotating the cert requires rebuilding ZeroFox with
    /// the new pin.
    #[arg(long, env = "ZEROFOX_TLS_CERT", default_value = "../build/proxy-tls.crt")]
    cert: String,

    /// Path to the TLS server private key (PEM).
    #[arg(long, env = "ZEROFOX_TLS_KEY", default_value = "../build/proxy-tls.key")]
    tls_key: String,
}

struct ZeroFoxProxy {
    verifier: Arc<Verifier>,
    upstream_host: String,
    upstream_port: u16,
}

impl ZeroFoxProxy {
    fn new(verifier: Verifier, upstream: &str) -> anyhow::Result<Self> {
        let (host, port_str) = upstream
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("upstream must be host:port, got {upstream:?}"))?;
        let port: u16 = port_str.parse()?;
        Ok(Self {
            verifier: Arc::new(verifier),
            upstream_host: host.to_owned(),
            upstream_port: port,
        })
    }
}

/// Per-request state.  Phase 1 (header verify) runs in `request_filter`;
/// phase 2 (body verify) runs in `request_body_filter` once all chunks have
/// been buffered.
#[derive(Default)]
pub struct ProxyCtx {
    phase_one: Option<PhaseOne>,
    body_buffer: Vec<u8>,
    body_hasher: Sha256,
    body_emitted: bool,
}

#[async_trait]
impl ProxyHttp for ZeroFoxProxy {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        ProxyCtx::default()
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(
            (self.upstream_host.as_str(), self.upstream_port),
            false,
            String::new(),
        )))
    }

    /// Phase 1.  Validate every attestation field except the body hash;
    /// short-circuit with 403 on any failure.  The body hash is checked in
    /// `request_body_filter` once the body has streamed in.
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
        let req = session.req_header();

        let ts = header_str(&req.headers, "x-zerofox-ts");
        let nonce = header_str(&req.headers, "x-zerofox-nonce");
        let token = header_str(&req.headers, "x-zerofox-token");
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

        let inputs = AttestInputs {
            ts: &ts,
            nonce_b64: &nonce,
            token_b64: &token,
            host: &host,
            method: &method,
            path: &path,
        };

        match self.verifier.verify_headers(&inputs) {
            Ok(p1) => {
                ctx.phase_one = Some(p1);
                Ok(false)
            }
            Err(e) => {
                warn!("rejected — {e} (host={host} {method} {path})");
                let _ = session.respond_error(403).await;
                Ok(true)
            }
        }
    }

    /// Phase 2.  Buffer body chunks (suppressing them from upstream), hash on
    /// the fly, then at end-of-stream verify against the expected hash and
    /// emit the buffered body for upstream forwarding.
    ///
    /// Trade-off: the upstream connection is opened and request headers are
    /// sent before body verification completes.  Upstream sees no body bytes
    /// until verification passes; on failure the connection is aborted before
    /// any body reaches upstream.  For services that act only after receiving
    /// a full body (the common case) this is equivalent to a 403.
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(chunk) = body.as_ref() {
            if ctx.body_buffer.len() + chunk.len() > MAX_BODY_BYTES {
                warn!(
                    "rejected — request body exceeds {MAX_BODY_BYTES} bytes (DoS guard)"
                );
                return Err(Error::explain(
                    ErrorType::HTTPStatus(413),
                    "request body too large",
                ));
            }
            ctx.body_hasher.update(chunk);
            ctx.body_buffer.extend_from_slice(chunk);
        }

        // Suppress every chunk while we accumulate; we'll emit the verified
        // buffer in one shot at end-of-stream.
        *body = None;

        if end_of_stream {
            let actual: [u8; 32] = ctx.body_hasher.clone().finalize().into();
            let p1 = ctx
                .phase_one
                .as_ref()
                .expect("request_body_filter without successful request_filter");

            if let Err(e) = self.verifier.verify_body_and_commit(p1, &actual) {
                warn!("rejected — {e}");
                return Err(Error::explain(
                    ErrorType::HTTPStatus(403),
                    "attestation body verification failed",
                ));
            }

            if !ctx.body_emitted {
                let buf = std::mem::take(&mut ctx.body_buffer);
                if !buf.is_empty() {
                    *body = Some(Bytes::from(buf));
                }
                ctx.body_emitted = true;
            }
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
        upstream_request.remove_header("x-zerofox-ts");
        upstream_request.remove_header("x-zerofox-nonce");
        upstream_request.remove_header("x-zerofox-token");
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
    let proxy =
        ZeroFoxProxy::new(verifier, &args.upstream).unwrap_or_else(|e| panic!("{e}"));

    let mut server = Server::new(None).expect("Pingora server init failed");
    server.bootstrap();

    let mut svc = http_proxy_service(&server.configuration, proxy);

    // TLS-only listener.  Browsers verify the SPKI of `args.cert` matches
    // a pin baked into the build (see ZeroFoxAttest.cpp::kProxySpkiSha256),
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

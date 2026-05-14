use std::sync::Arc;

use async_trait::async_trait;
use clap::Parser;
use log::{info, warn};
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_http::RequestHeader;
use pingora_proxy::{http_proxy_service, ProxyHttp, Session};

mod attest;
use attest::Verifier;

#[derive(Parser, Debug)]
#[command(about = "ZeroFox attestation proxy — verifies ECIES tokens, strips headers, forwards")]
struct Args {
    /// Address to listen on
    #[arg(long, env = "ZEROFOX_LISTEN", default_value = "0.0.0.0:8081")]
    listen: String,

    /// Upstream address to forward verified requests to (host:port)
    #[arg(long, env = "ZEROFOX_UPSTREAM")]
    upstream: String,

    /// Path to the EC P-256 private key PEM file
    #[arg(long, env = "ZEROFOX_KEY", default_value = "../build/proxy-private.pem")]
    key: String,
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

#[async_trait]
impl ProxyHttp for ZeroFoxProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

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

    /// Verify attestation headers.  Returns early with 403 on any failure;
    /// otherwise lets Pingora continue to upstream_request_filter.
    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<bool> {
        let headers = &session.req_header().headers;

        let ts = header_str(headers, "x-zerofox-ts");
        let token = header_str(headers, "x-zerofox-token");
        let host = header_str(headers, "host")
            .map(|h| h.split(':').next().unwrap_or(&h).to_owned());

        let (ts_val, token_val) = match (ts, token) {
            (Some(t), Some(tok)) => (t, tok),
            _ => {
                warn!(
                    "rejected — missing attestation headers (host={})",
                    host.as_deref().unwrap_or("?")
                );
                let _ = session.respond_error(403).await;
                return Ok(true);
            }
        };

        let host_val = host.unwrap_or_default();
        if let Err(e) = self.verifier.verify(&ts_val, &token_val, &host_val) {
            warn!("rejected — {e} (host={host_val})");
            let _ = session.respond_error(403).await;
            return Ok(true);
        }

        Ok(false)
    }

    /// Strip attestation headers from the request forwarded upstream.
    /// Only called when request_filter returned Ok(false), i.e. verification passed.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request.remove_header("x-zerofox-ts");
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
    let proxy = ZeroFoxProxy::new(verifier, &args.upstream)
        .unwrap_or_else(|e| panic!("{e}"));

    let mut server = Server::new(None).expect("Pingora server init failed");
    server.bootstrap();

    let mut svc = http_proxy_service(&server.configuration, proxy);
    svc.add_tcp(&args.listen);

    info!("listening on {} → {}", args.listen, args.upstream);
    server.add_service(svc);
    server.run_forever();
}

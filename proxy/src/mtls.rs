//! Baseline mutual-TLS client authentication.
//!
//! When `[mtls]` is enabled the listener *requires* every client to present a
//! certificate chaining to the configured CA (see [`crate::config::MtlsConfig`]).
//! Enforcement is done by OpenSSL at the handshake itself
//! (`SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT` against the CA store set
//! on the acceptor in `main`), so a client with no certificate or an untrusted
//! one is rejected before it ever reaches the request path.
//!
//! This module supplies the other half: a [`TlsAccept`] callback that runs
//! *after* a successful handshake and records the verified peer's identity
//! (Common Name + SubjectAltName DNS entries) into the connection's TLS digest
//! as a [`ClientCert`].  Because the handshake already enforced validity, the
//! callback does not re-verify — it only extracts the identity so the request
//! path can read it (for logging, and for the bypass subject allowlist).
//!
//! mTLS is one orthogonal layer among three: it authenticates the *user/device*
//! (client → proxy), TLS SPKI pinning authenticates the *proxy* to the browser
//! (proxy → client), and attestation proves the request came from a genuine
//! DenBrowser build and binds it against replay/tampering.  None replaces
//! another.

use std::any::Any;
use std::sync::Arc;

use async_trait::async_trait;
use pingora_core::listeners::{TlsAccept, TlsAcceptCallbacks};
use pingora_core::tls::nid::Nid;
use pingora_core::tls::ssl::SslRef;
use pingora_core::tls::x509::{X509, X509Ref};

use crate::config::MtlsConfig;

/// The verified identity of a connection's mTLS client certificate, attached to
/// the TLS digest by [`Recorder`] and read back in the request path via
/// `SslDigestExtension::get::<ClientCert>()`.
#[derive(Debug, Clone)]
pub struct ClientCert {
    /// Subject Common Name, if the cert carries one.
    pub common_name: Option<String>,
    /// SubjectAltName DNS entries, in certificate order.
    pub san_dns: Vec<String>,
}

impl ClientCert {
    /// The first identity — Common Name preferred, then SAN DNS names — that
    /// appears in `allowed`, or `None` if none match.
    pub fn matched<'a>(&'a self, allowed: &[String]) -> Option<&'a str> {
        if let Some(cn) = &self.common_name
            && allowed.iter().any(|a| a == cn)
        {
            return Some(cn);
        }
        self.san_dns
            .iter()
            .find(|san| allowed.iter().any(|a| a == *san))
            .map(String::as_str)
    }

    /// Extract the identity from a verified peer certificate.
    fn from_cert(cert: &X509Ref) -> Self {
        let common_name = cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|s| s.to_string());

        let san_dns = cert
            .subject_alt_names()
            .map(|names| {
                names
                    .iter()
                    .filter_map(|n| n.dnsname().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();

        ClientCert {
            common_name,
            san_dns,
        }
    }
}

/// TLS accept callback that records the verified client identity into the
/// digest.  Carries no state — validity was already enforced at the handshake.
struct Recorder;

#[async_trait]
impl TlsAccept for Recorder {
    async fn handshake_complete_callback(
        &self,
        ssl: &SslRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        // The handshake only reaches here after OpenSSL verified the peer cert
        // against the configured CA (hard mTLS), so a present cert is a valid
        // one.  We just surface its identity to the request path.
        let cert = ssl.peer_certificate()?;
        Some(Arc::new(ClientCert::from_cert(&cert)))
    }
}

/// Baseline mTLS settings, built once at startup.  Holds the CA path so `main`
/// can load it into the acceptor's trust store, the parsed CA certificates so
/// `main` can advertise them as acceptable issuers, and produces the
/// [`TlsAccept`] callbacks that record client identity.
pub struct Mtls {
    ca_path: String,
    ca_certs: Vec<X509>,
}

impl Mtls {
    /// Parse and validate `[mtls]`.  Returns `None` when disabled, or an error
    /// (missing/unreadable/empty CA bundle) that aborts startup rather than
    /// bringing up a listener that would reject every client.
    pub fn from_config(cfg: &MtlsConfig) -> anyhow::Result<Option<Self>> {
        if !cfg.enabled {
            return Ok(None);
        }
        if cfg.client_ca.is_empty() {
            anyhow::bail!("mtls is enabled but client_ca is not set");
        }
        // Parsed up front for a clear error, and kept: `main` loads the same
        // file into the acceptor's verification store via set_ca_file, and
        // advertises these certificates as acceptable issuers via add_client_ca.
        let pem = std::fs::read(&cfg.client_ca)
            .map_err(|e| anyhow::anyhow!("cannot read mtls client_ca {}: {e}", cfg.client_ca))?;
        let cas = X509::stack_from_pem(&pem)
            .map_err(|e| anyhow::anyhow!("cannot parse mtls client_ca {}: {e}", cfg.client_ca))?;
        if cas.is_empty() {
            anyhow::bail!("mtls client_ca {} contains no certificates", cfg.client_ca);
        }
        Ok(Some(Self {
            ca_path: cfg.client_ca.clone(),
            ca_certs: cas,
        }))
    }

    /// Path to the CA bundle to install as the client-cert trust store.
    pub fn ca_path(&self) -> &str {
        &self.ca_path
    }

    /// The parsed CA certificates, for advertising as acceptable issuers in the
    /// TLS `CertificateRequest` (see `main`).
    pub fn ca_certs(&self) -> &[X509] {
        &self.ca_certs
    }

    /// TLS accept callbacks that record the verified client identity.
    pub fn tls_callbacks(&self) -> TlsAcceptCallbacks {
        Box::new(Recorder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(cn: Option<&str>, sans: &[&str]) -> ClientCert {
        ClientCert {
            common_name: cn.map(str::to_owned),
            san_dns: sans.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn matched_prefers_cn() {
        let c = cert(Some("health-checker"), &["ops.internal"]);
        assert_eq!(c.matched(&["health-checker".into()]), Some("health-checker"));
    }

    #[test]
    fn matched_falls_back_to_san() {
        let c = cert(Some("unlisted-cn"), &["www.example.com", "ops.internal"]);
        assert_eq!(c.matched(&["ops.internal".into()]), Some("ops.internal"));
    }

    #[test]
    fn matched_returns_none_when_nothing_listed() {
        let c = cert(Some("cn"), &["a", "b"]);
        assert_eq!(c.matched(&["trusted".into()]), None);
        assert_eq!(cert(None, &[]).matched(&["x".into()]), None);
    }

    #[test]
    fn from_config_disabled_is_none() {
        assert!(Mtls::from_config(&MtlsConfig::default()).unwrap().is_none());
    }

    #[test]
    fn from_config_enabled_requires_ca() {
        let cfg = MtlsConfig {
            enabled: true,
            client_ca: String::new(),
        };
        assert!(Mtls::from_config(&cfg).is_err());
    }

    #[test]
    fn from_config_rejects_missing_ca_file() {
        let cfg = MtlsConfig {
            enabled: true,
            client_ca: "/nonexistent/ca.pem".into(),
        };
        assert!(Mtls::from_config(&cfg).is_err());
    }
}

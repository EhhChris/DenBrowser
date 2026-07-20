//! Attestation bypass ("proxy pass-through") for strongly authenticated callers.
//!
//! Some trusted infrastructure (health checks, internal automation) can't run
//! the DenBrowser attestation client but still needs to reach the upstream
//! through this proxy.  This module lets such callers skip attestation *only*
//! when they prove themselves two independent ways, both configured in
//! `[proxy_bypass]` (see [`crate::config`]):
//!
//! 1. **Source IP** — the client address is inside one of the configured CIDR
//!    ranges (checked in the request handler, see [`IpPolicy`]); and
//! 2. **Client certificate** — during the TLS handshake the client presented a
//!    certificate that chains to the configured CA *and* whose subject is on the
//!    allowlist (checked here, in [`CertVerifier`], during
//!    `handshake_complete_callback`).
//!
//! The design is **fail-open toward attestation, never toward bypass**: the TLS
//! listener only *requests* a client cert (it never requires one), and a soft
//! verify callback keeps the handshake alive even for absent or invalid certs —
//! so ordinary attestation clients, and bypass clients whose cert is wrong, are
//! never disconnected.  They simply don't get the [`BypassCred`] marker, and the
//! handler routes them through normal attestation.  A request is bypassed only
//! when *both* checks pass; anything else is attested as usual.

use std::any::Any;
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use ipnet::IpNet;
use log::warn;
use pingora_core::listeners::{TlsAccept, TlsAcceptCallbacks};
use pingora_core::tls::nid::Nid;
use pingora_core::tls::ssl::SslRef;
use pingora_core::tls::x509::store::X509StoreBuilder;
use pingora_core::tls::x509::{X509StoreContext, X509};

use crate::config::ProxyBypassConfig;

/// Proof, attached to a connection's TLS digest by [`CertVerifier`], that the
/// peer presented a client certificate which chained to the configured CA and
/// matched the subject allowlist.  Its mere presence authorizes the certificate
/// half of the bypass; `subject` is kept for logging.
///
/// Stored as `Arc<dyn Any + Send + Sync>` in the digest and read back by the
/// handler via `SslDigestExtension::get::<BypassCred>()`.
#[derive(Debug, Clone)]
pub struct BypassCred {
    pub subject: String,
}

/// The source-IP half of the bypass policy, consulted per request in the
/// handler.  (The certificate half lives in the TLS layer.)
pub struct IpPolicy {
    ranges: Vec<IpNet>,
}

impl IpPolicy {
    /// True if `ip` falls inside any configured range.
    pub fn allows(&self, ip: &IpAddr) -> bool {
        self.ranges.iter().any(|net| net.contains(ip))
    }
}

/// TLS accept callback that verifies a presented client certificate against the
/// configured CA and subject allowlist, without ever failing the handshake.
struct CertVerifier {
    ca_certs: Vec<X509>,
    allowed_subjects: Vec<String>,
}

#[async_trait]
impl TlsAccept for CertVerifier {
    async fn handshake_complete_callback(
        &self,
        ssl: &SslRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        // No cert, or no chain to validate against → not a bypass candidate.
        let leaf = ssl.peer_certificate()?;
        let chain = ssl.peer_cert_chain()?;

        // Chain-verify the leaf against a store built from the configured CA.
        // Any failure (bad signature, expired, untrusted issuer) yields `false`
        // here and thus no credential — the connection stays up and the request
        // will be attested normally.
        let store = match build_store(&self.ca_certs) {
            Ok(s) => s,
            Err(e) => {
                warn!("bypass: failed to build CA store: {e}");
                return None;
            }
        };
        let mut ctx = X509StoreContext::new().ok()?;
        let verified = ctx
            .init(&store, &leaf, chain, |c| c.verify_cert())
            .ok()?;
        if !verified {
            return None;
        }

        // Cert is trusted; now enforce the subject allowlist.
        let subject = matched_subject(&leaf, &self.allowed_subjects)?;
        Some(Arc::new(BypassCred { subject }))
    }
}

/// Build an X509 trust store from the configured CA certificates.  Rebuilt per
/// verifying handshake (cheap next to the handshake's asymmetric crypto, and
/// only reached when a client actually presents a cert), which sidesteps any
/// `Sync` concerns around sharing a prebuilt store across worker threads.
fn build_store(
    ca_certs: &[X509],
) -> Result<pingora_core::tls::x509::store::X509Store, pingora_core::tls::error::ErrorStack> {
    let mut builder = X509StoreBuilder::new()?;
    for ca in ca_certs {
        builder.add_cert(ca.clone())?;
    }
    Ok(builder.build())
}

/// Return the matching subject string if the certificate's Common Name or any
/// SubjectAltName DNS entry is on `allowed`, else `None`.
fn matched_subject(cert: &X509, allowed: &[String]) -> Option<String> {
    let cn = cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string());

    let sans: Vec<String> = cert
        .subject_alt_names()
        .map(|names| {
            names
                .iter()
                .filter_map(|n| n.dnsname().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    subject_allowed(cn.as_deref(), &sans, allowed)
}

/// Pure allowlist check, split out from certificate parsing so it can be unit
/// tested without a real cert.  Returns the first identity (CN preferred, then
/// SAN DNS names) that appears in `allowed`.
fn subject_allowed(cn: Option<&str>, sans: &[String], allowed: &[String]) -> Option<String> {
    if let Some(cn) = cn
        && allowed.iter().any(|a| a == cn)
    {
        return Some(cn.to_owned());
    }
    sans.iter()
        .find(|san| allowed.iter().any(|a| a == *san))
        .cloned()
}

/// Parse and validate `[proxy_bypass]`.  Returns `None` when the feature is
/// disabled, or the two halves of the policy when enabled: the [`IpPolicy`] for
/// the request handler and the [`TlsAcceptCallbacks`] to install on the TLS
/// listener.  Errors (empty/invalid ranges, unreadable CA, empty allowlist) are
/// raised here so misconfiguration aborts startup rather than silently letting
/// traffic bypass — or silently never bypassing.
pub fn from_config(
    cfg: &ProxyBypassConfig,
) -> anyhow::Result<Option<(IpPolicy, TlsAcceptCallbacks)>> {
    if !cfg.enabled {
        return Ok(None);
    }

    if cfg.allowed_ip_ranges.is_empty() {
        anyhow::bail!("proxy_bypass is enabled but allowed_ip_ranges is empty");
    }
    let mut ranges = Vec::with_capacity(cfg.allowed_ip_ranges.len());
    for r in &cfg.allowed_ip_ranges {
        let net: IpNet = r
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid CIDR {r:?} in allowed_ip_ranges: {e}"))?;
        ranges.push(net);
    }

    if cfg.allowed_subjects.is_empty() {
        anyhow::bail!("proxy_bypass is enabled but allowed_subjects is empty");
    }

    if cfg.client_ca.is_empty() {
        anyhow::bail!("proxy_bypass is enabled but client_ca is not set");
    }
    let ca_pem = std::fs::read(&cfg.client_ca)
        .map_err(|e| anyhow::anyhow!("cannot read client_ca {}: {e}", cfg.client_ca))?;
    let ca_certs = X509::stack_from_pem(&ca_pem)
        .map_err(|e| anyhow::anyhow!("cannot parse client_ca {}: {e}", cfg.client_ca))?;
    if ca_certs.is_empty() {
        anyhow::bail!("client_ca {} contains no certificates", cfg.client_ca);
    }

    let policy = IpPolicy { ranges };
    let verifier: TlsAcceptCallbacks = Box::new(CertVerifier {
        ca_certs,
        allowed_subjects: cfg.allowed_subjects.clone(),
    });
    Ok(Some((policy, verifier)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(ranges: &[&str]) -> IpPolicy {
        IpPolicy {
            ranges: ranges.iter().map(|r| r.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn ip_policy_matches_ranges() {
        let p = policy(&["10.0.0.0/8", "192.168.1.0/24"]);
        assert!(p.allows(&"10.4.5.6".parse().unwrap()));
        assert!(p.allows(&"192.168.1.42".parse().unwrap()));
        assert!(!p.allows(&"192.168.2.1".parse().unwrap()));
        assert!(!p.allows(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn ip_policy_supports_ipv6() {
        let p = policy(&["2001:db8::/32"]);
        assert!(p.allows(&"2001:db8::1".parse().unwrap()));
        assert!(!p.allows(&"2001:dead::1".parse().unwrap()));
    }

    #[test]
    fn subject_allowed_matches_cn() {
        let allowed = vec!["health-checker".to_string()];
        assert_eq!(
            subject_allowed(Some("health-checker"), &[], &allowed).as_deref(),
            Some("health-checker")
        );
        assert_eq!(subject_allowed(Some("attacker"), &[], &allowed), None);
    }

    #[test]
    fn subject_allowed_matches_san_when_cn_does_not() {
        let allowed = vec!["ops.internal".to_string()];
        let sans = vec!["www.example.com".to_string(), "ops.internal".to_string()];
        assert_eq!(
            subject_allowed(Some("some-cn"), &sans, &allowed).as_deref(),
            Some("ops.internal")
        );
    }

    #[test]
    fn subject_allowed_rejects_when_nothing_matches() {
        let allowed = vec!["trusted".to_string()];
        assert_eq!(
            subject_allowed(Some("cn"), &["a".into(), "b".into()], &allowed),
            None
        );
        assert_eq!(subject_allowed(None, &[], &allowed), None);
    }

    #[test]
    fn from_config_disabled_returns_none() {
        let cfg = ProxyBypassConfig::default();
        assert!(from_config(&cfg).unwrap().is_none());
    }

    #[test]
    fn from_config_enabled_requires_ip_ranges() {
        let cfg = ProxyBypassConfig {
            enabled: true,
            allowed_ip_ranges: vec![],
            client_ca: "x".into(),
            allowed_subjects: vec!["s".into()],
        };
        assert!(from_config(&cfg).is_err());
    }

    #[test]
    fn from_config_rejects_bad_cidr() {
        let cfg = ProxyBypassConfig {
            enabled: true,
            allowed_ip_ranges: vec!["not-a-cidr".into()],
            client_ca: "x".into(),
            allowed_subjects: vec!["s".into()],
        };
        assert!(from_config(&cfg).is_err());
    }

    #[test]
    fn from_config_requires_subjects() {
        // Valid CIDR but empty allowlist → error before the CA file is read.
        let cfg = ProxyBypassConfig {
            enabled: true,
            allowed_ip_ranges: vec!["10.0.0.0/8".into()],
            client_ca: "/nonexistent".into(),
            allowed_subjects: vec![],
        };
        assert!(from_config(&cfg).is_err());
    }
}

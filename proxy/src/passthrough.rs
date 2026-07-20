//! Attestation bypass ("proxy pass-through") for strongly authenticated callers.
//!
//! Some trusted infrastructure (health checks, internal automation) can't run
//! the DenBrowser attestation client but still needs to reach the upstream
//! through this proxy.  Bypass lets such callers skip attestation, but only on
//! top of baseline mTLS: `[proxy_bypass]` requires `[mtls]` to be enabled, so by
//! the time a request is evaluated here its client certificate has *already* been
//! verified against the mTLS CA during the handshake (see [`crate::mtls`]).
//!
//! Bypass therefore adds just two conditions on top of that verified identity,
//! both from `[proxy_bypass]` (see [`crate::config`]):
//!
//! 1. **Source IP** — the client address is inside one of the configured CIDR
//!    ranges; and
//! 2. **Certificate subject** — the mTLS-verified cert's Common Name or a SAN
//!    DNS entry is on the allowlist.
//!
//! A request is forwarded straight upstream (skipping attestation) only when
//! *both* pass; any miss falls through to normal attestation, so bypass never
//! weakens the path for a normal attested client.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::config::ProxyBypassConfig;
use crate::mtls::ClientCert;

/// The bypass policy: the CIDR ranges and subject allowlist a request must
/// satisfy (against an already-mTLS-verified client cert) to skip attestation.
pub struct BypassPolicy {
    ranges: Vec<IpNet>,
    allowed_subjects: Vec<String>,
}

impl BypassPolicy {
    /// Whether a request from `ip` presenting the mTLS-verified `cert` may skip
    /// attestation: its source IP must be in range *and* the certificate subject
    /// must be on the allowlist.  Returns the matched subject (for logging) when
    /// authorized, else `None`.
    pub fn authorizes<'a>(&self, ip: &IpAddr, cert: &'a ClientCert) -> Option<&'a str> {
        if !self.ranges.iter().any(|net| net.contains(ip)) {
            return None;
        }
        cert.matched(&self.allowed_subjects)
    }
}

/// Parse and validate `[proxy_bypass]`.  Returns `None` when disabled, or the
/// [`BypassPolicy`] when enabled.  `mtls_enabled` is threaded in because bypass
/// builds on baseline mTLS and is meaningless without it — enabling bypass while
/// mTLS is off is a configuration error, caught here so it aborts startup.
/// Empty ranges/allowlist and invalid CIDRs are likewise rejected up front.
pub fn from_config(
    cfg: &ProxyBypassConfig,
    mtls_enabled: bool,
) -> anyhow::Result<Option<BypassPolicy>> {
    if !cfg.enabled {
        return Ok(None);
    }

    if !mtls_enabled {
        anyhow::bail!("proxy_bypass is enabled but requires [mtls] to be enabled too");
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

    Ok(Some(BypassPolicy {
        ranges,
        allowed_subjects: cfg.allowed_subjects.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(ranges: &[&str], subjects: &[&str]) -> BypassPolicy {
        BypassPolicy {
            ranges: ranges.iter().map(|r| r.parse().unwrap()).collect(),
            allowed_subjects: subjects.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn cert(cn: &str) -> ClientCert {
        ClientCert {
            common_name: Some(cn.to_owned()),
            san_dns: vec![],
        }
    }

    #[test]
    fn authorizes_only_when_ip_and_subject_match() {
        let p = policy(&["10.0.0.0/8"], &["health-checker"]);
        let good = cert("health-checker");
        let wrong_subject = cert("intruder");

        // Both match → authorized.
        assert_eq!(
            p.authorizes(&"10.1.2.3".parse().unwrap(), &good),
            Some("health-checker")
        );
        // Right IP, wrong subject → denied.
        assert_eq!(p.authorizes(&"10.1.2.3".parse().unwrap(), &wrong_subject), None);
        // Right subject, wrong IP → denied.
        assert_eq!(p.authorizes(&"8.8.8.8".parse().unwrap(), &good), None);
    }

    #[test]
    fn supports_ipv6_ranges() {
        let p = policy(&["2001:db8::/32"], &["svc"]);
        let c = cert("svc");
        assert_eq!(p.authorizes(&"2001:db8::5".parse().unwrap(), &c), Some("svc"));
        assert_eq!(p.authorizes(&"2001:dead::5".parse().unwrap(), &c), None);
    }

    #[test]
    fn from_config_disabled_returns_none() {
        let cfg = ProxyBypassConfig::default();
        assert!(from_config(&cfg, true).unwrap().is_none());
    }

    #[test]
    fn from_config_requires_mtls() {
        let cfg = ProxyBypassConfig {
            enabled: true,
            allowed_ip_ranges: vec!["10.0.0.0/8".into()],
            allowed_subjects: vec!["s".into()],
        };
        assert!(from_config(&cfg, false).is_err());
        assert!(from_config(&cfg, true).is_ok());
    }

    #[test]
    fn from_config_requires_ip_ranges() {
        let cfg = ProxyBypassConfig {
            enabled: true,
            allowed_ip_ranges: vec![],
            allowed_subjects: vec!["s".into()],
        };
        assert!(from_config(&cfg, true).is_err());
    }

    #[test]
    fn from_config_rejects_bad_cidr() {
        let cfg = ProxyBypassConfig {
            enabled: true,
            allowed_ip_ranges: vec!["not-a-cidr".into()],
            allowed_subjects: vec!["s".into()],
        };
        assert!(from_config(&cfg, true).is_err());
    }

    #[test]
    fn from_config_requires_subjects() {
        let cfg = ProxyBypassConfig {
            enabled: true,
            allowed_ip_ranges: vec!["10.0.0.0/8".into()],
            allowed_subjects: vec![],
        };
        assert!(from_config(&cfg, true).is_err());
    }
}

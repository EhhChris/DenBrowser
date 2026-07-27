//! Runtime configuration for the DenBrowser proxy.
//!
//! The file is required. `--config` selects it, defaulting to `proxy.toml` in
//! the working directory.

use serde::Deserialize;

/// Top-level proxy configuration. New feature sections are added as sibling
/// tables here. Optional features default to "off / no-op"; required empty
/// values are rejected with a field-specific error during startup.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub proxy: ProxyConfig,

    #[serde(default)]
    pub attestation: AttestationConfig,

    #[serde(default)]
    pub rate_limiting: RateLimitConfig,

    #[serde(default)]
    pub mtls: MtlsConfig,

    #[serde(default)]
    pub proxy_bypass: ProxyBypassConfig,
}

/// `[proxy]` — listener, upstream, and TLS settings for this proxy process.
///
/// These values are required at startup.  Keeping them in the same file as the
/// attestation and access-control settings makes a deployment self-contained:
/// selecting a config file selects the complete proxy instance.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Address and port for the TLS listener, for example `0.0.0.0:8081`.
    #[serde(default)]
    pub listen: String,

    /// TLS upstream endpoint in `host:port` form.
    #[serde(default)]
    pub upstream: String,

    /// Path to the TLS server certificate chain in PEM format.
    #[serde(default)]
    pub tls_cert: String,

    /// Path to the TLS server private key in PEM format.
    #[serde(default)]
    pub tls_key: String,
}

impl ProxyConfig {
    /// Reject a missing core setting before Pingora starts.  Empty defaults
    /// keep deserialization backwards-compatible and make the startup error
    /// identify the exact field that must be added to an older config.
    pub fn validate(&self) -> anyhow::Result<()> {
        for (name, value) in [
            ("listen", self.listen.as_str()),
            ("upstream", self.upstream.as_str()),
            ("tls_cert", self.tls_cert.as_str()),
            ("tls_key", self.tls_key.as_str()),
        ] {
            if value.trim().is_empty() {
                anyhow::bail!("[proxy].{name} is required");
            }
        }
        Ok(())
    }
}

/// `[attestation]` — the proxy's own attestation key material.
///
/// The private key is what decrypts per-request ECIES tokens,
/// so a proxy without it cannot verify anything.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationConfig {
    /// Path to the EC P-256 attestation private key, SEC1 PEM — the private
    /// half of the public key baked into the browser build for this proxy
    /// (`scripts/gen-attest-key.sh --name <proxy>` writes both).  Relative
    /// paths resolve against the proxy's working directory, as `client_ca`
    /// does.  Required; startup aborts when it is unset, unreadable, or not a
    /// parseable EC key.
    #[serde(default)]
    pub private_key: String,
}

/// `[rate_limiting]` — a universal per-client-IP request cap plus optional
/// per-URL-pattern rules, each tracked independently per origin IP.
///
/// `enabled = false` (the default) disables the whole feature regardless of the
/// other fields, so an operator can keep a tuned ruleset in the file and flip it
/// off with a single line.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Master on/off switch for rate limiting.
    #[serde(default)]
    pub enabled: bool,

    /// Universal cap: at most `max_requests` per `window_secs` from any single
    /// client IP, across every request.  Leaving either at 0 disables the
    /// universal cap (per-pattern `rules` can still apply on their own).
    #[serde(default)]
    pub window_secs: u64,
    #[serde(default)]
    pub max_requests: isize,

    /// Per-URL-pattern overrides.  Each rule maintains its own counter keyed by
    /// origin IP, so a burst against one pattern never spends another pattern's
    /// (or the universal) budget.
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

/// One `[[rate_limiting.rules]]` entry: a glob matched against `host + path`
/// with its own window and cap.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Glob matched against `"{host}{path}"`, e.g. `example.com/secrets/*`.
    /// `*` matches any run of characters including `/`, so `.../secrets/*`
    /// covers everything nested under that prefix.
    pub pattern: String,
    /// Length of the sliding window, in seconds.
    pub window_secs: u64,
    /// Maximum requests permitted per window per origin IP for this pattern.
    pub max_requests: isize,
}

/// `[mtls]` — baseline mutual-TLS client authentication for the listener.
///
/// When enabled, **every** connection (attestation clients and bypass clients
/// alike) must present a client certificate that chains to `client_ca`, verified
/// during the TLS handshake; a client with no certificate or an untrusted one is
/// rejected at the handshake and never reaches the request path.  This sits *in
/// front of* attestation as an independent layer: it authenticates the user/
/// device, while attestation still proves the request came from a genuine
/// DenBrowser build and TLS pinning still authenticates the proxy to the browser.
///
/// Disabled by default, so a proxy with no config (or `enabled = false`) requests
/// no client certificate and behaves exactly as before.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MtlsConfig {
    /// Master on/off switch for baseline mTLS.
    #[serde(default)]
    pub enabled: bool,

    /// Path to a PEM bundle of CA certificate(s) that presented client
    /// certificates must chain to.  Required when `enabled`.
    #[serde(default)]
    pub client_ca: String,
}

/// `[proxy_bypass]` — an *escape hatch* that lets specific, strongly
/// authenticated callers skip attestation entirely and be forwarded straight
/// upstream.  It exists for trusted infrastructure (health checks, internal
/// automation) that cannot run the DenBrowser attestation client.
///
/// Bypass **builds on baseline [`MtlsConfig`]** and requires it to be enabled:
/// the client certificate is already verified against the mTLS CA at the
/// handshake, so bypass adds only two further conditions.  It is **default-deny**
/// — `enabled = false` (the default) means every request is attested.  When
/// enabled, a request is bypassed only if *both* hold: its source IP is in
/// `allowed_ip_ranges` *and* the mTLS-verified certificate's subject is in
/// `allowed_subjects`.  Any miss falls through to normal attestation.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyBypassConfig {
    /// Master on/off switch.  When false, no request is ever bypassed.
    #[serde(default)]
    pub enabled: bool,

    /// Source IP ranges (CIDR, e.g. `"10.0.0.0/8"`) permitted to bypass.  A
    /// request whose client IP is outside every range falls through to
    /// attestation.  Required (non-empty) when `enabled`.
    #[serde(default)]
    pub allowed_ip_ranges: Vec<String>,

    /// Subject allowlist matched against the mTLS-verified client certificate's
    /// Common Name or one of its SubjectAltName DNS entries.  This lets a single
    /// CA issue many user certs while only specific identities may bypass.
    /// Required (non-empty) when `enabled`.
    #[serde(default)]
    pub allowed_subjects: Vec<String>,
}

impl Config {
    /// Read and parse a TOML config file, returning a descriptive error (with
    /// the file path) on any I/O or parse failure.
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read config {path}: {e}"))?;
        let config: Config = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("cannot parse config {path}: {e}"))?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_disables_everything() {
        let c = Config::default();
        assert!(c.proxy.listen.is_empty());
        assert!(c.proxy.upstream.is_empty());
        assert!(c.proxy.tls_cert.is_empty());
        assert!(c.proxy.tls_key.is_empty());
        assert!(!c.rate_limiting.enabled);
        assert_eq!(c.rate_limiting.max_requests, 0);
        assert!(c.rate_limiting.rules.is_empty());
    }

    #[test]
    fn parses_proxy_config() {
        let toml = r#"
            [proxy]
            listen = "127.0.0.1:9443"
            upstream = "backend.internal:443"
            tls_cert = "/etc/denbrowser/proxy.crt"
            tls_key = "/etc/denbrowser/proxy.key"
        "#;
        let c: Config = toml::from_str(toml).unwrap();
        c.proxy.validate().unwrap();
        assert_eq!(c.proxy.listen, "127.0.0.1:9443");
        assert_eq!(c.proxy.upstream, "backend.internal:443");
        assert_eq!(c.proxy.tls_cert, "/etc/denbrowser/proxy.crt");
        assert_eq!(c.proxy.tls_key, "/etc/denbrowser/proxy.key");
    }

    #[test]
    fn proxy_config_requires_every_field_at_startup() {
        let toml = r#"
            [proxy]
            listen = "0.0.0.0:8081"
            upstream = "backend.internal:443"
            tls_cert = "/etc/denbrowser/proxy.crt"
        "#;
        let c: Config = toml::from_str(toml).unwrap();
        let error = c.proxy.validate().unwrap_err().to_string();
        assert!(error.contains("[proxy].tls_key is required"));
    }

    #[test]
    fn proxy_config_unknown_key_is_rejected() {
        let toml = r#"
            [proxy]
            listen = "0.0.0.0:8081"
            upstream = "backend.internal:443"
            tls_cert = "/etc/denbrowser/proxy.crt"
            tls_key = "/etc/denbrowser/proxy.key"
            listen_port = 8081
        "#;
        assert!(toml::from_str::<Config>(toml).is_err());
    }

    #[test]
    fn parses_full_config() {
        let toml = r#"
            [rate_limiting]
            enabled = true
            window_secs = 1
            max_requests = 100

            [[rate_limiting.rules]]
            pattern = "example.com/secrets/*"
            window_secs = 60
            max_requests = 5

            [[rate_limiting.rules]]
            pattern = "example.com/news/*"
            window_secs = 1
            max_requests = 50
        "#;
        let c: Config = toml::from_str(toml).unwrap();
        assert!(c.rate_limiting.enabled);
        assert_eq!(c.rate_limiting.window_secs, 1);
        assert_eq!(c.rate_limiting.max_requests, 100);
        assert_eq!(c.rate_limiting.rules.len(), 2);
        assert_eq!(c.rate_limiting.rules[0].pattern, "example.com/secrets/*");
        assert_eq!(c.rate_limiting.rules[0].max_requests, 5);
    }

    #[test]
    fn empty_config_is_valid_and_off() {
        let c: Config = toml::from_str("").unwrap();
        assert!(!c.rate_limiting.enabled);
    }

    #[test]
    fn unknown_key_is_rejected() {
        let toml = r#"
            [rate_limiting]
            enabled = true
            typo_field = 3
        "#;
        assert!(toml::from_str::<Config>(toml).is_err());
    }

    #[test]
    fn attestation_defaults_empty() {
        // Empty is the *parse* default; it is rejected at startup by
        // Verifier::from_config, not here.
        let c = Config::default();
        assert!(c.attestation.private_key.is_empty());
    }

    #[test]
    fn parses_attestation() {
        let toml = r#"
            [attestation]
            private_key = "/etc/denbrowser/partner-a-private.pem"
        "#;
        let c: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            c.attestation.private_key,
            "/etc/denbrowser/partner-a-private.pem"
        );
    }

    #[test]
    fn attestation_unknown_key_is_rejected() {
        let toml = r#"
            [attestation]
            privateKey = "/etc/denbrowser/key.pem"
        "#;
        assert!(toml::from_str::<Config>(toml).is_err());
    }

    #[test]
    fn mtls_defaults_off() {
        let c = Config::default();
        assert!(!c.mtls.enabled);
        assert!(c.mtls.client_ca.is_empty());
    }

    #[test]
    fn parses_mtls() {
        let toml = r#"
            [mtls]
            enabled = true
            client_ca = "/etc/denbrowser/user-ca.pem"
        "#;
        let c: Config = toml::from_str(toml).unwrap();
        assert!(c.mtls.enabled);
        assert_eq!(c.mtls.client_ca, "/etc/denbrowser/user-ca.pem");
    }

    #[test]
    fn proxy_bypass_defaults_off() {
        let c = Config::default();
        assert!(!c.proxy_bypass.enabled);
        assert!(c.proxy_bypass.allowed_ip_ranges.is_empty());
        assert!(c.proxy_bypass.allowed_subjects.is_empty());
    }

    #[test]
    fn parses_proxy_bypass() {
        let toml = r#"
            [proxy_bypass]
            enabled = true
            allowed_ip_ranges = ["10.0.0.0/8", "192.168.1.0/24"]
            allowed_subjects = ["health-checker", "ops.internal"]
        "#;
        let c: Config = toml::from_str(toml).unwrap();
        assert!(c.proxy_bypass.enabled);
        assert_eq!(c.proxy_bypass.allowed_ip_ranges.len(), 2);
        assert_eq!(c.proxy_bypass.allowed_subjects, ["health-checker", "ops.internal"]);
    }

    #[test]
    fn proxy_bypass_unknown_key_is_rejected() {
        let toml = r#"
            [proxy_bypass]
            enabled = true
            allow_all = true
        "#;
        assert!(toml::from_str::<Config>(toml).is_err());
    }
}

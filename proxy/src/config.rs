//! Runtime configuration for the DenBrowser proxy.
//!
//! Unlike the compile-time attestation/TLS material (passed as CLI flags), this
//! is *operational* configuration that a deployment tunes without rebuilding:
//! start with rate limiting, and grow from here.  The file is TOML so options
//! can carry inline comments and on/off toggles a human is expected to edit.
//!
//! The whole file is optional.  With no `--config`, [`Config::default`] applies
//! and every feature it gates (currently just rate limiting) stays off, so the
//! proxy behaves exactly as it did before this module existed.

use serde::Deserialize;

/// Top-level proxy configuration.  New feature sections are added as sibling
/// tables here (e.g. `[logging]`, `[upstream]`); each defaults to "off / no-op"
/// so an older config file keeps working after a new section is introduced.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub rate_limiting: RateLimitConfig,

    #[serde(default)]
    pub proxy_bypass: ProxyBypassConfig,
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

/// `[proxy_bypass]` — an *escape hatch* that lets specific, strongly
/// authenticated callers skip attestation entirely and be forwarded straight
/// upstream.  It exists for trusted infrastructure (health checks, internal
/// automation) that cannot run the DenBrowser attestation client.
///
/// Bypass is **default-deny**: `enabled = false` (the default) means every
/// request goes through normal attestation.  When enabled, a request is
/// bypassed only if it satisfies *all* configured conditions — its source IP is
/// in `allowed_ip_ranges` *and* it presented a client certificate that both
/// chains to `client_ca` and whose subject is in `allowed_subjects`.  Any check
/// that fails (or a missing/invalid cert) simply falls through to attestation,
/// so a misconfigured bypass never blocks a legitimate attested client.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyBypassConfig {
    /// Master on/off switch.  When false, no request is ever bypassed and the
    /// TLS listener behaves exactly as it does without this feature (no client
    /// certificate is requested).
    #[serde(default)]
    pub enabled: bool,

    /// Source IP ranges (CIDR, e.g. `"10.0.0.0/8"`) permitted to bypass.  A
    /// request whose client IP is outside every range falls through to
    /// attestation.  Required (non-empty) when `enabled`.
    #[serde(default)]
    pub allowed_ip_ranges: Vec<String>,

    /// Path to a PEM bundle of CA certificate(s).  A bypass candidate must
    /// present a client certificate that chains to one of these.  Required when
    /// `enabled`.
    #[serde(default)]
    pub client_ca: String,

    /// Subject allowlist.  After a client cert validates against `client_ca`,
    /// its Common Name or one of its SubjectAltName DNS entries must exactly
    /// match an entry here.  This lets a single CA issue many certs while only
    /// specific identities may bypass.  Required (non-empty) when `enabled`.
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
        assert!(!c.rate_limiting.enabled);
        assert_eq!(c.rate_limiting.max_requests, 0);
        assert!(c.rate_limiting.rules.is_empty());
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
    fn proxy_bypass_defaults_off() {
        let c = Config::default();
        assert!(!c.proxy_bypass.enabled);
        assert!(c.proxy_bypass.allowed_ip_ranges.is_empty());
        assert!(c.proxy_bypass.client_ca.is_empty());
        assert!(c.proxy_bypass.allowed_subjects.is_empty());
    }

    #[test]
    fn parses_proxy_bypass() {
        let toml = r#"
            [proxy_bypass]
            enabled = true
            allowed_ip_ranges = ["10.0.0.0/8", "192.168.1.0/24"]
            client_ca = "/etc/denbrowser/bypass-ca.pem"
            allowed_subjects = ["health-checker", "ops.internal"]
        "#;
        let c: Config = toml::from_str(toml).unwrap();
        assert!(c.proxy_bypass.enabled);
        assert_eq!(c.proxy_bypass.allowed_ip_ranges.len(), 2);
        assert_eq!(c.proxy_bypass.client_ca, "/etc/denbrowser/bypass-ca.pem");
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

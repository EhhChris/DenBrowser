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
    pub machine_identity: MachineIdentityConfig,

    #[serde(default)]
    pub proxy_bypass: ProxyBypassConfig,

    #[serde(default)]
    pub logging: LoggingConfig,
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

/// `[machine_identity]` — a fourth orthogonal layer that identifies the
/// *workstation* a request came from.
///
/// The DenBrowser build sends its machine certificate as a base64 DER header on
/// every request (the TLS handshake already carries the user certificate, and a
/// handshake carries exactly one client chain, so this identity cannot ride it).
/// The proxy verifies that the certificate chains to `machine_ca`, that its
/// Common Name is on `allowed_hostnames`, and that the name **forward-resolves
/// to the connecting IP** — then records that hostname in the audit trail.
///
/// This layer is an *identity claim validated against the CA and the network
/// origin*, **not** a proof that the endpoint holds the machine private key: a
/// certificate is a public document, so anyone able to copy it could present it
/// from a host the name resolves to.  It is therefore strictly weaker than
/// attestation against a compromised endpoint, and complements rather than
/// replaces it.
///
/// Because the forward-DNS check is unconditional, **enabling this requires
/// clients to reach the proxy on their own addresses**.  Behind NAT, a VPN
/// concentrator, or any shared egress the proxy sees the gateway's address,
/// which is in no workstation's A record, and every request is rejected.
///
/// Disabled by default, so a proxy with no config (or `enabled = false`) ignores
/// the header entirely and behaves exactly as before.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MachineIdentityConfig {
    /// Master on/off switch for machine identity.
    pub enabled: bool,

    /// Path to a PEM bundle of CA certificate(s) that presented machine
    /// certificates must chain to.  Required when `enabled`.  This must be a
    /// *different* CA from `[mtls].client_ca` — startup rejects an overlap,
    /// because the two identities are told apart by their issuer.
    pub machine_ca: String,

    /// Reject a request whose machine certificate is missing or invalid.  On by
    /// default: a layer that silently passes unidentified requests through is
    /// not an identity layer.  Set false only while rolling the browser side
    /// out, so a fleet mid-upgrade is not locked out.
    pub required: bool,

    /// Glob patterns the certificate's Common Name must match, e.g.
    /// `"ws-*.corp.example.com"`.  Empty (the default) accepts any name the CA
    /// signed — the forward-DNS check is still applied either way.
    ///
    /// As in [`RuleConfig::pattern`], `*` matches any run of characters
    /// *including dots*, so `*.corp.example.com` also matches
    /// `a.b.corp.example.com`.  Patterns must be written lowercase: the CN is
    /// lowercased before matching, since DNS names are case-insensitive.
    pub allowed_hostnames: Vec<String>,

    /// How long a successful hostname→addresses lookup is reused.  Workstation
    /// A records are stable for hours, so this is what keeps the check off the
    /// resolver: one query per workstation per window rather than one per
    /// request.
    pub dns_ttl_secs: u64,

    /// How long a *failed* lookup is remembered.  Deliberately shorter than
    /// `dns_ttl_secs` — it stops one unprovisioned machine from querying on
    /// every request, without locking a freshly-registered one out for the full
    /// positive window.
    pub dns_negative_ttl_secs: u64,

    /// How far past its TTL an entry may still be used when the resolver itself
    /// is failing.  This keeps a resolver outage from becoming a proxy outage
    /// without opening a fail-open hole: a *cold* cache plus a dead resolver
    /// still rejects.  Zero disables serving stale.
    pub dns_stale_grace_secs: u64,

    /// Treat any certificate in `machine_ca` as a trust anchor, rather than
    /// requiring the chain to reach a self-signed root.  Enterprises routinely
    /// distribute an *issuing* CA rather than the root; without this, verifying
    /// against such a bundle fails.
    pub partial_chain: bool,
}

impl Default for MachineIdentityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            machine_ca: String::new(),
            required: true,
            allowed_hostnames: Vec::new(),
            dns_ttl_secs: 300,
            dns_negative_ttl_secs: 30,
            dns_stale_grace_secs: 3600,
            partial_chain: false,
        }
    }
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

/// Rotation periods accepted by `[logging].rotation`.
///
/// Declared once here so `validate` and `logging::rotation_from_str` cannot
/// drift apart: config validation rejects anything outside this list, so the
/// mapping in `logging` only ever sees a value it knows.
pub const LOG_ROTATIONS: [&str; 4] = ["minutely", "hourly", "daily", "never"];

/// Bare level names accepted by `[logging].level`.
///
/// Only used to catch typos — see [`LoggingConfig::validate`].  A level string
/// containing `,` or `=` is directive syntax and is handed to `EnvFilter` whole.
pub const LOG_LEVELS: [&str; 6] = ["trace", "debug", "info", "warn", "error", "off"];

/// `[logging]` — where and how the proxy writes its own log output.
///
/// The proxy is the only DenBrowser component permitted to record anything (the
/// browser build has diagnostics patched out), so this output *is* the audit
/// trail.  It is nonetheless off-by-file by default: `dir` is empty, which means
/// stderr only, so a config file written before this section existed keeps
/// working and simply gains visible output.
///
/// Unlike the sections above, this one uses a container-level `#[serde(default)]`
/// rather than a per-field one.  Every other section's defaults are zero values,
/// so `derive(Default)` and serde agree by construction; these are not
/// (`level = "info"`, `max_files = 14`, `stderr = true`), and per-field
/// `default = "..."` functions would be a second copy of them, free to drift.
/// Deferring to `Default` keeps one source of truth for both paths.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoggingConfig {
    /// Directory to write rotating log files into.  Empty (the default)
    /// disables file logging and leaves only the stderr mirror.  Created at
    /// startup if it does not exist; relative paths resolve against the proxy's
    /// working directory, as `tls_cert` and `client_ca` do.
    pub dir: String,

    /// Base filename inside `dir`.  The appender appends the rotation stamp,
    /// producing e.g. `denbrowser-proxy.log.2026-08-01`.
    pub file_prefix: String,

    /// Verbosity, in `RUST_LOG` syntax — a bare level (`"info"`) or per-module
    /// directives (`"info,denbrowser_proxy=debug"`).  `RUST_LOG`, when set in
    /// the environment, overrides this value entirely.
    pub level: String,

    /// How often to start a new file: one of [`LOG_ROTATIONS`].
    pub rotation: String,

    /// How many rotated files to keep, oldest deleted first.  0 keeps every
    /// file, which makes disk growth unbounded — pair it with external
    /// retention if you choose it.
    pub max_files: usize,

    /// Also mirror output to stderr.  On by default so `cargo run`, journald,
    /// and the test scripts under `test/` still show live output.
    pub stderr: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            dir: String::new(),
            file_prefix: "denbrowser-proxy.log".to_owned(),
            level: "info".to_owned(),
            rotation: "daily".to_owned(),
            max_files: 14,
            stderr: true,
        }
    }
}

impl LoggingConfig {
    /// True when file logging is configured; `dir` is the master switch.
    pub fn file_enabled(&self) -> bool {
        !self.dir.trim().is_empty()
    }

    /// Reject an unusable logging setup before the subscriber is built, so the
    /// operator sees which field is wrong rather than a generic init failure.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !LOG_ROTATIONS.contains(&self.rotation.as_str()) {
            anyhow::bail!(
                "[logging].rotation must be one of {} (got {:?})",
                LOG_ROTATIONS.join(", "),
                self.rotation
            );
        }
        // Only meaningful once a file is actually being written; an empty
        // prefix would otherwise yield files named for the date alone.
        if self.file_enabled() && self.file_prefix.trim().is_empty() {
            anyhow::bail!("[logging].file_prefix is required when [logging].dir is set");
        }

        // `EnvFilter`'s grammar reads any bare word as a *target* name, so it
        // accepts `level = "inf"` without complaint — as "log only the target
        // named inf", which silently produces no output at all.  That failure
        // mode is precisely what this section exists to fix, so a single bare
        // token is checked against the real level names here.  Anything with a
        // `,` or `=` is genuine directive syntax and is left to `EnvFilter`.
        let level = self.level.trim();
        if !level.is_empty()
            && !level.contains(',')
            && !level.contains('=')
            && !LOG_LEVELS.contains(&level.to_ascii_lowercase().as_str())
        {
            anyhow::bail!(
                "[logging].level must be one of {} (or a RUST_LOG-style directive list) — got {:?}",
                LOG_LEVELS.join(", "),
                self.level
            );
        }
        Ok(())
    }
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
    fn machine_identity_defaults_off() {
        let c = Config::default();
        assert!(!c.machine_identity.enabled);
        assert!(c.machine_identity.machine_ca.is_empty());
        assert!(c.machine_identity.allowed_hostnames.is_empty());
        // Off by default, but *strict* once switched on.
        assert!(c.machine_identity.required);
        assert!(!c.machine_identity.partial_chain);
    }

    #[test]
    fn machine_identity_serde_defaults_match_the_default_impl() {
        // The container-level `#[serde(default)]` is what keeps these in step;
        // this fails loudly if someone reintroduces per-field defaults.
        let parsed: Config = toml::from_str("[machine_identity]\n").unwrap();
        let default = MachineIdentityConfig::default();
        assert_eq!(parsed.machine_identity.required, default.required);
        assert_eq!(parsed.machine_identity.dns_ttl_secs, default.dns_ttl_secs);
        assert_eq!(
            parsed.machine_identity.dns_negative_ttl_secs,
            default.dns_negative_ttl_secs
        );
        assert_eq!(
            parsed.machine_identity.dns_stale_grace_secs,
            default.dns_stale_grace_secs
        );
        assert_eq!(parsed.machine_identity.partial_chain, default.partial_chain);
    }

    #[test]
    fn parses_machine_identity() {
        let toml = r#"
            [machine_identity]
            enabled           = true
            machine_ca        = "/etc/denbrowser/machine-ca.pem"
            allowed_hostnames = ["ws-*.corp.example.com", "kiosk-*.corp.example.com"]
            dns_ttl_secs      = 600
            partial_chain     = true
        "#;
        let c: Config = toml::from_str(toml).unwrap();
        assert!(c.machine_identity.enabled);
        assert_eq!(c.machine_identity.machine_ca, "/etc/denbrowser/machine-ca.pem");
        assert_eq!(c.machine_identity.allowed_hostnames.len(), 2);
        assert_eq!(c.machine_identity.dns_ttl_secs, 600);
        assert!(c.machine_identity.partial_chain);
        // Unspecified fields keep their non-zero defaults.
        assert!(c.machine_identity.required);
        assert_eq!(c.machine_identity.dns_negative_ttl_secs, 30);
    }

    #[test]
    fn machine_identity_unknown_key_is_rejected() {
        let toml = r#"
            [machine_identity]
            enabled       = true
            hostname_check = "reverse"
        "#;
        assert!(toml::from_str::<Config>(toml).is_err());
    }

    #[test]
    fn config_without_machine_identity_still_parses() {
        // A config file written before this section existed must keep working.
        let toml = r#"
            [mtls]
            enabled   = true
            client_ca = "/etc/denbrowser/user-ca.pem"
        "#;
        let c: Config = toml::from_str(toml).unwrap();
        assert!(!c.machine_identity.enabled);
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

    #[test]
    fn logging_defaults_to_stderr_only() {
        // A config file written before `[logging]` existed must still parse, and
        // must not start writing files somewhere the operator did not choose.
        let c: Config = toml::from_str("[proxy]\nlisten = \"0.0.0.0:8081\"\n").unwrap();
        assert!(!c.logging.file_enabled());
        assert!(c.logging.dir.is_empty());
        assert!(c.logging.stderr);
        assert_eq!(c.logging.level, "info");
        assert_eq!(c.logging.rotation, "daily");
        assert_eq!(c.logging.max_files, 14);
        assert_eq!(c.logging.file_prefix, "denbrowser-proxy.log");
        c.logging.validate().unwrap();
    }

    #[test]
    fn logging_serde_defaults_match_the_default_impl() {
        // The container-level `#[serde(default)]` is what keeps these in step;
        // this fails loudly if someone reintroduces per-field defaults.
        let parsed: Config = toml::from_str("[logging]\n").unwrap();
        let default = LoggingConfig::default();
        assert_eq!(parsed.logging.dir, default.dir);
        assert_eq!(parsed.logging.file_prefix, default.file_prefix);
        assert_eq!(parsed.logging.level, default.level);
        assert_eq!(parsed.logging.rotation, default.rotation);
        assert_eq!(parsed.logging.max_files, default.max_files);
        assert_eq!(parsed.logging.stderr, default.stderr);
    }

    #[test]
    fn parses_logging_config() {
        let toml = r#"
            [logging]
            dir = "/var/log/denbrowser"
            file_prefix = "proxy.log"
            level = "info,denbrowser_proxy=debug"
            rotation = "hourly"
            max_files = 48
            stderr = false
        "#;
        let c: Config = toml::from_str(toml).unwrap();
        c.logging.validate().unwrap();
        assert!(c.logging.file_enabled());
        assert_eq!(c.logging.dir, "/var/log/denbrowser");
        assert_eq!(c.logging.file_prefix, "proxy.log");
        assert_eq!(c.logging.level, "info,denbrowser_proxy=debug");
        assert_eq!(c.logging.rotation, "hourly");
        assert_eq!(c.logging.max_files, 48);
        assert!(!c.logging.stderr);
    }

    #[test]
    fn logging_partial_section_keeps_other_defaults() {
        let c: Config = toml::from_str("[logging]\ndir = \"../build/logs\"\n").unwrap();
        assert!(c.logging.file_enabled());
        assert_eq!(c.logging.rotation, "daily");
        assert_eq!(c.logging.max_files, 14);
        assert!(c.logging.stderr);
    }

    #[test]
    fn logging_rejects_unknown_rotation() {
        let toml = r#"
            [logging]
            rotation = "weekly"
        "#;
        let c: Config = toml::from_str(toml).unwrap();
        let error = c.logging.validate().unwrap_err().to_string();
        assert!(error.contains("[logging].rotation"), "got: {error}");
        assert!(error.contains("weekly"), "error should quote the bad value: {error}");
    }

    #[test]
    fn logging_every_advertised_rotation_validates() {
        for rotation in LOG_ROTATIONS {
            let c = LoggingConfig {
                rotation: rotation.to_owned(),
                ..LoggingConfig::default()
            };
            c.validate()
                .unwrap_or_else(|e| panic!("{rotation} should validate: {e}"));
        }
    }

    #[test]
    fn logging_requires_file_prefix_only_when_writing_files() {
        let without_dir = LoggingConfig {
            file_prefix: String::new(),
            ..LoggingConfig::default()
        };
        // No file being written, so the prefix is irrelevant.
        without_dir.validate().unwrap();

        let with_dir = LoggingConfig {
            dir: "/var/log/denbrowser".to_owned(),
            file_prefix: "  ".to_owned(),
            ..LoggingConfig::default()
        };
        let error = with_dir.validate().unwrap_err().to_string();
        assert!(error.contains("[logging].file_prefix is required"), "got: {error}");
    }

    #[test]
    fn logging_rejects_bare_level_typos() {
        // The whole point of this section is that output stops being silent, so
        // the near-misses that would reintroduce silence are rejected by name.
        for typo in ["inf", "warning", "verbose", "INFOO"] {
            let c = LoggingConfig {
                level: typo.to_owned(),
                ..LoggingConfig::default()
            };
            let error = match c.validate() {
                Err(e) => e.to_string(),
                Ok(()) => panic!("{typo} should have been rejected as a level"),
            };
            assert!(error.contains("[logging].level"), "got: {error}");
        }
    }

    #[test]
    fn logging_accepts_valid_levels_and_directives() {
        for level in LOG_LEVELS {
            let c = LoggingConfig {
                level: level.to_owned(),
                ..LoggingConfig::default()
            };
            c.validate()
                .unwrap_or_else(|e| panic!("{level} should validate: {e}"));
        }
        // Case-insensitive, and directive lists bypass the bare-token check.
        for level in ["INFO", "Warn", "info,denbrowser_proxy=debug", "pingora_core=off"] {
            let c = LoggingConfig {
                level: level.to_owned(),
                ..LoggingConfig::default()
            };
            c.validate()
                .unwrap_or_else(|e| panic!("{level} should validate: {e}"));
        }
    }

    #[test]
    fn logging_unknown_key_is_rejected() {
        let toml = r#"
            [logging]
            dir = "/var/log/denbrowser"
            path = "/var/log/denbrowser/proxy.log"
        "#;
        assert!(toml::from_str::<Config>(toml).is_err());
    }
}

//! Machine identity — which *workstation* a request came from.
//!
//! The fourth orthogonal layer (see [`crate::config::MachineIdentityConfig`]).
//! The DenBrowser build sends its machine certificate as a base64 DER header on
//! every request; this module verifies it and yields the hostname for the audit
//! trail.
//!
//! # Why a header and not the TLS handshake
//!
//! A TLS handshake carries exactly one client certificate chain, and the user
//! certificate already occupies it (see [`crate::mtls`]).  There is no second
//! handshake to attach a second identity to either — this proxy is a *reverse*
//! proxy, so the browser makes one ordinary HTTPS connection to the origin.  So
//! the machine identity travels at the application layer.
//!
//! # What this proves, and what it does not
//!
//! A certificate is a public document.  Presenting one proves only that the
//! sender *had a copy*, not that it holds the private key — this layer performs
//! no proof of possession.  Two things keep the claim honest:
//!
//! 1. the certificate must chain to `machine_ca`, so the name was issued by us;
//!    and
//! 2. the name must **forward-resolve to the connecting IP**, so a copied
//!    certificate only works from a host that name actually points at.
//!
//! That makes machine identity strictly weaker than attestation against a
//! compromised endpoint (attestation is unforgeable precisely because the
//! browser holds no private key), and it is why the hostname is recorded rather
//! than used to grant anything.
//!
//! # Verification order
//!
//! Cheapest first, so a bad certificate never reaches the resolver:
//!
//! 1. base64-decode and parse the DER
//! 2. extract the Common Name, lowercase it, reject control characters
//! 3. match it against the `allowed_hostnames` globs (in memory)
//! 4. chain-verify against `machine_ca`
//! 5. forward-resolve it and require the client IP among the answers
//!
//! Steps 2 and 3 inspect an untrusted certificate only to reject it early; its
//! claimed name is not returned or resolved until step 4 establishes trust.
//! This means an allowlist miss reaches neither signature verification nor DNS.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use globset::{Glob, GlobMatcher};
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::{X509, X509StoreContext};

use crate::config::MachineIdentityConfig;
use crate::mtls::ClientCert;

/// Why a machine certificate was rejected.  One variant per failure so the
/// audit line names the actual cause, as [`crate::attest::AttestError`] does.
#[derive(Debug)]
pub enum MachineError {
    /// The header is absent (and `required` is set).
    Missing,
    /// The header is not valid base64.
    NotBase64,
    /// The bytes are not a parseable DER certificate.
    NotDer,
    /// The certificate does not chain to `machine_ca`, with OpenSSL's reason.
    UntrustedChain(String),
    /// The certificate carries no Common Name to identify the machine by.
    NoCommonName,
    /// The Common Name contains characters that must never reach a log line.
    UnsafeCommonName,
    /// The Common Name matched no `allowed_hostnames` pattern.
    HostnameNotAllowed(String),
    /// The Common Name does not resolve to the address the client connected
    /// from, so the certificate is being presented from somewhere else.
    HostnameAddressMismatch { cn: String, ip: IpAddr },
    /// The name could not be resolved at all, and no usable cached answer was
    /// available to fall back on.
    HostnameUnresolvable(String),
    /// The connection has no peer address to check the name against.  Should
    /// not happen for a TCP/TLS client; rejected rather than waved through.
    NoClientAddress,
}

impl std::fmt::Display for MachineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "X-DenBrowser-Machine-Cert is missing"),
            Self::NotBase64 => write!(f, "X-DenBrowser-Machine-Cert is not valid base64"),
            Self::NotDer => write!(f, "machine certificate is not parseable DER"),
            Self::UntrustedChain(r) => {
                write!(f, "machine certificate does not chain to machine_ca: {r}")
            }
            Self::NoCommonName => write!(f, "machine certificate has no Common Name"),
            Self::UnsafeCommonName => {
                write!(f, "machine certificate Common Name contains illegal characters")
            }
            Self::HostnameNotAllowed(cn) => {
                write!(f, "machine hostname {cn:?} matches no allowed_hostnames pattern")
            }
            Self::HostnameAddressMismatch { cn, ip } => write!(
                f,
                "machine hostname {cn:?} does not resolve to the connecting address {ip}"
            ),
            Self::HostnameUnresolvable(cn) => {
                write!(f, "machine hostname {cn:?} could not be resolved")
            }
            Self::NoClientAddress => {
                write!(f, "connection has no peer address to verify the machine hostname against")
            }
        }
    }
}

/// Resolves a hostname to its addresses.
///
/// Behind a trait so the cache can be exercised without a network, and so the
/// resolver can be swapped without touching the policy around it.
#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}

/// The real resolver: the system one, via `getaddrinfo` on tokio's blocking
/// pool.  Going through the system resolver means `/etc/resolv.conf`,
/// `/etc/hosts`, and any local caching daemon all behave as an operator
/// expects.  `lookup_host` needs a port to form a socket address; it is
/// discarded, only the addresses matter.
pub struct SystemResolver;

#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        let addrs = tokio::net::lookup_host((host, 0)).await?;
        Ok(addrs.map(|sa| sa.ip()).collect())
    }
}

/// One cached lookup.  A resolved-but-empty `addrs` is how a negative answer is
/// represented, so both outcomes share the expiry and stale-fallback logic.
struct CacheEntry {
    addrs: Vec<IpAddr>,
    fetched: Instant,
}

impl CacheEntry {
    fn is_negative(&self) -> bool {
        self.addrs.is_empty()
    }
}

/// Machine-identity settings, built once at startup: the trust store the
/// presented certificate must chain to, and the compiled hostname allowlist.
pub struct MachineIdentity {
    store: X509Store,
    /// Compiled `allowed_hostnames`.  Empty means "any name the CA signed".
    allowed: Vec<GlobMatcher>,
    /// Reject when the header is absent or invalid.
    required: bool,
    /// The parsed CA certificates, kept so `main` can check they do not overlap
    /// the mTLS user CA.
    ca_certs: Vec<X509>,
    /// Hostname → addresses, so the forward check costs one query per
    /// workstation per TTL rather than one per request.  Same shape as the
    /// attestation nonce cache: a `Mutex<HashMap<..>>` swept on insert.
    dns_cache: Mutex<HashMap<String, CacheEntry>>,
    resolver: Box<dyn Resolver>,
    dns_ttl: Duration,
    dns_negative_ttl: Duration,
    dns_stale_grace: Duration,
}

impl MachineIdentity {
    /// Parse and validate `[machine_identity]`.  Returns `None` when disabled,
    /// or an error that aborts startup rather than bringing up a proxy that
    /// would reject every request (or, worse, accept unverifiable ones).
    /// Mirrors [`crate::mtls::Mtls::from_config`].
    pub fn from_config(cfg: &MachineIdentityConfig) -> anyhow::Result<Option<Self>> {
        Self::from_config_with_resolver(cfg, Box::new(SystemResolver))
    }

    /// As [`Self::from_config`], with the resolver supplied — the seam the
    /// cache tests use to run offline and to drive resolver failures.
    pub fn from_config_with_resolver(
        cfg: &MachineIdentityConfig,
        resolver: Box<dyn Resolver>,
    ) -> anyhow::Result<Option<Self>> {
        if !cfg.enabled {
            return Ok(None);
        }
        if cfg.machine_ca.is_empty() {
            anyhow::bail!("machine_identity is enabled but machine_ca is not set");
        }

        let pem = std::fs::read(&cfg.machine_ca).map_err(|e| {
            anyhow::anyhow!(
                "cannot read machine_identity machine_ca {}: {e}",
                cfg.machine_ca
            )
        })?;
        let cas = X509::stack_from_pem(&pem).map_err(|e| {
            anyhow::anyhow!(
                "cannot parse machine_identity machine_ca {}: {e}",
                cfg.machine_ca
            )
        })?;
        if cas.is_empty() {
            anyhow::bail!(
                "machine_identity machine_ca {} contains no certificates",
                cfg.machine_ca
            );
        }

        let mut builder = X509StoreBuilder::new()
            .map_err(|e| anyhow::anyhow!("cannot create machine certificate store: {e}"))?;
        for ca in cas.iter() {
            // `add_cert` takes ownership, and we keep `cas` for the overlap
            // check in `main`, so hand it a clone rather than the original.
            builder
                .add_cert(ca.clone())
                .map_err(|e| anyhow::anyhow!("cannot add machine CA to store: {e}"))?;
        }
        if cfg.partial_chain {
            builder
                .set_flags(X509VerifyFlags::PARTIAL_CHAIN)
                .map_err(|e| anyhow::anyhow!("cannot set PARTIAL_CHAIN on machine store: {e}"))?;
        }

        // Compile every pattern up front, exactly as `ratelimit` does, so a bad
        // glob aborts startup with a field-specific error instead of silently
        // never matching — which would look like a working allowlist that
        // rejects the whole fleet.
        let mut allowed = Vec::with_capacity(cfg.allowed_hostnames.len());
        for pattern in &cfg.allowed_hostnames {
            if pattern != &pattern.to_ascii_lowercase() {
                anyhow::bail!(
                    "machine_identity allowed_hostnames pattern {pattern:?} must be lowercase \
                     (the certificate Common Name is lowercased before matching)"
                );
            }
            let matcher = Glob::new(pattern)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "invalid machine_identity allowed_hostnames pattern {pattern:?}: {e}"
                    )
                })?
                .compile_matcher();
            allowed.push(matcher);
        }

        Ok(Some(Self {
            store: builder.build(),
            allowed,
            required: cfg.required,
            ca_certs: cas,
            dns_cache: Mutex::new(HashMap::new()),
            resolver,
            dns_ttl: Duration::from_secs(cfg.dns_ttl_secs),
            dns_negative_ttl: Duration::from_secs(cfg.dns_negative_ttl_secs),
            dns_stale_grace: Duration::from_secs(cfg.dns_stale_grace_secs),
        }))
    }

    /// Whether an absent or invalid certificate rejects the request.
    pub fn required(&self) -> bool {
        self.required
    }

    /// The parsed machine CA certificates, for the startup check that they do
    /// not overlap the mTLS user CA.
    pub fn ca_certs(&self) -> &[X509] {
        &self.ca_certs
    }

    /// Steps 1–4: decode, extract and sanitize the Common Name, match it against
    /// the allowlist, then chain-verify.  Returns the normalized (lowercase)
    /// hostname only after trust is established.  The forward-DNS check is
    /// applied separately by the caller.
    pub fn verify_cert(&self, cert_b64: &str) -> Result<String, MachineError> {
        use base64::Engine as _;

        let der = base64::engine::general_purpose::STANDARD
            .decode(cert_b64.trim())
            .map_err(|_| MachineError::NotBase64)?;
        let cert = X509::from_der(&der).map_err(|_| MachineError::NotDer)?;

        // Inspect the claimed identity before doing signature verification, but
        // use it only for rejection at this stage.  An untrusted name must never
        // be returned, logged, or sent to the resolver.
        // Reuse the mTLS layer's subject extraction so CN/SAN semantics cannot
        // drift between the two certificate-identity paths.
        let identity = ClientCert::from_cert(&cert);
        let cn = identity.common_name.ok_or(MachineError::NoCommonName)?;

        // A CA that signs a name containing CR/LF would otherwise inject lines
        // into the audit trail, which is the one output this product produces.
        if cn.is_empty()
            || cn
                .chars()
                .any(|c| !c.is_ascii() || c.is_ascii_control() || c == ' ')
        {
            return Err(MachineError::UnsafeCommonName);
        }

        // DNS names are case-insensitive; normalize once so the allowlist match
        // and the later lookup both use the same string.
        let cn = cn.to_ascii_lowercase();

        if !self.allowed.is_empty() && !self.allowed.iter().any(|m| m.is_match(&cn)) {
            return Err(MachineError::HostnameNotAllowed(cn));
        }

        // The claimed name is structurally acceptable and in policy.  Now
        // chain-verify against the machine CA.  The presented certificate is a
        // bare leaf, so the untrusted-chain pool is empty.
        let empty: Stack<X509> =
            Stack::new().map_err(|e| MachineError::UntrustedChain(e.to_string()))?;
        let mut ctx =
            X509StoreContext::new().map_err(|e| MachineError::UntrustedChain(e.to_string()))?;
        // `init` installs a guard that calls X509_STORE_CTX_cleanup when the
        // closure returns, so `error()` has to be read *inside* it — afterwards
        // the context has already been torn down.
        let (ok, reason) = ctx
            .init(&self.store, &cert, &empty, |c| {
                let ok = c.verify_cert()?;
                Ok((ok, c.error().to_string()))
            })
            .map_err(|e| MachineError::UntrustedChain(e.to_string()))?;
        if !ok {
            return Err(MachineError::UntrustedChain(reason));
        }

        Ok(cn)
    }

    /// The whole check: verify the certificate, then confirm the name it claims
    /// forward-resolves to the address the client actually connected from.
    /// Returns the verified hostname for the audit trail.
    pub async fn verify(
        &self,
        cert_b64: &str,
        client_ip: Option<IpAddr>,
    ) -> Result<String, MachineError> {
        let ip = client_ip.ok_or(MachineError::NoClientAddress)?;
        let cn = self.verify_cert(cert_b64)?;

        let addrs = self.resolve_cached(&cn).await;
        match addrs {
            Some(addrs) if addrs.contains(&ip) => Ok(cn),
            Some(addrs) if addrs.is_empty() => Err(MachineError::HostnameUnresolvable(cn)),
            Some(_) => Err(MachineError::HostnameAddressMismatch { cn, ip }),
            None => Err(MachineError::HostnameUnresolvable(cn)),
        }
    }

    /// Addresses for `host`, from cache when fresh.  `None` means the resolver
    /// failed and nothing usable was cached — the caller rejects.  An empty
    /// vector is a cached *negative* answer (the name genuinely resolves to
    /// nothing).
    async fn resolve_cached(&self, host: &str) -> Option<Vec<IpAddr>> {
        // Fast path: a fresh entry, positive or negative.
        {
            let cache = self.dns_cache.lock().unwrap();
            if let Some(entry) = cache.get(host) {
                let ttl = if entry.is_negative() {
                    self.dns_negative_ttl
                } else {
                    self.dns_ttl
                };
                if entry.fetched.elapsed() < ttl {
                    return Some(entry.addrs.clone());
                }
            }
        }

        match self.resolver.resolve(host).await {
            Ok(addrs) => {
                self.store(host.to_owned(), addrs.clone());
                Some(addrs)
            }
            Err(_) => {
                // The resolver is failing.  Rather than let that become a proxy
                // outage, keep using the last good answer for a bounded grace
                // period.  A *cold* cache still rejects, so this widens no hole
                // — it only refuses to forget what we already proved.
                let cache = self.dns_cache.lock().unwrap();
                match cache.get(host) {
                    Some(entry)
                        if !entry.is_negative()
                            && entry.fetched.elapsed() < self.dns_ttl + self.dns_stale_grace =>
                    {
                        Some(entry.addrs.clone())
                    }
                    _ => None,
                }
            }
        }
    }

    /// Insert an answer, sweeping expired entries on the way through so the map
    /// stays bounded by the live fleet rather than by every name ever seen.
    fn store(&self, host: String, addrs: Vec<IpAddr>) {
        let mut cache = self.dns_cache.lock().unwrap();
        let keep = self.dns_ttl + self.dns_stale_grace;
        cache.retain(|_, e| e.fetched.elapsed() < keep);
        cache.insert(
            host,
            CacheEntry {
                addrs,
                fetched: Instant::now(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::Engine as _;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::extension::BasicConstraints;
    use openssl::x509::{X509Builder, X509NameBuilder};

    fn cfg(ca: &str) -> MachineIdentityConfig {
        MachineIdentityConfig {
            enabled: true,
            machine_ca: ca.to_owned(),
            ..MachineIdentityConfig::default()
        }
    }

    fn p256_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    fn name(cn: &str) -> openssl::x509::X509Name {
        let mut b = X509NameBuilder::new().unwrap();
        b.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
        b.build()
    }

    /// A self-signed CA: returns the certificate and its key.
    fn make_ca(cn: &str) -> (X509, PKey<Private>) {
        let key = p256_key();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        b.set_subject_name(&name(cn)).unwrap();
        b.set_issuer_name(&name(cn)).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::days_from_now(3650).unwrap()).unwrap();
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        (b.build(), key)
    }

    /// A leaf signed by `ca`, valid over the given absolute unix-time window.
    fn make_leaf_between(
        cn: &str,
        ca: &(X509, PKey<Private>),
        not_before: i64,
        not_after: i64,
    ) -> X509 {
        let key = p256_key();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&BigNum::from_u32(42).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        b.set_subject_name(&name(cn)).unwrap();
        b.set_issuer_name(ca.0.subject_name()).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::from_unix(not_before).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::from_unix(not_after).unwrap()).unwrap();
        b.sign(&ca.1, MessageDigest::sha256()).unwrap();
        b.build()
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn make_leaf(cn: &str, ca: &(X509, PKey<Private>)) -> X509 {
        make_leaf_between(cn, ca, now() - 3600, now() + 86_400)
    }

    fn b64(cert: &X509) -> String {
        base64::engine::general_purpose::STANDARD.encode(cert.to_der().unwrap())
    }

    /// A verifier trusting `ca`, with the given hostname allowlist.
    fn verifier(ca: &(X509, PKey<Private>), allowed: &[&str]) -> MachineIdentity {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("machine-ca.pem");
        std::fs::write(&path, ca.0.to_pem().unwrap()).unwrap();
        MachineIdentity::from_config(&MachineIdentityConfig {
            allowed_hostnames: allowed.iter().map(|s| s.to_string()).collect(),
            ..cfg(path.to_str().unwrap())
        })
        .unwrap()
        .unwrap()
    }

    #[test]
    fn accepts_a_cert_issued_by_the_machine_ca() {
        let ca = make_ca("Test Machine CA");
        let v = verifier(&ca, &[]);
        let leaf = make_leaf("ws-4417.corp.example.com", &ca);
        assert_eq!(
            v.verify_cert(&b64(&leaf)).unwrap(),
            "ws-4417.corp.example.com"
        );
    }

    #[test]
    fn rejects_a_cert_from_another_ca() {
        let ours = make_ca("Test Machine CA");
        let theirs = make_ca("Someone Else CA");
        let v = verifier(&ours, &[]);
        let leaf = make_leaf("ws-4417.corp.example.com", &theirs);
        assert!(matches!(
            v.verify_cert(&b64(&leaf)),
            Err(MachineError::UntrustedChain(_))
        ));
    }

    #[test]
    fn rejects_an_expired_cert() {
        let ca = make_ca("Test Machine CA");
        let v = verifier(&ca, &[]);
        // Valid from two days ago until one day ago.
        let leaf = make_leaf_between(
            "ws-4417.corp.example.com",
            &ca,
            now() - 172_800,
            now() - 86_400,
        );
        let err = v.verify_cert(&b64(&leaf)).unwrap_err();
        assert!(
            matches!(&err, MachineError::UntrustedChain(r) if r.contains("expired")),
            "expected an expiry reason, got: {err}"
        );
    }

    #[test]
    fn rejects_a_not_yet_valid_cert() {
        let ca = make_ca("Test Machine CA");
        let v = verifier(&ca, &[]);
        let leaf = make_leaf_between(
            "ws-4417.corp.example.com",
            &ca,
            now() + 86_400,
            now() + 172_800,
        );
        assert!(matches!(
            v.verify_cert(&b64(&leaf)),
            Err(MachineError::UntrustedChain(_))
        ));
    }

    #[test]
    fn rejects_malformed_input() {
        let ca = make_ca("Test Machine CA");
        let v = verifier(&ca, &[]);
        assert!(matches!(
            v.verify_cert("not base64!!"),
            Err(MachineError::NotBase64)
        ));
        let not_a_cert = base64::engine::general_purpose::STANDARD.encode(b"hello");
        assert!(matches!(
            v.verify_cert(&not_a_cert),
            Err(MachineError::NotDer)
        ));
    }

    #[test]
    fn rejects_a_cert_with_no_common_name() {
        let ca = make_ca("Test Machine CA");
        let v = verifier(&ca, &[]);
        let key = p256_key();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&BigNum::from_u32(7).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        b.set_subject_name(&X509NameBuilder::new().unwrap().build()).unwrap();
        b.set_issuer_name(ca.0.subject_name()).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
        b.sign(&ca.1, MessageDigest::sha256()).unwrap();
        assert!(matches!(
            v.verify_cert(&b64(&b.build())),
            Err(MachineError::NoCommonName)
        ));
    }

    #[test]
    fn rejects_a_common_name_that_would_corrupt_the_audit_log() {
        // The proxy's log output is the only record this product produces, so a
        // CA that signs a name containing a newline must not be able to forge
        // log lines through it.
        let ca = make_ca("Test Machine CA");
        let v = verifier(&ca, &[]);
        for bad in ["ws-1\naccepted — GET evil.example.com/", "ws 1", "ws-\u{00e9}1"] {
            let leaf = make_leaf(bad, &ca);
            assert!(
                matches!(v.verify_cert(&b64(&leaf)), Err(MachineError::UnsafeCommonName)),
                "should have rejected {bad:?}"
            );
        }
    }

    #[test]
    fn allowlist_globs_gate_the_hostname() {
        let ca = make_ca("Test Machine CA");
        let v = verifier(&ca, &["ws-*.corp.example.com", "kiosk-*.corp.example.com"]);

        assert_eq!(
            v.verify_cert(&b64(&make_leaf("ws-4417.corp.example.com", &ca)))
                .unwrap(),
            "ws-4417.corp.example.com"
        );
        assert_eq!(
            v.verify_cert(&b64(&make_leaf("kiosk-9.corp.example.com", &ca)))
                .unwrap(),
            "kiosk-9.corp.example.com"
        );

        // Signed by the right CA, but not a name this proxy accepts.
        let err = v
            .verify_cert(&b64(&make_leaf("laptop-1.corp.example.com", &ca)))
            .unwrap_err();
        assert!(
            matches!(&err, MachineError::HostnameNotAllowed(h) if h == "laptop-1.corp.example.com"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_a_disallowed_hostname_before_chain_verification() {
        let ours = make_ca("Test Machine CA");
        let theirs = make_ca("Someone Else CA");
        let v = verifier(&ours, &["ws-*.corp.example.com"]);

        // Both checks would fail.  The allowlist result proves that the cheap
        // rejection happens before the certificate's foreign signature would
        // reach X.509 chain verification.
        let err = v
            .verify_cert(&b64(&make_leaf("laptop-1.corp.example.com", &theirs)))
            .unwrap_err();
        assert!(
            matches!(&err, MachineError::HostnameNotAllowed(h) if h == "laptop-1.corp.example.com"),
            "got: {err}"
        );
    }

    #[test]
    fn hostname_matching_is_case_insensitive() {
        // DNS names are case-insensitive, so an uppercase CN must not slip past
        // a lowercase pattern — nor produce an uppercase audit entry.
        let ca = make_ca("Test Machine CA");
        let v = verifier(&ca, &["ws-*.corp.example.com"]);
        assert_eq!(
            v.verify_cert(&b64(&make_leaf("WS-4417.CORP.EXAMPLE.COM", &ca)))
                .unwrap(),
            "ws-4417.corp.example.com"
        );
    }

    #[test]
    fn empty_allowlist_accepts_any_name_the_ca_signed() {
        let ca = make_ca("Test Machine CA");
        let v = verifier(&ca, &[]);
        assert_eq!(
            v.verify_cert(&b64(&make_leaf("anything.internal", &ca))).unwrap(),
            "anything.internal"
        );
    }

    #[test]
    fn from_config_rejects_an_invalid_glob() {
        let ca = make_ca("Test Machine CA");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("machine-ca.pem");
        std::fs::write(&path, ca.0.to_pem().unwrap()).unwrap();
        let err = MachineIdentity::from_config(&MachineIdentityConfig {
            allowed_hostnames: vec!["ws-[".into()],
            ..cfg(path.to_str().unwrap())
        })
        .err()
        .expect("an unparseable glob must abort startup, not silently never match");
        assert!(err.to_string().contains("allowed_hostnames pattern"), "got: {err}");
    }

    // ── Forward-DNS check and its cache ──────────────────────────────────────

    /// A scripted resolver: counts calls, and can be flipped to fail so the
    /// stale-fallback path is exercised without a network.
    struct FakeResolver {
        addrs: Mutex<Vec<IpAddr>>,
        failing: std::sync::atomic::AtomicBool,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl FakeResolver {
        fn new(addrs: &[&str]) -> Self {
            Self {
                addrs: Mutex::new(addrs.iter().map(|a| a.parse().unwrap()).collect()),
                failing: std::sync::atomic::AtomicBool::new(false),
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn set_failing(&self, v: bool) {
            self.failing.store(v, std::sync::atomic::Ordering::SeqCst);
        }
        fn set_addrs(&self, addrs: &[&str]) {
            *self.addrs.lock().unwrap() = addrs.iter().map(|a| a.parse().unwrap()).collect();
        }
    }

    #[async_trait]
    impl Resolver for std::sync::Arc<FakeResolver> {
        async fn resolve(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(std::io::Error::other("resolver down"));
            }
            Ok(self.addrs.lock().unwrap().clone())
        }
    }

    /// A verifier trusting `ca` and using `resolver`, with the given TTLs.
    fn verifier_with(
        ca: &(X509, PKey<Private>),
        resolver: std::sync::Arc<FakeResolver>,
        ttl: u64,
        negative_ttl: u64,
        grace: u64,
    ) -> MachineIdentity {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("machine-ca.pem");
        std::fs::write(&path, ca.0.to_pem().unwrap()).unwrap();
        MachineIdentity::from_config_with_resolver(
            &MachineIdentityConfig {
                dns_ttl_secs: ttl,
                dns_negative_ttl_secs: negative_ttl,
                dns_stale_grace_secs: grace,
                ..cfg(path.to_str().unwrap())
            },
            Box::new(resolver),
        )
        .unwrap()
        .unwrap()
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[tokio::test]
    async fn accepts_when_the_name_resolves_to_the_client_address() {
        let ca = make_ca("Test Machine CA");
        let r = std::sync::Arc::new(FakeResolver::new(&["10.4.2.17"]));
        let v = verifier_with(&ca, r.clone(), 300, 30, 3600);
        let leaf = make_leaf("ws-4417.corp.example.com", &ca);
        assert_eq!(
            v.verify(&b64(&leaf), ip("10.4.2.17")).await.unwrap(),
            "ws-4417.corp.example.com"
        );
    }

    #[tokio::test]
    async fn rejects_a_valid_cert_presented_from_another_address() {
        // This is the check that carries the weight in place of proof of
        // possession: a copied certificate only works from an address the name
        // actually points at.
        let ca = make_ca("Test Machine CA");
        let r = std::sync::Arc::new(FakeResolver::new(&["10.4.2.17"]));
        let v = verifier_with(&ca, r.clone(), 300, 30, 3600);
        let leaf = make_leaf("ws-4417.corp.example.com", &ca);
        let err = v.verify(&b64(&leaf), ip("192.0.2.99")).await.unwrap_err();
        assert!(
            matches!(&err, MachineError::HostnameAddressMismatch { cn, ip }
                     if cn == "ws-4417.corp.example.com" && ip.to_string() == "192.0.2.99"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn rejects_when_there_is_no_client_address() {
        let ca = make_ca("Test Machine CA");
        let r = std::sync::Arc::new(FakeResolver::new(&["10.4.2.17"]));
        let v = verifier_with(&ca, r.clone(), 300, 30, 3600);
        let leaf = make_leaf("ws-4417.corp.example.com", &ca);
        assert!(matches!(
            v.verify(&b64(&leaf), None).await,
            Err(MachineError::NoClientAddress)
        ));
        // Rejected before any lookup — nothing to look up against.
        assert_eq!(r.calls(), 0);
    }

    #[tokio::test]
    async fn repeated_requests_hit_the_cache_not_the_resolver() {
        let ca = make_ca("Test Machine CA");
        let r = std::sync::Arc::new(FakeResolver::new(&["10.4.2.17"]));
        let v = verifier_with(&ca, r.clone(), 300, 30, 3600);
        let cert = b64(&make_leaf("ws-4417.corp.example.com", &ca));
        for _ in 0..25 {
            v.verify(&cert, ip("10.4.2.17")).await.unwrap();
        }
        assert_eq!(r.calls(), 1, "25 requests should cost exactly one lookup");
    }

    #[tokio::test]
    async fn an_expired_entry_is_refetched() {
        let ca = make_ca("Test Machine CA");
        let r = std::sync::Arc::new(FakeResolver::new(&["10.4.2.17"]));
        // Zero TTL: every request re-resolves.
        let v = verifier_with(&ca, r.clone(), 0, 0, 3600);
        let cert = b64(&make_leaf("ws-4417.corp.example.com", &ca));
        v.verify(&cert, ip("10.4.2.17")).await.unwrap();
        // A machine that moved is picked up rather than pinned by a stale entry.
        r.set_addrs(&["10.4.2.18"]);
        assert!(matches!(
            v.verify(&cert, ip("10.4.2.17")).await,
            Err(MachineError::HostnameAddressMismatch { .. })
        ));
        assert_eq!(r.calls(), 2);
    }

    #[tokio::test]
    async fn a_resolver_outage_is_covered_by_a_stale_entry() {
        let ca = make_ca("Test Machine CA");
        let r = std::sync::Arc::new(FakeResolver::new(&["10.4.2.17"]));
        // TTL 0 forces a refetch attempt on every call; the grace window is what
        // keeps the last good answer usable once the resolver starts failing.
        let v = verifier_with(&ca, r.clone(), 0, 0, 3600);
        let cert = b64(&make_leaf("ws-4417.corp.example.com", &ca));

        v.verify(&cert, ip("10.4.2.17")).await.expect("warms the cache");
        r.set_failing(true);
        v.verify(&cert, ip("10.4.2.17"))
            .await
            .expect("a resolver outage must not become a proxy outage");
    }

    #[tokio::test]
    async fn a_resolver_outage_with_a_cold_cache_still_rejects() {
        // The other half of the stale-fallback bargain: it only refuses to
        // forget what was already proved, it never waves through the unproven.
        let ca = make_ca("Test Machine CA");
        let r = std::sync::Arc::new(FakeResolver::new(&["10.4.2.17"]));
        let v = verifier_with(&ca, r.clone(), 300, 30, 3600);
        r.set_failing(true);
        let cert = b64(&make_leaf("ws-4417.corp.example.com", &ca));
        assert!(matches!(
            v.verify(&cert, ip("10.4.2.17")).await,
            Err(MachineError::HostnameUnresolvable(_))
        ));
    }

    #[tokio::test]
    async fn a_stale_entry_past_the_grace_window_stops_covering() {
        let ca = make_ca("Test Machine CA");
        let r = std::sync::Arc::new(FakeResolver::new(&["10.4.2.17"]));
        // No grace at all: a failing resolver rejects immediately.
        let v = verifier_with(&ca, r.clone(), 0, 0, 0);
        let cert = b64(&make_leaf("ws-4417.corp.example.com", &ca));
        v.verify(&cert, ip("10.4.2.17")).await.expect("warms the cache");
        r.set_failing(true);
        assert!(matches!(
            v.verify(&cert, ip("10.4.2.17")).await,
            Err(MachineError::HostnameUnresolvable(_))
        ));
    }

    #[tokio::test]
    async fn a_name_resolving_to_nothing_is_rejected_and_negatively_cached() {
        let ca = make_ca("Test Machine CA");
        let r = std::sync::Arc::new(FakeResolver::new(&[]));
        let v = verifier_with(&ca, r.clone(), 300, 30, 3600);
        let cert = b64(&make_leaf("ws-4417.corp.example.com", &ca));
        for _ in 0..5 {
            assert!(matches!(
                v.verify(&cert, ip("10.4.2.17")).await,
                Err(MachineError::HostnameUnresolvable(_))
            ));
        }
        assert_eq!(
            r.calls(),
            1,
            "an unprovisioned machine must not query on every request"
        );
    }

    #[tokio::test]
    async fn an_allowlist_miss_never_reaches_the_resolver() {
        // Ordering matters: a flood of bogus names must not be convertible into
        // resolver load.
        let ca = make_ca("Test Machine CA");
        let r = std::sync::Arc::new(FakeResolver::new(&["10.4.2.17"]));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("machine-ca.pem");
        std::fs::write(&path, ca.0.to_pem().unwrap()).unwrap();
        let v = MachineIdentity::from_config_with_resolver(
            &MachineIdentityConfig {
                allowed_hostnames: vec!["ws-*.corp.example.com".into()],
                ..cfg(path.to_str().unwrap())
            },
            Box::new(r.clone()),
        )
        .unwrap()
        .unwrap();

        let cert = b64(&make_leaf("laptop-1.corp.example.com", &ca));
        assert!(matches!(
            v.verify(&cert, ip("10.4.2.17")).await,
            Err(MachineError::HostnameNotAllowed(_))
        ));
        assert_eq!(r.calls(), 0);
    }

    #[tokio::test]
    async fn an_untrusted_cert_never_reaches_the_resolver() {
        let ours = make_ca("Test Machine CA");
        let theirs = make_ca("Someone Else CA");
        let r = std::sync::Arc::new(FakeResolver::new(&["10.4.2.17"]));
        let v = verifier_with(&ours, r.clone(), 300, 30, 3600);
        let cert = b64(&make_leaf("ws-4417.corp.example.com", &theirs));
        assert!(matches!(
            v.verify(&cert, ip("10.4.2.17")).await,
            Err(MachineError::UntrustedChain(_))
        ));
        assert_eq!(r.calls(), 0);
    }

    #[tokio::test]
    async fn the_cache_is_swept_rather_than_growing_without_bound() {
        let ca = make_ca("Test Machine CA");
        let r = std::sync::Arc::new(FakeResolver::new(&["10.4.2.17"]));
        // Everything expires immediately, so each insert sweeps the last.
        let v = verifier_with(&ca, r.clone(), 0, 0, 0);
        for i in 0..50 {
            let cert = b64(&make_leaf(&format!("ws-{i}.corp.example.com"), &ca));
            let _ = v.verify(&cert, ip("10.4.2.17")).await;
        }
        assert!(
            v.dns_cache.lock().unwrap().len() <= 1,
            "expired entries should be swept on insert, found {}",
            v.dns_cache.lock().unwrap().len()
        );
    }

    #[test]
    fn from_config_rejects_an_uppercase_glob() {
        // Names are lowercased before matching, so an uppercase pattern could
        // never match anything — fail loudly instead of rejecting the fleet.
        let ca = make_ca("Test Machine CA");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("machine-ca.pem");
        std::fs::write(&path, ca.0.to_pem().unwrap()).unwrap();
        let err = MachineIdentity::from_config(&MachineIdentityConfig {
            allowed_hostnames: vec!["WS-*.corp.example.com".into()],
            ..cfg(path.to_str().unwrap())
        })
        .err()
        .expect("an uppercase pattern must abort startup");
        assert!(err.to_string().contains("must be lowercase"), "got: {err}");
    }

    #[test]
    fn from_config_disabled_is_none() {
        assert!(
            MachineIdentity::from_config(&MachineIdentityConfig::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn from_config_enabled_requires_ca() {
        let err = MachineIdentity::from_config(&cfg(""))
            .err()
            .expect("empty machine_ca must be rejected");
        assert!(err.to_string().contains("machine_ca is not set"), "got: {err}");
    }

    #[test]
    fn from_config_rejects_missing_ca_file() {
        let err = MachineIdentity::from_config(&cfg("/nonexistent/machine-ca.pem"))
            .err()
            .expect("missing CA file must be rejected");
        assert!(
            err.to_string().contains("cannot read machine_identity machine_ca"),
            "got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_unparseable_ca_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-ca.pem");
        std::fs::write(&path, b"-----BEGIN CERTIFICATE-----\nnope\n").unwrap();
        let err = MachineIdentity::from_config(&cfg(path.to_str().unwrap()))
            .err()
            .expect("unparseable CA must be rejected");
        assert!(
            err.to_string().contains("cannot parse machine_identity machine_ca"),
            "got: {err}"
        );
    }

    #[test]
    fn from_config_rejects_empty_ca_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.pem");
        std::fs::write(&path, b"# no certificates here\n").unwrap();
        let err = MachineIdentity::from_config(&cfg(path.to_str().unwrap()))
            .err()
            .expect("empty bundle must be rejected");
        assert!(err.to_string().contains("contains no certificates"), "got: {err}");
    }
}

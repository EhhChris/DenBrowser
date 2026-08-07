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
//! 2. chain-verify against `machine_ca`
//! 3. extract the Common Name, lowercase it, reject control characters
//! 4. match it against the `allowed_hostnames` globs (in memory)
//! 5. forward-resolve it and require the client IP among the answers
//!
//! Step 4 sits before step 5 deliberately: an allowlist miss is rejected without
//! a lookup, so a flood of bogus names cannot be turned into resolver load.

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
        }
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
}

impl MachineIdentity {
    /// Parse and validate `[machine_identity]`.  Returns `None` when disabled,
    /// or an error that aborts startup rather than bringing up a proxy that
    /// would reject every request (or, worse, accept unverifiable ones).
    /// Mirrors [`crate::mtls::Mtls::from_config`].
    pub fn from_config(cfg: &MachineIdentityConfig) -> anyhow::Result<Option<Self>> {
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

    /// Steps 1–4: decode, chain-verify, extract and sanitize the Common Name,
    /// and match it against the allowlist.  Returns the normalized (lowercase)
    /// hostname.  The forward-DNS check is applied separately by the caller.
    pub fn verify_cert(&self, cert_b64: &str) -> Result<String, MachineError> {
        use base64::Engine as _;

        let der = base64::engine::general_purpose::STANDARD
            .decode(cert_b64.trim())
            .map_err(|_| MachineError::NotBase64)?;
        let cert = X509::from_der(&der).map_err(|_| MachineError::NotDer)?;

        // Chain-verify against the machine CA.  The presented certificate is a
        // bare leaf, so the untrusted-chain pool is empty.
        let empty: Stack<X509> = Stack::new().map_err(|e| MachineError::UntrustedChain(e.to_string()))?;
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

        Ok(cn)
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

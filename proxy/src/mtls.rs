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
//! (subject DN, Common Name, and SubjectAltName DNS entries) into the
//! connection's TLS digest as a [`ClientCert`].  Because the handshake already
//! enforced validity, the callback does not re-verify — it only extracts the
//! identity so the request path can read it (for the audit record, and for the
//! bypass subject allowlist).
//! That includes resumed handshakes: `main` sets a session-ID context so
//! client-authenticated sessions can be resumed, and on a resumed connection
//! `peer_certificate()` returns the certificate stored in the session, which
//! was verified at the full handshake that created it.
//!
//! mTLS is one orthogonal layer among four: it authenticates the *user* (client
//! → proxy), TLS SPKI pinning authenticates the *proxy* to the browser (proxy →
//! client), attestation attempts to prove the request came from a genuine
//! DenBrowser build and binds it against replay/tampering, and machine
//! identity ([`crate::machine`]) names the *workstation* it came from.  None
//! replaces another.

use std::any::Any;
use std::sync::Arc;

use async_trait::async_trait;
use pingora_core::listeners::{TlsAccept, TlsAcceptCallbacks};
use pingora_core::tls::nid::Nid;
use pingora_core::tls::ssl::SslRef;
use pingora_core::tls::x509::{X509, X509NameRef, X509Ref};

use crate::config::MtlsConfig;

/// The verified identity of a connection's mTLS client certificate, attached to
/// the TLS digest by [`Recorder`] and read back in the request path via
/// `SslDigestExtension::get::<ClientCert>()`.
#[derive(Debug, Clone)]
pub struct ClientCert {
    /// The full subject, as an RFC 4514 string (see [`distinguished_name`]).
    pub subject_dn: String,
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

    /// Extract the identity from a certificate.
    ///
    /// Shared with [`crate::machine`], which needs the same subject DN, Common
    /// Name, and SubjectAltName semantics for the machine certificate — keeping
    /// one implementation stops the two identity paths from drifting apart.
    /// Note this only *reads* the subject; the caller is responsible for having
    /// established that the certificate is trusted.
    pub fn from_cert(cert: &X509Ref) -> Self {
        let subject_dn = distinguished_name(cert.subject_name());

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
            subject_dn,
            common_name,
            san_dns,
        }
    }
}

/// Render a certificate name as an RFC 4514 string, most specific RDN first,
/// e.g. `CN=alice,OU=Staff,O=Example Corp,C=US`.
///
/// Unknown attributes are named by dotted OID.  Control characters are always
/// hex-escaped, so a hostile certificate cannot smuggle a line break through.
/// Each entry is rendered as its own RDN, so multi-valued RDNs use `,`, not `+`.
pub fn distinguished_name(name: &X509NameRef) -> String {
    let mut out = String::new();
    let entries: Vec<_> = name.entries().collect();
    for (i, entry) in entries.iter().rev().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let object = entry.object();
        let nid = object.nid();
        match nid.short_name() {
            Ok(short) if nid != Nid::UNDEF => out.push_str(short),
            _ => out.push_str(&object.to_string()),
        }
        out.push('=');
        let value = match entry.data().as_utf8() {
            Ok(utf8) => utf8.to_string(),
            Err(_) => String::from_utf8_lossy(entry.data().as_slice()).into_owned(),
        };
        escape_dn_value(&value, &mut out);
    }
    out
}

/// Escape one attribute value per RFC 4514 §2.4.
fn escape_dn_value(value: &str, out: &mut String) {
    use std::fmt::Write as _;

    let last = value.chars().count().saturating_sub(1);
    for (i, c) in value.chars().enumerate() {
        match c {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '#' if i == 0 => out.push_str("\\#"),
            ' ' if i == 0 || i == last => out.push_str("\\ "),
            c if c.is_control() => {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).bytes() {
                    let _ = write!(out, "\\{b:02X}");
                }
            }
            c => out.push(c),
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
            subject_dn: cn.map(|c| format!("CN={c}")).unwrap_or_default(),
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

    fn name(entries: &[(&str, &str)]) -> pingora_core::tls::x509::X509Name {
        let mut b = pingora_core::tls::x509::X509NameBuilder::new().unwrap();
        for (field, value) in entries {
            b.append_entry_by_text(field, value).unwrap();
        }
        b.build()
    }

    #[test]
    fn dn_is_rfc4514_most_specific_first() {
        let n = name(&[("C", "US"), ("O", "Example Corp"), ("OU", "Staff"), ("CN", "alice")]);
        assert_eq!(distinguished_name(&n), "CN=alice,OU=Staff,O=Example Corp,C=US");
    }

    #[test]
    fn dn_escapes_rfc4514_specials() {
        let n = name(&[("O", "Smith, Jones + Co; \"Ltd\" <x>"), ("CN", "#1 user ")]);
        assert_eq!(
            distinguished_name(&n),
            r#"CN=\#1 user\ ,O=Smith\, Jones \+ Co\; \"Ltd\" \<x\>"#
        );
    }

    #[test]
    fn dn_hex_escapes_control_characters() {
        // A CA that signs a name containing a newline must not be able to
        // break a line in whatever renders the DN.
        let n = name(&[("CN", "ws-1\naccepted")]);
        assert_eq!(distinguished_name(&n), r"CN=ws-1\0Aaccepted");
    }

    #[test]
    fn dn_keeps_non_ascii_text() {
        let n = name(&[("CN", "Zoë Ångström")]);
        assert_eq!(distinguished_name(&n), "CN=Zoë Ångström");
    }

    #[test]
    fn dn_names_unknown_attributes_by_oid() {
        let n = name(&[("1.3.6.1.4.1.55555.1", "x"), ("CN", "a")]);
        assert_eq!(distinguished_name(&n), "CN=a,1.3.6.1.4.1.55555.1=x");
    }

    #[test]
    fn dn_of_an_empty_name_is_empty() {
        assert_eq!(distinguished_name(&name(&[])), "");
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

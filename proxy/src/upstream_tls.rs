//! Outbound TLS trust, loaded once at startup and applied to each upstream peer.
//!
//! A configured PEM bundle replaces Pingora's default CA store for upstream
//! connections. An omitted bundle leaves the connector's system trust intact.
//! This is independent of the CAs used to authenticate incoming clients.

use std::sync::Arc;

use pingora_core::protocols::tls::CaType;
use pingora_core::tls::x509::X509;
use pingora_core::upstreams::peer::HttpPeer;

use crate::config::ProxyConfig;

#[derive(Debug)]
pub struct UpstreamTls {
    ca_certs: Option<Arc<CaType>>,
    insecure: bool,
}

impl UpstreamTls {
    /// Validate any configured CA bundle even when verification is explicitly
    /// disabled, so a configuration error always fails at startup.
    pub fn from_config(cfg: &ProxyConfig, insecure: bool) -> anyhow::Result<Self> {
        let ca_certs = if cfg.upstream_ca.is_empty() {
            None
        } else {
            let path = &cfg.upstream_ca;
            let pem = std::fs::read(path)
                .map_err(|e| anyhow::anyhow!("cannot read [proxy].upstream_ca {path}: {e}"))?;
            let certs = X509::stack_from_pem(&pem)
                .map_err(|e| anyhow::anyhow!("cannot parse [proxy].upstream_ca {path}: {e}"))?;
            if certs.is_empty() {
                anyhow::bail!("[proxy].upstream_ca {path} contains no certificates");
            }
            Some(Arc::new(certs.into_boxed_slice()))
        };
        Ok(Self { ca_certs, insecure })
    }

    /// Pingora installs `ca` as the connection's certificate verification store;
    /// it does not add these certificates to the connector's default roots.
    pub fn apply(&self, peer: &mut HttpPeer) {
        peer.options.ca = self.ca_certs.clone();
        peer.options.verify_cert = !self.insecure;
        peer.options.verify_hostname = !self.insecure;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::ssl::{SslAcceptor, SslMethod};
    use openssl::x509::extension::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    };
    use openssl::x509::{X509Builder, X509NameBuilder};
    use pingora_core::connectors::{ConnectorOptions, TransportConnector};
    use tokio::time::timeout;

    const HOSTNAME: &str = "upstream.test";
    const TIMEOUT: Duration = Duration::from_secs(5);
    type Certificate = (X509, PKey<Private>);

    fn certificate(cn: &str, issuer: Option<&Certificate>) -> Certificate {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
        let name = name.build();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(issuer.map(|ca| ca.0.subject_name()).unwrap_or(&name))
            .unwrap();
        b.set_pubkey(&key).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        b.set_not_before(&Asn1Time::from_unix(now - 60).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::from_unix(now + 3600).unwrap())
            .unwrap();
        if let Some(ca) = issuer {
            b.append_extension(BasicConstraints::new().critical().build().unwrap())
                .unwrap();
            b.append_extension(KeyUsage::new().digital_signature().build().unwrap())
                .unwrap();
            b.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
                .unwrap();
            let san = SubjectAlternativeName::new()
                .dns(cn)
                .build(&b.x509v3_context(Some(&ca.0), None))
                .unwrap();
            b.append_extension(san).unwrap();
            b.sign(&ca.1, MessageDigest::sha256()).unwrap();
        } else {
            b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            b.append_extension(KeyUsage::new().key_cert_sign().crl_sign().build().unwrap())
                .unwrap();
            b.sign(&key, MessageDigest::sha256()).unwrap();
        }
        (b.build(), key)
    }

    fn config(path: String) -> ProxyConfig {
        ProxyConfig {
            upstream_ca: path,
            ..ProxyConfig::default()
        }
    }

    fn write_bundle(dir: &tempfile::TempDir, name: &str, cas: &[&X509]) -> String {
        let path = dir.path().join(name);
        let pem: Vec<u8> = cas.iter().flat_map(|ca| ca.to_pem().unwrap()).collect();
        std::fs::write(&path, pem).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn trust(cas: &[&X509], insecure: bool) -> UpstreamTls {
        let dir = tempfile::tempdir().unwrap();
        let path = write_bundle(&dir, "upstream-ca.pem", cas);
        // The temporary bundle is removed before any connection is made: peers
        // must receive the already parsed certificates without reopening it.
        UpstreamTls::from_config(&config(path), insecure).unwrap()
    }

    #[test]
    fn omitted_ca_preserves_default_trust_and_verification() {
        let tls = UpstreamTls::from_config(&ProxyConfig::default(), false).unwrap();
        let mut peer = HttpPeer::new("127.0.0.1:443", true, HOSTNAME.into());
        tls.apply(&mut peer);
        assert!(peer.options.ca.is_none());
        assert!(peer.options.verify_cert);
        assert!(peer.options.verify_hostname);
    }

    #[test]
    fn unreadable_ca_names_the_setting_and_path_even_when_insecure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.pem").to_str().unwrap().to_owned();
        for insecure in [false, true] {
            let error = UpstreamTls::from_config(&config(path.clone()), insecure)
                .unwrap_err()
                .to_string();
            assert!(error.contains("cannot read [proxy].upstream_ca"), "{error}");
            assert!(error.contains(&path), "{error}");
        }
    }

    #[test]
    fn empty_and_invalid_bundles_fail_at_startup_even_when_insecure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.pem").to_str().unwrap().to_owned();
        for pem in [
            "",
            "not a certificate",
            "-----BEGIN CERTIFICATE-----\nbad\n-----END CERTIFICATE-----\n",
        ] {
            std::fs::write(&path, pem).unwrap();
            for insecure in [false, true] {
                let error = UpstreamTls::from_config(&config(path.clone()), insecure)
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("[proxy].upstream_ca"), "{error}");
                assert!(error.contains(&path), "{error}");
            }
        }
    }

    #[test]
    fn parsed_bundle_is_shared_across_peers_and_insecure_disables_both_checks() {
        let ca = certificate("Test CA", None);
        let tls = trust(&[&ca.0], true);
        let mut a = HttpPeer::new("127.0.0.1:443", true, HOSTNAME.into());
        let mut b = a.clone();
        tls.apply(&mut a);
        tls.apply(&mut b);
        assert!(Arc::ptr_eq(
            a.options.ca.as_ref().unwrap(),
            b.options.ca.as_ref().unwrap()
        ));
        assert!(!a.options.verify_cert);
        assert!(!a.options.verify_hostname);
    }

    /// Exercise the real Pingora connection path against a local TLS server.
    /// Both the async connection and the blocking OpenSSL server handshake have
    /// timeouts, and every server accepts one connection on an ephemeral port.
    async fn handshake(
        tls: &UpstreamTls,
        server_cert: &Certificate,
        connector_ca: Option<String>,
    ) -> pingora_core::Result<()> {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_certificate(&server_cert.0).unwrap();
        acceptor.set_private_key(&server_cert.1).unwrap();
        acceptor.check_private_key().unwrap();
        let acceptor = acceptor.build();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = timeout(TIMEOUT, listener.accept()).await.unwrap().unwrap();
            let stream = stream.into_std().unwrap();
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(TIMEOUT)).unwrap();
            stream.set_write_timeout(Some(TIMEOUT)).unwrap();
            tokio::task::spawn_blocking(move || {
                acceptor
                    .accept(stream)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            })
            .await
            .unwrap()
        });

        let mut options = ConnectorOptions::new(1);
        options.ca_file = connector_ca;
        let connector = TransportConnector::new(Some(options));
        let mut peer = HttpPeer::new(address, true, HOSTNAME.into());
        peer.options.connection_timeout = Some(TIMEOUT);
        tls.apply(&mut peer);
        let result = timeout(TIMEOUT, connector.new_stream(&peer))
            .await
            .expect("upstream handshake timed out");
        let server_result = timeout(TIMEOUT + TIMEOUT, server)
            .await
            .expect("TLS server timed out")
            .unwrap();
        if result.is_ok() {
            assert!(
                server_result.is_ok(),
                "TLS server rejected a successful connection: {server_result:?}"
            );
        }
        result.map(|_| ())
    }

    #[tokio::test]
    async fn configured_private_ca_accepts_matching_hostname() {
        let ca = certificate("Private CA", None);
        let leaf = certificate(HOSTNAME, Some(&ca));
        assert!(
            handshake(&trust(&[&ca.0], false), &leaf, None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn trusted_ca_does_not_disable_hostname_verification() {
        let ca = certificate("Private CA", None);
        let leaf = certificate("another.test", Some(&ca));
        let error = handshake(&trust(&[&ca.0], false), &leaf, None)
            .await
            .unwrap_err();
        assert_eq!(
            error.etype(),
            &pingora_core::ErrorType::InvalidCert,
            "{error}"
        );
    }

    #[tokio::test]
    async fn unrelated_ca_rejects_matching_hostname() {
        let ca = certificate("Private CA", None);
        let unrelated = certificate("Unrelated CA", None);
        let leaf = certificate(HOSTNAME, Some(&ca));
        let error = handshake(&trust(&[&unrelated.0], false), &leaf, None)
            .await
            .unwrap_err();
        assert_eq!(
            error.etype(),
            &pingora_core::ErrorType::InvalidCert,
            "{error}"
        );
    }

    #[tokio::test]
    async fn every_root_in_a_bundle_can_authenticate_the_upstream() {
        let a = certificate("Private CA A", None);
        let b = certificate("Private CA B", None);
        let tls = trust(&[&a.0, &b.0], false);
        assert_eq!(tls.ca_certs.as_ref().unwrap().len(), 2);
        for ca in [&a, &b] {
            let leaf = certificate(HOSTNAME, Some(ca));
            assert!(handshake(&tls, &leaf, None).await.is_ok());
        }
    }

    #[tokio::test]
    async fn configured_bundle_replaces_the_connectors_default_roots() {
        let default_ca = certificate("Connector default CA", None);
        let custom_ca = certificate("Configured upstream CA", None);
        let default_leaf = certificate(HOSTNAME, Some(&default_ca));
        let custom_leaf = certificate(HOSTNAME, Some(&custom_ca));
        let dir = tempfile::tempdir().unwrap();
        let default_path = write_bundle(&dir, "connector-ca.pem", &[&default_ca.0]);
        let defaults = UpstreamTls::from_config(&ProxyConfig::default(), false).unwrap();
        assert!(
            handshake(&defaults, &default_leaf, Some(default_path.clone()))
                .await
                .is_ok()
        );

        let custom = trust(&[&custom_ca.0], false);
        let error = handshake(&custom, &default_leaf, Some(default_path.clone()))
            .await
            .unwrap_err();
        assert_eq!(
            error.etype(),
            &pingora_core::ErrorType::InvalidCert,
            "{error}"
        );
        assert!(
            handshake(&custom, &custom_leaf, Some(default_path))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn insecure_override_accepts_untrusted_ca_and_wrong_hostname() {
        let ca = certificate("Private CA", None);
        let unrelated = certificate("Unrelated CA", None);
        let leaf = certificate("another.test", Some(&ca));
        assert!(
            handshake(&trust(&[&unrelated.0], true), &leaf, None)
                .await
                .is_ok()
        );
    }
}

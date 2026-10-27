//! The listener's TLS private key, optionally passphrase-protected.
//!
//! The key used to reach OpenSSL as a path (`set_private_key_file`, which
//! `TlsSettings::intermediate` also uses).  That call has no way to supply a
//! passphrase, so on an encrypted key OpenSSL falls back to its interactive
//! default: `Enter PEM pass phrase:` on the terminal.  A foreground run blocks
//! there; under systemd or in a container, with no terminal, the read hits EOF
//! and startup aborts with UI-library errors that never mention configuration.
//!
//! [`load`] reads and decrypts the key itself instead, with the passphrase from
//! `[proxy].tls_key_passphrase` or `[proxy].tls_key_passphrase_file`, and hands
//! `main` a ready [`PKey`].  The passphrase is supplied through a callback that
//! OpenSSL invokes only when the key is actually encrypted, so whether it ran
//! tells the two cases apart: an encrypted key with no passphrase configured
//! fails with an error naming the settings, and a passphrase configured for a
//! plaintext key is reported rather than silently ignored.
//!
//! Both PEM encryption formats are accepted: PKCS#8 (`BEGIN ENCRYPTED PRIVATE
//! KEY`, which `openssl pkey -aes256` writes) and OpenSSL's legacy one
//! (`Proc-Type: 4,ENCRYPTED`, which `openssl rsa -aes256 -traditional` writes).

use pingora_core::tls::pkey::{PKey, Private};
use tracing::warn;

use crate::config::ProxyConfig;

/// Read `[proxy].tls_key`, decrypting it with the configured passphrase when
/// it is encrypted.
///
/// Every failure aborts startup, as for the other key material: a listener
/// without its key cannot complete a single handshake.  A passphrase set for a
/// plaintext key is not an error — the key still loads — but it is logged,
/// because it usually means the key is not protected at rest the way the
/// operator believes.
pub fn load(cfg: &ProxyConfig) -> anyhow::Result<PKey<Private>> {
    let pem = std::fs::read(&cfg.tls_key)
        .map_err(|e| anyhow::anyhow!("cannot read [proxy].tls_key {}: {e}", cfg.tls_key))?;
    let passphrase = passphrase(cfg)?;

    // Set by the callback, which OpenSSL calls only for an encrypted key — and
    // at most once, because it caches the answer across the decoders it tries.
    let mut encrypted = false;
    let parsed = PKey::private_key_from_pem_callback(&pem, |buf| {
        encrypted = true;
        let pass = passphrase.as_deref().unwrap_or_default();
        // OpenSSL offers about 1 KiB.  A longer passphrase could only be
        // truncated into a wrong one, so supply none and let decryption fail.
        let Some(dest) = buf.get_mut(..pass.len()) else {
            return Ok(0);
        };
        dest.copy_from_slice(pass);
        Ok(pass.len())
    });

    match (parsed, encrypted) {
        (Ok(key), false) if passphrase.is_some() => {
            warn!(
                "[proxy].tls_key {} is not encrypted — the configured passphrase was not used",
                cfg.tls_key
            );
            Ok(key)
        }
        (Ok(key), _) => Ok(key),
        // OpenSSL asked for a passphrase there was none to give: name the
        // settings, rather than surfacing a bare "bad decrypt".
        (Err(_), true) if passphrase.is_none() => anyhow::bail!(
            "[proxy].tls_key {} is encrypted but no passphrase is configured — set \
             [proxy].tls_key_passphrase_file (or [proxy].tls_key_passphrase)",
            cfg.tls_key
        ),
        (Err(e), true) => anyhow::bail!(
            "cannot decrypt [proxy].tls_key {} with the configured passphrase: {e}",
            cfg.tls_key
        ),
        (Err(e), false) => anyhow::bail!("cannot parse [proxy].tls_key {}: {e}", cfg.tls_key),
    }
}

/// The passphrase configured for `tls_key`, if any: `tls_key_passphrase` as
/// written, or the first line of `tls_key_passphrase_file`.  That at most one
/// is set is checked by [`ProxyConfig::validate`].
fn passphrase(cfg: &ProxyConfig) -> anyhow::Result<Option<Vec<u8>>> {
    if !cfg.tls_key_passphrase.is_empty() {
        return Ok(Some(cfg.tls_key_passphrase.expose().as_bytes().to_vec()));
    }
    let path = &cfg.tls_key_passphrase_file;
    if path.is_empty() {
        return Ok(None);
    }
    let contents = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("cannot read [proxy].tls_key_passphrase_file {path}: {e}"))?;
    // First line only, without its line ending — how OpenSSL's own
    // `-passin file:` reads it, so a file that unlocks the key there unlocks it
    // here, and the newline `echo` appends is not taken as part of it.  A
    // trailing CR goes too, for a file saved with Windows line endings.
    let line = contents.split(|&b| b == b'\n').next().unwrap_or_default();
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.is_empty() {
        anyhow::bail!(
            "[proxy].tls_key_passphrase_file {path} is empty — its first line must be the passphrase"
        );
    }
    Ok(Some(line.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::rsa::Rsa;
    use openssl::symm::Cipher;

    const PASSPHRASE: &str = "correct horse battery staple";

    fn p256_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    /// PKCS#8 `ENCRYPTED PRIVATE KEY`, as `openssl pkey -aes256` writes it.
    fn pkcs8_encrypted(key: &PKey<Private>) -> Vec<u8> {
        key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), PASSPHRASE.as_bytes())
            .unwrap()
    }

    /// Legacy `Proc-Type: 4,ENCRYPTED` PEM, as `openssl ec -aes128` writes it.
    fn traditional_encrypted(key: &PKey<Private>) -> Vec<u8> {
        key.ec_key()
            .unwrap()
            .private_key_to_pem_passphrase(Cipher::aes_128_cbc(), PASSPHRASE.as_bytes())
            .unwrap()
    }

    /// Write `contents` to `name` in `dir`, returning the path as config names it.
    fn write(dir: &tempfile::TempDir, name: &str, contents: &[u8]) -> String {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn cfg(tls_key: String) -> ProxyConfig {
        ProxyConfig {
            tls_key,
            ..ProxyConfig::default()
        }
    }

    #[test]
    fn loads_a_plaintext_key_without_a_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let key = p256_key();
        let path = write(&dir, "tls.key", &key.private_key_to_pem_pkcs8().unwrap());
        assert!(load(&cfg(path)).unwrap().public_eq(&key));
    }

    #[test]
    fn decrypts_a_pkcs8_key_with_the_inline_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let key = p256_key();
        let pem = pkcs8_encrypted(&key);
        assert!(pem.starts_with(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        let c = ProxyConfig {
            tls_key_passphrase: PASSPHRASE.into(),
            ..cfg(write(&dir, "tls.key", &pem))
        };
        assert!(load(&c).unwrap().public_eq(&key));
    }

    #[test]
    fn decrypts_a_traditional_rsa_key_with_the_passphrase_file() {
        // The proxy's own tooling generates RSA keys (scripts/gen-proxy-tls.sh),
        // and this is the form OpenSSL 1.x's `openssl rsa -aes256` produced.
        let dir = tempfile::tempdir().unwrap();
        let rsa = Rsa::generate(2048).unwrap();
        let pem = rsa
            .private_key_to_pem_passphrase(Cipher::aes_128_cbc(), PASSPHRASE.as_bytes())
            .unwrap();
        assert!(String::from_utf8_lossy(&pem).contains("Proc-Type: 4,ENCRYPTED"));
        let key = PKey::from_rsa(rsa).unwrap();
        // As `echo "$PASSPHRASE" > file` writes it: the newline is not part of it.
        let pass = write(&dir, "tls.pass", format!("{PASSPHRASE}\n").as_bytes());
        let c = ProxyConfig {
            tls_key_passphrase_file: pass,
            ..cfg(write(&dir, "tls.key", &pem))
        };
        assert!(load(&c).unwrap().public_eq(&key));
    }

    #[test]
    fn passphrase_file_uses_only_its_first_line() {
        // A CRLF line ending and any later lines are both ignored.
        let dir = tempfile::tempdir().unwrap();
        let key = p256_key();
        let pass = write(
            &dir,
            "tls.pass",
            format!("{PASSPHRASE}\r\nnot part of it\n").as_bytes(),
        );
        let c = ProxyConfig {
            tls_key_passphrase_file: pass,
            ..cfg(write(&dir, "tls.key", &traditional_encrypted(&key)))
        };
        assert!(load(&c).unwrap().public_eq(&key));
    }

    #[test]
    fn an_encrypted_key_without_a_passphrase_names_the_settings() {
        // Must fail with an error naming the settings — never fall through to
        // OpenSSL's interactive prompt, which would block a foreground run.
        let dir = tempfile::tempdir().unwrap();
        let key = p256_key();
        for pem in [pkcs8_encrypted(&key), traditional_encrypted(&key)] {
            let error = load(&cfg(write(&dir, "tls.key", &pem)))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("is encrypted but no passphrase is configured"),
                "got: {error}"
            );
            assert!(
                error.contains("[proxy].tls_key_passphrase_file"),
                "got: {error}"
            );
        }
    }

    #[test]
    fn a_wrong_passphrase_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let key = p256_key();
        for pem in [pkcs8_encrypted(&key), traditional_encrypted(&key)] {
            let c = ProxyConfig {
                tls_key_passphrase: "Tr0ub4dor&3".into(),
                ..cfg(write(&dir, "tls.key", &pem))
            };
            let error = load(&c).unwrap_err().to_string();
            assert!(
                error.contains("cannot decrypt [proxy].tls_key") && error.contains("passphrase"),
                "got: {error}"
            );
        }
    }

    #[test]
    fn a_passphrase_for_a_plaintext_key_is_accepted() {
        // Unused, and logged as such, but not fatal.
        let dir = tempfile::tempdir().unwrap();
        let key = p256_key();
        let c = ProxyConfig {
            tls_key_passphrase: PASSPHRASE.into(),
            ..cfg(write(
                &dir,
                "tls.key",
                &key.private_key_to_pem_pkcs8().unwrap(),
            ))
        };
        assert!(load(&c).unwrap().public_eq(&key));
    }

    #[test]
    fn rejects_an_empty_passphrase_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "tls.key", &pkcs8_encrypted(&p256_key()));
        for contents in ["", "\n", "\r\n", "\npassphrase on the second line\n"] {
            let c = ProxyConfig {
                tls_key_passphrase_file: write(&dir, "tls.pass", contents.as_bytes()),
                ..cfg(path.clone())
            };
            let error = load(&c).unwrap_err().to_string();
            assert!(error.contains("is empty"), "{contents:?}: got {error}");
        }
    }

    #[test]
    fn rejects_a_missing_passphrase_file() {
        let dir = tempfile::tempdir().unwrap();
        let c = ProxyConfig {
            tls_key_passphrase_file: "/nonexistent/tls.pass".into(),
            ..cfg(write(&dir, "tls.key", &pkcs8_encrypted(&p256_key())))
        };
        let error = load(&c).unwrap_err().to_string();
        assert!(
            error.contains("cannot read [proxy].tls_key_passphrase_file /nonexistent/tls.pass"),
            "got: {error}"
        );
    }

    #[test]
    fn rejects_a_missing_key_file() {
        let error = load(&cfg("/nonexistent/tls.key".into()))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("cannot read [proxy].tls_key /nonexistent/tls.key"),
            "got: {error}"
        );
    }

    #[test]
    fn rejects_an_unparseable_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "tls.key", b"-----BEGIN PRIVATE KEY-----\nnope\n");
        let error = load(&cfg(path)).unwrap_err().to_string();
        assert!(
            error.contains("cannot parse [proxy].tls_key"),
            "got: {error}"
        );
    }
}

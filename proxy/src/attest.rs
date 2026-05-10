use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

const MAX_TS_DRIFT: i64 = 30;

// ephem_pub(65) + IV(12) + plaintext(≥1) + GCM-tag(16)
const TOKEN_MIN_LEN: usize = 94;

pub struct Verifier {
    private_key: SecretKey,
}

#[derive(Debug)]
pub enum AttestError {
    BadTimestamp,
    TimestampDrift(i64),
    InvalidToken(&'static str),
    DecryptFailed,
    PlaintextMismatch,
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadTimestamp => write!(f, "X-ZeroFox-Ts is not a valid integer"),
            Self::TimestampDrift(d) => {
                write!(f, "timestamp drift {d}s exceeds {MAX_TS_DRIFT}s window")
            }
            Self::InvalidToken(r) => write!(f, "invalid token: {r}"),
            Self::DecryptFailed => write!(f, "AES-128-GCM authentication failed"),
            Self::PlaintextMismatch => write!(f, "plaintext mismatch"),
        }
    }
}

impl Verifier {
    pub fn from_pem(pem: &str) -> anyhow::Result<Self> {
        let key = SecretKey::from_sec1_pem(pem)?;
        Ok(Self { private_key: key })
    }

    /// Returns `Ok(())` when the request is authentic and the timestamp is
    /// within the allowed window; an `AttestError` variant otherwise.
    pub fn verify(&self, ts_str: &str, token_b64: &str, host: &str) -> Result<(), AttestError> {
        // 1. Validate timestamp window.
        let ts: i64 = ts_str.parse().map_err(|_| AttestError::BadTimestamp)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let drift = (now - ts).abs();
        if drift > MAX_TS_DRIFT {
            return Err(AttestError::TimestampDrift(drift));
        }

        // 2. Decode and split: ephem_pub(65) || IV(12) || ct+tag.
        let raw = STANDARD
            .decode(token_b64)
            .map_err(|_| AttestError::InvalidToken("invalid base64"))?;
        if raw.len() < TOKEN_MIN_LEN {
            return Err(AttestError::InvalidToken("token too short"));
        }
        let ephem_bytes = &raw[..65];
        let iv = &raw[65..77];
        let ct_tag = &raw[77..]; // ciphertext with 16-byte GCM tag appended

        // 3. Parse ephemeral uncompressed EC point.
        let ephem_pub = PublicKey::from_sec1_bytes(ephem_bytes)
            .map_err(|_| AttestError::InvalidToken("EC point not on curve"))?;

        // 4. ECDH → shared secret Z (raw x-coordinate, 32 bytes).
        let shared = diffie_hellman(self.private_key.to_nonzero_scalar(), ephem_pub.as_affine());

        // 5. ANSI X9.63 KDF: SHA-256(Z || 0x00000001), take first 16 bytes as AES-128 key.
        let mut h = Sha256::new();
        h.update(shared.raw_secret_bytes());
        h.update([0x00, 0x00, 0x00, 0x01]);
        let digest = h.finalize();
        let aes_key = &digest[..16];

        // 6. AES-128-GCM decrypt.  The aes-gcm crate expects ciphertext || tag,
        //    which is exactly what ct_tag contains.
        let cipher = Aes128Gcm::new_from_slice(aes_key).expect("slice is 16 bytes");
        let nonce_arr: [u8; 12] = iv.try_into().expect("IV is 12 bytes");
        let nonce = Nonce::from(nonce_arr);
        let plaintext = cipher
            .decrypt(&nonce, ct_tag)
            .map_err(|_| AttestError::DecryptFailed)?;

        // 7. Check canonical plaintext.
        let expected = format!("zerofox-attest:{ts_str}:{host}");
        if plaintext != expected.as_bytes() {
            return Err(AttestError::PlaintextMismatch);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// Replicates ZeroFoxAttest.cpp: ECIES-encrypt a token for `proxy_pub`.
    fn make_token(proxy_pub: &PublicKey, ts_str: &str, host: &str) -> String {
        let ephem_priv = SecretKey::random(&mut OsRng);
        let ephem_pub = ephem_priv.public_key();
        let shared = diffie_hellman(ephem_priv.to_nonzero_scalar(), proxy_pub.as_affine());

        let mut h = Sha256::new();
        h.update(shared.raw_secret_bytes());
        h.update([0x00, 0x00, 0x00, 0x01]);
        let digest = h.finalize();
        let aes_key = &digest[..16];

        let iv = [0u8; 12]; // fixed IV is fine for unit tests
        let plaintext = format!("zerofox-attest:{ts_str}:{host}");
        let cipher = Aes128Gcm::new_from_slice(aes_key).unwrap();
        let ct_tag = cipher
            .encrypt(Nonce::from(iv), plaintext.as_bytes())
            .unwrap();

        let ep_bytes = ephem_pub.to_encoded_point(false).as_bytes().to_vec();
        let mut token = ep_bytes;
        token.extend_from_slice(&iv);
        token.extend_from_slice(&ct_tag);
        STANDARD.encode(token)
    }

    fn now_ts() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }

    fn fresh_verifier() -> (Verifier, PublicKey) {
        let priv_key = SecretKey::random(&mut OsRng);
        let pub_key = priv_key.public_key();
        (Verifier { private_key: priv_key }, pub_key)
    }

    #[test]
    fn valid_token_accepted() {
        let (v, pub_key) = fresh_verifier();
        let ts = now_ts();
        let token = make_token(&pub_key, &ts, "example.com");
        assert!(v.verify(&ts, &token, "example.com").is_ok());
    }

    #[test]
    fn stale_timestamp_rejected() {
        let (v, pub_key) = fresh_verifier();
        let ts = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 90)
            .to_string();
        let token = make_token(&pub_key, &ts, "example.com");
        assert!(matches!(
            v.verify(&ts, &token, "example.com"),
            Err(AttestError::TimestampDrift(_))
        ));
    }

    #[test]
    fn future_timestamp_within_window_accepted() {
        let (v, pub_key) = fresh_verifier();
        let ts = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 10)
            .to_string();
        let token = make_token(&pub_key, &ts, "example.com");
        assert!(v.verify(&ts, &token, "example.com").is_ok());
    }

    #[test]
    fn wrong_host_rejected() {
        let (v, pub_key) = fresh_verifier();
        let ts = now_ts();
        let token = make_token(&pub_key, &ts, "evil.com");
        assert!(matches!(
            v.verify(&ts, &token, "example.com"),
            Err(AttestError::PlaintextMismatch)
        ));
    }

    #[test]
    fn garbage_token_rejected() {
        let (v, _) = fresh_verifier();
        let ts = now_ts();
        let junk = STANDARD.encode([0u8; 100]);
        assert!(v.verify(&ts, &junk, "example.com").is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let (v, _) = fresh_verifier();
        let (_, other_pub) = fresh_verifier();
        let ts = now_ts();
        let token = make_token(&other_pub, &ts, "example.com");
        assert!(v.verify(&ts, &token, "example.com").is_err());
    }
}

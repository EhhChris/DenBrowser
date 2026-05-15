use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

const MAX_TS_DRIFT_SECS: i64 = 30;
const NONCE_TTL: Duration = Duration::from_secs(90);
const NONCE_LEN: usize = 16;
const HEX_HASH_LEN: usize = 64;

// ephem_pub(65) + IV(12) + plaintext(≥1) + GCM-tag(16)
const TOKEN_MIN_LEN: usize = 94;

const PLAINTEXT_PREFIX: &[u8] = b"denbrowser-attest:v2";

/// Header values + URL fields the verifier compares against the decrypted
/// plaintext.  The body is handled separately by `verify_body_and_commit`
/// because it streams in after the head has been parsed.
pub struct AttestInputs<'a> {
    pub ts: &'a str,
    pub nonce_b64: &'a str,
    pub token_b64: &'a str,
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
}

/// State carried from phase 1 (header verify) into phase 2 (body verify).
pub struct PhaseOne {
    pub nonce: [u8; NONCE_LEN],
    pub expected_body_hash: [u8; 32],
}

pub struct Verifier {
    private_key: SecretKey,
    nonce_cache: Mutex<HashMap<[u8; NONCE_LEN], Instant>>,
}

#[derive(Debug)]
pub enum AttestError {
    BadTimestamp,
    TimestampDrift(i64),
    InvalidNonce(&'static str),
    NonceReplay,
    InvalidToken(&'static str),
    DecryptFailed,
    PlaintextMismatch,
    BodyHashMismatch,
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadTimestamp => write!(f, "X-DenBrowser-Ts is not a valid integer"),
            Self::TimestampDrift(d) => {
                write!(f, "timestamp drift {d}s exceeds {MAX_TS_DRIFT_SECS}s window")
            }
            Self::InvalidNonce(r) => write!(f, "invalid X-DenBrowser-Nonce: {r}"),
            Self::NonceReplay => write!(f, "nonce already seen — replay rejected"),
            Self::InvalidToken(r) => write!(f, "invalid token: {r}"),
            Self::DecryptFailed => write!(f, "AES-128-GCM authentication failed"),
            Self::PlaintextMismatch => write!(f, "plaintext mismatch"),
            Self::BodyHashMismatch => write!(f, "body hash mismatch"),
        }
    }
}

impl Verifier {
    pub fn from_pem(pem: &str) -> anyhow::Result<Self> {
        let key = SecretKey::from_sec1_pem(pem)?;
        Ok(Self {
            private_key: key,
            nonce_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Phase 1.  Validate the three attestation headers and decrypt the token.
    /// Compares every plaintext field except the body hash, which is returned
    /// in `PhaseOne` so the caller can compare it once the body has streamed in.
    pub fn verify_headers(&self, i: &AttestInputs<'_>) -> Result<PhaseOne, AttestError> {
        // 1. Timestamp window
        let ts: i64 = i.ts.parse().map_err(|_| AttestError::BadTimestamp)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let drift = (now - ts).abs();
        if drift > MAX_TS_DRIFT_SECS {
            return Err(AttestError::TimestampDrift(drift));
        }

        // 2. Nonce decode + format
        let nonce_raw = STANDARD
            .decode(i.nonce_b64)
            .map_err(|_| AttestError::InvalidNonce("not base64"))?;
        if nonce_raw.len() != NONCE_LEN {
            return Err(AttestError::InvalidNonce("wrong length"));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_raw);

        // 3. Fast-path replay rejection.  Committed atomically in phase 2 so an
        //    attacker spamming garbage tokens can't fill the cache without
        //    also passing GCM authentication.
        {
            let cache = self.nonce_cache.lock().unwrap();
            if cache.contains_key(&nonce) {
                return Err(AttestError::NonceReplay);
            }
        }

        // 4. Token decode + split: ephem_pub(65) || IV(12) || ct+tag
        let raw = STANDARD
            .decode(i.token_b64)
            .map_err(|_| AttestError::InvalidToken("invalid base64"))?;
        if raw.len() < TOKEN_MIN_LEN {
            return Err(AttestError::InvalidToken("token too short"));
        }
        let ephem_bytes = &raw[..65];
        let iv = &raw[65..77];
        let ct_tag = &raw[77..];

        // 5. ECDH + ANSI X9.63 KDF (SHA-256, counter 0x00000001) → AES-128 key
        let ephem_pub = PublicKey::from_sec1_bytes(ephem_bytes)
            .map_err(|_| AttestError::InvalidToken("EC point not on curve"))?;
        let shared = diffie_hellman(self.private_key.to_nonzero_scalar(), ephem_pub.as_affine());

        let mut h = Sha256::new();
        h.update(shared.raw_secret_bytes());
        h.update([0x00, 0x00, 0x00, 0x01]);
        let digest = h.finalize();
        let aes_key = &digest[..16];

        // 6. AES-128-GCM decrypt
        let cipher = Aes128Gcm::new_from_slice(aes_key).expect("slice is 16 bytes");
        let nonce_arr: [u8; 12] = iv.try_into().expect("IV is 12 bytes");
        let plaintext = cipher
            .decrypt(&Nonce::from(nonce_arr), ct_tag)
            .map_err(|_| AttestError::DecryptFailed)?;

        // 7. Parse \n-separated plaintext and compare every non-body field.
        //    Layout: prefix\nnonce\nts\nhost\nmethod\npath\nbody_hash_hex
        let parts: Vec<&[u8]> = plaintext.split(|b| *b == b'\n').collect();
        if parts.len() != 7
            || parts[0] != PLAINTEXT_PREFIX
            || parts[1] != i.nonce_b64.as_bytes()
            || parts[2] != i.ts.as_bytes()
            || parts[3] != i.host.as_bytes()
            || parts[4] != i.method.as_bytes()
            || parts[5] != i.path.as_bytes()
        {
            return Err(AttestError::PlaintextMismatch);
        }

        // 8. Decode the body hash; phase 2 compares it against the actual body.
        if parts[6].len() != HEX_HASH_LEN {
            return Err(AttestError::PlaintextMismatch);
        }
        let mut expected_body_hash = [0u8; 32];
        for (idx, pair) in parts[6].chunks(2).enumerate() {
            let s = std::str::from_utf8(pair).map_err(|_| AttestError::PlaintextMismatch)?;
            expected_body_hash[idx] =
                u8::from_str_radix(s, 16).map_err(|_| AttestError::PlaintextMismatch)?;
        }

        Ok(PhaseOne {
            nonce,
            expected_body_hash,
        })
    }

    /// Phase 2.  Compare the actual body hash to the expected one; on success
    /// atomically inserts the nonce into the replay cache (so a TOCTOU race
    /// with a parallel replay still loses).
    pub fn verify_body_and_commit(
        &self,
        p1: &PhaseOne,
        actual_body_hash: &[u8; 32],
    ) -> Result<(), AttestError> {
        if &p1.expected_body_hash != actual_body_hash {
            return Err(AttestError::BodyHashMismatch);
        }

        let mut cache = self.nonce_cache.lock().unwrap();
        let now = Instant::now();

        // Cheap TTL sweep — every commit, not every peek.
        cache.retain(|_, t| now.duration_since(*t) < NONCE_TTL);

        match cache.entry(p1.nonce) {
            Entry::Occupied(_) => Err(AttestError::NonceReplay), // lost a parallel race
            Entry::Vacant(e) => {
                e.insert(now);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand_core::{OsRng, RngCore};

    fn sha256_hex(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        let digest = h.finalize();
        let mut s = String::with_capacity(64);
        for b in digest {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    fn body_hash(body: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(body);
        h.finalize().into()
    }

    /// Mirrors DenBrowserAttest.cpp::AddAttestHeaders — produces a v2 token.
    fn make_token(
        proxy_pub: &PublicKey,
        nonce_b64: &str,
        ts: &str,
        host: &str,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> String {
        let ephem_priv = SecretKey::random(&mut OsRng);
        let ephem_pub = ephem_priv.public_key();
        let shared = diffie_hellman(ephem_priv.to_nonzero_scalar(), proxy_pub.as_affine());

        let mut h = Sha256::new();
        h.update(shared.raw_secret_bytes());
        h.update([0x00, 0x00, 0x00, 0x01]);
        let digest = h.finalize();
        let aes_key = &digest[..16];

        let iv = [0u8; 12]; // fixed IV is fine for unit tests
        let plaintext = format!(
            "denbrowser-attest:v2\n{nonce_b64}\n{ts}\n{host}\n{method}\n{path}\n{}",
            sha256_hex(body)
        );
        let cipher = Aes128Gcm::new_from_slice(aes_key).unwrap();
        let ct_tag = cipher
            .encrypt(&Nonce::from(iv), plaintext.as_bytes())
            .unwrap();

        let ep_bytes = ephem_pub.to_encoded_point(false).as_bytes().to_vec();
        let mut token = ep_bytes;
        token.extend_from_slice(&iv);
        token.extend_from_slice(&ct_tag);
        STANDARD.encode(token)
    }

    fn fresh_verifier() -> (Verifier, PublicKey) {
        let priv_key = SecretKey::random(&mut OsRng);
        let pub_key = priv_key.public_key();
        (
            Verifier {
                private_key: priv_key,
                nonce_cache: Mutex::new(HashMap::new()),
            },
            pub_key,
        )
    }

    fn fresh_nonce_b64() -> String {
        // Random per call so tests don't collide on retries; the verifier under
        // test has a per-test cache so distinctness within a test is enough.
        let mut buf = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut buf);
        STANDARD.encode(buf)
    }

    fn now_ts() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }

    #[test]
    fn valid_token_accepted_and_replay_caught() {
        let (v, pk) = fresh_verifier();
        let ts = now_ts();
        let nonce = fresh_nonce_b64();
        let body: &[u8] = b"";
        let token = make_token(&pk, &nonce, &ts, "example.com", "GET", "/foo", body);
        let inputs = AttestInputs {
            ts: &ts,
            nonce_b64: &nonce,
            token_b64: &token,
            host: "example.com",
            method: "GET",
            path: "/foo",
        };

        let p1 = v.verify_headers(&inputs).expect("first call passes");
        v.verify_body_and_commit(&p1, &body_hash(body))
            .expect("body matches");

        // Replay attempt with the same nonce is caught by the fast path.
        assert!(matches!(
            v.verify_headers(&inputs),
            Err(AttestError::NonceReplay)
        ));
    }

    #[test]
    fn wrong_method_rejected() {
        let (v, pk) = fresh_verifier();
        let ts = now_ts();
        let nonce = fresh_nonce_b64();
        let token = make_token(&pk, &nonce, &ts, "example.com", "GET", "/foo", b"");
        let inputs = AttestInputs {
            ts: &ts,
            nonce_b64: &nonce,
            token_b64: &token,
            host: "example.com",
            method: "POST", // token was issued for GET
            path: "/foo",
        };
        assert!(matches!(
            v.verify_headers(&inputs),
            Err(AttestError::PlaintextMismatch)
        ));
    }

    #[test]
    fn wrong_path_rejected() {
        let (v, pk) = fresh_verifier();
        let ts = now_ts();
        let nonce = fresh_nonce_b64();
        let token = make_token(&pk, &nonce, &ts, "example.com", "GET", "/foo", b"");
        let inputs = AttestInputs {
            ts: &ts,
            nonce_b64: &nonce,
            token_b64: &token,
            host: "example.com",
            method: "GET",
            path: "/bar", // token was issued for /foo
        };
        assert!(matches!(
            v.verify_headers(&inputs),
            Err(AttestError::PlaintextMismatch)
        ));
    }

    #[test]
    fn tampered_body_rejected() {
        let (v, pk) = fresh_verifier();
        let ts = now_ts();
        let nonce = fresh_nonce_b64();
        let token = make_token(&pk, &nonce, &ts, "example.com", "POST", "/api", b"original");
        let inputs = AttestInputs {
            ts: &ts,
            nonce_b64: &nonce,
            token_b64: &token,
            host: "example.com",
            method: "POST",
            path: "/api",
        };
        let p1 = v.verify_headers(&inputs).expect("phase one ok");
        assert!(matches!(
            v.verify_body_and_commit(&p1, &body_hash(b"tampered")),
            Err(AttestError::BodyHashMismatch)
        ));
    }

    #[test]
    fn stale_timestamp_rejected() {
        let (v, pk) = fresh_verifier();
        let ts = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 120)
            .to_string();
        let nonce = fresh_nonce_b64();
        let token = make_token(&pk, &nonce, &ts, "example.com", "GET", "/x", b"");
        let inputs = AttestInputs {
            ts: &ts,
            nonce_b64: &nonce,
            token_b64: &token,
            host: "example.com",
            method: "GET",
            path: "/x",
        };
        assert!(matches!(
            v.verify_headers(&inputs),
            Err(AttestError::TimestampDrift(_))
        ));
    }

    #[test]
    fn bad_nonce_length_rejected() {
        let (v, pk) = fresh_verifier();
        let ts = now_ts();
        let bad_nonce = STANDARD.encode(b"only12bytes!");
        let token = make_token(&pk, &bad_nonce, &ts, "example.com", "GET", "/x", b"");
        let inputs = AttestInputs {
            ts: &ts,
            nonce_b64: &bad_nonce,
            token_b64: &token,
            host: "example.com",
            method: "GET",
            path: "/x",
        };
        assert!(matches!(
            v.verify_headers(&inputs),
            Err(AttestError::InvalidNonce(_))
        ));
    }

    #[test]
    fn wrong_key_rejected() {
        let (v, _) = fresh_verifier();
        let (_, other_pk) = fresh_verifier();
        let ts = now_ts();
        let nonce = fresh_nonce_b64();
        let token = make_token(&other_pk, &nonce, &ts, "example.com", "GET", "/x", b"");
        let inputs = AttestInputs {
            ts: &ts,
            nonce_b64: &nonce,
            token_b64: &token,
            host: "example.com",
            method: "GET",
            path: "/x",
        };
        // Either GCM auth or plaintext-prefix mismatch — both are rejections.
        assert!(v.verify_headers(&inputs).is_err());
    }
}

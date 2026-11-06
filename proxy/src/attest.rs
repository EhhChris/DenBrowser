use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::audit::Reason;
use crate::config::AttestationConfig;

const MAX_TS_DRIFT_SECS: i64 = 30;

/// How long past its timestamp window a token may still have its nonce
/// committed: the budget for a bound body to arrive, and for the checks that
/// precede forwarding (machine identity's DNS lookup included), once phase 1
/// has accepted the request.  Phase 1 may pass as late as ts + 31 s, so the
/// budget is at least this long and at most 31 s more.
const COMMIT_GRACE_SECS: i64 = 60;

/// How long a committed nonce is remembered.  Must exceed the whole span in
/// which one token can be accepted, [ts − 30, ts + 31 + grace), so that no
/// second acceptance can outlive the first one's entry; the check below pins
/// that, and what is left over is the tolerance to a backwards step of the
/// wall clock.
const NONCE_TTL: Duration = Duration::from_secs(180);
const _: () = assert!(
    NONCE_TTL.as_secs() as i64 > 2 * MAX_TS_DRIFT_SECS + 1 + COMMIT_GRACE_SECS,
    "NONCE_TTL must outlive the span in which a token can be accepted"
);

const NONCE_LEN: usize = 16;
const HEX_HASH_LEN: usize = 64;

/// Upper bound on expired nonces one commit removes, so a commit after a long
/// idle gap never turns into a full drain.  Total eviction work is bounded by
/// total insertions (each entry is popped once), so the cost stays amortised
/// O(1) per commit; after a burst followed by a trickle the backlog drains at
/// this rate per commit and is bounded by that burst.
const MAX_EVICTIONS_PER_COMMIT: usize = 256;

// ephem_pub(65) + IV(12) + plaintext(≥1) + GCM-tag(16)
const TOKEN_MIN_LEN: usize = 94;

const PLAINTEXT_PREFIX: &[u8] = b"denbrowser-attest:v2";

/// Sentinel that replaces the body-hash field when the DenBrowser client
/// declines to bind the body (large uploads).  It can never collide with a
/// real hash: a hex SHA-256 is always 64 chars, and this is not.
const UNBOUND_SENTINEL: &[u8] = b"unbound";

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

/// How the request body is (or isn't) cryptographically bound to the token.
///
/// `Hash` is the normal case: the token commits to `sha256(body)` and the proxy
/// buffers + verifies the body before forwarding.  `Unbound` is the large-upload
/// escape hatch: the DenBrowser client omits the body hash for uploads too large
/// to hash up front, so the proxy streams the body straight through without
/// buffering.  Origin attestation, nonce replay, timestamp, and method/host/path
/// binding still apply — only per-body integrity is dropped for these requests.
pub enum BodyBinding {
    Hash([u8; 32]),
    Unbound,
}

/// State carried from phase 1 (header verify) into phase 2 (body verify).
pub struct PhaseOne {
    pub nonce: [u8; NONCE_LEN],
    pub body_binding: BodyBinding,
    /// The token's timestamp, checked again when the nonce is committed.
    ts: i64,
}

/// The proxy clock as whole Unix seconds, the form `X-DenBrowser-Ts` uses.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Phase 1's timestamp check: `ts` must be within [`MAX_TS_DRIFT_SECS`] of
/// `now`.  Whole seconds, so a token passes for the 61 s of wall time in
/// [ts − 30, ts + 31).
fn check_drift(ts: i64, now: i64) -> Result<(), AttestError> {
    // Saturating: a timestamp near `i64::MIN` must be refused, not overflow.
    let drift = now.saturating_sub(ts).saturating_abs();
    if drift > MAX_TS_DRIFT_SECS {
        return Err(AttestError::TimestampDrift(drift));
    }
    Ok(())
}

/// The commit-time check: the same lower bound as phase 1, and an upper bound
/// extended by [`COMMIT_GRACE_SECS`], so a nonce is committed only in
/// [ts − 30, ts + 31 + grace).
///
/// Phase 1 runs before a bound body streams in, and the client controls how
/// long that takes.  Without a check here, copies of one captured request
/// could all pass phase 1 inside the window, then each finish its body one
/// TTL apart, each finding the previous copy's nonce already expired.
fn check_commit_window(ts: i64, now: i64) -> Result<(), AttestError> {
    let elapsed = now.saturating_sub(ts);
    if elapsed < -MAX_TS_DRIFT_SECS {
        return Err(AttestError::TimestampDrift(elapsed.saturating_abs()));
    }
    if elapsed > MAX_TS_DRIFT_SECS + COMMIT_GRACE_SECS {
        return Err(AttestError::CommitTooLate(elapsed));
    }
    Ok(())
}

/// The replay cache: every nonce committed in the last [`NONCE_TTL`].
///
/// A nonce has to stay here until its token can no longer be accepted.  Phase
/// 1 accepts a token only in [ts − 30, ts + 31) of proxy wall time, and
/// [`Verifier::commit_nonce`] commits its nonce only in
/// [ts − 30, ts + 31 + [`COMMIT_GRACE_SECS`]), so every acceptance of one
/// token falls inside that 121 s span.  An entry that lives 180 s from its
/// commit outlives the span with 59 s to spare, which is also the tolerance to
/// a backwards step of the wall clock: a larger step could reopen the window
/// for tokens whose nonces have aged out.  Eviction is by age and never by
/// size: a cache that dropped entries under load would reopen replay inside
/// the span.
///
/// Expiry costs amortised O(1) per commit.  The clock is read under the lock,
/// so commits land in `expiry` in time order and the oldest entry is always at
/// its front; each commit pops the ones that have aged out instead of scanning
/// the whole set.  An earlier version swept the whole map on every commit,
/// which cost O(live nonces) per accepted request and so grew with the request
/// rate.
#[derive(Default)]
struct NonceCache {
    seen: HashSet<[u8; NONCE_LEN]>,
    /// Commit order, oldest first, with when each entry was committed.
    expiry: VecDeque<([u8; NONCE_LEN], Instant)>,
}

impl NonceCache {
    /// Whether `nonce` has been committed and not yet dropped.  An entry past
    /// its TTL but not yet popped still counts as seen.  That can only add a
    /// rejection, never an acceptance: the request refused would be a fresh
    /// token reusing a nonce from at least three minutes earlier, which a
    /// browser minting 128-bit random nonces never does.
    fn contains(&self, nonce: &[u8; NONCE_LEN]) -> bool {
        self.seen.contains(nonce)
    }

    /// Atomically record `nonce`, failing if it is already present, after
    /// dropping entries that have aged out as of `now`.  Callers pass a
    /// non-decreasing `now`, which keeps `expiry` ordered.
    fn commit(&mut self, nonce: [u8; NONCE_LEN], now: Instant) -> Result<(), AttestError> {
        self.evict_expired(now);
        if !self.seen.insert(nonce) {
            return Err(AttestError::NonceReplay); // lost a parallel race
        }
        self.expiry.push_back((nonce, now));
        Ok(())
    }

    fn evict_expired(&mut self, now: Instant) {
        let mut evicted = 0;
        while let Some(&(nonce, committed)) = self.expiry.front() {
            if evicted == MAX_EVICTIONS_PER_COMMIT || now.duration_since(committed) < NONCE_TTL {
                break;
            }
            self.expiry.pop_front();
            self.seen.remove(&nonce);
            evicted += 1;
        }
    }
}

pub struct Verifier {
    private_key: SecretKey,
    nonce_cache: Mutex<NonceCache>,
}

#[derive(Debug)]
pub enum AttestError {
    BadTimestamp,
    TimestampDrift(i64),
    /// The nonce was committed too long after the token's timestamp: the body,
    /// or the checks before forwarding, took longer than the commit window.
    CommitTooLate(i64),
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
            Self::CommitTooLate(d) => {
                let limit = MAX_TS_DRIFT_SECS + COMMIT_GRACE_SECS;
                write!(
                    f,
                    "nonce committed {d}s after X-DenBrowser-Ts, past the {limit}s commit \
                     window — the body or the checks before forwarding took too long"
                )
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

impl AttestError {
    /// The audit reason this failure is recorded under.
    pub fn reason(&self) -> Reason {
        match self {
            Self::BadTimestamp => Reason::TimestampInvalid,
            Self::TimestampDrift(_) | Self::CommitTooLate(_) => Reason::TimestampOutOfWindow,
            Self::InvalidNonce(_) => Reason::NonceInvalid,
            Self::NonceReplay => Reason::NonceReplay,
            Self::InvalidToken(_) => Reason::TokenMalformed,
            Self::DecryptFailed => Reason::TokenDecryptFailed,
            Self::PlaintextMismatch => Reason::TokenRequestMismatch,
            Self::BodyHashMismatch => Reason::BodyHashMismatch,
        }
    }
}

impl Verifier {
    /// Load the attestation private key named by `[attestation] private_key`.
    ///
    /// Every failure here aborts startup: a proxy that cannot decrypt tokens
    /// would reject every attested request, so coming up at all would be worse
    /// than not starting.  Mirrors [`crate::mtls::Mtls::from_config`], except
    /// that this key is mandatory rather than gated on an `enabled` switch.
    pub fn from_config(cfg: &AttestationConfig) -> anyhow::Result<Self> {
        if cfg.private_key.is_empty() {
            anyhow::bail!(
                "attestation.private_key is not set — point it at this proxy's \
                 EC P-256 private key (scripts/gen-attest-key.sh --name <proxy>)"
            );
        }
        let pem = std::fs::read_to_string(&cfg.private_key).map_err(|e| {
            anyhow::anyhow!(
                "cannot read attestation private_key {}: {e}",
                cfg.private_key
            )
        })?;
        Self::from_pem(&pem).map_err(|e| {
            anyhow::anyhow!(
                "cannot parse attestation private_key {}: {e}",
                cfg.private_key
            )
        })
    }

    pub fn from_pem(pem: &str) -> anyhow::Result<Self> {
        let key = SecretKey::from_sec1_pem(pem)?;
        Ok(Self {
            private_key: key,
            nonce_cache: Mutex::new(NonceCache::default()),
        })
    }

    /// Phase 1.  Validate the three attestation headers and decrypt the token.
    /// Compares every plaintext field except the body hash, which is returned
    /// in `PhaseOne` so the caller can compare it once the body has streamed in.
    pub fn verify_headers(&self, i: &AttestInputs<'_>) -> Result<PhaseOne, AttestError> {
        // 1. Timestamp window
        let ts: i64 = i.ts.parse().map_err(|_| AttestError::BadTimestamp)?;
        check_drift(ts, unix_now())?;

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
            if cache.contains(&nonce) {
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

        // 8. Body binding.  Either the `unbound` sentinel (large upload, streamed
        //    through without a body check) or a hex SHA-256 that phase 2 compares
        //    against the actual body.
        let body_binding = if parts[6] == UNBOUND_SENTINEL {
            BodyBinding::Unbound
        } else {
            if parts[6].len() != HEX_HASH_LEN {
                return Err(AttestError::PlaintextMismatch);
            }
            let mut expected_body_hash = [0u8; 32];
            for (idx, pair) in parts[6].chunks(2).enumerate() {
                let s = std::str::from_utf8(pair).map_err(|_| AttestError::PlaintextMismatch)?;
                expected_body_hash[idx] =
                    u8::from_str_radix(s, 16).map_err(|_| AttestError::PlaintextMismatch)?;
            }
            BodyBinding::Hash(expected_body_hash)
        };

        Ok(PhaseOne {
            nonce,
            body_binding,
            ts,
        })
    }

    /// Atomically insert the request's nonce into the replay cache, rejecting
    /// if it is already present (so a TOCTOU race with a parallel replay still
    /// loses).  Expired entries are dropped on the way through; see
    /// [`NonceCache`].
    ///
    /// The token's timestamp is checked again here, against the commit window
    /// of [`check_commit_window`], not only in phase 1: for a bound body the
    /// two are separated by the body upload, which the client controls.  Every
    /// acceptance of one token therefore falls in a single span that
    /// [`NONCE_TTL`] outlives.
    pub fn commit_nonce(&self, p1: &PhaseOne) -> Result<(), AttestError> {
        let mut cache = self.nonce_cache.lock().unwrap();
        // Replay first, so a late copy of an already accepted request is
        // recorded as the replay it is rather than as a slow upload.
        if cache.contains(&p1.nonce) {
            return Err(AttestError::NonceReplay);
        }
        check_commit_window(p1.ts, unix_now())?;
        // The clock is read under the lock, so commits are queued in time
        // order (which `NonceCache` relies on) rather than in lock-acquisition
        // order.
        cache.commit(p1.nonce, Instant::now())
    }

    /// Commit a bare nonce at a supplied time, skipping the timestamp re-check,
    /// so tests can age the cache without sleeping.
    #[cfg(test)]
    fn commit_nonce_at(&self, nonce: &[u8; NONCE_LEN], now: Instant) -> Result<(), AttestError> {
        self.nonce_cache.lock().unwrap().commit(*nonce, now)
    }

    /// Phase 2.  For a bound body, compare the actual body hash to the expected
    /// one; then atomically commit the nonce.  Unbound requests have their
    /// nonce committed in phase 1 by the caller (there is no body hash to wait
    /// for) and are not routed here; if one ever were, the commit below either
    /// protects it or fails loudly with `NonceReplay`, rather than silently
    /// skipping replay protection.
    pub fn verify_body_and_commit(
        &self,
        p1: &PhaseOne,
        actual_body_hash: &[u8; 32],
    ) -> Result<(), AttestError> {
        if let BodyBinding::Hash(expected) = &p1.body_binding
            && expected != actual_body_hash
        {
            return Err(AttestError::BodyHashMismatch);
        }
        self.commit_nonce(p1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn from_config_requires_private_key() {
        let err = Verifier::from_config(&AttestationConfig::default())
            .err()
            .expect("empty private_key must be rejected");
        assert!(err.to_string().contains("private_key is not set"));
    }

    #[test]
    fn from_config_rejects_missing_key_file() {
        let cfg = AttestationConfig {
            private_key: "/nonexistent/partner-a-private.pem".into(),
        };
        let err = Verifier::from_config(&cfg)
            .err()
            .expect("missing key file must be rejected");
        assert!(err.to_string().contains("cannot read attestation private_key"));
    }

    #[test]
    fn from_config_rejects_unparseable_key_file() {
        let path = std::env::temp_dir().join("denbrowser-not-a-key.pem");
        std::fs::write(&path, b"-----BEGIN EC PRIVATE KEY-----\nnope\n").unwrap();
        let cfg = AttestationConfig {
            private_key: path.to_string_lossy().into_owned(),
        };
        let err = Verifier::from_config(&cfg)
            .err()
            .expect("unparseable key file must be rejected");
        let _ = std::fs::remove_file(&path);
        assert!(err.to_string().contains("cannot parse attestation private_key"));
    }

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
        make_token_with_body_field(
            proxy_pub,
            nonce_b64,
            ts,
            host,
            method,
            path,
            &sha256_hex(body),
        )
    }

    /// Like `make_token` but takes the raw body-binding field so tests can
    /// build the `unbound` sentinel (or malformed values) directly.
    fn make_token_with_body_field(
        proxy_pub: &PublicKey,
        nonce_b64: &str,
        ts: &str,
        host: &str,
        method: &str,
        path: &str,
        body_field: &str,
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
            "denbrowser-attest:v2\n{nonce_b64}\n{ts}\n{host}\n{method}\n{path}\n{body_field}"
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
                nonce_cache: Mutex::new(NonceCache::default()),
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
    fn unbound_token_yields_unbound_binding_and_commits_nonce() {
        let (v, pk) = fresh_verifier();
        let ts = now_ts();
        let nonce = fresh_nonce_b64();
        // Client declined to bind the body (large upload): body field == sentinel.
        let token = make_token_with_body_field(
            &pk, &nonce, &ts, "example.com", "POST", "/upload", "unbound",
        );
        let inputs = AttestInputs {
            ts: &ts,
            nonce_b64: &nonce,
            token_b64: &token,
            host: "example.com",
            method: "POST",
            path: "/upload",
        };

        let p1 = v.verify_headers(&inputs).expect("headers verify");
        assert!(matches!(p1.body_binding, BodyBinding::Unbound));

        // Unbound requests commit the nonce in phase 1 (no body hash to await).
        v.commit_nonce(&p1).expect("first commit succeeds");

        // A replay of the same nonce is now rejected on the fast path.
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

    // ── Replay-cache expiry ──────────────────────────────────────────────────
    //
    // Driven through `commit_nonce_at` with a supplied clock, so the TTL is
    // exercised without sleeping.  Times only ever move forward from `t0`:
    // subtracting from `Instant::now()` can underflow on a freshly booted host.

    fn nonce_bytes(i: u64) -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        n[..8].copy_from_slice(&i.to_be_bytes());
        n
    }

    fn cache_len(v: &Verifier) -> (usize, usize) {
        let cache = v.nonce_cache.lock().unwrap();
        (cache.seen.len(), cache.expiry.len())
    }

    #[test]
    fn nothing_is_evicted_before_the_ttl() {
        // Eviction is by age only.  Far more entries than one commit may
        // evict, all still inside the TTL: every one must survive, so a cache
        // under load never reopens the replay window early.
        let (v, _) = fresh_verifier();
        let t0 = Instant::now();
        let count = 8 * MAX_EVICTIONS_PER_COMMIT as u64;
        for i in 0..count {
            v.commit_nonce_at(&nonce_bytes(i), t0).unwrap();
        }

        let just_inside = t0 + NONCE_TTL - Duration::from_secs(1);
        v.commit_nonce_at(&nonce_bytes(count), just_inside).unwrap();
        assert_eq!(cache_len(&v), (count as usize + 1, count as usize + 1));
        for i in [0, count / 2, count - 1] {
            assert!(
                matches!(
                    v.commit_nonce_at(&nonce_bytes(i), just_inside),
                    Err(AttestError::NonceReplay)
                ),
                "nonce {i} must still be a replay inside the TTL"
            );
        }
    }

    #[test]
    fn expired_nonces_are_dropped_in_bounded_batches_and_become_usable() {
        let (v, _) = fresh_verifier();
        let t0 = Instant::now();
        // Three and a half batches' worth, so draining takes several commits
        // and the last batch is a partial one.  Derived from the constant so
        // the arithmetic below holds whatever it is set to.
        let count = (3 * MAX_EVICTIONS_PER_COMMIT + MAX_EVICTIONS_PER_COMMIT / 2) as u64;
        let batches = (count as usize).div_ceil(MAX_EVICTIONS_PER_COMMIT);
        for i in 0..count {
            v.commit_nonce_at(&nonce_bytes(i), t0).unwrap();
        }

        // The first commit past the TTL drops one bounded batch, not all of
        // them, so a commit after a long idle gap stays cheap.
        let past = t0 + NONCE_TTL;
        v.commit_nonce_at(&nonce_bytes(count), past).unwrap();
        let remaining = count as usize - MAX_EVICTIONS_PER_COMMIT + 1;
        assert_eq!(cache_len(&v), (remaining, remaining));

        // Each further commit drains another batch until the old entries are
        // gone; the fresh ones committed at `past` are untouched.
        for i in 1..batches as u64 {
            v.commit_nonce_at(&nonce_bytes(count + i), past).unwrap();
        }
        assert_eq!(cache_len(&v), (batches, batches));

        // Dropped means forgotten: the first nonce is accepted again.
        v.commit_nonce_at(&nonce_bytes(0), past)
            .expect("an expired nonce is no longer a replay");
        assert_eq!(cache_len(&v), (batches + 1, batches + 1));
    }

    #[test]
    fn a_rejected_replay_leaves_the_cache_unchanged() {
        // The set and the expiry queue must stay in step: a replay that loses
        // the race must not push a second expiry entry for the same nonce, nor
        // refresh the stamp of the one that is there.
        let (v, _) = fresh_verifier();
        let t0 = Instant::now();
        v.commit_nonce_at(&nonce_bytes(7), t0).unwrap();
        for _ in 0..3 {
            assert!(matches!(
                v.commit_nonce_at(&nonce_bytes(7), t0 + Duration::from_secs(1)),
                Err(AttestError::NonceReplay)
            ));
        }
        assert_eq!(cache_len(&v), (1, 1));
        let cache = v.nonce_cache.lock().unwrap();
        assert_eq!(cache.expiry.front(), Some(&(nonce_bytes(7), t0)));
    }

    #[test]
    fn a_commit_outside_the_commit_window_is_refused() {
        // Phase 1 can pass long before a bound body finishes arriving, so the
        // timestamp is checked again at commit.  A `PhaseOne` built with a
        // stale timestamp stands in for a request whose body took too long.
        let (v, _) = fresh_verifier();
        let now: i64 = now_ts().parse().unwrap();
        let stale = PhaseOne {
            nonce: nonce_bytes(1),
            body_binding: BodyBinding::Hash(body_hash(b"")),
            ts: now - MAX_TS_DRIFT_SECS - COMMIT_GRACE_SECS - 60,
        };
        let err = v
            .verify_body_and_commit(&stale, &body_hash(b""))
            .unwrap_err();
        assert!(matches!(err, AttestError::CommitTooLate(_)), "got: {err}");
        assert_eq!(err.reason(), Reason::TimestampOutOfWindow);
        assert!(err.to_string().contains("commit window"), "got: {err}");
        assert!(matches!(
            v.commit_nonce(&stale),
            Err(AttestError::CommitTooLate(_))
        ));
        assert_eq!(cache_len(&v), (0, 0), "a refused commit records nothing");

        // Inside the grace: phase 1 would no longer accept this timestamp, but
        // a request that passed phase 1 earlier and took a while to upload
        // its body still commits.
        let slow = PhaseOne {
            nonce: nonce_bytes(2),
            body_binding: BodyBinding::Hash(body_hash(b"")),
            ts: now - MAX_TS_DRIFT_SECS - COMMIT_GRACE_SECS / 2,
        };
        v.verify_body_and_commit(&slow, &body_hash(b""))
            .expect("inside the commit window");
        assert_eq!(cache_len(&v), (1, 1));
    }

    #[test]
    fn a_late_copy_is_recorded_as_a_replay_not_a_slow_upload() {
        // A copy that passed phase 1 alongside the original, then finished its
        // body after the commit window, is a replay: the audit record must say
        // so (high risk) rather than blame the clock (medium).
        let (v, _) = fresh_verifier();
        let now: i64 = now_ts().parse().unwrap();
        let original = PhaseOne {
            nonce: nonce_bytes(9),
            body_binding: BodyBinding::Hash(body_hash(b"")),
            ts: now,
        };
        v.verify_body_and_commit(&original, &body_hash(b""))
            .unwrap();
        let late_copy = PhaseOne {
            nonce: nonce_bytes(9),
            body_binding: BodyBinding::Hash(body_hash(b"")),
            ts: now - MAX_TS_DRIFT_SECS - COMMIT_GRACE_SECS - 60,
        };
        assert!(matches!(
            v.verify_body_and_commit(&late_copy, &body_hash(b"")),
            Err(AttestError::NonceReplay)
        ));
        assert_eq!(cache_len(&v), (1, 1));
    }

    #[test]
    fn the_windows_are_exact_at_their_edges() {
        // With a supplied clock, so a second boundary during the test cannot
        // shift the answer.  Phase 1: [ts − 30, ts + 30] in whole seconds.
        let now = 1_800_000_000i64;
        for ts in [now - MAX_TS_DRIFT_SECS, now, now + MAX_TS_DRIFT_SECS] {
            check_drift(ts, now).unwrap();
        }
        for ts in [now - MAX_TS_DRIFT_SECS - 1, now + MAX_TS_DRIFT_SECS + 1] {
            assert!(matches!(
                check_drift(ts, now),
                Err(AttestError::TimestampDrift(d)) if d == MAX_TS_DRIFT_SECS + 1
            ));
        }

        // Commit: the same lower bound, the upper one extended by the grace.
        let latest = now - MAX_TS_DRIFT_SECS - COMMIT_GRACE_SECS;
        for ts in [latest, now, now + MAX_TS_DRIFT_SECS] {
            check_commit_window(ts, now).unwrap();
        }
        assert!(matches!(
            check_commit_window(latest - 1, now),
            Err(AttestError::CommitTooLate(d)) if d == MAX_TS_DRIFT_SECS + COMMIT_GRACE_SECS + 1
        ));
        assert!(matches!(
            check_commit_window(now + MAX_TS_DRIFT_SECS + 1, now),
            Err(AttestError::TimestampDrift(d)) if d == MAX_TS_DRIFT_SECS + 1
        ));
    }

    #[test]
    fn verify_body_and_commit_commits_an_unbound_nonce_too() {
        // Not a path `main` takes, but if it ever were, the nonce must still
        // be committed rather than waved through.
        let (v, _) = fresh_verifier();
        let p1 = PhaseOne {
            nonce: nonce_bytes(3),
            body_binding: BodyBinding::Unbound,
            ts: now_ts().parse().unwrap(),
        };
        v.verify_body_and_commit(&p1, &body_hash(b"anything"))
            .unwrap();
        assert!(matches!(
            v.verify_body_and_commit(&p1, &body_hash(b"anything")),
            Err(AttestError::NonceReplay)
        ));
    }

    #[test]
    fn extreme_timestamps_are_refused_without_overflowing() {
        // `now + i64::MIN` is the value a wrapping `now - ts` would turn into
        // `i64::MIN`, whose `abs` wraps back to `i64::MIN` and so compares as
        // inside the window; the saturating arithmetic must refuse it.
        let now = 1_800_000_000i64;
        for ts in [
            i64::MIN,
            i64::MIN + 1,
            i64::MAX,
            0,
            -1,
            now.wrapping_add(i64::MIN),
        ] {
            assert!(
                matches!(check_drift(ts, now), Err(AttestError::TimestampDrift(_))),
                "{ts} should be outside the phase 1 window"
            );
            assert!(
                check_commit_window(ts, now).is_err(),
                "{ts} should be outside the commit window"
            );
        }
    }
}

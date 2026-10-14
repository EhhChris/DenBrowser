//! Structured JSON audit records — the proxy's log schema.
//!
//! Every log line is one JSON object, told apart by `event.kind`: `audit` is
//! one per HTTP request, collected in a [`RequestAudit`] and emitted from
//! pingora's `logging` hook once the exchange has finished; `system` is
//! everything else, wrapped by [`crate::logging`].
//!
//! `audit/audit-log.schema.json` defines the format and `audit/README.md` the
//! severity scale.  The tests below regenerate `audit/audit-log.examples.jsonl`
//! and check the schema against this code.
//!
//! Records must never contain the URL path or query string.

use std::net::{IpAddr, SocketAddr};
use std::time::{Instant, SystemTime};

use serde::{Serialize, Serializer};
use tracing::Level;

use crate::machine::{MachineError, VerifiedMachine};

/// Record layout version, written as `schema_version` and pinned in the schema.
/// Bump the minor version for additive changes, the major for breaking ones.
pub const SCHEMA_VERSION: &str = "1.0";

/// `tracing` target for audit records, and the `logger` they carry.
pub const TARGET: &str = "denbrowser_proxy::audit";

/// Field carrying an audit event's pre-serialized record, which `logging`
/// writes verbatim.  [`emit`] spells the same name as an identifier.
pub const RECORD_FIELD: &str = "audit_record";

// Length caps on client-influenced strings copied into a record.
const MAX_DN_CHARS: usize = 1024;
const MAX_HOST_CHARS: usize = 256;
const MAX_METHOD_CHARS: usize = 32;
const MAX_NONCE_CHARS: usize = 64;

/// How much attention an audit event deserves (see `audit/README.md`).
/// `info` is only for requests that were not refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Where in the request pipeline a failure happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Per-IP rate limiting, before anything else is examined.
    RateLimit,
    /// Presence of the `X-DenBrowser-Ts` / `-Nonce` / `-Token` headers.
    AttestationHeaders,
    /// The workstation certificate: its presence, then (after the token passes)
    /// its chain, name policy, and forward-DNS check.
    MachineIdentity,
    /// Timestamp window, nonce, token decryption, and request binding.
    AttestationToken,
    /// Body size limit and body hash, for requests whose body is bound.
    AttestationBody,
    /// After forwarding: the upstream failed.
    Upstream,
    /// The client's side of the connection failed.
    Downstream,
    /// The proxy itself failed.
    Internal,
}

impl Stage {
    /// Whether a failure at this stage is a failure of attestation proper.
    pub fn is_attestation(self) -> bool {
        matches!(
            self,
            Self::AttestationHeaders | Self::AttestationToken | Self::AttestationBody
        )
    }
}

/// Defines [`Reason`] with each variant's code, stage, and severity.
macro_rules! reasons {
    ($( $(#[$doc:meta])* $variant:ident => $code:literal, $stage:ident, $severity:ident; )*) => {
        /// Why a request was refused or failed.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Reason {
            $( $(#[$doc])* $variant, )*
        }

        impl Reason {
            /// Every reason, in table order.
            #[cfg(test)]
            pub const ALL: &'static [Reason] = &[$(Reason::$variant),*];

            /// The machine-readable code written as `event.reason`.
            pub fn code(self) -> &'static str {
                match self { $(Reason::$variant => $code,)* }
            }

            /// The pipeline stage this reason is detected at.
            pub fn stage(self) -> Stage {
                match self { $(Reason::$variant => Stage::$stage,)* }
            }

            /// How seriously to take it.
            pub fn severity(self) -> Severity {
                match self { $(Reason::$variant => Severity::$severity,)* }
            }
        }
    };
}

reasons! {
    /// The client exceeded a `[rate_limiting]` cap.
    RateLimited                  => "rate_limited",                    RateLimit,          Medium;
    /// None of the attestation headers were sent: not DenBrowser, or a
    /// DenBrowser not configured for this proxy.
    NoAttestationHeaders         => "no_attestation_headers",          AttestationHeaders, Low;
    /// Some attestation headers (or the Host header) are missing or unreadable,
    /// or a machine certificate arrived without any attestation.
    IncompleteAttestationHeaders => "incomplete_attestation_headers",  AttestationHeaders, High;
    /// Machine identity is required and no certificate was sent.
    MachineCertMissing           => "machine_cert_missing",            MachineIdentity,    Medium;
    /// The machine certificate header is not base64 DER.
    MachineCertMalformed         => "machine_cert_malformed",          MachineIdentity,    High;
    /// The machine certificate has no Common Name.
    MachineCertNoCommonName      => "machine_cert_no_common_name",     MachineIdentity,    High;
    /// The machine certificate's Common Name holds characters no hostname may.
    MachineCertUnsafeCommonName  => "machine_cert_unsafe_common_name", MachineIdentity,    High;
    /// The machine certificate names a host outside `allowed_hostnames`.
    MachineHostnameNotAllowed    => "machine_hostname_not_allowed",    MachineIdentity,    High;
    /// The machine certificate has expired.
    MachineCertExpired           => "machine_cert_expired",            MachineIdentity,    Medium;
    /// The machine certificate is not valid yet.
    MachineCertNotYetValid       => "machine_cert_not_yet_valid",      MachineIdentity,    Medium;
    /// The machine certificate does not chain to `machine_ca`.
    MachineCertUntrusted         => "machine_cert_untrusted",          MachineIdentity,    High;
    /// The machine's hostname does not resolve.
    MachineHostnameUnresolvable  => "machine_hostname_unresolvable",   MachineIdentity,    Medium;
    /// A trusted machine certificate presented from an address its name does
    /// not resolve to — a copied certificate, or DNS lagging a DHCP change.
    MachineAddressMismatch       => "machine_address_mismatch",        MachineIdentity,    High;
    /// The connection has no peer address to check the machine name against.
    MachineNoClientAddress       => "machine_no_client_address",       MachineIdentity,    Medium;
    /// `X-DenBrowser-Ts` is not an integer.
    TimestampInvalid             => "timestamp_invalid",               AttestationToken,   High;
    /// The token's timestamp is outside the accepted window — usually a
    /// workstation clock that has drifted.
    TimestampOutOfWindow         => "timestamp_out_of_window",         AttestationToken,   Medium;
    /// `X-DenBrowser-Nonce` is not 16 bytes of base64.
    NonceInvalid                 => "nonce_invalid",                   AttestationToken,   High;
    /// The nonce was already used: a replay, or a network-stack resend.
    NonceReplay                  => "nonce_replay",                    AttestationToken,   High;
    /// The token is not base64, is too short, or carries no valid EC point.
    TokenMalformed               => "token_malformed",                 AttestationToken,   High;
    /// The token did not decrypt with this proxy's key: forged, corrupted, or
    /// built for a different proxy.
    TokenDecryptFailed           => "token_decrypt_failed",            AttestationToken,   High;
    /// The token decrypted but commits to a different method, host, path,
    /// timestamp, or nonce than the request carrying it.
    TokenRequestMismatch         => "token_request_mismatch",          AttestationToken,   Critical;
    /// A bound body exceeded the size that can be verified before forwarding.
    BodyTooLarge                 => "body_too_large",                  AttestationBody,    Medium;
    /// The body does not match the hash the token commits to.
    BodyHashMismatch             => "body_hash_mismatch",              AttestationBody,    Critical;
    /// The client failed to deliver the body being verified.
    BodyReadFailed               => "body_read_failed",                Downstream,         Low;
    /// The upstream could not be reached or failed mid-exchange.
    UpstreamError                => "upstream_error",                  Upstream,           Medium;
    /// The client's connection failed mid-exchange.
    DownstreamError              => "downstream_error",                Downstream,         Low;
    /// The proxy failed, or the request ended before a decision was recorded.
    InternalError                => "internal_error",                  Internal,           Medium;
}

impl Serialize for Reason {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.code())
    }
}

/// What the proxy decided to do with the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Attested and forwarded upstream.
    Forward,
    /// Forwarded upstream without attestation under `[proxy_bypass]`.
    Bypass,
    /// Refused by attestation, machine identity, or body verification.
    Reject,
    /// Refused by rate limiting.
    RateLimit,
    /// The request failed before a decision was reached.
    Error,
}

/// Whether the exchange completed as decided.  A refusal is a `failure`, as is
/// a forwarded request whose upstream or client connection then failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
}

/// How far attestation got.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    /// Every check passed and the nonce was committed.
    Verified,
    /// An attestation check failed; `event.reason` says which.
    Failed,
    /// Skipped under `[proxy_bypass]`.
    Bypassed,
    /// The token had verified, but another control refused the request before
    /// attestation finished (machine identity, or the body could not be read).
    Incomplete,
    /// No attestation check ran: refused earlier, or the request errored first.
    NotEvaluated,
}

/// How far machine identity got.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineStatus {
    /// The certificate chained to `machine_ca` and its name resolved to the
    /// connecting address.
    Verified,
    /// Required and missing, or verification failed; `event.reason` says which.
    Failed,
    /// Not sent, and `required = false` let the request through.
    Absent,
    /// The request was refused (or bypassed) before machine identity was checked.
    NotEvaluated,
    /// `[machine_identity]` is disabled on this proxy.
    Disabled,
}

/// Whether the token commits to the request body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Binding {
    /// The body hash is in the token and was verified before forwarding.
    Bound,
    /// A large upload streamed through without a body hash.
    Unbound,
}

impl From<&crate::attest::BodyBinding> for Binding {
    fn from(binding: &crate::attest::BodyBinding) -> Self {
        match binding {
            crate::attest::BodyBinding::Hash(_) => Self::Bound,
            crate::attest::BodyBinding::Unbound => Self::Unbound,
        }
    }
}

/// One audit line.  Field order here is the key order on the wire.
#[derive(Debug, Serialize)]
pub struct AuditRecord {
    /// When the record was written: the end of the exchange, UTC.
    pub timestamp: String,
    pub schema_version: &'static str,
    pub level: &'static str,
    pub logger: &'static str,
    pub event: AuditEvent,
    pub message: String,
    /// The proxy's own address on this connection.
    pub proxy: Endpoint,
    /// The connecting host.
    pub client: Endpoint,
    pub user: UserFields,
    pub machine: MachineFields,
    pub attestation: AttestationFields,
    pub http: HttpFields,
    pub transfer: TransferFields,
}

#[derive(Debug, Serialize)]
pub struct AuditEvent {
    pub kind: &'static str,
    pub action: Action,
    pub outcome: Outcome,
    pub stage: Option<Stage>,
    pub reason: Option<Reason>,
    pub severity: Severity,
    pub duration_ms: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Endpoint {
    pub ip: Option<IpAddr>,
    pub port: Option<u16>,
}

impl From<Option<SocketAddr>> for Endpoint {
    fn from(addr: Option<SocketAddr>) -> Self {
        Self {
            ip: addr.map(|a| a.ip()),
            port: addr.map(|a| a.port()),
        }
    }
}

/// The mTLS user certificate, verified at the handshake; null when `[mtls]` is
/// disabled.
#[derive(Debug, Serialize)]
pub struct UserFields {
    pub subject_dn: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MachineFields {
    pub status: MachineStatus,
    /// Subject DN of the presented machine certificate, even if unverified;
    /// `chain_verified` says whether to trust it.
    pub subject_dn: Option<String>,
    /// The verified workstation hostname; only set when `status` is `verified`.
    pub hostname: Option<String>,
    /// Whether `subject_dn` chained to `machine_ca`.
    pub chain_verified: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AttestationFields {
    pub status: AttestationStatus,
    /// `X-DenBrowser-Nonce` as sent (bounded), the transaction's identifier.
    pub nonce: Option<String>,
    /// `X-DenBrowser-Ts` as an ISO 8601 time, when it parses as one.
    pub client_timestamp: Option<String>,
    /// Known once the token decrypts.
    pub body_binding: Option<Binding>,
}

/// The request, without its path — see the module docs.
#[derive(Debug, Serialize)]
pub struct HttpFields {
    pub method: Option<String>,
    pub host: Option<String>,
    /// Status sent to the client; null when the connection died before one was.
    pub status_code: Option<u16>,
}

/// Body bytes moved, excluding headers and TLS framing.
#[derive(Debug, Serialize)]
pub struct TransferFields {
    /// Read from the client (uploaded).
    pub request_body_bytes: u64,
    /// Sent to the client (downloaded).
    pub response_body_bytes: u64,
}

/// A non-audit line: startup, configuration, and diagnostics.
#[derive(Debug, Serialize)]
pub struct SystemRecord<'a> {
    pub timestamp: String,
    pub schema_version: &'static str,
    pub level: &'static str,
    pub logger: &'a str,
    pub event: SystemEvent,
    pub message: &'a str,
    /// Any structured fields the event carried besides its message.
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct SystemEvent {
    pub kind: &'static str,
}

impl<'a> SystemRecord<'a> {
    pub fn new(
        timestamp: String,
        level: &Level,
        logger: &'a str,
        message: &'a str,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        Self {
            timestamp,
            schema_version: SCHEMA_VERSION,
            level: level.as_str(),
            logger,
            event: SystemEvent { kind: "system" },
            message,
            fields,
        }
    }
}

/// Facts gathered at the end of the request, from the session and from
/// [`RequestAudit::response_body`]'s count.
pub struct Connection {
    pub proxy: Option<SocketAddr>,
    pub client: Option<SocketAddr>,
    pub user_subject_dn: Option<String>,
    pub status_code: Option<u16>,
    pub request_body_bytes: usize,
    pub response_body_bytes: u64,
}

/// The audit state of one request: pingora's per-request `CTX`.
///
/// `request_filter` records what it saw and decided through the methods below,
/// and `logging` calls [`Self::finish`] once the exchange is over.
pub struct RequestAudit {
    started: Instant,
    action: Option<Action>,
    reason: Option<Reason>,
    message: Option<String>,
    method: Option<String>,
    host: Option<String>,
    attestation: AttestationFields,
    /// Set once the token passes; a later refusal then reads as `incomplete`.
    token_verified: bool,
    machine: MachineFields,
    /// The machine certificate header as sent, kept so its DN can be recorded
    /// even if it is never verified.
    presented_machine_cert: Option<String>,
    /// Response body bytes relayed to the client; see [`Self::response_body`].
    response_body_bytes: u64,
}

impl RequestAudit {
    pub fn new(machine_identity_enabled: bool) -> Self {
        Self {
            started: Instant::now(),
            action: None,
            reason: None,
            message: None,
            method: None,
            host: None,
            attestation: AttestationFields {
                status: AttestationStatus::NotEvaluated,
                nonce: None,
                client_timestamp: None,
                body_binding: None,
            },
            token_verified: false,
            machine: MachineFields {
                status: if machine_identity_enabled {
                    MachineStatus::NotEvaluated
                } else {
                    MachineStatus::Disabled
                },
                subject_dn: None,
                hostname: None,
                chain_verified: false,
            },
            presented_machine_cert: None,
            response_body_bytes: 0,
        }
    }

    /// The request line, minus its path.
    pub fn request(&mut self, method: &str, host: Option<&str>) {
        self.method = Some(bounded(method, MAX_METHOD_CHARS));
        self.host = host.map(|h| bounded(h, MAX_HOST_CHARS));
    }

    /// The attestation timestamp and nonce as sent, before either is trusted.
    pub fn attestation_headers(&mut self, ts: Option<&str>, nonce: Option<&str>) {
        self.attestation.nonce = nonce.map(|n| bounded(n, MAX_NONCE_CHARS));
        self.attestation.client_timestamp = ts
            .and_then(|t| t.trim().parse::<i64>().ok())
            .and_then(unix_timestamp);
    }

    pub fn machine_cert_presented(&mut self, cert_b64: String) {
        self.presented_machine_cert = Some(cert_b64);
    }

    pub fn presented_machine_cert(&self) -> Option<&str> {
        self.presented_machine_cert.as_deref()
    }

    /// No machine certificate, and `required = false` lets the request on.
    pub fn machine_absent(&mut self) {
        self.machine.status = MachineStatus::Absent;
    }

    pub fn machine_verified(&mut self, id: VerifiedMachine) {
        self.machine = MachineFields {
            status: MachineStatus::Verified,
            subject_dn: Some(bounded(&id.subject_dn, MAX_DN_CHARS)),
            hostname: Some(id.hostname),
            chain_verified: true,
        };
        // The DN is already known; nothing left to parse at finish.
        self.presented_machine_cert = None;
    }

    pub fn machine_rejected(&mut self, e: &MachineError) {
        self.machine.status = MachineStatus::Failed;
        self.machine.chain_verified = e.chain_verified();
        self.reject(e.reason(), e.to_string());
    }

    /// Phase one of attestation passed; the body binding is now known.
    pub fn token_verified(&mut self, binding: Binding) {
        self.token_verified = true;
        self.attestation.body_binding = Some(binding);
    }

    /// The request is refused.  `message` must not contain the URL path.
    pub fn reject(&mut self, reason: Reason, message: impl Into<String>) {
        self.action = Some(if reason == Reason::RateLimited {
            Action::RateLimit
        } else {
            Action::Reject
        });
        self.reason = Some(reason);
        self.message = Some(message.into());
        self.attestation.status = if reason.stage().is_attestation() {
            AttestationStatus::Failed
        } else if self.token_verified {
            AttestationStatus::Incomplete
        } else {
            AttestationStatus::NotEvaluated
        };
    }

    /// Fully attested; the request goes upstream.
    pub fn forward(&mut self) {
        self.action = Some(Action::Forward);
        self.attestation.status = AttestationStatus::Verified;
        self.message = Some(match self.attestation.body_binding {
            Some(Binding::Unbound) => {
                "attested upload forwarded; body streamed unbound (not hash-verified)".to_owned()
            }
            _ => "attested request forwarded".to_owned(),
        });
    }

    /// Forwarded without attestation; `subject` is the allowlisted identity
    /// from the mTLS-verified client certificate.
    pub fn bypass(&mut self, subject: &str) {
        self.action = Some(Action::Bypass);
        self.attestation.status = AttestationStatus::Bypassed;
        self.message = Some(format!(
            "attestation bypassed for allowlisted client certificate subject {}",
            bounded(subject, MAX_DN_CHARS)
        ));
    }

    /// Count a chunk of response body on its way to the client.  pingora's
    /// HTTP/1 `body_bytes_sent` includes the response header.
    pub fn response_body(&mut self, len: usize) {
        self.response_body_bytes = self.response_body_bytes.saturating_add(len as u64);
    }

    pub fn response_body_bytes(&self) -> u64 {
        self.response_body_bytes
    }

    /// Emit this request's record.  `error` is pingora's terminal error, if the
    /// exchange failed after the decision (see [`classify_proxy_error`]).
    pub fn finish(&mut self, conn: &Connection, error: Option<(Reason, String)>) {
        let level = self.level(error.is_some());
        // Skip building the record when the filter would discard it.
        let enabled = if level == Level::INFO {
            tracing::enabled!(target: TARGET, Level::INFO)
        } else {
            tracing::enabled!(target: TARGET, Level::WARN)
        };
        if !enabled {
            return;
        }
        let duration_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let record = self.record(conn, error, timestamp(SystemTime::now()), duration_ms);
        emit(level, &record);
    }

    fn outcome(&self, failed: bool) -> Outcome {
        match self.action {
            Some(Action::Forward | Action::Bypass) if !failed => Outcome::Success,
            _ => Outcome::Failure,
        }
    }

    /// Successes at `info`, everything else at `warn`, so that
    /// `[logging].level = "warn"` keeps exactly the refusals and failures.
    fn level(&self, failed: bool) -> Level {
        match self.outcome(failed) {
            Outcome::Success => Level::INFO,
            Outcome::Failure => Level::WARN,
        }
    }

    /// Build the record with the given timestamp and duration.
    fn record(
        &mut self,
        conn: &Connection,
        mut error: Option<(Reason, String)>,
        timestamp: String,
        duration_ms: u64,
    ) -> AuditRecord {
        if self.action.is_none() && error.is_none() {
            // `request_filter` always records a decision, so this is a bug.
            error = Some((
                Reason::InternalError,
                "request ended before an access decision was recorded".to_owned(),
            ));
        }
        let failed = error.is_some();
        let level = self.level(failed);
        let outcome = self.outcome(failed);

        // A refusal keeps its own reason over any later transport error.
        if let Some((reason, message)) = error
            && matches!(self.action, None | Some(Action::Forward | Action::Bypass))
        {
            self.action.get_or_insert(Action::Error);
            self.reason = Some(reason);
            self.message = Some(message);
        }

        if self.machine.subject_dn.is_none()
            && let Some(cert) = self.presented_machine_cert.take()
        {
            self.machine.subject_dn =
                crate::machine::presented_subject_dn(&cert).map(|dn| bounded(&dn, MAX_DN_CHARS));
        }

        AuditRecord {
            timestamp,
            schema_version: SCHEMA_VERSION,
            level: level.as_str(),
            logger: TARGET,
            event: AuditEvent {
                kind: "audit",
                action: self.action.unwrap_or(Action::Error),
                outcome,
                stage: self.reason.map(Reason::stage),
                reason: self.reason,
                severity: self.reason.map_or(Severity::Info, Reason::severity),
                duration_ms,
            },
            message: self.message.take().unwrap_or_default(),
            proxy: conn.proxy.into(),
            client: conn.client.into(),
            user: UserFields {
                subject_dn: conn
                    .user_subject_dn
                    .as_deref()
                    .map(|dn| bounded(dn, MAX_DN_CHARS)),
            },
            machine: self.machine.clone(),
            attestation: self.attestation.clone(),
            http: HttpFields {
                method: self.method.take(),
                host: self.host.take(),
                status_code: conn.status_code,
            },
            transfer: TransferFields {
                request_body_bytes: conn.request_body_bytes as u64,
                response_body_bytes: conn.response_body_bytes,
            },
        }
    }
}

/// Map pingora's terminal error for a request onto a reason and message.
pub fn classify_proxy_error(e: &pingora_core::Error) -> (Reason, String) {
    use pingora_core::ErrorSource;

    let (reason, side) = match e.esource() {
        ErrorSource::Upstream => (Reason::UpstreamError, "upstream"),
        ErrorSource::Downstream => (Reason::DownstreamError, "client connection"),
        ErrorSource::Internal | ErrorSource::Unset => (Reason::InternalError, "internal"),
    };
    // The error type only: pingora's context strings are free-form text.
    (reason, format!("{side} error: {}", e.etype().as_str()))
}

fn emit(level: Level, record: &AuditRecord) {
    let line = match serde_json::to_string(record) {
        Ok(line) => line,
        Err(e) => {
            tracing::error!("cannot serialize audit record: {e}");
            return;
        }
    };
    // `audit_record` here is `RECORD_FIELD`; the macros need it as an ident.
    if level == Level::INFO {
        tracing::info!(target: TARGET, audit_record = line.as_str());
    } else {
        tracing::warn!(target: TARGET, audit_record = line.as_str());
    }
}

/// Fixed-width RFC 3339 UTC with milliseconds, so the strings sort in time
/// order: `2026-10-14T13:04:05.123Z`.
pub fn timestamp(t: SystemTime) -> String {
    format_utc(time::OffsetDateTime::from(t))
}

/// The last instant a four-digit ISO 8601 year can express,
/// 9999-12-31T23:59:59Z, as Unix seconds.
const MAX_ISO_UNIX_SECS: i64 = 253_402_300_799;

/// A client-supplied Unix time as ISO 8601, or `None` when it falls outside
/// what the format can express without an expanded year.
fn unix_timestamp(secs: i64) -> Option<String> {
    if !(0..=MAX_ISO_UNIX_SECS).contains(&secs) {
        return None;
    }
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .map(format_utc)
}

fn format_utc(t: time::OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond()
    )
}

/// `s`, cut to at most `max_chars` characters with a trailing `…` when cut.
fn bounded(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        None => s.to_owned(),
        Some((cut, _)) => format!("{}…", &s[..cut]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{Duration, UNIX_EPOCH};

    use base64::Engine as _;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509Builder, X509NameBuilder};
    use serde_json::Value;

    use crate::attest::AttestError;

    const EXAMPLES_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/audit/audit-log.examples.jsonl"
    );
    const SCHEMA_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/audit/audit-log.schema.json");
    const UPDATE_VAR: &str = "DENBROWSER_UPDATE_AUDIT_EXAMPLES";

    fn at(unix_ms: u64) -> String {
        timestamp(UNIX_EPOCH + Duration::from_millis(unix_ms))
    }

    // ── Timestamps and bounds ────────────────────────────────────────────────

    #[test]
    fn timestamps_are_fixed_width_utc_with_milliseconds() {
        assert_eq!(at(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(at(1_709_251_199_999), "2024-02-29T23:59:59.999Z");
        assert_eq!(at(1_791_983_045_007), "2026-10-14T13:04:05.007Z");
    }

    #[test]
    fn client_timestamps_beyond_four_digit_years_are_dropped() {
        assert_eq!(
            unix_timestamp(0).as_deref(),
            Some("1970-01-01T00:00:00.000Z")
        );
        assert_eq!(
            unix_timestamp(MAX_ISO_UNIX_SECS).as_deref(),
            Some("9999-12-31T23:59:59.000Z")
        );
        assert_eq!(unix_timestamp(MAX_ISO_UNIX_SECS + 1), None);
        assert_eq!(unix_timestamp(-1), None);
        assert_eq!(unix_timestamp(i64::MAX), None);
    }

    #[test]
    fn bounded_cuts_on_a_character_boundary() {
        assert_eq!(bounded("short", 10), "short");
        assert_eq!(bounded("exactly", 7), "exactly");
        assert_eq!(bounded("ååååå", 3), "ååå…");
    }

    // ── How decisions become records ────────────────────────────────────────

    fn conn(status: Option<u16>, up: usize, down: u64) -> Connection {
        Connection {
            proxy: Some("10.20.0.5:8443".parse().unwrap()),
            client: Some("10.4.2.17:52144".parse().unwrap()),
            user_subject_dn: Some(USER_DN.to_owned()),
            status_code: status,
            request_body_bytes: up,
            response_body_bytes: down,
        }
    }

    fn json(ctx: &mut RequestAudit, conn: &Connection, error: Option<(Reason, String)>) -> Value {
        serde_json::to_value(ctx.record(conn, error, at(0), 0)).unwrap()
    }

    #[test]
    fn a_forwarded_request_is_info_with_no_reason() {
        let mut ctx = RequestAudit::new(true);
        ctx.request("GET", Some(HOST));
        ctx.token_verified(Binding::Bound);
        ctx.forward();
        let r = json(&mut ctx, &conn(Some(200), 0, 10), None);
        assert_eq!(r["level"], "INFO");
        assert_eq!(r["event"]["action"], "forward");
        assert_eq!(r["event"]["outcome"], "success");
        assert_eq!(r["event"]["severity"], "info");
        assert_eq!(r["event"]["stage"], Value::Null);
        assert_eq!(r["event"]["reason"], Value::Null);
        assert_eq!(r["attestation"]["status"], "verified");
        assert_eq!(r["attestation"]["body_binding"], "bound");
        assert_eq!(r["transfer"]["response_body_bytes"], 10);
    }

    #[test]
    fn attestation_failures_carry_their_reason_and_severity() {
        for e in [
            AttestError::BadTimestamp,
            AttestError::TimestampDrift(95),
            AttestError::InvalidNonce("wrong length"),
            AttestError::NonceReplay,
            AttestError::InvalidToken("token too short"),
            AttestError::DecryptFailed,
            AttestError::PlaintextMismatch,
            AttestError::BodyHashMismatch,
        ] {
            let mut ctx = RequestAudit::new(true);
            ctx.reject(e.reason(), e.to_string());
            let r = json(&mut ctx, &conn(Some(403), 0, 0), None);
            assert_eq!(r["level"], "WARN", "{e}");
            assert_eq!(r["event"]["action"], "reject", "{e}");
            assert_eq!(r["event"]["outcome"], "failure", "{e}");
            assert_eq!(r["event"]["reason"], e.reason().code(), "{e}");
            assert_eq!(
                r["event"]["severity"],
                serde_json::to_value(e.reason().severity()).unwrap()
            );
            assert_eq!(r["attestation"]["status"], "failed", "{e}");
            assert_eq!(r["message"], e.to_string());
        }
    }

    #[test]
    fn missing_headers_are_low_but_partial_headers_are_high() {
        assert_eq!(Reason::NoAttestationHeaders.severity(), Severity::Low);
        assert_eq!(
            Reason::IncompleteAttestationHeaders.severity(),
            Severity::High
        );
        // Every other refusal is more than low, bar the client going away.
        for r in Reason::ALL {
            if !matches!(
                r,
                Reason::NoAttestationHeaders | Reason::BodyReadFailed | Reason::DownstreamError
            ) {
                assert_ne!(r.severity(), Severity::Low, "{r:?}");
            }
            assert_ne!(r.severity(), Severity::Info, "{r:?} is a failure");
        }
    }

    #[test]
    fn a_machine_failure_after_the_token_reads_as_incomplete() {
        let mut ctx = RequestAudit::new(true);
        ctx.token_verified(Binding::Bound);
        ctx.machine_rejected(&MachineError::HostnameAddressMismatch {
            cn: MACHINE_HOST.to_owned(),
            ip: "192.0.2.99".parse().unwrap(),
        });
        let r = json(&mut ctx, &conn(Some(403), 0, 0), None);
        assert_eq!(r["event"]["stage"], "machine_identity");
        assert_eq!(r["attestation"]["status"], "incomplete");
        assert_eq!(r["machine"]["status"], "failed");
        assert_eq!(r["machine"]["chain_verified"], true);
    }

    #[test]
    fn a_refusal_before_attestation_reads_as_not_evaluated() {
        let mut ctx = RequestAudit::new(true);
        ctx.reject(Reason::RateLimited, "request rate limit exceeded");
        let r = json(&mut ctx, &conn(Some(429), 0, 0), None);
        assert_eq!(r["event"]["action"], "rate_limit");
        assert_eq!(r["attestation"]["status"], "not_evaluated");
        assert_eq!(r["machine"]["status"], "not_evaluated");
    }

    #[test]
    fn a_disabled_machine_layer_says_so() {
        let mut ctx = RequestAudit::new(false);
        ctx.token_verified(Binding::Bound);
        ctx.forward();
        let r = json(&mut ctx, &conn(Some(200), 0, 0), None);
        assert_eq!(r["machine"]["status"], "disabled");
    }

    #[test]
    fn an_upstream_error_after_forwarding_is_a_failed_forward() {
        let mut ctx = RequestAudit::new(true);
        ctx.token_verified(Binding::Bound);
        ctx.forward();
        let err = pingora_core::Error::new_up(pingora_core::ErrorType::ConnectRefused);
        let r = json(
            &mut ctx,
            &conn(Some(502), 0, 0),
            Some(classify_proxy_error(&err)),
        );
        assert_eq!(r["level"], "WARN");
        assert_eq!(r["event"]["action"], "forward");
        assert_eq!(r["event"]["outcome"], "failure");
        assert_eq!(r["event"]["reason"], "upstream_error");
        assert_eq!(r["event"]["stage"], "upstream");
        assert_eq!(r["message"], "upstream error: ConnectRefused");
        // Attestation itself still succeeded.
        assert_eq!(r["attestation"]["status"], "verified");
    }

    #[test]
    fn a_transport_error_after_a_refusal_keeps_the_refusal() {
        let mut ctx = RequestAudit::new(true);
        ctx.reject(Reason::NonceReplay, "nonce already seen — replay rejected");
        let err = pingora_core::Error::new_down(pingora_core::ErrorType::ConnectionClosed);
        let r = json(
            &mut ctx,
            &conn(Some(403), 0, 0),
            Some(classify_proxy_error(&err)),
        );
        assert_eq!(r["event"]["reason"], "nonce_replay");
        assert_eq!(r["message"], "nonce already seen — replay rejected");
    }

    #[test]
    fn a_request_without_a_decision_is_still_recorded() {
        let mut ctx = RequestAudit::new(true);
        let r = json(&mut ctx, &conn(None, 0, 0), None);
        assert_eq!(r["event"]["action"], "error");
        assert_eq!(r["event"]["reason"], "internal_error");
        assert_eq!(r["level"], "WARN");
    }

    #[test]
    fn proxy_errors_are_classified_by_side() {
        use pingora_core::{Error, ErrorType};
        assert_eq!(
            classify_proxy_error(&Error::new_up(ErrorType::ConnectTimedout)),
            (
                Reason::UpstreamError,
                "upstream error: ConnectTimedout".to_owned()
            )
        );
        assert_eq!(
            classify_proxy_error(&Error::new_down(ErrorType::ConnectionClosed)),
            (
                Reason::DownstreamError,
                "client connection error: ConnectionClosed".to_owned()
            )
        );
        assert_eq!(
            classify_proxy_error(&Error::new_in(ErrorType::InternalError)),
            (
                Reason::InternalError,
                "internal error: InternalError".to_owned()
            )
        );
    }

    #[test]
    fn a_presented_machine_cert_is_recorded_unverified() {
        let mut ctx = RequestAudit::new(true);
        ctx.machine_cert_presented(workstation(MACHINE_HOST));
        ctx.reject(Reason::NoAttestationHeaders, "none");
        let r = json(&mut ctx, &conn(Some(403), 0, 0), None);
        assert_eq!(r["machine"]["status"], "not_evaluated");
        assert_eq!(r["machine"]["subject_dn"], workstation_dn(MACHINE_HOST));
        assert_eq!(r["machine"]["chain_verified"], false);
        assert_eq!(r["machine"]["hostname"], Value::Null);
    }

    #[test]
    fn an_unparseable_machine_cert_records_no_dn() {
        let mut ctx = RequestAudit::new(true);
        ctx.machine_cert_presented("not base64!!".to_owned());
        ctx.machine_rejected(&MachineError::NotBase64);
        let r = json(&mut ctx, &conn(Some(403), 0, 0), None);
        assert_eq!(r["machine"]["subject_dn"], Value::Null);
        assert_eq!(r["event"]["reason"], "machine_cert_malformed");
    }

    #[test]
    fn client_controlled_values_are_bounded() {
        let mut ctx = RequestAudit::new(true);
        let host = "h".repeat(5000);
        ctx.request(&"M".repeat(500), Some(&host));
        ctx.attestation_headers(Some("1791983045"), Some(&"n".repeat(5000)));
        ctx.reject(
            Reason::NonceInvalid,
            "invalid X-DenBrowser-Nonce: not base64",
        );
        let r = json(&mut ctx, &conn(Some(403), 0, 0), None);
        assert_eq!(
            r["http"]["host"].as_str().unwrap().chars().count(),
            MAX_HOST_CHARS + 1
        );
        assert_eq!(
            r["http"]["method"].as_str().unwrap().chars().count(),
            MAX_METHOD_CHARS + 1
        );
        assert_eq!(
            r["attestation"]["nonce"].as_str().unwrap().chars().count(),
            MAX_NONCE_CHARS + 1
        );
        assert_eq!(
            r["attestation"]["client_timestamp"],
            "2026-10-14T13:04:05.000Z"
        );
    }

    // ── The examples file ────────────────────────────────────────────────────
    //
    // `audit/audit-log.examples.jsonl` is generated below by making the same
    // `RequestAudit` calls `request_filter` makes.  Regenerate with:
    //
    //     DENBROWSER_UPDATE_AUDIT_EXAMPLES=1 cargo test examples_file

    const USER_DN: &str = "CN=alice.nguyen,OU=Staff,O=Example Corp,C=US";
    const HOST: &str = "intranet.example.com";
    const MACHINE_HOST: &str = "ws-4417.corp.example.com";
    const NONCE: &str = "kX2b0f9Qm1T4yH8uJc3LwA==";
    /// 2026-10-14T13:04:05.250Z; each example is one second after the last.
    const EXAMPLE_EPOCH_MS: u64 = 1_791_983_045_250;

    /// A self-signed certificate with the given subject, as base64 DER.
    fn cert_b64(subject: &[(&str, &str)]) -> String {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        for (field, value) in subject {
            name.append_entry_by_text(field, value).unwrap();
        }
        let name = name.build();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        base64::engine::general_purpose::STANDARD.encode(b.build().to_der().unwrap())
    }

    fn workstation(cn: &str) -> String {
        cert_b64(&[
            ("C", "US"),
            ("O", "Example Corp"),
            ("OU", "Workstations"),
            ("CN", cn),
        ])
    }

    fn workstation_dn(cn: &str) -> String {
        format!("CN={cn},OU=Workstations,O=Example Corp,C=US")
    }

    struct Example {
        ctx: RequestAudit,
        conn: Connection,
        error: Option<(Reason, String)>,
        duration_ms: u64,
    }

    impl Example {
        fn new(ctx: RequestAudit, conn: Connection, duration_ms: u64) -> Self {
            Self {
                ctx,
                conn,
                error: None,
                duration_ms,
            }
        }
    }

    enum Entry {
        /// Built from the record's own time, in Unix seconds.
        Audit(Box<dyn Fn(i64) -> Example>),
        System(Level, &'static str, &'static str),
    }

    /// `request_filter`'s first steps for a DenBrowser request from the example
    /// workstation, whose clock runs one second behind the proxy's.
    fn attested(method: &str, now: i64) -> RequestAudit {
        let mut ctx = RequestAudit::new(true);
        ctx.request(method, Some(HOST));
        ctx.attestation_headers(Some(&(now - 1).to_string()), Some(NONCE));
        ctx.machine_cert_presented(workstation(MACHINE_HOST));
        ctx
    }

    fn verified_machine() -> VerifiedMachine {
        VerifiedMachine {
            hostname: MACHINE_HOST.to_owned(),
            subject_dn: workstation_dn(MACHINE_HOST),
        }
    }

    /// Refused after the token passed, by machine identity.
    fn machine_refusal(now: i64, cert: String, e: MachineError, duration_ms: u64) -> Example {
        let mut ctx = attested("GET", now);
        ctx.machine_cert_presented(cert);
        ctx.token_verified(Binding::Bound);
        ctx.machine_rejected(&e);
        Example::new(ctx, conn(Some(403), 0, 0), duration_ms)
    }

    /// Refused by the token checks.
    fn token_refusal(ctx: RequestAudit, e: AttestError) -> Example {
        let mut ctx = ctx;
        ctx.reject(e.reason(), e.to_string());
        Example::new(ctx, conn(Some(403), 0, 0), 1)
    }

    fn entries() -> Vec<Entry> {
        use Entry::{Audit, System};
        vec![
            System(
                Level::INFO,
                "denbrowser_proxy",
                "listening TLS on 0.0.0.0:8443 → backend.internal:443",
            ),
            // ── Allowed ──────────────────────────────────────────────────────
            Audit(Box::new(|now| {
                let mut ctx = attested("POST", now);
                ctx.token_verified(Binding::Bound);
                ctx.machine_verified(verified_machine());
                ctx.forward();
                Example::new(ctx, conn(Some(200), 512, 18_734), 42)
            })),
            Audit(Box::new(|now| {
                let mut ctx = attested("PUT", now);
                ctx.token_verified(Binding::Unbound);
                ctx.machine_verified(verified_machine());
                ctx.forward();
                Example::new(ctx, conn(Some(201), 52_428_800, 96), 3_510)
            })),
            Audit(Box::new(|now| {
                // `[machine_identity] required = false`, and none was sent.
                let mut ctx = RequestAudit::new(true);
                ctx.request("GET", Some(HOST));
                ctx.attestation_headers(Some(&(now - 1).to_string()), Some(NONCE));
                ctx.machine_absent();
                ctx.token_verified(Binding::Bound);
                ctx.forward();
                Example::new(ctx, conn(Some(200), 0, 4_096), 18)
            })),
            Audit(Box::new(|_| {
                let mut ctx = RequestAudit::new(true);
                ctx.request("GET", Some(HOST));
                ctx.attestation_headers(None, None);
                ctx.bypass("health-checker");
                let mut conn = conn(Some(200), 0, 2);
                conn.client = Some("10.9.0.12:40112".parse().unwrap());
                conn.user_subject_dn =
                    Some("CN=health-checker,OU=Operations,O=Example Corp,C=US".to_owned());
                Example::new(ctx, conn, 6)
            })),
            // ── Refused, in pipeline order ───────────────────────────────────
            Audit(Box::new(|now| {
                let mut ctx = attested("GET", now);
                ctx.reject(Reason::RateLimited, "request rate limit exceeded");
                Example::new(ctx, conn(Some(429), 0, 0), 0)
            })),
            Audit(Box::new(|_| {
                let mut ctx = RequestAudit::new(true);
                ctx.request("GET", Some(HOST));
                ctx.attestation_headers(None, None);
                ctx.reject(
                    Reason::NoAttestationHeaders,
                    "no DenBrowser attestation headers — not DenBrowser, or a \
                     DenBrowser not configured for this proxy",
                );
                Example::new(ctx, conn(Some(403), 0, 0), 0)
            })),
            Audit(Box::new(|now| {
                let mut ctx = RequestAudit::new(true);
                ctx.request("GET", Some(HOST));
                ctx.attestation_headers(Some(&(now - 1).to_string()), Some(NONCE));
                ctx.machine_cert_presented(workstation(MACHINE_HOST));
                ctx.reject(
                    Reason::IncompleteAttestationHeaders,
                    "incomplete attestation headers (missing or unreadable: x-denbrowser-token)",
                );
                Example::new(ctx, conn(Some(403), 0, 0), 0)
            })),
            Audit(Box::new(|now| {
                let mut ctx = RequestAudit::new(true);
                ctx.request("GET", Some(HOST));
                ctx.attestation_headers(Some(&(now - 1).to_string()), Some(NONCE));
                ctx.machine_rejected(&MachineError::Missing);
                Example::new(ctx, conn(Some(403), 0, 0), 0)
            })),
            Audit(Box::new(|now| {
                machine_refusal(
                    now,
                    "bm90IGEgY2VydGlmaWNhdGU=".into(),
                    MachineError::NotDer,
                    1,
                )
            })),
            Audit(Box::new(|now| {
                let cert = cert_b64(&[("C", "US"), ("O", "Example Corp")]);
                machine_refusal(now, cert, MachineError::NoCommonName, 1)
            })),
            Audit(Box::new(|now| {
                let cert = workstation("ws-4417\naccepted");
                machine_refusal(now, cert, MachineError::UnsafeCommonName, 1)
            })),
            Audit(Box::new(|now| {
                let cn = "laptop-1.corp.example.com";
                let e = MachineError::HostnameNotAllowed(cn.into());
                machine_refusal(now, workstation(cn), e, 1)
            })),
            Audit(Box::new(|now| {
                machine_refusal(now, workstation(MACHINE_HOST), MachineError::CertExpired, 1)
            })),
            Audit(Box::new(|now| {
                machine_refusal(
                    now,
                    workstation(MACHINE_HOST),
                    MachineError::CertNotYetValid,
                    1,
                )
            })),
            Audit(Box::new(|now| {
                let e =
                    MachineError::UntrustedChain("unable to get local issuer certificate".into());
                machine_refusal(now, workstation(MACHINE_HOST), e, 1)
            })),
            Audit(Box::new(|now| {
                let e = MachineError::HostnameUnresolvable(MACHINE_HOST.into());
                machine_refusal(now, workstation(MACHINE_HOST), e, 12)
            })),
            Audit(Box::new(|now| {
                let e = MachineError::HostnameAddressMismatch {
                    cn: MACHINE_HOST.into(),
                    ip: "10.4.2.17".parse().unwrap(),
                };
                machine_refusal(now, workstation(MACHINE_HOST), e, 9)
            })),
            Audit(Box::new(|now| {
                let mut ex = machine_refusal(
                    now,
                    workstation(MACHINE_HOST),
                    MachineError::NoClientAddress,
                    0,
                );
                ex.conn.client = None;
                ex
            })),
            Audit(Box::new(|_| {
                let mut ctx = RequestAudit::new(true);
                ctx.request("GET", Some(HOST));
                ctx.attestation_headers(Some("yesterday"), Some(NONCE));
                ctx.machine_cert_presented(workstation(MACHINE_HOST));
                token_refusal(ctx, AttestError::BadTimestamp)
            })),
            Audit(Box::new(|now| {
                let mut ctx = attested("GET", now);
                ctx.attestation_headers(Some(&(now - 95).to_string()), Some(NONCE));
                token_refusal(ctx, AttestError::TimestampDrift(95))
            })),
            Audit(Box::new(|now| {
                let mut ctx = attested("GET", now);
                ctx.attestation_headers(Some(&(now - 1).to_string()), Some("c2hvcnQ="));
                token_refusal(ctx, AttestError::InvalidNonce("wrong length"))
            })),
            Audit(Box::new(|now| {
                token_refusal(attested("GET", now), AttestError::NonceReplay)
            })),
            Audit(Box::new(|now| {
                token_refusal(
                    attested("GET", now),
                    AttestError::InvalidToken("token too short"),
                )
            })),
            Audit(Box::new(|now| {
                token_refusal(attested("GET", now), AttestError::DecryptFailed)
            })),
            Audit(Box::new(|now| {
                token_refusal(attested("POST", now), AttestError::PlaintextMismatch)
            })),
            Audit(Box::new(|now| {
                let mut ctx = attested("POST", now);
                ctx.token_verified(Binding::Bound);
                ctx.machine_verified(verified_machine());
                ctx.reject(
                    Reason::BodyTooLarge,
                    "bound body exceeds 65536 bytes (must be sent as an unbound upload)",
                );
                Example::new(ctx, conn(Some(413), 69_632, 0), 4)
            })),
            Audit(Box::new(|now| {
                let mut ctx = attested("POST", now);
                ctx.token_verified(Binding::Bound);
                ctx.machine_verified(verified_machine());
                let e = AttestError::BodyHashMismatch;
                ctx.reject(e.reason(), e.to_string());
                Example::new(ctx, conn(Some(403), 2_048, 0), 3)
            })),
            Audit(Box::new(|now| {
                let mut ctx = attested("POST", now);
                ctx.token_verified(Binding::Bound);
                ctx.machine_verified(verified_machine());
                ctx.reject(
                    Reason::BodyReadFailed,
                    "could not read request body: ReadError",
                );
                Example::new(ctx, conn(Some(400), 1_024, 0), 30_001)
            })),
            // ── Failed after forwarding ──────────────────────────────────────
            System(
                Level::ERROR,
                "pingora_proxy",
                // pingora's wording, ending in the path-free `request_summary`.
                "Fail to proxy: Upstream ConnectRefused context: Fail to connect to addr: \
                 10.30.0.8:443, scheme: HTTPS, sni: backend.internal cause:  context: Fail to \
                 connect to 10.30.0.8:443 cause: Connection refused (os error 111), status: 502, \
                 tries: 1, retry: false, POST intranet.example.com",
            ),
            Audit(Box::new(|now| {
                let mut ctx = attested("POST", now);
                ctx.token_verified(Binding::Bound);
                ctx.machine_verified(verified_machine());
                ctx.forward();
                let mut ex = Example::new(ctx, conn(Some(502), 512, 0), 7);
                ex.error = Some(classify_proxy_error(&pingora_core::Error::new_up(
                    pingora_core::ErrorType::ConnectRefused,
                )));
                ex
            })),
            Audit(Box::new(|now| {
                let mut ctx = attested("GET", now);
                ctx.token_verified(Binding::Bound);
                ctx.machine_verified(verified_machine());
                ctx.forward();
                let mut ex = Example::new(ctx, conn(Some(200), 0, 1_048_576), 2_204);
                ex.error = Some(classify_proxy_error(&pingora_core::Error::new_down(
                    pingora_core::ErrorType::ConnectionClosed,
                )));
                ex
            })),
            Audit(Box::new(|now| {
                // pingora failed before `request_filter` reached a decision.
                let mut ctx = RequestAudit::new(true);
                ctx.request("GET", Some(HOST));
                ctx.attestation_headers(Some(&(now - 1).to_string()), Some(NONCE));
                ctx.machine_cert_presented(workstation(MACHINE_HOST));
                let mut ex = Example::new(ctx, conn(Some(500), 0, 0), 0);
                ex.error = Some(classify_proxy_error(&pingora_core::Error::new_in(
                    pingora_core::ErrorType::InternalError,
                )));
                ex
            })),
        ]
    }

    fn example_lines() -> Vec<String> {
        entries()
            .into_iter()
            .enumerate()
            .map(|(i, entry)| {
                let ms = EXAMPLE_EPOCH_MS + i as u64 * 1000;
                match entry {
                    Entry::Audit(build) => {
                        let mut ex = build((ms / 1000) as i64);
                        let record =
                            ex.ctx
                                .record(&ex.conn, ex.error.take(), at(ms), ex.duration_ms);
                        serde_json::to_string(&record).unwrap()
                    }
                    Entry::System(level, logger, message) => {
                        let record = SystemRecord::new(
                            at(ms),
                            &level,
                            logger,
                            message,
                            serde_json::Map::new(),
                        );
                        serde_json::to_string(&record).unwrap()
                    }
                }
            })
            .collect()
    }

    fn examples() -> Vec<Value> {
        let text = std::fs::read_to_string(EXAMPLES_PATH)
            .unwrap_or_else(|e| panic!("cannot read {EXAMPLES_PATH}: {e}"));
        text.lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn examples_file_is_current() {
        let generated = example_lines().join("\n") + "\n";
        if std::env::var_os(UPDATE_VAR).is_some() {
            std::fs::write(EXAMPLES_PATH, &generated).unwrap();
            return;
        }
        let on_disk = std::fs::read_to_string(EXAMPLES_PATH).unwrap_or_default();
        if on_disk != generated {
            let diff = on_disk
                .lines()
                .zip(generated.lines())
                .enumerate()
                .find(|(_, (a, b))| a != b)
                .map(|(i, (a, b))| {
                    format!(
                        "first difference at line {}:\n  file: {a}\n  code: {b}",
                        i + 1
                    )
                })
                .unwrap_or_else(|| "line counts differ".to_owned());
            panic!(
                "audit/audit-log.examples.jsonl is out of date; regenerate with \
                 {UPDATE_VAR}=1 cargo test examples_file\n{diff}"
            );
        }
    }

    #[test]
    fn every_reason_and_action_has_an_example() {
        let examples = examples();
        let field = |key: &str| -> Vec<Value> {
            examples.iter().map(|e| e["event"][key].clone()).collect()
        };
        let reasons = field("reason");
        for r in Reason::ALL {
            assert!(
                reasons.contains(&Value::from(r.code())),
                "no example for {}",
                r.code()
            );
        }
        let actions = field("action");
        for a in [
            Action::Forward,
            Action::Bypass,
            Action::Reject,
            Action::RateLimit,
            Action::Error,
        ] {
            let a = serde_json::to_value(a).unwrap();
            assert!(actions.contains(&a), "no example for action {a}");
        }
        assert!(field("kind").contains(&Value::from("system")));
    }

    // ── The schema ───────────────────────────────────────────────────────────

    fn schema() -> Value {
        let text = std::fs::read_to_string(SCHEMA_PATH)
            .unwrap_or_else(|e| panic!("cannot read {SCHEMA_PATH}: {e}"));
        serde_json::from_str(&text).unwrap()
    }

    fn names<T: Serialize>(values: &[T]) -> Vec<Value> {
        values
            .iter()
            .map(|v| serde_json::to_value(v).unwrap())
            .collect()
    }

    #[test]
    fn schema_reason_table_matches_the_code() {
        let schema = schema();
        let table = schema["$defs"]["reason"]["oneOf"]
            .as_array()
            .expect("reason.oneOf");
        let in_schema: Vec<(Value, Value, Value)> = table
            .iter()
            .map(|r| {
                (
                    r["const"].clone(),
                    r["x-stage"].clone(),
                    r["x-severity"].clone(),
                )
            })
            .collect();
        let in_code: Vec<(Value, Value, Value)> = Reason::ALL
            .iter()
            .map(|r| {
                (
                    Value::from(r.code()),
                    serde_json::to_value(r.stage()).unwrap(),
                    serde_json::to_value(r.severity()).unwrap(),
                )
            })
            .collect();
        assert_eq!(
            in_schema, in_code,
            "schema reason table out of step with `reasons!`"
        );
    }

    #[test]
    fn schema_enums_match_the_code() {
        let schema = schema();
        let defs = &schema["$defs"];
        let enum_of = |name: &str| -> Vec<Value> {
            defs[name]["enum"]
                .as_array()
                .unwrap_or_else(|| panic!("$defs.{name}.enum missing"))
                .clone()
        };
        use Severity as Sv;
        assert_eq!(
            enum_of("severity"),
            names(&[Sv::Info, Sv::Low, Sv::Medium, Sv::High, Sv::Critical])
        );
        use Stage as St;
        assert_eq!(
            enum_of("stage"),
            names(&[
                St::RateLimit,
                St::AttestationHeaders,
                St::MachineIdentity,
                St::AttestationToken,
                St::AttestationBody,
                St::Upstream,
                St::Downstream,
                St::Internal,
            ])
        );
        assert_eq!(
            enum_of("action"),
            names(&[
                Action::Forward,
                Action::Bypass,
                Action::Reject,
                Action::RateLimit,
                Action::Error
            ])
        );
        assert_eq!(
            enum_of("outcome"),
            names(&[Outcome::Success, Outcome::Failure])
        );
        use AttestationStatus as A;
        assert_eq!(
            enum_of("attestationStatus"),
            names(&[
                A::Verified,
                A::Failed,
                A::Bypassed,
                A::Incomplete,
                A::NotEvaluated
            ])
        );
        use MachineStatus as M;
        assert_eq!(
            enum_of("machineStatus"),
            names(&[
                M::Verified,
                M::Failed,
                M::Absent,
                M::NotEvaluated,
                M::Disabled
            ])
        );
        assert_eq!(
            enum_of("bodyBinding"),
            names(&[Binding::Bound, Binding::Unbound])
        );
        assert_eq!(defs["schemaVersion"]["const"], SCHEMA_VERSION);
    }

    #[test]
    fn schema_lists_every_record_field_the_code_writes() {
        // Catches a field the schema documents but the code no longer writes.
        let schema = schema();
        let documented: Vec<&String> = schema["$defs"]["auditRecord"]["properties"]
            .as_object()
            .unwrap()
            .keys()
            .collect();
        let example = examples()
            .into_iter()
            .find(|e| e["event"]["kind"] == "audit")
            .unwrap();
        let written: Vec<&String> = example.as_object().unwrap().keys().collect();
        let mut documented = documented;
        let mut written = written;
        documented.sort();
        written.sort();
        assert_eq!(documented, written);
    }
}

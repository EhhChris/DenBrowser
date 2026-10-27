//! Log subscriber setup for the DenBrowser proxy.
//!
//! The browser half of DenBrowser has telemetry and diagnostics patched out, so
//! this process is the only component permitted to record anything: its log is
//! the audit trail.  [`init`] builds a subscriber that writes to a rotating file
//! in an operator-chosen directory and, by default, mirrors the same events to
//! stderr.
//!
//! # Every line is JSON
//!
//! Both outputs use [`JsonLines`].  Per-request audit records arrive already
//! serialized (see [`crate::audit`]) and are written verbatim; every other
//! event — startup messages, `fatal`, pingora's own diagnostics — is wrapped in
//! a `system` record.  The layout is defined by `audit/audit-log.schema.json`.
//!
//! # Why `tracing` rather than a plain `log` backend
//!
//! File writes go through [`tracing_appender::non_blocking`], which hands the
//! actual I/O to a background thread.  `request_filter` runs on a tokio worker
//! owned by pingora, and a synchronous write there would stall that worker for
//! the duration of a disk hiccup.
//!
//! `tracing` also subsumes the older `log` facade rather than competing with it.
//! pingora emits through `log`, and `tracing-subscriber`'s default `tracing-log`
//! feature installs a `LogTracer` that forwards those records into the same
//! subscriber, so pingora's internals land in the same file as our own events.
//!
//! # Caveats worth knowing before changing this
//!
//! * **The guard must outlive the server.**  [`init`] returns a
//!   [`WorkerGuard`]; dropping it flushes and stops the writer thread.  `main`
//!   holds it for the life of the process.  Note that `Server::run_forever`
//!   diverges and ends in `process::exit`, so that drop never actually runs —
//!   records already handed to the writer are written, but a few buffered lines
//!   can be lost at shutdown.  This is bounded, not solved.  The stderr mirror
//!   is why fatal messages still reach the operator regardless.
//! * **The writer is a thread, and threads do not survive `fork`.**  `main`
//!   calls `Server::new(None)`, which leaves pingora's `daemon` flag false, so
//!   nothing forks today.  If that ever changes, logging must be initialised
//!   *after* the fork or the writer thread will vanish silently.
//! * **Backpressure over loss.**  The writer is built with `lossy(false)`: when
//!   the buffer fills, the logging call blocks instead of discarding the record.
//!   For an audit log a stalled request is preferable to a hole in the trail.
//! * **Pingora's own refusals are quiet.**  A request pingora rejects before
//!   `request_filter` runs (malformed request line, duplicate or ambiguous
//!   `Host`, bad framing) is answered 400 without reaching any `ProxyHttp`
//!   hook, so it gets no audit record, and since pingora 0.9.0 its `system`
//!   line is logged at `debug` only, so at `info` it leaves no trace.  That gap
//!   is accepted: the debug line carries up to 2 KiB of the raw request,
//!   attestation token and machine certificate included, which must never
//!   land in this file.

use std::fmt::Write as _;
use std::time::SystemTime;

use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::{Event, Subscriber};
use tracing_appender::non_blocking::{NonBlockingBuilder, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

use crate::audit;
use crate::config::LoggingConfig;

/// Environment variable that overrides `[logging].level` when set.
const ENV_FILTER_VAR: &str = "RUST_LOG";

/// Install the global subscriber described by `cfg`.
///
/// Returns the [`WorkerGuard`] for the background file writer, or `None` when
/// no log directory is configured and output goes to stderr alone.  The caller
/// must keep the guard alive; see the module docs.
///
/// Fails rather than degrading: if a log directory is configured but cannot be
/// created or written, the proxy has been asked for an audit trail it cannot
/// produce, and silently falling back to stderr would hide that from whoever
/// asked.  This mirrors the config file being mandatory in `main`.
pub fn init(cfg: &LoggingConfig) -> anyhow::Result<Option<WorkerGuard>> {
    cfg.validate()?;

    let filter = build_filter(cfg)?;

    // Both layers are optional, and `Option<Layer>` is itself a `Layer` that
    // does nothing when `None` — so the same registry expression covers all
    // four on/off combinations without juggling boxed trait objects.
    let (file_layer, guard) = match cfg.file_enabled() {
        true => {
            let (writer, guard) = build_file_writer(cfg)?;
            (Some(fmt::layer().event_format(JsonLines).with_writer(writer)), Some(guard))
        }
        false => (None, None),
    };
    let stderr_layer = cfg
        .stderr
        .then(|| fmt::layer().event_format(JsonLines).with_writer(std::io::stderr));

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(stderr_layer)
        .try_init()
        .map_err(|e| anyhow::anyhow!("cannot install log subscriber: {e}"))?;

    sync_log_bridge_level();

    Ok(guard)
}

/// Formats every event as one JSON line.
///
/// An event on [`audit::TARGET`] has its [`audit::RECORD_FIELD`] written
/// verbatim; anything else is wrapped in an [`audit::SystemRecord`].  JSON
/// escaping stops hostile values (DNs, Host headers) from injecting newlines.
pub struct JsonLines;

impl<S, N> FormatEvent<S, N> for JsonLines
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let meta = event.metadata();
        let mut fields = Fields::new(meta.target() == audit::TARGET);
        event.record(&mut fields);

        if let Some(line) = fields.audit_record {
            return writeln!(writer, "{line}");
        }

        // Records bridged from `log` (all of pingora) have target "log"; the
        // real origin is in the `log.target` field.
        let logger = fields.log_target.as_deref().unwrap_or(meta.target());
        let record = audit::SystemRecord::new(
            audit::timestamp(SystemTime::now()),
            meta.level(),
            logger,
            &fields.message,
            fields.extra,
        );
        let line = serde_json::to_string(&record).map_err(|_| std::fmt::Error)?;
        writeln!(writer, "{line}")
    }
}

/// Collects an event's fields for [`JsonLines`].
struct Fields {
    /// Only an event on the audit target may supply a verbatim record.
    audit: bool,
    audit_record: Option<String>,
    message: String,
    log_target: Option<String>,
    extra: serde_json::Map<String, serde_json::Value>,
}

impl Fields {
    fn new(audit: bool) -> Self {
        Self {
            audit,
            audit_record: None,
            message: String::new(),
            log_target: None,
            extra: serde_json::Map::new(),
        }
    }

    fn put(&mut self, field: &Field, value: serde_json::Value) {
        match field.name() {
            "message" => {
                self.message = match value {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                }
            }
            // Source location added by the `log` bridge; not logged.
            "log.module_path" | "log.file" | "log.line" => {}
            name => {
                self.extra.insert(name.to_owned(), value);
            }
        }
    }
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            audit::RECORD_FIELD if self.audit => self.audit_record = Some(value.to_owned()),
            "log.target" => self.log_target = Some(value.to_owned()),
            _ => self.put(field, value.into()),
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // `message` arrives here as `fmt::Arguments`, whose Debug is the text.
        let mut text = String::new();
        let _ = write!(text, "{value:?}");
        self.record_str(field, &text);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, value.into());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, value.into());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        // NaN and infinities have no JSON form; they become null.
        self.put(field, serde_json::Number::from_f64(value).map_or(serde_json::Value::Null, Into::into));
    }
}

/// Resolve the filter from `RUST_LOG` if present, otherwise `[logging].level`.
///
/// A malformed value is an error either way rather than a silent fallback: a
/// typo in a filter directive would otherwise quietly cost you the events you
/// were trying to see.
///
/// Note that `EnvFilter` catches less than you might expect.  Its grammar reads
/// a bare word as a *target* name, so `"inf"` parses cleanly as "log only the
/// target `inf`" and yields silence rather than an error.
/// [`LoggingConfig::validate`] screens bare tokens for exactly that reason; what
/// reaches here is a genuine parse failure, such as a bad level after `=`.
fn build_filter(cfg: &LoggingConfig) -> anyhow::Result<EnvFilter> {
    match std::env::var(ENV_FILTER_VAR) {
        Ok(var) if !var.trim().is_empty() => EnvFilter::try_new(&var)
            .map_err(|e| anyhow::anyhow!("invalid {ENV_FILTER_VAR} {var:?}: {e}")),
        _ => EnvFilter::try_new(&cfg.level)
            .map_err(|e| anyhow::anyhow!("invalid [logging].level {:?}: {e}", cfg.level)),
    }
}

/// Build the rotating file appender and wrap it in the background writer.
fn build_file_writer(
    cfg: &LoggingConfig,
) -> anyhow::Result<(tracing_appender::non_blocking::NonBlocking, WorkerGuard)> {
    let dir = cfg.dir.trim();

    // The appender would create this itself, but doing it here means a
    // permissions problem names the directory instead of surfacing as a
    // generic "failed to create log file".
    std::fs::create_dir_all(dir)
        .map_err(|e| anyhow::anyhow!("cannot create [logging].dir {dir:?}: {e}"))?;

    let mut builder = RollingFileAppender::builder()
        .rotation(rotation_from_str(&cfg.rotation)?)
        .filename_prefix(cfg.file_prefix.trim());

    // Deliberately left unset when 0.  `max_log_files(0)` is not "keep
    // everything" — tracing-appender computes `files.len() - (max_files - 1)`,
    // which underflows at 0 and prunes the whole directory.  Omitting the call
    // is the only way to express unlimited retention.
    if cfg.max_files > 0 {
        builder = builder.max_log_files(cfg.max_files);
    }

    // `build` opens the first file eagerly, so an unwritable directory fails
    // here at startup rather than on the first request.
    let appender = builder
        .build(dir)
        .map_err(|e| anyhow::anyhow!("cannot open log file in {dir:?}: {e}"))?;

    Ok(NonBlockingBuilder::default()
        .lossy(false)
        .finish(appender))
}

/// Map a validated `[logging].rotation` value onto the appender's enum.
///
/// [`LoggingConfig::validate`] has already rejected anything outside
/// `LOG_ROTATIONS`, so the fallback arm is unreachable in practice — it stays an
/// error rather than a panic so adding a value in one place and forgetting the
/// other is a startup message, not a crash.
fn rotation_from_str(rotation: &str) -> anyhow::Result<Rotation> {
    match rotation {
        "minutely" => Ok(Rotation::MINUTELY),
        "hourly" => Ok(Rotation::HOURLY),
        "daily" => Ok(Rotation::DAILY),
        "never" => Ok(Rotation::NEVER),
        other => anyhow::bail!("unsupported [logging].rotation {other:?}"),
    }
}

/// Clamp the `log` facade to the level the subscriber actually cares about.
///
/// `LogTracer` opens the `log` gate all the way to `Trace`, so without this
/// every pingora `trace!` would allocate a `log::Record` and build a tracing
/// event only to be discarded by the filter.  Reading the level back from
/// `LevelFilter::current()` (rather than hardcoding `Info`) keeps `RUST_LOG=debug`
/// working: raising our own verbosity raises pingora's with it.
fn sync_log_bridge_level() {
    let level = match LevelFilter::current().into_level() {
        Some(tracing::Level::ERROR) => log::LevelFilter::Error,
        Some(tracing::Level::WARN) => log::LevelFilter::Warn,
        Some(tracing::Level::INFO) => log::LevelFilter::Info,
        Some(tracing::Level::DEBUG) => log::LevelFilter::Debug,
        Some(tracing::Level::TRACE) => log::LevelFilter::Trace,
        None => log::LevelFilter::Off,
    };
    log::set_max_level(level);
}

#[cfg(test)]
mod tests {
    use super::*;

    // `init` installs a *global* subscriber and can therefore only succeed once
    // per process.  Exactly one test below calls it — `init_syncs_log_bridge_level`
    // — and the rest exercise the fallible pieces directly, so nothing here is
    // order-dependent.  Adding a second `init` call would break that.

    fn cfg_with_dir(dir: &str) -> LoggingConfig {
        LoggingConfig {
            dir: dir.to_owned(),
            ..LoggingConfig::default()
        }
    }

    #[test]
    fn file_writer_creates_missing_directory() {
        let tmp = tempfile::tempdir().unwrap();
        // Nested and absent: create_dir_all has to build both components.
        let dir = tmp.path().join("logs").join("proxy");
        assert!(!dir.exists());

        let cfg = cfg_with_dir(dir.to_str().unwrap());
        let (_writer, _guard) = build_file_writer(&cfg).expect("writer should build");

        assert!(dir.is_dir(), "log directory should have been created");
        let created: Vec<_> = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).collect();
        assert_eq!(created.len(), 1, "the first log file should be opened eagerly");
        assert!(
            created[0]
                .file_name()
                .to_str()
                .unwrap()
                .starts_with("denbrowser-proxy.log"),
            "log file should use the configured prefix, got {:?}",
            created[0].file_name()
        );
    }

    #[test]
    fn file_writer_rejects_unwritable_directory() {
        // /proc rejects directory creation for any user, root included, so this
        // exercises the failure path without depending on the test uid.
        let cfg = cfg_with_dir("/proc/denbrowser-should-not-exist");
        let err = build_file_writer(&cfg).expect_err("unwritable dir must fail");
        assert!(
            err.to_string().contains("[logging].dir"),
            "error should name the offending field, got: {err}"
        );
    }

    #[test]
    fn zero_max_files_is_accepted() {
        // Guards the underflow described in `build_file_writer`: 0 must mean
        // "keep everything", never "prune everything".
        let tmp = tempfile::tempdir().unwrap();
        let cfg = LoggingConfig {
            dir: tmp.path().to_str().unwrap().to_owned(),
            max_files: 0,
            ..LoggingConfig::default()
        };
        let (_writer, _guard) = build_file_writer(&cfg).expect("max_files = 0 should build");
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 1);
    }

    #[test]
    fn every_documented_rotation_maps() {
        for name in crate::config::LOG_ROTATIONS {
            assert!(
                rotation_from_str(name).is_ok(),
                "{name} is advertised in LOG_ROTATIONS but does not map"
            );
        }
        assert!(rotation_from_str("weekly").is_err());
    }

    #[test]
    fn filter_falls_back_to_config_level() {
        // Not asserting on RUST_LOG itself: the environment is process-global
        // and mutating it would race the other tests in this binary.
        let cfg = LoggingConfig {
            level: "warn,denbrowser_proxy=trace".to_owned(),
            ..LoggingConfig::default()
        };
        assert!(build_filter(&cfg).is_ok());
    }

    #[test]
    fn init_syncs_log_bridge_level() {
        // The one test that installs the global subscriber; see the note above.
        //
        // This is what proves pingora's output is reachable.  pingora logs
        // through the `log` facade, and `LogTracer` gates those records on
        // `log::max_level()` *before* the tracing filter ever sees them — so if
        // this is left at the default, raising `[logging].level` to debug
        // silently gets you nothing from pingora.
        if std::env::var("RUST_LOG").is_ok_and(|v| !v.trim().is_empty()) {
            eprintln!("skipping: RUST_LOG is set and would override the config level");
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let cfg = LoggingConfig {
            dir: tmp.path().to_str().unwrap().to_owned(),
            level: "debug".to_owned(),
            ..LoggingConfig::default()
        };

        let _guard = init(&cfg).expect("init should succeed");

        assert_eq!(
            log::max_level(),
            log::LevelFilter::Debug,
            "the log->tracing bridge must be opened to the configured level"
        );
        assert!(
            log::log_enabled!(log::Level::Debug),
            "a pingora debug! record must pass the facade's level gate"
        );
        assert!(
            !log::log_enabled!(log::Level::Trace),
            "trace should stay closed so pingora's trace! records cost nothing"
        );
    }

    /// Run `f` under a thread-local [`JsonLines`] subscriber and return the
    /// lines it wrote.  Must stay thread-local: another test installs the
    /// global subscriber.
    fn capture(f: impl FnOnce()) -> Vec<serde_json::Value> {
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buf = Buf(Arc::new(Mutex::new(Vec::new())));
        let writer = buf.clone();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .event_format(JsonLines)
                .with_writer(move || writer.clone()),
        );
        tracing::subscriber::with_default(subscriber, f);

        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        out.lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}")))
            .collect()
    }

    #[test]
    fn plain_events_become_system_records() {
        let lines = capture(|| {
            tracing::info!(port = 8443u64, "listening on {}", "0.0.0.0:8443");
        });
        assert_eq!(lines.len(), 1);
        let l = &lines[0];
        assert_eq!(l["event"]["kind"], "system");
        assert_eq!(l["level"], "INFO");
        assert_eq!(l["schema_version"], audit::SCHEMA_VERSION);
        assert_eq!(l["logger"], "denbrowser_proxy::logging::tests");
        assert_eq!(l["message"], "listening on 0.0.0.0:8443");
        assert_eq!(l["fields"]["port"], 8443);
        assert!(l["timestamp"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn bridged_log_records_keep_their_origin_and_drop_source_locations() {
        // The shape tracing-log gives a pingora `log` record.
        let lines = capture(|| {
            tracing::event!(
                target: "log",
                tracing::Level::ERROR,
                log.target = "pingora_proxy",
                log.module_path = "pingora_proxy",
                log.file = "src/lib.rs",
                log.line = 917u64,
                "Fail to proxy: Upstream ConnectRefused"
            );
        });
        let l = &lines[0];
        assert_eq!(l["logger"], "pingora_proxy");
        assert_eq!(l["level"], "ERROR");
        assert!(l.get("fields").is_none(), "source location should be dropped: {l}");
    }

    #[test]
    fn audit_records_are_written_verbatim() {
        let lines = capture(|| {
            let mut ctx = audit::RequestAudit::new(false);
            ctx.request("GET", Some("app.example.com"));
            ctx.reject(audit::Reason::NoAttestationHeaders, "none");
            ctx.finish(
                &audit::Connection {
                    proxy: None,
                    client: None,
                    tls_client_subject: None,
                    status_code: Some(403),
                    request_body_bytes: 0,
                    response_body_bytes: 0,
                },
                None,
            );
        });
        assert_eq!(lines.len(), 1);
        let l = &lines[0];
        assert_eq!(l["event"]["kind"], "audit");
        assert_eq!(l["logger"], audit::TARGET);
        assert_eq!(l["level"], "WARN");
        assert_eq!(l["event"]["reason"], "no_attestation_headers");
        assert!(l.get(audit::RECORD_FIELD).is_none(), "record must not be wrapped");
    }

    #[test]
    fn only_the_audit_target_can_supply_a_verbatim_line() {
        let lines = capture(|| {
            tracing::warn!(audit_record = "{\"forged\":true}", "hello");
        });
        let l = &lines[0];
        assert_eq!(l["event"]["kind"], "system");
        assert_eq!(l["fields"][audit::RECORD_FIELD], "{\"forged\":true}");
    }

    #[test]
    fn newlines_in_values_cannot_split_a_line() {
        let lines = capture(|| {
            tracing::warn!("evil\n{{\"event\":{{\"kind\":\"audit\"}}}}");
        });
        assert_eq!(lines.len(), 1, "an embedded newline must stay escaped");
        assert_eq!(lines[0]["event"]["kind"], "system");
    }

    #[test]
    fn filter_rejects_malformed_level() {
        // A bad *level* after `=` is one of the few things EnvFilter genuinely
        // refuses; see `build_filter` for why a bare typo is not.
        let cfg = LoggingConfig {
            level: "denbrowser_proxy=nonsense".to_owned(),
            ..LoggingConfig::default()
        };
        let err = build_filter(&cfg).expect_err("malformed level must fail");
        assert!(err.to_string().contains("[logging].level"), "got: {err}");
    }

    #[test]
    fn bare_level_typo_is_caught_by_config_validation() {
        // EnvFilter itself accepts this, reading "inf" as a target name — which
        // is why LoggingConfig::validate screens bare tokens before we get here.
        let cfg = LoggingConfig {
            level: "inf".to_owned(),
            ..LoggingConfig::default()
        };
        assert!(
            build_filter(&cfg).is_ok(),
            "precondition: EnvFilter is permissive about bare words"
        );
        let err = cfg.validate().expect_err("validate must reject the typo");
        assert!(err.to_string().contains("[logging].level"), "got: {err}");
    }
}

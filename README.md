> **Note:** This project and its scaffolding were built with AI assistance (Claude, Anthropic).
> Review all generated code and patches carefully before use in production.
> The author of the repository has reviewed every change in detail, but does not have extensive history working with browsers, pingora, or rust professionally.
> If you find bugs or problems in implementation during peer review please do no hesitate to raise an issue.

# DenBrowser

A set of patches for building a branded version of Firefox ESR browser that attempts to restrict users from removing data from the browser or otherwise persisting it locally. DenBrowser is **not** a complete solution, and really only makes sense when the deployment and operating environment is largely controlled and the user has no elevated privileges. The intended purpose is to provide a moderate approach to data loss prevention strategies with less intense external infrastructure requirements and less user impact on performance for use in **controlled** environments.

**Currently tracking Firefox ESR 140.x** (most recently built against 140.11.0esr;
`scripts/fetch-esr.sh` pulls whatever ESR is current at fetch time).

As this project progresses tags will be cut and attempt to follow the latest ESR releases.
Patches 015 and 017 are regenerated semantically (`scripts/gen-015-patch.sh`,
`scripts/gen-017-patch.sh`) per ESR; the remaining patches use small enough
context that they usually carry across point releases unmodified.

---

## Prerequisites

- Python 3, Rust, Node.js (required by Firefox build system — see [Firefox build docs](https://firefox-source-docs.mozilla.org/setup/))
- **[sccache](https://github.com/mozilla/sccache)** — required compiler wrapper.
  `config/mozconfig` sets `--with-compiler-wrapper=sccache`, so the build will
  fail at configure if it's not on `PATH`. It also dramatically reduces
  incremental rebuild times (minutes instead of an hour+ on a warm cache).
  - macOS:   `brew install sccache`
  - Linux:   `cargo install sccache` (or your distro package)
  - Windows: `cargo install sccache` or `choco install sccache`

  The default 50 GB cache size is set via `SCCACHE_CACHE_SIZE` in
  `config/mozconfig`; adjust there if you're tight on disk.
- ~20 GB free disk space for the source + build artifacts (plus up to 50 GB
  for the sccache cache, separately configurable)

## Deployment requirements

DenBrowser keeps page content out of Firefox's on-disk profile (PBM forced on,
disk cache hard-disabled, downloads blocked, SanitizeOnShutdown locked).
What it cannot control is the **operating system** writing process memory
to disk underneath it. To close that gap, every deployment host must:

- **Enable full-disk encryption** (FileVault on macOS, BitLocker on Windows,
  LUKS on Linux). Anything the OS pages out to swap/pagefile, captures in a
  crash dump (`WerFault`, `sysdiagnose`, kernel minidump), or writes to a
  hibernation image is then encrypted at rest under a user- or TPM-bound key.
- **Disable hibernation**, or ensure the hibernation image is encrypted.
  (FDE generally covers this, but verify on locked-down kiosk images.)
- **On Linux**, prefer `swapoff` or an encrypted swap partition. Unencrypted
  swap defeats every in-memory protection in this project.

These are operational controls, not build-time controls. The browser cannot
enforce them; the deployment image must. See `patches/007-ramdisk-profile.patch`
for the detailed analysis of why DenBrowser does not ship a RAM-disk profile.

## Quick start

```bash
# 1. Bootstrap the Firefox build system (first time only)
./scripts/fetch-esr.sh            # downloads & verifies Firefox ESR source
cd src/firefox-$(cat src/.esr_version)
./mach bootstrap                  # installs Rust, cbindgen, etc.
cd ../..

# 2. Build
./build.sh # Attempts the full build process on the last esr version pulled by fetch-esr.sh
```

---

## Project structure

```
DenBrowser/
├── build.sh                    # Full build orchestration
├── branding/                   # DenBrowser branding assets (icons, etc.)
├── config/
│   ├── mozconfig               # Firefox build flags + app identity
│   ├── policies.json           # Enterprise policy enforcement (loaded at startup)
│   ├── mozilla.cfg             # Hardened lockPref overrides (autoconfig-locked)
│   ├── autoconfig.js           # Bootstrap that tells Firefox to load mozilla.cfg
│   └── site-config.json        # Per-deployment whitelist / blacklist / clipboard sites /
│                               #   attestation proxies / bookmarks
├── patches/
│   ├── README.md               # Patch development guide
│   └── NNN-*.patch             # See "Patches" table below
├── proxy/
│   ├── Cargo.toml
│   ├── proxy.example.toml      # Example operational config (attestation key, rate limiting, …)
│   └── src/
│       ├── main.rs             # Pingora-based attestation proxy entrypoint
│       ├── attest.rs           # ECIES verification + replay cache
│       ├── config.rs           # Operational TOML config loader
│       ├── ratelimit.rs        # Per-origin-IP request rate limiting
│       ├── mtls.rs             # Baseline mutual-TLS client authentication
│       └── passthrough.rs      # Attestation bypass (IP + cert-subject allowlist)
└── scripts/
    ├── fetch-esr.sh            # Download + verify latest Firefox ESR source
    ├── apply-patches.sh        # Apply patches with dry-run validation
    ├── gen-attest-key.sh       # Generate a proxy's ECDSA P-256 attestation keypair
    ├── gen-proxy-tls.sh        # Generate a proxy's TLS cert + report its SPKI pin
    ├── gen-user-cert.sh        # Generate mTLS user (browser client) cert + CA
    └── gen-015-patch.sh        # Regenerate patch 015 for the current ESR version
```

---

## Defense layers

DenBrowser's protections are layered across four enforcement points so any
single bypass still leaves the rest in place:

1. **Build-time flags** (`config/mozconfig`) — `--disable-crashreporter`,
   `--disable-updater`, `--disable-tests`, `--disable-parental-controls`,
   `--disable-profiling`, `--disable-accessibility`, `--enable-hardening`,
   `--enable-strip` / `--enable-install-strip`.  Code paths and symbols are
   never compiled in.
2. **Source patches** — applied to the Firefox source tree before build;
   compiled into the binary and cannot be disabled at runtime by any
   user-accessible mechanism.
3. **Enterprise policies** (`config/policies.json`) — loaded at startup;
   lock UI surfaces and per-URL permissions.  Cannot be overridden by
   profile state.
4. **Autoconfig prefs** (`config/mozilla.cfg` via `config/autoconfig.js`) —
   `lockPref` values that override `prefs.js`, `about:config`, and all
   profile state. Patch 017 additionally compiles the entire `mozilla.cfg`
   set into `libxul`, so the same locks survive deletion or substitution
   of the on-disk autoconfig files.

The categories below summarize what is protected and where the enforcement
lives.

| Concern | Patch(es) | Policy | lockPref |
|---|---|---|---|
| Profile / on-disk content | — | `SanitizeOnShutdown`, `DisableFormHistory` | `browser.privatebrowsing.autostart`, `browser.cache.disk.*`, `browser.cache.offline.*`, `media.cache_size`, `places.history.enabled`, `signon.rememberSignons`, `browser.formfill.enable`, `browser.sessionstore.*`, `browser.pagethumbnails.capturing_disabled`, `browser.shell.shortcutFavicons`, `dom.serviceWorkers.enabled` |
| Screenshots (built-in + OS capture) | 001 | `DisableScreenshots` | `extensions.screenshots.disabled` |
| Screen / window / browser capture | 002 | — | `media.getusermedia.screensharing.enabled`, `media.getusermedia.browser.enabled`, `media.getusermedia.window.focus_source.enabled` |
| Clipboard + drag-and-drop | 003 | — | `dom.allow_cut_copy`, `dom.event.clipboardevents.enabled` |
| Downloads / Save As / wallpaper | 004 | `PromptForDownloadLocation` | `browser.download.useDownloadDir`, `browser.download.forbid_open_with`, `browser.download.always_ask_before_handling_new_types`, `browser.download.manager.retention`, `browser.download.start_downloads_in_tmp_dir`, `browser.helperApps.deleteTempFileOnExit` |
| Printing + print-to-PDF | 005 | `DisablePrinting` | `print.enabled` |
| Per-request attestation to proxy | 006 | — | — |
| RAM-disk profile | 007 (intentional stub — FDE on host instead) | — | — |
| Developer tools (incl. CLI debug flags) | 008, 015 | `DisableDeveloperTools`, `BlockAboutConfig`, `BlockAboutProfiles`, `BlockAboutSupport`, `BlockAboutAddons` | `devtools.policy.disabled`, `devtools.chrome.enabled`, `devtools.debugger.remote-enabled`, `devtools.debugger.prompt-connection`, `marionette.enabled` |
| Branding | 009 | — | — |
| Telemetry / diagnostics | 010 | `DisableTelemetry`, `DisableFirefoxStudies`, `DisableFeedbackCommands` | `datareporting.policy.dataSubmissionEnabled`, `datareporting.healthreport.uploadEnabled`, `toolkit.telemetry.enabled`, `toolkit.telemetry.unified`, `app.normandy.enabled`, `app.shield.optoutstudies.enabled` |
| Extensions (loading + install) | 011 | `ExtensionSettings: {* blocked}`, `DisableSystemAddonUpdate` | `xpinstall.enabled` |
| Proxy TLS SPKI pinning | 012 | — | — |
| Sync / Firefox Accounts | 013 | `DisableFirefoxAccounts` | `identity.fxaccounts.enabled` (covered by policy) |
| Site whitelist / blacklist | 014 | — | — |
| Argv + env-var stripping | 015 | — | — |
| Window-title leak | 016 | — | — |
| Camera / Microphone / Location / Notifications / VR | — | `Permissions: Camera/Microphone/Location/Notifications/VirtualReality {Block: <all_urls>, Locked: true}`, `Autoplay: block-audio-video` | `geo.enabled`, `media.peerconnection.enabled`, `media.navigator.enabled` |
| Cookies — in-memory, no third-party | — | `Cookies: reject-foreign + ExpireAtSessionEnd + Locked` | (via policy) |
| DRM / EME | — | `EncryptedMediaExtensions {Enabled: false, Locked: true}` | — |
| Password manager / form autofill | — | `PasswordManagerEnabled: false`, `DisableMasterPasswordCreation`, `DisableProfileImport` | `signon.rememberSignons`, `extensions.formautofill.available` |
| First-run / new-tab / Pocket / messaging | — | `DisablePocket`, `OverrideFirstRunPage`, `OverridePostUpdatePage`, `NoDefaultBookmarks`, `FirefoxHome`, `UserMessaging` | — |
| App + system-addon updates | — | `DisableAppUpdate`, `AppUpdateURL`, `DisableSystemAddonUpdate` | `app.update.background.enabled`, `extensions.update.enabled`, `extensions.systemAddon.update.enabled` |
| HTTPS-only enforcement | — | `HttpsOnlyMode: force_enabled` | — |
| Translation / search-suggest / DoH | — | `TranslateEnabled: false`, `SearchSuggestEnabled: false`, `DNSOverHTTPS {Enabled: false, Locked: true}`, `NetworkPrediction: false` | `network.dns.disablePrefetch`, `network.dns.disablePrefetchFromHTTPS`, `network.prefetch-next`, `network.predictor.enabled`, `network.http.speculative-parallel-limit`, `browser.urlbar.suggest.history`, `browser.urlbar.suggest.bookmark` |
| Fingerprinting + tracking protection | — | — | `privacy.resistFingerprinting`, `privacy.resistFingerprinting.block_mozAddonManager`, `privacy.trackingprotection.enabled`, `privacy.trackingprotection.socialtracking.enabled`, `privacy.trackingprotection.cryptomining.enabled`, `privacy.trackingprotection.fingerprinting.enabled` |
| External protocol handlers (mailto/tel/sms/…) | — | — | `network.protocol-handler.external-default`, `network.protocol-handler.external.mailto`, `network.protocol-handler.external.tel`, `network.protocol-handler.external.sms`, `dom.registerProtocolHandler.enabled` |
| Phone-home endpoints (Safe Browsing, captive-portal, Remote Settings, OCSP, blocklist, etc.) | — | — | `browser.safebrowsing.*`, `network.captive-portal-service.enabled`, `network.connectivity-service.enabled`, `browser.discovery.enabled`, `services.settings.server`, `security.OCSP.*`, `security.remote_settings.*`, `extensions.blocklist.*`, `extensions.update.url`, `app.update.url`, `network.trr.confirmationNS` |
| Web-platform capability APIs (Share / FS Access / USB / HID / Serial / MIDI / Bluetooth / Payments / Push / Notifications / SpeechSynth / Idle / Battery / Sensors / WebTransport / file://) | — | — | `dom.webshare.enabled`, `dom.fs.enabled`, `dom.origin-private-file-system.enabled`, `dom.webusb.enabled`, `dom.webhid.enabled`, `dom.webserial.enabled`, `dom.serial.enabled`, `dom.webmidi.enabled`, `dom.bluetooth.enabled`, `dom.payments.request.enabled`, `dom.push.enabled`, `dom.webnotifications.enabled`, `media.webspeech.synth.enabled`, `media.webspeech.recognition.enable`, `dom.idle-detection.enabled`, `dom.battery.enabled`, `device.sensors.enabled`, `network.webtransport.enabled`, `network.protocol-handler.expose.file` |

Per-deployment configuration (`config/site-config.json`) drives the
compile-time switches and the baked-in bookmarks:

- `clipboard_sites` — hosts that may use the in-browser internal clipboard
  (patch 003).  Empty list = no in-browser copy/paste anywhere.
- `site_whitelist` — if non-empty, only these hosts (and subdomains) may be
  loaded over HTTP(S); everything else is blocked, with top-level navigation
  showing a DenBrowser error page
  (patch 014).
- `site_blacklist` — used only when whitelist is empty.
- `proxies` — the attestation proxies this build talks to, one entry per
  partner application (patches 006 + 012).  See
  [Attestation proxies](#attestation-proxies-site-configjson) below.
- `bookmarks` — curated shortcuts shown as tiles on the custom new-tab and home
  page (patch 018; the home button and startup page are pointed at
  `about:denbrowserhome` via a `browser.startup.homepage` lock).  Each entry is
  an object with required `title` and `url`; `url` must be `http(s)`.  At build
  time (`build.sh` Step 2.7) the list is rendered as static HTML tiles into
  `denbrowser-newtab.html` (titles/URLs are HTML-escaped, URLs restricted to
  `http(s)` since the tiles are injected as raw HTML, and each tile uses
  `target="_self"` so it opens in the current tab).  An empty/absent list
  shows a "No shortcuts configured" placeholder.  These are *not* Firefox
  bookmarks: the activity-stream new-tab page does not render in this
  permanent-private build, and the bookmark store itself is read-only
  (patch 019), so there is no editable bookmark UI.  Example:

  ```json
  "bookmarks": [
    { "title": "Intranet", "url": "https://intranet.example.com" },
    { "title": "Docs", "url": "https://docs.example.com" }
  ]
  ```

### Attestation proxies (`site-config.json`)

A deployment normally fronts several partner applications, each behind its
**own** attestation proxy with its own attestation keypair and TLS cert — no
partner should be able to verify (or mint) another partner's tokens.  The
`proxies` array is the build-time map from *domains* to *the proxy that fronts
them*, and it drives both compile-time proxy features at once:

- the attestation public key used to encrypt a request's token (patch 006), and
- the TLS SPKI pin enforced when connecting to those domains (patch 012).

```json
"proxies": [
  {
    "name":       "partner-a",
    "domains":    ["app.partner-a.example.com", "cdn.partner-a.example.com"],
    "attest_key": "partner-a-public.der",
    "tls_cert":   "partner-a-tls.crt"
  },
  {
    "name":       "partner-b",
    "domains":    ["partner-b.example.com"],
    "attest_key": "partner-b-public.der",
    "tls_cert": "partner-b-tls.crt"
  }
]
```

- `name` — label for this proxy; appears in browser log messages and names the
  key material.  Letters/digits/`._-`, unique across entries.
- `domains` — every hostname this proxy fronts.  Matching is exact **or a
  subdomain** of a listed domain (`partner-a.com` also claims
  `app.partner-a.com`), the same rule `site_whitelist` uses.
- `attest_key` — the proxy's attestation public key in DER
  (`scripts/gen-attest-key.sh --name <name>`).  A bare filename is read from
  `build/`; a path is taken relative to the repo root.
- `tls_cert` / `tls_spki_sha256` — the TLS pin, given either as a cert file the
  build hashes for you (`scripts/gen-proxy-tls.sh --name <name>`) or as the
  32-byte sha256 itself in hex or base64, for production hosts whose cert never
  lands on the build machine.  Set at most one.  An entry with neither is still
  attested but **not pinned** (the build warns).

Setting up one partner end-to-end:

```bash
./scripts/gen-attest-key.sh --name partner-a
./scripts/gen-proxy-tls.sh  --name partner-a --host app.partner-a.example.com
# add the printed entry to config/site-config.json, then:
./build.sh

# run that partner's proxy with its own material:
cd proxy && cargo run --release -- \
  --listen   0.0.0.0:8443 \
  --upstream app-backend.partner-a.internal:443 \
  --cert     ../build/partner-a-tls.crt \
  --tls-key  ../build/partner-a-tls.key \
  --config   partner-a.toml   # its [attestation] private_key names the key
```

Each proxy instance is a separate process with its own listener, key, cert, and
`proxy.toml`; the proxy binary itself is unchanged by the multi-proxy model.
Rotating one partner's key or cert only touches that partner's entry, but it
does still require a DenBrowser rebuild — the pin and the public key are
compiled in by design.

### Proxy runtime configuration (`proxy/proxy.toml`)

The attestation proxy loads a **required** TOML config file for *operational*
settings tuned per deployment without rebuilding.  It defaults to `proxy.toml`
in the working directory (override with `--config <path>` or the
`DENBROWSER_CONFIG` env var); the proxy **exits on startup** if the file is
missing or unparseable, so it never comes up with unintended (e.g.
mTLS-disabled) settings.  Copy the annotated `proxy/proxy.example.toml` to
`proxy/proxy.toml` and edit it.  This config is separate from the compile-time
attestation/TLS key flags, and from `config/site-config.json` (which feeds the
browser build), and is the place to grow as more runtime options are added.

**Attestation key** (`[attestation]`) is the one **required** section — it names
this proxy's EC P-256 attestation private key, the private half of the public key
baked into the browser build for it:

```toml
[attestation]
private_key = "/etc/denbrowser/partner-a-private.pem"
```

Startup **aborts** if it is unset, unreadable, or not a parseable EC key, rather
than bringing up a proxy that would reject every attested request.  Relative
paths resolve against the proxy's working directory, as `client_ca` does.  There
is no CLI flag and no default path: each partner's proxy process names its own
key in its own config file, so one partner can never decrypt another's tokens,
and a deployment that forgets the key fails loudly instead of silently picking
up whatever happens to sit at a default location.

**Rate limiting** (`[rate_limiting]`) throttles requests per origin IP.  A bad
config aborts startup rather than starting unprotected, and a request over any
applicable limit is answered `429` *before* attestation or the upstream is
touched, so floods are shed cheaply.

- `enabled` — master on/off switch for the whole feature.
- `window_secs` / `max_requests` — the **universal cap**: at most `max_requests`
  per `window_secs` from any single client IP, across every request.  Set either
  to `0` to disable the universal cap and rely on `rules` alone.
- `[[rate_limiting.rules]]` — **per-URL-pattern** limits, each with its own
  window and cap and its own counter keyed by origin IP, so a burst against one
  pattern is throttled independently of the others and of the universal cap.
  `pattern` is a glob matched against `"{host}{path}"` (where `*` matches any run
  of characters, including `/`); rules are evaluated top-to-bottom, first match
  wins.  Counting uses `pingora-limits`' sliding-window estimator.

  ```toml
  [rate_limiting]
  enabled = true
  window_secs = 1        # universal: 100 requests / second / IP
  max_requests = 100

  [[rate_limiting.rules]]
  pattern = "example.com/secrets/*"   # 5 requests / minute / IP
  window_secs = 60
  max_requests = 5
  ```

  Note: when clients share an egress IP (NAT), the per-IP counters are shared —
  size caps for the deployment's real per-IP concurrency.

**Baseline mTLS** (`[mtls]`) requires every client to authenticate with a
certificate at the TLS handshake — a third orthogonal layer alongside the
existing two, replacing neither:

- **mTLS** authenticates the *user/device* to the proxy (client → proxy).
- **TLS SPKI pinning** (patch 012) authenticates the *proxy* to the browser
  (proxy → client); the browser pins the proxy's cert, defeating MITM even by a
  validly-CA-issued cert. mTLS is the opposite direction and does not replace it.
- **Attestation** (ECIES headers) proves the request came from a genuine
  DenBrowser build and binds it against replay/tampering — properties a client
  cert doesn't provide. mTLS proves *who* holds a key but not *what software*
  produced the request, so the two are complementary.

  When `[mtls] enabled = true`, the listener is configured with
  `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT` against `client_ca`, so a
  client with no certificate or one that doesn't chain to the CA is **rejected at
  the handshake** and never reaches the request path.  Disabled by default (no
  client certificate requested; behaviour identical to before).  A bad config
  (missing/unreadable/empty CA bundle) aborts startup.

  ```toml
  [mtls]
  enabled = true
  client_ca = "/etc/denbrowser/user-ca.pem"
  ```

**Attestation bypass** (`[proxy_bypass]`) is an opt-in escape hatch that lets
trusted infrastructure (health checks, internal automation) that can't run the
DenBrowser attestation client reach the upstream.  It **builds on baseline mTLS**
(and requires `[mtls]` enabled): the client certificate is already verified at
the handshake, so bypass adds only two conditions on top of that verified
identity, and is **default-deny**:

- `enabled` — master switch. When off, every request is attested.
- `allowed_ip_ranges` — CIDR ranges; the client's source IP must be inside one.
- `allowed_subjects` — the mTLS-verified cert's CN or a SAN DNS entry must be on
  this allowlist (so one CA can issue many user certs while only named identities
  may bypass).

  A request is forwarded straight upstream (skipping attestation) only when the
  source IP **and** the cert-subject checks both pass; any miss falls through to
  normal attestation.  A bad config (bypass enabled without mTLS, empty
  ranges/allowlist, invalid CIDR) aborts startup.

  ```toml
  [proxy_bypass]
  enabled = true
  allowed_ip_ranges = ["10.0.0.0/8"]
  allowed_subjects = ["health-checker"]
  ```

---

## Patches

Patches apply in lexicographic order via `scripts/apply-patches.sh`.  Each
patch file's header has the full rationale; the summary below is intended
for navigation.

| # | Name | Summary |
|---|---|---|
| 000 | `fix-bindgen-basic-string-view` | Upstream build fix for libclang/bindgen on recent toolchains.  No security effect. |
| 001 | `disable-screenshots` | Block built-in screenshot UI **and** exclude the window from OS screen-capture (`NSWindowSharingNone` on macOS, `WDA_EXCLUDEFROMCAPTURE` on Windows). |
| 002 | `disable-screenshare` | Unconditionally reject `getDisplayMedia()` and legacy `getUserMedia({video:{mediaSource:"screen"}})` at both JS and C++ layers. |
| 003 | `restrict-clipboard` | Block clipboard read/write and drag-and-drop everywhere; optional in-process clipboard for `clipboard_sites` so copy/paste works within the controlled site set without ever touching the OS clipboard. |
| 004 | `restrict-downloads` | Cancel every file-save path: `internalSave`, `nsExternalHelperAppService::CreateListener`, `ShellService.canSetDesktopBackground`, and the Mac / Windows `SetDesktopBackground` C++ entry points. |
| 005 | `disable-printing` | Reject `nsPrintJob::CommonPrint` for both print and print-preview — covers `window.print`, print-to-PDF, and any internal caller. |
| 006 | `attest-requests` | Inject per-request ECIES attestation headers (v2: binds nonce + ts + host + method + path + body hash) into outbound HTTP/HTTPS requests for the Pingora proxy to verify.  Carries a build-time table of N proxies (domains → attestation key + TLS pin, generated from `site-config.json`'s `proxies`) and attests with the key of the proxy claiming the request's host; hosts no proxy claims are left untouched. |
| 007 | `ramdisk-profile` | **Intentionally not implemented** (STUB).  The header documents why: PBM + locked disk-cache prefs + `SanitizeOnShutdown` already keep content off disk, and the residual swap/hibernation risk needs FDE on the host — see [Deployment requirements](#deployment-requirements). |
| 008 | `disable-devtools` | Hardcode `isDisabledByPolicy()` to `true` in both `DevToolsShim` and `DevToolsStartup`, so devtools stay off even if the policy/pref state is manipulated. |
| 009 | `denbrowser-branding` | DenBrowser branding directory (icons, brand strings, Windows installer assets, Visual Elements manifest). |
| 010 | `disable-diagnostics` | Replace `TelemetryReportingPolicy.dataSubmissionEnabled` getter with `return false`; short-circuit `TelemetryController.setupTelemetry` to a no-op. |
| 011 | `disable-extensions` | Filter addon install locations to `SCOPE_APPLICATION` only; throw on any `AddonInstall.install()` call regardless of state. |
| 012 | `pin-proxy-tls` | Pin each attestation proxy's TLS SPKI (sha256) into the build — the pin column of patch 006's proxy table, so every partner proxy is pinned to its own cert; abort the handshake in `AuthCertificateHook` before any application data flows if the leaf cert doesn't match. |
| 013 | `disable-sync` | Hardcode `WeaveService.enabled` and `FXA_ENABLED` to `false`; remove the Sync preferences pane and Synced-Tabs sidebar entries from the UI. |
| 014 | `site-filter` | Compile-time whitelist/blacklist enforcement in `nsDocShell::InternalLoad` for the navigation error page and `nsHttpChannel::AsyncOpen` for all HTTP(S) requests; localize the "blocked page" message. |
| 015 | `strip-blocked-args` | Strip security-sensitive CLI flags (`--profile`, `--marionette`, `--remote-debugging-port`, `--screenshot`, `--headless`, `--safe-mode`, `--jsdebugger`, …) **and** environment variables (`MOZ_LOG`, `SSLKEYLOGFILE`, `MOZ_DISABLE_*_SANDBOX`, `MOZ_PROFILER_STARTUP*`, `MOZ_CRASHREPORTER*`, …) from the process before any Firefox code reads them.  Regenerate per-ESR via `scripts/gen-015-patch.sh`. |
| 016 | `fixed-window-title` | Override `nsCocoaWindow::SetTitle` / Windows + GTK `nsWindow::SetTitle` to substitute the constant string `"DenBrowser"` for the page-supplied title — prevents page-title leakage through `CGWindowListCopyWindowInfo`, `EnumWindows`/`GetWindowTextW`, `_NET_WM_NAME`, etc. |
| 017 | `compile-in-lockprefs` | Generate a C++ function (`SetupDenBrowserLockdown`) from `config/mozilla.cfg` and call it from `Preferences::GetInstanceForService` after pref-config-startup. Locks every pref directly in `libxul`, removing the dependency on the on-disk `mozilla.cfg`/`autoconfig.js` pair for layer-4 enforcement. Regenerate per-ESR (and on every `mozilla.cfg` edit) via `scripts/gen-017-patch.sh`. Skipped in `--dev` builds. |
| 018 | `custom-newtab` | Replace the (blank-in-PBM) activity-stream new-tab page with a self-contained shortcuts page. `about:denbrowserhome` is registered as a plain chrome `about:` page via the C++ `AboutRedirector` (like `about:robots`/`about:privatebrowsing`), mapping to `chrome://browser/content/denbrowser-newtab.{html,css}`; it renders as untrusted content in a normal child process, sidestepping the newtab add-on entirely. `AboutNewTab.newTabURL` is pinned to it so every new tab loads it. Tiles are injected from `site-config.json`'s `bookmarks` by `build.sh` Step 2.7. |
| 019 | `readonly-bookmarks` | Make the bookmark store read-only: the seven public mutation methods of `Bookmarks.sys.mjs` (insert/insertTree/update/moveToFolder/remove/eraseEverything/reorder) reject before doing any work, so no caller can create, edit, or delete bookmarks. |

---

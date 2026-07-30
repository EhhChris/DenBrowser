# TPM attestation (design)

**Status:** design only — no code has been written. This document specifies an
optional, build-time TPM layer for the browser→proxy attestation path, and records
the decisions and dependencies behind it so the implementation does not have to
re-derive them.

**Scope decisions taken up front:**

| Question | Decision |
|---|---|
| Request-path signing model | Session binding — one TPM quote per session, software ECDSA per request |
| What the evidence proves | Boot state, via a PCR quote |
| Platform | Windows only |

---

## 1. Why

The attestation layer that exists today (`patches/006-attest-requests.patch` →
`netwerk/base/DenBrowserAttest.cpp`, verified by `proxy/src/attest.rs`) has **no
client-held secret.**

It encrypts a canonical request descriptor to the proxy's *public* P-256 key —
ephemeral ECDH, ANSI X9.63 KDF, AES-128-GCM — and that public key is compiled into
every shipped binary as `kDenProxyKey_N[]` (see `build.sh` Step 2.5, and the
`DenProxyEntry` table at `patches/006-attest-requests.patch:273-294`). ECIES needs
only the public half to encrypt. The repo's own tooling demonstrates the
consequence: `test/attestation/test_roundtrip.py` and
`proxy/stress/denbrowser_stress.py` both mint fully valid tokens from
`build/proxy-public.pem` alone.

So the current layer delivers request binding (method, host, path, body hash),
replay rejection, and a timestamp window. It does **not** demonstrate that a request
came from a genuine DenBrowser running on an approved machine. Anyone who extracts
the compiled-in public key can produce tokens the proxy accepts.

A TPM supplies the missing piece: a signing key that is created inside the chip,
cannot be exported, and can additionally sign a statement about how the machine
booted.

### 1.1 What this does and does not buy

Worth being blunt about, because "TPM attestation" is often assumed to mean more
than it does.

**It does:**

- Raise the bar from *"extract the public key and mint tokens from anywhere"* to
  *"be on an enrolled machine with that specific TPM physically present."*
- Give a device identity that cannot be copied. This is strictly stronger than the
  file-based mTLS client certificate produced by `scripts/gen-user-cert.sh`, which is
  a file on disk and can be copied to another machine.
- Provide signed boot-state evidence: Secure Boot enabled, no test-signing, no kernel
  debugger, a known bootloader.

**It does not:**

- Prove the process making the request is an unmodified DenBrowser. A TPM measures
  boot, not userspace. Any code running as that user, on that machine, can drive the
  TPM and mint valid sessions. Closing that gap needs Windows code-integrity policy
  attestation, which is a substantially larger project than this one.
- Help on an already-compromised machine. Once an attacker has code execution as the
  browser's user, they inherit the browser's TPM access.

The honest summary: this converts a *software* secret that isn't secret into a
*hardware-bound machine* identity, plus boot-state evidence. It is a real and
significant improvement over the status quo, and it is not remote code attestation.

---

## 2. Prerequisite: an AK trust anchor

**A PCR quote is only as trustworthy as the key that signed it, and nothing inside a
quote blob asserts that a real TPM produced it.**

This needs stating plainly because it is the one way to build this feature and end up
with no security at all. A `TPMS_ATTEST` structure is roughly fifty lines of
byte-marshalling. An attacker generates an ordinary P-256 keypair in software, writes
out a structure with `magic = 0xFF544347`, `type = TPM_ST_ATTEST_QUOTE`, and whatever
`pcrDigest` claims the boot state they want to appear to have, signs it, and sends it.
Every signature check the proxy performs will pass. If the proxy accepts quotes from
any attestation key it has not seen before, the entire layer is decorative.

Boot-state policy therefore rests on an attestation-key trust anchor. Two ways to get
one:

### 2.1 Enrollment allowlist (recommended starting point)

An administrator provisions each machine once and records its AK public key on the
proxy. The proxy accepts quotes only from enrolled keys.

The AK is identified by its TPM **Name**, which is the standard way to refer to a TPM
object:

```
Name = TPM_ALG_SHA256 (0x000B, big-endian u16) || SHA256(marshalled pubArea)
```

The proxy must additionally check the key's `objectAttributes` in the `pubArea`:

| Attribute | Why it matters |
|---|---|
| `fixedTPM` | The key cannot be duplicated to another TPM |
| `fixedParent` | The key cannot be re-parented |
| `sensitiveDataOrigin` | The private half was generated inside the TPM, not imported |
| `restricted` | The key will only sign TPM-internal structures, so it cannot be tricked into signing an attacker-chosen "quote" |
| `sign` | It is a signing key |

`restricted` is the load-bearing one for quoting. A non-restricted key will sign
arbitrary external data, which means an attacker on the machine could ask the TPM to
sign a fabricated `TPMS_ATTEST` and get a genuine TPM signature over a lie. A
restricted signing key refuses to sign anything that starts with the TPM_GENERATED
magic value unless the TPM itself produced it.

This mirrors how the repo already provisions mTLS material in
`scripts/gen-user-cert.sh` — an admin-run script whose output is placed into proxy
configuration. Since Windows AK provisioning already requires a per-machine step
(§7), the marginal cost of recording the resulting public key is close to zero.

### 2.2 EK certificate chain (optional upgrade)

Validate that the machine's Endorsement Key certificate chains to a TPM
manufacturer's root, then use `TPM2_MakeCredential` / `TPM2_ActivateCredential` to
prove the AK lives in the same TPM as that EK. This lets a proxy trust "any genuine
TPM from an approved vendor" without per-machine enrollment.

The costs are real and are the reason this is not the recommended starting point:

- There is **no canonical vendor CA bundle.** You assemble one per fleet from
  Infineon, Nuvoton, STMicro, Intel (PTT), AMD (fTPM), and Microsoft roots.
- Intel PTT endorsement certificates are retrieved from an Intel URL at provisioning
  time rather than being present on the machine.
- On Windows, reading the EK *certificate* requires **administrator rights**
  (`NCRYPT_PCP_EKNVCERT_PROPERTY` and its RSA/ECC variants are not exposed in a
  non-admin context). The EK *public key* (`NCRYPT_PCP_EKPUB_PROPERTY`) is available
  to a normal user.

Start with §2.1. Add §2.2 later if per-machine enrollment becomes an operational
burden.

---

## 3. Protocol

### 3.1 Why session binding

A TPM signing operation costs roughly 20–100 ms on a discrete TPM, and the device
serializes: one command at a time through the resource manager. Signing every HTTP
request with the TPM would make browsing unusable and would turn the TPM into a
global lock on the browser's network path.

So the TPM is used **once per session** to bind an ephemeral software key, and that
software key signs each request. Per-request cost becomes a software ECDSA-P256
signature — on the order of 50 µs — and the hot path never touches the TPM device at
all.

A useful side effect: because the TPM is only touched at session setup, this design
does not depend on the TPM being reachable from whichever process ends up running
necko's channel setup.

### 3.2 Session establishment

1. The browser generates an ephemeral **software** P-256 session keypair via NSS,
   using the same `PK11_GenerateKeyPair` call already present at
   `patches/006-attest-requests.patch:596-606`.

2. The browser asks the TPM for a `TPM2_Quote` over the configured PCR selection,
   passing as `qualifyingData`:

   ```
   SHA256("denbrowser-tpm-bind:v1" || session_pub || expiry_be64 || proxy_name)
   ```

   `session_pub` is the 65-byte SEC1 uncompressed point. `proxy_name` is the entry
   name from the `kDenProxies` table, which stops a session minted for one proxy from
   being replayed against another.

3. The browser assembles a binding blob and derives
   `session_id = SHA256(blob)[0..16]`.

### 3.3 Binding blob

All integers big-endian. The client caches the exact bytes so re-sends are identical
and the session id stays stable.

```
u8       version            = 1
u8[65]   session_pub          SEC1 uncompressed P-256 point
u64      expiry_unix
u16 len + bytes  ak_pub       marshalled TPMT_PUBLIC (pubArea)
u16 len + bytes  quoted       TPMS_ATTEST, exactly as returned by TPM2_Quote
u16 len + bytes  signature    TPMT_SIGNATURE
u16 len + bytes  pcr_values   concatenated digests, in pcrSelect order
u32 len + bytes  tcg_log      WBCL from Tbsi_Get_TCG_Log_Ex (may be empty)
```

Typical size is 1–2 KB without the log; the WBCL can add tens of KB, which is why it
is sent only on the bind request and not on every request.

### 3.4 Canonical plaintext v3

The existing v2 plaintext is 7 newline-separated fields
(`proxy/src/attest.rs:23` and `:199-209`). v3 adds an eighth:

```
denbrowser-attest:v3
<nonce_b64>
<ts>
<host>
<method>
<path>
<sha256_hex | "unbound">
<session_id_b64>              ← new
```

Carrying `session_id` *inside* the GCM-authenticated plaintext is what welds the two
layers together. Without it, a per-request TPM signature could be lifted from one
request and attached to a different ECIES token.

### 3.5 Headers

Alongside the existing `X-DenBrowser-Ts`, `X-DenBrowser-Nonce`, and
`X-DenBrowser-Token`:

| Header | Sent | Contents |
|---|---|---|
| `X-DenBrowser-TPM-Session` | every request | base64 16-byte session id |
| `X-DenBrowser-TPM-Sig` | every request | base64 64-byte raw `r‖s` ECDSA-P256 over `SHA256(plaintext_v3)` |
| `X-DenBrowser-TPM-Bind` | first request of a session, and on re-bind | base64 binding blob |

**Re-bind handshake.** The proxy's session cache is in-process and TTL-bounded, so a
client's session can be evicted (proxy restart, TTL expiry, a different proxy
instance). When the proxy sees a session id it does not know and no bind blob, it
answers `403` with `X-DenBrowser-TPM-Rebind: 1`. The browser retries that request once
with `X-DenBrowser-TPM-Bind` attached. Cap this at one retry per request so a
misbehaving proxy cannot induce a loop.

`upstream_request_filter` (`proxy/src/main.rs:292-302`) must strip all three new
headers in addition to the three it strips today.

---

## 4. Proxy verification

New module `proxy/src/tpm.rs`, invoked from `request_filter`
(`proxy/src/main.rs:143-289`) after phase-1 header verification and before body
handling.

When `[tpm].enabled`:

1. Any TPM header missing → **403.** *This is the stated requirement: once the
   feature is on, an attested request that does not carry TPM evidence fails.*
2. Session-cache hit → jump to step 9.
3. Cache miss and no bind blob → **403** plus `X-DenBrowser-TPM-Rebind: 1`.
4. `session_id == SHA256(blob)[0..16]`; `expiry` is in the future and no further out
   than `max_session_lifetime_secs`. Otherwise 403.
5. Compute the AK Name from `pubArea` and look it up in the enrollment allowlist.
   Not enrolled → **403.** (See §2 — this step is what makes the rest mean anything.)
6. Check `objectAttributes` per §2.1. Any missing attribute → 403.
7. Verify `TPMT_SIGNATURE` over `SHA256(quoted)` using the AK public key.
8. Parse `TPMS_ATTEST` and check:
   - `magic == 0xFF544347` (TPM_GENERATED_VALUE)
   - `type == 0x8018` (TPM_ST_ATTEST_QUOTE)
   - `extraData` equals the recomputed `qualifyingData` from §3.2
   - `pcrSelect` matches the configured selection exactly
   - `pcrDigest == SHA256(concat(pcr_values))`

   Then apply PCR policy (§9). Any mismatch → 403.
9. Verify `X-DenBrowser-TPM-Sig` over `SHA256(plaintext_v3)` with the cached
   `session_pub`, and confirm plaintext field 8 matches the session id header.
   Otherwise 403.
10. Insert or refresh the session-cache entry.

**Implementation notes.**

- Reuse the `Mutex<HashMap<_, Instant>>` plus `retain()` TTL-sweep pattern from
  `Verifier::commit_nonce` (`proxy/src/attest.rs:238-252`) for the session cache. Note
  the same caveat that applies there: the sweep only runs on insert, so a workload
  that is all cache hits never prunes.
- Add a `TpmError` enum with a `Display` impl mirroring `AttestError`
  (`proxy/src/attest.rs:68-95`), so rejections produce the same style of single-line
  `warn!` the rest of the proxy uses.
- Keep `403` for every rejection, consistent with the existing status map.
  `X-DenBrowser-TPM-Rebind` is what distinguishes the one recoverable case.
- Version interop: accept v2 plaintext only while `audit_only = true` (§6). Once
  enforcement is on, v2 is rejected — otherwise a client can downgrade out of TPM
  simply by sending the old prefix.

---

## 5. Build-time configuration

The feature is off unless the build config turns it on, following the existing
"empty table means off" convention used by `kDenProxies`
(`patches/006-attest-requests.patch:288-294`), `kDenSiteWhitelist`
(`patches/014-site-filter.patch:155-160`), and `kDenClipboardSites`.

New block in the build config (`config/site-config.json` today — see §10 on renaming
it):

```json
"tpm": {
  "enabled": true,
  "pcrs": [0, 2, 4, 7, 11],
  "bank": "sha256",
  "ak_key_name": "DenBrowserAK",
  "session_lifetime_secs": 3600,
  "include_tcg_log": true,
  "fail_closed": true
}
```

A new **`build.sh` Step 2.9** generates from it, using the same sentinel-replacement
technique as Step 2.5 (`build.sh:158-372`): an inline `python3` heredoc that replaces
the region between `// ── DEN: TPM_CONFIG ──` and `// ── DEN END: TPM_CONFIG ──`,
and `die()`s unless exactly one match is found. Target is a new
`netwerk/base/DenBrowserTpm.cpp`:

```cpp
// GENERATED by build.sh (Step 2.9). Do not edit here — edit the JSON, rebuild.
#define DENBROWSER_TPM_ENABLED 1
static const uint32_t kDenTpmPcrs[] = {0, 2, 4, 7, 11};
static const uint32_t kDenTpmSessionLifetimeSecs = 3600;
static const bool     kDenTpmIncludeTcgLog = true;
static const bool     kDenTpmFailClosed = true;
```

The default shipped in the patch is `#define DENBROWSER_TPM_ENABLED 0` with an empty
PCR array, so a stock build compiles no TPM code and acquires no new runtime
dependency.

**Validation the generator must perform**, matching the strictness Step 2.5 already
applies to `proxies`:

- `enabled: true` on a non-Windows target is a hard error, not a warning.
- PCR indices must be in 0–23 and unique.
- `bank` must be `sha256`.
- `session_lifetime_secs` within sane bounds (say 300–86400).
- `ak_key_name` matching the existing `NAME_RE` style used at `build.sh:165`.

**`fail_closed`.** When true (recommended), a TPM failure makes `AddAttestHeaders`
return an error so the channel fails with a distinguishable code. This is
deliberately unlike the surrounding code, which returns `NS_OK` on essentially every
crypto failure (`patches/006-attest-requests.patch:494-687`) and so silently emits
unattested traffic. With TPM enforcement on, failing open just produces a confusing
403 page instead of a clear local error — the user cannot tell a policy rejection
from a broken TPM. Fail closed and say why.

---

## 6. Proxy runtime configuration

New `[tpm]` section in `proxy/src/config.rs`, following the shape every other section
uses — `#[serde(deny_unknown_fields)]`, `#[serde(default)]` on each field, default
off, validated at startup so misconfiguration panics rather than degrading
(`proxy/src/main.rs:330-368`):

```toml
[tpm]
enabled = false
enrollment = ""                     # path to the enrollment file; required when enabled
max_session_lifetime_secs = 3600
session_cache_ttl_secs = 3600
pcr_selection = [0, 2, 4, 7, 11]
pcr_policy = "log"                  # "off" | "log" | "pinned"
require_tcg_log = true
audit_only = false                  # staged-rollout escape hatch: log, don't reject
```

`enabled = true` implies TPM evidence is **required** — there is no separate
`required` knob, because "on but not enforced" is not a state worth having by
accident.

`audit_only` exists only because the browser fleet and the proxy cannot be flipped
at the same instant. It logs what it would have rejected and forwards anyway. It
must be turned off to get any security benefit, and the startup log should say so
loudly while it is on.

Mirror the new section into `proxy/proxy.example.toml` with the same commentary
density as the existing sections there.

**Enrollment file** (`enrollment`), JSON:

```json
{
  "version": 1,
  "devices": [
    {
      "label": "laptop-42",
      "ak_name": "000b<hex sha256 of pubArea>",
      "ak_pub_sec1": "<base64 SEC1 point>",
      "pcr_policy": null
    }
  ]
}
```

`pcr_policy` is per-device and overrides the global setting, so one machine can be
pinned while the fleet runs on log policy.

---

## 7. Windows client implementation

### 7.1 Recommended path: NCrypt PCP for the key, raw TBS for the quote

- Create the AK once via
  `NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0)` followed by
  `NCryptCreatePersistedKey(hProv, &hKey, NCRYPT_ECDSA_P256_ALGORITHM, L"DenBrowserAK", 0, 0)`.
  User-scoped keys need no administrator rights; `NCRYPT_MACHINE_KEY_FLAG` does.
- Retrieve the underlying TPM handle via `NCRYPT_PCP_PLATFORMHANDLE_PROPERTY`.
- Marshal a `TPM2_Quote` command and submit it with `Tbsi_Context_Create` +
  `Tbsip_Submit_Command`.
- Fetch the boot log with `Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, ...)`.

### 7.2 Why not `NCryptCreateClaim(NCRYPT_CLAIM_PLATFORM)`

It is the Windows-native route and it does produce a platform attestation. The
problem is the output: the claim blob is a Microsoft-defined container whose intended
verifier is `NCryptVerifyClaim` — that is, Windows. This proxy is Rust, runs on Linux,
and should stay that way. Parsing the claim container in Rust means reverse-engineering
a format that exists to be consumed by a Windows API.

The raw-TBS path yields standard TCG structures (`TPMS_ATTEST`, `TPMT_SIGNATURE`,
`TPMT_PUBLIC`) that a Rust verifier parses with no Windows dependency at all.
`google/go-attestation` (`attest/pcp_windows.go`) is the reference implementation of
exactly this combination — PCP for key management, raw TBS command submission for
quoting — and is worth reading before writing any of this.

### 7.3 Warning on constants

Current MSDN for `NCryptCreateClaim` documents only the `NCRYPT_CLAIM_VBS_*` claim
types and the `NCRYPTBUFFER_ATTESTATION_STATEMENT_*` buffer types.
`NCRYPT_CLAIM_PLATFORM` and `NCRYPTBUFFER_TPM_PLATFORM_CLAIM_PCR_MASK` /
`NCRYPTBUFFER_TPM_PLATFORM_CLAIM_NONCE` are referenced in Azure Attestation
documentation but are not fully specified in the public API reference.

**Take exact constant names and numeric values from `ncrypt.h` in the Windows SDK.**
Do not transcribe them from documentation, including this document.

### 7.4 Code placement

All TPM code goes under `#if DENBROWSER_TPM_ENABLED` inside `#ifdef XP_WIN`. That is
Pattern B from `patches/015-strip-blocked-args.patch:191-201`, the repo's existing
precedent for platform-conditional code in an otherwise shared file, and it avoids the
mac-only-code-path objection recorded at `patches/007-ramdisk-profile.patch:71-72`.

Register `DenBrowserTpm.{h,cpp}` in `netwerk/base/moz.build` exactly as patch 006
registers `DenBrowserAttest` (`patches/006-attest-requests.patch:766-785`), adding:

```python
OS_LIBS += ['tbs', 'ncrypt']
```

The call site is unchanged — `nsHttpChannel::SetupChannelForTransaction`, which calls
`denbrowser::AddAttestHeaders` (`patches/006-attest-requests.patch:798-812`). That
runs in the parent process, and because session binding keeps the TPM off the
per-request path (§3.1), a socket-process configuration never needs TPM device access
during request setup.

---

## 8. External dependencies

The short answer: **on Windows, none.** The longer answer, by component:

### 8.1 Windows client — no external dependencies

`tbs.dll` / `tbs.lib` and `ncrypt.dll` / `ncrypt.lib` are in-box, present since
Windows 8. Requirements are a provisioned TPM 2.0 (`Get-Tpm` reports
`TpmReady : True`) and Windows 8 or later.

| Operation | Administrator required? |
|---|---|
| Create / use a PCP user key | No |
| `TPM2_Quote` via TBS | No |
| `Tbsi_Get_TCG_Log_Ex` (WBCL) | No |
| Read EK public (`NCRYPT_PCP_EKPUB_PROPERTY`) | No |
| Read EK **certificate** (`NCRYPT_PCP_EKNVCERT_PROPERTY`) | **Yes** |
| Create a machine-scoped key (`NCRYPT_MACHINE_KEY_FLAG`) | **Yes** |

Only the last two matter, and only if EK-chain enrollment (§2.2) is adopted later.

Choosing Windows-only sidesteps the two worst dependency problems in this space:

- **No `tpm2-tss` to vendor.** On Linux this would mean pulling `libtss2-esys`,
  `libtss2-mu`, and `libtss2-tctildr` into a Firefox build that currently has *no
  mechanism at all* for external native libraries — everything so far reuses what
  Firefox already links (NSS, NSPR, XPCOM). That would have needed either a
  `third_party/` import with its own `moz.build`, a `--with-system-*` configure
  option, or runtime `dlopen`.
- **No `/dev/tpmrm0` permission problem.** On Linux that device is `tss:tss` mode
  `0660`, so the browser's user must be in the `tss` group — a deployment requirement
  that would have been the single largest source of support tickets.

### 8.2 Proxy — no TPM, no C library

The proxy never talks to a TPM. Verification is byte-parsing plus ECDSA-P256 plus
SHA-256, all of which the crate graph already supports:

| Need | Status |
|---|---|
| ECDSA-P256 verify | `p256` is already a direct dependency (`proxy/Cargo.toml:25`); enable its `ecdsa` feature. `ecdsa` and `elliptic-curve` are already in `Cargo.lock` transitively. |
| SHA-256 | `sha2` already a direct dependency |
| base64 | already a direct dependency |
| TPM structure parsing | ~250 lines hand-rolled. `TPMS_ATTEST`, `TPMT_PUBLIC`, and `TPMT_SIGNATURE` are simple big-endian length-prefixed structures. |
| TCG event-log parsing | Only needed for `pcr_policy = "log"`. Either the `uefi-eventlog` crate or a hand-rolled `TCG_PCR_EVENT2` parser. **This is the only genuinely new crate.** |
| X.509, if EK chains are added later | Reuse the `openssl` crate pingora already pulls in and `proxy/src/mtls.rs` already uses. Zero new dependencies. |

Explicitly **not** `tss-esapi`. It is the right crate for talking to a TPM, and the
proxy does not have one; adding it would drag `libtss2` onto every proxy host for no
benefit.

### 8.3 Operational dependencies — the real ones

These, not the libraries, are what this feature actually costs:

- **Per-machine enrollment.** Every machine needs a provisioning run whose output
  lands in the proxy's enrollment file. This is the same operational shape as
  `scripts/gen-user-cert.sh` today, so the process exists — it just gains a step.
- **PCR churn.** Firmware and bootloader updates move PCRs 0, 2, and 4; Secure Boot
  `dbx` updates move PCR 7. Under a pinning policy, every Patch Tuesday that ships a
  bootloader update locks out the fleet. §9 is the mitigation.
- **Vendor root CAs**, only under §2.2: no canonical bundle exists, Intel PTT certs
  are fetched online at provisioning time, and reading the EK cert needs admin. This
  is the most annoying dependency in the whole design and the main reason the
  enrollment allowlist is recommended first.

---

## 9. PCR policy

**Recommendation: replay the log, do not pin the digests.**

Pinning opaque PCR digests is the obvious implementation and the wrong one. PCR
values are digests over a chain of boot measurements; any firmware update, UEFI
setting change, bootloader update, or `dbx` revocation update changes them. A policy
that pins digests turns a security control into an outage generator, and the
predictable response — someone widens the allowlist until it stops paging them —
leaves you worse off than not having it.

Instead:

1. Quote PCRs **0, 2, 4, 7, 11** in the SHA-256 bank.
2. Ship the WBCL alongside the quote.
3. The proxy replays the log: fold each event's digest into a simulated PCR and check
   the result matches the quoted `pcrDigest`. This proves the log is genuine, because
   the quote is TPM-signed and the log alone is not.
4. Evaluate **policy on the events**, not on the final digest:
   - `EV_EFI_VARIABLE_DRIVER_CONFIG` for `SecureBoot` — must be enabled
   - `EV_EFI_VARIABLE_AUTHORITY` — which certificate authorized the bootloader
   - Windows SIPA events for boot-debug, kernel-debug, test-signing, and
     code-integrity state

That policy survives firmware updates, because "Secure Boot is on and the bootloader
was signed by Microsoft" stays true across them while the digest does not.

PCR selection rationale:

| PCR | Measures | Volatility |
|---|---|---|
| 0 | UEFI firmware code | Changes on firmware update |
| 2 | Option ROM code | Changes with hardware |
| 4 | Boot manager / bootloader | Changes on bootloader update |
| 7 | Secure Boot state and signing authority | Relatively stable; moves on `dbx` update |
| 11 | BitLocker / Windows boot phases | Windows-managed |

`pcr_policy = "pinned"` remains available for locked-down fleets with controlled
firmware, with the maintenance cost understood. `pcr_policy = "off"` binds device
identity only and ignores boot state — still useful, since §2 identity alone is a
large improvement over today.

`mattifestation/TCGLogTools` is a useful reference for WBCL and SIPA event structure;
Microsoft's Device Health Attestation performs essentially the log-replay check
described here.

---

## 10. Renaming the build config

`config/site-config.json` now drives clipboard policy, site filtering, attestation
proxies, TLS pins, bookmarks — and, with this design, TPM. "Site config" undersells
it; `config/denbrowser-build.json` is the accurate name. Recorded here as a specified
but separately-executed change.

**47 textual occurrences across 10 files**, in two tiers:

**Repo-side — doable in this checkout.** Exactly one functional line:

- `build.sh:156` — the `SITE_CONFIG=` assignment, the only place the path is defined.
  Every other hit is a comment or an operator-facing message (lines 143, 179, 182, 259,
  332, 374, 378, 387, 432, 436, 564); the three `python3` invocations pass `$SITE_CONFIG`
  rather than repeating the filename. Note line 332 writes the filename into generated
  C++ source, and the Python locals named `site_config_path` (`build.sh:446`, `:449`,
  `:450`) are worth renaming too even though they do not contain the string.
- `README.md` ×8 (lines 62, 148, 160, 181, 234, 266, 398, 410) — including the heading
  at line 181 and the intra-document anchor `#attestation-proxies-site-configjson` at
  line 160, which breaks silently if the heading changes.
- `scripts/gen-attest-key.sh` (19, 30, 37, 117) and `scripts/gen-proxy-tls.sh`
  (29, 39, 77, 143) — header docs and "next steps" output.
- `proxy/proxy.example.toml` (22, 37) — comments.

**Patch-side — blocked in this checkout.** Nine `+` lines across patches 003, 006,
012, 014, and 018 become comments in the Firefox tree. One of them,
`patches/006-attest-requests.patch:355`, is inside a runtime `MOZ_LOG` string that
operators read, so leaving it stale is user-visible. Per `docs/patch-workflow.md` and
`patches/README.md`, patch files are generated artifacts: changing these means editing
the corresponding commits on the `DenBrowser` branch of the fork at `../firefox` and
re-running `scripts/gen-patches.sh`. That fork is not present in this checkout, so the
procedure is recorded rather than performed.

**Migration footgun.** `build.sh` treats a missing config as "all features off" and
continues (`build.sh:374`, `build.sh:432`). A rename with no fallback would silently
disable clipboard policy, site filtering, attestation, and bookmarks on any tree that
still has the old filename — a security regression that produces no error. The rename
should read the new name, fall back to the old name with a deprecation warning, and
hard-error if both files exist.

---

## 11. Implementation phases

Ordered so each phase is verifiable on its own.

1. **Proxy `tpm.rs` + `[tpm]` config + unit tests.** Fully testable without hardware:
   mint TPM structures in software in the tests, exactly as
   `proxy/src/attest.rs:278-602` fakes the ECIES client today.
2. **Extend `test/attestation/test_roundtrip.py`** to mint TPM-bound sessions in
   software. This is the honest way to exercise the verifier end to end without a TPM,
   and it follows the existing pattern of reimplementing the client in Python.
3. **Build-config schema + `build.sh` Step 2.9 codegen.**
4. **Enrollment script** (`scripts/gen-tpm-enrollment.ps1`).
5. **Browser patch `021-tpm-attest.patch`**, authored on the fork branch per
   `docs/patch-workflow.md`.
6. **Config rename** (§10).

Phases 1–4 are verifiable in this repo. Phase 5 requires an ESR source tree and the
`../firefox` fork, neither of which is present here, and cannot be compile-checked
without them.

One thing to weigh before starting phase 1: the ECIES protocol is currently
implemented four times independently — C++ in `DenBrowserAttest.cpp`, Rust test
helpers in `attest.rs:335-390`, and Python in both `test_roundtrip.py` and
`denbrowser_stress.py` — with only prose comments keeping them in sync. Moving to a v3
plaintext means touching all four. That is a good moment to consider whether the
canonical plaintext format should be specified in one place that the others are
checked against.

---

## 12. Open questions

- **Session cache across proxy instances.** The nonce replay cache
  (`proxy/src/attest.rs:65`) is already per-process, so horizontal scaling already
  reopens replay across instances. The TPM session cache inherits the same limitation,
  with a milder failure mode: a cache miss costs a re-bind round trip rather than a
  security gap. Worth deciding together if the proxy is ever scaled out.
- **Session lifetime.** One hour is a starting point, not a considered answer. It
  bounds how long a session key extracted from browser memory stays useful.
- **Re-quote cadence.** This design quotes once per session. Periodically re-quoting
  mid-session would shrink the window in which a stolen session key is usable, at the
  cost of a latency spike whenever it happens.
- **`audit_only` exit criteria.** Decide up front what evidence retires it, so it does
  not become permanent.

# DENCAP Citrix endpoint prototype

This directory contains the endpoint half of a DenBrowser screenshot-protection
bridge. It uses a classic Citrix static virtual channel named `DENCAP` to carry
short-lived browser leases from the VDA to Citrix Workspace. While at least one
valid lease exists, the endpoint module applies and verifies
`WDA_EXCLUDEFROMCAPTURE` on the whole top-level ICA window. It restores the
window's prior display affinity after the final release or lease timeout.

This is not Citrix App Protection/Protected Apps and does not change how normal
desktop ICA connections are published.

Citrix App Protection can also be assigned to a full desktop Delivery Group,
not only individual published apps. Prefer that supported feature if always-on
desktop protection is acceptable. Citrix documents restrictions around
launching protected resources from an RDP session, and it does not provide this
browser-lifetime lease behavior, which is why this prototype remains useful for
the stated topology.

## The non-negotiable Phase-0 test

Windows permits `SetWindowDisplayAffinity` only for a top-level window owned by
the calling process. The client module therefore obtains the current ICA HWND
using Citrix's `WdGetICAWindowInfo` query and refuses to write unless all of
these are true:

```text
IsWindow(hwnd)
GetAncestor(hwnd, GA_ROOT) == hwnd
GetWindowThreadProcessId(hwnd) == GetCurrentProcessId()
GetWindowDisplayAffinity(hwnd) succeeds
```

Test this before building the rest of the deployment. Some Workspace/Desktop
Viewer versions put the top-level window in `CDViewer.exe` while a virtual
driver runs in `wfica32.exe`. If the PIDs differ, this design is a **no-go for
that Workspace build**. A service, elevated helper, browser process, or
cross-process injection-free implementation cannot work around the Windows
ownership rule.

`CitrixAdapter::Initialize` returns `kReady`, `kRetryLater`, or `kUnsupported`
plus the structured probe result for logging. A missing/not-yet-created HWND is
retryable; a real owner-PID mismatch is a permanent no-go for that module
instance.
The SDK-neutral `dencap_hwnd_probe` tool can inspect a known HWND, but the
authoritative probe is the one inside the Citrix module because only it has
the SDK's `PVD` context and `WdGetICAWindowInfo`.

## Runtime flow

```text
DenBrowser in VDA
  ACQUIRE(UUID, sequence, 30 s) ─┐
  RENEW(UUID, sequence, 30 s)  ──┼─ DENCAP static VC
  RELEASE(UUID, sequence)      ──┘
                                      │
                                      ▼
Citrix Workspace endpoint module
  query ICA HWND → prove ownership → save old affinity
  → SetWindowDisplayAffinity(0x11) → read back 0x11
  → restore saved affinity after the last lease
```

Patch 021 implements the browser side as follows:

1. In an ICA session, open `DENCAP` only in the primary browser process after
   Firefox startup/remoting has selected that process but before browser UI is
   created.
2. Generate a cryptographically random 128-bit lease ID.
3. Send `ACQUIRE` with sequence 1 and a 30-second request.
4. Send `RENEW` every 5 seconds, increasing the sequence each time.
5. On a missing response or transport failure, retry `ACQUIRE` for the same
   UUID with a fresh sequence after a 250 ms backoff while the last verified
   lease remains valid. Each packet read has a 1.5-second response deadline;
   delayed positive statuses remain usable via their original sequence/send
   time. A pure timeout keeps the packet-aligned channel, while a failed write
   or malformed short frame forces a reopen.
6. Maintain a separate watchdog which terminates DenBrowser two seconds before
   the conservative last-verified expiry, even if the channel worker stalls.
7. Send `RELEASE` on orderly final shutdown.
8. Refuse startup without an `ACQUIRE` status that reports `kOk`, affinity
   `0x11`, and the exact requested 30-second lease.
9. Terminate immediately on an explicit negative protection status. Exhausted
   transport retries terminate before the last verified endpoint lease could
   expire, rather than after a single missed acknowledgement.

The endpoint times out a crashed or disconnected browser without relying on a
channel-close notification. It supports 64 concurrent UUIDs so several
DenBrowser instances share one ICA-window affinity safely. The client rechecks
the window every second and also consumes Citrix's
`WdRegisterWindowChangeCallback` notification when the installed SDK supports
it. The callback itself only increments an atomic generation; the work is done
from `DriverPoll`.

The 30-second expiry is an availability/security tradeoff. A normal renewal
starts at second 5, leaving roughly 20 seconds for bounded recovery attempts
before the watchdog fails closed at least 2 seconds before the conservative
expiry. The browser calculates that deadline from the local request-send time,
not ACK receipt time or the endpoint's unrelated monotonic clock. Orderly
shutdown attempts an immediate write-only RELEASE. If the channel is already
unavailable or that write is lost, the endpoint retains protection for at most
the remaining lease, just as it does after a crash or disconnect. A suspended
VDA/browser whose watchdog cannot run can still outlive the lease. If that
frozen-session case is in scope, retain protection until ICA disconnect and
accept that abnormal browser exits may require an administrative reset.

The retry grace assumes that the same endpoint virtual-driver instance and
protected ICA HWND survive while status packets are delayed. It does not treat
a full Workspace reconnect as equivalent to packet loss: `DriverClose` calls
`CitrixAdapter::Shutdown`, which restores WDA, and a replacement window starts
unprotected until the new driver processes ACQUIRE. Pilot disconnect/reconnect
behavior for every supported Workspace build. If content can remain visible
during that transition, the production client shell must retain protection
fail-secure across reconnect/window replacement or provide an immediate
disconnect signal that makes the browser exit; browser-side lease retries
alone cannot prove a newly created client window was protected continuously.

Windows affinity has no ownership token. If an unrelated in-process component
writes the same numeric affinity while DENCAP is active, Windows provides no
way to distinguish that write from ours. The implementation avoids clobbering
clearly different later values and otherwise restores the exact value observed
before its first write.

See [protocol/README.md](protocol/README.md) for the wire contract.

## What must be deployed

There are three separate pieces:

1. **DenBrowser/VDA patch.** The browser opens the server side of static channel
   `DENCAP`, implements the lease loop above, and waits for status frames. The
   endpoint code here does not make an unmodified browser send leases. The
   patch loads the WFAPI runtime shipped with the VDA from Citrix's
   machine-wide HDX install location (with legacy VDA fallbacks); do not install
   the WFAPI SDK on production VDAs just for this feature.
2. **Citrix endpoint virtual-driver DLL.** Install a signed build on every
   Windows device that runs Citrix Workspace and is expected to enforce this
   policy. Build both x86 and x64 variants if both Workspace architectures are
   present. Citrix Workspace 2603 and later can be native x64, and an x86 DLL
   cannot load into that process.
3. **VDA virtual-channel policy.** Current VDAs enable the custom virtual
   channel allow list by default. Add the exact executable that opens the
   channel, for example:

   ```text
   DENCAP,C:\Program Files\DenBrowser\denbrowser.exe
   ```

   If a broker process owns the channel instead, allow-list that exact process.
   Roll the policy out through Citrix Studio/GPO and restart affected VDAs as
   required by the Citrix policy documentation.

No separate service is required or useful on the endpoint: a service would not
own the ICA window. No Citrix "protected application" publication is required.

Patch 021 checks Windows' session protocol first, then uses the VDA
`WFGetActiveProtocol` export when a Workstation VDA presents ICA as a console
session. Validate that export and the WFAPI install registry values during the
VDA pilot; they are part of the browser-side deployment gate.

## Build

Two separate things happen here, on very different cadences. Keeping them
apart is the main thing to understand before starting:

| | Produces | How often |
|---|---|---|
| **Build** (this section) | a signed `dencap_vd.dll` | once per Workspace generation × architecture |
| **Install** ([below](#client-registration-and-rollout)) | that DLL plus its module registration on an endpoint | once per endpoint, scriptable |

Only the build needs the Citrix SDK and a Visual Studio toolchain. Once a
signed DLL exists for a given Workspace generation it is a fixed artifact;
endpoints thereafter receive only the file and the registration.

Everything below runs from a Visual Studio Developer PowerShell, from the
repository root. Do the steps in order: **step 2 can rule out the whole
approach for a given Workspace build**, so run it before spending time on
steps 3 and 4.

### Step 1 — Build and test the SDK-neutral components

No Citrix SDK required.

```powershell
cmake -S citrix -B out\citrix -A x64
cmake --build out\citrix --config RelWithDebInfo
ctest --test-dir out\citrix -C RelWithDebInfo --output-on-failure
```

This builds:

- `dencap_core`: lease and WDA state machine;
- `dencap_lease_engine_tests`: dependency-free state-machine tests;
- `dencap_hwnd_probe`: a diagnostic ownership/read-back tool.

Use `-A Win32` instead of `-A x64` for the 32-bit variant.

### Step 2 — Run the ownership pre-check

The probe is read-only unless `--apply` is explicitly supplied:

```powershell
out\citrix\RelWithDebInfo\dencap_hwnd_probe.exe --hwnd 0x123456
out\citrix\RelWithDebInfo\dencap_hwnd_probe.exe --self-test
```

The standalone tool will correctly report `NO-GO` for a window owned by a
different process, while still attempting the read-only affinity query.
`--self-test` creates an owned hidden top-level window and performs an
apply/read-back/restore cycle.

This tool is an early indicator, not the verdict: the authoritative result is
the in-driver Phase-0 probe from step 4, because only it has the SDK's `PVD`
context. See [The non-negotiable Phase-0 test](#the-non-negotiable-phase-0-test)
for what a `NO-GO` means — for a real owner-PID mismatch, no packaging or
installer work can rescue that Workspace build.

### Step 3 — Build the adapter against the Citrix SDK

Download the official Virtual Channel SDK matching the deployed Citrix
Workspace release and architecture, unpack it anywhere, and point
`CITRIX_VCSDK_ROOT` at that directory. Do not mix headers or libraries from
another CWA generation.

```powershell
cmake -S citrix -B out\citrix-sdk -A x64 `
  -DDENCAP_BUILD_CITRIX_ADAPTER=ON `
  -DCITRIX_VCSDK_ROOT='C:\citrix\vcsdk-2402'
cmake --build out\citrix-sdk --config Release
```

Headers and import libraries are located under that root automatically, for
the architecture selected by `-A`. Configure prints what it resolved:

```text
-- DENCAP Citrix adapter:
--   SDK version:     unspecified (set CITRIX_VCSDK_VERSION to record it)
--   SDK root:        C:/citrix/vcsdk-2402
--   Target arch:     x64
--   Headers:         C:/citrix/vcsdk-2402/inc
--   Vdapi.lib:       C:/citrix/vcsdk-2402/lib/x64/Vdapi.lib
--   wdica30.lib:     C:/citrix/vcsdk-2402/lib/x64/wdica30.lib
--   Window callback: ON
```

Check that summary before building — it is the cheapest place to catch a
mismatched SDK or architecture. If a path is wrong, configure fails with the
list of directories it searched rather than a link error later.

Configuration variables:

| Variable | Default | Purpose |
|---|---|---|
| `CITRIX_VCSDK_ROOT` | — | Unpacked SDK root. Normally the only variable you set. |
| `CITRIX_VCSDK_VERSION` | empty | Free-text label for the SDK/Workspace generation, echoed in the summary so a build tree records which SDK produced it. |
| `CITRIX_VC_INCLUDE_DIR` | derived | Override when `vdapi.h`/`wdapi.h` are not under `<root>\inc` or `<root>\include`. |
| `CITRIX_VDAPI_LIBRARY` | derived | Override for a library layout the lookup does not recognise. |
| `CITRIX_WDICA_LIBRARY` | derived | Optional; only some SDK generations ship `wdica30.lib` separately. |
| `DENCAP_CITRIX_HAS_WINDOW_CALLBACK` | `ON` | Set `OFF` for an SDK that does not declare `WdRegisterWindowChangeCallback` or its information classes. The one-second polling fallback remains active. |

An override, when set, is used verbatim and still validated, so a typo fails at
configure time. Layout detection lives in
[`cmake/DenCapCitrixSdk.cmake`](cmake/DenCapCitrixSdk.cmake); add a candidate
directory there rather than carrying local overrides if a new SDK generation
needs one.

### Step 4 — Produce the DLL from the SDK sample driver

Step 3 produces a **static adapter library, not a standalone DLL**. Citrix's
`DriverOpen`, virtual-write hook, DLL exports, `.def` file, library set, and
configuration format vary across SDK releases, so the DLL shell comes from
Citrix's own sample rather than being guessed here.

Start with the official sample virtual-driver project shipped in the selected
SDK and add:

- `client/dencap_citrix_adapter.cpp`;
- `client/dencap_lease_engine.cpp`;
- `client/dencap_window_protector.cpp`;
- the corresponding headers and `protocol/dencap_protocol.h`.

Retain the sample's `Load` export and its exact `Vdapi.lib`/`wdica30.lib`
linkage. The adapter deliberately includes the real `vdapi.h` and `wdapi.h`
rather than reproducing SDK types. Citrix's public documentation currently
shows both three- and four-argument `VdCallWd` calls; the adapter selects at
compile time the signature declared by the actual header.

Wire the adapter into the sample's driver shell as described in
[Official-sample integration boundary](#official-sample-integration-boundary)
below, then sign the resulting DLL. Log the complete `OwnershipProbeResult`
from `CitrixAdapter::Initialize` on first run: that is the authoritative
Phase-0 verdict.

Repeat steps 3 and 4 per architecture if both x86 and x64 Workspace builds are
present. Citrix Workspace 2603 and later can be native x64, and an x86 DLL
cannot load into that process.

### Official-sample integration boundary

Wire the adapter into the selected sample's known-good driver shell:

```text
DriverOpen:
  open static channel "DENCAP" using kWfApiChannelName and the sample's
  OPENVIRTUALCHANNEL flow (the WFAPI form is space-padded to seven bytes)
  create CitrixAdapter from the PVD
  run Initialize and log the complete OwnershipProbeResult
  if the result is an absent/not-yet-created HWND, retry from DriverPoll
  if it is a different owner PID, mark the module unsupported

DataArrival / PVDWRITEPROCEDURE:
  copy pBuf before returning; do not perform WDA work in this callback
  enqueue the bytes in the sample driver's bounded input queue

DriverPoll:
  drain queued bytes through CitrixAdapter::OnChannelBytes
  make ResponseSink synchronously write or copy each exact 64-byte status
  frame into the sample's supported output queue before returning
  call CitrixAdapter::Poll even when no data arrived

DriverClose:
  call CitrixAdapter::Shutdown before destroying the driver context
  log/treat a false return as a serious callback-unregistration diagnostic
```

`Shutdown` is terminal. Destroy the adapter with the driver context after
`DriverClose`; do not attempt to reopen the same C++ object. If callback
unregistration fails, `Shutdown` preserves the registration handle and can be
called again. The callback does not dereference an adapter instance, but the
official driver shell must not silently unload a DLL while Citrix might still
retain its function pointer; record `last_callback_error()` and follow the
matching SDK's teardown behavior.

Citrix says the data-arrival callback must not block, and its buffer does not
remain valid after return. Keep the callback as a bounded copy only. Do not
invent a write function: use the exact output queue/write mechanism in the
matching SDK sample.

## Client registration and rollout

Citrix client-module registration is version- and architecture-specific.
Native x64 CWA uses native configuration paths; x86 CWA on x64 Windows uses
`WOW6432Node`. Citrix's own examples also differ in whitespace and registry
location, and editing `Module.ini` after Workspace installation does not
retroactively register a module.

For that reason this prototype does not contain a fabricated `.reg` file: it
cannot know which Workspace release you run. That is an argument against
shipping a *generic* one, not evidence that your fleet needs something
complicated. Capture the registration once against your pinned Workspace
build, and it becomes a fixed artifact like the DLL.

Do this once per Workspace generation, using the selected SDK sample's
installer/configuration entry as the source of truth:

1. Pick a unique module name such as `DENCAPVD` (the module name need not equal
   the `DENCAP` channel).
2. Install and register the unmodified SDK sample on a disposable endpoint.
3. Export and diff the actual CWA configuration-storage entries under
   `...\Citrix\ICA Client\Engine\Configuration\Advanced\Modules`.
4. Substitute the signed DENCAP DLL and module name in an MSI/WiX package.
5. Validate both per-machine/per-user behavior and x86/x64 registry views for
   the exact Workspace release.
6. Pilot Phase 0, lease expiry, Workspace reconnect, multi-monitor changes,
   Desktop Viewer mode changes, and browser crash recovery before broad
   deployment.

After that capture, the per-endpoint install is the DLL plus those recorded
configuration-storage values — one package, or a golden-image bake-in. Note
that copying the DLL alone does nothing: CWA reads its module list from
configuration storage seeded at Workspace install time, so a file drop with no
registration is never loaded.

The scripts in [deploy](deploy) copy and remove a validated binary using
`SupportsShouldProcess`; they intentionally do **not** edit the registry.

## RDP and security boundary

This client module protects the ICA window on the machine where its Citrix
Workspace process runs. It does not send a protection command "up" through an
outer RDP client, and WDA is not a DRM guarantee. In a nested
RDP-to-Windows-to-Citrix topology, test whether the supported Windows/RDP build
honors the inner window's WDA value in the encoded RDP desktop. If the outer
RDP client is the capture target and the inner WDA is not honored, the outer
hop needs its own supported enforcement; this Citrix channel cannot control a
window in another machine/process.

Also expect the protected Citrix window to be blank/omitted in legitimate
screen sharing and potentially in the interactive nested RDP stream. That is
the intended consequence of excluding the whole ICA connection window.

Useful upstream references:

- [Citrix Virtual Channel SDK architecture](https://developer-docs.citrix.com/en-us/citrix-workspace-app-for-windows/citrix-virtual-channel-sdk-for-citrix-workspace-app-for-windows/architecture.html)
- [Citrix Virtual Channel SDK programming reference](https://developer-docs.citrix.com/en-us/citrix-workspace-app-for-windows/citrix-virtual-channel-sdk-for-citrix-workspace-app-for-windows/programming-reference)
- [Citrix WFAPI programming guide](https://developer-docs.citrix.com/en-us/citrix-virtual-apps-desktops/citrix-winframe-api-sdk/programming-guide.html)
- [Citrix custom virtual-channel allow list](https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/policies/reference/ica-policy-settings/virtual-channel-allow-list-policy-settings.html)
- [Citrix native x64 transition FAQ](https://docs.citrix.com/en-us/citrix-workspace-app-for-windows/transition-to-64-bit-faq.html)
- [Citrix App Protection configuration](https://docs.citrix.com/en-us/citrix-workspace-app/app-protection/configure/configure-anti-keylogging-and-anti-screen-capture)
- [Microsoft SetWindowDisplayAffinity](https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-setwindowdisplayaffinity)

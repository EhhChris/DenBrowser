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
the calling process. The client module obtains the current ICA HWND using
Citrix's `WdGetICAWindowInfo` query, resolves its top-level ancestor with
`GetAncestor(..., GA_ROOT)`, and refuses to write unless all of these are true
for that resolved window:

```text
IsWindow(hwnd)
GetAncestor(hwnd, GA_ROOT) == hwnd
GetWindowThreadProcessId(hwnd) == GetCurrentProcessId()
GetWindowDisplayAffinity(hwnd) succeeds
```

Citrix can return an ICA child window. Resolving its root is necessary before
applying display affinity; the child window's owner PID does not establish who
owns the root. Ownership is checked on the resolved root itself. The adapter
does not follow popup ownership chains with `GA_ROOTOWNER`.

Test this first in the Demo Center. Some Workspace/Desktop
Viewer versions put the top-level window in `CDViewer.exe` or
`Citrix.DesktopViewer.App.exe` while a virtual driver runs in `wfica32.exe`.
If the PIDs differ, this design is a **no-go for that Workspace configuration**.
A service, elevated helper, browser process, or
cross-process injection-free implementation cannot work around the Windows
ownership rule.

The September 17 Workspace 2507.1 pilot passed this gate after disabling
**Show Desktop Viewer** on the StoreFront website, with no `ConnectionBar`
change. ACQUIRE and 30 successive renewals reported `status=0 affinity=0x11`.
This establishes ownership and read-back in that configuration; actual capture
and reconnect behavior still require the [live acceptance tests](DEMO.md).

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
9. Terminate when an explicit negative protection status is read. Exhausted
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

## Build the Workspace package

From ordinary PowerShell at the repository root:

```powershell
.\citrix\Build-DenCap.ps1
```

This locates Visual Studio C++/CMake/Ninja, builds and tests x86 and x64, and
writes a dated `build/dencap/DENCAP-demo-*.zip`. It includes the loadable
`dencap_vd.dll`, symbols, diagnostic probe, runtime installers, registration
scripts and hashes. Use `-Architecture x86` for x86 only, or `-SdkRoot` to
select another extracted SDK. The supplied `citrix/VCSDK` is sufficient and
unchanged. No additional Workspace SDK or endpoint service is required.

The installer selects the DLL matching the Workspace engine's architecture.
It checks the matching Visual C++ runtime and reports the bundled runtime
installer command when needed.

For direct CMake builds, enable `DENCAP_BUILD_CITRIX_DRIVER=ON`, which also
enables the adapter. The SDK uses `src/inc`, `src/inc/win32`, `src/shared/inc`,
and `bin/Release/Win32` or `bin/Release/x64` libraries `vdapi.lib` and
`clibdll.lib`. SDK consumers inherit 8-byte packing and x86 stdcall. The core
retains its ordinary calling convention. ARM64 selection exists but is not
validated or packaged here.

CTest includes lease-engine tests, a real SDK link check and a simulated
Citrix host fixture using real owned Windows windows. It verifies framing,
legacy/HPC transport, backpressure, isolation, delayed initialization,
protection, idle expiry, release and teardown. Live Workspace remains a
separate compatibility test.

## Driver integration and registration

`client/dencap_driver.cpp` provides the SDK lifecycle entry points and the
`Load` export at ordinal 1 via `client/dencap_driver.def`. Per-driver bounded
queues hold input bytes and complete STATUS frames. Data arrival only copies
input; periodic `DriverPoll` performs protection work and output, including
idle lease expiry. Output backpressure retains frames for retry; a positive
status held beyond its granted lease becomes negative. Input overflow stops
channel parsing so partial bytes cannot become new requests.

Polling retains detected protection failures until they can be queued for
the active leases. The browser sees them when it next reads the channel;
this is not an instantaneous signal. Normal browser shutdown releases before
Firefox's fast shutdown and gives an in-flight exchange a bounded grace period.
Crash/termination relies on lease expiry. A known VDA with missing/broken WFAPI
fails browser startup instead of silently treating an uncertain session as local.

`DriverClose` shuts down the adapter and restores affinity. Failed window
callback unregistration retains a module reference obtained at open, keeping
callback code loaded for the process lifetime. Logs go to
`%LOCALAPPDATA%\DenBrowser\Citrix\dencap-<PID>.log` (about 2 MiB maximum)
and `OutputDebugString`.

The installer supports per-machine Workspace. Close Citrix sessions/Workspace
and run elevated from the extracted package:

```powershell
.\deploy\Install-DenCapClient.ps1 -AllowUnsignedDevelopmentBuild
```

The unsigned switch is explicit for this local lab build; signed builds can
omit it. `-WhatIf` previews installation. `-WorkspacePath` supplies the ICA
engine directory when discovery is ambiguous. Registration appends DENCAP to
`VirtualDriverEx`, preserves other drivers, and records a manifest for removal.
The uninstaller removes only this installation's owned registration and DLL.

See [DEMO.md](DEMO.md) for the two-machine walkthrough and
[the verification record](../docs/citrix-demo-center.md) for acceptance gates.
The browser must be rebuilt with patch 021; older binaries cannot negotiate
this protection.

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

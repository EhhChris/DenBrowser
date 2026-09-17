# Citrix Demo Center verification

Updated 2026-09-17 on `codex/citrix-capture-protection`, using the supplied
VCSDK 2507.1. No additional Workspace SDK is required and the SDK is unchanged.

## Deployment

```text
Your computer -> RDP -> machine A (Workspace 2507.1)
                           -> StoreFront/ICA -> machine B (VDA + DenBrowser)
```

| Location | Install |
| --- | --- |
| Machine A | Packaged DENCAP DLL and Workspace registration |
| Machine B | Complete rebuilt DenBrowser and DENCAP channel policy |
| StoreFront | Show Desktop Viewer disabled on the demo website |
| Build machine | VCSDK, Visual Studio C++ tools; MozillaBuild for the browser |

The installer selects the DLL matching the Workspace engine architecture.
Neither demo machine needs the SDK or an extra service.
Workspace 2507.1 uses the x86 endpoint DLL even on x64 Windows. The package
includes an x64 DLL, but native x64 Workspace has not been live-validated here;
its SDK/runtime compatibility and capture behavior require a separate pilot.

## Completed implementation

The endpoint now has a loadable DLL with SDK lifecycle entry points, bounded
transport queues, legacy/HPC writes, periodic polling, ownership checks and
logs. Browser shutdown releases before Firefox's fast shutdown, and a known
VDA with missing/broken WFAPI cannot silently bypass enforcement. Packaging
includes both DLL architectures, symbols, runtime installers and registration
scripts that preserve unrelated virtual channels.

## Local verification

| Check | Result / scope |
| --- | --- |
| SDK DLL build, MSVC x86 and x64 | Passed |
| CTest, each architecture | 3/3: lease engine, real SDK link and driver fixture |
| Driver fixture | Simulated Citrix host; real owned HWNDs, child-to-root resolution, foreign-process root rejection and affinity APIs |
| Patch application and browser production source compilation | Passed with real Firefox generated headers |
| Browser worker fixture | Detection, startup rejection and shutdown using mocked WFAPI/WTS |
| Installer | 58 isolated checks passed on Windows PowerShell 5.1 and PowerShell 7; no live installation |
| Full browser build/link and `mach package` | Passed on local Firefox 153.1.0, including the final shutdown fix |
| Live Workspace loading and incoming ACQUIRE | Confirmed by September 17 endpoint logs |
| Live ICA root ownership and affinity read-back | Passed after disabling Show Desktop Viewer; 30 successful renewals over 150 seconds |
| Native x64 Workspace | DLL build and local fixtures passed; live compatibility test outstanding |
| Capture exclusion through outer RDP | Demo Center test required |

The driver fixture covers framing, backpressure, per-driver isolation,
initialization retries, protection, idle expiry, release and teardown.
These checks do not substitute for a real Citrix connection.

The September 17 pilot reached the endpoint over HPC, but Phase 0 rejected the
SDK's child HWND with `status=9 win32=5` because it differed from its top-level
root. The child's owner matched the driver process; the old log did not report
the root's owner. The adapter now resolves `GA_ROOT` before the existing strict
ownership/affinity checks. A root owned by a different process remains rejected.

The corrected package was then tested at 18:00 UTC. Its resolved `hwnd` and
`root` both reported `00090396`, but `owner=10888` differed from `current=6044`.
Process inspection confirmed that PID 10888 was `Citrix.DesktopViewer.App.exe`
and PID 6044 was `wfica32.exe`. The subsequent ACQUIRE reached the endpoint and
returned `status=9 win32=5 affinity=0x0`. This confirms a compatibility limit
with the tested Desktop Viewer configuration, rather than a missing SDK,
blocked virtual channel or stale DLL. In this case `win32=5` is emitted by the
plug-in's ownership pre-check; it does not indicate that elevation will help.
That Desktop Viewer configuration remains incompatible with this implementation.

The 18:24 UTC connection then passed Phase 0 with `owner=current=9052`,
`hwnd=root=000404EA`, `status=0 win32=0` and `callback=1`. At 18:25:24 UTC,
ACQUIRE returned `status=0 affinity=0x11`; sequences 2 through 31 renewed
successfully at approximately five-second intervals through 18:27:54 UTC.
The tester confirmed that only **Show Desktop Viewer** was disabled;
`ConnectionBar` was not changed. This verifies ownership, affinity read-back
and steady renewal in that session. Actual captures, release/crash behavior,
reconnects and the outer RDP stream still need the live acceptance tests below.

### Verified pilot configuration

On the StoreFront server, use an isolated Demo Center store website and record
its current setting. Open its **User interface settings** and clear **Show
Desktop Viewer**, then save. This is Citrix's documented setting for web
launches that open native Workspace. See [StoreFront 2507 user interface
settings](https://docs.citrix.com/en-us/storefront/2507-ltsr/stores/websites/client-interface-settings.html).

If Desktop Viewer remains, Citrix also documents `ConnectionBar=0` under the
existing `[Application]` section of
`C:\inetpub\wwwroot\Citrix\<StoreName>\App_Data\default.ica`, together with
`showDesktopViewer="false"` in the associated website's `web.config`. Back up
the files before editing; these settings apply to the selected store/website,
not just one user. Propagate changes if using a StoreFront server group. See
[Citrix's configuration instructions](https://support.citrix.com/external/article/585673/how-to-hide-desktop-viewer-toolbar.html)
and [Desktop Viewer still appearing](https://support.citrix.com/external/article/CTX202450/desktop-viewer-is-showing-up-even-though.html).

Save work, close the current Citrix connection and exit Workspace on machine A,
then launch again from that website using native Workspace. Inspect the new
`phase0` line and retry DenBrowser on machine B. A viable result requires
`phase0=0 status=0`, followed by ACQUIRE `status=0 affinity=0x11` and the capture
tests below. Disabling Show Desktop Viewer passed the ownership/affinity test
in the reported Workspace 2507.1 session. Repeat the check for other versions
and launch routes; Citrix's setting documentation does not guarantee the root
HWND owner. If ownership still differs, the current plug-in cannot protect
that window. Keep the verified setting as part of the demo configuration.

## Packaged artifacts

The packaged browser's `--version` invocation returns 127 by design: the
existing DenBrowser launcher only accepts its restricted public command-line
grammar. It is not a supported smoke-test command; no launch-policy exception
was added for this work.

Ready artifacts from this verification:

- Workspace: `build/dencap/DENCAP-demo-20260917-184823-124.zip` (supersedes the September 16 endpoint package)
- VDA: `build/dencap/DenBrowser-VDA-20260916-210831-281.zip`

The endpoint package's 20 files and the browser package's 55 application files
were checked against their SHA256 manifests. The packaged browser's `xul.dll`
matches the final build, and all three runtime configuration overlays match
the normal repository configuration.

## Build and install

Follow [the package walkthrough](../citrix/DEMO.md). The endpoint build is:

```powershell
.\citrix\Build-DenCap.ps1
```

Extract its dated ZIP on machine A, close Citrix sessions/Workspace, then run
in elevated PowerShell:

```powershell
.\deploy\Install-DenCapClient.ps1 -AllowUnsignedDevelopmentBuild
```

Build DenBrowser with patch 021 and `mach package`. The helper
`citrix/Package-DenBrowser.ps1` includes the required configuration overlays.
Install the entire application on machine B and allow its exact executable:

```text
DENCAP,C:\Program Files\DenBrowser\denbrowser.exe
```

See Citrix's [virtual-channel allow-list guide](https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/hdx-transport/virtual-channel-allow-list.html).

## Live acceptance gates

1. Inspect `%LOCALAPPDATA%\DenBrowser\Citrix\dencap-<PID>.log` on machine A.
   Phase 0 must prove a top-level ICA HWND owned by the module's process.
   ACQUIRE must report `status=0` and `affinity=0x11`.
2. A missing module or blocked channel must prevent DenBrowser startup in ICA.
   Confirm this on the actual Workstation VDA too.
3. Test captures on machine A and of the outer RDP window on your own computer.
   Normal interactive use must remain usable; blanking the RDP stream fails
   that goal.
4. Closing the last browser must promptly restore affinity. Two independent
   browser processes must retain protection until both close.
5. Crash the browser: protection should expire after the remaining lease,
   at most about 30 seconds plus endpoint polling delay.
6. Delay acknowledgements: short outages should recover; prolonged failure
   must terminate the browser before the conservative verified lease deadline.
7. Test reconnect, fullscreen/windowed transitions, monitor changes and a
   suspended VDA. Visible unprotected intervals fail continuous protection.

Windows requires a top-level HWND owned by the caller for
[SetWindowDisplayAffinity](https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-setwindowdisplayaffinity).
If Desktop Viewer owns that window in a different process, this design cannot
protect it through the Workspace DLL. A standalone probe cannot prove the
in-driver ownership condition.

The lease protects the whole ICA window on machine A; it cannot directly
control an outer RDP client's window on another computer. Window replacement
and a fully suspended VDA also cannot receive continuous protection guarantees
from a finite lease alone. These are live compatibility gates.

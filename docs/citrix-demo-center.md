# Citrix Demo Center verification

Updated 2026-09-16 on `codex/citrix-capture-protection`, using the supplied
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
| StoreFront | Existing desktop launch configuration |
| Build machine | VCSDK, Visual Studio C++ tools; MozillaBuild for the browser |

The installer selects the DLL matching the Workspace engine architecture.
Neither demo machine needs the SDK or an extra service.

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
| Driver fixture | Simulated Citrix host; real owned HWNDs and affinity APIs |
| Patch application and browser production source compilation | Passed with real Firefox generated headers |
| Browser worker fixture | Detection, startup rejection and shutdown using mocked WFAPI/WTS |
| Installer | 58 isolated checks passed on Windows PowerShell 5.1 and PowerShell 7; no live installation |
| Full browser build/link and `mach package` | Passed on local Firefox 153.1.0, including the final shutdown fix |
| Live Workspace loading and ICA window ownership | Demo Center test required |
| Capture exclusion through outer RDP | Demo Center test required |

The driver fixture covers framing, backpressure, per-driver isolation,
initialization retries, protection, idle expiry, release and teardown.
These checks do not substitute for a real Citrix connection.

The packaged browser's `--version` invocation returns 127 by design: the
existing DenBrowser launcher only accepts its restricted public command-line
grammar. It is not a supported smoke-test command; no launch-policy exception
was added for this work.

Ready artifacts from this verification:

- Workspace: `build/dencap/DENCAP-demo-20260916-210434-987.zip`
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

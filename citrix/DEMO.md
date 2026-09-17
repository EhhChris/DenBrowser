# DENCAP Demo Center package

This package contains the Workspace plug-in. DenBrowser is built separately
with the repository's normal Windows browser build.

For the intended setup:

```text
Your computer -> RDP -> machine A (Workspace 2507.1)
                           -> StoreFront/ICA -> machine B (VDA + DenBrowser)
```

## 1. Install the plug-in on machine A

Extract the entire ZIP. Close all Citrix sessions and exit Workspace/Desktop
Viewer. Open an elevated PowerShell in the extracted package directory and run:

```powershell
.\deploy\Install-DenCapClient.ps1 -AllowUnsignedDevelopmentBuild
```

The installer detects Workspace, selects the matching DLL and registers it
without replacing the other virtual drivers. The unsigned switch is needed for
this locally built lab package. Omit it when deploying a signed DLL.

DLL architecture must match the Workspace engine. Workspace 2507.1 uses the
x86 DLL on both x86 and x64 Windows; do not manually choose the x64 DLL just
because Windows is 64-bit. The package contains both architectures. The x64
DLL has passed local build/fixture checks only, not a live native x64
Workspace pilot.

If the installer reports an outdated/missing Visual C++ runtime, run the
matching bundled runtime installer it names, then repeat the install command.
For Workspace 2507.1 this will normally be:

```powershell
.\runtime\vc_redist.x86.exe /install /passive /norestart
```

If Workspace detection is ambiguous, pass `-WorkspacePath` with the directory
containing its ICA engine executable. Use `-WhatIf` to preview installation.
Reconnect the Citrix desktop after installation. No SDK needs to be installed
on either demo machine.

## 2. Install the rebuilt browser on machine B

Build the updated DenBrowser on your build machine in the MozillaBuild shell:

```bash
cd /c/proj/DenBrowser
bash build.sh --skip-fetch
cd src/firefox-153.1.0
./mach package
```

These paths use the source version already present during development. Keep
patch 021 enabled and use a normal build, not `--dev`. Then in PowerShell, pass
the newly produced browser ZIP to the packaging helper:

```powershell
.\citrix\Package-DenBrowser.ps1 -ApplicationArchive 'src\denbrowser-obj\dist\<new-browser-package>.zip'
```

This copies the required `mozilla.cfg`, `defaults/pref/autoconfig.js` and
`distribution/policies.json` from the finished build into the archive, so they
do not need to be assembled by hand. The resulting `DenBrowser-VDA-*.zip` is
under `build/dencap`.

Extract and install the complete application on machine B, for example at
`C:\Program Files\DenBrowser`. Do not copy just the EXE.

In the Citrix policy applying to machine B, add this virtual-channel allow-list
entry, adjusted to the actual browser path:

```text
DENCAP,C:\Program Files\DenBrowser\denbrowser.exe
```

Apply the policy and restart the affected VDA as required by your environment.
The browser uses the VDA's existing WFAPI runtime.

## 3. Disable Desktop Viewer for the demo website

On the StoreFront server, edit the website used for this demo. Under **User
interface settings**, clear **Show Desktop Viewer** and save. Use a scoped
demo website because this setting affects launches through that website.
See [Citrix's StoreFront setting](https://docs.citrix.com/en-us/storefront/2507-ltsr/stores/websites/client-interface-settings.html).

Save work, close the existing Citrix connection and exit Workspace on machine A,
then launch again from that website using native Workspace. In the September 17
Workspace 2507.1 pilot, this change alone gave the plug-in an owned top-level
window and successful `affinity=0x11` renewals. No `ConnectionBar` change was
needed. With Desktop Viewer enabled, the root belonged to
`Citrix.DesktopViewer.App.exe`, so the plug-in in `wfica32.exe` could not protect
it. Recheck the ownership and capture tests after Workspace upgrades or changes
to the launch route; disabling the setting is not a universal compatibility
guarantee.

## 4. Test the complete connection

Use a non-sensitive page first. Logs on machine A are under:

```text
%LOCALAPPDATA%\DenBrowser\Citrix\dencap-<Workspace-process-id>.log
```

The first gate is a successful `phase0`: the ICA window must be a top-level
window owned by the same Workspace process that loaded the plug-in. An
accepted ACQUIRE must report `status=0` and `affinity=0x11`. A different window
owner means this approach is unsupported for that Workspace configuration.

The plug-in resolves an SDK-returned child window to its top-level ancestor
before checking ownership. In packages built before the September 17 fix,
`phase0=2 status=9 win32=5` with different `hwnd` and `root` values could mean
the child was rejected before the root was examined. Upgrade the endpoint
package for that case; the browser package and VDA policy need no change.
The new Phase-0 log reports the resolved window and its actual owner.

To upgrade, close Citrix sessions and exit Workspace, then run the same
installation command from the newly extracted package. The installer updates
the previously recorded installation. Start a fresh Citrix connection afterward.
Success is `phase0=0 status=0`, followed by an ACQUIRE STATUS with
`status=0 affinity=0x11`. If the resolved root's `owner` differs from `current`,
the DLL still refuses protection because Windows requires the owning process.

Check all of the following:

- DenBrowser refuses startup when the plug-in/channel is unavailable.
- Opening it protects the ICA window; closing the last instance promptly
  restores the previous display affinity.
- A crashed browser releases protection after its remaining lease expires
  (up to about 30 seconds plus polling delay).
- A second independent browser process keeps protection active when the first
  closes. A second window in the same browser process is not a separate lease.
- Capture from machine A and from your own computer's outer RDP window excludes
  the protected content, while normal interactive use over RDP still works.
- Reconnects, fullscreen changes and monitor changes do not expose visible
  unprotected content. These remain required live compatibility tests.

Local automated tests do not prove capture behavior in Citrix or through RDP.
Protection applies to the whole ICA window. It may blank that window in the
interactive outer RDP stream; if so, this topology does not meet the usability
goal. Window replacement/reconnect and a fully suspended VDA cannot be given
a continuous-protection guarantee by a finite browser lease alone.

## Remove the plug-in

Close Citrix sessions and exit Workspace, then run in elevated PowerShell:

```powershell
.\deploy\Uninstall-DenCapClient.ps1
```

The uninstaller removes this package's registration and DLL using its install
manifest. It preserves unrelated Workspace modules. Reconnect afterward.

## Rebuild this package

From ordinary PowerShell in the DenBrowser repository:

```powershell
.\citrix\Build-DenCap.ps1
```

This locates Visual Studio C++ tools, builds/tests x86 and x64 with the supplied
VCSDK, and produces a dated ZIP under `build/dencap`. Use `-Architecture x86`
to build only the variant normally needed by Workspace 2507.1. The ZIP includes
symbols, a standalone HWND diagnostic probe, runtime installers, and hashes.

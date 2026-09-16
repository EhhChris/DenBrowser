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

## 3. Test the complete connection

Use a non-sensitive page first. Logs on machine A are under:

```text
%LOCALAPPDATA%\DenBrowser\Citrix\dencap-<Workspace-process-id>.log
```

The first gate is a successful `phase0`: the ICA window must be a top-level
window owned by the same Workspace process that loaded the plug-in. An
accepted ACQUIRE must report `status=0` and `affinity=0x11`. A different window
owner means this approach is unsupported for that Workspace configuration.

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

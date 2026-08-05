# Windows: from source to a signed MSI

How to take a DenBrowser build all the way to a code-signed `.msi` that can be
pushed to Windows 11 machines, on an **air-gapped build host**.

This document picks up where `build.sh` leaves off. It assumes you already have
a working build environment (MozillaBuild, MSVC Build Tools, Rust, sccache,
`~/.mozbuild` populated by a previous `./mach bootstrap`) and that `./build.sh`
already completes on this machine. Everything specific to `./mach package` and
later is spelled out here, including every tool that does **not** come with
Windows 11, MozillaBuild, or this repository.

Every upstream behaviour described here was read out of the Firefox ESR 153
source (`browser/installer/`, `toolkit/mozapps/installer/`,
`python/mozbuild/mozbuild/repackaging/`). Where something depends on *your*
machine rather than on upstream code, there is an explicit "verify with…"
command instead of an assertion.

---

## 0. What you are actually building

`mach package` and friends produce a chain of artifacts, each wrapping the
previous one:

```
 ./mach build
   └─ objdir/dist/bin/                     raw application (denbrowser.exe + libs)
                                           ← build.sh Step 6 drops the runtime
                                             config files in here

 ./mach package
   ├─ objdir/dist/denbrowser/              staged app dir — ONLY the files that
   │                                       browser/installer/package-manifest.in
   │                                       selects out of dist/bin
   ├─ objdir/dist/denbrowser-<ver>.en-US.win64.zip
   │                                       zip of that staged dir
   ├─ objdir/browser/installer/windows/instgen/setup.exe
   │                                       the NSIS installer program   [needs makensis]
   └─ objdir/dist/denbrowser-<ver>.en-US.win64.installer.exe
                                           7-Zip self-extractor = SFX stub +
                                           app files + setup.exe        [needs 7zz]

 ./mach repackage msi
   └─ …installer.msi                       MSI that embeds the installer .exe
                                           and runs it silently          [needs WiX]

 signtool
   └─ Authenticode signatures on the binaries, setup.exe, installer .exe and .msi
                                                                        [needs signtool + your cert]
```

Two properties of this chain matter for planning:

- **The MSI is a wrapper, not a real MSI.** Mozilla's `installer.wxs` contains no
  components and no files. It embeds the full installer `.exe` as a binary
  stream and runs it with `/S` plus a set of switches mapped from MSI
  properties. Its only feature is at `Level="0"`, deliberately, so **the MSI
  never registers itself as an installed product**. The thing that registers in
  Add/Remove Programs is the NSIS installer inside it. This has real consequences
  for deployment tooling — see [§8](#8-deploying).
- **Only what is in the staged dir gets installed.** The NSIS installer copies
  `core\*` (the staged dir, renamed) into the install directory. Anything not
  staged simply does not exist on the target machine. This is the trap described
  in [§4.1](#41-required-make-the-runtime-config-files-part-of-the-package).

---

## 1. Assumptions

| | |
|---|---|
| Build host | Windows 11 x64, air-gapped, MozillaBuild shell for all `mach` commands |
| Repo | this repository, checked out **with its `.git` directory** (Step 2.8 stamps the About dialog from the commit) |
| Source | Firefox ESR source tarball carried in physically; `./build.sh --tarball <path>` (implies `--skip-fetch`) |
| Target | `x86_64` / `win64`, `en-US` |
| Build mode | **production** — never pass `--dev` for anything you ship; it strips the DevTools locks and disables patches 008 and 017 |

Paths used in examples — substitute your own:

```
Repo               C:\den\DenBrowser              (MozillaBuild: /c/den/DenBrowser)
Firefox source     C:\den\DenBrowser\src\firefox-153.1.0
Object dir         C:\den\DenBrowser\src\denbrowser-obj
Carried-in tools   C:\den\tools\
```

The object dir location comes from `config/mozconfig`
(`MOZ_OBJDIR=@TOPSRCDIR@/../denbrowser-obj`), i.e. it sits next to the extracted
source, not inside it.

> **MSYS vs Windows paths.** `mach` runs a *native Windows* Python. Arguments
> that are paths must be Windows-style (`C:/den/tools/wix314/candle.exe`).
> MSYS-style `/c/den/...` will usually be translated for you, but not always —
> use `C:/...` for any `--candle`, `--light`, `--setupexe`, `-o` argument and you
> will never have to debug it.

---

## 2. External dependencies

Everything in this table is needed at `mach package` time or later. "Ships with"
answers the only question that matters on an air-gapped host: *do I have to
carry this in?*

| # | Dependency | Used by | Ships with | Carry in? |
|---|---|---|---|---|
| D1 | **NSIS** (`makensis.exe`) | `mach build` (uninstaller) and `mach package` (builds `setup.exe`) | MozillaBuild | Only if the check in §3 fails |
| D2 | **7-Zip CLI** (`7zz.exe`) | `mach package` (builds the SFX installer `.exe`) | MozillaBuild — but the **name** matters, see D2 | Only if the check in §3 fails |
| D3 | **UPX** (`upx.exe`) | `mach package`, optional — compresses the SFX stub | MozillaBuild | No (optional) |
| D4 | **WiX Toolset v3.14.x** (`candle.exe`, `light.exe`) | `mach repackage msi` | **Nothing — always carry in** | **Yes** (~10 MB) |
| D5 | **signtool.exe** | all signing steps | Windows SDK component, not in-box | **Yes** (~22 MB) — or use the PowerShell fallback, see D5b |
| D5b | *(alternative)* `Set-AuthenticodeSignature` | all signing steps | Windows PowerShell, in-box | No |
| D6 | **Your code-signing certificate** + private key, and the issuing CA chain | all signing steps | — | **Yes** |
| D7 | **RFC-3161 timestamp authority** | signing, optional but see §6.1 | — | Network-only — read §6.1 |
| D8 | **Firefox ESR source tarball** | `build.sh --tarball` | — | **Yes** (~600 MB) |

### D1 — NSIS (`makensis.exe`)

**What it does.** Compiles Mozilla's NSIS scripts
(`browser/installer/windows/nsis/installer.nsi` plus the branding defines from
`branding.nsi`) into `setup.exe`: the program that actually copies files into
`C:\Program Files\DenBrowser`, writes registry keys, creates shortcuts, and
registers the uninstaller. It is also used during `mach build` to produce
`dist/bin/uninstall/helper.exe`.

**Where it comes from.** MozillaBuild bundles NSIS, and configure finds it with:

```python
nsis = check_prog("MAKENSISU", ("makensis",), bootstrap="nsis/bin",
                  allow_missing=True, when=target_is_windows)
```

`allow_missing=True` means **configure succeeds without it** and only
`mach package` fails, late and confusingly. Two hard requirements are enforced at
configure time: version **≥ 3.0b1**, and on a Windows host the binary must be
**32-bit**.

**If it is missing.** Mozilla's own docs state that building with a version of
NSIS other than the one shipped in the latest supported MozillaBuild is
unsupported and likely to fail, so the right fix is to install/refresh
MozillaBuild rather than to source NSIS separately. If you must do it by hand,
the fallback is NSIS 3.x from `nsis.sourceforge.io` (32-bit `makensis.exe`)
placed on `PATH`, or the toolchain layout at `~/.mozbuild/nsis/bin/makensis.exe`.
Note that the NSIS *plugins* Firefox needs (`AccessControl.dll`, `UAC.dll`,
`ShellLink.dll`, …) and `nsisui.exe` are checked into the Firefox source tree
under `other-licenses/nsis/`, so they are already in your tarball — you never
need to source those separately.

### D2 — 7-Zip (`7zz.exe`)

**What it does.** `mach repackage installer` compresses the staged app dir plus
`setup.exe` into a `.7z` payload, then concatenates the SFX stub + tag file +
payload into the final self-extracting `installer.exe`.

**Naming gotcha.** Configure looks for the binary named **`7zz`**, not `7z`:

```python
check_prog("7Z", ("7zz",), allow_missing=True, bootstrap="7zz", when=target_is_windows)
```

If your MozillaBuild only provides `7z.exe`, the cheapest fix is to copy it (or
7-Zip's standalone `7za.exe`) to a directory on `PATH` under the name
`7zz.exe` — the command-line syntax used
(`a -r -t7z -mx -m0=BCJ2 -m1=LZMA:d25 …`) is the same. Mozilla builds theirs from
the official `ip7z/7zip` sources.

### D3 — UPX (optional)

Used only to shrink the self-extracting stub, and only when `UPX` is set in the
build config or `MOZ_AUTOMATION` is on. Skipping it costs a few hundred KB and
changes nothing functional. Ignore it unless you care about installer size.

### D4 — WiX Toolset v3.14.x — **the candle/light dependency**

**What `candle.exe` and `light.exe` do.** They are the two halves of the WiX v3
compiler chain:

- **`candle.exe`** is the *compiler*. It reads a WiX source file
  (`installer.wxs`, an XML description of an MSI) and emits an object file
  (`installer.wixobj`).
- **`light.exe`** is the *linker*. It takes the `.wixobj` and produces the actual
  `.msi` database, embedding the referenced binary (here: your installer `.exe`)
  into the MSI's `Binary` table.

`mach repackage msi` runs exactly these two commands, in this order
(from `python/mozbuild/mozbuild/repackaging/msi.py`):

```
candle -out <tmp>\installer.wixobj <tmp>\installer.wxs
light  -cultures:neutral -sw1076 -sw1079 -out <tmp>\installer.msi <tmp>\installer.wixobj
```

The two `-sw` flags suppress warnings LGHT1076/LGHT1079 about the very long
command strings in the custom actions — those warnings are expected and
harmless.

**Which version.** You need **WiX v3**, because `candle`/`light` are v3 tools.
WiX v4 and v5 replaced them with a single `wix.exe` and `mach repackage msi`
does not know how to drive it. Use the latest v3 (v3.14.1, released March 2024).

**Where to get it.** `https://github.com/wixtoolset/wix3/releases` — download
**`wix314-binaries.zip`** (not `wix314.exe`). The binaries zip is a plain
extract-and-go archive with no installer, no registry, no admin rights; ideal for
an air-gapped host. Unzip it to e.g. `C:\den\tools\wix314\`, which gives you
`C:\den\tools\wix314\candle.exe` and `light.exe`.

**Runtime prerequisite.** WiX v3.14 dropped .NET Framework 3.5 support and runs
on modern .NET Framework 4.x, which is in-box on Windows 11 — so no extra
download. (Deliberately *avoid* WiX 3.11: it needs .NET Framework 3.5, which is
an on-demand Windows feature that wants to fetch payload from Windows Update or
a mounted ISO — exactly the thing you cannot do air-gapped.) Verify on the build
host with the smoke test in §3.

### D5 — signtool.exe

**What it does.** Applies an Authenticode signature to a PE binary (`.exe`,
`.dll`) or an MSI, and can add an RFC-3161 countersignature (timestamp).

**Where to get it — two options.**

- **Windows SDK.** Install the *Windows SDK Signing Tools for Desktop Apps*
  component. For air-gapped use, run `winsdksetup.exe /layout C:\sdk-layout` on
  a connected machine, carry the layout folder in, and install from it offline.
  Heavy (multi-GB layout) but it is the "official" route and the one your
  security team will recognise.
- **NuGet package (recommended for air-gap).** `Microsoft.Windows.SDK.BuildTools`
  from nuget.org is a single ~22 MB `.nupkg`, which is just a zip. Rename to
  `.zip`, extract, and you get:

  ```
  bin\10.0.<build>.0\x64\signtool.exe        ← use this one
  bin\10.0.<build>.0\x86\signtool.exe
  bin\10.0.<build>.0\arm64\signtool.exe
  ```

  Copy the `x64` folder to `C:\den\tools\signtool\`. No install, no admin.

### D5b — PowerShell fallback (zero downloads)

`Set-AuthenticodeSignature` is part of Windows PowerShell and can sign `.exe`
and `.msi` files with a PFX or a certificate from the machine store:

```powershell
$cert = Get-PfxCertificate -FilePath C:\den\certs\denbrowser.pfx
Set-AuthenticodeSignature -FilePath C:\path\to\file.msi -Certificate $cert `
    -HashAlgorithm SHA256 -TimestampServer http://timestamp.digicert.com
```

Confirm it works on a throwaway copy of one artifact before committing to it as
your only signing path. `signtool` remains preferable when you need dual
signing, page hashes (`/ph`), or an HSM/token CSP — but if the only thing
standing between you and a signed MSI is "I can't get signtool onto the box",
this is a legitimate way through.

### D6 — Certificate material

You need, on the build host:

- the code-signing certificate **and its private key** — as a `.pfx`, or already
  present in the machine's certificate store, or on a token/HSM with its CSP/KSP
  driver installed;
- the **full issuing chain** (root + any intermediates) so verification succeeds
  locally.

You also need the chain deployed to **every target machine** — an internally
issued cert only validates where your CA is trusted (Trusted Root / Intermediate
CA stores, and Trusted Publishers if you enforce AppLocker or WDAC publisher
rules). Push it by GPO/Intune *before* the browser.

### D7 — Timestamping (read this before you sign)

An Authenticode signature without a timestamp becomes invalid the moment the
signing certificate expires — including on machines where the software was
already installed. A timestamp pins the signature to a moment when the cert was
valid, so it stays valid afterwards. Timestamping requires an HTTP call to a
Time Stamping Authority **at signing time**, which an air-gapped host cannot
make. Your options:

1. **Internal TSA.** If your PKI already offers an RFC-3161 timestamp endpoint
   reachable from the build network, use it: `/tr http://tsa.internal/... /td SHA256`.
   Best outcome.
2. **Sign on a connected, controlled host.** Move the *unsigned* artifacts out to
   a machine that can reach a public TSA, sign there, move them back. Keeps
   timestamps; moves the private key problem to that host.
3. **Sign without a timestamp.** Works, and is often acceptable for an internal
   fleet on a rebuild-and-redeploy cadence — but understand that every artifact
   you ship stops validating on the cert's expiry date. If you take this route,
   write the expiry date into your rebuild calendar.

Decide this *before* §6, because it changes the signtool command line.

### D8 — Firefox ESR source tarball

`scripts/fetch-esr.sh` downloads and verifies the tarball from Mozilla, which
your build host cannot do. Fetch
`firefox-<version>esr.source.tar.xz` on a connected machine, verify its checksum
against Mozilla's `SHA256SUMS` **there**, carry it in, and pass it with
`./build.sh --tarball <path>`.

---

## 3. Pre-flight checks on the build host

Run all of these in the **MozillaBuild shell** before you start. Each maps to a
dependency above; fix any failure now rather than 40 minutes into a build.

```bash
# D1 — NSIS: must print v3.x and be a 32-bit binary
makensis -version

# D2 — 7-Zip under the name the build system looks for
7zz --help | head -3

# D3 — optional
upx --version | head -1

# D4 — WiX (use YOUR path). Should print the WiX banner and usage.
"C:/den/tools/wix314/candle.exe" -?
"C:/den/tools/wix314/light.exe"  -?
```

```powershell
# D5 — signtool (PowerShell)
& "C:\den\tools\signtool\signtool.exe" /?

# D6 — is the signing cert visible, and does it have a private key?
Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert |
    Select-Object Subject, Thumbprint, NotAfter, HasPrivateKey
```

After a build has been configured at least once, confirm what configure actually
found — this is authoritative, unlike `PATH` guesswork:

```bash
grep -E "MAKENSISU|'7Z'|UPX" /c/den/DenBrowser/src/denbrowser-obj/config.status
```

An empty or absent `MAKENSISU` there means `mach package` **will** fail at the
installer step even though `mach build` succeeded, because configure is allowed
to not find NSIS (`allow_missing=True`). Another quick signal from a completed
build: if `src/denbrowser-obj/dist/bin/uninstall/helper.exe` exists, NSIS was
found.

---

## 4. One-time changes to this repository

These are changes you make **once**, before the first packaging run — ordinary
edits to this repo, not per-build work. §4.1 is not optional.

### 4.1 REQUIRED: make the runtime config files part of the package

**The problem.** `build.sh` Step 6 installs three files into
`objdir/dist/bin` *after* the build:

| File | Purpose |
|---|---|
| `mozilla.cfg` | the locked-pref layer (`config/mozilla.cfg`) |
| `defaults/pref/autoconfig.js` | tells Gecko to read `mozilla.cfg` |
| `distribution/policies.json` | **every enterprise policy** — `AIControls`, `SanitizeOnShutdown`, `Permissions`, `ExtensionSettings`, `HttpsOnlyMode`, `DisableTelemetry`, … |

`mach package` does not copy `dist/bin` wholesale. It copies exactly what
`browser/installer/package-manifest.in` lists — and that manifest lists **none of
these three**. `distribution/*` is in the manifest but sits behind
`#if defined(BUILT_BY_MOZILLA)`, which is not defined for our builds.

**The consequence if you skip this step.** The `.zip`, the installer `.exe` and
the `.msi` all install a browser with **no policies.json at all**. Patch 017
compiles the `mozilla.cfg` locks into `libxul`, so the pref layer survives — but
every policy in `config/policies.json` silently stops applying. The browser will
look fine and be measurably less locked down than the one you tested with
`./mach run`. Nothing warns you.

**The fix.** Add the three files to the package manifest, Windows-guarded. Edit
`src/firefox-<ver>/browser/installer/package-manifest.in` and add this block
right after the `; [Default Preferences]` section (around the
`@RESPATH@/defaults/pref/channel-prefs.js` entry):

```
; DenBrowser runtime configuration, installed into dist/bin by build.sh Step 6.
; Windows-only: on macOS build.sh writes these inside the .app bundle rather
; than into dist/bin, so the packager would not find them there.
#ifdef XP_WIN
@RESPATH@/mozilla.cfg
@RESPATH@/defaults/pref/autoconfig.js
@RESPATH@/distribution/policies.json
#endif
```

`@RESPATH@` resolves to `dist/bin` as the source and to the root of the installed
application as the destination, which is exactly where all three files belong.

Because the source tree is re-extracted or reverted on each `build.sh` run, make
this permanent by turning it into a patch file
(`patches/024-package-runtime-config.patch`) following `docs/patch-workflow.md`,
or by adding an injection step to `build.sh` alongside Steps 2.5–2.8. Until you
do, re-apply the edit after every `apply-patches.sh` run — and **always** run the
verification in Step 8 below.

> **Alternative, if you would rather not touch the manifest.** Let
> `mach package` run as-is, then copy the three files into
> `objdir/dist/denbrowser/`, rebuild the zip with
> `7zz a -tzip <new>.zip denbrowser` from `objdir/dist`, and feed that zip to
> `mach repackage installer` in Step 10. You are re-running `repackage installer`
> anyway if you sign `setup.exe`, so this costs one extra command — but it is a
> manual step that is easy to forget, which is why the manifest edit is
> preferred.

### 4.2 STRONGLY RECOMMENDED: two mozconfig flags

Add to `config/mozconfig`:

```
ac_add_options --with-redist                   # package the MSVC runtime DLLs
ac_add_options --disable-default-browser-agent # no Mozilla default-browser telemetry task
```

**`--with-redist`.** Firefox's own docs say to add this "if you intend to
distribute your build to others". It makes the packager include
`vcruntime140.dll` / `msvcp140.dll` (the `MOZ_PACKAGE_MSVC_DLLS` block of the
manifest) in the package. Without it, DenBrowser fails to start on any target
machine that does not already have the Visual C++ 2015–2022 redistributable
installed. If configure reports *"Could not find redistributable MSVCRT files"*,
your MSVC install is missing its Redist component.

**`--disable-default-browser-agent`.** On Windows browser builds this defaults to
**on** (`build/moz.configure/update-programs.configure`), which builds
`default-browser-agent.exe` and lets the installer register a scheduled task that
monitors the user's default-browser setting and reports to Mozilla. For a build
whose entire premise is that it does not phone home, compile it out. Belt and
braces: `config/policies.json` has no `DisableDefaultBrowserAgent` entry today —
consider adding one — and the MSI can be installed with
`REGISTER_DEFAULT_AGENT=false` (§8).

Changing mozconfig forces a full rebuild; do it before the build in Step 3, not
after.

### 4.3 OPTIONAL: finish the installer-side branding

`scripts/apply-patches.sh` copies Windows branding binaries into the source tree,
preferring `branding/denbrowser/` in this repo and falling back to Firefox
**Nightly** art for anything missing. The NSIS installer consumes exactly these
files (`BRANDING_FILES` in `browser/installer/windows/Makefile.in`):

```
branding.nsi                        ← created by patch 009 (DenBrowser strings)
firefox64.ico                       ← in this repo
wizHeader.bmp                       ← NOT in this repo → Nightly artwork
wizHeaderRTL.bmp                    ← NOT in this repo → Nightly artwork
wizWatermark.bmp                    ← NOT in this repo → Nightly artwork
stubinstaller/bgstub.jpg            ← NOT in this repo → Nightly artwork
stubinstaller/installing_page.css   ← NOT in this repo → Nightly
stubinstaller/profile_cleanup_page.css
```

The three `wiz*.bmp` files are the wizard header/watermark images shown when
someone runs the installer `.exe` **interactively**. Silent/MSI installs never
display them, so this is cosmetic — but if the `.exe` may be run by hand, drop
your own bitmaps into `branding/denbrowser/` and they will be picked up
automatically on the next `apply-patches.sh`.

Two other cosmetic leftovers, both hardcoded in Mozilla's NSIS scripts rather
than in branding: the Add/Remove Programs **Publisher** value is the literal
string `"Mozilla"` (`shared.nsh`), and registry keys are written under
`HKLM\SOFTWARE\Mozilla\DenBrowser\…`. Changing either means patching the NSIS
scripts; neither affects behaviour.

---

## 5. The ordered run

From here on, every step is per-build. Steps 1–5 are the build you already do;
they are listed so the sequence is complete and so the packaging-relevant side
effects are visible.

### Step 1 — Stage the source tarball

Copy `firefox-<ver>esr.source.tar.xz` from your transfer media to e.g.
`C:\den\transfer\`. Do not extract it by hand; `build.sh` does that and derives
the version from the archive.

### Step 2 — Commit the repo

`build.sh` Step 2.8 stamps the About dialog with `git rev-parse --short HEAD`,
adding `-dirty` if tracked files are modified. A shipped build should not say
`-dirty`, so commit (or stash) any local edits — including the manifest change
from §4.1 if you turned it into a patch file.

### Step 3 — Run the full build

MozillaBuild shell:

```bash
cd /c/den/DenBrowser
./build.sh --tarball /c/den/transfer/firefox-153.1.0esr.source.tar.xz --jobs 16
```

What this does, in order (see `build.sh`; `--tarball` implies `--skip-fetch` and
`--no-revert`):

| build.sh step | What it contributes | Survives `mach package`? |
|---|---|---|
| 1 | Extracts the tarball to `src/firefox-<ver>`, writes `src/.esr_version` | n/a |
| 2 | `apply-patches.sh`: applies `patches/*.patch`, then copies Windows branding binaries (icons, wizard bitmaps, VisualElements) into `browser/branding/denbrowser/` | Yes — compiled/packaged as part of the app and the installer |
| 2.5 | Generates the attestation proxy table into `DenBrowserAttest.cpp` from `config/site-config.json` | Yes — compiled into `libxul` |
| 2.6 | Injects clipboard/whitelist/blacklist arrays into the C++ sources | Yes — compiled in |
| 2.7 | Renders `bookmarks` into `denbrowser-newtab.html` | Yes — packaged in `omni.ja` |
| 2.8 | Stamps `DEN_BUILD_COMMIT` into `aboutDialog.js` | Yes — packaged in `omni.ja` |
| 2.9 | Copies `branding/DenBrowser.iconset` PNGs to `default16..256.png` | Yes — packaged in `omni.ja` |
| 3 | Installs `config/mozconfig` as `.mozconfig`, appends `-j<N>` | n/a |
| 4 | Writes `policies.json` to `browser/app/distribution/` (**staging only — never packaged from here**) | No |
| 5 | `./mach build` | — |
| 6 | Copies `mozilla.cfg`, `defaults/pref/autoconfig.js` and `distribution/policies.json` into `dist/bin` | **Only with the §4.1 manifest change** |

Expect 30–90 minutes on a cold sccache.

### Step 4 — Sanity-check the build output

```bash
OBJ=/c/den/DenBrowser/src/denbrowser-obj
ls -l "$OBJ/dist/bin/denbrowser.exe"
ls -l "$OBJ/dist/bin/mozilla.cfg" \
      "$OBJ/dist/bin/defaults/pref/autoconfig.js" \
      "$OBJ/dist/bin/distribution/policies.json"
ls -l "$OBJ/dist/bin/uninstall/helper.exe"   # present ⇒ NSIS was found
```

All five must exist. If the three config files are missing, `build.sh` Step 6
did not run — re-read its output.

### Step 5 — Smoke-test before packaging

```bash
cd /c/den/DenBrowser/src/firefox-153.1.0
./mach run
```

Confirm the branding, that `about:denbrowserhome` renders your shortcuts, and
that the lockdown behaves. It is much cheaper to catch a config mistake here than
after signing.

### Step 6 — (Optional, recommended) Sign the application binaries

Sign now, **before** packaging: the packager copies files, so signatures made
here ride into the zip, the installer and the MSI unchanged. Do this if your
environment enforces WDAC/AppLocker publisher rules, or if you want every shipped
PE to be attributable.

PowerShell, from the objdir:

```powershell
$sign = "C:\den\tools\signtool\signtool.exe"
$bin  = "C:\den\DenBrowser\src\denbrowser-obj\dist\bin"
$signArgs = @("sign","/fd","SHA256","/sha1","<YOUR-CERT-THUMBPRINT>","/d","DenBrowser")
# add: "/tr","http://tsa.internal/tsa","/td","SHA256"   ← only if you have a TSA (D7)

Get-ChildItem $bin -Recurse -Include *.exe,*.dll |
    ForEach-Object { & $sign @signArgs $_.FullName }
```

Skip this step entirely if you only need the outer artifacts signed; nothing
downstream depends on it.

### Step 7 — Package

```bash
cd /c/den/DenBrowser/src/firefox-153.1.0
./mach package
```

This single command does four things, in this order:

1. **Stages** `dist/bin` → `dist/denbrowser/`, selecting files per
   `package-manifest.in` and building `omni.ja`.
2. **Zips** the staged dir → `dist/denbrowser-<ver>.en-US.win64.zip`.
3. **Compiles the NSIS installer** → `browser/installer/windows/instgen/setup.exe`
   *(D1)*.
4. **Builds the self-extracting installer** by 7-zipping the staged files +
   `setup.exe` behind the SFX stub →
   `dist/denbrowser-<ver>.en-US.win64.installer.exe` *(D2, D3)*.

`<ver>` is `browser/config/version.txt` (e.g. `153.1.0`) — note that the *package*
name uses the plain version while the *display* version
(`browser/config/version_display.txt`, e.g. `153.1.0esr`) is what you pass to the
MSI step later.

### Step 8 — Verify the staged package (do not skip)

This is the check that catches the §4.1 trap:

```bash
OBJ=/c/den/DenBrowser/src/denbrowser-obj
ls -l "$OBJ/dist/denbrowser/mozilla.cfg" \
      "$OBJ/dist/denbrowser/defaults/pref/autoconfig.js" \
      "$OBJ/dist/denbrowser/distribution/policies.json"
```

If any of those three is missing, **stop**. Apply §4.1 (or its alternative) and
re-run `./mach package`. Everything past this point just wraps the staged
directory; a missing policies.json here is a missing policies.json on every
machine you deploy to.

Also confirm the runtime DLLs made it in, if you enabled `--with-redist`:

```bash
ls "$OBJ/dist/denbrowser/"*.dll | grep -Ei "vcruntime|msvcp"
```

---

## 6. Signing and the final artifacts

### 6.1 Choose your timestamp posture

Everything below shows the signing arguments as `$signArgs`. Set them once, per your
D7 decision:

```powershell
$sign = "C:\den\tools\signtool\signtool.exe"

# Pick ONE of the following two.

# (a) With an internal TSA — preferred:
$signArgs = @("sign","/fd","SHA256","/sha1","<THUMBPRINT>",
              "/tr","http://tsa.internal/tsa","/td","SHA256","/d","DenBrowser")

# (b) Air-gapped, no TSA — signature expires with the certificate:
$signArgs = @("sign","/fd","SHA256","/sha1","<THUMBPRINT>","/d","DenBrowser")
```

Use `/f C:\den\certs\denbrowser.pfx /p <password>` instead of `/sha1` if you are
signing from a PFX rather than the certificate store. For a token/HSM, add the
CSP/key-container arguments your provider documents (`/csp`, `/kc`).

### Step 9 — Sign the NSIS `setup.exe`

`setup.exe` is extracted to a temp directory and executed by the SFX at install
time. Signing it matters if WDAC/AppLocker inspects what actually runs.

```powershell
& $sign @signArgs "C:\den\DenBrowser\src\denbrowser-obj\browser\installer\windows\instgen\setup.exe"
```

If you skip this, skip Step 10 as well and just sign the installer `.exe` that
`mach package` already produced.

### Step 10 — Rebuild the installer around the signed `setup.exe`

`mach package` built the installer with the *unsigned* `setup.exe`, so rebuild
it. This is the same command `makensis.mk` runs internally:

```bash
SRC=/c/den/DenBrowser/src/firefox-153.1.0
OBJ=/c/den/DenBrowser/src/denbrowser-obj
VER=153.1.0

cd "$SRC"
./mach repackage installer \
  --package-name denbrowser \
  --package   "C:/den/DenBrowser/src/denbrowser-obj/dist/denbrowser-$VER.en-US.win64.zip" \
  --tag       "C:/den/DenBrowser/src/firefox-153.1.0/browser/installer/windows/app.tag" \
  --setupexe  "C:/den/DenBrowser/src/denbrowser-obj/browser/installer/windows/instgen/setup.exe" \
  --sfx-stub  other-licenses/7zstub/firefox/7zSD.Win32.sfx \
  -o          "C:/den/DenBrowser/src/denbrowser-obj/dist/denbrowser-$VER.en-US.win64.installer.exe"
```

Notes:

- `--package-name denbrowser` **must** match the top-level directory inside the
  zip (it is `MOZ_APP_NAME`); the tool renames it to `core` inside the SFX.
- `--sfx-stub` is resolved relative to the source root, so keep it relative.
  Use `7zSD.ARM64.sfx` instead if you ever target ARM64.
- `--tag` points at `app.tag`, the 7-Zip SFX configuration. It still says
  `Title="Mozilla Firefox"`, which is the title of the extraction progress window.
  To brand it, copy `app.tag`, change the `Title=` line, and point `--tag` at
  your copy.
- Requires D2 (`7zz`).

### Step 11 — Sign the installer `.exe`

```powershell
& $sign @signArgs "C:\den\DenBrowser\src\denbrowser-obj\dist\denbrowser-153.1.0.en-US.win64.installer.exe"
```

### Step 12 — Prepare a DenBrowser WiX source file

`mach repackage msi` fills these values into the `.wxs` before compiling — and
**hardcodes two of them to Mozilla's**
(`python/mozbuild/mozbuild/repackaging/msi.py`):

| WiX variable | Value used | Where it shows up |
|---|---|---|
| `Vendor` | **`"Mozilla"`** (hardcoded) | MSI `Manufacturer` |
| `BrandFullName` | **`"Mozilla Firefox"`** (hardcoded) | MSI `ProductName` |
| `Version` | your `--version` | in the product name |
| `AB_CD` | your `--locale` | in the product name |
| `Architecture` | from `--arch` | MSI `Platform` |
| `ExeSourcePath` | your `--setupexe` | the embedded binary |
| `EmbeddedVersionCode` | `--version` with `esr` stripped, padded to 4 parts | MSI `Version` |

Left alone, your MSI announces itself as *"Mozilla Firefox 153.1.0esr x64 en-US"*
by *"Mozilla"*, and carries Mozilla's `Product Id` and `UpgradeCode` GUIDs. Fix
it by using your own `.wxs` — the hardcoded `Vendor`/`BrandFullName` defines
become unused once your file stops referencing them.

```bash
cp /c/den/DenBrowser/src/firefox-153.1.0/browser/installer/windows/msi/installer.wxs \
   /c/den/DenBrowser/config/denbrowser.wxs
```

Then edit the `<Product …>` element (the first element inside `<Wix>`):

```xml
<!-- before -->
<Product Name="$(var.BrandFullName) $(var.Version) $(var.Architecture) $(var.AB_CD)"
         Manufacturer="$(var.Vendor)" Language="0" Codepage="1252"
         Version="$(var.EmbeddedVersionCode)" Id="1294a4c5-9977-480f-9497-c0ea1e630130"
         UpgradeCode="3118ab4c-b433-4fbb-b9fa-8f9ca4b5c103" >

<!-- after -->
<Product Name="DenBrowser $(var.Version) $(var.Architecture) $(var.AB_CD)"
         Manufacturer="Your Organization" Language="0" Codepage="1252"
         Version="$(var.EmbeddedVersionCode)" Id="PUT-A-NEW-GUID-HERE"
         UpgradeCode="PUT-ANOTHER-NEW-GUID-HERE" >
```

Generate the two GUIDs with `[guid]::NewGuid()` in PowerShell. Keep the
`UpgradeCode` **stable across all future DenBrowser releases**; mint a fresh
`Product Id` per release (or use `Id="*"`). Keep `$(var.Version)`,
`$(var.Architecture)`, `$(var.AB_CD)` and `$(var.EmbeddedVersionCode)` as-is —
those are the values `mach` passes in.

Check this file into the repo so it is versioned; re-diff it against upstream
`installer.wxs` on each ESR bump in case Mozilla changed the property set.

### Step 13 — Build the MSI

```bash
SRC=/c/den/DenBrowser/src/firefox-153.1.0
VER=153.1.0            # from browser/config/version.txt
DISP=153.1.0esr        # from browser/config/version_display.txt

cd "$SRC"
./mach repackage msi \
  --wsx      "C:/den/DenBrowser/config/denbrowser.wxs" \
  --version  "$DISP" \
  --locale   en-US \
  --arch     x86_64 \
  --setupexe "C:/den/DenBrowser/src/denbrowser-obj/dist/denbrowser-$VER.en-US.win64.installer.exe" \
  --candle   "C:/den/tools/wix314/candle.exe" \
  --light    "C:/den/tools/wix314/light.exe" \
  -o         "C:/den/DenBrowser/src/denbrowser-obj/dist/denbrowser-$VER.en-US.win64.installer.msi"
```

Points that bite people:

- **`--setupexe` here is the full self-extracting installer `.exe` from Step 10,
  not the bare NSIS `setup.exe`.** The flag name is misleading. The bare
  `setup.exe` carries no application files and would produce an MSI that installs
  nothing. (This matches how Mozilla's own release pipeline invokes it.)
- Sign the installer `.exe` **before** this step (Step 11) — it is embedded
  verbatim into the MSI, so signing it afterwards is impossible.
- `--arch` accepts `x86` or `x86_64` only, and maps to the MSI `Platform`
  (`x86`/`x64`).
- `--version` may not contain `a` or `b` if you want a real `EmbeddedVersionCode`;
  a trailing `esr` is stripped automatically, so `153.1.0esr` → `153.1.0.0`.
- Requires D4 (`candle.exe`, `light.exe`). Windows-only — `repackage msi` refuses
  to run anywhere else.

### Step 14 — Sign the MSI

```powershell
& $sign @signArgs "C:\den\DenBrowser\src\denbrowser-obj\dist\denbrowser-153.1.0.en-US.win64.installer.msi"
```

---

## 7. Verify before you ship

```powershell
$dist = "C:\den\DenBrowser\src\denbrowser-obj\dist"
$sign = "C:\den\tools\signtool\signtool.exe"

# /pa = verify under the Authenticode policy (what Windows itself applies).
# /v prints the chain, so you can confirm it terminates at YOUR CA.
& $sign verify /pa /v "$dist\denbrowser-153.1.0.en-US.win64.installer.msi"
& $sign verify /pa /v "$dist\denbrowser-153.1.0.en-US.win64.installer.exe"
```

If you signed without a timestamp (D7 option 3), the output will show no
countersignature — expected. Add `/tw` only if you *want* verification to fail on
an untimestamped signature.

Then install on a clean test VM (one that trusts your CA) and check the things
that packaging can silently break:

```powershell
# Start-Process -Wait, because msiexec returns immediately when launched directly.
Start-Process msiexec -Wait -ArgumentList @(
    "/i", "C:\den\denbrowser-153.1.0.en-US.win64.installer.msi",
    "/qn", "/l*v", "C:\den\msi-install.log")

$app = "C:\Program Files\DenBrowser"
Test-Path "$app\denbrowser.exe"
Test-Path "$app\mozilla.cfg"                      # ← §4.1
Test-Path "$app\defaults\pref\autoconfig.js"      # ← §4.1
Test-Path "$app\distribution\policies.json"       # ← §4.1, the important one
Get-ChildItem "$app\vcruntime140.dll","$app\msvcp140.dll" -ErrorAction SilentlyContinue
```

Launch it and confirm the **policy-driven** behaviours are on. Choose the checks
carefully: printing, downloads, clipboard and DevTools are enforced by compiled-in
patches and by patch 017's baked-in `lockPref`s, so they pass *even when
`policies.json` is missing* — they prove nothing about packaging. The behaviours
that come from `policies.json` alone are the real canaries:

| Check | Expected | Comes only from |
|---|---|---|
| Type `about:config` in the URL bar | blocked | `BlockAboutConfig` |
| `about:support`, `about:profiles`, `about:addons` | blocked | `BlockAbout*` |
| Load an `http://` URL | upgraded/blocked | `HttpsOnlyMode: force_enabled` |
| A page requests camera/microphone/location | denied without a prompt | `Permissions` |

If `about:config` opens, `policies.json` did not make it into the package — go
back to §4.1.

Finally, confirm the uninstall entry looks right:

```powershell
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Where-Object DisplayName -like 'DenBrowser*' |
    Select-Object DisplayName, Publisher, InstallLocation, UninstallString
```

`DisplayName` comes from `BrandFullNameInternal` in `branding.nsi` and will read
`DenBrowser (x64 en-US)`; `Publisher` is Mozilla's hardcoded string unless you
patched it (§4.3).

---

## 8. Deploying

**The MSI takes properties on the command line**, which it forwards to the NSIS
installer. From `installer.wxs`:

| Property | Default | Effect |
|---|---|---|
| `INSTALL_DIRECTORY_PATH` | — | full install path |
| `INSTALL_DIRECTORY_NAME` | — | directory name under Program Files |
| `TASKBAR_SHORTCUT` | `true` | pin to taskbar |
| `DESKTOP_SHORTCUT` | `true` | desktop shortcut |
| `START_MENU_SHORTCUT` | `true` | Start-menu shortcut |
| `PRIVATE_BROWSING_SHORTCUT` | `true` | separate private-browsing shortcut — pointless in this permanent-PBM build; set `false` |
| `REGISTER_DEFAULT_AGENT` | `true` | registers the default-browser scheduled task — set `false` (see §4.2) |
| `INSTALL_MAINTENANCE_SERVICE` | `true` | no-op unless built with the maintenance service |
| `REMOVE_DISTRIBUTION_DIR` | `true` | removes a **pre-existing** install's `distribution\` before copying files; the new one from your package is written afterwards, so leaving this at the default does not endanger your `policies.json` |
| `PREVENT_REBOOT_REQUIRED` | `false` | avoid queuing a reboot |
| `EXTRACT_DIR` | — | extract only, do not install |

A typical silent deployment (PowerShell; the backtick is the line continuation):

```powershell
msiexec /i denbrowser-153.1.0.en-US.win64.installer.msi /qn `
  INSTALL_DIRECTORY_PATH="C:\Program Files\DenBrowser" `
  DESKTOP_SHORTCUT=false PRIVATE_BROWSING_SHORTCUT=false `
  REGISTER_DEFAULT_AGENT=false PREVENT_REBOOT_REQUIRED=true
```

**Detection rules must not use the MSI product code.** The wrapper's only feature
is `Level="0"`, so Windows Installer never records the MSI as an installed
product. Detect the *application* instead — file version of
`C:\Program Files\DenBrowser\denbrowser.exe`, or the Uninstall registry key
found in §7. This is the single most common surprise when importing these MSIs
into Intune or SCCM.

**Uninstall** goes through the NSIS uninstaller
(`"C:\Program Files\DenBrowser\uninstall\helper.exe" /S`), not `msiexec /x`.

**Updates:** this build is compiled with `--disable-updater` and
`DisableAppUpdate`, so there is no in-product update path by design. Upgrading
means deploying a new MSI over the old install.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `mach package` fails compiling `installer.nsi`, or `MAKENSISU` is empty in `config.status` | NSIS not found at configure time | D1; then re-run configure (`./mach configure`) — a stale `config.status` keeps the missing value |
| A 7-Zip / `7Z` error while building the installer `.exe` | configure never found a binary named `7zz` | D2, then `./mach configure` |
| Packaging aborts with a missing-file error naming `mozilla.cfg` / `autoconfig.js` / `policies.json` | §4.1 manifest lines added, but `build.sh` Step 6 did not run (packaging fatal-warnings are on) | run a full `./build.sh` before packaging, or drop the manifest lines |
| Installed browser behaves *less* locked down than `./mach run` | `policies.json` was not packaged | §4.1 + Step 8 verification |
| `candle.exe` / `light.exe` not found | wrong path, or MSYS-style path passed to a native tool | pass `C:/…` paths |
| `light.exe` warnings LGHT1076 / LGHT1079 | expected — the custom-action command strings are long | already suppressed by `-sw1076 -sw1079`; ignore |
| MSI shows "Mozilla Firefox" / "Mozilla" in ARP or in Intune | `msi.py` hardcodes `Vendor`/`BrandFullName` | Step 12 — use your own `.wxs` |
| MSI installs but nothing appears | `--setupexe` was the bare `instgen\setup.exe` | pass the full installer `.exe` (Step 13) |
| `signtool verify` fails on the test machine | CA chain not trusted there | deploy root/intermediate before the app (D6) |
| Browser will not start on a clean machine (missing `vcruntime140.dll`) | no `--with-redist` | §4.2 |
| About dialog shows `-dirty` | uncommitted tracked changes at build time | Step 2 |

---

## Appendix — command cheat-sheet

MozillaBuild shell. `SRC`/`OBJ` are MSYS paths, `SRC_W`/`OBJ_W` the same
directories in `C:/…` form, `VER` = `browser/config/version.txt`, `DISP` =
`browser/config/version_display.txt`:

```bash
./build.sh --tarball /c/den/transfer/firefox-153.1.0esr.source.tar.xz --jobs 16
cd "$SRC" && ./mach package
ls "$OBJ/dist/denbrowser/mozilla.cfg" "$OBJ/dist/denbrowser/distribution/policies.json"
# → sign instgen/setup.exe (PowerShell)
./mach repackage installer --package-name denbrowser \
  --package "$OBJ_W/dist/denbrowser-$VER.en-US.win64.zip" \
  --tag "$SRC_W/browser/installer/windows/app.tag" \
  --setupexe "$OBJ_W/browser/installer/windows/instgen/setup.exe" \
  --sfx-stub other-licenses/7zstub/firefox/7zSD.Win32.sfx \
  -o "$OBJ_W/dist/denbrowser-$VER.en-US.win64.installer.exe"
# → sign the installer .exe (PowerShell)
./mach repackage msi --wsx C:/den/DenBrowser/config/denbrowser.wxs \
  --version "$DISP" --locale en-US --arch x86_64 \
  --setupexe "$OBJ_W/dist/denbrowser-$VER.en-US.win64.installer.exe" \
  --candle C:/den/tools/wix314/candle.exe --light C:/den/tools/wix314/light.exe \
  -o "$OBJ_W/dist/denbrowser-$VER.en-US.win64.installer.msi"
# → sign the .msi (PowerShell)
```

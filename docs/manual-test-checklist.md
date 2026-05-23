# DenBrowser Manual Test Checklist

A non-technical walkthrough for verifying every data-exfiltration protection
DenBrowser ships. Work top to bottom and check each box. Each test tells you
**what to do** and **what you should see** if the protection is working.

Before you start:

- [ ] DenBrowser is installed and launched from the normal Start menu / Dock
      shortcut (not from a terminal).
- [ ] Have a second, normal browser open on the same machine for comparison
      if you want to confirm "what a non-locked-down browser would do."
- [ ] You know one site that is on your deployment's allow-list — referred
      to below as **`<allowed site>`** (e.g. the corporate web app DenBrowser
      was deployed to access).
- [ ] You know one site that is *not* on the allow-list — referred to as
      **`<blocked site>`** (any public site like a news homepage works).

Throughout the checklist, "the page" means whatever site is currently loaded
in DenBrowser. Tests under "Block expected" mean **you want the action to
fail** — a failed attempt is a successful test.

---

## 1. Screenshots & screen capture (patch 001)

- [ ] **Built-in screenshot tool is gone.** Right-click anywhere on a page.
      You should *not* see a "Take Screenshot" menu item. Open the page
      menu (≡ in the top-right) → "More Tools". No screenshot entry.
- [ ] **Keyboard shortcut does nothing.** Press `Ctrl+Shift+S`
      (Windows/Linux) or `Cmd+Shift+S` (Mac) while on a page. Nothing
      should appear — no overlay, no selection rectangle.
- [ ] **OS screenshot of the window is blank.** While DenBrowser is the
      visible window:
   - **Windows:** Press `Win+Shift+S`, draw a box around the DenBrowser
     window. The captured image should be solid black (or empty) where
     DenBrowser was.
   - **Mac:** Press `Cmd+Shift+4`, click the DenBrowser window. The
     resulting file in `~/Desktop` should be black/empty for the
     DenBrowser area.
- [ ] **Screen-recording software shows black.** Open the OS's built-in
      screen recorder (Game Bar on Windows, QuickTime on Mac) and record
      a few seconds with DenBrowser in front. Play it back — DenBrowser's
      window area should be black.

## 2. Screen / window / tab sharing (patch 002)

- [ ] **`getDisplayMedia` is rejected.** Navigate to any video-call site
      that supports screen sharing (Google Meet, Whereby, Jitsi, etc., if
      on the allow-list — otherwise use whatever your deployment permits
      that has a "share screen" button). Click "Share screen" / "Present".
      The button should fail immediately with an error like "Permission
      denied" or "Screen sharing not available" — *no* picker dialog
      should appear listing your screens/windows.

## 3. Clipboard & drag-and-drop (patch 003)

For a site **not** in the `clipboard_sites` list (most pages):

- [ ] **Copy from a page does nothing.** Select some text on the page and
      press `Ctrl+C` / `Cmd+C`. Open Notepad / TextEdit and paste. Nothing
      should appear (or the previous clipboard contents remain).
- [ ] **Right-click "Copy" does nothing.** Select text, right-click,
      choose Copy. Paste into Notepad — empty / unchanged.
- [ ] **Paste into the page does nothing.** Copy text from Notepad. Click
      into any text field on the page. Press `Ctrl+V` / `Cmd+V`. Nothing
      pastes.
- [ ] **Drag text out of the page fails.** Try to click-and-drag selected
      text from the page into Notepad. The drop should be rejected (no
      text arrives in Notepad).
- [ ] **Drag a file into the page fails.** Drag a file from the desktop
      onto the page. The page should not accept it (no upload dialog,
      no file appearing in any drop zone).

For a site that **is** in the `clipboard_sites` list (ask your admin which
one is configured, if any):

- [ ] Copy/paste **within that site's tab** works normally.
- [ ] Copying from that site and pasting into Notepad still **fails** —
      the clipboard never leaves the browser.

## 4. Downloads, Save As, wallpaper (patch 004)

- [ ] **Save As is blocked.** Press `Ctrl+S` / `Cmd+S` on any page.
      Nothing should be saved. Check your Downloads folder — no new file.
- [ ] **Right-click "Save Image" fails.** Right-click any image on the
      page. Either the menu item is missing, or clicking it produces no
      file in Downloads.
- [ ] **Right-click "Save Link As" fails.** Right-click any link, choose
      Save Link As. No file is saved.
- [ ] **Downloading via a direct link fails.** Click a link that would
      normally trigger a download (e.g. a `.pdf` or `.zip` link). The
      download should be cancelled or rejected — no file in Downloads.
- [ ] **Set As Desktop Background fails.** Right-click an image and
      choose "Set As Desktop Background" if the option is present. Your
      wallpaper should not change. (On many builds this menu item is
      removed entirely — that also counts as a pass.)

## 5. Printing (patch 005)

- [ ] **Print dialog never appears.** Press `Ctrl+P` / `Cmd+P` on any
      page. Nothing should open — no print preview, no printer picker.
- [ ] **Page menu has no Print.** Open the ≡ menu in the top-right. The
      Print entry should be missing or do nothing when clicked.
- [ ] **Print-to-PDF is also blocked.** Even if you can reach a print
      dialog through some path, the "Save as PDF" option should not
      produce a file.

## 6. Developer tools (patch 008)

- [ ] **F12 does nothing.** Press `F12` on any page. No DevTools panel
      should appear.
- [ ] **Keyboard shortcut does nothing.** Press `Ctrl+Shift+I` /
      `Cmd+Opt+I`. No DevTools.
- [ ] **Right-click "Inspect" is gone or inert.** Right-click anywhere on
      a page. Either there is no "Inspect" / "Inspect Element" entry, or
      clicking it does nothing.
- [ ] **`about:devtools` is blocked.** Type `about:devtools` into the
      address bar and press Enter. You should get a "blocked" / error
      page, not a working tools page.
- [ ] **`about:config` is blocked.** Type `about:config` and press Enter.
      Should be blocked.
- [ ] **`about:support` is blocked.** Same — should be blocked.

## 7. Telemetry & diagnostics (patch 010)

- [ ] **`about:telemetry` is blocked or empty.** Type `about:telemetry`
      in the address bar. Either it's blocked, or the page loads but
      shows no pending pings and "Upload Enabled: false".
- [ ] **No crash reporter prompt.** If you ever see DenBrowser crash, no
      "send report" dialog should appear afterward.

## 8. Extensions / add-ons (patch 011)

- [ ] **`about:addons` is blocked.** Type `about:addons` in the address
      bar. Should be blocked.
- [ ] **`addons.mozilla.org` install fails.** Navigate to
      `https://addons.mozilla.org` (if reachable). On any extension page,
      click "Add to Firefox". You should get an install error or the
      button should do nothing — no extension should appear installed.
- [ ] **Dragging a `.xpi` file onto DenBrowser fails.** Download (in a
      different browser) any small `.xpi` file and drag it onto a
      DenBrowser window. The install prompt should not succeed.

## 9. Sync / Firefox Accounts (patch 013)

- [ ] **No "Sign in to Sync" in the menu.** Open the ≡ menu in the
      top-right. There should be no "Sign in", "Sync", or account-avatar
      entry.
- [ ] **Settings has no Sync pane.** Open Settings / Preferences. In the
      left-side category list there should be **no** "Sync" entry.
- [ ] **No Synced-Tabs sidebar.** Press `Ctrl+B` to open the bookmarks
      sidebar, then check the sidebar dropdown. There should be no
      "Synced Tabs" option.

## 10. Site allow-list / block-list (patch 014)

- [ ] **Allowed site loads normally.** Type `<allowed site>` in the
      address bar. The page loads as expected.
- [ ] **Blocked site shows the DenBrowser block page.** Type
      `<blocked site>` in the address bar. You should see a DenBrowser
      branded "this site is not permitted" page — *not* the actual
      content, *not* a generic Firefox error.
- [ ] **Link to a blocked site is also blocked.** From an allowed page,
      click any link that goes to a different domain not on the
      allow-list. You should land on the block page, not the destination.
- [ ] **Subdomains of allowed sites work.** If `example.com` is allowed,
      `www.example.com` and `app.example.com` should also load.

## 11. Window title leak (patch 016)

- [ ] **Taskbar / Dock shows only "DenBrowser".** Load any page with a
      distinctive `<title>` (e.g. a search results page that puts your
      query in the title). Hover the DenBrowser icon in the Windows
      taskbar / look at the Mac Dock tooltip / look at the Linux
      window-list. It should read **"DenBrowser"** — never the page
      title.
- [ ] **Alt-Tab / Mission Control shows only "DenBrowser".** Press
      `Alt+Tab` (Windows/Linux) or `Cmd+Tab` + Mission Control (Mac).
      The DenBrowser thumbnail/label should say "DenBrowser", not the
      page title.

## 12. Cookies, history, passwords, on-disk state

These are enforced by policy + locked prefs rather than a single patch,
but they're easy to user-verify.

- [ ] **History is empty.** Press `Ctrl+H` / `Cmd+Y`. The history sidebar
      should be empty after restart, even if you browsed several sites
      in the current session.
- [ ] **No "Save password" prompt.** Log into any site that asks for a
      password. DenBrowser should **not** offer to save the password.
- [ ] **No autofill suggestions.** Click into a form field that you've
      typed into before. No previously-typed values should drop down as
      suggestions.
- [ ] **Closing and reopening starts fresh.** Close DenBrowser entirely.
      Reopen it. You should land on the configured start page, with no
      previous tabs restored and no cookies preserved (you should be
      logged out of whatever you were logged into).

## 13. Permission-API blocks (camera, mic, location, notifications)

- [ ] **Camera request is denied silently.** Visit any site with a
      "test your camera" feature (if on the allow-list). No permission
      prompt should appear; the camera should simply not turn on.
- [ ] **Microphone request is denied silently.** Same for microphone.
- [ ] **Location request is denied silently.** Visit any site that asks
      for your location ("find stores near me"). No prompt; no location
      provided.
- [ ] **Notification request is denied silently.** Visit any site that
      asks to send notifications. No "Allow notifications?" prompt
      should appear.

---

## How to report a failure

If any box **doesn't behave as described** — i.e., the protection failed —
record:

1. Which checklist item.
2. The exact site / URL you were on.
3. The platform (Windows / Mac / Linux + version).
4. The DenBrowser version (≡ menu → About DenBrowser, or ask your admin).
5. A short description of what happened instead.

Send that to your DenBrowser deployment admin. **Do not** attempt to
screenshot or screen-record the failure with DenBrowser visible — those
protections are part of what's being tested.

---

# Appendix — Items requiring technical verification

The following protections cannot reasonably be confirmed by a non-technical
user from inside the browser. They require an admin / engineer with shell
access to the proxy, the build, or the running process. Hand this section
to whoever owns the deployment.

## A1. Per-request attestation headers (patch 006)

**What it does:** Every outbound HTTP request from DenBrowser is signed
with an ECIES header bound to nonce + timestamp + host + method + path +
body hash. The Pingora proxy verifies the signature and rejects unsigned
or replayed requests.

**How to verify:**

- [ ] On the proxy host, tail the Pingora logs while a user browses.
      Every request from DenBrowser should log a successful attestation
      verification.
- [ ] Try issuing a request to the proxy from `curl` on the same network.
      It should be rejected (no valid attestation header).
- [ ] Replay a captured DenBrowser request (same nonce/ts) within the
      replay-cache window. It should be rejected as a replay.

## A2. Proxy TLS SPKI pinning (patch 012)

**What it does:** The expected SHA-256 of the proxy's TLS leaf
certificate's SubjectPublicKeyInfo is compiled into the DenBrowser
binary. Any other cert — even one that chains to a trusted CA — aborts
the handshake before application data flows.

**How to verify:**

- [ ] Stand up a MITM proxy (mitmproxy, Burp) between DenBrowser and the
      real proxy, with a cert that chains to a CA installed in the OS
      trust store. DenBrowser should **fail to connect** — not show a
      cert warning, just refuse outright.
- [ ] Rotate the proxy's TLS cert without rebuilding DenBrowser.
      DenBrowser should fail to connect until rebuilt with the new pin.

## A3. CLI flag and env-var stripping (patch 015)

**What it does:** Security-sensitive command-line flags (`--profile`,
`--marionette`, `--remote-debugging-port`, `--screenshot`, `--headless`,
`--safe-mode`, `--jsdebugger`, etc.) and environment variables
(`MOZ_LOG`, `SSLKEYLOGFILE`, `MOZ_DISABLE_*_SANDBOX`,
`MOZ_PROFILER_STARTUP*`, `MOZ_CRASHREPORTER*`, etc.) are stripped from
the process before any Firefox code reads them.

**How to verify:**

- [ ] Launch DenBrowser from a terminal with
      `--remote-debugging-port=9222`. Then try to connect a Chrome
      DevTools client to `localhost:9222`. The connection should fail
      (no debugger listener was ever opened).
- [ ] Launch with `--profile /tmp/evil`. The browser should ignore the
      flag and use its normal profile location.
- [ ] Launch with `SSLKEYLOGFILE=/tmp/keys.log` set in the environment.
      Browse an HTTPS site. The file should not be created / should
      remain empty.
- [ ] Launch with `--headless`. Browser should still open a normal
      visible window.
- [ ] Regenerate patch 015 for each new ESR via
      `scripts/gen-015-patch.sh` and re-run these tests, since the
      argument-parsing surface changes between ESR versions.

## A4. Build-time hardening flags

**What it does:** `config/mozconfig` sets `--disable-crashreporter`,
`--disable-updater`, `--disable-tests`, `--disable-parental-controls`,
`--disable-profiling`, `--disable-accessibility`, `--enable-hardening`,
`--enable-strip`, `--enable-install-strip`.

**How to verify:**

- [ ] After build, run `strings` against the binary and grep for
      `crashreporter`, `updater`, `marionette` — should be absent or
      drastically reduced compared to a stock Firefox build.
- [ ] Confirm no `crashreporter` or `updater` binaries shipped in the
      install directory.

## A5. Host-level operational controls

These are **not** enforced by the browser — they must be enforced by the
OS image DenBrowser is deployed onto. See README.md → "Deployment
requirements".

- [ ] Full-disk encryption enabled (BitLocker / FileVault / LUKS).
- [ ] Hibernation disabled, or hibernation image encrypted.
- [ ] On Linux: swap disabled (`swapoff`) or on an encrypted partition.
- [ ] User account is unprivileged (cannot install software, cannot
      attach a debugger to running processes, cannot read other users'
      memory).

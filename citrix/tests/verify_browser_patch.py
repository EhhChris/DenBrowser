#!/usr/bin/env python3
"""Verify patch 021 without modifying the Firefox checkout.

Run from a Visual Studio x64 Developer shell after configuring Firefox:
  python citrix/tests/verify_browser_patch.py

The test copies only the files touched by the patch, applies it there, compiles
the production lease worker against Firefox's real generated headers, then
runs browser tests with fake WFAPI/WTS and real Windows threads/events.
It does not build/link Firefox or exercise a real Citrix connection.
"""

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def run(arguments, **kwargs):
    print("+", subprocess.list2cmdline([str(arg) for arg in arguments]), flush=True)
    subprocess.run([str(arg) for arg in arguments], check=True, **kwargs)


def main():
    repo = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=repo / "src/firefox-153.1.0")
    parser.add_argument("--objdir", type=Path, default=repo / "src/denbrowser-obj")
    parser.add_argument("--output", type=Path, default=repo / "build/citrix-browser-verify")
    parser.add_argument("--compiler", type=Path)
    parser.add_argument("--patch-tool", type=Path)
    args = parser.parse_args()
    args.source = args.source.resolve()
    args.objdir = args.objdir.resolve()
    args.output = args.output.resolve()

    if args.source == args.output or args.source in args.output.parents:
        parser.error("--output must be outside the Firefox source checkout")
    config = args.objdir / "mozilla-config.h"
    include = args.objdir / "dist/include"
    if not config.is_file() or not (include / "mozilla/RandomNum.h").is_file():
        parser.error("--objdir must contain configured Firefox generated headers")

    if not args.compiler:
        bundled = Path.home() / ".mozbuild/clang/bin/clang-cl.exe"
        try:
            args.compiler = bundled if bundled.is_file() else None
        except OSError:
            args.compiler = None
        args.compiler = args.compiler or shutil.which("clang-cl")
    if not args.compiler:
        parser.error("clang-cl is required; use --compiler or Mozilla's toolchain")
    if not args.patch_tool:
        installed = Path(os.environ.get("MOZILLABUILD", "C:/mozilla-build"))
        bundled = installed / "msys2/usr/bin/patch.exe"
        args.patch_tool = bundled if bundled.is_file() else shutil.which("patch")
    if not args.patch_tool:
        parser.error("GNU patch is required; use --patch-tool or MozillaBuild")

    # A fresh directory avoids stale extracted sources without deleting files.
    args.output.mkdir(parents=True, exist_ok=True)
    import tempfile
    work = Path(tempfile.mkdtemp(prefix="verify-", dir=args.output))
    print(f"Verification artifacts: {work}", flush=True)
    existing_files = ("toolkit/xre/moz.build", "toolkit/xre/nsAppRunner.cpp")
    added_files = ("toolkit/xre/DenCitrixCaptureProtection.cpp",
                   "toolkit/xre/DenCitrixCaptureProtection.h",
                   "toolkit/xre/DenCitrixCaptureProtocol.h")
    for relative in (*existing_files, *added_files):
        if relative in added_files and not (args.source / relative).is_file():
            continue
        target = work / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.source / relative, target)
    patch = repo / "patches/021-citrix-capture-protection.patch"
    patch_command = [args.patch_tool, "--batch", "--fuzz=0", "-p1", "-d", work,
                     "-i", patch]
    if any((work / relative).exists() for relative in added_files):
        # Validate the complete current patch in reverse before changing even
        # the copies. Do not silently mix an older browser patch with new code.
        try:
            run([*patch_command, "--reverse", "--dry-run"])
        except subprocess.CalledProcessError as error:
            raise RuntimeError(
                "Firefox contains a different or partially applied patch 021. "
                "Use an unpatched checkout or one with the current patch fully "
                "applied; the original source was not modified.") from error
        run([*patch_command, "--reverse"])
    run([*patch_command, "--forward"])

    # Validate the lifecycle placement that the isolated worker test cannot
    # exercise: RELEASE must precede Firefox's fast XPCOM shutdown.
    runner = (work / "toolkit/xre/nsAppRunner.cpp").read_text()
    main_start = runner.index("int XREMain::XRE_main(")
    loop = runner.index("rv = XRE_mainRun();", main_start)
    release = runner.index("denCitrixCaptureProtection = nullptr;", loop)
    shutdown = runner.index("mScopedXPCOM = nullptr;", loop)
    if not loop < release < shutdown:
        raise RuntimeError("lease release must run after the loop and before XPCOM teardown")

    source = work / "toolkit/xre"
    common = [args.compiler, "/nologo", "/std:c++20", "/EHsc", "/MD",
              "/DNOMINMAX", "/DWIN32_LEAN_AND_MEAN", f"/I{source}",
              f"/I{include}", f"/I{include / 'nspr'}"]
    run([*common, "/c", "/DMOZILLA_CLIENT", "/FI", config,
         source / "DenCitrixCaptureProtection.cpp",
         f"/Fo{work / 'DenCitrixCaptureProtection.obj'}"])

    # Protocol structs are shared by copy with the endpoint, so check that the
    # browser copy still matches the canonical definition after patch edits.
    browser_protocol = (source / "DenCitrixCaptureProtocol.h").read_text()
    endpoint_protocol = (repo / "citrix/protocol/dencap_protocol.h").read_text()
    for text in (browser_protocol, endpoint_protocol):
        if "namespace dencap {" not in text:
            raise RuntimeError("missing protocol namespace")
    def wire_definition(text):
        body = text.split("namespace dencap {", 1)[1].split("inline bool", 1)[0]
        return re.sub(r"\s+", "", re.sub(r"//[^\n]*", "", body))

    if wire_definition(browser_protocol) != wire_definition(endpoint_protocol):
        raise RuntimeError("browser and endpoint protocol definitions differ")

    executable = work / "dencap_browser_tests.exe"
    run([*common, repo / "citrix/tests/dencap_browser_tests.cpp",
         f"/Fo{work / 'dencap_browser_tests.obj'}", f"/Fe{executable}",
         "/link", "advapi32.lib", "wtsapi32.lib"])
    run([executable], timeout=20)
    print("PASS: patch application, real Firefox header compilation, lifecycle "
          "placement, protocol parity, and browser tests", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

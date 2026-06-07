#!/usr/bin/env python3
"""Blank the contents of test payload files in a Firefox source tree.

Usage: blank-test-payloads.py FIREFOX_SRC_DIR

Keeps every file and directory -- so the build graph stays 100% intact and the
configure/emitter stage can never hit a missing path -- and truncates only the
CONTENTS of payload files inside test directories to empty.

A file inside a test dir is KEPT INTACT when any of these hold:
  - its extension is a build-input / code / config type (KEEP_EXTS), or
  - it is a build file (moz.build / *.mozbuild / jar.mn / Makefile* / configure*), or
  - a moz.build names it as a real input (GeneratedFile inputs, SOURCES, ...);
    Files() metadata globs are excluded, so test fixtures referenced only for
    BUG_COMPONENT/SCHEDULES are still blanked.
Everything else under a test dir is truncated to empty.
"""
import ast
import os
import sys

TEST_DIR_NAMES = {
    "test", "tests", "mochitest", "mochitests", "reftest", "reftests",
    "crashtests", "crashtest", "jit-test", "gtest",
}
TESTING_KEEP = {"mozbase"}

# Extensions never blanked: build inputs, source code, and config/manifests the
# emitter parses. Test fixtures (.html/.js/.svg/.json/.xml/.css/.txt/binaries)
# are NOT here, so they get blanked.
KEEP_EXTS = {
    # data / config / manifests read at build time
    ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".json5",
    # certificates / keys (e.g. security/manager/ssl xpcshell roots)
    ".pem", ".crt", ".cer", ".der", ".key", ".pub", ".p12", ".pfx",
    # source / interface / generated includes
    ".py", ".cpp", ".cc", ".cxx", ".c", ".m", ".mm", ".h", ".hh", ".hpp",
    ".hxx", ".inc", ".rs", ".idl", ".webidl", ".ipdl", ".ipdlh",
    ".s", ".asm", ".def", ".rc",
    # build system
    ".in", ".mk", ".m4", ".sh", ".build",
}
KEEP_NAMES = {
    "moz.build", "moz.configure", "jar.mn",
    "makefile", "makefile.in", "configure", "configure.in",
}


def resolve(token, base_dir, ff_dir):
    if token.startswith("/"):
        return os.path.normpath(os.path.join(ff_dir, token.lstrip("/")))
    return os.path.normpath(os.path.join(base_dir, token))


def under_test(abspath, ff_dir):
    try:
        rel = os.path.relpath(abspath, ff_dir)
    except ValueError:
        return False
    if rel.startswith(".."):
        return False
    parts = rel.split(os.sep)
    for i, part in enumerate(parts):
        if part in TEST_DIR_NAMES:
            return True
        if i == 0 and part == "testing" and len(parts) > 1 and parts[1] not in TESTING_KEEP:
            return True
    return False


def input_literals(tree):
    """String literals that may be build inputs: excludes Files() args (metadata
    globs) and, via the AST, comments."""
    skip = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", None)
            if name == "Files":
                for arg in node.args:
                    for s in ast.walk(arg):
                        if isinstance(s, ast.Constant) and isinstance(s.value, str):
                            skip.add(id(s))
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in skip]


def referenced_inputs(ff_dir):
    """Files under a test dir that a moz.build names as a real (non-Files) input."""
    keep = set()
    for dirpath, _, filenames in os.walk(ff_dir):
        for name in filenames:
            if name != "moz.build" and not name.endswith(".mozbuild"):
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    tree = ast.parse(f.read(), filename=path)
            except (OSError, SyntaxError):
                continue
            for lit in input_literals(tree):
                if not lit or "*" in lit or "?" in lit or ":" in lit:
                    continue
                ap = resolve(lit, dirpath, ff_dir)
                if under_test(ap, ff_dir) and os.path.isfile(ap):
                    keep.add(ap)
    return keep


def keep_file(fp, ff_dir, referenced):
    name = os.path.basename(fp).lower()
    if name in KEEP_NAMES or name.endswith(".mozbuild"):
        return True
    if os.path.splitext(name)[1] in KEEP_EXTS:
        return True
    return os.path.normpath(fp) in referenced


def main(argv):
    if len(argv) != 2:
        print("usage: blank-test-payloads.py FIREFOX_SRC_DIR", file=sys.stderr)
        return 2
    ff_dir = os.path.normpath(argv[1])
    if not os.path.isdir(ff_dir):
        print(f"[blank-test-payloads] ERROR: not a directory: {ff_dir}", file=sys.stderr)
        return 1

    referenced = referenced_inputs(ff_dir)
    third_party = os.path.join(ff_dir, "third_party")

    blanked = kept = 0
    bytes_freed = 0
    for dirpath, dirnames, filenames in os.walk(ff_dir):
        # Never touch vendored code. Cargo verifies a per-file checksum for every
        # crate (.cargo-checksum.json), so blanking even a test file there breaks
        # the build; other vendored libraries may have their own integrity checks
        # too.
        if dirpath == third_party or ".cargo-checksum.json" in filenames:
            dirnames[:] = []
            continue
        if not under_test(dirpath, ff_dir):
            continue
        for name in filenames:
            fp = os.path.join(dirpath, name)
            if keep_file(fp, ff_dir, referenced):
                kept += 1
                continue
            try:
                sz = os.path.getsize(fp)
                if sz == 0:
                    continue
                with open(fp, "w", encoding="utf-8", newline="") as f:
                    pass  # truncate to empty
                blanked += 1
                bytes_freed += sz
            except OSError:
                pass

    print(f"[blank-test-payloads] Kept {len(referenced)} referenced build input(s) "
          f"inside test dirs.")
    print(f"[blank-test-payloads] Blanked {blanked} payload file(s) "
          f"(~{bytes_freed // (1024 * 1024)} MB of content); "
          f"kept {kept} build-input/code/config file(s) intact.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
"""Report per-patch Firefox source changes split by code, comments, and blanks.

By default the newest stable denbrowser-* tag in ../firefox is compared with
the nearest FIREFOX_*esr_RELEASE tag on its first-parent history. Use explicit
tags for reproducible historical reports.

Examples:
  scripts/patch-stats.py
  scripts/patch-stats.py --base-tag FIREFOX_153_1_0esr_RELEASE \
      --tag denbrowser-153.1.0esr-2
  scripts/patch-stats.py --show-files
  scripts/patch-stats.py --no-local-stubs
  scripts/patch-stats.py --format json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_FORK = ROOT_DIR.parent / "firefox"
PATCH_SUBJECT_RE = re.compile(r"^\d{3}-[a-z0-9][a-z0-9-]*$")
DENBROWSER_STABLE_TAG_RE = re.compile(
    r"^denbrowser-\d+(?:\.\d+)*esr-\d+$"
)
ESR_RELEASE_TAG_RE = re.compile(r"^FIREFOX_\d+(?:_\d+)*esr_RELEASE$")
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
CXX_RAW_STRING_RE = re.compile(
    r'(?:u8|u|U|L)?R"(?P<delimiter>[^ ()\\\t\r\n]{0,16})\('
)
RUST_RAW_STRING_RE = re.compile(r'(?:br|r)(?P<hashes>#{0,255})"')
DIFF_OPTIONS = ("--no-ext-diff", "--no-textconv", "--find-renames")


class ReportError(Exception):
    pass


@dataclass(frozen=True)
class CommentSyntax:
    name: str
    line_tokens: Tuple[str, ...] = ()
    block_start: Optional[str] = None
    block_end: Optional[str] = None
    quotes: Tuple[str, ...] = ('"', "'")
    nested_blocks: bool = False
    code_prefixes: Tuple[str, ...] = ()


C_LIKE = CommentSyntax("C-like", ("//",), "/*", "*/")
RUST = CommentSyntax("Rust", ("//",), "/*", "*/", nested_blocks=True)
CSS = CommentSyntax("CSS", (), "/*", "*/")
MARKUP = CommentSyntax("markup", (), "<!--", "-->")
HASH = CommentSyntax("hash", ("#",), quotes=('"', "'", "`"))
INI = CommentSyntax("INI", ("#", ";"))
PROPERTIES = CommentSyntax("properties", ("#", "!"))
NSIS = CommentSyntax("NSIS", ("#", ";"), "/*", "*/")
PLAIN = CommentSyntax("plain")
JAR_MN = CommentSyntax(
    "jar.mn",
    ("#",),
    code_prefixes=(
        "#filter",
        "#include",
        "#if",
        "#ifdef",
        "#ifndef",
        "#else",
        "#elif",
        "#endif",
        "#define",
        "#undef",
        "#expand",
        "#literal",
    ),
)


C_LIKE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
    ".m", ".mm", ".js", ".mjs", ".jsx", ".ts", ".tsx", ".idl",
    ".webidl", ".ipdl", ".ipdlh",
}
HASH_SUFFIXES = {
    ".py", ".sh", ".bash", ".zsh", ".configure", ".conf", ".ftl",
    ".toml", ".yaml", ".yml", ".mk",
}
MARKUP_SUFFIXES = {".html", ".htm", ".xhtml", ".xml", ".svg"}
PLAIN_SUFFIXES = {".json"}


@dataclass
class Counts:
    code_added: int = 0
    code_deleted: int = 0
    comment_added: int = 0
    comment_deleted: int = 0
    blank_added: int = 0
    blank_deleted: int = 0

    def record(self, side: str, category: str) -> None:
        attr = f"{category}_{side}"
        setattr(self, attr, getattr(self, attr) + 1)

    def merge(self, other: "Counts") -> None:
        for attr in (
            "code_added", "code_deleted", "comment_added",
            "comment_deleted", "blank_added", "blank_deleted",
        ):
            setattr(self, attr, getattr(self, attr) + getattr(other, attr))

    @property
    def total_added(self) -> int:
        return self.code_added + self.comment_added + self.blank_added

    @property
    def total_deleted(self) -> int:
        return self.code_deleted + self.comment_deleted + self.blank_deleted

    @property
    def churn(self) -> int:
        return self.total_added + self.total_deleted

    def as_dict(self) -> Dict[str, object]:
        return {
            "added": {
                "code": self.code_added,
                "comment": self.comment_added,
                "blank": self.blank_added,
                "total": self.total_added,
            },
            "deleted": {
                "code": self.code_deleted,
                "comment": self.comment_deleted,
                "blank": self.blank_deleted,
                "total": self.total_deleted,
            },
            "churn": self.churn,
        }


@dataclass(frozen=True)
class FileChange:
    status: str
    old_path: Optional[str]
    new_path: Optional[str]

    @property
    def display_path(self) -> str:
        if self.old_path and self.new_path and self.old_path != self.new_path:
            return f"{self.old_path} -> {self.new_path}"
        return self.new_path or self.old_path or "<unknown>"


@dataclass
class FileReport:
    change: FileChange
    counts: Counts = field(default_factory=Counts)
    binary: bool = False

    def as_dict(self) -> Dict[str, object]:
        return {
            "status": self.change.status,
            "path": self.change.display_path,
            "binary": self.binary,
            **self.counts.as_dict(),
        }


@dataclass
class PatchReport:
    name: str
    commit: Optional[str]
    files: List[FileReport] = field(default_factory=list)
    stub: bool = False

    @property
    def counts(self) -> Counts:
        result = Counts()
        for file_report in self.files:
            result.merge(file_report.counts)
        return result

    @property
    def binary_files(self) -> int:
        return sum(file_report.binary for file_report in self.files)

    def as_dict(self) -> Dict[str, object]:
        return {
            "patch": self.name,
            "commit": self.commit,
            "stub": self.stub,
            "source": "local-patch-manifest" if self.stub else "firefox-tag-commit",
            "file_count": len(self.files),
            "binary_files": self.binary_files,
            **self.counts.as_dict(),
            "files": [file_report.as_dict() for file_report in self.files],
        }


def run_git_bytes(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    process = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and process.returncode != 0:
        message = process.stderr.decode("utf-8", "replace").strip()
        raise ReportError(f"git {' '.join(args)} failed: {message}")
    return process


def git_text(repo: Path, *args: str) -> str:
    return run_git_bytes(repo, *args).stdout.decode("utf-8", "replace")


def resolve_commit(repo: Path, ref: str) -> str:
    return git_text(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").strip()


def short_tag_name(ref: str) -> str:
    prefix = "refs/tags/"
    return ref[len(prefix):] if ref.startswith(prefix) else ref


def resolve_tag_commit(repo: Path, ref: str) -> Tuple[str, str]:
    name = short_tag_name(ref)
    commit = resolve_commit(repo, f"refs/tags/{name}")
    return name, commit


def resolve_esr_base_tag(repo: Path, ref: str) -> Tuple[str, str]:
    name = short_tag_name(ref)
    if not ESR_RELEASE_TAG_RE.fullmatch(name):
        raise ReportError(
            "--base-tag must name a FIREFOX_<version>esr_RELEASE tag, "
            "not a commit, branch, or patched DenBrowser tag"
        )
    return resolve_tag_commit(repo, name)


def latest_denbrowser_tag(repo: Path) -> str:
    output = git_text(
        repo,
        "for-each-ref",
        "--sort=-version:refname",
        "--format=%(refname:short)",
        "refs/tags/denbrowser-*",
    )
    tags = [
        line
        for line in output.splitlines()
        if DENBROWSER_STABLE_TAG_RE.fullmatch(line)
    ]
    if not tags:
        raise ReportError(
            "no stable denbrowser-<version>esr-<rev> tags found; pass --tag explicitly"
        )
    return tags[0]


def infer_base_tag(repo: Path, tag_commit: str) -> str:
    process = run_git_bytes(
        repo,
        "describe",
        "--tags",
        "--first-parent",
        "--match",
        "FIREFOX_*esr_RELEASE",
        "--abbrev=0",
        tag_commit,
        check=False,
    )
    if process.returncode != 0:
        raise ReportError(
            "could not infer an ESR base tag; pass --base-tag explicitly"
        )
    tag = process.stdout.decode("utf-8", "replace").strip()
    if not ESR_RELEASE_TAG_RE.fullmatch(tag):
        raise ReportError(f"inferred base tag has unexpected name: {tag}")
    return tag


def validate_linear_stack(repo: Path, base: str, tip: str) -> List[Tuple[str, str]]:
    ancestor = run_git_bytes(repo, "merge-base", "--is-ancestor", base, tip, check=False)
    if ancestor.returncode != 0:
        raise ReportError("the selected ESR base is not an ancestor of the patch tag")

    commits = git_text(
        repo, "rev-list", "--reverse", "--topo-order", f"{base}..{tip}"
    ).splitlines()
    if not commits:
        raise ReportError("the selected range contains no patch commits")

    result: List[Tuple[str, str]] = []
    expected_parent = base
    names = set()
    for commit in commits:
        parents = git_text(repo, "show", "-s", "--format=%P", commit).split()
        if parents != [expected_parent]:
            raise ReportError(
                f"{commit[:12]} is not part of a linear one-commit-per-patch stack"
            )
        name = git_text(repo, "show", "-s", "--format=%s", commit).strip()
        if not PATCH_SUBJECT_RE.fullmatch(name):
            raise ReportError(
                f"{commit[:12]} has non-patch subject {name!r}; expected NNN-name"
            )
        if name in names:
            raise ReportError(f"duplicate patch subject in range: {name}")
        names.add(name)
        result.append((commit, name))
        expected_parent = commit

    if commits[-1] != tip:
        raise ReportError("the patch tag is not the tip of the selected linear stack")
    return result


def syntax_for_path(path: str) -> CommentSyntax:
    name = Path(path).name.lower()
    suffix = Path(path).suffix.lower()
    if name == "jar.mn":
        return JAR_MN
    if name in {"moz.build", "moz.configure", "makefile", "makefile.in"}:
        return HASH
    if name.endswith(".mozbuild"):
        return HASH
    if suffix == ".rs":
        return RUST
    if suffix == ".json5":
        return C_LIKE
    if suffix in C_LIKE_SUFFIXES:
        return C_LIKE
    if suffix == ".css":
        return CSS
    if suffix in MARKUP_SUFFIXES:
        return MARKUP
    if suffix in HASH_SUFFIXES:
        return HASH
    if suffix == ".ini":
        return INI
    if suffix == ".properties":
        return PROPERTIES
    if suffix == ".nsi":
        return NSIS
    if suffix in PLAIN_SUFFIXES:
        return PLAIN
    raise ReportError(
        f"unsupported text type for {path}; add its comment syntax to patch-stats.py"
    )


def has_code_prefix(stripped: str, syntax: CommentSyntax) -> bool:
    for prefix in syntax.code_prefixes:
        if stripped == prefix or stripped.startswith(prefix + " "):
            return True
    return False


def skip_quoted(line: str, start: int, quote: str) -> int:
    index = start + 1
    while index < len(line):
        if line[index] == "\\":
            index += 2
        elif line[index] == quote:
            return index + 1
        else:
            index += 1
    return len(line)


def find_string_end(
    line: str, token: str, start: int, backslash_escapes: bool
) -> Optional[int]:
    index = start
    while True:
        found = line.find(token, index)
        if found < 0:
            return None
        if not backslash_escapes:
            return found
        backslashes = 0
        check = found - 1
        while check >= 0 and line[check] == "\\":
            backslashes += 1
            check -= 1
        if backslashes % 2 == 0:
            return found
        index = found + 1


def multiline_string_start(
    line: str, index: int, syntax: CommentSyntax
) -> Optional[Tuple[int, str, bool]]:
    at_token_boundary = index == 0 or not (
        line[index - 1].isalnum() or line[index - 1] == "_"
    )
    if syntax is C_LIKE and at_token_boundary:
        match = CXX_RAW_STRING_RE.match(line, index)
        if match:
            return match.end(), f"){match.group('delimiter')}\"", False
    if syntax is RUST and at_token_boundary:
        match = RUST_RAW_STRING_RE.match(line, index)
        if match:
            return match.end(), f"\"{match.group('hashes')}", False
    if syntax is HASH:
        for token in ('"""', "'''"):
            if line.startswith(token, index):
                return index + len(token), token, True
    if syntax in {C_LIKE, HASH} and line.startswith("`", index):
        return index + 1, "`", True
    return None


def classify_blob(data: bytes, path: str) -> List[str]:
    text = data.decode("utf-8", "replace")
    lines = text.splitlines()
    if not lines:
        return []
    syntax = syntax_for_path(path)
    categories: List[str] = []
    block_depth = 0
    multiline_end: Optional[Tuple[str, bool]] = None

    for line_number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            categories.append("blank")
            continue
        if block_depth == 0 and line_number == 1 and stripped.startswith("#!"):
            categories.append("code")
            continue
        if block_depth == 0 and has_code_prefix(stripped, syntax):
            categories.append("code")
            continue

        index = 0
        saw_code = False
        saw_comment = False
        while index < len(line):
            if multiline_end:
                saw_code = True
                end_token, backslash_escapes = multiline_end
                end_index = find_string_end(
                    line, end_token, index, backslash_escapes
                )
                if end_index is None:
                    index = len(line)
                    continue
                index = end_index + len(end_token)
                multiline_end = None
                continue
            if block_depth:
                saw_comment = True
                if (
                    syntax.nested_blocks
                    and syntax.block_start
                    and line.startswith(syntax.block_start, index)
                ):
                    block_depth += 1
                    index += len(syntax.block_start)
                elif syntax.block_end and line.startswith(syntax.block_end, index):
                    block_depth -= 1
                    index += len(syntax.block_end)
                else:
                    index += 1
                continue

            if line[index].isspace():
                index += 1
                continue
            line_token = next(
                (token for token in syntax.line_tokens if line.startswith(token, index)),
                None,
            )
            if line_token is not None:
                saw_comment = True
                break
            if syntax.block_start and line.startswith(syntax.block_start, index):
                saw_comment = True
                block_depth = 1
                index += len(syntax.block_start)
                continue
            string_start = multiline_string_start(line, index, syntax)
            if string_start:
                saw_code = True
                content_start, end_token, backslash_escapes = string_start
                end_index = find_string_end(
                    line, end_token, content_start, backslash_escapes
                )
                if end_index is None:
                    multiline_end = (end_token, backslash_escapes)
                    index = len(line)
                else:
                    index = end_index + len(end_token)
                continue
            if line[index] in syntax.quotes:
                saw_code = True
                index = skip_quoted(line, index, line[index])
                continue
            saw_code = True
            index += 1

        categories.append("code" if saw_code else "comment" if saw_comment else "blank")
    return categories


def parse_name_status(raw: bytes) -> List[FileChange]:
    fields = raw.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    changes: List[FileChange] = []
    index = 0
    while index < len(fields):
        status = fields[index].decode("ascii", "replace")
        index += 1
        kind = status[:1]
        if kind in {"R", "C"}:
            if index + 1 >= len(fields):
                raise ReportError("malformed rename/copy record from git diff")
            old_path = os.fsdecode(fields[index])
            new_path = os.fsdecode(fields[index + 1])
            index += 2
        else:
            if index >= len(fields):
                raise ReportError("malformed path record from git diff")
            path = os.fsdecode(fields[index])
            index += 1
            old_path = None if kind == "A" else path
            new_path = None if kind == "D" else path
        changes.append(FileChange(status, old_path, new_path))
    return changes


def parse_numstat(raw: bytes) -> Tuple[int, int, int]:
    added = 0
    deleted = 0
    binaries = 0
    for line in raw.splitlines():
        fields = line.split(b"\t", 2)
        if len(fields) != 3:
            raise ReportError("malformed record from git diff --numstat")
        added_field, deleted_field = fields[:2]
        if added_field == b"-" and deleted_field == b"-":
            binaries += 1
            continue
        if added_field == b"-" or deleted_field == b"-":
            raise ReportError("inconsistent binary record from git diff --numstat")
        try:
            added += int(added_field)
            deleted += int(deleted_field)
        except ValueError as error:
            raise ReportError("non-numeric record from git diff --numstat") from error
    return added, deleted, binaries


def parse_hunks(diff_text: str, old_lines: Sequence[str], new_lines: Sequence[str]) -> Counts:
    counts = Counts()
    in_hunk = False
    old_index = 0
    new_index = 0
    for line in diff_text.splitlines():
        match = HUNK_RE.match(line)
        if match:
            old_index = int(match.group(1)) - 1
            new_index = int(match.group(2)) - 1
            in_hunk = True
            continue
        if not in_hunk or not line or line.startswith("\\ No newline"):
            continue
        prefix = line[0]
        if prefix == "-":
            if not 0 <= old_index < len(old_lines):
                raise ReportError("deleted line number fell outside the old file")
            counts.record("deleted", old_lines[old_index])
            old_index += 1
        elif prefix == "+":
            if not 0 <= new_index < len(new_lines):
                raise ReportError("added line number fell outside the new file")
            counts.record("added", new_lines[new_index])
            new_index += 1
        elif prefix == " ":
            old_index += 1
            new_index += 1
    return counts


class Analyzer:
    def __init__(self, repo: Path):
        self.repo = repo
        self.blob_cache: Dict[Tuple[str, str], bytes] = {}
        self.class_cache: Dict[Tuple[str, str], List[str]] = {}

    def blob(self, ref: str, path: str) -> bytes:
        key = (ref, path)
        if key not in self.blob_cache:
            self.blob_cache[key] = run_git_bytes(self.repo, "show", f"{ref}:{path}").stdout
        return self.blob_cache[key]

    def classes(self, ref: str, path: str) -> List[str]:
        key = (ref, path)
        if key not in self.class_cache:
            self.class_cache[key] = classify_blob(self.blob(ref, path), path)
        return self.class_cache[key]

    def changed_files(self, old_ref: str, new_ref: str) -> List[FileChange]:
        raw = run_git_bytes(
            self.repo,
            "diff",
            "--name-status",
            "-z",
            *DIFF_OPTIONS,
            old_ref,
            new_ref,
            "--",
        ).stdout
        return parse_name_status(raw)

    def file_report(self, old_ref: str, new_ref: str, change: FileChange) -> FileReport:
        old_data = self.blob(old_ref, change.old_path) if change.old_path else b""
        new_data = self.blob(new_ref, change.new_path) if change.new_path else b""
        paths = [path for path in (change.old_path, change.new_path) if path]
        pathspecs = [f":(literal){path}" for path in dict.fromkeys(paths)]
        diff_data = run_git_bytes(
            self.repo,
            "diff",
            "--no-color",
            "--unified=0",
            *DIFF_OPTIONS,
            old_ref,
            new_ref,
            "--",
            *pathspecs,
        ).stdout
        binary = (
            b"\0" in old_data
            or b"\0" in new_data
            or b"Binary files " in diff_data
            or b"GIT binary patch" in diff_data
        )
        if binary:
            return FileReport(change, binary=True)
        old_classes = self.classes(old_ref, change.old_path) if change.old_path else []
        new_classes = self.classes(new_ref, change.new_path) if change.new_path else []
        diff_text = diff_data.decode("utf-8", "replace")
        return FileReport(change, parse_hunks(diff_text, old_classes, new_classes))

    def report(self, name: str, commit: Optional[str], old_ref: str, new_ref: str) -> PatchReport:
        files = [
            self.file_report(old_ref, new_ref, change)
            for change in self.changed_files(old_ref, new_ref)
        ]
        report = PatchReport(name, commit, files)
        raw_numstat = run_git_bytes(
            self.repo,
            "diff",
            "--numstat",
            *DIFF_OPTIONS,
            old_ref,
            new_ref,
            "--",
        ).stdout
        expected_added, expected_deleted, expected_binaries = parse_numstat(raw_numstat)
        counts = report.counts
        if (counts.total_added, counts.total_deleted, report.binary_files) != (
            expected_added,
            expected_deleted,
            expected_binaries,
        ):
            raise ReportError(
                f"classified totals for {name} do not match git --numstat: "
                f"classified +{counts.total_added}/-{counts.total_deleted} "
                f"with {report.binary_files} binaries; expected "
                f"+{expected_added}/-{expected_deleted} with {expected_binaries} binaries"
            )
        return report


def find_stubs() -> List[str]:
    patch_dir = ROOT_DIR / "patches"
    if not patch_dir.is_dir():
        return []
    stubs = []
    for path in sorted(patch_dir.glob("*.patch")):
        try:
            first_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[:5]
        except OSError:
            continue
        if any(line.startswith("# STUB") for line in first_lines):
            stubs.append(path.stem)
    return stubs


def aggregate(reports: Iterable[PatchReport]) -> Tuple[int, int, Counts]:
    file_count = 0
    binary_files = 0
    counts = Counts()
    for report in reports:
        file_count += len(report.files)
        binary_files += report.binary_files
        counts.merge(report.counts)
    return file_count, binary_files, counts


def table_row(label: str, files: int, binaries: int, counts: Counts, width: int) -> str:
    return (
        f"{label:<{width}}  {files:>5} {binaries:>3} "
        f"{counts.code_added:>6} {counts.code_deleted:>6} "
        f"{counts.comment_added:>9} {counts.comment_deleted:>9} "
        f"{counts.blank_added:>7} {counts.blank_deleted:>7} "
        f"{counts.total_added:>7} {counts.total_deleted:>7} {counts.churn:>7}"
    )


def print_table(
    repo: Path,
    tag_name: str,
    tag_commit: str,
    base_name: str,
    base_commit: str,
    reports: List[PatchReport],
    final_tree: PatchReport,
    show_files: bool,
) -> None:
    labels = [
        report.name + (" [local stub]" if report.stub else "")
        for report in reports
    ]
    if show_files:
        labels.extend(
            "  " + file_report.change.display_path
            for report in reports
            for file_report in report.files
        )
    width = max([len("PATCH"), len("PATCH CHURN"), len("FINAL TREE"), *map(len, labels)])
    print(f"Firefox fork: {repo}")
    print(f"Patch tag:   {tag_name} ({tag_commit[:12]})")
    print(f"ESR base:    {base_name} ({base_commit[:12]})")
    print("Classification: comment-only lines are comments; mixed code/comments are code.")
    print("Patch headers, commit messages, diff metadata, and local stubs are excluded from LOC.")
    if any(report.stub for report in reports):
        print(f"Local stubs:  {ROOT_DIR / 'patches'} (not stored in the Firefox tag)")
    print()
    print(
        f"{'PATCH':<{width}}  FILES BIN  CODE+  CODE- COMMENT+ COMMENT- "
        " BLANK+  BLANK-  TOTAL+  TOTAL-   CHURN"
    )
    print("-" * (width + 83))
    for report in reports:
        label = report.name + (" [local stub]" if report.stub else "")
        print(table_row(label, len(report.files), report.binary_files, report.counts, width))
        if show_files:
            for file_report in report.files:
                print(
                    table_row(
                        "  " + file_report.change.display_path,
                        1,
                        int(file_report.binary),
                        file_report.counts,
                        width,
                    )
                )
    print("-" * (width + 83))
    stack_files, stack_binaries, stack_counts = aggregate(reports)
    print(table_row("PATCH CHURN", stack_files, stack_binaries, stack_counts, width))
    print(
        table_row(
            "FINAL TREE",
            len(final_tree.files),
            final_tree.binary_files,
            final_tree.counts,
            width,
        )
    )
    print()
    print("PATCH CHURN sums parent-to-commit changes and can count a line more than once.")
    print("Its FILES value is file-change occurrences; a path touched twice counts twice.")
    print("FINAL TREE is the direct ESR-base-to-tag delta.")
    print("Binary files increment BIN but have no line counts.")


def print_json(
    repo: Path,
    tag_name: str,
    tag_commit: str,
    base_name: str,
    base_commit: str,
    reports: List[PatchReport],
    final_tree: PatchReport,
) -> None:
    stack_files, stack_binaries, stack_counts = aggregate(reports)
    payload = {
        "firefox_fork": str(repo),
        "patch_tag": {"name": tag_name, "commit": tag_commit},
        "esr_base": {"name": base_name, "commit": base_commit},
        "classification": {
            "comment": "comment-only changed source line",
            "code": "nonblank source line containing any code, including trailing comments",
            "blank": "whitespace-only changed source line",
            "binary": "counted as a binary file with no line counts",
            "excluded": ["patch headers", "commit messages", "diff metadata", "stubs"],
        },
        "local_stub_manifest": (
            str(ROOT_DIR / "patches")
            if any(report.stub for report in reports)
            else None
        ),
        "patches": [report.as_dict() for report in reports],
        "patch_churn": {
            "file_changes": stack_files,
            "binary_files": stack_binaries,
            **stack_counts.as_dict(),
        },
        "final_tree": final_tree.as_dict(),
    }
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    print()


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Count Firefox source changes per DenBrowser patch commit."
    )
    parser.add_argument(
        "--fork",
        type=Path,
        default=DEFAULT_FORK,
        help=f"Firefox Git checkout (default: {DEFAULT_FORK})",
    )
    parser.add_argument(
        "--tag",
        help="DenBrowser tag to report (default: newest stable denbrowser-* tag)",
    )
    parser.add_argument(
        "--base-tag",
        help="Mozilla ESR release tag (default: inferred from the selected tag)",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )
    parser.add_argument(
        "--show-files",
        action="store_true",
        help="include per-file rows in table output",
    )
    parser.add_argument(
        "--no-local-stubs",
        action="store_true",
        help="omit stub rows read from this checkout's patches directory",
    )
    args = parser.parse_args(argv[1:])
    if args.show_files and args.format != "table":
        parser.error("--show-files is only valid with --format table")
    return args


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    try:
        repo = args.fork.expanduser().resolve()
        if not repo.is_dir():
            raise ReportError(f"Firefox checkout not found: {repo}")
        git_text(repo, "rev-parse", "--git-dir")

        requested_tag = args.tag or latest_denbrowser_tag(repo)
        tag_name, tag_commit = resolve_tag_commit(repo, requested_tag)
        requested_base = args.base_tag or infer_base_tag(repo, tag_commit)
        base_name, base_commit = resolve_esr_base_tag(repo, requested_base)
        stack = validate_linear_stack(repo, base_commit, tag_commit)

        analyzer = Analyzer(repo)
        reports = []
        parent = base_commit
        for commit, name in stack:
            reports.append(analyzer.report(name, commit, parent, commit))
            parent = commit

        active_names = {report.name for report in reports}
        if not args.no_local_stubs:
            for stub in find_stubs():
                if stub in active_names:
                    raise ReportError(
                        f"local stub also appears as an active patch commit: {stub}"
                    )
                reports.append(PatchReport(stub, None, stub=True))
        reports.sort(key=lambda report: report.name)
        final_tree = analyzer.report("FINAL TREE", tag_commit, base_commit, tag_commit)

        if args.format == "json":
            print_json(
                repo, tag_name, tag_commit, base_name, base_commit, reports, final_tree
            )
        else:
            print_table(
                repo,
                tag_name,
                tag_commit,
                base_name,
                base_commit,
                reports,
                final_tree,
                args.show_files,
            )
        return 0
    except ReportError as error:
        print(f"[patch-stats] ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))

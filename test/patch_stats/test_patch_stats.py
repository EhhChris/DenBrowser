import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "patch-stats.py"
SPEC = importlib.util.spec_from_file_location("patch_stats", SCRIPT)
patch_stats = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = patch_stats
SPEC.loader.exec_module(patch_stats)


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def init_repo(path):
    git(path, "init", "-q")
    git(path, "config", "user.name", "Patch Stats Test")
    git(path, "config", "user.email", "patch-stats@example.invalid")


class CommentClassificationTests(unittest.TestCase):
    def test_c_like_comments_strings_and_preprocessor(self):
        data = b"""#include <stdio.h>
// comment only
int value = 1; // trailing comment
/* block starts
 * block body
 */

const char* url = \"http://example.test\";
"""
        self.assertEqual(
            patch_stats.classify_blob(data, "sample.cpp"),
            ["code", "comment", "code", "comment", "comment", "comment", "blank", "code"],
        )

    def test_code_after_block_comment_is_code(self):
        data = b"""/* comment */ int value = 1;
/* comment only */
"""
        self.assertEqual(
            patch_stats.classify_blob(data, "sample.js"),
            ["code", "comment"],
        )

    def test_css_hashes_are_code(self):
        data = b"""#page { color: #fff; }
/* comment */
"""
        self.assertEqual(
            patch_stats.classify_blob(data, "sample.css"),
            ["code", "comment"],
        )

    def test_json5_comments(self):
        self.assertEqual(
            patch_stats.classify_blob(
                b"// line comment\n/* block comment */\n{key: 1}\n",
                "sample.json5",
            ),
            ["comment", "comment", "code"],
        )

    def test_hash_comments_shebang_and_strings(self):
        data = b"""#!/usr/bin/env bash
# comment
echo \"# not a comment\" # mixed
"""
        self.assertEqual(
            patch_stats.classify_blob(data, "sample.sh"),
            ["code", "comment", "code"],
        )

    def test_jar_directives_are_code(self):
        data = b"""#filter substitution
# ordinary comment
% content browser %content/
"""
        self.assertEqual(
            patch_stats.classify_blob(data, "jar.mn"),
            ["code", "comment", "code"],
        )

    def test_markup_block_comment(self):
        data = b"""<!-- start
middle
end -->
<div><!-- mixed --></div>
"""
        self.assertEqual(
            patch_stats.classify_blob(data, "sample.xhtml"),
            ["comment", "comment", "comment", "code"],
        )

    def test_multiline_literals_do_not_open_comments(self):
        javascript = b"const value = `\n// string data\n/* more data */\n`;\nlet code = 1;\n"
        self.assertEqual(
            patch_stats.classify_blob(javascript, "sample.mjs"),
            ["code", "code", "code", "code", "code"],
        )
        cpp = b'auto value = R"tag(\n// string data\n/* more data */\n)tag";\nint code = 1;\n'
        self.assertEqual(
            patch_stats.classify_blob(cpp, "sample.cpp"),
            ["code", "code", "code", "code", "code"],
        )

    def test_python_triple_quoted_text_is_code(self):
        data = b'help_text = """\n# string data\n"""\n# comment\n'
        self.assertEqual(
            patch_stats.classify_blob(data, "moz.build"),
            ["code", "code", "code", "comment"],
        )

    def test_ini_properties_and_nsis(self):
        self.assertEqual(
            patch_stats.classify_blob(b"; note\nkey=value\n", "sample.ini"),
            ["comment", "code"],
        )
        self.assertEqual(
            patch_stats.classify_blob(b"! note\nkey=value\n", "sample.properties"),
            ["comment", "code"],
        )
        self.assertEqual(
            patch_stats.classify_blob(b"!define APP Foo\n; note\n", "sample.nsi"),
            ["code", "comment"],
        )


class DiffParsingTests(unittest.TestCase):
    def test_block_comment_state_carries_in_from_outside_the_hunk(self):
        old = patch_stats.classify_blob(
            b"/* open\nunchanged comment\nold comment\n*/\n", "sample.cpp"
        )
        new = patch_stats.classify_blob(
            b"/* open\nunchanged comment\nnew comment\n*/\n", "sample.cpp"
        )
        counts = patch_stats.parse_hunks(
            "@@ -3 +3 @@\n-old comment\n+new comment\n", old, new
        )
        self.assertEqual(counts.comment_added, 1)
        self.assertEqual(counts.comment_deleted, 1)
        self.assertEqual(counts.code_added, 0)

    def test_hunk_line_numbers_select_full_blob_categories(self):
        old = ["code", "comment", "comment", "blank"]
        new = ["code", "comment", "code", "comment", "blank"]
        diff = """@@ -2,2 +2,3 @@
-// old
-/* removed */
+// replacement
+int replacement = 1;
+// added
"""
        counts = patch_stats.parse_hunks(diff, old, new)
        self.assertEqual(counts.code_added, 1)
        self.assertEqual(counts.comment_added, 2)
        self.assertEqual(counts.comment_deleted, 2)
        self.assertEqual(counts.total_added, 3)
        self.assertEqual(counts.total_deleted, 2)

    def test_name_status_records(self):
        changes = patch_stats.parse_name_status(
            b"M\0one.cpp\0A\0two.js\0R100\0old.css\0new.css\0"
        )
        self.assertEqual(changes[0].display_path, "one.cpp")
        self.assertIsNone(changes[1].old_path)
        self.assertEqual(changes[2].display_path, "old.css -> new.css")

    def test_numstat_totals_include_binary_files(self):
        self.assertEqual(
            patch_stats.parse_numstat(
                b"3\t1\tone.cpp\n-\t-\tlogo.png\n4\t0\tnew.js\n"
            ),
            (7, 1, 1),
        )


class PatchManifestTests(unittest.TestCase):
    def test_stub_marker_can_include_an_explanation(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            patch_dir = root / "patches"
            patch_dir.mkdir()
            (patch_dir / "007-example.patch").write_text(
                "# STUB — intentional placeholder\n# PATCH: 007-example\n",
                encoding="utf-8",
            )
            with mock.patch.object(patch_stats, "ROOT_DIR", root):
                self.assertEqual(patch_stats.find_stubs(), ["007-example"])


class GitIntegrationTests(unittest.TestCase):
    def test_latest_tag_ignores_beta_and_base_must_be_release_tag(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            repo = Path(temporary_dir)
            init_repo(repo)
            (repo / "source.cpp").write_text("int value = 1;\n", encoding="utf-8")
            git(repo, "add", "source.cpp")
            git(repo, "commit", "-q", "-m", "upstream base")
            base_commit = git(repo, "rev-parse", "HEAD")
            git(repo, "tag", "FIREFOX_1_0esr_RELEASE")
            git(repo, "tag", "denbrowser-1.0esr-beta10-2")
            git(repo, "tag", "denbrowser-1.0esr-1")

            self.assertEqual(
                patch_stats.latest_denbrowser_tag(repo),
                "denbrowser-1.0esr-1",
            )
            self.assertEqual(
                patch_stats.resolve_esr_base_tag(repo, "FIREFOX_1_0esr_RELEASE"),
                ("FIREFOX_1_0esr_RELEASE", base_commit),
            )
            with self.assertRaisesRegex(
                patch_stats.ReportError, "must name a FIREFOX_"
            ):
                patch_stats.resolve_esr_base_tag(repo, base_commit)

    def test_rename_detection_ignores_diff_renames_config(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            repo = Path(temporary_dir)
            init_repo(repo)
            source = repo / "before.cpp"
            source.write_text("int value = 1;\n", encoding="utf-8")
            git(repo, "add", "before.cpp")
            git(repo, "commit", "-q", "-m", "upstream base")
            base_commit = git(repo, "rev-parse", "HEAD")

            source.rename(repo / "after.cpp")
            git(repo, "add", "-A")
            git(repo, "commit", "-q", "-m", "000-rename-file")
            tip_commit = git(repo, "rev-parse", "HEAD")
            git(repo, "config", "diff.renames", "false")

            report = patch_stats.Analyzer(repo).report(
                "000-rename-file", tip_commit, base_commit, tip_commit
            )
            self.assertEqual(len(report.files), 1)
            self.assertEqual(report.files[0].change.status, "R100")
            self.assertEqual(report.counts.total_added, 0)
            self.assertEqual(report.counts.total_deleted, 0)


if __name__ == "__main__":
    unittest.main()

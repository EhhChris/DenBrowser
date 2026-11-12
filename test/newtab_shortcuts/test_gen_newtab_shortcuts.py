import base64
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "gen-newtab-shortcuts.py"

PAGE = """<!doctype html>
<html>
  <body>
    <nav class="den-tiles" aria-label="Shortcuts">
        <!-- DEN_SHORTCUTS_START -->
        <p class="den-empty">No shortcuts configured.</p>
        <!-- DEN_SHORTCUTS_END -->
    </nav>
  </body>
</html>
"""


def png_bytes():
    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\x00\x60\xdf")
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat)
            + chunk(b"IEND", b""))


IMAGES = {
    "png": (png_bytes(), "image/png"),
    "jpeg": (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9",
             "image/jpeg"),
    "gif": (b"GIF89a\x01\x00\x01\x00\x00\x00\x00;", "image/gif"),
    "webp": (b"RIFF\x1a\x00\x00\x00WEBPVP8L\x0d\x00\x00\x00\x2f\x00\x00\x00\x10\x07\x10\x11\x11\x88\x88\xfe\x07\x00",
             "image/webp"),
    "ico": (b"\x00\x00\x01\x00\x01\x00\x01\x01\x00\x00\x01\x00\x20\x00\x30\x00\x00\x00\x16\x00\x00\x00",
            "image/x-icon"),
    "svg": (b'<?xml version="1.0" encoding="UTF-8"?>\n<!-- icon -->\n'
            b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><rect width="1" height="1"/></svg>\n',
            "image/svg+xml"),
}


class GenNewtabShortcutsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.repo = self.tmp / "repo"
        self.images = self.repo / "config" / "shortcut-images"
        self.images.mkdir(parents=True)
        self.page = self.tmp / "denbrowser-newtab.html"
        self.page.write_text(PAGE, encoding="utf-8")
        self.config = self.tmp / "site-config.json"

    def run_gen(self, bookmarks=None, config=None, timeout=None):
        if config is None:
            config = {} if bookmarks is None else {"bookmarks": bookmarks}
        self.config.write_text(json.dumps(config), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.page), str(self.config), str(self.repo)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )

    def shortcuts(self):
        content = self.page.read_text(encoding="utf-8")
        start = content.index("<!-- DEN_SHORTCUTS_START -->")
        end = content.index("<!-- DEN_SHORTCUTS_END -->")
        return content[start:end + len("<!-- DEN_SHORTCUTS_END -->")]

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")

    def assert_error(self, result, *fragments):
        self.assertEqual(result.returncode, 1)
        self.assertTrue(result.stderr.startswith("ERROR: "), result.stderr)
        for fragment in fragments:
            self.assertIn(fragment, result.stderr)
        self.assertEqual(self.page.read_text(encoding="utf-8"), PAGE)

    def write_image(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_no_bookmarks_gives_placeholder(self):
        for config in ({}, {"bookmarks": []}):
            with self.subTest(config=config):
                result = self.run_gen(config=config)
                self.assert_ok(result)
                self.assertEqual(
                    result.stdout,
                    "[build] Injected 0 new-tab shortcut(s) into denbrowser-newtab.html\n",
                )
                self.assertEqual(self.page.read_text(encoding="utf-8"), PAGE)

    def test_missing_config_gives_placeholder(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(self.page), str(self.tmp / "absent.json"),
             str(self.repo)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assert_ok(result)
        self.assertEqual(self.page.read_text(encoding="utf-8"), PAGE)

    def test_letter_badge_tile(self):
        result = self.run_gen([
            {"title": "intranet", "url": "https://intranet.example.com"},
            {"title": "Docs", "url": "https://docs.example.com"},
        ])
        self.assert_ok(result)
        self.assertEqual(
            result.stdout,
            "[build] Injected 2 new-tab shortcut(s) into denbrowser-newtab.html\n",
        )
        expected = PAGE.replace(
            '<p class="den-empty">No shortcuts configured.</p>',
            '<a class="den-tile" target="_self" href="https://intranet.example.com">'
            '<span class="den-badge">I</span><span class="den-label">intranet</span></a>\n'
            '        <a class="den-tile" target="_self" href="https://docs.example.com">'
            '<span class="den-badge">D</span><span class="den-label">Docs</span></a>',
        )
        self.assertEqual(self.page.read_text(encoding="utf-8"), expected)

    def test_each_image_type_embeds_with_mime_type(self):
        for name, (data, mime) in IMAGES.items():
            with self.subTest(type=name):
                self.page.write_text(PAGE, encoding="utf-8")
                self.write_image(self.images / f"icon.{name}", data)
                result = self.run_gen([
                    {"title": "Site", "url": "https://site.example", "image": f"icon.{name}"},
                ])
                self.assert_ok(result)
                encoded = base64.b64encode(data).decode("ascii")
                self.assertIn(
                    '<a class="den-tile" target="_self" href="https://site.example">'
                    f'<img class="den-icon" src="data:{mime};base64,{encoded}" alt="">'
                    '<span class="den-label">Site</span></a>',
                    self.shortcuts(),
                )
                self.assertNotIn("den-badge", self.shortcuts())

    def test_type_is_detected_from_content_not_extension(self):
        self.write_image(self.images / "logo.svg", IMAGES["png"][0])
        result = self.run_gen([
            {"title": "Site", "url": "https://site.example", "image": "logo.svg"},
        ])
        self.assert_ok(result)
        self.assertIn('src="data:image/png;base64,', self.shortcuts())

    def test_bare_filename_resolves_to_shortcut_images(self):
        self.write_image(self.images / "a.png", IMAGES["png"][0])
        self.write_image(self.repo / "a.png", IMAGES["gif"][0])
        result = self.run_gen([{"title": "A", "url": "https://a.example", "image": "a.png"}])
        self.assert_ok(result)
        self.assertIn("data:image/png;base64,", self.shortcuts())

    def test_value_with_separator_is_relative_to_repo_root(self):
        self.write_image(self.repo / "branding" / "a.gif", IMAGES["gif"][0])
        result = self.run_gen([
            {"title": "A", "url": "https://a.example", "image": "branding/a.gif"},
        ])
        self.assert_ok(result)
        self.assertIn("data:image/gif;base64,", self.shortcuts())

    def test_absolute_path_is_used_as_is(self):
        path = self.write_image(self.tmp / "elsewhere" / "a.webp", IMAGES["webp"][0])
        result = self.run_gen([{"title": "A", "url": "https://a.example", "image": str(path)}])
        self.assert_ok(result)
        self.assertIn("data:image/webp;base64,", self.shortcuts())

    def test_missing_image_file(self):
        result = self.run_gen([{"title": "Gone", "url": "https://a.example", "image": "gone.png"}])
        self.assert_error(result, "'Gone'", str(self.images / "gone.png"), "not found")

    def test_unsupported_image_type(self):
        path = self.write_image(self.images / "notes.png", b"just some text\n")
        result = self.run_gen([{"title": "Text", "url": "https://a.example", "image": "notes.png"}])
        self.assert_error(result, "'Text'", str(path), "PNG, JPEG, GIF, WebP, ICO, SVG")

    def test_oversize_image(self):
        data = IMAGES["png"][0]
        path = self.write_image(self.images / "big.png", data + b"\x00" * (262145 - len(data)))
        result = self.run_gen([{"title": "Big", "url": "https://a.example", "image": "big.png"}])
        self.assert_error(result, "'Big'", str(path), "262145 bytes")

    def test_image_at_size_limit_is_accepted(self):
        data = IMAGES["png"][0]
        self.write_image(self.images / "max.png", data + b"\x00" * (262144 - len(data)))
        result = self.run_gen([{"title": "Max", "url": "https://a.example", "image": "max.png"}])
        self.assert_ok(result)

    def test_invalid_image_value(self):
        for value in (42, ["a.png"], {"path": "a.png"}, True):
            with self.subTest(image=value):
                result = self.run_gen([
                    {"title": "Bad", "url": "https://a.example", "image": value},
                ])
                self.assert_error(result, "'Bad'", "must be a string")

    def test_blank_image_keeps_letter_badge(self):
        self.assert_ok(self.run_gen([{"title": "Site", "url": "https://site.example"}]))
        expected = self.page.read_text(encoding="utf-8")
        for value in ("", "   ", None):
            with self.subTest(image=value):
                self.page.write_text(PAGE, encoding="utf-8")
                result = self.run_gen([
                    {"title": "Site", "url": "https://site.example", "image": value},
                ])
                self.assert_ok(result)
                self.assertEqual(self.page.read_text(encoding="utf-8"), expected)

    def assert_rejected_promptly(self, data):
        self.write_image(self.images / "slow.svg", data)
        try:
            result = self.run_gen(
                [{"title": "Slow", "url": "https://a.example", "image": "slow.svg"}],
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            self.fail("SVG detection did not finish within 5 seconds")
        self.assert_error(result, "'Slow'", "not a supported type")

    def test_long_leading_whitespace_rejected_promptly(self):
        self.assert_rejected_promptly(b" \t\r\n" * 2000 + b"not svg")
        self.assert_rejected_promptly(b"\n" * 5000 + b"<svg:svg xmlns:svg='x'/>")

    def test_many_comments_before_non_svg_root_rejected_promptly(self):
        self.assert_rejected_promptly(b"<!-- c -->" * 25000 + b"<html/>")

    def test_svg_with_doctype_internal_subset(self):
        data = (b'<?xml version="1.0"?>\n'
                b'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
                b'"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [\n'
                b'  <!ENTITY ns "http://www.w3.org/2000/svg">\n'
                b'  <!-- ] > -->\n'
                b']>\n'
                b'<svg xmlns="&ns;" viewBox="0 0 1 1"/>\n')
        self.write_image(self.images / "dtd.svg", data)
        result = self.run_gen([{"title": "A", "url": "https://a.example", "image": "dtd.svg"}])
        self.assert_ok(result)
        self.assertIn("data:image/svg+xml;base64,", self.shortcuts())

    def test_title_and_url_are_html_escaped(self):
        result = self.run_gen([
            {"title": "<b>&\"'", "url": "https://a.example/?q=\"<x>&y='z'"},
        ])
        self.assert_ok(result)
        self.assertIn(
            '<a class="den-tile" target="_self" '
            'href="https://a.example/?q=&quot;&lt;x&gt;&amp;y=&#x27;z&#x27;">'
            '<span class="den-badge">&lt;</span>'
            '<span class="den-label">&lt;b&gt;&amp;&quot;&#x27;</span></a>',
            self.shortcuts(),
        )

    def test_backslashes_in_values_are_kept_literally(self):
        result = self.run_gen([{"title": r"C:\new \1", "url": r"https://a.example/\g<0>"}])
        self.assert_ok(result)
        self.assertIn(r'href="https://a.example/\g&lt;0&gt;"', self.shortcuts())
        self.assertIn(r'<span class="den-label">C:\new \1</span>', self.shortcuts())

    def test_non_http_url_rejected(self):
        for url in ("javascript:alert(1)", "chrome://browser/content/", "ftp://a.example"):
            with self.subTest(url=url):
                result = self.run_gen([{"title": "X", "url": url}])
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, f"ERROR: bookmark url must be http(s): {url!r}\n")
                self.assertEqual(self.page.read_text(encoding="utf-8"), PAGE)

    def test_missing_title_or_url_rejected(self):
        result = self.run_gen([{"title": "X"}])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            result.stderr, "ERROR: bookmark entry needs both title and url: {'title': 'X'}\n"
        )

    def test_missing_markers(self):
        self.page.write_text("<html></html>\n", encoding="utf-8")
        result = self.run_gen([{"title": "X", "url": "https://x.example"}])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            result.stderr, f"ERROR: DEN_SHORTCUTS markers not found in {self.page}\n"
        )
        self.assertEqual(self.page.read_text(encoding="utf-8"), "<html></html>\n")

    def test_rerun_on_generated_page_is_stable(self):
        self.write_image(self.images / "a.svg", IMAGES["svg"][0])
        bookmarks = [
            {"title": "A", "url": "https://a.example", "image": "a.svg"},
            {"title": "B", "url": "https://b.example"},
        ]
        self.assert_ok(self.run_gen(bookmarks))
        first = self.page.read_text(encoding="utf-8")
        self.assert_ok(self.run_gen(bookmarks))
        self.assertEqual(self.page.read_text(encoding="utf-8"), first)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Generate the shortcut tiles of the custom new-tab page (patch 018).

Usage: gen-newtab-shortcuts.py PAGE_HTML SITE_CONFIG_JSON REPO_ROOT

Replaces everything between the DEN_SHORTCUTS markers of PAGE_HTML with one
tile per entry of SITE_CONFIG_JSON's "bookmarks" list, or a "No shortcuts
configured." placeholder when the list is empty or the config is absent.

Each bookmark needs "title" and an http(s) "url". An optional "image" replaces
the letter badge with that file, embedded as a data: URI; a blank or null
"image" keeps the badge. It is resolved as:
  - an absolute path: used as is;
  - a value containing a path separator: relative to REPO_ROOT;
  - a bare filename: REPO_ROOT/config/shortcut-images/<name>.
Supported types (detected from content): PNG, JPEG, GIF, WebP, ICO, SVG.
Images are limited to 256 KiB.
"""
import base64
import html
import json
import os
import re
import sys

MAX_IMAGE_BYTES = 256 * 1024
SUPPORTED_TYPES = "PNG, JPEG, GIF, WebP, ICO, SVG"
XML_SPACE = " \t\r\n"


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def skip_doctype(text, i):
    """Return the index just past the DOCTYPE starting at i, or -1."""
    depth = 0
    i += len("<!DOCTYPE")
    while i < len(text):
        c = text[i]
        if c in "\"'":
            i = text.find(c, i + 1)
            if i < 0:
                return -1
        elif text.startswith("<!--", i):
            i = text.find("-->", i + 4)
            if i < 0:
                return -1
            i += 2
        elif c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
        elif c == ">" and depth <= 0:
            return i + 1
        i += 1
    return -1


def is_svg(text):
    """Skip the XML prolog in linear time and check for an <svg> root."""
    i, n = 0, len(text)
    while True:
        while i < n and text[i] in XML_SPACE:
            i += 1
        if text.startswith("<?", i):
            end = text.find("?>", i + 2)
            i = -1 if end < 0 else end + 2
        elif text.startswith("<!--", i):
            end = text.find("-->", i + 4)
            i = -1 if end < 0 else end + 3
        elif text.startswith("<!DOCTYPE", i):
            i = skip_doctype(text, i)
        else:
            break
        if i < 0:
            return False
    return text.startswith("<svg", i) and i + 4 < n and text[i + 4] in XML_SPACE + "/>"


def resolve_image_path(image, repo_root):
    if os.path.isabs(image):
        return image
    separators = {"/", os.sep, os.altsep} - {None}
    if any(sep in image for sep in separators):
        return os.path.join(repo_root, image)
    return os.path.join(repo_root, "config", "shortcut-images", image)


def detect_mime(data):
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data.startswith(b"\x00\x00\x01\x00"):
        return "image/x-icon"
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None
    if is_svg(text):
        return "image/svg+xml"
    return None


def image_data_uri(bookmark, repo_root):
    title, image = bookmark.get("title"), bookmark["image"]
    path = resolve_image_path(image, repo_root)
    if not os.path.isfile(path):
        fail(f"bookmark {title!r}: image file not found: {path}")
    size = os.path.getsize(path)
    if size > MAX_IMAGE_BYTES:
        fail(f"bookmark {title!r}: image {path} is {size} bytes, over the "
             f"{MAX_IMAGE_BYTES}-byte (256 KiB) limit")
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        fail(f"bookmark {title!r}: cannot read image {path}: {e.strerror}")
    mime = detect_mime(data)
    if mime is None:
        fail(f"bookmark {title!r}: image {path} is not a supported type "
             f"(supported: {SUPPORTED_TYPES})")
    return f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"


def main(argv):
    if len(argv) != 4:
        print("Usage: gen-newtab-shortcuts.py PAGE_HTML SITE_CONFIG_JSON REPO_ROOT",
              file=sys.stderr)
        sys.exit(2)
    page_path, site_config_path, repo_root = argv[1], argv[2], argv[3]

    bookmarks = []
    if os.path.isfile(site_config_path):
        with open(site_config_path, encoding="utf-8") as f:
            bookmarks = json.load(f).get("bookmarks", [])

    tiles = []
    for b in bookmarks:
        title, url = b.get("title"), b.get("url")
        if not title or not url:
            print(f"ERROR: bookmark entry needs both title and url: {b!r}",
                  file=sys.stderr)
            sys.exit(1)
        if not re.match(r"^https?://", url, re.IGNORECASE):
            print(f"ERROR: bookmark url must be http(s): {url!r}", file=sys.stderr)
            sys.exit(1)
        image = b.get("image")
        if image is not None and not isinstance(image, str):
            fail(f"bookmark {title!r}: image must be a string: {image!r}")
        if image is not None and image.strip():
            icon = f'<img class="den-icon" src="{image_data_uri(b, repo_root)}" alt="">'
        else:
            badge = html.escape(title.strip()[0].upper())
            icon = f'<span class="den-badge">{badge}</span>'
        # target="_self" forces the click to navigate the current tab. A plain
        # (empty-target) top-level link can be defaulted to a new tab by Gecko
        # (nsDocShell::ShouldOpenInBlankTarget); an explicit non-empty target
        # bypasses that path so the shortcut consumes the tab in use.
        tiles.append(
            f'<a class="den-tile" target="_self" href="{html.escape(url, quote=True)}">'
            f'{icon}'
            f'<span class="den-label">{html.escape(title)}</span></a>'
        )

    inner = ("\n        ".join(tiles) if tiles
             else '<p class="den-empty">No shortcuts configured.</p>')

    start, end = "<!-- DEN_SHORTCUTS_START -->", "<!-- DEN_SHORTCUTS_END -->"
    with open(page_path, encoding="utf-8") as f:
        content = f.read()
    pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.DOTALL)
    replacement = f"{start}\n        {inner}\n        {end}"
    new_content, n = pattern.subn(lambda _: replacement, content)
    if n == 0:
        print(f"ERROR: DEN_SHORTCUTS markers not found in {page_path}",
              file=sys.stderr)
        sys.exit(1)
    with open(page_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(new_content)
    print(f"[build] Injected {len(tiles)} new-tab shortcut(s) into denbrowser-newtab.html")


if __name__ == "__main__":
    main(sys.argv)

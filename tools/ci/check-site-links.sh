#!/usr/bin/env bash
#
# check-site-links.sh — every link in the built documentation site resolves
# (issue #247, F-UX-005/F-UX-012; helper committed under issue #190).
#
# The documentation site shipped links to files that were never published and
# outbound links over plain HTTP. Run it against the jekyll output directory
# (`_site`) or any directory of HTML pages; offline-safe: external links are
# checked for scheme, never fetched.
#
# Checked per <a>/<link>/<script>/<img> reference in each *.html under DIR:
#   - `path` (no scheme, optional ?query) must resolve to an existing file or
#     directory under DIR, relative to the page
#   - `path` ending in `.md` is a violation — published links must target the
#     built `.html` page, not the raw markdown (issue #247, F-UX-001)
#   - `path` ending in `.html` that does not exist falls back to the
#     same-basename `.md` — running against the *source* tree (e.g. `docs/`
#     on trunk) resolves built URLs to their markdown sources
#   - `/path` (site-absolute) resolves under DIR itself; if missing, the first
#     segment is dropped (a Pages `baseurl` prefix such as `/mmt-dpi/`)
#   - `path#frag` / `#frag` — the fragment must exist as id= or name= in the
#     target file (markdown sources: as a heading slug)
#   - `http://` outbound links are violations (HTTPS or nothing); loopback
#     targets (localhost/127.0.0.1/[::1]) are exempt — demo consoles are
#     served over plain HTTP by design
#
# Site-navigation guards (issue #579, F-UX-008/F-UX-009/F-UX-017):
#   - source tree (DIR holds _config.yml): no top-level guide (*.md) carries
#     a literal `[TOC]` line — Python-Markdown syntax kramdown prints as text;
#     use `* TOC` + `{:toc}` — and every one declares `layout: default` and a
#     `title:`, so it renders with the guide layout (docs/_layouts/default.html)
#     and its breadcrumb; every `[label](./page.md)` entry of the docs index
#     (the page with `permalink: /docs/`) names its target's title: label and
#     title, lowercased with punctuation folded to spaces, are equal or one
#     contains the other as whole words
#   - built site (DIR holds docs/index.html, the docs index): no page shows a
#     `<p>[TOC]</p>`, and every page except the landing page (DIR/index.html,
#     its own design) links to the site root and to the docs index
#   Templates under _layouts/ and _includes/ are not pages: their Liquid
#   hrefs are checked through the rendered pages of the built-site pass.
#
# Exit codes: 0 = all links resolve, 1 = broken/unsafe link(s), 2 = helper
# broken (missing dir, no html files).
#
# Usage: bash tools/ci/check-site-links.sh [DIR]     (default: _site)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

DIR="${1:-_site}"

[ -d "$DIR" ] || { echo "✗ site directory not found: $DIR" >&2
                   echo "To fix:  build the site first (jekyll build → _site)," >&2
                   echo "         or point at a directory of HTML pages" >&2
                   exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

python3 - "$DIR" <<'PYEOF'
import glob
import html
import os
import re
import sys

root = sys.argv[1]
pages = sorted(glob.glob(os.path.join(root, "**", "*.html"), recursive=True))
# never scan nested jekyll output, bundled gems (setup-ruby's bundler-cache
# installs under docs/vendor/bundle on CI), caches or VCS dirs — those are
# build artifacts, not site source
SKIP_DIRS = {"_site", "vendor", ".jekyll-cache", ".bundle", ".git",
             "_layouts", "_includes"}
pages = [p for p in pages
         if not SKIP_DIRS.intersection(
             os.path.relpath(p, root).split(os.sep))]
if not pages:
    print(f"✗ no *.html files under {root}", file=sys.stderr)
    sys.exit(2)

ATTR = re.compile(r'(?:href|src)\s*=\s*["\']([^"\']+)["\']', re.I)
ID = re.compile(r'(?:id|name)\s*=\s*["\']([^"\']+)["\']')
HEADING = re.compile(r'^#{1,6}\s+(.+?)\s*#*\s*$', re.M)


def kramdown_slug(text):
    # Jekyll renders headings with kramdown's auto-id rule: strip inline
    # markup, lowercase, drop anything but alnum/space/hyphen, spaces → '-'.
    text = re.sub(r'[`*\[\]()]', '', text)
    text = re.sub(r'[^a-z0-9_ -]', '', text.lower())
    return text.replace(' ', '-')


def anchors_of(target):
    """Anchor ids of a target: id=/name= for HTML, heading slugs for .md."""
    try:
        text = open(target, encoding="utf-8", errors="replace").read()
    except OSError:
        return set()
    if target.endswith(".md"):
        return {kramdown_slug(h) for h in HEADING.findall(text)}
    return set(ID.findall(text))


ids = {}
for page in pages:
    ids[page] = anchors_of(page)

errors = 0


def fail(page, ref, why):
    global errors
    errors += 1
    print(f"  ✗ {page}: {ref} — {why}")


def resolve(page, path):
    """Map a link path to a file under root. Returns (target, None) or
    (None, reason)."""
    if path.startswith("/"):
        # site-absolute: resolve under the checked root; a missing hit may
        # carry a baseurl prefix — retry after dropping the first segment
        cand = os.path.normpath(os.path.join(root, path.lstrip("/")))
        if not os.path.exists(cand) and "/" in path.lstrip("/"):
            cand = os.path.normpath(
                os.path.join(root, path.lstrip("/").split("/", 1)[1]))
        target = cand
    else:
        target = os.path.normpath(os.path.join(os.path.dirname(page), path))

    if os.path.isdir(target):
        return target, None
    if os.path.exists(target):
        if target.endswith(".md"):
            return None, "raw .md target — link the built .html page instead"
        return target, None
    if target.endswith(".html"):
        # source-tree run: the built .html is produced from a .md sibling
        md = target[:-len(".html")] + ".md"
        if os.path.exists(md):
            return md, None
    if path.endswith(".md") or target.endswith(".md"):
        return None, "raw .md target — link the built .html page instead"
    return None, "target file does not exist"


root_real = os.path.normpath(root)
docs_index_dir = os.path.join(root_real, "docs")
links_home = set()
links_docs = set()


def note_nav(page, target):
    """Record a page linking the site root or the docs index (built site)."""
    target = os.path.normpath(target)
    if target in (root_real, os.path.join(root_real, "index.html")):
        links_home.add(page)
    if target in (docs_index_dir, os.path.join(docs_index_dir, "index.html")):
        links_docs.add(page)


for page in pages:
    text = open(page, encoding="utf-8", errors="replace").read()
    for raw in ATTR.findall(text):
        ref = html.unescape(raw).strip()
        if not ref or ref.startswith(("mailto:", "tel:", "javascript:",
                                      "data:")):
            continue
        if re.match(r'https?://', ref):
            if ref.startswith("http://") and not re.match(
                    r'http://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])',
                    ref):
                fail(page, ref, "plain-HTTP outbound link")
            continue
        if "://" in ref:
            continue                       # other schemes — not checked
        path = ref.split("#", 1)[0].split("?", 1)[0]
        frag = ref.partition("#")[2]
        if not path:
            target = page
        else:
            if os.path.splitext(path)[1].lower() == ".md":
                fail(page, ref,
                     "raw .md target — link the built .html page instead")
                continue
            target, err = resolve(page, path)
            if err:
                fail(page, ref, err)
                continue
            note_nav(page, target)
            if os.path.isdir(target):
                continue
        if frag:
            anchors = ids.get(target)
            if anchors is None:
                anchors = anchors_of(target)
            if frag not in anchors:
                fail(page, ref, f"anchor #{frag} not found in {target}")

# --- site-navigation guards (issue #579) ---------------------------------
TOC_MARKER = re.compile(r'^\[TOC\]\s*$', re.M)
FRONT = re.compile(r'\A---\n(.*?)\n---\n', re.S)
INDEX_LINK = re.compile(r'^\s*[*-]\s+\[([^\]]+)\]\(\./([^)#\s]+\.md)\)', re.M)


def front_matter(text):
    """Top-level `key: value` pairs of a page's YAML front matter."""
    m = FRONT.match(text)
    if not m:
        return None
    keys = {}
    for line in m.group(1).splitlines():
        km = re.match(r'^([A-Za-z_][\w-]*):\s*(.*?)\s*$', line)
        if km:
            keys[km.group(1)] = km.group(2).strip('"\'')
    return keys


def words(text):
    return " " + " ".join(re.sub(r'[^a-z0-9]+', " ", text.lower()).split()) + " "


def nav_fail(where, why):
    global errors
    errors += 1
    print(f"  ✗ {where}: {why}")


if os.path.isfile(os.path.join(root, "_config.yml")):
    guides = sorted(glob.glob(os.path.join(root, "*.md")))
    meta = {}
    for guide in guides:
        text = open(guide, encoding="utf-8", errors="replace").read()
        for m in TOC_MARKER.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            nav_fail(f"{guide}:{line}", "literal [TOC] marker kramdown prints"
                     " as text — use `* TOC` + `{:toc}`")
        fm = front_matter(text)
        meta[os.path.basename(guide)] = fm or {}
        if fm is None:
            nav_fail(guide, "no front matter — the page is published raw,"
                     " without the guide layout")
            continue
        if fm.get("layout") != "default":
            nav_fail(guide, "front matter lacks `layout: default` — the page"
                     " misses the site bar and breadcrumb")
        if not fm.get("title"):
            nav_fail(guide, "front matter lacks a `title:`")
    index = [g for g, fm in meta.items() if fm.get("permalink") == "/docs/"]
    if len(index) != 1:
        nav_fail(root, f"expected one docs index (permalink: /docs/), found"
                 f" {len(index)}")
    else:
        index_path = os.path.join(root, index[0])
        text = open(index_path, encoding="utf-8", errors="replace").read()
        for label, target in INDEX_LINK.findall(text):
            title = meta.get(target, {}).get("title")
            if title is None:
                continue                  # missing target: a link failure
            a, b = words(label), words(title)
            if a not in b and b not in a:
                nav_fail(index_path, f"label '{label}' does not name the"
                         f" title of {target} ('{title}')")
elif os.path.isfile(os.path.join(root, "docs", "index.html")):
    landing = os.path.join(root_real, "index.html")
    for page in pages:
        text = open(page, encoding="utf-8", errors="replace").read()
        if "<p>[TOC]</p>" in text:
            nav_fail(page, "renders a literal [TOC] marker")
        if os.path.normpath(page) == landing:
            continue
        if page not in links_home:
            nav_fail(page, "no link to the site root (landing page)")
        if page not in links_docs:
            nav_fail(page, "no link to the docs index (docs/)")

if errors:
    print(f"✗ {errors} broken or unsafe link(s) or navigation gap(s)"
          f" under {root}", file=sys.stderr)
    print("To fix:  publish the target, correct the path/anchor, or use"
          " HTTPS (issue #247); give the guide its layout, title and"
          " {:toc}, or make the docs-index label name the page title"
          " (issue #579)", file=sys.stderr)
    sys.exit(1)
print(f"✓ all links resolve and every guide is navigable across"
      f" {len(pages)} page(s) under {root}")
PYEOF

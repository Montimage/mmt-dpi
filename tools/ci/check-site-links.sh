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
SKIP_DIRS = {"_site", "vendor", ".jekyll-cache", ".bundle", ".git"}
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
            if os.path.isdir(target):
                continue
        if frag:
            anchors = ids.get(target)
            if anchors is None:
                anchors = anchors_of(target)
            if frag not in anchors:
                fail(page, ref, f"anchor #{frag} not found in {target}")

if errors:
    print(f"✗ {errors} broken or unsafe link(s) under {root}",
          file=sys.stderr)
    print("To fix:  publish the target, correct the path/anchor, or use"
          " HTTPS (issue #247)", file=sys.stderr)
    sys.exit(1)
print(f"✓ all links resolve across {len(pages)} page(s) under {root}")
PYEOF

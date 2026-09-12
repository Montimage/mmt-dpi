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
#   - `path` (no scheme) must resolve to an existing file or directory under
#     DIR, relative to the page
#   - `path#frag` / `#frag` — the fragment must exist as id= or name= in the
#     target file
#   - `http://` outbound links are violations (HTTPS or nothing)
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
if not pages:
    print(f"✗ no *.html files under {root}", file=sys.stderr)
    sys.exit(2)

ATTR = re.compile(r'(?:href|src)\s*=\s*["\']([^"\']+)["\']', re.I)
ID = re.compile(r'(?:id|name)\s*=\s*["\']([^"\']+)["\']')

ids = {}
for page in pages:
    ids[page] = set(ID.findall(open(page, encoding="utf-8",
                                    errors="replace").read()))

errors = 0


def fail(page, ref, why):
    global errors
    errors += 1
    print(f"  ✗ {page}: {ref} — {why}")


for page in pages:
    text = open(page, encoding="utf-8", errors="replace").read()
    for raw in ATTR.findall(text):
        ref = html.unescape(raw).strip()
        if not ref or ref.startswith(("mailto:", "tel:", "javascript:",
                                      "data:")):
            continue
        if re.match(r'https?://', ref):
            if ref.startswith("http://"):
                fail(page, ref, "plain-HTTP outbound link")
            continue
        if "://" in ref:
            continue                       # other schemes — not checked
        path, _, frag = ref.partition("#")
        target = page
        if path:
            target = os.path.normpath(os.path.join(os.path.dirname(page),
                                                   path))
            if not os.path.exists(target):
                fail(page, ref, "target file does not exist")
                continue
            if os.path.isdir(target):
                continue
        if frag and target.endswith(".html") and frag not in ids.get(target,
                                                                     set()):
            fail(page, ref, f"anchor #{frag} not found in {target}")

if errors:
    print(f"✗ {errors} broken or unsafe link(s) under {root}",
          file=sys.stderr)
    print("To fix:  publish the target, correct the path/anchor, or use"
          " HTTPS (issue #247)", file=sys.stderr)
    sys.exit(1)
print(f"✓ all links resolve across {len(pages)} page(s) under {root}")
PYEOF

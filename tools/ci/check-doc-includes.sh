#!/usr/bin/env bash
#
# check-doc-includes.sh — keep README's copies of the canonical shared
# fragments in docs/_includes/ byte-identical to their source, and assert the
# documentation site includes the same fragments rather than restating them
# (issue #248, F-UX-011).
#
# README's feature list, quick start and first code sample used to be
# maintained twice — once here, once in docs/index.html — and had already
# drifted (200+ vs 643 protocols). The canonical text now lives once in
# docs/_includes/*.md:
#
#   - README.md embeds it between
#       <!-- begin-shared: docs/_includes/NAME.md -->
#       <!-- end-shared:   docs/_includes/NAME.md -->
#     markers — run with --write after editing a fragment.
#   - docs/index.html pulls it in with {% include NAME.md %} + markdownify
#     (the landing page carries Jekyll front matter so Liquid runs).
#
# This script asserts both halves: the marked README blocks equal the
# fragment byte-for-byte, and index.html references each fragment through an
# include tag instead of a hand copy.
#
#   default (check)  exit 1 when a block differs from its fragment or an
#                    include tag is missing, 0 when in sync.
#   --write          rewrite the marked blocks in place, then exit 0.
#
# Exit codes: 0 = in sync / written, 1 = drift or missing include, 2 = broken.
#
# Usage: bash tools/ci/check-doc-includes.sh [--write]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

WRITE=0
[ "${1:-}" = "--write" ] && WRITE=1

for f in README.md docs/index.html; do
    [ -f "$f" ] || { echo "✗ required file missing: $f" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

if [ "$WRITE" -eq 1 ]; then
    python3 - <<'PYEOF'
import re

readme_path = "README.md"
text = open(readme_path, encoding="utf-8").read()

pat = re.compile(
    r'(<!-- begin-shared: (\S+) -->\n)\n?(.*?)\n?(<!-- end-shared: \2 -->)',
    re.S)

def sync(m):
    frag_path = m.group(2)
    try:
        frag = open(frag_path, encoding="utf-8").read().strip("\n")
    except OSError:
        print(f"  ✗ fragment missing: {frag_path}")
        return m.group(0)
    return f"{m.group(1)}\n{frag}\n\n{m.group(4)}"

out = pat.sub(sync, text)
open(readme_path, "w", encoding="utf-8").write(out)
print("✓ synced shared blocks in README.md")
PYEOF
    exit 0
fi

python3 - <<'PYEOF'
import re
import sys

readme = open("README.md", encoding="utf-8").read()
site = open("docs/index.html", encoding="utf-8").read()

errors = 0
seen = []

pat = re.compile(
    r'<!-- begin-shared: (\S+) -->\n\n?(.*?)\n?<!-- end-shared: \1 -->',
    re.S)

for m in pat.finditer(readme):
    frag_path, block = m.group(1), m.group(2)
    seen.append(frag_path)
    try:
        frag = open(frag_path, encoding="utf-8").read().strip("\n")
    except OSError:
        print(f"  ✗ shared fragment not found: {frag_path}")
        errors += 1
        continue
    if block.strip("\n") == frag:
        print(f"  ✓ README block == {frag_path}")
    else:
        print(f"  ✗ README block differs from {frag_path} "
              f"(run tools/ci/check-doc-includes.sh --write)")
        errors += 1

    # The site must include the same fragment, not restate it.
    tag = "{% include " + frag_path.rsplit("/", 1)[-1] + " %}"
    if tag in site:
        print(f"  ✓ docs/index.html includes {frag_path.rsplit('/', 1)[-1]}")
    else:
        print(f"  ✗ docs/index.html does not include "
              f"{frag_path.rsplit('/', 1)[-1]} — expected `{tag}`")
        errors += 1

if not seen:
    print("✗ no begin-shared/end-shared markers found in README.md",
          file=sys.stderr)
    sys.exit(2)

sys.exit(1 if errors else 0)
PYEOF

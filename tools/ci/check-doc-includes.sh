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
# include tag instead of a hand copy. It also asserts that install commands
# live only in docs/_includes/quick-start.md (issue #577): no install.sh
# command line in README outside its shared blocks, in docs/index.html or in
# docs/*.md (docs/DECISIONS.md, the append-only record, excepted), and the
# landing hero takes its install command from the fragment's hero-install
# block at build time.
#
#   default (check)  exit 1 when a block differs from its fragment, an
#                    include tag is missing or an install command is
#                    restated, 0 when in sync.
#   --write          rewrite the marked blocks in place, then exit 0.
#
# Exit codes: 0 = in sync / written, 1 = drift, missing include or restated
# install command, 2 = broken.
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
import glob
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

# Install commands live only in docs/_includes/quick-start.md (issue #577,
# F-UX-004): no other page restates an install.sh command line. README is
# scanned outside its shared blocks; docs/DECISIONS.md is the append-only
# record, which quotes past commands and is never rewritten.
install_cmd = re.compile(r"(?:curl|wget)\b[^\n]*install\.sh|\b(?:ba)?sh +install\.sh\b")
pages = {"README.md": pat.sub("", readme), "docs/index.html": site}
for path in sorted(glob.glob("docs/*.md")):
    if path != "docs/DECISIONS.md":
        pages[path] = open(path, encoding="utf-8").read()
restated = [(path, n, line.strip())
            for path, text in pages.items()
            for n, line in enumerate(text.splitlines(), 1)
            if install_cmd.search(line)]
for path, n, line in restated:
    where = "outside its shared blocks" if path == "README.md" else f"line {n}"
    print(f"  ✗ {path} ({where}) restates an install command — use the "
          f"docs/_includes/quick-start.md one: {line[:100]}")
    errors += 1
if not restated:
    print("  ✓ install commands appear only in docs/_includes/quick-start.md "
          f"(README outside its shared blocks, docs/index.html, {len(pages) - 2} docs/*.md)")

# The landing hero's install command is the fragment's hero-install block,
# taken at build time rather than copied (issue #577).
if ('split: "<!-- hero-install"' in site
        and 'data-cmd="{{ hero_install | escape }}"' in site
        and "<!-- hero-install" in open("docs/_includes/quick-start.md", encoding="utf-8").read()):
    print("  ✓ docs/index.html takes its hero install command from quick-start.md")
else:
    print("  ✗ docs/index.html's hero install command is not taken from the "
          "hero-install block of docs/_includes/quick-start.md")
    errors += 1

sys.exit(1 if errors else 0)
PYEOF

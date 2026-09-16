#!/usr/bin/env bash
# validate-exported-symbols.sh — regenerate/verify docs/Exported-Symbols.md
# (issue #249, F-DOCS-011; run by the doc-validators job from issue #187).
#
# The document's symbol table drifted twice at once: it listed 1,690 rows for
# a libmmt_core.so that today exports 447 `T` symbols — including rows for
# libmmt_tcpip symbols and the loader's own _init/_fini — and it marked every
# row `public = Y`, a column that described the symbol table itself (nm only
# lists exported symbols) rather than the installed header contract.
#
# The regenerated table keeps every exported `T` symbol but derives `public`
# from header membership: a symbol is public when its (demangled base) name is
# declared in src/mmt_core/public_include/*.h — the set sdk/Makefile installs
# to $(MMT_INC). That is the column's only honest source.
#
#   --check (default)  regenerate the table and fail when the committed file
#                      differs — CI mode.
#   --write            rewrite docs/Exported-Symbols.md in place.
#
# The hand-maintained preamble (deprecation notes etc.) is preserved: only the
# rows under the `| # | symbol | public |` table header are regenerated.
# A ten-symbol sample of the rows marked public is re-resolved against the
# public headers on every run — the check the audit's sample failed.
#
# Needs the built library; when sdk/lib/libmmt_core.so* is absent the script
# builds just that target (make -C sdk <abs path to libmmt_core.so>).
#
# Exit codes: 0 = in sync / written, 1 = table drifted, 2 = validator broken.
#
# Usage: bash scripts/validate-exported-symbols.sh [--check|--write]

set -euo pipefail

MODE="${1:---check}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DOC="docs/Exported-Symbols.md"
[ -f "$DOC" ] || { echo "✗ $DOC missing" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }
command -v nm >/dev/null 2>&1 || { echo "✗ nm is required (binutils)" >&2; exit 2; }

case "$MODE" in
    --check|--write) ;;
    *) echo "Usage: $0 [--check|--write]" >&2; exit 2 ;;
esac

LIB=""
for cand in sdk/lib/libmmt_core.so sdk/lib/libmmt_core.so.*; do
    [ -e "$cand" ] && { LIB="$cand"; break; }
done
if [ -z "$LIB" ]; then
    echo "  sdk/lib/libmmt_core.so* not found — building that target only"
    make -C sdk "$ROOT/sdk/lib/libmmt_core.so" >/dev/null
    for cand in sdk/lib/libmmt_core.so sdk/lib/libmmt_core.so.*; do
        [ -e "$cand" ] && { LIB="$cand"; break; }
    done
fi
[ -n "$LIB" ] || { echo "✗ could not build sdk/lib/libmmt_core.so" >&2; exit 2; }

python3 - "$DOC" "$LIB" "$MODE" <<'PYEOF'
import re
import subprocess
import sys

doc_path, lib, mode = sys.argv[1], sys.argv[2], sys.argv[3]

# --- declared public names: src/mmt_core/public_include/*.h ----------------
import glob
text = ""
for h in sorted(glob.glob("src/mmt_core/public_include/*.h")):
    text += open(h, encoding="utf-8", errors="replace").read() + "\n"
text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
text = re.sub(r"//[^\n]*", "", text)
decls = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", text))
decls |= set(m.group(1) for m in
             re.finditer(r"\b(?:extern|MMTAPI)\b[^;{}()]*?\b([A-Za-z_]\w*)\s*;",
                         text))
if not decls:
    print("✗ no declarations parsed from src/mmt_core/public_include/",
          file=sys.stderr)
    sys.exit(2)

# --- exported T symbols of the built libmmt_core ---------------------------
out = subprocess.run(["nm", "-gC", "--defined-only", lib],
                     capture_output=True, text=True)
if out.returncode != 0:
    print(f"✗ nm failed on {lib}: {out.stderr.strip()}", file=sys.stderr)
    sys.exit(2)
syms = sorted(l.split(" T ", 1)[1].strip()
              for l in out.stdout.splitlines() if " T " in l)
if not syms:
    print(f"✗ no T symbols in {lib}", file=sys.stderr)
    sys.exit(2)

# --- regenerate the table under the existing preamble ----------------------
src = open(doc_path, encoding="utf-8").read()
m = re.search(r"^\| #\s*\| symbol \| public \|.*$", src, re.M)
if not m:
    print("✗ symbol-table header not found in the doc", file=sys.stderr)
    sys.exit(2)
head_end = src.find("\n", m.end())
sep = src[head_end + 1:src.find("\n", head_end + 1)]
if not re.match(r"^\|[-:| ]+\|?\s*$", sep):
    print("✗ table separator line not found after the header", file=sys.stderr)
    sys.exit(2)
preamble = src[:src.find("\n", head_end + 1) + 1]

rows = []
n_public = 0
for i, s in enumerate(syms, 1):
    base = s.split("(", 1)[0].strip()
    public = base in decls
    n_public += public
    rows.append(f"|{i}|`{s}`|{'**Y**' if public else 'N'}|")
generated = preamble + "\n".join(rows) + "\n"

# --- ten-symbol sample of the public rows must resolve ---------------------
pub_syms = [s for s in syms if s.split("(", 1)[0].strip() in decls]
if not pub_syms:
    print("✗ no exported symbol resolves to a public header", file=sys.stderr)
    sys.exit(2)
step = max(1, len(pub_syms) // 10)
sample = pub_syms[::step][:10]
unresolved = [s for s in sample
              if s.split("(", 1)[0].strip() not in decls]
if unresolved:
    print(f"✗ public sample does not resolve in public headers: {unresolved}",
          file=sys.stderr)
    sys.exit(1)
print(f"  ✓ ten-symbol public sample resolves: {', '.join(sample)}")

for loader in ("_init", "_fini"):
    if loader in syms and loader.split("(", 1)[0] in decls:
        print(f"✗ loader symbol `{loader}` marked public", file=sys.stderr)
        sys.exit(1)

if mode == "--write":
    open(doc_path, "w", encoding="utf-8").write(generated)
    print(f"  wrote {doc_path}: {len(syms)} exported symbols, "
          f"{n_public} public (header-declared)")
    sys.exit(0)

if generated == src:
    print(f"✓ {doc_path} is in sync ({len(syms)} exported symbols, "
          f"{n_public} public)")
    sys.exit(0)
print(f"✗ {doc_path} is stale — regenerate with:", file=sys.stderr)
print(f"      bash scripts/validate-exported-symbols.sh --write", file=sys.stderr)
sys.exit(1)
PYEOF

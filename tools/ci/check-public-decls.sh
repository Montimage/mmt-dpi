#!/usr/bin/env bash
#
# check-public-decls.sh — every public declaration resolves to a definition
# (issue #229, F-DEAD-005; helper committed under issue #190).
#
# A declaration in a public header with no definition anywhere is a link
# error waiting for the first caller — and it shipped, so the header is a
# contract the library does not honour.
#
# What it checks: every `MMTAPI … MMTCALL name(…)` declaration in
# src/mmt_core/public_include/*.h resolves to a function definition in the
# tracked sources under src/. With --libs DIR (or when built libraries are
# found under sdk/lib or $MMT_BASE/dpi/lib) the same names are additionally
# checked against `nm -D` output — the check the task record asks for.
# It also fails when a declaration with an unsigned return type has a
# definition that returns -1 (issue #546, F-CLEAN-020).
#
# With --list it only prints the declared names, sorted and unique, one per
# line — the set tools/ci/check-api-contracts.sh compares the public-API
# contract table against (issue #525). It exits 2 when an MMTAPI declaration
# lacks the MMTCALL marker, which the name set would otherwise miss.
#
# Exit codes: 0 = all declarations resolve, 1 = unresolved declaration(s)
#             or an unsigned public function returning -1,
#             2 = helper broken (also: --list parsed no declaration).
#
# Usage: bash tools/ci/check-public-decls.sh [--libs DIR | --list]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

LIBS_DIR=""
LIST_ONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --libs) LIBS_DIR="${2:?--libs needs a directory}"; shift ;;
        --list) LIST_ONLY=1 ;;
        *)      echo "✗ unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }
ls src/mmt_core/public_include/*.h >/dev/null 2>&1 \
    || { echo "✗ src/mmt_core/public_include/*.h not found" >&2; exit 2; }

# Auto-detect built libraries when --libs was not given.
if [ -z "$LIBS_DIR" ] && [ "$LIST_ONLY" -eq 0 ]; then
    for cand in sdk/lib "${MMT_BASE:-/opt/mmt}/dpi/lib"; do
        if ls "$cand"/*.so* >/dev/null 2>&1; then
            LIBS_DIR="$cand"
            break
        fi
    done
fi

python3 - "$LIBS_DIR" "$LIST_ONLY" <<'PYEOF'
import glob
import re
import subprocess
import sys

libs_dir = sys.argv[1]
list_only = sys.argv[2] == "1"

text = ""
for h in glob.glob("src/mmt_core/public_include/*.h"):
    text += open(h, encoding="utf-8", errors="replace").read() + "\n"
text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
text = re.sub(r"//[^\n]*", "", text)

# Public declarations: `MMTAPI <rettype> MMTCALL name( ... );`
decls = sorted(set(
    m.group(1)
    for m in re.finditer(r"\bMMTAPI\b[^;{}]*?\bMMTCALL\b[^;{}]*?\b"
                         r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", text, re.S)))
if not decls:
    # Fallback for headers without the MMTCALL marker.
    decls = sorted(set(
        m.group(1)
        for m in re.finditer(r"\bMMTAPI\b[^;{}]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                             text, re.S)))
    decls = [d for d in decls if d not in ("__declspec", "deprecated")]
if not decls:
    print("✗ no public declarations parsed — did the MMTAPI markers move?",
          file=sys.stderr)
    sys.exit(2)

if list_only:
    # MMTCALL is defined empty (mmt_exports.h), so `MMTAPI int foo(void);`
    # compiles and exports foo yet escapes the MMTCALL match above — and
    # with it the contract check (issue #525). Match MMTAPI alone, outside
    # preprocessor lines (the macro definitions), and refuse a list that
    # would drop a name: exit 2 aborts tests/core_engine/run_tests.sh
    # (set -e) instead of emitting a union that hides the missing marker.
    no_pp = re.sub(r"^[ \t]*#(?:[^\n]*\\\n)*[^\n]*", "", text, flags=re.M)
    mmtapi = set(
        m.group(1)
        for m in re.finditer(r"\bMMTAPI\b[^;{}]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                             no_pp, re.S)) - {"__declspec", "deprecated"}
    unmarked = sorted(mmtapi - set(decls))
    if unmarked:
        print("✗ MMTAPI declaration(s) without MMTCALL: " + " ".join(unmarked),
              file=sys.stderr)
        print("To fix:  declare them as `MMTAPI <type> MMTCALL name(...)`",
              file=sys.stderr)
        sys.exit(2)
    print("\n".join(decls))
    sys.exit(0)

src = ""
for c in glob.glob("src/**/*.c", recursive=True) + \
        glob.glob("src/**/*.cpp", recursive=True):
    src += open(c, encoding="utf-8", errors="replace").read() + "\n"

missing = []
for name in decls:
    # A definition has a body: `name( <not-ending-in-;> ) {`. Calls and
    # prototypes end in `;` so they cannot satisfy this pattern.
    if not re.search(r"\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", src):
        missing.append(name)

if missing:
    print(f"✗ {len(missing)} public declaration(s) resolve to no definition:",
          file=sys.stderr)
    for n in missing:
        print(f"      {n}", file=sys.stderr)
    print("To fix:  implement the declaration or delete it from the public"
          " header (issue #229)", file=sys.stderr)
    sys.exit(1)

print(f"✓ all {len(decls)} public declarations resolve to a definition")

# Issue #546 (F-CLEAN-020): a public function with an unsigned return type
# must not `return -1` — the caller sees UINT_MAX/UINT64_MAX under a contract
# that reads "-1". Return a named sentinel (MMT_NO_PROTO_ID, ...) instead.
# Flags a literal `return -1;` and a local initialised to -1 that is returned.
decl_text = re.sub(r"^[ \t]*#(?:[^\n]*\\\n)*[^\n]*", "", text, flags=re.M)
rettype = {
    m.group(2): " ".join(m.group(1).split())
    for m in re.finditer(r"\bMMTAPI\b([^;{}]*?)\bMMTCALL\b\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                         decl_text, re.S)}
unsigned_re = re.compile(r"\b(unsigned|uint(8|16|32|64)_t|size_t|mmt_proto_id_t)\b")
src_nc = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
src_nc = re.sub(r"//[^\n]*", "", src_nc)
neg1 = r"\(?\s*-\s*1\s*\)?"
minus_one = []
for name, rt in sorted(rettype.items()):
    if "*" in rt or not unsigned_re.search(rt):
        continue
    # A definition starts its line with the return type; a call opening a
    # block (`if (fn(x)) {`) does not, so a caller's body is never scanned.
    for m in re.finditer(r"(?m)^[A-Za-z_][^\n;{}()=]*\b" + re.escape(name)
                         + r"\s*\([^;{}]*\)\s*\{", src_nc):
        depth, end = 0, len(src_nc)
        for j in range(m.end() - 1, len(src_nc)):
            if src_nc[j] == "{":
                depth += 1
            elif src_nc[j] == "}":
                depth -= 1
                if depth == 0:
                    end = j + 1
                    break
        body = src_nc[m.end() - 1:end]
        hit = re.search(r"\breturn\s*" + neg1 + r"\s*;", body) is not None
        for var in set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*" + neg1 + r"\s*[;,]", body)):
            if re.search(r"\breturn\s*\(?\s*" + re.escape(var) + r"\s*\)?\s*;", body):
                hit = True
        if hit:
            minus_one.append(f"{name} ({rt})")
            break
if minus_one:
    print(f"✗ {len(minus_one)} public function(s) with an unsigned return type return -1:",
          file=sys.stderr)
    for n in minus_one:
        print(f"      {n}", file=sys.stderr)
    print("To fix:  return a named sentinel of the return type instead (issue #546)",
          file=sys.stderr)
    sys.exit(1)
print("✓ no public function with an unsigned return type returns -1")

# Optional stronger pass: every declared symbol must also be *exported* by a
# built shared library (nm -D), not merely defined somewhere in the tree.
if libs_dir:
    defined = set()
    for so in sorted(glob.glob(libs_dir.rstrip("/") + "/*.so*")):
        try:
            out = subprocess.run(["nm", "-D", "--defined-only", so],
                                 capture_output=True, text=True, check=False)
        except OSError:
            continue
        for line in out.stdout.splitlines():
            parts = line.split()
            if parts:
                defined.add(parts[-1])
    if not defined:
        print(f"✗ no dynamic symbols found under {libs_dir}", file=sys.stderr)
        sys.exit(2)
    unexported = [n for n in decls if n not in defined]
    if unexported:
        print(f"✗ {len(unexported)} declaration(s) not exported by the built"
              f" libraries under {libs_dir}:", file=sys.stderr)
        for n in unexported:
            print(f"      {n}", file=sys.stderr)
        sys.exit(1)
    print(f"✓ all declarations are exported by the libraries in {libs_dir}")
PYEOF

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
# Export budget (issue #533): MMTAPI is libmmt_core's export marker — the core
# is built -fvisibility=hidden (rules/common.mk). The MMTAPI declaration set is
# every distinct name declared with the MMTAPI token, functions and data, in
# src/mmt_core/public_include/*.h and src/mmt_core/private_include/*.h
# (comments and preprocessor lines ignored). The check fails when
# `nm -D --defined-only` of the built library lists more than that count + 5
# symbols, or any symbol outside the set (the loader's _init/_fini aside), and
# also when a name of the set is missing from that list — an MMTAPI
# declaration whose definition was compiled hidden (its translation unit did
# not see the MMTAPI declaration) would otherwise vanish silently.
#
# Protocol plugins (issue #534): libmmt_tcpip, libmmt_tmobile,
# libmmt_business_app and libmmt_tdicom are built -fvisibility=hidden as well
# and export only their MMTAPI declarations. Each has a `## libmmt_<name>`
# section in the doc with a `| symbol |` table, and the check fails unless
# that table lists exactly the symbols `nm -D --defined-only` reports for the
# library (the loader's _init/_fini and the linker's _edata/_end/__bss_start
# aside). Every symbol added or removed is named. An intentional change is
# recorded by regenerating the table with --write, so a pull request that
# changes a plugin's export set without updating the doc fails CI. The
# fixture self-test is tools/ci/tests/test-exported-symbols.sh.
#
# Needs the built libraries; when one is absent from sdk/lib the script
# builds just the missing targets (make -C sdk <abs path to libmmt_<name>.so>).
#
# Environment (for the fixture self-test):
#   MMT_EXPORTS_LIB_DIR  library directory (default sdk/lib). When set, a
#                        missing library is an error (exit 2), never built.
#   MMT_EXPORTS_DOC      the document (default docs/Exported-Symbols.md).
#   MMT_EXPORTS_LIBS     libraries to check, space-separated, out of
#                        core tcpip tmobile business_app tdicom (default: all).
#
# Exit codes: 0 = in sync / written, 1 = table drifted, export budget
#             exceeded, an MMTAPI declaration not exported, or a plugin's
#             exports differ from its section, 2 = validator broken.
#
# Usage: bash scripts/validate-exported-symbols.sh [--check|--write]

set -euo pipefail

MODE="${1:---check}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DOC="${MMT_EXPORTS_DOC:-docs/Exported-Symbols.md}"
LIB_DIR="${MMT_EXPORTS_LIB_DIR:-sdk/lib}"
read -r -a LIBS <<< "${MMT_EXPORTS_LIBS:-core tcpip tmobile business_app tdicom}"
[ -f "$DOC" ] || { echo "✗ $DOC missing" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }
command -v nm >/dev/null 2>&1 || { echo "✗ nm is required (binutils)" >&2; exit 2; }

case "$MODE" in
    --check|--write) ;;
    *) echo "Usage: $0 [--check|--write]" >&2; exit 2 ;;
esac
[ "${#LIBS[@]}" -gt 0 ] || { echo "✗ MMT_EXPORTS_LIBS names no library" >&2; exit 2; }
for name in "${LIBS[@]}"; do
    case "$name" in
        core|tcpip|tmobile|business_app|tdicom) ;;
        *) echo "✗ unknown library in MMT_EXPORTS_LIBS: $name" >&2; exit 2 ;;
    esac
done

# find_lib NAME prints LIB_DIR/libmmt_NAME.so (or its versioned file).
find_lib() {
    local cand
    for cand in "$LIB_DIR/libmmt_$1.so" "$LIB_DIR"/libmmt_"$1".so.*; do
        [ -e "$cand" ] && { echo "$cand"; return 0; }
    done
    return 1
}

missing=()
for name in "${LIBS[@]}"; do
    find_lib "$name" >/dev/null || missing+=("$name")
done
if [ "${#missing[@]}" -gt 0 ]; then
    if [ -n "${MMT_EXPORTS_LIB_DIR:-}" ]; then
        echo "✗ library not found in $LIB_DIR: ${missing[*]}" >&2
        exit 2
    fi
    targets=()
    for name in "${missing[@]}"; do targets+=("$ROOT/sdk/lib/libmmt_$name.so"); done
    echo "  not built in sdk/lib: ${missing[*]} — building those targets only"
    make -C sdk -j"$(nproc 2>/dev/null || echo 2)" "${targets[@]}" >/dev/null
fi
LIB_ARGS=()
for name in "${LIBS[@]}"; do
    lib="$(find_lib "$name")" || { echo "✗ could not build $LIB_DIR/libmmt_$name.so" >&2; exit 2; }
    LIB_ARGS+=("$name=$lib")
done

python3 - "$DOC" "$MODE" "${LIB_ARGS[@]}" <<'PYEOF'
import re
import subprocess
import sys

doc_path, mode = sys.argv[1], sys.argv[2]
libs = dict(a.split("=", 1) for a in sys.argv[3:])
src = open(doc_path, encoding="utf-8").read()
generated = src
budget_ok = True
plugins_ok = True
n_syms = n_public = 0

if "core" in libs:
    lib = libs["core"]
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
    # The table ends at the first line that is not a row; the plugin sections
    # (issue #534) follow it.
    rest = src[len(preamble):]
    rows_end = 0
    for line in rest.splitlines(keepends=True):
        if not line.startswith("|"):
            break
        rows_end += len(line)
    tail = rest[rows_end:]

    rows = []
    n_public = 0
    for i, s in enumerate(syms, 1):
        base = s.split("(", 1)[0].strip()
        public = base in decls
        n_public += public
        rows.append(f"|{i}|`{s}`|{'**Y**' if public else 'N'}|")
    generated = preamble + "\n".join(rows) + "\n" + tail
    n_syms = len(syms)

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

    # --- export set: dynamic exports == MMTAPI declarations (issue #533) -------
    LOADER = {"_init", "_fini"}
    NON_NAMES = {"__attribute__", "__declspec", "deprecated", "visibility"}
    api_text = ""
    for h in sorted(glob.glob("src/mmt_core/public_include/*.h") +
                    glob.glob("src/mmt_core/private_include/*.h")):
        api_text += open(h, encoding="utf-8", errors="replace").read() + "\n"
    api_text = re.sub(r"/\*.*?\*/", "", api_text, flags=re.S)
    api_text = re.sub(r"//[^\n]*", "", api_text)
    api_text = re.sub(r"^[ \t]*#(?:[^\n]*\\\n)*[^\n]*", "", api_text, flags=re.M)
    api_text = re.sub(r"__attribute__\s*\(\((?:[^()]|\([^()]*\))*\)\)", "",
                      api_text)
    api = set(m.group(1) for m in
              re.finditer(r"\bMMTAPI\b[^;{}]*?\b([A-Za-z_]\w*)\s*\(", api_text))
    api |= set(m.group(1) for m in
               re.finditer(r"\bMMTAPI\b[^;{}()]*?\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*;",
                           api_text))
    api -= NON_NAMES
    if not api:
        print("✗ no MMTAPI declaration parsed from src/mmt_core/*_include/",
              file=sys.stderr)
        sys.exit(2)
    dyn = subprocess.run(["nm", "-D", "--defined-only", lib],
                         capture_output=True, text=True)
    if dyn.returncode != 0:
        print(f"✗ nm -D failed on {lib}: {dyn.stderr.strip()}", file=sys.stderr)
        sys.exit(2)
    exports = sorted(set(l.split()[-1] for l in dyn.stdout.splitlines()
                         if l.split()))
    budget = len(api) + 5
    leaked = [s for s in exports if s not in api and s not in LOADER]
    missing = sorted(api - set(exports))
    print(f"  exports: {len(exports)} dynamic symbols; MMTAPI declarations: "
          f"{len(api)} (budget {budget})")
    if len(exports) > budget:
        print(f"✗ {lib} exports {len(exports)} symbols, over the budget of "
              f"{budget} (MMTAPI declarations + 5)", file=sys.stderr)
        budget_ok = False
    if leaked:
        print(f"✗ {len(leaked)} exported symbol(s) not declared MMTAPI:",
              file=sys.stderr)
        for s in leaked:
            print(f"      {s}", file=sys.stderr)
        budget_ok = False
    if leaked or len(exports) > budget:
        print("To fix:  declare the symbol MMTAPI in a src/mmt_core header, or "
              "keep it hidden (issue #533)", file=sys.stderr)
    if missing:
        print(f"✗ {len(missing)} MMTAPI declaration(s) not exported by {lib}:",
              file=sys.stderr)
        for s in missing:
            print(f"      {s}", file=sys.stderr)
        print("To fix:  include the declaring header in the defining source file "
              "so the definition gets default visibility, or drop the MMTAPI "
              "declaration (issue #533)", file=sys.stderr)
        budget_ok = False
    if budget_ok:
        print("  ✓ every export is an MMTAPI declaration and every MMTAPI "
              "declaration is exported, within the budget")


# --- protocol plugins: exports == their doc section (issue #534) ----------
PLUGIN_IGNORED = {"_init", "_fini", "_edata", "_end", "__bss_start"}


def plugin_section(text, name):
    """Return (rows_start, rows_end, documented symbols) of the `| symbol |`
    table under `## libmmt_<name>`, or None when the section or its table is
    missing."""
    head = re.search(rf"^## libmmt_{re.escape(name)}[ \t]*$", text, re.M)
    if not head:
        return None
    nxt = re.search(r"^## ", text[head.end():], re.M)
    sec_end = head.end() + nxt.start() if nxt else len(text)
    tab = re.search(r"^\| symbol \|[ \t]*\n\|[-:| ]+\|?[ \t]*\n",
                    text[head.end():sec_end], re.M)
    if not tab:
        return None
    rows_start = head.end() + tab.end()
    rows_end, documented = rows_start, []
    for line in text[rows_start:sec_end].splitlines(keepends=True):
        if not line.startswith("|"):
            break
        m = re.match(r"^\|\s*`([^`]+)`\s*\|", line)
        if m:
            documented.append(m.group(1))
        rows_end += len(line)
    return rows_start, rows_end, documented


for name in ("tcpip", "tmobile", "business_app", "tdicom"):
    if name not in libs:
        continue
    lib = libs[name]
    dyn = subprocess.run(["nm", "-D", "--defined-only", lib],
                         capture_output=True, text=True)
    if dyn.returncode != 0:
        print(f"✗ nm -D failed on {lib}: {dyn.stderr.strip()}", file=sys.stderr)
        sys.exit(2)
    exports = sorted(set(l.split()[-1] for l in dyn.stdout.splitlines()
                         if l.split()) - PLUGIN_IGNORED)
    rows = "".join(f"|`{e}`|\n" for e in exports)
    sec = plugin_section(generated, name)
    if sec is None:
        print(f"✗ {doc_path} has no `## libmmt_{name}` section with a "
              f"`| symbol |` table", file=sys.stderr)
        print("To fix:  bash scripts/validate-exported-symbols.sh --write "
              "appends it (issue #534)", file=sys.stderr)
        plugins_ok = False
        generated = (generated.rstrip("\n") + f"\n\n## libmmt_{name}\n\n"
                     "| symbol |\n|:-|\n" + rows)
        continue
    rows_start, rows_end, documented = sec
    added = sorted(set(exports) - set(documented))
    removed = sorted(set(documented) - set(exports))
    generated = generated[:rows_start] + rows + generated[rows_end:]
    if (added or removed) and mode == "--write":
        print(f"  recording the changed export set of libmmt_{name}:")
        for e in added:
            print(f"      + {e}")
        for e in removed:
            print(f"      - {e}")
    elif added or removed:
        plugins_ok = False
        print(f"✗ {lib} exports differ from the libmmt_{name} section of "
              f"{doc_path}:", file=sys.stderr)
        for e in added:
            print(f"      + {e}  (exported, not recorded)", file=sys.stderr)
        for e in removed:
            print(f"      - {e}  (recorded, no longer exported)",
                  file=sys.stderr)
        print("To fix:  keep the symbol hidden (only MMTAPI declarations "
              "are exported), or record the change with "
              "`bash scripts/validate-exported-symbols.sh --write` "
              "(issue #534)", file=sys.stderr)
    else:
        print(f"  ✓ libmmt_{name}: {len(exports)} exports, as recorded")

if mode == "--write":
    open(doc_path, "w", encoding="utf-8").write(generated)
    print(f"  wrote {doc_path}: {n_syms} exported core symbols, "
          f"{n_public} public (header-declared), and the plugin tables")
    sys.exit(0 if budget_ok else 1)

if generated == src:
    if plugins_ok:
        print(f"✓ {doc_path} is in sync ({n_syms} exported core symbols, "
              f"{n_public} public)")
    sys.exit(0 if budget_ok and plugins_ok else 1)
print(f"✗ {doc_path} is stale — regenerate with:", file=sys.stderr)
print(f"      bash scripts/validate-exported-symbols.sh --write", file=sys.stderr)
sys.exit(1)
PYEOF

#!/usr/bin/env bash
# validate-doc-drift.sh — Check-only validation for the drift class issue
# #249 closed (F-DOCS-004/010/013/014/018, F-CLEAN-019).
# Usage: ./validate-doc-drift.sh [--check] [--run-destructive]
#
# What it asserts, one check per recorded finding:
#
#   F-DOCS-004  docs/troubleshooting.md carries a correcting entry whose
#               statement of NDEBUG's semantics matches rules/common.mk
#               (the default build defines -DNDEBUG; NDEBUG=1 suppresses it).
#   F-DOCS-010  DEB_PACKAGE_CHECKLIST.md no longer sits at the root posing as
#               current status; the moved copy under docs/ carries a dated
#               header naming the version it describes (1.7.10) and the
#               library the original report omitted (libmmt_tdicom).
#   F-DOCS-013  every `gcc -o BIN` in docs/Examples.md is followed by run
#               commands that invoke ./BIN — never a different binary.
#   F-DOCS-018  every src/examples/*.c file is named on the page, and the
#               page either compiles each one or states it covers a subset.
#   F-DOCS-014  the unsupported-platform instruction blocks (Homebrew
#               formulas, ARCH=osx/win32/win64 builds, /opt/windows staging)
#               are gone from Compilation-and-Installation-Instructions.md,
#               and docs/DECISIONS.md records the deletion.
#   F-CLEAN-019 tools/ci/vendor-paths.txt lists the vendored sources, each
#               carries a VENDORED banner with a pinned upstream reference,
#               and the clean-code metrics read the list — exclusion by
#               configuration, not convention.
#
# Same check-only contract as the other scripts/validate-*.sh: findings are
# reported, the script exits non-zero when any check fails.
#
# Exit codes: 0 = consistent, N = number of failed checks, 2 = broken.

set -euo pipefail

MODE="${1:---check}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ERRORS=0

check() {
    local desc="$1"
    local cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
        echo "  ✓ $desc"
    else
        echo "  ✗ $desc"
        ERRORS=$((ERRORS + 1))
    fi
}

if [ "$MODE" = "--run-destructive" ]; then
    echo "Running in destructive mode (not implemented for this script)."
    exit 0
fi

if [ "$MODE" != "--check" ]; then
    echo "Usage: $0 [--check] [--run-destructive]"
    exit 1
fi

command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

echo "=== doc-drift validation (issue #249) ==="

# --- F-DOCS-004: troubleshooting log correction -----------------------------
echo ""
echo "-- F-DOCS-004: NDEBUG semantics --"

# The rule file's own statement of the semantics: an `ifdef NDEBUG` block in
# which -DNDEBUG is added only on the else (default) side.
check "rules/common.mk: default build defines -DNDEBUG, NDEBUG=1 suppresses it" \
      "awk '/^ifdef NDEBUG/{f=1} f{print} f&&/^endif/{exit}' rules/common.mk \
          | grep -Eq '^else' \
       && awk '/^ifdef NDEBUG/{f=1} f{print} f&&/^endif/{exit}' rules/common.mk \
          | awk '/^else/{e=1} e&&/-DNDEBUG/{d=1} END{exit !(e&&d)}'"

# The correcting entry lives in the newest dated section of the append-only
# log and must state the suppress semantics against -DNDEBUG.
check "docs/troubleshooting.md carries a correcting NDEBUG entry" \
      "awk '/^## /{sec=\$0} /NDEBUG=1/{if (sec != \"## 2026-07-21\") print}' \
          docs/troubleshooting.md | grep -q 'suppress' \
       && awk '/^## /{sec=\$0} /suppress/{if (sec != \"## 2026-07-21\") print}' \
          docs/troubleshooting.md | grep -q -- '-DNDEBUG'"

# --- F-DOCS-010: DEB_PACKAGE_CHECKLIST.md ------------------------------------
echo ""
echo "-- F-DOCS-010: .deb checklist --"

check "DEB_PACKAGE_CHECKLIST.md is no longer at the repo root" \
      "test ! -f DEB_PACKAGE_CHECKLIST.md"
check "docs/DEB_PACKAGE_CHECKLIST.md exists with Jekyll front matter" \
      "head -4 docs/DEB_PACKAGE_CHECKLIST.md | grep -q 'layout: default'"
check "dated header names the described version (1.7.10)" \
      "sed -n '1,16p' docs/DEB_PACKAGE_CHECKLIST.md | grep -Eq '20[0-9]{2}-[0-9]{2}-[0-9]{2}' \
       && sed -n '1,16p' docs/DEB_PACKAGE_CHECKLIST.md | grep -q '1\.7\.10'"
check "dated header names the omitted library (libmmt_tdicom)" \
      "sed -n '1,16p' docs/DEB_PACKAGE_CHECKLIST.md | grep -q 'libmmt_tdicom'"

# --- F-DOCS-013 / F-DOCS-018: docs/Examples.md --------------------------------
echo ""
echo "-- F-DOCS-013/018: Examples.md --"

if ! python3 - <<'PYEOF'
import glob
import os
import re
import sys

errors = 0

doc = open("docs/Examples.md", encoding="utf-8").read()

# F-DOCS-013: inside ```sh fences, every `gcc -o BIN` sets the expected run
# binary; every `./X` (optionally via sudo) run line must invoke it.
compiled = None
pairs = 0
in_sh = False
for n, line in enumerate(doc.splitlines(), 1):
    if re.match(r"^```\s*sh\s*$", line):
        in_sh = True
        continue
    if in_sh and line.startswith("```"):
        in_sh = False
        continue
    if not in_sh:
        continue
    m = re.search(r"\bgcc\b[^#]*?\s-o\s+([A-Za-z0-9_.-]+)", line)
    if m:
        compiled = m.group(1)
        continue
    m = re.match(r"^\s*(?:sudo\s+)?\./([A-Za-z0-9_.-]+)", line)
    if m:
        pairs += 1
        if compiled is None or m.group(1) != compiled:
            errors += 1
            print(f"  ✗ line {n}: runs './{m.group(1)}' but the compile step "
                  f"produced '{compiled}'")
if pairs == 0:
    errors += 1
    print("  ✗ no compile/run pairs found in docs/Examples.md")
elif errors == 0:
    print(f"  ✓ all {pairs} run command(s) invoke the binary the preceding "
          f"compile step produced")

# F-DOCS-018: every example source is named on the page, and the page either
# compiles each one or says it covers a subset.
examples = sorted(os.path.basename(p)
                  for p in glob.glob("src/examples/*.c"))
if not examples:
    print("  ✗ no src/examples/*.c found", file=sys.stderr)
    sys.exit(2)
unnamed = [e for e in examples if e not in doc]
if unnamed:
    errors += 1
    print(f"  ✗ example source(s) not named in docs/Examples.md: {unnamed}")
else:
    print(f"  ✓ all {len(examples)} src/examples/*.c files are named on the page")
compiled_set = set(re.findall(r"\bgcc\b[^#\n]*?\s-o\s+([A-Za-z0-9_.-]+)", doc))
unwalked = [e[:-2] for e in examples if e[:-2] not in compiled_set]
if unwalked and not re.search(r"subset|not covered|walks through", doc):
    errors += 1
    print(f"  ✗ {unwalked} have no compile step and the page does not state "
          f"it covers a subset")
elif unwalked:
    print(f"  ✓ {len(unwalked)} example(s) without a walkthrough "
          f"({', '.join(unwalked)}) are covered by the page's subset statement")
else:
    print("  ✓ every example has a compile step")

sys.exit(errors)
PYEOF
then
    ERRORS=$((ERRORS + 1))
fi

# --- F-DOCS-014: unsupported-platform sections -------------------------------
echo ""
echo "-- F-DOCS-014: macOS/Windows sections --"

check "no Homebrew install instructions remain" \
      "! grep -Eq 'brew install|Hombrew|libpth-dev' docs/Compilation-and-Installation-Instructions.md"
check "no ARCH=osx/win build instructions remain" \
      "! grep -Eq 'make.*ARCH=(osx|win32|win64)|mingw|/opt/windows' docs/Compilation-and-Installation-Instructions.md"
check "docs/DECISIONS.md records the deletion" \
      "awk '/^## 2026-09-16/{f=1} f' docs/DECISIONS.md | grep -q '#249' \
       && awk '/^## 2026-09-16/{f=1} f' docs/DECISIONS.md | grep -qi 'homebrew'"

# --- F-CLEAN-019: vendored-source configuration ------------------------------
echo ""
echo "-- F-CLEAN-019: vendored sources --"

VENDOR_LIST="tools/ci/vendor-paths.txt"
check "tools/ci/vendor-paths.txt exists" "test -f $VENDOR_LIST"
check "vendor-paths.txt carries a pinned upstream reference" \
      "grep -Eq 'nodejs/http-parser.*v2\.9\.4|v2\.9\.4.*nodejs/http-parser' $VENDOR_LIST"

vendored_ok=1
while IFS= read -r p; do
    case "$p" in ''|'#'*) continue ;; esac
    if [ ! -f "$p" ]; then
        echo "  ✗ vendored path listed but missing: $p"
        vendored_ok=0
        continue
    fi
    if ! head -40 "$p" | grep -q 'VENDORED'; then
        echo "  ✗ $p carries no VENDORED banner in its first 40 lines"
        vendored_ok=0
    elif ! head -40 "$p" | grep -q 'v2\.9\.4'; then
        echo "  ✗ $p banner names no pinned upstream reference"
        vendored_ok=0
    fi
done < "$VENDOR_LIST"
[ "$vendored_ok" -eq 1 ] && echo "  ✓ every listed vendored file exists and carries a pinned VENDORED banner" \
    || ERRORS=$((ERRORS + 1))

for s in tools/ci/report-function-shape.sh tools/ci/lint-markers.sh \
         tools/ci/lint-commented-code.sh tools/ci/count-init-wrappers.sh \
         tools/ci/run-cppcheck.sh; do
    check "$s excludes vendored sources via $VENDOR_LIST" \
          "grep -q 'vendor-paths.txt' $s"
done

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "Result: PASS (all checks passed)"
else
    echo "Result: FAIL ($ERRORS check(s) failed)"
fi

exit $ERRORS

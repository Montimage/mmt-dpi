#!/usr/bin/env bash
# validate-agent-environment.sh — Check-only validation for docs/AGENT_ENVIRONMENT.md.
# Usage: ./validate-agent-environment.sh [--check] [--run-destructive]
#
# docs/AGENT_ENVIRONMENT.md is the single source of truth for the agent-runnable
# build/test environment, and it backs nearly every claim with a `path:line`
# citation into the build system. Those citations rot silently whenever
# rules/*.mk, sdk/Makefile or tests/run_all_tests.sh gain or lose lines. This
# script is the guard. It checks three things:
#
#   1. Citations — every `path:line` / `path:start-end` citation in the doc is
#      registered in the CITATIONS table below, every registered citation is
#      still cited by the doc, the cited file exists, the range lies inside it,
#      the range's *boundaries* still land on the lines the citation is for, and
#      — where the claim is about a value rather than a location — the range
#      still contains that value. Position and content are checked separately on
#      purpose: a range checked only for "the anchor appears somewhere inside"
#      stays green after the code it cites has slid by several lines (the
#      failure this doc suffered), while one checked only at its boundaries
#      stays green after the value inside it changed.
#   2. Contract — the doc names the build and test commands of record, and its
#      suite count, suite list and runtime band agree with the actual runner.
#   3. Single source of truth — the toolchain install line, the `MMT_BASE`
#      prefix contract and the "clean before switching BUILD=" rule are each
#      *defined* in exactly one tracked Markdown file (this doc), with other
#      docs linking to it, and every such link resolves to a real heading.
#
# Moving or adding a citation in the doc? Add/adjust its row in CITATIONS — an
# unregistered citation fails by design, so the anchors can never drift.
set -euo pipefail

MODE="${1:---check}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOC_REL="docs/AGENT_ENVIRONMENT.md"
DOC="$ROOT/$DOC_REL"
ERRORS=0

ok() {
    echo "  ✓ $1"
}

fail() {
    echo "  ✗ $1"
    ERRORS=$((ERRORS + 1))
}

check() {
    local desc="$1"
    local cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
        ok "$desc"
    else
        fail "$desc"
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

echo "=== AGENT_ENVIRONMENT.md validation ==="

if [ ! -f "$DOC" ]; then
    echo "  ✗ $DOC_REL does not exist"
    echo ""
    echo "Result: FAIL (1 check(s) failed)"
    exit 1
fi

# -----------------------------------------------------------------------------
# 1. Citations
# -----------------------------------------------------------------------------
echo ""
echo "-- citations --"

# Citations as the doc writes them, normalised to one "path:range" per line. A
# single backticked citation may carry several comma-separated ranges
# (`rules/common.mk:189-191, 213-216, 279-288`); each becomes its own entry.
# shellcheck disable=SC2016  # backticks below are Markdown syntax, not a subshell
doc_citations="$(
    grep -o '`[^`]*`' "$DOC" \
        | tr -d '`' \
        | grep -E '^[A-Za-z0-9_./-]+:[0-9]+(-[0-9]+)?([,[:space:]]+[0-9]+(-[0-9]+)?)*$' \
        | awk -F: '{
              path = $1
              n = split($2, ranges, /[,[:space:]]+/)
              for (i = 1; i <= n; i++)
                  if (ranges[i] != "") print path ":" ranges[i]
          }' \
        | sort -u
)"

# Registered anchors, tab-separated:
#
#   <path>:<start>[-<end>]  <head-regex>  <tail-regex>  <claim>  [<body-regex>]
#
# <head-regex> must match the range's FIRST line and <tail-regex> its LAST line,
# so both ends are pinned. Use "-" as <tail-regex> for a single-line citation.
# <body-regex> is optional and must match SOMEWHERE inside the range; give it
# whenever the doc's claim is about a value the range must still contain.
registered=""
while IFS=$'\t' read -r cite head tail claim body; do
    case "$cite" in ''|'#'*) continue ;; esac
    if [ -z "$head" ] || [ -z "$tail" ] || [ -z "$claim" ]; then
        fail "$cite — malformed CITATIONS row (expected at least four tab-separated fields)"
        continue
    fi

    registered="${registered}${cite}"$'\n'

    file="${cite%%:*}"
    spec="${cite##*:}"
    start="${spec%%-*}"
    end="${spec##*-}"

    if [ ! -f "$ROOT/$file" ]; then
        fail "$cite — cited file does not exist"
        continue
    fi
    total="$(awk 'END { print NR }' "$ROOT/$file")"
    if [ "$start" -lt 1 ] || [ "$start" -gt "$end" ] || [ "$end" -gt "$total" ]; then
        fail "$cite — range is outside $file (1-$total)"
        continue
    fi

    if ! sed -n "${start}p" "$ROOT/$file" | grep -Eq -- "$head"; then
        fail "$cite — stale: line $start does not match /$head/ (cited for: $claim)"
        continue
    fi
    if [ "$start" != "$end" ] && [ "$tail" != "-" ] \
       && ! sed -n "${end}p" "$ROOT/$file" | grep -Eq -- "$tail"; then
        fail "$cite — stale: line $end does not match /$tail/ (cited for: $claim)"
        continue
    fi
    if [ -n "$body" ] && [ "$body" != "-" ] \
       && ! sed -n "${start},${end}p" "$ROOT/$file" | grep -Eq -- "$body"; then
        fail "$cite — stale: nothing in that range matches /$body/ (cited for: $claim)"
        continue
    fi
    ok "$cite — $claim"
done <<'CITATIONS'
rules/common-linux.mk:47	^# -flto=auto is GCC-only	-	LTO is enabled for GCC only
rules/common-linux.mk:6-12	^ifdef ENABLESEC	^endif	ENABLESEC objects get -fPIC and the libxml2 include path	LIBXML2_CFLAGS
rules/common-linux.mk:51-103	^MMT_RELEASE_BUILD := 1	^endif +# release builds only	release hardening, disabled for sanitizer profiles	MMT_HARDEN_CFLAGS
rules/common-linux.mk:89-97	^# TUNE=native \(opt-in, NEVER the default	^endif	TUNE=native is opt-in, never the default
rules/common-linux.mk:126-138	^# -Wl,-z,defs	^endif	the self-containedness guard, skipped for sanitizers
rules/common-linux.mk:139-142	^ifdef ENABLESEC	^endif	the ENABLESEC engines link against libxml2	LIBXML2_LIBS
rules/common-linux.mk:150-154	^ifdef ENABLESEC	^endif	ENABLESEC adds both engines to the libraries target	LIBSECURITY
rules/common-linux.mk:161	\$\(CXX\) .*-shared .*\$\(LIBCORE\)\.so	-	shared libraries are linked with $(CXX)
rules/common-linux.mk:187-203	^ifdef ENABLESEC	^endif	the engine link rules are ENABLESEC-gated	LIBSECURITY
rules/common.mk:3	^MMT_BASE \?=/opt/mmt	-	MMT_BASE defaults to /opt/mmt
rules/common.mk:21-24	^ifndef VERBOSE	^endif	VERBOSE=1 prints full compile commands
rules/common.mk:30	^CFLAGS .*-DPLUGINS_REPOSITORY_OPT=	-	the plugin repository path is baked into the objects
rules/common.mk:38-43	^ifdef NDEBUG	^endif	NDEBUG=1 keeps assert()/debug() active
rules/common.mk:56-74	^# nghttp2: prefer pkg-config	^endif	libnghttp2 is auto-detected and optional	libnghttp2
rules/common.mk:76-84	^# libxml2 \(only the ENABLESEC	^endif	libxml2 is resolved for the ENABLESEC engines	libxml-2\.0
rules/common.mk:87-93	^ifdef DEBUG	^endif	DEBUG=1 swaps -O3 for -g
rules/common.mk:94-98	^# VALGRIND = 1	^endif	VALGRIND=1 adds Valgrind-friendly instrumentation
rules/common.mk:100-127	^# BUILD=asan to compile with AddressSanitizer	^endif	the BUILD=asan profile is defined here	\-fsanitize=address,undefined
rules/common.mk:120-127	^ifeq \(\$\(BUILD\),asan\)	^endif	the ASan+UBSan flag set the suites mirror	\-fsanitize=address,undefined
rules/common.mk:129-157	^# BUILD=tsan to compile with ThreadSanitizer	^endif	the BUILD=tsan profile is defined here	\-fsanitize=thread
rules/common.mk:150-157	^ifeq \(\$\(BUILD\),tsan\)	^endif	the TSan flag set the suites mirror	\-fsanitize=thread
rules/common.mk:159-166	^# SHOWLOG = 1	^endif	SHOWLOG=1 enables MMT_LOG() output
rules/common.mk:189-191	^ifdef ENABLESEC	^endif	ENABLESEC selects the fuzz include directory	SDKINC_FUZZ
rules/common.mk:213-216	^ifdef ENABLESEC	^endif	ENABLESEC names the two optional libraries	LIBSECURITY
rules/common.mk:239-253	^# Extra diagnostic warnings	^MMT_WARN_FLAGS \?=	extra diagnostics are deliberately not -Werror	NOT -Werror
rules/common.mk:279-288	^ifdef ENABLESEC	^endif	ENABLESEC selects the engine objects	SECURITY_OBJECTS
rules/common.mk:426-428	^%\.o: %\.c	\$\(CC\) \$\(CFLAGS\)	object rules depend on source timestamps only
sdk/Makefile:8-13	^ifdef MMT_BASE	^endif	an unset MMT_BASE targets /opt/mmt and needs root	NEED_ROOT_PERMISSION
sdk/Makefile:28-29	^--refresh-plugin-engine:	plugins_engine\.o	changing MMT_BASE forces plugins_engine.o to recompile
sdk/Makefile:45-51	ln -sf .*libmmt_core\.so	ln -sf .*LIBDICOM	make install creates the unversioned .so symlinks	LIBMOBILE
sdk/Makefile:46-47	ln -sf .*libmmt_fuzz\.so	ln -sf .*libmmt_security\.so	install symlinks both ENABLESEC engines
sdk/Makefile:109-110	ln -s .*libmmt_fuzz\.so	ln -s .*libmmt_security\.so	the dist tree symlinks both ENABLESEC engines
sdk/Makefile:248-251	^test:	\./proto_attributes_iterator	the make test target builds from the installed prefix	\$\(MMT_EXAMS\)/proto_attributes_iterator\.c
tests/run_all_tests.sh:8-98	^# Modes:	^esac	the runner has two opt-in sanitizer modes	\-fsanitize=thread
tests/run_all_tests.sh:86-89	command -v setarch	^ *fi$	TSan re-execs once with ASLR disabled
tests/run_all_tests.sh:155-168	^DEFAULT_SUITES=\(	^\)$	the default suite list lives in DEFAULT_SUITES	nas_ies_tail
tests/run_all_tests.sh:181-283	^# --- coverage report	^fi$	--coverage writes an lcov tracefile and a line rate	coverage\.info
tests/run_all_tests.sh:285-301	^# --- phase0 harnesses	^fi$	--with-harnesses delegates to the aggregate runner	run_all_harnesses\.sh
CITATIONS

registered="$(printf '%s' "$registered" | grep -v '^$' | sort -u)"

while IFS= read -r cite; do
    [ -n "$cite" ] || continue
    printf '%s\n' "$registered" | grep -qxF -- "$cite" \
        || fail "$cite — cited by the doc but not registered in CITATIONS (add an anchor)"
done <<< "$doc_citations"

while IFS= read -r cite; do
    [ -n "$cite" ] || continue
    printf '%s\n' "$doc_citations" | grep -qxF -- "$cite" \
        || fail "$cite — registered in CITATIONS but no longer cited by the doc"
done <<< "$registered"

# -----------------------------------------------------------------------------
# 2. Build/test contract
# -----------------------------------------------------------------------------
echo ""
echo "-- build/test contract --"

check "names the build command of record" \
      "grep -qF 'make -C sdk -j\$(nproc)' '$DOC'"
check "names the test command of record" \
      "grep -qF 'bash tests/run_all_tests.sh' '$DOC'"
check "documents the 'make -C sdk test' trap" \
      "grep -qF 'make -C sdk test' '$DOC'"

RUNNER="$ROOT/tests/run_all_tests.sh"
suites="$(awk '/^DEFAULT_SUITES=\(/ { f = 1; next }
               f && /^\)/          { f = 0 }
               f && NF             { gsub(/[[:space:]]/, ""); print }' "$RUNNER")"
suite_count="$(printf '%s\n' "$suites" | grep -c . || true)"

if grep -qE "\*\*${suite_count}/${suite_count} suites pass\*\*" "$DOC" \
   && grep -qE "(^|[^0-9])${suite_count} suites([^0-9]|\$)" "$DOC"; then
    ok "states the suite count ${suite_count}, matching DEFAULT_SUITES"
else
    fail "does not state the suite count ${suite_count} found in DEFAULT_SUITES"
fi

suites_ok=1
while IFS= read -r suite; do
    [ -n "$suite" ] || continue
    if ! grep -qF -- "\`$suite\`" "$DOC"; then
        fail "suite '$suite' is in DEFAULT_SUITES but is not listed in the doc"
        suites_ok=0
    fi
    if [ ! -d "$ROOT/tests/$suite" ]; then
        fail "suite '$suite' is in DEFAULT_SUITES but tests/$suite/ does not exist"
        suites_ok=0
    fi
done <<< "$suites"
if [ "$suites_ok" -eq 1 ]; then
    ok "all ${suite_count} DEFAULT_SUITES entries are listed in the doc and exist under tests/"
fi

# The runtime figure must be a band, not one optimistic number, and it must
# bracket every measurement recorded next to it (F-DOCS-007).
band="$(grep -oE 'roughly \*\*[0-9]+–[0-9]+ s\*\*' "$DOC" | head -1 | grep -oE '[0-9]+–[0-9]+' || true)"
if [ -z "$band" ]; then
    fail "states no test runtime band (expected: roughly **N–M s**)"
else
    low="${band%%–*}"
    high="${band##*–}"
    measured="$(sed -n '/measured:/,/)/p' "$DOC" | grep -oE '[0-9]+ s' | grep -oE '^[0-9]+' || true)"
    if [ -z "$measured" ]; then
        fail "runtime band ${low}–${high} s records no measured runtime to justify it"
    else
        band_ok=1
        for m in $measured; do
            if [ "$m" -lt "$low" ] || [ "$m" -gt "$high" ]; then
                fail "runtime band ${low}–${high} s does not bracket the measured ${m} s"
                band_ok=0
            fi
        done
        if [ "$band_ok" -eq 1 ]; then
            ok "runtime band ${low}–${high} s brackets every measurement it records ($(echo "$measured" | tr '\n' ' ' | sed 's/ $//')) s"
        fi
    fi
fi

# -----------------------------------------------------------------------------
# 3. Single source of truth
# -----------------------------------------------------------------------------
echo ""
echo "-- single source of truth --"

# Tracked Markdown, minus docs/DECISIONS.md: that log is append-only by
# convention (AGENTS.md), so historical entries there quote facts on purpose and
# are never the live definition.
md_files() {
    if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
        git -C "$ROOT" ls-files '*.md'
    else
        (cd "$ROOT" && find . -name '*.md' -not -path './.git/*' | sed 's|^\./||')
    fi | grep -v '^docs/DECISIONS\.md$'
}

# True when one single line of the file matches every pattern given, in any
# order — so a duplicate cannot slip through by reordering or re-indenting.
# Backslash continuations are folded first, so the multi-line layout `install.sh`
# uses for its package list counts as the one line it logically is.
line_matches_all() {
    local file="$1"
    shift
    local out
    out="$(sed -e :a -e '/\\$/N; s/\\\n//; ta' "$file")"
    local p
    for p in "$@"; do
        out="$(printf '%s\n' "$out" | grep -E -- "$p" || true)"
        [ -n "$out" ] || return 1
    done
    return 0
}

defined_once() {
    local label="$1"
    shift
    local hits count
    hits="$(md_files | while IFS= read -r f; do
                [ -f "$ROOT/$f" ] || continue
                if line_matches_all "$ROOT/$f" "$@"; then echo "$f"; fi
            done)"
    count="$(printf '%s\n' "$hits" | grep -c . || true)"
    if [ "$count" -eq 1 ] && [ "$hits" = "$DOC_REL" ]; then
        ok "$label — defined once, in $DOC_REL"
    elif [ "$count" -eq 0 ]; then
        fail "$label — not defined anywhere (expected it in $DOC_REL)"
    else
        fail "$label — defined in $count files: $(printf '%s' "$hits" | tr '\n' ' ')"
    fi
}

# The toolchain install line is identified by its package set on one apt-get
# line, independent of order or indentation. Package sets installed for a
# different job (the CubieBoard/ARM notes, the QoE demo, the prebuilt ZIP, the
# Debian packaging checklist) are a different fact, not a copy of this one, and
# executable package lists are exempt because they have to be runnable.
defined_once "toolchain install line" \
             'apt-get install' 'build-essential' 'libnghttp2-dev'
defined_once "MMT_BASE default declaration" \
             'MMT_BASE \?=/opt/mmt'
# shellcheck disable=SC2016  # backticks are Markdown syntax inside the pattern
defined_once "MMT_BASE build/install identity rule" \
             'Keep `MMT_BASE` identical across'
# Matched on the -D flag form, so a doc may still *mention* the macro (or link
# back here) without being counted as a second definition.
defined_once "PLUGINS_REPOSITORY_OPT explanation" \
             '\-DPLUGINS_REPOSITORY_OPT='
# shellcheck disable=SC2016  # backticks are Markdown syntax inside the pattern
defined_once "clean-before-switching-BUILD rule" \
             'Always `make -C sdk clean` before switching build profiles'

# Documents that need one of those facts must link here rather than copy it, and
# every anchor they link to must be a real heading in the doc.
for ref in CLAUDE.md AGENTS.md CONTRIBUTING.md README.md \
           docs/DEVELOPMENT.md docs/DEPLOYMENT.md docs/USER_GUIDE.md \
           docs/Compilation-and-Installation-Instructions.md; do
    [ -f "$ROOT/$ref" ] || continue
    check "$ref links to $DOC_REL" "grep -qF 'AGENT_ENVIRONMENT.md' '$ROOT/$ref'"
done

# Heading slugs the doc actually offers (GitHub rules: lowercase, drop
# punctuation other than '-' and '_', spaces to hyphens).
slugs="$(grep -E '^#{2,} ' "$DOC" \
    | sed -E 's/^#+ //' \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/`//g; s/[^a-z0-9 _-]//g; s/^ +//; s/ +$//; s/ +/-/g')"

anchors="$(md_files | while IFS= read -r f; do
               grep -o 'AGENT_ENVIRONMENT\.md#[a-z0-9_-]*' "$ROOT/$f" 2>/dev/null || true
           done | sed 's/.*#//' | sort -u)"

anchor_errors=0
while IFS= read -r anchor; do
    [ -n "$anchor" ] || continue
    if ! printf '%s\n' "$slugs" | grep -qxF -- "$anchor"; then
        fail "link target #$anchor has no matching heading in $DOC_REL"
        anchor_errors=1
    fi
done <<< "$anchors"
if [ "$anchor_errors" -eq 0 ]; then
    ok "every #anchor linked into $DOC_REL resolves to a heading"
fi

echo ""
if [ "$ERRORS" -eq 0 ]; then
    echo "Result: PASS (all checks passed)"
    exit 0
fi
echo "Result: FAIL ($ERRORS check(s) failed)"
# Sibling validators exit with the failure count; cap it so a large count can
# never wrap to 0 through the 8-bit exit status.
[ "$ERRORS" -gt 125 ] && ERRORS=125
exit "$ERRORS"

#!/usr/bin/env bash
#
# report-unreachable-sections.sh — section-level reachability probe of the
# shared libraries (issue #541, F-DEAD-007).
#
# The release build compiles every object with -ffunction-sections
# -fdata-sections and links each library with -Wl,--gc-sections
# (rules/common-linux.mk), so a function or object nothing reaches is
# silently dropped from the .so instead of being deleted from the source.
# Since issues #533/#534 every library but the ENABLESEC engines is compiled
# with -fvisibility=hidden, so the exported MMTAPI declarations are the only
# roots: a section the linker removes is unreachable AND non-public.
#
# This probe makes that list visible. It copies the working tree (tracked and
# untracked, non-ignored files — the checkout's own sdk/ build is never
# touched) into a temporary directory and builds the default SDK there with
#   DEBUG=1                                   -O0: no inlining, so a function
#                                             the source still calls keeps its
#                                             own section; -O3 inlines hidden
#                                             globals into their callers and
#                                             reports the out-of-line copies
#   MMT_EXTRA_CFLAGS+=-ffunction-sections -fdata-sections
#   LDFLAGS=-Wl,--gc-sections -Wl,--print-gc-sections
# then reads the linker's "removing unused section 'S' in file 'lib.a(o)'"
# lines. Each section is attributed to the tracked source its object was
# built from, and kept only when it names a symbol: anonymous sections
# (.rodata, string pools such as .rodata.<fn>.str1.8) and function-local
# statics (dotted names such as mmt_log_site_.0) belong to an enclosing
# function, which is reported itself. Generated asn1c sources
# (src/mmt_mobile/asn1c/) and the vendored list (tools/ci/vendor-paths.txt)
# are out of scope: they are not edited here.
#
# What remains is gated against the committed allowlist
# tools/ci/unreachable-sections-allowlist.txt ($UNREACHABLE_ALLOWLIST
# overrides it): one row per retained section, "<source> <symbol> <tag>",
# the tag saying why it stays —
#   test       reached only from a unit suite or a phase0 harness that links
#              the static archive (a test hook, or the code under test)
#   consumer   reached by a known consumer that links the static archive
#              (5Greplay calls update_http2_data() through libmmt_tcpip.a)
#   config     reached only in another build profile (e.g. BUILD=asan)
#   generated  defined in a generated header the source includes
#   folded     a constant the compiler folds into every use at -O0
#
#   default            gate: exit 1 when a section is unreachable and not
#                      allowlisted, or an allowlisted row is no longer
#                      unreachable (stale: delete it).
#   --report-only      print "<source> <symbol> <library>" for every
#                      unreachable section in scope and exit 0.
#   --emit-allowlist   print allowlist rows for today's sections, keeping the
#                      tag of a row already listed and writing `todo` for a
#                      new one (todo is not a valid tag: classify it).
#   --log FILE         read the linker output from FILE instead of building
#                      (the self-test drives the parser this way).
#   --save-log FILE    copy the build's linker output to FILE.
#
# Exit codes: 0 = no unreachable section outside the allowlist,
#             1 = unlisted section or stale allowlist row,
#             2 = helper broken (build failed, the linker printed no removed
#                 section at all, an object maps to no or several sources,
#                 missing or malformed allowlist).
#
# Usage: bash tools/ci/report-unreachable-sections.sh [--report-only |
#               --emit-allowlist] [--log FILE] [--save-log FILE]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

MODE=gate
LOG=""
SAVE_LOG=""
ALLOWLIST="${UNREACHABLE_ALLOWLIST:-tools/ci/unreachable-sections-allowlist.txt}"
while [ $# -gt 0 ]; do
    case "$1" in
        --report-only)    MODE=report ;;
        --emit-allowlist) MODE=emit ;;
        --log)            LOG="${2:?--log needs a file}"; shift ;;
        --save-log)       SAVE_LOG="${2:?--save-log needs a file}"; shift ;;
        *)                echo "✗ unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

die() { echo "✗ $*" >&2; exit 2; }

# shellcheck source=tools/ci/vendor-paths-lib.sh
. "$ROOT/tools/ci/vendor-paths-lib.sh"
vendor_paths_load "$VENDOR_LIST" || exit 2

WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

if [ -z "$LOG" ]; then
    command -v make >/dev/null 2>&1 || die "make is required"
    # The working tree, not HEAD: uncommitted edits are what a change is
    # checked with. Deleted-but-tracked files are skipped.
    mkdir -p "$WORK/tree"
    git ls-files -z --cached --others --exclude-standard \
        | while IFS= read -r -d '' f; do [ -e "$f" ] && printf '%s\0' "$f"; done \
        | tar --null -T - -cf - | tar -xf - -C "$WORK/tree"
    # The copy has no .git: name the revision and epoch explicitly so the
    # no-git-history guard of rules/common.mk does not fire under CI=true.
    git_version="$(git log --format=%h -n 1 2>/dev/null || true)"
    epoch="$(git log -1 --format=%ct 2>/dev/null || true)"
    LOG="$WORK/build.log"
    echo "Building the default SDK at -O0 with --print-gc-sections (temporary copy)..." >&2
    if ! LDFLAGS="-Wl,--gc-sections -Wl,--print-gc-sections" \
        make -C "$WORK/tree/sdk" -j"$(nproc 2>/dev/null || echo 2)" \
            DEBUG=1 BUILD= ENABLESEC= \
            MMT_BASE="$WORK/prefix" \
            GIT_VERSION="${git_version:-probe}" \
            SOURCE_DATE_EPOCH="${epoch:-0}" \
            MMT_EXTRA_CFLAGS="${MMT_EXTRA_CFLAGS:+$MMT_EXTRA_CFLAGS }-ffunction-sections -fdata-sections" \
            > "$LOG" 2>&1; then
        tail -n 30 "$LOG" >&2
        die "the probe build failed (last 30 lines above)"
    fi
    [ -z "$SAVE_LOG" ] || cp -- "$LOG" "$SAVE_LOG"
fi
[ -f "$LOG" ] || die "linker log not found: $LOG"

# Object basename -> tracked source. Objects are built next to their source
# (rules/common.mk), and the archives keep only basenames, so a basename
# shared by two sources would make the attribution ambiguous.
# The same listing as the copy (tracked plus untracked, non-ignored), so a new
# source not yet added to the index is attributed too.
git ls-files --cached --others --exclude-standard -- 'src/*.c' 'src/*.cpp' \
    | while IFS= read -r f; do [ -e "$f" ] && printf '%s\n' "$f"; done \
    | grep -v '^src/examples/' > "$WORK/sources" || true
[ -s "$WORK/sources" ] || die "no tracked src/ sources found"

# Vendored paths, one per line, for awk.
printf '%s\n' "${VENDOR_PATHS[@]}" > "$WORK/vendored"

awk -v sources="$WORK/sources" -v vendored="$WORK/vendored" '
BEGIN {
    while ((getline p < sources) > 0) {
        b = p; sub(/.*\//, "", b); sub(/\.(c|cpp)$/, ".o", b)
        if (b in src) dup[b] = 1
        src[b] = p
    }
    while ((getline p < vendored) > 0) vend[p] = 1
}
/removing unused section / {
    if (!match($0, /section \047[^\047]*\047/)) next
    sec = substr($0, RSTART + 9, RLENGTH - 10)
    if (!match($0, /in file \047[^\047]*\047/)) next
    file = substr($0, RSTART + 9, RLENGTH - 10)
    total++
    # Only archive members are SDK objects; crt files and the like are not.
    if (!match(file, /\/?lib[^\/]*\.a\([^)]*\)$/)) next
    lib = substr(file, RSTART, RLENGTH); sub(/^\//, "", lib)
    obj = lib; sub(/^[^(]*\(/, "", obj); sub(/\)$/, "", obj)
    sub(/\.a\(.*$/, "", lib)
    if (!(obj in src)) { unmapped[obj] = 1; next }
    if (obj in dup) { ambiguous[obj] = 1; next }
    path = src[obj]
    if (path ~ /^src\/mmt_mobile\/asn1c\// || (path in vend)) { excluded++; next }
    sym = sec
    if (!sub(/^\.(text|rodata|data\.rel\.ro\.local|data\.rel\.ro|data\.rel\.local|data\.rel|data|bss|tbss|tdata)\./, "", sym)) { anon++; next }
    sub(/^(unlikely|startup|hot|exit)\./, "", sym)
    # Function-local statics and string pools carry a dot: they belong to
    # their enclosing function, reported on its own.
    if (sym == "" || sym ~ /\./) { anon++; next }
    key = path " " sym
    if (!(key in seen)) { seen[key] = 1; print path, sym, lib }
}
END {
    for (o in unmapped)  print "UNMAPPED", o > "/dev/stderr"
    for (o in ambiguous) print "AMBIGUOUS", o > "/dev/stderr"
    printf "%d %d %d\n", total, excluded, anon > "/dev/stderr"
}' "$LOG" > "$WORK/found.unsorted" 2> "$WORK/parse.err"

if grep -q '^\(UNMAPPED\|AMBIGUOUS\) ' "$WORK/parse.err"; then
    sed -n -e 's/^UNMAPPED \(.*\)$/✗ object \1 maps to no tracked source/p' \
        -e 's/^AMBIGUOUS \(.*\)$/✗ object \1 maps to several tracked sources/p' "$WORK/parse.err" >&2
    die "an archive member maps to no tracked source or to several"
fi
read -r total excluded anon < <(grep -v '^\(UNMAPPED\|AMBIGUOUS\) ' "$WORK/parse.err" | tail -n 1)
[ "${total:-0}" -gt 0 ] || die "the linker reported no removed section: --print-gc-sections was not honoured"
LC_ALL=C sort -u "$WORK/found.unsorted" > "$WORK/found"
found_n="$(wc -l < "$WORK/found" | tr -d ' ')"

if [ "$MODE" = report ]; then
    cat "$WORK/found"
    echo "$found_n unreachable section(s) in scope ($excluded generated/vendored, $anon anonymous or local-static skipped)" >&2
    exit 0
fi

[ -f "$ALLOWLIST" ] || die "allowlist not found: $ALLOWLIST"
# Allowlist rows: <source> <symbol> <tag>; '#' comments and blank lines.
awk '
/^[[:space:]]*(#|$)/ { next }
NF != 3 || $3 !~ /^(test|consumer|config|generated|folded)$/ { bad = 1; print "✗ malformed allowlist row " NR ": " $0 > "/dev/stderr"; next }
{ print $1, $2, $3 }
END { exit bad }' "$ALLOWLIST" > "$WORK/allow" || exit 2
LC_ALL=C sort -u -k1,2 "$WORK/allow" > "$WORK/allow.sorted"

if [ "$MODE" = emit ]; then
    awk 'NR == FNR { tag[$1 " " $2] = $3; next }
         { k = $1 " " $2; print $1, $2, (k in tag ? tag[k] : "todo") }' \
        "$WORK/allow.sorted" "$WORK/found"
    exit 0
fi

cut -d' ' -f1,2 "$WORK/found" > "$WORK/found.keys"
cut -d' ' -f1,2 "$WORK/allow.sorted" > "$WORK/allow.keys"
LC_ALL=C comm -23 "$WORK/found.keys" "$WORK/allow.keys" > "$WORK/unlisted"
LC_ALL=C comm -13 "$WORK/found.keys" "$WORK/allow.keys" > "$WORK/stale"
allow_n="$(wc -l < "$WORK/allow.keys" | tr -d ' ')"

rc=0
if [ -s "$WORK/unlisted" ]; then
    echo "✗ unreachable non-public section(s) — delete the code, or allowlist a justified one:" >&2
    sed 's/^/    /' "$WORK/unlisted" >&2
    rc=1
fi
if [ -s "$WORK/stale" ]; then
    echo "✗ stale allowlist row(s) — no longer unreachable, delete them from $ALLOWLIST:" >&2
    sed 's/^/    /' "$WORK/stale" >&2
    rc=1
fi
if [ "$rc" -eq 0 ]; then
    echo "✓ 0 unreachable non-public sections outside the allowlist ($allow_n allowlisted; $excluded generated/vendored and $anon anonymous or local-static sections out of scope)"
fi
exit "$rc"

#!/usr/bin/env bash
#
# check-canonical-init-wrappers.sh — zero byte-shape-identical init wrappers
# (issue #226, F-DEAD-011).
#
# Task 5.2 folded the 106 `void mmt_init_classify_me_<proto>(void)` wrappers
# whose bodies all normalize to the same canonical shape —
#
#   <proto>_selection_bitmask = MMT_SELECTION_BITMASK_PROTOCOL_<flags>;
#   MMT_SAVE_AS_BITMASK(detection_bitmask, PROTO_UNKNOWN);
#   [MMT_ADD_PROTOCOL_TO_BITMASK(detection_bitmask, PROTO_<id>);]   (optional)
#   MMT_SAVE_AS_BITMASK(excluded_protocol_bitmask, PROTO_<id>);
#
# — into the generic mmt_init_classify_bitmasks() helper in
# src/mmt_tcpip/lib/mmt_tcpip_internal_defs_macros.h, invoked by the
# registered init_proto_*_struct functions.
#
# This gate re-finds any wrapper whose body still normalizes to that shape:
# reintroducing one means the generic helper was bypassed. The richer
# wrappers that remain (multi-protocol detection lists, extra exclusions —
# Task 5.3 material) do not match and stay untouched.
#
# What it counts: `mmt_init_classify_me_*` definitions in tracked C sources
# under src/ whose normalized body is exactly the canonical statement
# sequence above (comments or any other statement disqualify it).
#
# Exit codes: 0 = no canonical wrappers, 1 = canonical wrapper(s) found,
#             2 = helper broken.
#
# Usage: bash tools/ci/check-canonical-init-wrappers.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

# Vendored sources are excluded by configuration, not convention
# (issue #249, F-CLEAN-019): tools/ci/vendor-paths.txt lists them.
VENDOR_LIST="tools/ci/vendor-paths.txt"
[ -f "$VENDOR_LIST" ] || { echo "✗ vendored-source list not found: $VENDOR_LIST" >&2; exit 2; }

VENDOR_LIST="$VENDOR_LIST" python3 - <<'PYEOF'
import os
import re
import subprocess
import sys

# A `void mmt_init_classify_me_<name>(...)` definition: signature at line
# start (the opening brace may sit on the same line or the next — both
# styles exist in the tree), body ends at the closing brace in column 0.
DEF_RE = re.compile(
    r'(?m)^void[ \t]+mmt_init_classify_me_([A-Za-z0-9_]+)[ \t]*\([^)]*\)'
    r'[ \t]*(?:\n[ \t]*)?\{(?P<body>.*?)^\}',
    re.DOTALL,
)

# Canonical statement shapes, whitespace-normalized.
SEL_RE = re.compile(
    r'[A-Za-z0-9_]*selection_bitmask\s*=\s*'
    r'MMT_SELECTION_BITMASK_PROTOCOL_[A-Za-z0-9_]+\s*;$')
DET_RESET_RE = re.compile(
    r'MMT_SAVE_AS_BITMASK\s*\(\s*detection_bitmask\s*,\s*PROTO_UNKNOWN\s*\)\s*;$')
DET_ADD_RE = re.compile(
    r'MMT_ADD_PROTOCOL_TO_BITMASK\s*\(\s*detection_bitmask\s*,\s*'
    r'PROTO_[A-Za-z0-9_]+\s*\)\s*;$')
EXC_RE = re.compile(
    r'MMT_SAVE_AS_BITMASK\s*\(\s*excluded_protocol_bitmask\s*,\s*'
    r'PROTO_[A-Za-z0-9_]+\s*\)\s*;$')


def normalized_statements(body):
    """Statement list of a wrapper body, or None when a whole-line comment
    (or block comment) makes it non-canonical. A `//` trailing a statement
    is noise — several folded wrappers carry `//BW: check this out` notes —
    but a standalone comment line is content the generic helper cannot
    reproduce, so it disqualifies the body."""
    stmts = []
    for line in body.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith('//') or '/*' in s:
            return None
        stmts.append(re.sub(r'//.*$', '', s).strip())
    return stmts


def is_canonical(body):
    stmts = normalized_statements(body)
    if stmts is None or len(stmts) not in (3, 4):
        return False
    if not (SEL_RE.match(stmts[0]) and DET_RESET_RE.match(stmts[1])
            and EXC_RE.match(stmts[-1])):
        return False
    return len(stmts) == 3 or DET_ADD_RE.match(stmts[2]) is not None

vendor_excludes = []
with open(os.environ['VENDOR_LIST']) as fh:
    for line in fh:
        line = line.strip()
        if line and not line.startswith('#'):
            vendor_excludes.append(':!:' + line)

out = subprocess.run(['git', 'ls-files', 'src/*.c'] + vendor_excludes,
                     check=True, capture_output=True, text=True)
files = [line for line in out.stdout.splitlines() if line.strip()]

canonical = []
total = 0
for path in files:
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            src = fh.read()
    except OSError:
        continue
    for m in DEF_RE.finditer(src):
        total += 1
        if is_canonical(m.group('body')):
            canonical.append('%s: mmt_init_classify_me_%s' % (path, m.group(1)))

print('    init-wrapper definitions: %d' % total)
print('    canonical-shape wrappers: %d' % len(canonical))

if canonical:
    print('✗ %d wrapper(s) still match the canonical shape:' % len(canonical),
          file=sys.stderr)
    for hit in canonical:
        print('    %s' % hit, file=sys.stderr)
    print('To fix: call mmt_init_classify_bitmasks() from the registered '
          'init_proto_*_struct instead of re-adding a per-protocol wrapper.',
          file=sys.stderr)
    sys.exit(1)

print('✓ no canonical-shape init wrappers remain')
PYEOF

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
# reintroducing one means the generic helper was bypassed. Task 5.3 (#227)
# then folded the richer wrappers too — multi-protocol detection lists ride a
# new mmt_init_classify_bitmasks_multi() helper, and whatever the generic path
# cannot express survives inline with a comment.
#
# Phase 2 of this script is the Task 5.3 normalised-body report: it
# histograms the remaining raw bitmask-init blocks (maximal runs of
# statements on the TU-local bitmask globals, identifiers normalised away)
# and fails when one repeats 3 or more times or carries no comment — the
# "every surviving init block is converted or commented" invariant made
# checkable.
#
# What it counts: `mmt_init_classify_me_*` definitions in tracked C sources
# under src/ whose normalized body is exactly the canonical statement
# sequence above (comments or any other statement disqualify it), plus the
# raw init-block histogram described above.
#
# Exit codes: 0 = clean, 1 = canonical wrapper(s) found or a repeated /
#             uncommented init block, 2 = helper broken.
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

# --- Task 5.3 (issue #227): normalised-body report over surviving init logic
#
# A "logic block" is a maximal run of consecutive raw bitmask-init statements
# acting on the three translation-unit-local globals every protocol TU owns —
# selection_bitmask, detection_bitmask, excluded_protocol_bitmask. Blank and
# comment-only lines do not break a run; any other statement does. Protocols
# routed through mmt_init_classify_bitmasks{,_multi}() contribute no raw
# statements, so converted protocols never appear in this report — only the
# genuinely distinct init logic Task 5.3 allowed to survive does, and it must
# carry a comment naming the protocol-specific behaviour.
#
# Two invariants are asserted here:
#   * no normalised logic block repeats 3 or more times (the duplication
#     threshold the M3 metric checks);
#   * every surviving raw init block carries a comment (inside the run or on
#     the line directly above it).
INIT_OP_RE = re.compile(
    r'^\s*(?:selection_bitmask\s*=|'
    r'MMT_(?:SAVE_AS_BITMASK|ADD_PROTOCOL_TO_BITMASK|BITMASK_RESET|'
    r'BITMASK_SET|BITMASK_SET_ALL)\(\s*'
    r'(?:detection_bitmask|excluded_protocol_bitmask|selection_bitmask)\s*[,)])')
COMMENT_RE = re.compile(r'(//|/\*|\*/)')


def normalize_stmt(s):
    s = re.sub(r'//.*$', '', s).strip()
    s = re.sub(r'\s+', ' ', s)
    s = re.sub(r'MMT_SELECTION_BITMASK_PROTOCOL_[A-Za-z0-9_]+', 'SEL', s)
    s = re.sub(r'PROTO_[A-Za-z0-9_]+', 'PROTO', s)
    return s


blocks = {}          # normalised block text -> [location, ...]
uncommented = []     # locations of raw init runs carrying no comment

for path in files:
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            lines = fh.read().splitlines()
    except OSError:
        continue
    run = None           # {'norm': [..], 'start': int, 'commented': bool}
    prev_nonempty = ''   # last non-blank line before the current one

    def end_run():
        global run
        if run is None:
            return
        key = '\n'.join(run['norm'])
        loc = '%s:%d' % (path, run['start'])
        blocks.setdefault(key, []).append(loc)
        if not run['commented']:
            uncommented.append(loc)
        run = None

    for lineno, line in enumerate(lines, 1):
        s = line.strip()
        if INIT_OP_RE.match(line):
            if run is None:
                run = {'norm': [], 'start': lineno,
                       'commented': bool(COMMENT_RE.search(prev_nonempty))}
            if COMMENT_RE.search(line):
                run['commented'] = True
            run['norm'].append(normalize_stmt(line))
        elif not s:
            pass                      # blank lines neither break nor mark
        elif s.startswith('//') or s.startswith('/*') or s.startswith('*'):
            if run is not None and COMMENT_RE.search(line):
                run['commented'] = True   # comment inside a run
        else:
            end_run()
        if s:
            prev_nonempty = line
    end_run()

print('    raw init-logic blocks: %d (distinct normalised: %d)'
      % (sum(len(v) for v in blocks.values()), len(blocks)))
for norm, locs in sorted(blocks.items(), key=lambda kv: -len(kv[1])):
    first = norm.splitlines()[0] if norm else ''
    print('      %dx  %s%s  [%s]'
          % (len(locs), first[:60], '…' if '\n' in norm or len(first) > 60 else '',
             ', '.join(locs)))

failed = False
for norm, locs in blocks.items():
    if len(locs) >= 3:
        print('✗ init-logic block repeated %d times (≥3):' % len(locs),
              file=sys.stderr)
        for loc in locs:
            print('    %s' % loc, file=sys.stderr)
        failed = True
if uncommented:
    print('✗ raw init-logic block(s) without a comment naming the '
          'protocol-specific behaviour:', file=sys.stderr)
    for loc in uncommented:
        print('    %s' % loc, file=sys.stderr)
    failed = True
if failed:
    print('To fix: route the shared shape through '
          'mmt_init_classify_bitmasks{,_multi}() and comment whatever the '
          'generic path cannot express.', file=sys.stderr)
    sys.exit(1)

print('✓ no init-logic block repeats ≥3 times and every surviving raw '
      'block is commented')
PYEOF

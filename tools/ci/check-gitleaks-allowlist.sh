#!/usr/bin/env bash
#
# Assert that every allowlist pattern in .gitleaks.toml still matches something
# tracked (issue #191, F-SEC-013).
#
# An allowlist entry that matches nothing is drift: it was written for a path
# that has since been renamed or deleted, and it survives as dead configuration
# that nobody re-reads. The dangerous direction is the opposite one — a rule
# broad enough to cover the whole tree silently disables the scan for a whole
# file class. Both are caught here: a `paths` entry must match at least one
# tracked file, and a `regexes` entry must match content in at least one.
#
# Exit 0 when every pattern matches, 1 otherwise.
#
# Usage: bash tools/ci/check-gitleaks-allowlist.sh [path/to/.gitleaks.toml]

set -euo pipefail

CONFIG="${1:-.gitleaks.toml}"

if [ ! -f "$CONFIG" ]; then
    echo "✗ gitleaks config not found: $CONFIG" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "✗ python3 is required to validate $CONFIG" >&2
    exit 1
fi

git ls-files -z > /tmp/gitleaks-tracked.$$ || {
    echo "✗ not a git repository (or git ls-files failed)" >&2
    exit 1
}
trap 'rm -f /tmp/gitleaks-tracked.$$' EXIT

python3 - "$CONFIG" /tmp/gitleaks-tracked.$$ <<'PYEOF'
import re
import sys

config_path, tracked_path = sys.argv[1], sys.argv[2]

with open(tracked_path, "rb") as fh:
    tracked = [p.decode("utf-8", "surrogateescape")
               for p in fh.read().split(b"\0") if p]

text = open(config_path, encoding="utf-8").read()

# Strip comments so a pattern quoted inside a comment is not collected.
lines = [re.sub(r"(?<!')#.*$", "", line) for line in text.split("\n")]
stripped = "\n".join(lines)


def block(name):
    """Return the ''' ''' quoted entries of the named array, or None if absent."""
    m = re.search(name + r"\s*=\s*\[(.*?)\]", stripped, re.S)
    if not m:
        return None
    return re.findall(r"'''(.*?)'''", m.group(1), re.S)


def compile_or_fail(pat, kind, failures):
    try:
        return re.compile(pat)
    except re.error as exc:
        failures.append(f"{kind} pattern is not a valid regex: {pat!r} ({exc})")
        return None


failures = []
checked = 0

paths = block("paths")
if paths is None:
    print("  note: no `paths` allowlist in this config")
    paths = []

for pat in paths:
    checked += 1
    rx = compile_or_fail(pat, "paths", failures)
    if rx is None:
        continue
    hits = [p for p in tracked if rx.search(p)]
    if not hits:
        failures.append(
            f"paths pattern matches no tracked file: {pat!r}\n"
            f"      it is dead configuration — delete it, or fix the path it meant to cover"
        )
    else:
        print(f"  ok  paths   {pat}  ({len(hits)} tracked file(s))")

regexes = block("regexes")
if regexes is None:
    regexes = []

for pat in regexes:
    checked += 1
    rx = compile_or_fail(pat, "regexes", failures)
    if rx is None:
        continue
    hits = 0
    for p in tracked:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                if rx.search(fh.read()):
                    hits += 1
                    break
        except (OSError, IsADirectoryError):
            continue
    if hits == 0:
        failures.append(
            f"regexes pattern matches no tracked file content: {pat!r}\n"
            f"      the false positive it suppressed is gone — delete it"
        )
    else:
        print(f"  ok  regexes {pat}")

if checked == 0:
    print("✗ no allowlist patterns found — is this the right config?")
    sys.exit(1)

if failures:
    print("")
    print(f"✗ {len(failures)} stale gitleaks allowlist pattern(s) in {config_path}:")
    for f in failures:
        print(f"    - {f}")
    print("")
    print("To fix:  remove the dead entry from .gitleaks.toml, or correct its path")
    sys.exit(1)

print("")
print(f"✓ all {checked} gitleaks allowlist pattern(s) still match tracked files")
PYEOF

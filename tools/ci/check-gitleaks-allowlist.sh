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
# It also asserts the config has detection rules at all (issue #488,
# F-SEC-001): a config with no [[rules]] and no `[extend] useDefault = true`
# scans with zero rules, so the scan passes on any secret. The legacy
# singular `[allowlist]` table is rejected in favour of `[[allowlists]]`.
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

# A private mktemp file, not a predictable /tmp/<name>.$$ path (issue #508).
TRACKED="$(mktemp)"
trap 'rm -f "$TRACKED"' EXIT
git ls-files -z > "$TRACKED" || {
    echo "✗ not a git repository (or git ls-files failed)" >&2
    exit 1
}

python3 - "$CONFIG" "$TRACKED" <<'PYEOF'
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
    """Return the ''' ''' quoted entries of every array with this name (one
    per [[allowlists]] table), or None if there is none."""
    arrays = re.findall(r"^\s*" + name + r"\s*=\s*\[(.*?)\]", stripped, re.S | re.M)
    if not arrays:
        return None
    return [e for a in arrays for e in re.findall(r"'''(.*?)'''", a, re.S)]


def compile_or_fail(pat, kind, failures):
    try:
        return re.compile(pat)
    except re.error as exc:
        failures.append(f"{kind} pattern is not a valid regex: {pat!r} ({exc})")
        return None


failures = []
checked = 0

# Detection rules: without them every allowlist below is moot.
extend = re.search(r"^\s*\[extend\]\s*$(.*?)(?=^\s*\[|\Z)", stripped, re.S | re.M)
use_default = bool(extend and re.search(r"^\s*useDefault\s*=\s*true\s*$",
                                        extend.group(1), re.M))
own_rules = bool(re.search(r"^\s*\[\[rules\]\]\s*$", stripped, re.M))
if use_default:
    print("  ok  rules   [extend] useDefault = true (gitleaks default ruleset)")
elif own_rules:
    print("  ok  rules   config defines its own [[rules]]")
else:
    failures.append(
        "config has no detection rules: no `[extend] useDefault = true` and no [[rules]]\n"
        "      gitleaks then scans with zero rules and passes on any secret (issue #488)"
    )

if re.search(r"^\s*\[allowlist\]\s*$", stripped, re.M):
    failures.append(
        "legacy `[allowlist]` table found — use `[[allowlists]]` (gitleaks >= 8.25)"
    )

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
    print(f"✗ {len(failures)} gitleaks config problem(s) in {config_path}:")
    for f in failures:
        print(f"    - {f}")
    print("")
    print("To fix:  restore the detection rules, migrate to [[allowlists]], or remove")
    print("         the dead entry from .gitleaks.toml / correct its path")
    sys.exit(1)

print("")
print(f"✓ detection rules present; all {checked} gitleaks allowlist pattern(s) still match tracked files")
PYEOF

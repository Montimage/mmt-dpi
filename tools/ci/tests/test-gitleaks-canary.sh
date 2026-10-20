#!/usr/bin/env bash
#
# Canary self-test for the secret scan (issue #488, F-SEC-001).
#
# The failure this guards against is a scan that cannot fail: a .gitleaks.toml
# with no [[rules]] and no `[extend] useDefault = true` loads zero detection
# rules, so tools/ci/run-gitleaks.sh reports "no leaks found" for any history.
# This test plants a synthetic AWS access key in a throwaway git repository
# that carries the repository's own .gitleaks.toml and .gitleaksignore, and
# asserts the real scan script exits non-zero and names the AWS rule. A clean
# throwaway repository with the same config must scan clean, so the canary
# also proves the config loads and its allowlists do not swallow the key.
#
# The key is assembled at runtime from fragments, so this file never contains
# a string the scanner would flag in the repository's own history. It is not
# a credential: "CANARYFAKEKEY234" is a made-up suffix in AWS key syntax.
#
# Needs network access: run-gitleaks.sh downloads the pinned, checksum-verified
# gitleaks release. Runs in the secret-scan CI job.
#
# Usage: bash tools/ci/tests/test-gitleaks-canary.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCAN="${REPO_ROOT}/tools/ci/run-gitleaks.sh"
CHECK="${REPO_ROOT}/tools/ci/check-gitleaks-allowlist.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() { echo "✗ canary: $*" >&2; exit 1; }

# A throwaway repository holding the repo's scan config and one commit.
make_repo() {
    local dir="$1"
    mkdir -p "$dir"
    git -C "$dir" init -q --template=
    cp "${REPO_ROOT}/.gitleaks.toml" "$dir/.gitleaks.toml"
    cp "${REPO_ROOT}/.gitleaksignore" "$dir/.gitleaksignore"
    printf 'canary fixture for tools/ci/tests/test-gitleaks-canary.sh\n' > "$dir/README"
}

commit_all() {
    # Isolate from the contributor's git setup: a global excludesFile could
    # ignore the planted file, and a global hook could refuse the commit.
    git -C "$1" -c core.excludesFile=/dev/null add -A -f
    git -C "$1" -c user.name=canary -c user.email=canary@example.invalid \
        -c commit.gpgsign=false -c core.hooksPath=/dev/null \
        commit -q --no-verify -m "$2"
}

# Runs the real scan script in a repo; prints its exit status.
scan() {
    local dir="$1" status
    set +e
    (cd "$dir" && GITLEAKS_REPORT="$dir/report.json" GITLEAKS_MARKER="$dir/marker" \
        bash "$SCAN") > "$dir/scan.log" 2>&1
    status=$?
    set -e
    echo "$status"
}

# 1. The config gate rejects a rule-less config (offline, no download).
printf '[[allowlists]]\npaths = [\n    '"'''"'^README$'"'''"',\n]\n' > "$work/norules.toml"
(cd "$REPO_ROOT" && bash "$CHECK" "$work/norules.toml") > "$work/check.log" 2>&1 \
    && fail "check-gitleaks-allowlist.sh accepted a config with no detection rules"
grep -q 'no detection rules' "$work/check.log" \
    || fail "check-gitleaks-allowlist.sh failed for the wrong reason:$(sed 's/^/ /' "$work/check.log")"
echo "✓ check-gitleaks-allowlist.sh rejects a config with no detection rules"

# 2. Negative control: the same config scans a clean repository clean.
make_repo "$work/clean"
commit_all "$work/clean" "clean fixture"
status="$(scan "$work/clean")"
[ "$status" -eq 0 ] \
    || { cat "$work/clean/scan.log" >&2; fail "clean repository scanned non-zero (exit $status)"; }
echo "✓ run-gitleaks.sh exits 0 on a clean repository"

# 3. The canary: a planted AWS access key must fail the scan.
make_repo "$work/leak"
key_id="AKIA""CANARYFAKEKEY234"
printf '[default]\naws_access_key_id = %s\n' "$key_id" > "$work/leak/credentials"
commit_all "$work/leak" "plant canary secret"
status="$(scan "$work/leak")"
[ "$status" -ne 0 ] \
    || { cat "$work/leak/scan.log" >&2; fail "planted AWS key was not detected (exit 0)"; }
python3 - "$work/leak/report.json" <<'PYEOF' || fail "report does not name the AWS rule for the planted file"
import json, sys
findings = json.load(open(sys.argv[1]))
sys.exit(0 if any(f.get("RuleID") == "aws-access-token" and f.get("File") == "credentials"
                  for f in findings) else 1)
PYEOF
echo "✓ run-gitleaks.sh exits ${status} and reports aws-access-token for the planted key"

echo "✓ gitleaks canary passed"

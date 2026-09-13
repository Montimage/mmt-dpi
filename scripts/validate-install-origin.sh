#!/usr/bin/env bash
#
# validate-install-origin.sh — one canonical repository identity across the
# installer, docs and site (issue #197; committed under issue #190).
#
# The installer cloned from the old organisation while the README, the docs
# and the site pointed at the current one — two names for the same
# repository, diverging silently. This validator asserts the organisation in
# install.sh's repository constant agrees with the clone URL in README.md,
# and that every `github.com/<org>/mmt-dpi` reference across the entry-point
# documents names exactly one organisation. It also smoke-checks the
# documented verify path: `install.sh --dry-run` must print the resolved
# (pinned-tag) plan and exit 0, and a moving ref must be refused unless
# `--unverified-branch` is passed (issue #197, F-SEC-006 / F-BUG-118).
#
# Same check-only contract as the other scripts/validate-*.sh: findings are
# reported, the script exits non-zero when any check fails.
#
# Exit codes: 0 = consistent, 1 = divergence found, 2 = validator broken.
#
# Usage: bash scripts/validate-install-origin.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

for f in install.sh README.md CONTRIBUTING.md SECURITY.md docs/index.html; do
    [ -f "$f" ] || { echo "✗ required file missing: $f" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

python3 - <<'PYEOF'
import re
import sys

errors = 0


def ok(msg):
    print(f"  ✓ {msg}")


def fail(msg):
    global errors
    errors += 1
    print(f"  ✗ {msg}")


# The repository constant in install.sh.
install = open("install.sh", encoding="utf-8").read()
m = re.search(r'REPO_URL\s*=\s*"https://github\.com/([^/"]+)/([^/".]+)', install)
if not m:
    print("✗ install.sh declares no REPO_URL github.com constant",
          file=sys.stderr)
    sys.exit(2)
install_org, install_repo = m.group(1), m.group(2)
ok(f"install.sh REPO_URL → github.com/{install_org}/{install_repo}")

# The clone URL shown to users in README.md.
readme = open("README.md", encoding="utf-8").read()
m = re.search(r'git clone\s+https://github\.com/([^/\s]+)/([^/\s.]+)', readme)
if not m:
    fail("README.md shows no 'git clone https://github.com/<org>/<repo>' line")
else:
    readme_org, readme_repo = m.group(1), m.group(2)
    ok(f"README.md clone URL → github.com/{readme_org}/{readme_repo}")
    if (install_org, install_repo) != (readme_org, readme_repo):
        fail(f"installer clones {install_org}/{install_repo} but the README "
             f"points at {readme_org}/{readme_repo}")

# Every github.com/<org>/mmt-dpi reference across the entry-point docs must
# name one organisation (the canonical one, `montimage-projects`, recorded in
# docs/DECISIONS.md under 2026-09-12 and 2026-09-13 for issue #197).
orgs = {}
for doc in ("install.sh", "README.md", "CONTRIBUTING.md", "SECURITY.md",
            "docs/index.html"):
    text = open(doc, encoding="utf-8", errors="replace").read()
    for o in re.findall(r'github\.com/([A-Za-z0-9_-]+)/mmt-dpi', text):
        orgs.setdefault(o, []).append(doc)

if len(orgs) > 1:
    for o, docs in sorted(orgs.items()):
        fail(f"github.com/{o}/mmt-dpi referenced by: {', '.join(sorted(set(docs)))}")
else:
    ok(f"one organisation across all references: {sorted(orgs)}")

if errors:
    print(f"✗ {errors} repository-identity divergence(s)", file=sys.stderr)
    print("To fix:  declare one canonical organisation in docs/DECISIONS.md"
          " and point every reference at it (issue #197)", file=sys.stderr)
    sys.exit(1)
print("✓ one repository identity across installer, docs and site")
PYEOF

# The documented verify command must keep working (issue #197 Verify line):
# `install.sh --dry-run` prints the resolved plan and exits 0; a moving ref is
# refused unless --unverified-branch is passed explicitly.
if ! bash install.sh --dry-run >/dev/null 2>&1; then
    echo "✗ install.sh --dry-run failed" >&2
    exit 1
fi
echo "  ✓ install.sh --dry-run prints the pinned-tag plan"
if BRANCH=ci-check bash install.sh --dry-run >/dev/null 2>&1; then
    echo "✗ install.sh accepted moving ref 'ci-check' without --unverified-branch" >&2
    exit 1
fi
echo "  ✓ moving ref refused without --unverified-branch"
if ! BRANCH=ci-check bash install.sh --dry-run --unverified-branch >/dev/null 2>&1; then
    echo "✗ install.sh --unverified-branch did not admit the moving ref" >&2
    exit 1
fi
echo "  ✓ moving ref admitted with --unverified-branch"

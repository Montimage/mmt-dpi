#!/usr/bin/env bash
#
# check-release-verification.sh — released packages are verifiable
# (issue #198, F-SEC-005/F-SEC-015 — plan task 1.8).
#
# A released .deb/.rpm used to be unverifiable: no checksum manifest, no
# SBOM, no provenance attestation, and the workflow did not even request
# the permissions attestation needs — while README told users to install
# the downloaded file as root. This is the static gate that keeps the
# wiring from silently rotting: it re-checks the workflow and README
# contracts the release pipeline relies on, without pushing a tag.
#
# Checked against .github/workflows/release-packages.yml + README.md:
#   - the release job still gates on tags (refs/tags/v)
#   - the release job grants id-token: write and attestations: write
#   - an actions/attest-build-provenance step attests the published set
#     (subject-path covering the release/ directory, so every attached
#     asset — packages, SBOMs, SHA256SUMS — is an attestation subject)
#   - a SHA256SUMS manifest is generated with sha256sum and published via
#     the release files glob
#   - an SBOM is generated per package in the build job (sbom-action or a
#     direct syft call), written under dist/packages so the upload glob
#     ships it, and collected into the release asset set (*.sbom.json)
#   - README.md documents `sha256sum --check` and `gh attestation verify`
#   - every `uses:` action reference stays SHA-pinned (repo convention)
#
# Exit codes: 0 = verifiable wiring present, 1 = a violation, 2 = helper
# broken.
#
# Usage: bash tools/ci/check-release-verification.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

WORKFLOW=".github/workflows/release-packages.yml"
README="README.md"

[ -f "$WORKFLOW" ] || { echo "✗ workflow not found: $WORKFLOW" >&2; exit 2; }
[ -f "$README" ]   || { echo "✗ README not found: $README" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

python3 - "$WORKFLOW" "$README" <<'PYEOF'
import re
import sys

workflow_path, readme_path = sys.argv[1], sys.argv[2]
wf = open(workflow_path, encoding="utf-8").read()
readme = open(readme_path, encoding="utf-8").read()

errors = 0


def fail(msg):
    global errors
    errors += 1
    print(f"  ✗ {msg}")


def ok(msg):
    print(f"  ✓ {msg}")


# Isolate the release job block: `  release:` at jobs level, up to the next
# top-level job key (two-space indent, `word:`) or EOF.
m = re.search(r"(?m)^  release:\n(.*?)(?=^  [a-zA-Z_][a-zA-Z0-9_-]*:[^\S\n]*$|\Z)",
              wf, re.S)
release_job = m.group(1) if m else ""
if not release_job:
    fail("no `release:` job found in the workflow")

# --- tag gate + permissions -------------------------------------------------
if release_job:
    if re.search(r"refs/tags/v", release_job):
        ok("release job still gates on refs/tags/v")
    else:
        fail("release job no longer gated to tag pushes (refs/tags/v)")

    perm_block = re.search(r"(?m)^    permissions:\n((?:      .*\n?)*)",
                           release_job)
    perms = perm_block.group(1) if perm_block else ""
    for need in ("id-token", "attestations"):
        if re.search(rf"(?m)^\s*{re.escape(need)}:\s*write\b", perms):
            ok(f"release job requests {need}: write")
        else:
            fail(f"release job permissions lack `{need}: write` — "
                 "build-provenance attestation cannot run")
    if re.search(r"(?m)^\s*contents:\s*write\b", perms):
        ok("release job keeps contents: write (release creation)")
    else:
        fail("release job lost contents: write")

# --- provenance attestation over the published set --------------------------
if re.search(r"uses:\s*actions/attest-build-provenance@[0-9a-f]{40}",
             release_job or wf):
    ok("actions/attest-build-provenance step present (SHA-pinned)")
elif "attest-build-provenance" in wf:
    fail("attest-build-provenance is referenced but not SHA-pinned")
else:
    fail("no attest-build-provenance step — artifacts ship unattested")

attest_step = re.search(
    r"uses:\s*actions/attest-build-provenance@[0-9a-f]{40}[^#]*(?:#[^\n]*)?"
    r"\n((?:\s{6,}.*\n?)*)", release_job or wf)
subjects = ""
if attest_step:
    subjects = attest_step.group(1)
if re.search(r"subject-(path|checksums):\s*[^\n]*release/", subjects):
    ok("attestation subjects cover the release/ asset set")
elif "attest-build-provenance" in (release_job or wf):
    fail("attestation subjects do not cover release/ — "
         "published assets would not all be attested")

# --- SHA256SUMS manifest ----------------------------------------------------
if re.search(r"sha256sum\b[^|\n>]*>\s*SHA256SUMS", release_job or wf) \
        or re.search(r"SHA256SUMS", release_job):
    ok("SHA256SUMS manifest is generated in the release job")
else:
    fail("no SHA256SUMS manifest generated for the release")

pub = re.search(r"(?m)^\s*files:\s*([^\n#]+)", release_job or "")
if pub and re.search(r"release/\*|release/\*\*", pub.group(1)):
    ok("published file glob covers the manifest and SBOMs (release/*)")
else:
    fail("release files glob does not cover release/* — manifest/SBOMs "
         "would not be attached")

# --- per-package SBOM -------------------------------------------------------
if re.search(r"uses:\s*anchore/sbom-action@[0-9a-f]{40}", wf) \
        or re.search(r"\bsyft\b", wf):
    ok("SBOM generation step present in the workflow")
else:
    fail("no SBOM generation step (sbom-action/syft) — F-SEC-015 unmet")

sbom_out = re.search(r"output-file:.*dist/packages", wf)
if sbom_out or re.search(r"dist/packages/\*", wf):
    ok("SBOM lands under dist/packages (uploaded with the package artifact)")
else:
    fail("SBOM output is not under dist/packages — the artifact upload "
         "glob would not ship it")

if re.search(r"\.sbom\.json", release_job):
    ok("release job collects *.sbom.json into the published set")
else:
    fail("release job does not collect *.sbom.json — SBOMs would not "
         "reach the release")

# --- README verification docs ------------------------------------------------
if re.search(r"sha256sum\s+(-c|--check)\b", readme):
    ok("README documents sha256sum --check")
else:
    fail("README does not document `sha256sum --check` — users cannot "
         "verify the manifest")

if re.search(r"gh\s+attestation\s+verify", readme):
    ok("README documents `gh attestation verify`")
else:
    fail("README does not document `gh attestation verify` — users "
         "cannot check provenance")

# --- SHA pinning (repo convention) -------------------------------------------
unpinned = []
for use in re.findall(r"uses:\s*([^\s#]+)", wf):
    if use.startswith("./"):
        continue
    if not re.search(r"@[0-9a-f]{40}$", use):
        unpinned.append(use)
if unpinned:
    for u in unpinned:
        fail(f"action not SHA-pinned: {u}")
else:
    ok("every actions/ reference is SHA-pinned")

if errors:
    print(f"✗ {errors} release-verification violation(s)", file=sys.stderr)
    print("To fix:  restore the verification wiring in "
          ".github/workflows/release-packages.yml (issue #198)",
          file=sys.stderr)
    sys.exit(1)
print("✓ released packages are verifiable: SBOM + SHA256SUMS + attestation")
PYEOF

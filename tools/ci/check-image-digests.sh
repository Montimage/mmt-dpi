#!/usr/bin/env bash
#
# check-image-digests.sh — release container images are digest-pinned
# (issue #217, F-DEP-101/F-CI-012/F-SEC-007; helper committed under #190).
#
# Every GitHub action is SHA-pinned, but the container images that actually
# compile the shipped packages were floating major tags — the strongest link
# in the supply chain was the least pinned, and invisible to the dependency
# bot because the references lived in a shell command rather than a manifest.
#
# Checked against .github/workflows/release-packages.yml:
#   - every `image:` value is referenced as name@sha256:<64-hex-digest>
#   - the same image@digest pairs are recorded in the tracked
#     tools/ci/base-images.txt so the dependency bot can flag drift, and the
#     workflow actually reads that file
#
# Exit codes: 0 = all pinned + recorded, 1 = a violation, 2 = helper broken.
#
# Usage: bash tools/ci/check-image-digests.sh [release-workflow.yml]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

WORKFLOW="${1:-.github/workflows/release-packages.yml}"
BASELINE="tools/ci/base-images.txt"

[ -f "$WORKFLOW" ] || { echo "✗ workflow not found: $WORKFLOW" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

python3 - "$WORKFLOW" "$BASELINE" <<'PYEOF'
import re
import sys

workflow_path, baseline_path = sys.argv[1], sys.argv[2]
text = open(workflow_path, encoding="utf-8").read()

# Every `image:` / `container:` value — in block mappings and in the inline
# `{ name: …, image: "…", pkg: … }` matrix rows this workflow uses.
refs = re.findall(r'(?:image|container)\s*:\s*["\']([^"\']+)["\']', text) \
     + re.findall(r'(?m)^\s*(?:image|container)\s*:\s*([^"\'\s,#}]+)', text)
refs = sorted(set(r for r in refs if "${{" not in r))
if not refs:
    print(f"✗ no image/container references found in {workflow_path} — is "
          "this the right file?", file=sys.stderr)
    sys.exit(2)

errors = 0
unpinned = [r for r in refs if "@sha256:" not in r]
for r in unpinned:
    print(f"  ✗ floating image reference: {r}")
if unpinned:
    errors += len(unpinned)
else:
    print(f"  ✓ all {len(refs)} image reference(s) are digest-pinned")

bad_digest = [r for r in refs
              if "@sha256:" in r and not re.search(r'@sha256:[0-9a-f]{64}$', r)]
for r in bad_digest:
    print(f"  ✗ malformed digest pin: {r}")
errors += len(bad_digest)

# The pinned set must be recorded in a tracked baseline file the workflow
# reads, so the dependency bot can diff it.
try:
    recorded = set()
    for line in open(baseline_path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if line:
            recorded.add(line)
except OSError:
    print(f"  ✗ {baseline_path} not found")
    errors += 1
    recorded = set()

if recorded:
    missing = [r for r in refs if r not in recorded]
    stale = [r for r in recorded
             if r not in refs and not r.startswith("digest-source")]
    for r in missing:
        print(f"  ✗ pinned image missing from {baseline_path}: {r}")
        errors += 1
    for r in stale:
        print(f"  ✗ {baseline_path} entry matches no workflow image: {r}")
        errors += 1
    if not missing and not stale:
        print(f"  ✓ {baseline_path} records all {len(refs)} image(s)")

if baseline_path not in text:
    print(f"  ✗ {workflow_path} never reads {baseline_path} — the file is "
          "decoration, not a source")
    errors += 1

if errors:
    print(f"✗ {errors} image-pinning violation(s)", file=sys.stderr)
    print("To fix:  pin each image as name@sha256:<digest> and record it in",
          file=sys.stderr)
    print(f"         {baseline_path} (issue #217)", file=sys.stderr)
    sys.exit(1)
print("✓ release container images are digest-pinned and recorded")
PYEOF

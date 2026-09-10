#!/usr/bin/env bash
#
# Secret scan using a pinned gitleaks binary (issue #191, F-DEP-001, F-SEC-001).
#
# This is the fallback path for the secret-scan job. gitleaks-action requires a
# licence key for organization accounts, so on an org repository without the
# GITLEAKS_LICENSE secret the action step fails and scans nothing. The gitleaks
# binary itself carries no such requirement, so this path keeps the gate real
# whether or not the licence secret is configured.
#
# The binary is pinned by version and verified by SHA-256 before it is run: an
# unpinned scanner download is a supply-chain hole in the very job whose purpose
# is catching leaked credentials.
#
# Writes the findings report and a marker file that
# tools/ci/assert-gitleaks-ran.sh checks, so a silently skipped scan cannot pass
# for a clean one. Exits non-zero when gitleaks reports findings.

set -euo pipefail

GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"
REPORT="${GITLEAKS_REPORT:-gitleaks-report.json}"
MARKER="${GITLEAKS_MARKER:-.gitleaks-scan-ran}"

# Checksums come from the release's own gitleaks_<version>_checksums.txt.
# CI runners are x86_64; arm64 is here so a contributor on an ARM machine can
# run the same scan locally instead of having to trust CI for it.
case "$(uname -m)" in
    x86_64|amd64)
        GITLEAKS_ARCH="x64"
        GITLEAKS_SHA256_DEFAULT="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
        ;;
    aarch64|arm64)
        GITLEAKS_ARCH="arm64"
        GITLEAKS_SHA256_DEFAULT="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"
        ;;
    *)
        echo "✗ no pinned gitleaks build for architecture $(uname -m)" >&2
        echo "To fix:  add its checksum from the release checksums.txt to this script" >&2
        exit 1
        ;;
esac
GITLEAKS_SHA256="${GITLEAKS_SHA256:-$GITLEAKS_SHA256_DEFAULT}"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

tarball="gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz"
url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${tarball}"

echo "[gitleaks] fetching v${GITLEAKS_VERSION} (linux/${GITLEAKS_ARCH})"
if ! curl -fsSL --retry 3 --retry-delay 2 -o "${workdir}/${tarball}" "$url"; then
    echo "✗ could not download gitleaks v${GITLEAKS_VERSION}" >&2
    echo "To fix:  check network access, or bump GITLEAKS_VERSION if the release was withdrawn" >&2
    exit 1
fi

echo "[gitleaks] verifying checksum"
actual="$(sha256sum "${workdir}/${tarball}" | awk '{print $1}')"
if [ "$actual" != "$GITLEAKS_SHA256" ]; then
    echo "✗ gitleaks checksum mismatch — refusing to run the binary" >&2
    echo "    expected: $GITLEAKS_SHA256" >&2
    echo "    actual:   $actual" >&2
    echo "To fix:  if this is a deliberate version bump, update GITLEAKS_SHA256 from" >&2
    echo "         https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt" >&2
    exit 1
fi

tar -xzf "${workdir}/${tarball}" -C "$workdir" gitleaks
chmod +x "${workdir}/gitleaks"
"${workdir}/gitleaks" version

# gitleaks 8.19 split `detect` into `git` and `dir`; `detect` still works but is
# deprecated. Prefer `git`, fall back so a version bump in either direction runs.
if "${workdir}/gitleaks" git --help >/dev/null 2>&1; then
    scan_cmd=(git)
else
    scan_cmd=(detect)
fi

echo "[gitleaks] scanning full history with: gitleaks ${scan_cmd[*]}"
set +e
"${workdir}/gitleaks" "${scan_cmd[@]}" . \
    --config .gitleaks.toml \
    --report-format json \
    --report-path "$REPORT" \
    --redact \
    --exit-code 2 \
    --verbose
status=$?
set -e

# The marker records that a scan executed, independent of its verdict. Written
# before the exit so a run that *found* something still counts as having run.
date -u +%Y-%m-%dT%H:%M:%SZ > "$MARKER"
echo "gitleaks ${GITLEAKS_VERSION} exit=${status}" >> "$MARKER"

case "$status" in
    0)
        echo "✓ gitleaks found no secrets"
        ;;
    2)
        count="$(python3 -c "import json,sys; print(len(json.load(open('$REPORT'))))" 2>/dev/null || echo "?")"
        echo "✗ gitleaks found ${count} potential secret(s) — see ${REPORT}" >&2
        echo "To fix:  rotate the credential, then suppress the finding by fingerprint" >&2
        echo "         in .gitleaksignore only after triage confirms a false positive" >&2
        exit 1
        ;;
    *)
        echo "✗ gitleaks exited ${status} without completing a scan" >&2
        exit 1
        ;;
esac

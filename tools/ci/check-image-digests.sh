#!/usr/bin/env bash
#
# check-image-digests.sh — every CI container image is digest-pinned
# (issue #217, F-DEP-101/F-CI-012/F-SEC-007; helper committed under #190;
# extended to every workflow by issue #491, F-DEP-202).
#
# Every GitHub action is SHA-pinned, but the container images that actually
# compile the shipped packages were floating major tags — the strongest link
# in the supply chain was the least pinned, and invisible to the dependency
# bot because the references lived in a shell command rather than a manifest.
#
# With no argument it scans every .github/workflows/*.yml|*.yaml and every
# .github/actions/*/action.yml|yaml. Image references are collected from:
#   - `image:` / `container:` values — block mappings, `container: <ref>`
#     shorthand and the inline `{ name: …, image: "…" }` matrix rows
#   - `uses: docker://<ref>` steps
#   - the image operand of `docker run|create|pull` commands in run blocks
# and checked that:
#   - every reference is name@sha256:<64-hex-digest>
#   - every pinned reference is recorded in tools/ci/base-images.txt, the
#     file tools/ci/refresh-base-images.sh resolves against upstream on the
#     schedule of .github/workflows/base-image-refresh.yml
#   - every recorded entry is still used by some scanned file (full scan only)
#   - release-packages.yml actually reads that file (it greps its matrix pin)
# References built from `${{ … }}` or shell variables are skipped: they
# resolve to a value scanned elsewhere (the matrix rows).
#
# Exit codes: 0 = all pinned + recorded, 1 = a violation, 2 = helper broken.
#
# Usage: bash tools/ci/check-image-digests.sh [workflow.yml ...]
#   ROOT_DIR=<dir>        repository root to scan (default: this checkout)
#   IMAGE_BASELINE=<path> baseline file, relative to ROOT_DIR
#                         (default: tools/ci/base-images.txt)

set -euo pipefail

ROOT="${ROOT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$ROOT"

BASELINE="${IMAGE_BASELINE:-tools/ci/base-images.txt}"

command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

python3 - "$BASELINE" "$@" <<'PYEOF'
import glob
import re
import shlex
import sys

baseline_path, explicit = sys.argv[1], sys.argv[2:]

if explicit:
    files = explicit
    full_scan = False
else:
    files = []
    for pattern in (".github/workflows/*.yml", ".github/workflows/*.yaml",
                    ".github/actions/*/action.yml",
                    ".github/actions/*/action.yaml"):
        files.extend(sorted(glob.glob(pattern)))
    full_scan = True

if not files:
    print("✗ no workflow files found — is this the repository root?",
          file=sys.stderr)
    sys.exit(2)
for f in files:
    try:
        open(f, encoding="utf-8").close()
    except OSError:
        print(f"✗ workflow not found: {f}", file=sys.stderr)
        sys.exit(2)

# A YAML key at line start (optionally a `- ` list item) or inside an inline
# `{ … }` mapping — never the tail of another key such as `cache-image:`.
KEY_PREFIX = r'(?:^[ \t]*(?:-[ \t]+)?|[{,][ \t]*)'
KEY_QUOTED = re.compile(
    KEY_PREFIX + r'(?:image|container)[ \t]*:[ \t]*["\']([^"\']+)["\']')
KEY_BARE = re.compile(
    KEY_PREFIX + r'(?:image|container)[ \t]*:[ \t]*([^"\'\s,#{}]+)')
USES_DOCKER = re.compile(r'uses[ \t]*:[ \t]*["\']?docker://([^"\'\s#]+)')
DOCKER_CMD = re.compile(r'\bdocker\s+(run|create|pull)\b(.*)')
# docker run/create options that consume the following word.
VALUE_OPTS = {
    "-v", "--volume", "-w", "--workdir", "-e", "--env", "--env-file",
    "--platform", "--name", "-u", "--user", "--network", "--net",
    "--entrypoint", "--mount", "-p", "--publish", "-l", "--label",
    "--cap-add", "--cap-drop", "--security-opt", "--tmpfs", "--device",
    "--ulimit", "-m", "--memory", "--cpus", "-h", "--hostname",
    "--add-host", "--pull", "--shm-size", "--ipc", "--pid", "--group-add",
    "--volumes-from", "--log-driver", "--log-opt", "--runtime", "--gpus",
    "--restart", "--stop-timeout", "--stop-signal", "--dns", "--dns-search",
    "--dns-option", "--cidfile", "-a", "--attach", "--expose", "--health-cmd",
    "--health-interval", "--health-retries", "--health-timeout", "-c",
    "--cpu-shares", "--cpuset-cpus", "--storage-opt", "--sysctl",
    "--isolation", "--label-file", "--mac-address", "--ip", "--ip6",
    "--memory-swap", "--pids-limit", "--userns", "--uts", "--cgroupns",
    "--cgroup-parent", "--blkio-weight", "--oom-score-adj", "--detach-keys",
}


def logical_lines(text):
    """Yield (line_no, line) with shell `\\` continuations joined."""
    buf, start = "", None
    for no, raw in enumerate(text.splitlines(), 1):
        if raw.lstrip().startswith("#"):
            continue
        if start is None:
            start = no
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        yield start, buf + raw
        buf, start = "", None
    if buf:
        yield start, buf


def docker_image(args):
    try:
        words = shlex.split(args, comments=True)
    except ValueError:
        words = args.split()
    skip = False
    for w in words:
        if skip:
            skip = False
            continue
        if w in ("&&", "||", ";", "|"):
            return None
        if w.startswith("-"):
            if "=" not in w and w in VALUE_OPTS:
                skip = True
            continue
        return w
    return None


refs = {}  # ref -> [file:line, ...]
for path in files:
    text = open(path, encoding="utf-8").read()
    for no, line in logical_lines(text):
        found = KEY_QUOTED.findall(line) + KEY_BARE.findall(line) \
              + USES_DOCKER.findall(line)
        for m in DOCKER_CMD.finditer(line):
            img = docker_image(m.group(2))
            if img:
                found.append(img)
        for r in found:
            if "${{" in r or "$" in r:
                continue
            refs.setdefault(r, []).append(f"{path}:{no}")

if not refs:
    print("✗ no image/container references found in the scanned files — "
          "is this the right file?", file=sys.stderr)
    sys.exit(2)

errors = 0
unpinned = sorted(r for r in refs if "@sha256:" not in r)
for r in unpinned:
    print(f"  ✗ floating image reference: {r}  ({', '.join(refs[r])})")
errors += len(unpinned)
if not unpinned:
    print(f"  ✓ all {len(refs)} image reference(s) in {len(files)} file(s) "
          "are digest-pinned")

bad_digest = sorted(r for r in refs
                    if "@sha256:" in r
                    and not re.search(r'@sha256:[0-9a-f]{64}$', r))
for r in bad_digest:
    print(f"  ✗ malformed digest pin: {r}  ({', '.join(refs[r])})")
errors += len(bad_digest)

# The pinned set must be recorded in the tracked baseline file that the
# scheduled refresh job resolves against upstream.
recorded, baseline_read = set(), True
try:
    for line in open(baseline_path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if line and not line.startswith("digest-source"):
            recorded.add(line)
except OSError:
    print(f"  ✗ {baseline_path} not found")
    errors += 1
    baseline_read = False

pinned = sorted(r for r in refs if "@sha256:" in r)
if baseline_read:
    missing = [r for r in pinned if r not in recorded]
    stale = sorted(r for r in recorded if r not in refs) if full_scan else []
    for r in missing:
        print(f"  ✗ pinned image missing from {baseline_path}: {r}  "
              f"({', '.join(refs[r])})")
    for r in stale:
        print(f"  ✗ {baseline_path} entry matches no workflow image: {r}")
    errors += len(missing) + len(stale)
    if not missing and not stale:
        print(f"  ✓ {baseline_path} records all {len(pinned)} pinned image(s)")

for path in files:
    if path.endswith("release-packages.yml") \
            and baseline_path not in open(path, encoding="utf-8").read():
        print(f"  ✗ {path} never reads {baseline_path} — the file is "
              "decoration, not a source")
        errors += 1

if errors:
    print(f"✗ {errors} image-pinning violation(s)", file=sys.stderr)
    print("To fix:  pin each image as name:tag@sha256:<index-digest> and "
          "record it in", file=sys.stderr)
    print(f"         {baseline_path} (issues #217, #491); resolve a digest "
          "with", file=sys.stderr)
    print("         docker buildx imagetools inspect <name>:<tag>",
          file=sys.stderr)
    sys.exit(1)
print("✓ CI container images are digest-pinned and recorded")
PYEOF

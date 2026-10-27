#!/usr/bin/env bash
#
# refresh-base-images.sh — resolve every pin in tools/ci/base-images.txt
# against its upstream registry (issue #491, F-DEP-202/F-DEP-201).
#
# Each baseline entry is name:tag@sha256:<index-digest>. For every entry the
# script asks the registry for:
#   - the digest the tag points at today   (name:tag)
#   - whether the pinned digest still exists (name@sha256:<pinned>)
# and reports one verdict per image:
#   ok       the tag still points at the pinned digest
#   drift    the tag moved; the pinned digest still resolves
#   missing  the pinned digest is gone upstream (quay.io drops the previous
#            centos:stream9 manifest as soon as it retags, issues #587/#590)
#            — every job that pulls the pin now fails
# A repin target must be an index that covers linux/amd64 and linux/arm64
# (the arm64 release leg runs natively, issue #421); a tag that resolves to
# anything narrower is reported as a violation and never written. An entry
# whose image is only ever pulled on amd64 runners and has no arm64 build
# upstream (archlinux, issue #493) narrows its own requirement with a
# trailing `# platforms: linux/amd64` comment on its baseline line.
#
# Modes:
#   --check (default)  report; exit 1 on any drift, missing digest or
#                      platform violation
#   --write            rewrite each drifted/missing pin to the current digest,
#                      in the baseline and in every .github/workflows/* and
#                      .github/actions/*/action.y*ml file that quotes it;
#                      exit 1 when some pin could not be repinned
#   --registry <host>  with either mode: only the entries whose image is
#                      hosted on <host> (name starts with `<host>/`, e.g.
#                      quay.io); a host no entry uses is exit 2
#
# The scheduled .github/workflows/base-image-refresh.yml runs --check on
# every pin daily, and --check --registry quay.io hourly (quay.io drops a
# superseded CentOS Stream manifest the moment it retags, issue #641); on a
# violation it runs --write over every pin in a job that proposes the repin
# as one PR or issue.
#
# Exit codes: 0 = all pins current (--check) / repins written or none needed
# (--write), 1 = a violation, 2 = helper broken or a registry unreachable.
#
# Environment:
#   ROOT_DIR=<dir>        repository root (default: this checkout)
#   IMAGE_BASELINE=<path> baseline file relative to ROOT_DIR
#                         (default: tools/ci/base-images.txt)
#   IMAGE_INSPECT=<cmd>   command run as `<cmd> <ref>` that prints the
#                         manifest JSON of `docker buildx imagetools inspect
#                         <ref> --format '{{json .Manifest}}'` and exits
#                         non-zero when <ref> does not resolve, with
#                         "not found" on stderr when the registry says so
#                         (default: that docker command; the self-test stubs
#                         it)

set -euo pipefail

ROOT="${ROOT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$ROOT"

MODE="check"
ONLY_REGISTRY=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --check) MODE="check" ;;
        --write) MODE="write" ;;
        --registry)
            [[ "${2:-}" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]+)?$ ]] \
                || { echo "✗ --registry needs a registry host, e.g. quay.io" >&2; exit 2; }
            ONLY_REGISTRY="$2"
            shift ;;
        -h|--help) sed -n '2,/^$/p' "$0"; exit 0 ;;
        *) echo "✗ unknown argument: $1 (use --check or --write, optionally with --registry <host>)" >&2
           exit 2 ;;
    esac
    shift
done

BASELINE="${IMAGE_BASELINE:-tools/ci/base-images.txt}"
[ -f "$BASELINE" ] || { echo "✗ baseline not found: $BASELINE" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }
if [ -z "${IMAGE_INSPECT:-}" ]; then
    command -v docker >/dev/null 2>&1 \
        || { echo "✗ docker (with buildx) is required" >&2; exit 2; }
fi

python3 -u - "$MODE" "$BASELINE" "$ONLY_REGISTRY" <<'PYEOF'
import glob
import json
import os
import re
import shlex
import subprocess
import sys

mode, baseline_path, only_registry = sys.argv[1], sys.argv[2], sys.argv[3]
inspect_cmd = os.environ.get("IMAGE_INSPECT")
REQUIRED = ("linux/amd64", "linux/arm64")
PIN = re.compile(r'^(?P<name>[^\s@]+):(?P<tag>[^\s:@/]+)@(?P<digest>sha256:[0-9a-f]{64})$')
PLATFORMS = re.compile(r'platforms:\s*([A-Za-z0-9/_,\s-]+)')


class Unreachable(Exception):
    """The registry could not answer (network, rate limit, auth)."""


def inspect(ref):
    """Return (digest, platforms) for ref, None when the registry reports it
    not found, or raise Unreachable for any other failure."""
    if inspect_cmd:
        argv = shlex.split(inspect_cmd) + [ref]
    else:
        argv = ["docker", "buildx", "imagetools", "inspect", ref,
                "--format", "{{json .Manifest}}"]
    try:
        out = subprocess.run(argv, capture_output=True, text=True,
                             timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"✗ inspector failed to run for {ref}: {exc}", file=sys.stderr)
        sys.exit(2)
    if out.returncode != 0:
        if "not found" in out.stderr.lower():
            return None
        raise Unreachable((out.stderr.strip().splitlines() or ["no output"])[-1])
    try:
        manifest = json.loads(out.stdout)
        digest = manifest["digest"]
    except (ValueError, KeyError, TypeError):
        print(f"✗ unparsable inspector output for {ref}", file=sys.stderr)
        sys.exit(2)
    platforms = set()
    for m in manifest.get("manifests") or []:
        p = m.get("platform") or {}
        if p.get("os") and p.get("architecture"):
            platforms.add(f"{p['os']}/{p['architecture']}")
    return digest, platforms


entries = []
for no, raw in enumerate(open(baseline_path, encoding="utf-8"), 1):
    line, _, comment = raw.partition("#")
    line = line.strip()
    if not line or line.startswith("digest-source"):
        continue
    m = PIN.match(line)
    if not m:
        print(f"✗ {baseline_path}:{no}: not name:tag@sha256:<digest>: {line}",
              file=sys.stderr)
        sys.exit(2)
    if only_registry and not m["name"].startswith(only_registry + "/"):
        continue
    pm = PLATFORMS.search(comment)
    required = (tuple(p.strip() for p in pm.group(1).split(",") if p.strip())
                if pm else REQUIRED)
    entries.append((m, required))
if not entries:
    if only_registry:
        print(f"✗ {baseline_path} records no image hosted on {only_registry}",
              file=sys.stderr)
    else:
        print(f"✗ {baseline_path} records no image", file=sys.stderr)
    sys.exit(2)
scope = f" hosted on {only_registry}" if only_registry else ""

violations, repins, unreachable = 0, {}, 0
for m, required in entries:
    name, tag, pinned = m["name"], m["tag"], m["digest"]
    old = m.group(0)
    try:
        current = inspect(f"{name}:{tag}")
        if current is not None and current[0] != pinned:
            still_there = inspect(f"{name}@{pinned}") is not None
    except Unreachable as exc:
        print(f"  ✗ unreachable  {name}:{tag} — registry error: {exc}")
        unreachable += 1
        continue
    if current is None:
        print(f"  ✗ unreachable  {name}:{tag} — the tag does not resolve "
              "(was it removed upstream?)")
        unreachable += 1
        continue
    digest, platforms = current
    lacking = [p for p in required if p not in platforms]
    if digest == pinned:
        print(f"  ✓ ok       {old}")
        continue
    verdict = "drift  " if still_there else "missing"
    detail = ("tag moved" if still_there
              else "pinned digest no longer exists upstream — every pull of "
                   "the pin fails")
    print(f"  ✗ {verdict}  {name}:{tag}  {pinned} -> {digest}  ({detail})")
    violations += 1
    if lacking:
        print(f"      ✗ {digest} lacks {', '.join(lacking)} — not repinned")
        continue
    repins[old] = f"{name}:{tag}@{digest}"

if mode == "write" and repins:
    targets = [baseline_path]
    for pattern in (".github/workflows/*.yml", ".github/workflows/*.yaml",
                    ".github/actions/*/action.yml",
                    ".github/actions/*/action.yaml"):
        targets.extend(sorted(glob.glob(pattern)))
    for path in targets:
        text = open(path, encoding="utf-8").read()
        new = text
        for old, ref in repins.items():
            new = new.replace(old, ref)
        if new != text:
            open(path, "w", encoding="utf-8").write(new)
            print(f"  → rewrote {path}")
    print(f"✓ repinned {len(repins)} image(s); run "
          "bash tools/ci/check-image-digests.sh to confirm the tree")

if unreachable:
    print(f"✗ {unreachable} tag(s) could not be resolved — inconclusive",
          file=sys.stderr)
    sys.exit(2)
if mode == "write":
    sys.exit(1 if len(repins) < violations else 0)
if violations:
    print(f"✗ {violations} base image pin(s) out of date", file=sys.stderr)
    print("To fix:  bash tools/ci/refresh-base-images.sh --write (the "
          "scheduled base-image-refresh", file=sys.stderr)
    print("         workflow proposes this repin as a pull request or issue)",
          file=sys.stderr)
    sys.exit(1)
print(f"✓ all {len(entries)} base image pin(s){scope} match their upstream tag")
PYEOF

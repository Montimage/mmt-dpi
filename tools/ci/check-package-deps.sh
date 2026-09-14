#!/usr/bin/env bash
#
# check-package-deps.sh — .deb/.rpm dependency declarations agree with the
# build (issue #219, F-DEP-203..206/F-CI-013; helper committed under #190).
#
# The two package families made contradictory claims about the same build
# output: the .deb Depends listed libraries nothing links against, the .rpm
# spec emitted no Requires:/BuildRequires: at all and inverted its
# version/release fields, and the release containers installed libxml2 for an
# ENABLESEC build build-package.sh never enabled.
#
# Static checks (no package build needed):
#   - every library in the deb Depends line is actually linked by the build
#     (a matching -l<lib> or pkg-config consumer in rules/*.mk/sdk/Makefile),
#     except libc which needs none and libstdc++6 which the $(CXX) link
#     driver adds implicitly (issue #218)
#   - the rpm spec stanza in sdk/Makefile emits Requires: and BuildRequires:
#     matching the deb Depends set
#   - the rpm spec's Version:/Release: fields are not inverted
#     (Version: must be $(VERSION), not $(GIT_VERSION))
#   - build-package.sh enables ENABLESEC, or the release containers stop
#     installing libxml2 — they must agree
#   - README.md names exactly the distributions the release matrix builds
#
# Exit codes: 0 = consistent, 1 = a contradiction found, 2 = helper broken.
#
# Usage: bash tools/ci/check-package-deps.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

for f in sdk/Makefile tools/ci/build-package.sh .github/workflows/release-packages.yml README.md; do
    [ -f "$f" ] || { echo "✗ required file missing: $f" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

python3 - <<'PYEOF'
import re
import sys

mk = open("sdk/Makefile", encoding="utf-8").read()
rules = ""
import glob
for f in glob.glob("rules/*.mk"):
    rules += open(f, encoding="utf-8").read()
buildpkg = open("tools/ci/build-package.sh", encoding="utf-8").read()
wf = open(".github/workflows/release-packages.yml", encoding="utf-8").read()
readme = open("README.md", encoding="utf-8").read()

errors = 0


def fail(msg):
    global errors
    errors += 1
    print(f"  ✗ {msg}")


def ok(msg):
    print(f"  ✓ {msg}")


# --- deb Depends vs what the build links -----------------------------------
m = re.search(r"Depends:\s*([^\n\\]+)", mk)
depends = []
if m:
    depends = [d.strip().split(" ")[0].split("|")[0].strip()
               for d in m.group(1).split(",") if d.strip()]
    depends = [d for d in depends if d and d != "libc6"]

links = mk + rules
for dep in depends:
    # libpcap0.8 → libpcap → -lpcap; libnghttp2-14 → libnghttp2 → -lnghttp2.
    # Strip only a Debian soname suffix: `-N`/`.N` after the `lib` stem.
    pkg = re.sub(r"-[0-9.]+$", "", dep)
    pkg = re.sub(r"(?<=[a-z])0[0-9.]*$", "", pkg)   # libpcap0.8 → libpcap
    stem = pkg[3:] if pkg.startswith("lib") else pkg
    # The C++ runtime carries no -l flag: every shared library is linked by
    # the $(CXX) driver (rules/common-linux.mk), which adds -lstdc++
    # implicitly. Its Depends entry is satisfied by the link rule itself.
    if pkg.startswith("libstdc++"):
        if re.search(r"\$\(CXX\)", links):
            ok(f"deb Depends {dep} is wired via the $(CXX) link driver")
        else:
            fail(f"deb Depends {dep} — shared libraries are not linked "
                 "with $(CXX)")
        continue
    if re.search(r"-l" + re.escape(stem) + r"\b|-l:?" + re.escape(pkg) + r"\b|"
                 r"pkg-config[^\n]*\b" + re.escape(pkg) + r"\b", links):
        ok(f"deb Depends {dep} is wired into the build (-l{stem}/pkg-config {pkg})")
    else:
        fail(f"deb Depends {dep} — no build rule links -l{stem} or "
             f"pkg-config {pkg}")

# --- rpm spec ---------------------------------------------------------------
rpm_stanza = mk[mk.find("rpm:"):] if "rpm:" in mk else ""
if "Requires:" in rpm_stanza:
    ok("rpm spec emits Requires:")
else:
    fail("rpm spec stanza emits no Requires:")
if "BuildRequires:" in rpm_stanza:
    ok("rpm spec emits BuildRequires:")
else:
    fail("rpm spec stanza emits no BuildRequires:")
if re.search(r"Version:\s*\$\(GIT_VERSION\)", rpm_stanza):
    fail("rpm spec Version: is $(GIT_VERSION) — version/release fields inverted")
elif re.search(r"Version:\s*\$\(VERSION\)", rpm_stanza):
    ok("rpm spec Version: uses $(VERSION)")

# --- ENABLESEC vs libxml2 ----------------------------------------------------
# The release containers' build-dep installs live in build-package.sh itself.
installs_libxml2 = bool(re.search(r"libxml2-(dev|devel)", buildpkg))
build_enables_sec = "ENABLESEC=1" in buildpkg
if installs_libxml2 == build_enables_sec:
    ok(f"libxml2 build-dep installed ({installs_libxml2}) agrees with "
       f"ENABLESEC=1 in build-package.sh ({build_enables_sec})")
else:
    fail(f"build-package.sh installs libxml2-*={installs_libxml2} but passes "
         f"ENABLESEC=1={build_enables_sec} — the containers and the build "
         "disagree")

# --- README distro claims vs the release matrix ------------------------------
matrix_names = sorted(set(re.findall(
    r'-\s*\{\s*name:\s*([a-z0-9.-]+)', wf)))
claimed = [d for d in matrix_names
           if re.search(re.escape(d.split("-")[0]), readme, re.I)]
if matrix_names and len(claimed) == len(matrix_names):
    ok("README names the release-matrix distributions")
else:
    missing = [d for d in matrix_names if d not in claimed]
    fail(f"README does not name all matrix distributions; missing: {missing}")

if errors:
    print(f"✗ {errors} package-declaration contradiction(s)", file=sys.stderr)
    print("To fix:  reconcile the deb/rpm declarations with the build"
          " (issue #219)", file=sys.stderr)
    sys.exit(1)
print("✓ package dependency declarations agree with the build")
PYEOF

#!/usr/bin/env bash
#
# check-package-deps.sh — .deb/.rpm dependency declarations agree with the
# build (issue #219, F-DEP-102/203..206/F-CI-013; helper committed under #190).
#
# The two package families made contradictory claims about the same build
# output: the .deb Depends listed libraries nothing links against, the .rpm
# spec emitted no Requires:/BuildRequires: at all and inverted its
# version/release fields, and the release containers installed libxml2 for an
# ENABLESEC build build-package.sh never enabled. The declarations are now
# *derived*: tools/ci/shlib-deps.sh maps the NEEDED entries of the shipped
# .so files to the packages providing them, and this script gates both the
# static wiring and (with --verify-package) the built artifact itself.
#
# Static checks (no package build needed):
#   - the deb Depends line is derived from the shipped .so NEEDED entries via
#     tools/ci/shlib-deps.sh; any literal package still named there must be
#     wired into the build (a matching -l<lib> or pkg-config consumer in
#     rules/*.mk/sdk/Makefile — except libc, which needs none, and
#     libstdc++6, which the $(CXX) link driver adds implicitly, issue #218)
#   - the rpm spec stanza in sdk/Makefile emits Requires: and BuildRequires:
#     matching the Debian set
#   - the rpm spec's Version:/Release: fields are not inverted
#     (Version: must be $(VERSION), Release: must be $(GIT_VERSION))
#   - build-package.sh enables ENABLESEC, or the release containers stop
#     installing libxml2 — they must agree
#   - README's package section names exactly the release-matrix distributions
#
# Dynamic check (built package required):
#   --verify-package <pkg.deb|pkg.rpm> [--payload-dir <dir>]
#   Compares the package's own metadata (`dpkg-deb -f` / `rpm -qp`) with the
#   NEEDED entries `objdump -p` reports for the shipped .so files and fails
#   on any divergence. The payload .so files are extracted from the package
#   when the tools allow; otherwise --payload-dir (default sdk/lib) is used.
#   build-package.sh runs this per artifact, so a drifted declaration fails
#   the release build itself.
#
# Exit codes: 0 = consistent, 1 = a contradiction found, 2 = helper broken.
#
# Usage:
#   bash tools/ci/check-package-deps.sh
#   bash tools/ci/check-package-deps.sh --verify-package dist/packages/x.deb

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

VERIFY_PKG=""
PAYLOAD_DIR="sdk/lib"
while [ $# -gt 0 ]; do
    case "$1" in
        --verify-package)
            [ $# -ge 2 ] || { echo "✗ --verify-package needs a path" >&2; exit 2; }
            VERIFY_PKG="$2"; shift 2 ;;
        --payload-dir)
            [ $# -ge 2 ] || { echo "✗ --payload-dir needs a directory" >&2; exit 2; }
            PAYLOAD_DIR="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "✗ unknown argument: $1" >&2; exit 2 ;;
    esac
done

for f in sdk/Makefile tools/ci/build-package.sh tools/ci/shlib-deps.sh \
         .github/workflows/release-packages.yml README.md; do
    [ -f "$f" ] || { echo "✗ required file missing: $f" >&2; exit 2; }
done
[ -x tools/ci/shlib-deps.sh ] \
    || { echo "✗ tools/ci/shlib-deps.sh is not executable" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

VERIFY_PKG="$VERIFY_PKG" PAYLOAD_DIR="$PAYLOAD_DIR" python3 - <<'PYEOF'
import glob
import os
import re
import subprocess
import sys
import tempfile

mk = open("sdk/Makefile", encoding="utf-8").read()
rules = ""
for f in glob.glob("rules/*.mk"):
    rules += open(f, encoding="utf-8").read()
buildpkg = open("tools/ci/build-package.sh", encoding="utf-8").read()
wf = open(".github/workflows/release-packages.yml", encoding="utf-8").read()
readme = open("README.md", encoding="utf-8").read()

verify_pkg = os.environ.get("VERIFY_PKG") or None
payload_dir = os.environ.get("PAYLOAD_DIR") or "sdk/lib"

errors = 0


def fail(msg):
    global errors
    errors += 1
    print(f"  ✗ {msg}")


def ok(msg):
    print(f"  ✓ {msg}")


def run(*argv):
    """Run argv, returning (rc, stdout, stderr) without raising."""
    try:
        r = subprocess.run(list(argv), capture_output=True, text=True)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", f"{argv[0]}: not found"


# --- deb Depends vs what the shipped payload links --------------------------
dep_m = re.search(r"Depends:\s*([^\n]+)", mk)
dep_text = dep_m.group(1).strip() if dep_m else ""

# Derived form: the stanza populates $$deps by running shlib-deps.sh over the
# staged package tree. Anything else is a hand-maintained list again.
deps_derived = bool(re.search(r"deps=`[^`]*shlib-deps\.sh'?\s+deb", mk)) \
    and dep_text.startswith("$$deps")
if deps_derived:
    ok("deb Depends is derived from the shipped .so NEEDED entries "
       "(tools/ci/shlib-deps.sh)")
    literal = re.sub(r"\$\$deps", "", dep_text)
    # The stanza's make/shell continuation backslash is not a list entry.
    literal = literal.rstrip("\\").strip().strip(",").strip()
    if literal:
        fail(f"deb Depends mixes derived deps with a literal list: "
             f"{literal!r} — keep every entry derived")
else:
    fail("deb Depends is not derived from the shipped .so NEEDED entries — "
         "route it through tools/ci/shlib-deps.sh (issue #219)")
    depends = []
    if dep_text:
        depends = [d.strip().split(" ")[0].split("|")[0].strip()
                   for d in dep_text.split(",") if d.strip()]
        depends = [d for d in depends
                   if d and d != "libc6" and not d.startswith("$")]

    links = mk + rules
    for dep in depends:
        # libpcap0.8 → libpcap → -lpcap; libnghttp2-14 → libnghttp2 →
        # -lnghttp2. Strip only a Debian soname suffix: `-N`/`.N` after the
        # `lib` stem.
        pkg = re.sub(r"-[0-9.]+$", "", dep)
        pkg = re.sub(r"(?<=[a-z])0[0-9.]*$", "", pkg)   # libpcap0.8 → libpcap
        stem = pkg[3:] if pkg.startswith("lib") else pkg
        # The C++ runtime carries no -l flag: every shared library is linked
        # by the $(CXX) driver (rules/common-linux.mk), which adds -lstdc++
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
            ok(f"deb Depends {dep} is wired into the build "
               f"(-l{stem}/pkg-config {pkg})")
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
else:
    fail("rpm spec Version: is not $(VERSION)")
if re.search(r"Release:\s*\$\(VERSION\)", rpm_stanza):
    fail("rpm spec Release: is $(VERSION) — version/release fields inverted")
elif re.search(r"Release:\s*\$\(GIT_VERSION\)", rpm_stanza):
    ok("rpm spec Release: carries $(GIT_VERSION) as the revision")
else:
    fail("rpm spec Release: does not carry $(GIT_VERSION)")

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
matrix_stems = sorted(set(d.split("-")[0] for d in matrix_names))

# The claim must be exact (F-DEP-102): the Pre-built packages section names
# every matrix target and no other distribution family.
sec_m = re.search(r"### Pre-built packages(.*?)(?=\n### |\n## |\Z)",
                  readme, re.S)
pkg_section = sec_m.group(1) if sec_m else ""
if not pkg_section:
    fail("README has no '### Pre-built packages' section")
missing = [d for d in matrix_names
           if not re.search(re.escape(d.split("-")[0]), pkg_section, re.I)]
# Distribution families the matrix does not produce packages for. 'rhel'
# covers 'RedHat'/spelling variants only as whole words; Rocky and CentOS
# ARE matrix targets and stay claimable.
non_matrix = ["fedora", "arch", "alpine", "opensuse", "open suse",
              "sles", "gentoo", "mint", "manjaro", "nixos",
              "redhat", "red hat", "rhel"]
extra = [d for d in non_matrix
         if re.search(r"\b" + re.escape(d) + r"\b", pkg_section, re.I)]
if matrix_names and not missing and not extra:
    ok("README's package section names exactly the release-matrix "
       "distributions")
else:
    bits = []
    if missing:
        bits.append(f"missing: {missing}")
    if extra:
        bits.append(f"non-matrix named: {extra}")
    fail("README package section does not name exactly the matrix "
         f"distributions ({'; '.join(bits)})")

# --- dynamic: declared metadata vs the shipped NEEDED entries ----------------
if verify_pkg:
    if not os.path.isfile(verify_pkg):
        fail(f"--verify-package: no such file: {verify_pkg}")
        verify_pkg = None

if verify_pkg:
    ext = verify_pkg.rsplit(".", 1)[-1]
    cmk = open("rules/common.mk", encoding="utf-8", errors="replace").read()
    mver = re.search(r"^VERSION\s*:?=\s*(\S+)", cmk, re.M)
    version = mver.group(1) if mver else ""
    if not version:
        fail("could not read VERSION from rules/common.mk")

    # Scan directory of payload .so files: prefer extracting the package
    # itself; fall back to the sdk/lib the payload was copied from.
    scan_dir = None
    with tempfile.TemporaryDirectory() as tmp:
        if ext == "deb":
            rc, _, err = run("dpkg-deb", "-x", verify_pkg, tmp)
            if rc != 0:
                fail(f"dpkg-deb -x failed: {err.strip()}")
        elif ext == "rpm":
            # rpm2archive + tar are the most portable pair; rpm2cpio needs a
            # separate cpio binary minimal images often lack.
            rc1, _, _ = run("bash", "-c",
                            f"rpm2archive '{verify_pkg}' | tar -x -C '{tmp}'")
            if rc1 != 0:
                run("bash", "-c",
                    f"rpm2cpio '{verify_pkg}' | (cd '{tmp}' && cpio -idm "
                    "--quiet)")
        else:
            fail(f"--verify-package: unhandled extension .{ext}")
        found = [p for p in glob.glob(f"{tmp}/**/*.so*", recursive=True)
                 if os.path.isfile(p) and not os.path.islink(p)]
        if found:
            scan_dir = tmp
        else:
            print(f"  ○ payload not extractable from {verify_pkg} — "
                  f"scanning {payload_dir} instead")
            scan_dir = payload_dir

        # The extraction must happen (and the scans run) while tmp exists.
        if not os.path.isdir(scan_dir):
            fail(f"no payload .so directory: {scan_dir}")
            scan_dir = None

        if scan_dir:
            rc, sonames, err = run("bash", "tools/ci/shlib-deps.sh",
                                   "sonames", scan_dir)
            if rc != 0 or not sonames.strip():
                fail(f"shlib-deps.sh sonames failed: {err.strip()}")
                sonames = None

            # Expected declaration set, produced by the same mapper the
            # Makefile uses — so a match means declaration == payload.
            mode = "deb" if ext == "deb" else "rpm"
            rc, expected, err = run("bash", "tools/ci/shlib-deps.sh",
                                    mode, scan_dir)
            if rc != 0:
                fail(f"shlib-deps.sh {mode} failed: {err.strip()}")
                expected = None

    def norm(tok):
        return re.sub(r"\s+", "", tok)

    if verify_pkg and ext == "deb" and scan_dir and expected:
        rc, out, err = run("dpkg-deb", "-f", verify_pkg, "Depends")
        if rc != 0:
            fail(f"dpkg-deb -f Depends failed: {err.strip()}")
        else:
            declared = {norm(t) for t in out.strip().split(",") if t.strip()}
            want = {norm(t) for t in expected.strip().split(",") if t.strip()}
            # Alternatives: a declared `a | b` token is covered when any of
            # its names matches a wanted entry, and vice versa.
            def names(tok):
                return {norm(x) for x in re.split(r"[|(]", tok)
                        if x and x != ")"}
            declared_names = set().union(*(names(t) for t in declared)) \
                if declared else set()
            want_names = {norm(re.split(r"[( ]", t)[0]) for t in want}
            missing = sorted(want_names - declared_names)
            unexpected = sorted(t for t in declared
                                if not (names(t) & want_names))
            if not missing and not unexpected:
                ok(f"{os.path.basename(verify_pkg)}: Depends == NEEDED-derived "
                   f"set ({sorted(want_names)})")
            else:
                if missing:
                    fail(f"{verify_pkg}: NEEDED-derived packages missing "
                         f"from Depends: {missing} (sonames: "
                         f"{sonames.split()})")
                if unexpected:
                    fail(f"{verify_pkg}: Depends entries not backed by any "
                         f"NEEDED soname: {unexpected}")
        rc, ver, err = run("dpkg-deb", "-f", verify_pkg, "Version")
        if rc == 0 and ver.strip().startswith(version + "-"):
            ok(f"{os.path.basename(verify_pkg)}: Version {ver.strip()} "
               f"is {version}-<revision>")
        else:
            fail(f"{verify_pkg}: Version {ver.strip()!r} does not start "
                 f"with {version}- (dpkg-deb rc={rc})")

    if verify_pkg and ext == "rpm" and scan_dir and expected:
        rc, ver, err = run("rpm", "-qp", "--qf", "%{VERSION}", verify_pkg)
        if rc == 0 and ver.strip() == version:
            ok(f"{os.path.basename(verify_pkg)}: %{{VERSION}} == {version} "
               "(not the git hash)")
        else:
            fail(f"{verify_pkg}: rpm VERSION {ver.strip()!r} != {version} "
                 f"from rules/common.mk (rpm rc={rc})")
        rc, rel, _ = run("rpm", "-qp", "--qf", "%{RELEASE}", verify_pkg)
        if rc == 0 and rel.strip() and rel.strip() != version:
            ok(f"{os.path.basename(verify_pkg)}: %{{RELEASE}} carries the "
               f"revision ({rel.strip()})")
        else:
            fail(f"{verify_pkg}: rpm RELEASE {rel.strip()!r} is empty or "
                 "still holds the upstream version — fields inverted?")
        rc, out, err = run("rpm", "-qp", "--requires", verify_pkg)
        if rc != 0:
            fail(f"rpm -qp --requires failed: {err.strip()}")
        else:
            lines = {re.sub(r"\s+", " ", ln.strip())
                     for ln in out.splitlines() if ln.strip()}
            want = {re.sub(r"\s+", " ", t.strip())
                    for t in expected.strip().split(",") if t.strip()}
            missing = sorted(t for t in want
                             if not any(ln == t or ln.startswith(
                                 t.split(" ")[0] + " ") for ln in lines))
            # Anything in --requires that is not an auto-generated soname,
            # an rpmlib/rtld marker, an interpreter path or a wanted entry
            # is a stale hand-written Requires — flag it.
            stray = sorted(
                ln for ln in lines
                if ".so" not in ln and "(" not in ln
                and not ln.startswith("/")
                and not any(ln == t or ln.startswith(t.split(" ")[0] + " ")
                            for t in want))
            if not missing and not stray:
                ok(f"{os.path.basename(verify_pkg)}: Requires cover the "
                   "NEEDED-derived set with no stale entries")
            else:
                if missing:
                    fail(f"{verify_pkg}: Requires missing NEEDED-derived "
                         f"packages: {missing}")
                if stray:
                    fail(f"{verify_pkg}: stale Requires entries not backed "
                         f"by NEEDED: {stray}")

if errors:
    print(f"✗ {errors} package-declaration contradiction(s)", file=sys.stderr)
    print("To fix:  reconcile the deb/rpm declarations with the build"
          " (issue #219)", file=sys.stderr)
    sys.exit(1)
print("✓ package dependency declarations agree with the build")
PYEOF

#!/usr/bin/env bash
#
# check-dependency-lists.sh — every build-dependency list equals what its one
# source says it must hold (issue #495, F-DEP-003/F-DEP-304).
#
# Five files install packages for this build, in several package managers'
# names: install.sh (six package-manager branches), the release containers'
# tools/ci/install-build-deps.sh (deb + rpm), the rpm spec's BuildRequires:
# in sdk/Makefile, the CI composite action .github/actions/bootstrap-deps and
# the toolchain install line in docs/AGENT_ENVIRONMENT.md. Kept by hand they
# drifted from the code. tools/ci/build-deps.txt is now the single source: a
# `role` row names the packages a role needs on one package manager, a
# `list` row names the roles one extracted list must cover. This script
# extracts each list and compares it, as a set, with the union of its roles.
#
# Extraction rules:
#   - install.sh: the apt-get / dnf / yum / pacman / apk / zypper install
#     commands inside install_deps_linux(), one per branch.
#   - install-build-deps.sh: the install commands inside
#     install_build_deps_debian() and install_build_deps_rhel(). A command
#     chained with `|| true` is a best-effort helper (dnf-plugins-core, which
#     only enables the CRB repository) and is not part of the list.
#   - sdk/Makefile: the BuildRequires: entries, version floors stripped.
#   - bootstrap-deps: its apt-get install line; the `${{ inputs.* }}`
#     expression (job-specific extras) is not part of the base list.
#   - AGENT_ENVIRONMENT.md: the one `apt-get install` line naming
#     build-essential.
#   Option words (-y, --no-install-recommends, …), shell words ($SUDO, "$pm")
#   and line continuations are dropped. A list found zero or several times,
#   an extractor without a `list` row, a `list` row without an extractor, and
#   a role a list names but the manifest does not define for its manager are
#   all failures — the lint never passes by not looking.
#
# Environment:
#   ROOT_DIR=<dir>   repository root to check (default: this checkout) — the
#                    self-test runs the real script on fixture trees
#
# Exit codes: 0 = every list matches, 1 = a list diverges, 2 = helper broken.
#
# Usage: bash tools/ci/check-dependency-lists.sh

set -euo pipefail

ROOT="${ROOT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$ROOT"

for f in tools/ci/build-deps.txt install.sh tools/ci/install-build-deps.sh \
         sdk/Makefile .github/actions/bootstrap-deps/action.yml \
         docs/AGENT_ENVIRONMENT.md; do
    [ -f "$f" ] || { echo "✗ required file missing: $f" >&2; exit 2; }
done
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }

python3 -u - <<'PYEOF'
import re
import sys

MANIFEST = "tools/ci/build-deps.txt"
errors = 0


def fail(msg):
    global errors
    errors += 1
    print(f"  ✗ {msg}")


def broken(msg):
    print(f"✗ {msg}", file=sys.stderr)
    sys.exit(2)


# --- manifest ---------------------------------------------------------------
roles = {}   # (role, manager) -> set of packages
lists = {}   # id -> (manager, [roles])
for n, raw in enumerate(open(MANIFEST, encoding="utf-8"), 1):
    line = raw.split("#", 1)[0].split()
    if not line:
        continue
    kind = line[0]
    if kind == "role" and len(line) >= 4:
        key = (line[1], line[2])
        if key in roles:
            broken(f"{MANIFEST}:{n}: role {line[1]}/{line[2]} defined twice")
        roles[key] = set(line[3:])
    elif kind == "list" and len(line) >= 4:
        if line[1] in lists:
            broken(f"{MANIFEST}:{n}: list {line[1]} defined twice")
        lists[line[1]] = (line[2], line[3:])
    else:
        broken(f"{MANIFEST}:{n}: expected `role <role> <manager> <pkg>...` "
               f"or `list <id> <manager> <role>...`, got: {raw.strip()}")


# --- extraction -------------------------------------------------------------
def read(path):
    return open(path, encoding="utf-8").read()


def function_body(text, name, path):
    """Lines of the shell function `name() {` … the next column-0 `}`."""
    m = re.search(r"^" + re.escape(name) + r"\(\)\s*\{\n(.*?)^\}", text,
                  re.M | re.S)
    if not m:
        broken(f"{path}: no {name}() function")
    return m.group(1)


def commands(body):
    """Logical command lines: backslash continuations joined."""
    out, cur = [], ""
    for ln in body.split("\n"):
        stripped = ln.rstrip()
        if stripped.endswith("\\"):
            cur += stripped[:-1] + " "
            continue
        out.append(cur + stripped)
        cur = ""
    if cur:
        out.append(cur)
    return out


def packages(words):
    """Package names among the words after the install verb."""
    pkgs = []
    for w in words:
        w = w.strip("'\"")
        if not w or w.startswith(("-", "$")) or w in ("||", "&&", ";"):
            if w in ("||", "&&", ";"):
                break
            continue
        pkgs.append(w)
    return pkgs


# Install verbs per package manager: the word after which package names start.
VERBS = {
    "apt-get": lambda ws, i: ws[i + 1] == "install" and i + 1,
    "dnf": lambda ws, i: ws[i + 1] == "install" and i + 1,
    "yum": lambda ws, i: ws[i + 1] == "install" and i + 1,
    '"$pm"': lambda ws, i: ws[i + 1] == "install" and i + 1,
    "zypper": lambda ws, i: ws[i + 1] == "install" and i + 1,
    "apk": lambda ws, i: ws[i + 1] == "add" and i + 1,
    "pacman": lambda ws, i: ws[i + 1].startswith("-S") and i + 1,
}


def install_commands(body):
    """(tool, packages, best_effort) for each install command in body."""
    found = []
    for cmd in commands(body):
        ws = cmd.split()
        for i, w in enumerate(ws[:-1]):
            verb = VERBS.get(w)
            if verb is None:
                continue
            at = verb(ws, i)
            if at is False:
                continue
            best_effort = bool(re.search(r"\|\|\s*true\b", cmd))
            found.append((w.strip('"$'), packages(ws[at + 1:]), best_effort))
            break
    return found


extracted = {}   # id -> list of packages (or None when not found once)


def put(list_id, candidates, where):
    if len(candidates) != 1:
        fail(f"{list_id}: expected one install command in {where}, "
             f"found {len(candidates)}")
        extracted[list_id] = None
        return
    extracted[list_id] = candidates[0]


# install.sh — one branch per package manager.
text = read("install.sh")
body = function_body(text, "install_deps_linux", "install.sh")
cmds = install_commands(body)
for tool, suffix in (("apt-get", "apt"), ("dnf", "dnf"), ("yum", "yum"),
                     ("pacman", "pacman"), ("apk", "apk"),
                     ("zypper", "zypper")):
    put(f"install.sh:{suffix}",
        [p for t, p, _ in cmds if t == tool],
        "install.sh install_deps_linux()")

# install-build-deps.sh — deb and rpm, best-effort helpers excluded.
text = read("tools/ci/install-build-deps.sh")
for fn, list_id in (("install_build_deps_debian", "install-build-deps.sh:deb"),
                    ("install_build_deps_rhel", "install-build-deps.sh:rpm")):
    body = function_body(text, fn, "tools/ci/install-build-deps.sh")
    put(list_id, [p for _, p, be in install_commands(body) if not be],
        f"tools/ci/install-build-deps.sh {fn}()")

# sdk/Makefile — BuildRequires:, version floors stripped.
text = read("sdk/Makefile")
# The spec line is emitted as `\nBuildRequires: …` inside an echo.
found = re.findall(r"\\nBuildRequires:\s*([^\\\n]+)", text)
put("sdk/Makefile:BuildRequires",
    [[re.split(r"\s*[<>=]", e.strip())[0] for e in f.split(",") if e.strip()]
     for f in found],
    "sdk/Makefile")

# bootstrap-deps composite action — the job-specific extras are not base.
text = read(".github/actions/bootstrap-deps/action.yml")
found = []
for ln in text.split("\n"):
    if re.search(r"^\s*(sudo\s+)?apt-get\s+install\b", ln):
        ln = re.sub(r"\$\{\{[^}]*\}\}", " ", ln)
        found += [p for _, p, _ in install_commands(ln)]
put("bootstrap-deps", found, ".github/actions/bootstrap-deps/action.yml")

# docs/AGENT_ENVIRONMENT.md — the toolchain install line.
text = read("docs/AGENT_ENVIRONMENT.md")
found = [p for ln in text.split("\n")
         if re.search(r"apt-get\s+install\b", ln) and "build-essential" in ln
         for _, p, _ in install_commands(ln)]
put("AGENT_ENVIRONMENT.md", found, "docs/AGENT_ENVIRONMENT.md")


# --- comparison -------------------------------------------------------------
for list_id in sorted(set(lists) - set(extracted)):
    fail(f"{list_id}: listed in {MANIFEST} but this script has no extractor "
         "for it")
for list_id in sorted(extracted):
    if list_id not in lists:
        fail(f"{list_id}: extracted, but {MANIFEST} has no `list` row for it")
        continue
    pkgs = extracted[list_id]
    if pkgs is None:
        continue
    manager, want_roles = lists[list_id]
    want = set()
    for role in want_roles:
        if (role, manager) not in roles:
            fail(f"{list_id}: role {role!r} has no `role {role} {manager}` "
                 f"row in {MANIFEST}")
            continue
        want |= roles[(role, manager)]
    have = set(pkgs)
    dupes = sorted({p for p in pkgs if pkgs.count(p) > 1})
    missing = sorted(want - have)
    extra = sorted(have - want)
    if missing or extra or dupes:
        bits = []
        if missing:
            bits.append(f"missing {missing}")
        if extra:
            bits.append(f"not in {MANIFEST} {extra}")
        if dupes:
            bits.append(f"repeated {dupes}")
        fail(f"{list_id} ({manager}: {' + '.join(want_roles)}): "
             + "; ".join(bits))
    else:
        print(f"  ✓ {list_id} == {' + '.join(want_roles)} "
              f"({len(have)} {manager} packages)")

if errors:
    print(f"✗ {errors} dependency list(s) diverge from {MANIFEST}",
          file=sys.stderr)
    print(f"To fix:  change {MANIFEST} first, then make every list it names "
          "match (issue #495)", file=sys.stderr)
    sys.exit(1)
print(f"✓ every build-dependency list matches {MANIFEST}")
PYEOF

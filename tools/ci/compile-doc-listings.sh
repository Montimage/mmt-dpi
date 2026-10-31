#!/usr/bin/env bash
#
# compile-doc-listings.sh — every C listing of the docs and every example
# program compiles against an installed SDK (issue #581, F-DOCS-006,
# F-BUG-018).
#
# Nothing compiled docs/Examples.md or src/examples/, so they rotted: three
# of the five listings did not compile (`=` mangled to `#`, a field read
# through the opaque mmt_session_t, a header path that is not installed) and
# an example had `return;` in `int main`. This gate compiles, against the
# headers and libraries of an installed SDK:
#
#   * every ```c fenced listing of each DOC (default docs/Examples.md), with
#     the first `gcc …` command of the ```sh fence that follows it, before the
#     next listing — so the command the reader copies is checked too. /opt/mmt
#     in that command is the install prefix, and only `-I`/`-L`/`-l`/`-o`/`-g`/
#     `-O`/`-W<warning>`/`-D`/`-std` arguments and the source file are
#     accepted from it (no `-Wno-*`, `-w`, `-Wl,`/`-Wp,`/`-Wa,`); <STRICT>
#     below is appended after them, so a documented flag cannot disarm it.
#     A fence tagged ```C, ```cpp or ```c <anything> is refused (exit 2).
#     A listing with no such command is compiled with the default command
#     below; a listing without a `main(` is compiled with `-c` only.
#   * every src/examples/*.c, with the default command:
#         $CC <STRICT> -o <name> <file> -I <prefix>/dpi/include
#             -L <prefix>/dpi/lib -lmmt_core -ldl -lpcap
#
# <STRICT> is `-Wall -Werror=return-type` plus the diagnostics GCC 14 turned
# into errors by default (implicit-function-declaration, implicit-int,
# int-conversion, incompatible-pointer-types, and return-mismatch /
# declaration-missing-parameter-type where the compiler knows them), so
# GCC 13 — the CI toolchain — rejects what GCC >= 14 rejects. No -std is
# forced: the compiler's default dialect is the reader's. EXTRA_CFLAGS (the
# runner's sanitizer and -f[un]signed-char flags) is appended.
#
# Programs are compiled and linked, never run (tests/docs_lifecycle runs
# packet_handler.c). Other pages' complete programs can be added as DOC
# arguments; the prototype listings of the API reference pages are checked
# against the headers by tools/ci/public-prototypes.py instead.
#
# Usage: bash tools/ci/compile-doc-listings.sh [--prefix DIR] [DOC...]
#   --prefix DIR  an installed SDK (DIR/dpi/include, DIR/dpi/lib). Without
#                 it the SDK is built and installed into a throwaway prefix
#                 first — `make -C sdk clean` included, so an existing sdk/
#                 build is discarded, as the suites that build it do.
#   DOC paths are relative to the repository root.
# Env: CC (default gcc), EXTRA_CFLAGS, JOBS, SDK_BUILD_PROFILE (BUILD=).
#
# Exit codes: 0 = everything compiles, 1 = a listing or example does not,
#             2 = helper broken (bad arguments, no listing found, a C fence
#             not tagged exactly ```c, SDK build or install failed, missing
#             tool).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

PREFIX=""
DOCS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="${2:?--prefix needs a directory}"; shift ;;
        -h|--help) sed -n '2,/^$/s/^# \{0,1\}//p' "$0"; exit 0 ;;
        -*)       echo "✗ unknown option: $1" >&2; exit 2 ;;
        *)        DOCS+=("$1") ;;
    esac
    shift
done
[ "${#DOCS[@]}" -gt 0 ] || DOCS=(docs/Examples.md)

CC="${CC:-gcc}"
command -v python3 >/dev/null 2>&1 || { echo "✗ python3 is required" >&2; exit 2; }
command -v "$CC" >/dev/null 2>&1 || { echo "✗ compiler '$CC' not found" >&2; exit 2; }
for d in "${DOCS[@]}"; do
    [ -f "$d" ] || { echo "✗ $d: no such file" >&2; exit 2; }
done

WORK="$(mktemp -d)"
OWN_PREFIX=""
cleanup() { rm -rf "$WORK"; [ -z "$OWN_PREFIX" ] || rm -rf "$OWN_PREFIX"; }
trap cleanup EXIT

if [ -z "$PREFIX" ]; then
    OWN_PREFIX="$(mktemp -d)"
    PREFIX="$OWN_PREFIX"
    JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"
    profile=()
    [ -z "${SDK_BUILD_PROFILE:-}" ] || profile=("BUILD=${SDK_BUILD_PROFILE}")
    echo "building + installing the SDK into ${PREFIX} ..."
    make -C sdk clean >/dev/null 2>&1 || true
    if ! { make -C sdk "${profile[@]}" -j"$JOBS" MMT_BASE="$PREFIX" \
           && make -C sdk "${profile[@]}" MMT_BASE="$PREFIX" install; } \
           >"$WORK/build.log" 2>&1; then
        echo "✗ SDK build/install failed — last lines:" >&2
        tail -20 "$WORK/build.log" >&2
        exit 2
    fi
fi
if ! { [ -e "$PREFIX/dpi/lib/libmmt_core.so" ] && [ -f "$PREFIX/dpi/include/mmt_core.h" ]; }; then
    echo "✗ $PREFIX holds no installed SDK (dpi/lib/libmmt_core.so, dpi/include/mmt_core.h)" >&2
    exit 2
fi

# The strict set: what GCC 14 rejects by default, made fatal on older GCC.
STRICT=(-Wall -Werror=return-type -Werror=implicit-function-declaration
        -Werror=implicit-int -Werror=int-conversion
        -Werror=incompatible-pointer-types)
for f in -Werror=return-mismatch -Werror=declaration-missing-parameter-type; do
    if echo 'int x;' | "$CC" "$f" -Werror -x c -c -o /dev/null - >/dev/null 2>&1; then
        STRICT+=("$f")
    fi
done

CC="$CC" PREFIX="$PREFIX" WORK="$WORK" STRICT="${STRICT[*]}" \
python3 - "${DOCS[@]}" <<'PYEOF'
import glob
import os
import re
import shlex
import subprocess
import sys

cc = os.environ["CC"]
prefix = os.environ["PREFIX"]
work = os.environ["WORK"]
strict = os.environ["STRICT"].split()
extra = shlex.split(os.environ.get("EXTRA_CFLAGS", ""))
inc, lib = os.path.join(prefix, "dpi", "include"), os.path.join(prefix, "dpi", "lib")
LIBS = ["-lmmt_core", "-ldl", "-lpcap"]
# Arguments a documented command may carry; anything else is refused.
# -W is limited to warning switches that cannot disarm the strict set:
# -Wno-*, -w and the -Wl,/-Wp,/-Wa, passthroughs are refused (and the strict
# set is appended after the documented arguments, so it wins regardless).
ALLOWED = re.compile(r"^(-[IL].*|-l[A-Za-z0-9_]+|-o|-g\d?|-O[0-3sg]?|-W(?!no-)[a-z][a-z0-9-]*(=[A-Za-z0-9_-]+)?|"
                     r"-D[A-Za-z_][A-Za-z0-9_=]*|-std=[a-z0-9+]+|-pthread)$")


def default_cmd(src, out, link):
    if not link:
        return [cc, *strict, *extra, "-c", "-o", out + ".o", src, "-I", inc]
    return [cc, *strict, *extra, "-o", out, src, "-I", inc, "-L", lib, *LIBS]


def listings(doc):
    """(line, code, command-or-None) for every ```c fence of doc."""
    lines = open(doc, encoding="utf-8").read().split("\n")
    found, i = [], 0
    while i < len(lines):
        # A C fence spelled any other way (```C, ```cpp, ```c title=…) would
        # silently leave the gate: refuse it instead.
        if (re.match(r"^\s*```\s*(?:c|C|cpp|c\+\+|h)(?:[\s{]|$)", lines[i])
                and not re.match(r"^\s*```\s*c\s*$", lines[i])):
            print(f"✗ {doc}:{i + 1}: C fence {lines[i].strip()!r} — tag C listings "
                  "exactly ```c so this gate compiles them", file=sys.stderr)
            sys.exit(2)
        if not re.match(r"^\s*```\s*c\s*$", lines[i]):
            i += 1
            continue
        start, j = i + 1, i + 1
        while j < len(lines) and not re.match(r"^\s*```", lines[j]):
            j += 1
        code = "\n".join(lines[start:j]) + "\n"
        cmd, k, in_sh = None, j + 1, False
        while k < len(lines) and cmd is None:
            if re.match(r"^\s*```\s*c\s*$", lines[k]):
                break
            if re.match(r"^\s*```\s*(sh|bash|shell)\s*$", lines[k]):
                in_sh = True
            elif re.match(r"^\s*```", lines[k]):
                in_sh = False
            elif in_sh and re.match(r"^\s*\$?\s*gcc\s", lines[k]):
                cmd = re.sub(r"^\s*\$?\s*", "", lines[k])
            k += 1
        found.append((start + 1, code, cmd))
        i = j + 1
    return found


def documented_cmd(cmd, where):
    """The documented gcc command as an argv, or (None, reason)."""
    argv = shlex.split(cmd.replace("/opt/mmt", prefix))
    srcs = [a for a in argv[1:] if a.endswith(".c")]
    if len(srcs) != 1:
        return None, f"expected one .c source in {cmd!r}"
    # Walk the arguments: a separate -o/-I/-L consumes exactly the next one,
    # which must not look like an option, so a value can never smuggle a
    # third token (`-I -I -w`) past the allowlist.
    bad, has_out, i = [], False, 1
    while i < len(argv):
        a = argv[i]
        if a in ("-o", "-I", "-L"):
            if i + 1 >= len(argv) or argv[i + 1].startswith("-"):
                bad.append(a)
                i += 1
                continue
            has_out = has_out or a == "-o"
            i += 2
            continue
        if a not in srcs and not ALLOWED.match(a):
            bad.append(a)
        i += 1
    if bad:
        return None, f"argument(s) not accepted from a documented command: {bad}"
    if not has_out:
        return None, f"no -o in {cmd!r}"
    return [cc, *argv[1:], *strict, *extra], srcs[0]


def run(argv, cwd, label):
    p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
    if p.returncode == 0:
        print(f"  ✓ {label}")
        return 0
    print(f"  ✗ {label}")
    for line in (p.stdout + p.stderr).strip().splitlines()[:20]:
        print(f"      {line}")
    return 1


fails, total = 0, 0
for doc in sys.argv[1:]:
    found = listings(doc)
    if not found:
        print(f"✗ {doc}: no ```c listing found", file=sys.stderr)
        sys.exit(2)
    print(f"-- {doc}: {len(found)} listing(s)")
    for n, (line, code, cmd) in enumerate(found, 1):
        d = os.path.join(work, "doc", f"{os.path.basename(doc)}-{n}")
        os.makedirs(d)
        link = re.search(r"\bmain\s*\(", code) is not None
        label = f"{doc}:{line}"
        if cmd and link:
            argv, src = documented_cmd(cmd, label)
            if argv is None:
                print(f"  ✗ {label}: {src}")
                fails += 1
                total += 1
                continue
            label += f" ({os.path.basename(src)}, documented command)"
        else:
            src, argv = "listing.c", default_cmd("listing.c", "listing", link)
            label += " (default command)" if link else " (fragment, -c)"
        with open(os.path.join(d, os.path.basename(src)), "w", encoding="utf-8") as f:
            f.write(code)
        total += 1
        fails += run(argv, d, label)

examples = sorted(glob.glob(os.path.join("src", "examples", "*.c")))
if not examples:
    print("✗ no src/examples/*.c found", file=sys.stderr)
    sys.exit(2)
print(f"-- src/examples: {len(examples)} program(s)")
os.makedirs(os.path.join(work, "examples"))
for ex in examples:
    out = os.path.join(work, "examples", os.path.basename(ex)[:-2])
    total += 1
    fails += run(default_cmd(os.path.abspath(ex), out, True), work, ex)

print()
print(f"compiler: {cc}; strict flags: {' '.join(strict)}"
      + (f"; EXTRA_CFLAGS: {' '.join(extra)}" if extra else ""))
if fails:
    print(f"✗ {fails} of {total} listing(s)/example(s) do not compile")
    sys.exit(1)
print(f"✓ all {total} listings and examples compile against {prefix}")
PYEOF

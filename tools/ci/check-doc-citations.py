#!/usr/bin/env python3
"""check-doc-citations.py — every `path:line` citation in docs/*.md still
lands on the code it names (issue #582, F-DOCS-009).

Unguarded citations rotted (most of the unanchored ones pointed at the wrong
line or a removed file) while the anchored ones of docs/AGENT_ENVIRONMENT.md
stayed correct, so this generalises that guard to every page.

A citation is a path — one with a directory part, or a file name with an
extension — followed by `:N`, `:N-M` or a comma-separated list of them
(`rules/common.mk:38-43`, `sdk/Makefile:88`, `mmt_core.h:1134,989,707`);
a version such as `ubuntu:24.04` is not one. Inside a fenced code block only
a path with a directory part counts (a comment such as
`// see src/mmt_core/public_include/mmt_core.h:779`), so a bare `file.c:42:`
of compiler output shown there is not read as a citation. Each range is checked
on its own:

  - the path is a file of the repository, named from the repository root
    (a bare basename or the generated `sdk/include/` copy is not) — or, for
    a citation that is the text of a github.com `blob/<ref>/<path>#L` link,
    the basename of the link's <path>, which is then the file checked;
  - the range lies inside the file;
  - the range is registered in the registry (tools/ci/doc-citations.txt)
    for that page, with a needle the range's first line must hold and,
    optionally, one its last line must hold — moving code means updating
    the line numbers in the page and the registry; removing or changing the
    code a citation is for fails until the citation is re-verified;
  - every registered row is still cited by its page (no stale rows).

Registry records (tab-separated; `#` starts a comment line):

  cite <page> <path:range> <head-needle> [<tail-needle>]
      one checked range; needles are fixed substrings, `-` = no tail needle
  delegate <page> <script>
      the page's citations are anchored by <script> instead (it must exist
      and name the page); this checker still requires each to resolve and
      to lie inside its file
  exempt <page> <reason>
      the page is an append-only record whose entries describe the tree on
      their date, so its citations are not re-anchored; the page must say
      "append-only" in its first 15 lines

Every docs/*.md page is checked; a page without citations needs no record.

Usage: python3 tools/ci/check-doc-citations.py [--root DIR] [--registry FILE]

Exit codes: 0 = every citation resolves and is anchored, 1 = a citation or
registry row failed, 2 = helper broken (unreadable registry, malformed row).
"""

import argparse
import glob
import os
import re
import sys

CITE = re.compile(
    r"(?<![A-Za-z0-9_./~$-])"
    r"((?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+"
    r"|[A-Za-z0-9_-][A-Za-z0-9_.-]*\.[A-Za-z][A-Za-z0-9]*)"
    r":(\d+(?:-\d+)?(?:,\s*\d+(?:-\d+)?)*)"
    r"(?![A-Za-z0-9_/-]|\.\d)")
FENCE = re.compile(r"^\s*(```|~~~)")
# A citation shown as link text names the file by its basename and links the
# repository path: [`proto_tcp.c:1217`](https://github.com/o/r/blob/main/src/…/proto_tcp.c#L1217)
LINKED = re.compile(r"`?\]\(https://github\.com/[^/]+/[^/]+/blob/[^/]+/([^)#\s]+)#L")


def parse_args():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))
    ap.add_argument("--registry", default="tools/ci/doc-citations.txt")
    return ap.parse_args()


def broken(msg):
    print(f"✗ {msg}", file=sys.stderr)
    sys.exit(2)


def load_registry(path):
    cites, delegates, exempts = {}, {}, {}
    try:
        lines = open(path, encoding="utf-8").read().split("\n")
    except OSError as exc:
        broken(f"cannot read registry {path}: {exc}")
    for n, raw in enumerate(lines, 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        f = raw.split("\t")
        kind = f[0]
        where = f"{path}:{n}"
        if kind == "cite" and len(f) in (4, 5):
            page, cite, head = f[1], f[2], f[3]
            tail = f[4] if len(f) == 5 else "-"
            m = re.fullmatch(r"(.+):(\d+)(?:-(\d+))?", cite)
            if not m or not head:
                broken(f"{where}: malformed cite row {raw!r}")
            key = (page, cite)
            if key in cites:
                broken(f"{where}: duplicate row for {page} {cite}")
            cites[key] = (head, tail, where)
        elif kind == "delegate" and len(f) == 3:
            delegates[f[1]] = f[2]
        elif kind == "exempt" and len(f) == 3:
            exempts[f[1]] = f[2]
        else:
            broken(f"{where}: malformed row {raw!r} (see the header of "
                   "tools/ci/check-doc-citations.py)")
    return cites, delegates, exempts


def citations(page):
    """(line number, path, 'a-b' or 'a') for every range the page cites."""
    out = []
    fenced = False
    for n, line in enumerate(open(page, encoding="utf-8").read().split("\n"), 1):
        if FENCE.match(line):
            fenced = not fenced
            continue
        for m in CITE.finditer(line):
            path = m.group(1)
            if fenced and "/" not in path:
                continue
            link = LINKED.match(line, m.end())
            if link and os.path.basename(link.group(1)) == os.path.basename(path):
                path = link.group(1)
            for rng in re.split(r",\s*", m.group(2)):
                out.append((n, path, rng))
    return out


def main():
    args = parse_args()
    os.chdir(args.root)
    cites, delegates, exempts = load_registry(args.registry)
    errors = 0
    checked = anchored = 0
    seen = set()
    cache = {}

    def fail(msg):
        nonlocal errors
        errors += 1
        print(f"  ✗ {msg}")

    def file_lines(path):
        if path not in cache:
            cache[path] = open(path, encoding="utf-8",
                               errors="replace").read().split("\n")
            if cache[path] and cache[path][-1] == "":
                cache[path].pop()
        return cache[path]

    pages = sorted(glob.glob("docs/*.md"))
    for page in list(exempts) + list(delegates):
        if page not in pages:
            fail(f"{args.registry}: {page} is listed but is not a docs/*.md page")
    for page, reason in exempts.items():
        if page in pages:
            head = "\n".join(open(page, encoding="utf-8").read().split("\n")[:15])
            if "append-only" not in head.lower():
                fail(f"{page}: exempt as '{reason}' but its first 15 lines do "
                     "not declare it append-only")
    for page, script in delegates.items():
        if not os.path.isfile(script):
            fail(f"{page}: delegated to {script}, which does not exist")
        elif page not in open(script, encoding="utf-8").read() and \
                os.path.basename(page) not in open(script, encoding="utf-8").read():
            fail(f"{page}: delegated to {script}, which does not name it")

    for page in pages:
        if page in exempts:
            continue
        for n, path, rng in citations(page):
            where = f"{page}:{n} `{path}:{rng}`"
            checked += 1
            if path.startswith("sdk/include/"):
                fail(f"{where}: sdk/include/ is the generated copy — cite "
                     f"src/mmt_core/public_include/{path[len('sdk/include/'):]}")
                continue
            if not os.path.isfile(path):
                fail(f"{where}: no such file from the repository root "
                     "(cite the full repository path)")
                continue
            a, _, b = rng.partition("-")
            a, b = int(a), int(b or a)
            lines = file_lines(path)
            if not (1 <= a <= b <= len(lines)):
                fail(f"{where}: range outside the file ({len(lines)} lines)")
                continue
            if page in delegates:
                continue
            key = (page, f"{path}:{rng}")
            seen.add(key)
            row = cites.get(key)
            if row is None:
                fail(f"{where}: not registered in {args.registry} — verify "
                     "the line and add a cite row with its needle")
                continue
            head, tail, _ = row
            if head not in lines[a - 1]:
                fail(f"{where}: line {a} no longer holds {head!r}: "
                     f"{lines[a - 1].strip()!r}")
                continue
            if tail != "-" and tail not in lines[b - 1]:
                fail(f"{where}: line {b} no longer holds {tail!r}: "
                     f"{lines[b - 1].strip()!r}")
                continue
            anchored += 1
    for key, (_, _, where) in sorted(cites.items(), key=lambda kv: kv[1][2]):
        if key not in seen and key[0] not in exempts:
            fail(f"{where}: {key[0]} no longer cites {key[1]} — drop the row")

    if errors:
        print(f"✗ {errors} citation problem(s) in docs/*.md "
              f"({checked} range(s) checked)")
        return 1
    print(f"✓ {checked} cited range(s) in docs/*.md resolve; {anchored} "
          f"anchored by {args.registry}, the rest by their page's own guard")
    return 0


if __name__ == "__main__":
    sys.exit(main())

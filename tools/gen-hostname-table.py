#!/usr/bin/env python3
"""gen-hostname-table.py -- generate the hostname-suffix C table (issue #566).

data/hostnames.txt is the source of the SNI / HTTP Host suffix -> protocol map
that get_proto_id_by_hostname() builds its trie from; this script turns it into
src/mmt_tcpip/lib/mmt_tcpip_classif_doted_host_names.inc, the initializer
mmt_tcpip_classif_utils.c includes. The .inc is committed (the build needs no
Python) and must equal this script's output: --check is the drift gate the
core_engine suite runs.

The data file is validated before anything is written:
  - exactly one "# version: YYYY-MM-DD" header line, a real date, before the
    first entry;
  - every entry is "<suffix> <PROTO_ID>": the suffix lowercase printable ASCII
    starting with '.', without whitespace, '"' or '\\'; the id a PROTO_* name
    #defined with a non-zero value in mmt_tcpip_protocols.h;
  - no suffix listed twice (the trie keeps one protocol per suffix).
The entry lengths are computed, so a hand-typed length can no longer drift
from its string. Entries are emitted in file order.

Usage:
  python3 tools/gen-hostname-table.py            # rewrite the .inc
  python3 tools/gen-hostname-table.py --check    # exit 1 when the .inc is stale
  options: --data FILE, --header FILE, --output FILE (defaults: the repository's)

Exit: 0 = written / current, 1 = invalid data or stale .inc, 2 = usage or I/O.
"""

import argparse
import datetime
import difflib
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DATA = os.path.join(ROOT, "data", "hostnames.txt")
HEADER = os.path.join(ROOT, "src", "mmt_tcpip", "include", "mmt_tcpip_protocols.h")
OUTPUT = os.path.join(ROOT, "src", "mmt_tcpip", "lib",
                      "mmt_tcpip_classif_doted_host_names.inc")

VERSION_RE = re.compile(r"^#\s*version:\s*(\S+)\s*$")
SUFFIX_RE = re.compile(r'^\.[\x21-\x7e]+$')
PROTO_RE = re.compile(r"^PROTO_[A-Z0-9_]+$")
DEFINE_RE = re.compile(r"^\s*#\s*define\s+(PROTO_[A-Z0-9_]+)\s+(\d+)\b")


class DataError(Exception):
    pass


def defined_protocols(header):
    ids = {}
    with open(header, encoding="utf-8") as f:
        for line in f:
            m = DEFINE_RE.match(line)
            if m:
                ids[m.group(1)] = int(m.group(2))
    return ids


def parse(data, ids):
    """Return (version, [(suffix, proto)]) or raise DataError naming every fault."""
    errors, entries, seen = [], [], {}
    version = None
    name = os.path.relpath(data, ROOT) if data.startswith(ROOT + os.sep) else data
    with open(data, encoding="utf-8") as f:
        lines = f.read().splitlines()
    for no, raw in enumerate(lines, 1):
        line = raw.strip()
        where = "%s:%d" % (name, no)
        if not line:
            continue
        if line.startswith("#"):
            m = VERSION_RE.match(line)
            if m:
                if version is not None:
                    errors.append("%s: second version line" % where)
                elif entries:
                    errors.append("%s: the version line must precede the entries" % where)
                try:
                    # strptime, not fromisoformat: Python >= 3.11 also takes
                    # the basic (20261031) and week (2026-W44-6) forms
                    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", m.group(1)):
                        raise ValueError(m.group(1))
                    datetime.datetime.strptime(m.group(1), "%Y-%m-%d")
                except ValueError:
                    errors.append("%s: version %r is not a YYYY-MM-DD date" % (where, m.group(1)))
                version = m.group(1)
            continue
        fields = line.split()
        if len(fields) != 2:
            errors.append('%s: expected "<suffix> <PROTO_ID>", got %r' % (where, line))
            continue
        suffix, proto = fields
        if not SUFFIX_RE.match(suffix) or '"' in suffix or "\\" in suffix:
            errors.append("%s: suffix %r must start with '.' and hold printable ASCII "
                          "without '\"' or '\\'" % (where, suffix))
        elif suffix != suffix.lower():
            errors.append("%s: suffix %r must be lowercase (lookups fold case)" % (where, suffix))
        if not PROTO_RE.match(proto) or ids.get(proto, 0) == 0:
            errors.append("%s: %r is not a PROTO_* id defined (non-zero) in %s"
                          % (where, proto, os.path.basename(HEADER)))
        if suffix in seen:
            errors.append("%s: suffix %r already listed at line %d" % (where, suffix, seen[suffix]))
        else:
            seen[suffix] = no
        entries.append((suffix, proto))
    if version is None:
        errors.append("%s: no '# version: YYYY-MM-DD' header line" % name)
    if not entries:
        errors.append("%s: no entries" % name)
    if errors:
        raise DataError("\n".join(errors))
    return version, entries


def render(version, entries):
    out = [
        "/* GENERATED FILE -- do not edit by hand (issue #566).",
        " * Source: data/hostnames.txt, version %s; regenerate with" % version,
        " *   python3 tools/gen-hostname-table.py",
        " * The hostname-suffix table of get_proto_id_by_hostname(), included by",
        " * mmt_tcpip_classif_utils.c. %d entries. */" % len(entries),
        "static const protocol_match doted_host_names[] = {",
    ]
    out += ['    {"%s", %s,%d},' % (s, p, len(s)) for s, p in entries]
    out += ["    { NULL, 0, 0}", "};", ""]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--check", action="store_true",
                    help="compare with the committed .inc instead of writing it")
    ap.add_argument("--data", default=DATA)
    ap.add_argument("--header", default=HEADER)
    ap.add_argument("--output", default=OUTPUT)
    args = ap.parse_args()

    try:
        ids = defined_protocols(args.header)
        version, entries = parse(args.data, ids)
    except DataError as e:
        print(str(e), file=sys.stderr)
        print("✗ %s is invalid -- nothing written" % args.data, file=sys.stderr)
        return 1
    except OSError as e:
        print("✗ %s" % e, file=sys.stderr)
        return 2
    text = render(version, entries)

    if args.check:
        try:
            with open(args.output, encoding="utf-8") as f:
                current = f.read()
        except OSError as e:
            print("✗ %s" % e, file=sys.stderr)
            return 2
        if current != text:
            diff = difflib.unified_diff(current.splitlines(), text.splitlines(),
                                        args.output, "generated", lineterm="")
            sys.stderr.write("\n".join(list(diff)[:40]) + "\n")
            print("✗ %s is stale -- regenerate it: python3 tools/gen-hostname-table.py"
                  % args.output, file=sys.stderr)
            return 1
        print("✓ hostname table current: %d entries, version %s" % (len(entries), version))
        return 0

    tmp = args.output + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, args.output)
    except OSError as e:
        print("✗ %s" % e, file=sys.stderr)
        return 2
    print("wrote %s: %d entries, version %s" % (args.output, len(entries), version))
    return 0


if __name__ == "__main__":
    sys.exit(main())

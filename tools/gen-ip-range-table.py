#!/usr/bin/env python3
"""gen-ip-range-table.py -- generate the IPv4 prefix -> protocol C table (issue #557).

data/ip_ranges.txt is the source of the compiled-in IPv4 attribution ranges
that _find_proto_id_by_address() looks up; this script turns it into
src/mmt_tcpip/lib/mmt_tcpip_classif_proto_ip_address.inc, the initializer
mmt_tcpip_classif_utils.c includes. The .inc is committed (the build needs no
Python) and must equal this script's output: --check is the drift gate the
core_engine suite runs.

The prefixes are flattened into one sorted array of disjoint intervals that
covers the whole IPv4 space: each interval starts at `start`, runs to the next
interval's start, and carries the protocol and the length of the longest
listed prefix containing it (0 / 0 for space no prefix covers). A lookup is
one binary search; the prefix length is kept because the caller compares the
source and destination matches by it (src wins a tie).

The data file is validated before anything is written:
  - exactly one "# version: YYYY-MM-DD" header line, a real date, before the
    first entry;
  - every entry is "<network>/<prefix> <PROTO_ID>": a dotted-quad network with
    its host bits zero, a prefix of 1..32, a PROTO_* name #defined with a
    non-zero value below 65536 in mmt_tcpip_protocols.h;
  - no network/prefix listed twice (one protocol per prefix).

--prefix-table FILE also writes the prefixes, in file order, as the
proto_based_ip_t initializer the table was before issue #557: the
core_engine suite's differential test (tests/core_engine/test_ip_range_lpm.c)
rebuilds the former per-prefix AVL forest from it and checks that the
interval lookup returns the same protocol for every listed prefix.

Usage:
  python3 tools/gen-ip-range-table.py            # rewrite the .inc
  python3 tools/gen-ip-range-table.py --check    # exit 1 when the .inc is stale
  options: --data FILE, --header FILE, --output FILE (defaults: the repository's),
           --prefix-table FILE

Exit: 0 = written / current, 1 = invalid data or stale .inc, 2 = usage or I/O.
"""

import argparse
import datetime
import difflib
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DATA = os.path.join(ROOT, "data", "ip_ranges.txt")
HEADER = os.path.join(ROOT, "src", "mmt_tcpip", "include", "mmt_tcpip_protocols.h")
OUTPUT = os.path.join(ROOT, "src", "mmt_tcpip", "lib",
                      "mmt_tcpip_classif_proto_ip_address.inc")

VERSION_RE = re.compile(r"^#\s*version:\s*(\S+)\s*$")
CIDR_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$")
PROTO_RE = re.compile(r"^PROTO_[A-Z0-9_]+$")
DEFINE_RE = re.compile(r"^\s*#\s*define\s+(PROTO_[A-Z0-9_]+)\s+(\d+)\b")
NONE = (0, "PROTO_UNKNOWN")  # (prefix length, protocol) of space no prefix covers


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


def dotted(addr):
    return "%d.%d.%d.%d" % (addr >> 24, (addr >> 16) & 255, (addr >> 8) & 255, addr & 255)


def parse(data, ids):
    """Return (version, [(network, prefix, proto)]) or raise DataError naming every fault."""
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
                    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", m.group(1)):
                        raise ValueError(m.group(1))
                    datetime.datetime.strptime(m.group(1), "%Y-%m-%d")
                except ValueError:
                    errors.append("%s: version %r is not a YYYY-MM-DD date" % (where, m.group(1)))
                version = m.group(1)
            continue
        fields = line.split()
        if len(fields) != 2:
            errors.append('%s: expected "<network>/<prefix> <PROTO_ID>", got %r' % (where, line))
            continue
        cidr, proto = fields
        m = CIDR_RE.match(cidr)
        octets = [int(g) for g in m.groups()[:4]] if m else []
        if not m or any(o > 255 for o in octets):
            errors.append("%s: %r is not a dotted-quad <network>/<prefix>" % (where, cidr))
            continue
        prefix = int(m.group(5))
        if not 1 <= prefix <= 32:
            errors.append("%s: prefix /%d of %r is outside 1..32" % (where, prefix, cidr))
            continue
        network = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        if network & ~mask & 0xFFFFFFFF:
            errors.append("%s: %r has host bits set (network %s/%d)"
                          % (where, cidr, dotted(network & mask), prefix))
            continue
        if not PROTO_RE.match(proto) or not 0 < ids.get(proto, 0) < 65536:
            errors.append("%s: %r is not a PROTO_* id defined (non-zero, below 65536) in %s"
                          % (where, proto, os.path.basename(HEADER)))
        key = (network, prefix)
        if key in seen:
            errors.append("%s: %s/%d already listed at line %d" % (where, dotted(network), prefix, seen[key]))
        else:
            seen[key] = no
        entries.append((network, prefix, proto))
    if version is None:
        errors.append("%s: no '# version: YYYY-MM-DD' header line" % name)
    if not entries:
        errors.append("%s: no entries" % name)
    if errors:
        raise DataError("\n".join(errors))
    return version, entries


def flatten(entries):
    """Disjoint [(start, prefix, proto, source)] covering 0 .. 2^32-1, sorted.

    CIDR prefixes are laminar (two are nested or disjoint), so one sweep over
    them in (network, prefix) order with a stack of the enclosing prefixes
    yields every change of the longest-prefix match. Adjacent intervals with
    the same (prefix, proto) are merged: a lookup only reads those two."""
    out = []  # [start, (prefix, proto), source]

    def put(start, value, source):
        if out and out[-1][0] == start:  # the previous interval is empty
            out.pop()
        if out and out[-1][1] == value:
            return
        out.append((start, value, source))

    stack = []  # (last address, (prefix, proto), source) of enclosing prefixes
    put(0, NONE, None)
    for network, prefix, proto in sorted(entries, key=lambda e: (e[0], e[1])):
        while stack and stack[-1][0] < network:
            last = stack.pop()[0]
            if stack:
                put(last + 1, stack[-1][1], stack[-1][2])
            else:
                put(last + 1, NONE, None)
        last = network + (1 << (32 - prefix)) - 1
        source = "%s/%d" % (dotted(network), prefix)
        stack.append((last, (prefix, proto), source))
        put(network, (prefix, proto), source)
    while stack:
        last = stack.pop()[0]
        if last == 0xFFFFFFFF:
            continue
        if stack:
            put(last + 1, stack[-1][1], stack[-1][2])
        else:
            put(last + 1, NONE, None)
    return [(start, value[0], value[1], source) for start, value, source in out]


def render(version, entries, intervals):
    out = [
        "/* GENERATED FILE -- do not edit by hand (issue #557).",
        " * Source: data/ip_ranges.txt, version %s; regenerate with" % version,
        " *   python3 tools/gen-ip-range-table.py",
        " * The compiled-in IPv4 attribution table of _find_proto_id_by_address(),",
        " * included by mmt_tcpip_classif_utils.c: %d prefixes flattened into %d"
        % (len(entries), len(intervals)),
        " * disjoint intervals, sorted by start address. An interval runs from its",
        " * start to the next one's; it carries the protocol and the prefix length",
        " * of the longest listed prefix containing it (0 = no prefix). The first",
        " * interval starts at 0.0.0.0, so every address falls in exactly one. */",
        "#define IP_RANGE_INTERVAL_COUNT %d" % len(intervals),
        "static const ip_range_interval_t ip_range_intervals[IP_RANGE_INTERVAL_COUNT] = {",
    ]
    for start, prefix, proto, source in intervals:
        row = "    {0x%08xu, %s, %d}," % (start, proto, prefix)
        out.append(row + (" /* %s */" % source if source else ""))
    out += ["};", ""]
    return "\n".join(out)


def render_prefixes(version, entries):
    out = [
        "/* GENERATED by tools/gen-ip-range-table.py --prefix-table from",
        " * data/ip_ranges.txt, version %s: the %d prefixes in file order, as the" % (version, len(entries)),
        " * proto_based_ip_t table mmt_tcpip_classif_utils.c held before issue #557. */",
        "static const proto_based_ip_t ip_range_prefixes[] = {",
    ]
    for network, prefix, proto in entries:
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        out.append("    {%d, 0x%08xu, 0x%08xu, %s}," % (prefix, mask, network, proto))
    out += ["    {0, 0, 0, 0}", "};", ""]
    return "\n".join(out)


def write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--check", action="store_true",
                    help="compare with the committed .inc instead of writing it")
    ap.add_argument("--data", default=DATA)
    ap.add_argument("--header", default=HEADER)
    ap.add_argument("--output", default=OUTPUT)
    ap.add_argument("--prefix-table", metavar="FILE",
                    help="also write the prefixes as a proto_based_ip_t initializer")
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
    intervals = flatten(entries)
    text = render(version, entries, intervals)

    try:
        if args.prefix_table:
            write(args.prefix_table, render_prefixes(version, entries))
        if args.check:
            with open(args.output, encoding="utf-8") as f:
                current = f.read()
            if current != text:
                diff = difflib.unified_diff(current.splitlines(), text.splitlines(),
                                            args.output, "generated", lineterm="")
                sys.stderr.write("\n".join(list(diff)[:40]) + "\n")
                print("✗ %s is stale -- regenerate it: python3 tools/gen-ip-range-table.py"
                      % args.output, file=sys.stderr)
                return 1
            print("✓ IP-range table current: %d prefixes, %d intervals, version %s"
                  % (len(entries), len(intervals), version))
            return 0
        write(args.output, text)
    except OSError as e:
        print("✗ %s" % e, file=sys.stderr)
        return 2
    print("wrote %s: %d prefixes, %d intervals, version %s"
          % (args.output, len(entries), len(intervals), version))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""check_inter_proto_excluded.py — the excluded_proto column of
src/mmt_tcpip/lib/inter_proto_classif_list.def against the checkers' sources
(issue #560).

Each MMT_INTER_PROTO / MMT_INTER_PROTO_LEGACY row's fourth column must be the
protocol id the checker's translation unit passes as the last argument of its
mmt_init_classify_bitmasks*() call — the id its excluded bitmask holds — or
PROTO_UNKNOWN when that unit makes no such call. The run-time check of
init_tcpip_plugin() only refuses an id no unit recorded; this one also catches
a row naming another unit's id. A unit that adds a further id to its static
excluded bitmask after the call (MMT_ADD_PROTOCOL_TO_BITMASK on
excluded_protocol_bitmask) must be listed in EXTRA_EXCLUSIONS: its frozen
entry carries only the first id, which a central guard (#561) has to know.

Usage: check_inter_proto_excluded.py [REPO_ROOT]   exit 0 pass, 1 fail
"""
import glob
import os
import re
import sys

# Units whose static excluded bitmask holds more than the helper's id.
EXTRA_EXCLUSIONS = {
    "proto_jabber.c": ["PROTO_TRUPHONE"],
}

HELPER = re.compile(r"mmt_init_classify_bitmasks(?:_multi)?\s*\(([^;]*)\);", re.S)
EXTRA = re.compile(r"MMT_ADD_PROTOCOL_TO_BITMASK\s*\(\s*excluded_protocol_bitmask\s*,\s*(\w+)\s*\)")
ROW = re.compile(r"\bMMT_INTER_PROTO(?:_LEGACY)?\s*\(\s*(PROTO_\w+)\s*,\s*(\w+)\s*,"
                 r"\s*\d+\s*,\s*(\w+)\s*\)")


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "..")
    lib = os.path.join(root, "src", "mmt_tcpip", "lib")
    sources = {}
    for path in glob.glob(os.path.join(lib, "**", "*.c"), recursive=True):
        with open(path, errors="replace") as f:
            sources[path] = f.read()
    with open(os.path.join(lib, "inter_proto_classif_list.def")) as f:
        rows = ROW.findall(f.read())
    failures = 0
    if len(rows) < 150:
        print("✗ only %d rows with an excluded_proto column" % len(rows))
        failures += 1
    for parent, fn, excluded in rows:
        defining = [p for p, s in sources.items()
                    if re.search(r"^\s*(?:static\s+)?(?:inline\s+)?(?:int|mmt_classify_verdict_t)\s+"
                                 + fn + r"\s*\(\s*ipacket_t", s, re.M)]
        if len(defining) != 1:
            print("✗ %s: defined in %d sources" % (fn, len(defining)))
            failures += 1
            continue
        text = sources[defining[0]]
        calls = HELPER.findall(text)
        if len(calls) > 1:
            print("✗ %s: %d mmt_init_classify_bitmasks*() calls in %s"
                  % (fn, len(calls), os.path.basename(defining[0])))
            failures += 1
            continue
        want = calls[0].split(",")[-1].strip() if calls else "PROTO_UNKNOWN"
        if excluded != want:
            print("✗ %s (%s): column %s, its source excludes %s"
                  % (fn, parent, excluded, want))
            failures += 1
        extra = EXTRA.findall(text)
        listed = EXTRA_EXCLUSIONS.get(os.path.basename(defining[0]), [])
        if sorted(set(extra)) != sorted(listed):
            print("✗ %s: further static exclusions %s, EXTRA_EXCLUSIONS lists %s"
                  % (os.path.basename(defining[0]), sorted(set(extra)), listed))
            failures += 1
    if failures:
        print("✗ inter_proto_classif_list.def excluded_proto column: %d failure(s)" % failures)
        return 1
    print("✓ excluded_proto column matches the checkers' sources (%d rows)" % len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())

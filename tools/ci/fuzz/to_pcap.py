#!/usr/bin/env python3
"""Wrap a libFuzzer input into a well-formed classic pcap (issue #530).

tools/ci/fuzz/packet_fuzzer.c reads its input leniently: a pcap whose last
record is cut short is clamped, and input with no pcap magic is one Ethernet
frame. A finding can therefore be a file that libpcap — and with it the
phase0_classify replay of tools/ci/run-fuzz.sh — rejects as malformed. This
script applies the target's own parse rules and writes the frames the
target processed as a little-endian microsecond pcap with the same link
type, so the reproducer replays through both drivers and can be committed to
tools/ci/fuzz/regressions (with its sha256 in manifest.txt).

Usage: tools/ci/fuzz/to_pcap.py <libfuzzer-input> <out.pcap>
"""
import struct
import sys

MAX_FRAME = 65535
MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<", b"\x4d\x3c\xb2\xa1": "<",   # little-endian us / ns
    b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">",   # big-endian us / ns
}


def frames(data):
    """Return (linktype, [(sec, usec, frame, wire_len)]) as the target sees it."""
    order = MAGICS.get(data[:4]) if len(data) >= 24 else None
    if order is None:
        return 1, [(0, 0, data[:MAX_FRAME], len(data))] if data else []
    linktype = struct.unpack(order + "I", data[20:24])[0] & 0x0FFFFFFF
    nanos = data[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    out, off = [], 24
    while len(data) - off >= 16:
        sec, usec, incl, wire = struct.unpack(order + "IIII", data[off:off + 16])
        off += 16
        incl = min(incl, len(data) - off)
        if incl > MAX_FRAME:
            break
        frame = data[off:off + incl]
        off += incl
        if incl:
            out.append((sec, usec // 1000 if nanos else usec, frame, max(wire, incl)))
    return linktype, out


def main():
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    with open(sys.argv[1], "rb") as f:
        linktype, records = frames(f.read())
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, MAX_FRAME, linktype)]
    for sec, usec, frame, wire in records:
        out.append(struct.pack("<IIII", sec, usec % 1_000_000, len(frame), wire))
        out.append(frame)
    with open(sys.argv[2], "wb") as f:
        f.write(b"".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())

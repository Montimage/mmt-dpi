#!/usr/bin/env python3
"""Generate a synthetic multi-flow RADIUS pcap to exercise per-session state.

Part of issue #65 (multi-threaded TSan harness). MMT-DPI classifies RADIUS by
*content*, not by port: mmt_check_radius() matches a UDP-with-payload packet
whose RADIUS code field is a defined packet code (1-5, 11-13, 40-45) and whose
RADIUS length field equals the actual UDP payload length, at least 20 bytes
(see src/mmt_tcpip/lib/protocols/proto_radius.c). The parser state for RADIUS
is kept PER SESSION (issue #23), so to exercise that state under
ThreadSanitizer we need many DISTINCT RADIUS flows replayed concurrently.

This tool emits a classic little-endian pcap (DLT_EN10MB) with several distinct
UDP 5-tuples, each carrying a valid RADIUS Access-Request payload (20-byte
header + a couple of attributes), and several packets per flow so that session
*lookups* (not just inserts) happen too.

Pure stdlib (struct only) — no scapy needed, so it is reproducible in CI.

Usage:
    tools/phase0/gen_radius_pcap.py [out.pcap] [--flows N] [--packets-per-flow K]

Default output: /tmp/radius.pcap
"""
import argparse
import struct

ETH_HLEN = 14
IP_HLEN = 20
UDP_HLEN = 8
RADIUS_HLEN = 20  # code(1) + id(1) + length(2) + authenticator(16)

# Access-Request is one of the codes mmt_check_radius accepts.
RADIUS_ACCESS_REQUEST = 1


def eth_header(src_mac, dst_mac):
    return dst_mac + src_mac + struct.pack("!H", 0x0800)


def ip_header(src_ip, dst_ip, payload_len):
    ver_ihl = (4 << 4) | (IP_HLEN // 4)
    total_len = IP_HLEN + UDP_HLEN + payload_len
    # ttl=64, proto=17 (UDP). Checksum left 0 (parsers under test do not verify it).
    return struct.pack("!BBHHHBBH4s4s",
                       ver_ihl, 0, total_len, 0, 0x4000, 64, 17, 0,
                       src_ip, dst_ip)


def udp_header(sport, dport, payload_len):
    length = UDP_HLEN + payload_len
    # Checksum left 0 (legal for IPv4 UDP and not verified by the parsers).
    return struct.pack("!HHHH", sport, dport, length, 0)


def radius_attribute(attr_type, value):
    # type(1) + length(1) + value; length counts the whole TLV.
    return struct.pack("!BB", attr_type, 2 + len(value)) + value


def radius_payload(identifier):
    # A couple of valid attributes: User-Name (1) and NAS-Identifier (32).
    attrs = (radius_attribute(1, b"mmt-user")
             + radius_attribute(32, b"mmt-nas"))
    authenticator = bytes((identifier + i) & 0xFF for i in range(16))
    total_len = RADIUS_HLEN + len(attrs)
    # The length field MUST equal the actual RADIUS (== UDP) payload length and
    # code MUST be one mmt_check_radius() accepts to classify the flow.
    header = struct.pack("!BBH", RADIUS_ACCESS_REQUEST, identifier & 0xFF,
                         total_len) + authenticator
    return header + attrs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out", nargs="?", default="/tmp/radius.pcap",
                    help="output pcap path (default: /tmp/radius.pcap)")
    ap.add_argument("--flows", type=int, default=12,
                    help="number of distinct UDP 5-tuples / RADIUS sessions")
    ap.add_argument("--packets-per-flow", type=int, default=4)
    args = ap.parse_args()

    src_mac = b"\x02\x00\x00\x00\x00\x01"
    dst_mac = b"\x02\x00\x00\x00\x00\x02"

    with open(args.out, "wb") as f:
        # pcap global header: magic, ver 2.4, tz=0, sigfigs=0, snaplen, DLT_EN10MB(1)
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        ts = 0
        for k in range(args.packets_per_flow):
            for i in range(args.flows):
                # Distinct 5-tuple per flow: a unique client IP and source port.
                src_ip = struct.pack("!I", 0x0A000001 + i)  # 10.0.0.x
                dst_ip = struct.pack("!I", 0xC0A80001)       # 192.168.0.1
                sport = 1024 + i
                dport = 1812  # RADIUS auth (cosmetic; classification is content-based)
                payload = radius_payload(identifier=(i * 8 + k))
                pkt = (eth_header(src_mac, dst_mac)
                       + ip_header(src_ip, dst_ip, len(payload))
                       + udp_header(sport, dport, len(payload))
                       + payload)
                ts += 1
                f.write(struct.pack("<IIII", ts // 1000000, ts % 1000000,
                                    len(pkt), len(pkt)))
                f.write(pkt)
    total = args.flows * args.packets_per_flow
    print("wrote %s: %d RADIUS flows x %d pkts = %d packets"
          % (args.out, args.flows, args.packets_per_flow, total))


if __name__ == "__main__":
    main()

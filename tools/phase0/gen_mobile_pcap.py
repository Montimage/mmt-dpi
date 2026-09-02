#!/usr/bin/env python3
"""Generate synthetic mobile/security pcaps for the pcap-driven harness (issue #144).

Covers the mobile/security parsers:
  - RADIUS  (UDP, code<=5, length==payload) via src/mmt_tcpip/lib/protocols/proto_radius.c
  - GTP     (UDP 2152/2123/3386, version 0/1/2, message_len guard) via proto_gtp.c
  - GTPv2   (UDP 2123, version=2) via src/mmt_mobile/proto_gtpv2.c
  - SCTP + DIAMETER (PPID 46, version=1) via proto_diameter.c
  - SCTP + S1AP     (PPID 18) via proto_s1ap.c
  - SCTP + NGAP     (PPID 60) via proto_ngap.c
  - SCTP trunk (SACK, INIT) exercises SCTP sub-protocols

Each pcap is a classic little-endian DLT_EN10MB capture, built with stdlib
``struct`` only so it is reproducible in CI without scapy. Payloads are
minimal but structurally valid so the parser enters its classification path;
a truncated variant is included for the H-guard / bound-check oracle.

Usage:
    tools/phase0/gen_mobile_pcap.py --out-dir /tmp/mobile-pcaps
    tools/phase0/gen_mobile_pcap.py --out-dir /tmp/mobile-pcaps --pcap diameter
"""
import argparse
import os
import struct

ETH_HLEN = 14
IP_HLEN = 20
UDP_HLEN = 8
SCTP_COMMON_HLEN = 12
SCTP_DATA_HLEN = 16

# Hand-crafted, decoder-exact S1AP InitialUEMessage fragment from
# tests/s1ap_ngap_decode/test_s1ap_ngap_decode.c:VECTOR_ATTACH_REQUEST_IMSI.
# Outer decode succeeds for this vector (the handler then returns -1 cleanly
# for the vendored ANY inner decode). Used verbatim for S1AP over SCTP so the
# S1AP bytes are as close to real as possible without invoking the C encoder.
S1AP_VECTOR = bytes([
    0x00, 0x0c, 0x00, 0x14,
    0x00, 0x00, 0x01, 0x00, 0x1a, 0x00,
    0x0d, 0x0c,
    0x07, 0x41, 0x01, 0x08,
    0x09, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0x89
])


def eth_header(src=b"\x02\x00\x00\x00\x00\x01", dst=b"\x02\x00\x00\x00\x00\x02"):
    return dst + src + struct.pack("!H", 0x0800)


def ip_header(src_ip, dst_ip, proto, payload_len, ident=0):
    ver_ihl = (4 << 4) | (IP_HLEN // 4)
    total = IP_HLEN + payload_len
    return struct.pack("!BBHHHBBH4s4s",
                       ver_ihl, 0, total, ident, 0x4000, 64, proto, 0,
                       src_ip, dst_ip)


def udp_header(sport, dport, payload_len):
    length = UDP_HLEN + payload_len
    return struct.pack("!HHHH", sport, dport, length, 0)


def sctp_common_header(src_port, dst_port, vtag=0x12345678):
    # Common header: source(2) + dest(2) + vtag(4) + checksum(4)
    return struct.pack("!HHII", src_port, dst_port, vtag, 0)


def sctp_data_chunk(payload, ppid, stream=1, ssn=1, tsn=1000, flags=0x03):
    # Pad payload to 4-byte boundary with zeros; length field excludes padding
    # so the parser's ntohs(length)-hlen arithmetic still lands on payload.
    # The pcap frame itself carries the full padded bytes (wire = padded).
    pad = (4 - (len(payload) % 4)) % 4
    padded = payload + b"\x00" * pad
    chunk_len = SCTP_DATA_HLEN + len(padded)
    # Note: chunk length in the header is the non-padded length (spec says
    # padding not included in length). Use non-padded length for parser
    # arithmetic, but write padded bytes to the wire so the next chunk
    # (if any) would align. Here we have exactly one chunk per packet, so
    # the distinction is cosmetic.
    hdr_len = SCTP_DATA_HLEN + len(payload)
    hdr = struct.pack("!BBHIHHI",
                      0x00, flags, hdr_len, tsn, stream, ssn, ppid)
    # chunk header with padded length stored? keep parser-friendly hdr_len
    # but wire includes padding bytes after.
    # Rebuild header with correct hdr_len; payload on wire is padded.
    # Some parsers compare hdr.length against caplen — so ensure packet's
    # IP total_len reflects the padded wire length.
    return hdr + padded, hdr_len


def pcap_open(path):
    f = open(path, "wb")
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    return f


def pcap_write(f, pkt, ts_us=0):
    f.write(struct.pack("<IIII", ts_us // 1_000_000, ts_us % 1_000_000,
                        len(pkt), len(pkt)))
    f.write(pkt)


# --- RADIUS -----------------------------------------------------------------

def radius_payload(identifier):
    # type 1 = User-Name, type 32 = NAS-Identifier; code 1 = Access-Request
    def attr(t, v):
        return struct.pack("!BB", t, 2 + len(v)) + v
    attrs = attr(1, b"mmt-user") + attr(32, b"mmt-nas")
    auth = bytes((identifier + i) & 0xFF for i in range(16))
    total = 20 + len(attrs)
    hdr = struct.pack("!BBH", 1, identifier & 0xFF, total) + auth
    return hdr + attrs


def gen_radius_pcap(path):
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0xC0A80001)
    payload = radius_payload(0x42)
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 17, UDP_HLEN + len(payload))
           + udp_header(50000, 1812, len(payload))
           + payload)
    pcap_write(f, pkt, ts_us=0)
    # Truncated: only 4 bytes (H-guard must reject without sanitizer fault)
    trunc = payload[:4]
    pkt2 = (eth_header()
            + ip_header(src_ip, dst_ip, 17, UDP_HLEN + len(trunc))
            + udp_header(50001, 1812, len(trunc))
            + trunc)
    pcap_write(f, pkt2, ts_us=1000)
    f.close()
    print("wrote %s (RADIUS Access-Request + truncated)" % path)


# --- GTP (v1 / v0 over UDP 2152) -------------------------------------------

def gtp_header(version=1, pt=1, msg_type=0xff, length=8, teid=0x01020304):
    # flags: version(3) | PT(1) | reserved(1) | E(1) | S(1) | PN(1)
    flags = (version << 5) | (pt << 4) | 0
    return struct.pack("!BBHI", flags, msg_type, length, teid)


def gen_gtp_pcap(path):
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    # Valid GTPv1 T-PDU (PT=1, version=1, message_type 0xff per proto_gtp.c)
    # Inner payload is 8 bytes of dummy user data
    inner = b"\x45\x00\x00\x08" + b"\x00" * 4
    hdr = gtp_header(version=1, pt=1, msg_type=0xff, length=len(inner), teid=0x01020304)
    payload = hdr + inner
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 17, UDP_HLEN + len(payload))
           + udp_header(40000, 2152, len(payload))
           + payload)
    pcap_write(f, pkt, ts_us=0)
    # Second packet: GTPv0 variant over port 3386 (version=0 path in proto_gtp.c)
    hdr0 = gtp_header(version=0, pt=1, msg_type=0x10, length=len(inner), teid=0x00000000)
    payload0 = hdr0 + inner
    pkt0 = (eth_header()
            + ip_header(src_ip, dst_ip, 17, UDP_HLEN + len(payload0))
            + udp_header(40001, 3386, len(payload0))
            + payload0)
    pcap_write(f, pkt0, ts_us=1000)
    # Third: truncated GTP (only 4 bytes, triggers payload_len < sizeof guard)
    trunc = payload[:4]
    pkt2 = (eth_header()
            + ip_header(src_ip, dst_ip, 17, UDP_HLEN + len(trunc))
            + udp_header(40002, 2152, len(trunc))
            + trunc)
    pcap_write(f, pkt2, ts_us=2000)
    f.close()
    print("wrote %s (GTP v1 T-PDU + v0 + truncated)" % path)


# --- GTPv2 (UDP 2123, version=2) -------------------------------------------

def gtpv2_payload(teid=0xdeadbeef, seq=0x010203):
    # Flags byte: (spare 3 | T 1 | P 1 | version 3) ; version must be 2
    # Byte 0 = 0b010_1_0_010  -> T=1, P=0, version=2
    f1 = (0 << 5) | (0 << 4) | (1 << 3) | 0 << 1 | 2  # crude; mimic proto_gtpv2.h bit layout
    # Simpler: construct header per struct gtpv2_header bitfields as little-endian
    # But easier to pack raw bytes that satisfy classifier: version bits ==2,
    # and length field is total after byte 2.
    # Use flags byte = 0x4A  (0100 1010 -> version 2, T=1, P=0 on little endian view)
    # Actually the struct is bitfield; set byte to 0x48 | 0x02 -> 0x4A for T=1 version2.
    flags = 0x4a  # version 2 | T=1 as parsed by the plugin
    msg_type = 32  # Create Session Request
    # length excludes first 4 bytes per spec (flags+type+len header vs payload)
    # proto_gtpv2.c: if next_offset+ ntohs(hdr->length) > caplen -> fail, so set plausible
    # We'll set length = 4 (teid) + 3 (seq+spare) + 4 (rest) = 11 -> but must be >=8 for header
    inner = b"\x00" * 8
    # length field is 2 bytes: total GTPv2 message length minus first 4 bytes (?)
    # Use len(inner)+7 (teid(4)+seq(3)) and set length accordingly.
    length = 4 + 3 + len(inner)  # teid + seq(3) + inner
    hdr = struct.pack("!BBH", flags, msg_type, length) + struct.pack("!I", teid) + struct.pack("!BBB", (seq >> 16) & 0xFF, (seq >> 8) & 0xFF, seq & 0xFF) + b"\x00"
    return hdr + inner


def gen_gtpv2_pcap(path):
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    payload = gtpv2_payload(teid=0x01020304, seq=0x000001)
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 17, UDP_HLEN + len(payload))
           + udp_header(50000, 2123, len(payload))
           + payload)
    pcap_write(f, pkt, ts_us=0)
    # Truncated: version bit still 2 but caplen too short for sizeof check
    trunc = payload[:6]
    pkt2 = (eth_header()
            + ip_header(src_ip, dst_ip, 17, UDP_HLEN + len(trunc))
            + udp_header(50001, 2123, len(trunc))
            + trunc)
    pcap_write(f, pkt2, ts_us=1000)
    f.close()
    print("wrote %s (GTPv2 Create Session + truncated)" % path)


# --- Diameter over SCTP (PPID 46) -------------------------------------------

def diameter_payload():
    # 20-byte header: version=1, length=20, flags(R,P,E,T)=0, command_code=257, app_id=0, h2h/e2e
    version = 1
    length = 20  # includes header, multiple of 4
    # Pack as per struct diameter_header: version(1) + length 24bits + flags nibble...
    # For mmt_check: only version==1 and length+offset<=caplen matter; so keep minimal.
    # Build raw: version(1) + 3-byte length + flags(1) + cmd 3bytes + app 4 + h2h 4 + e2e 4
    hdr = struct.pack("!B", version) + struct.pack("!I", length)[1:] \
          + struct.pack("!B", 0x00) + struct.pack("!I", 257)[1:] \
          + struct.pack("!I", 0) + struct.pack("!I", 0x01020304) + struct.pack("!I", 0x05060708)
    # hdr should be exactly 20 bytes
    assert len(hdr) == 20
    return hdr


def gen_diameter_pcap(path):
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    # SCTP common + DATA chunk with PPID 46
    d_payload = diameter_payload()
    chunk, chunk_hdr_len = sctp_data_chunk(d_payload, ppid=46)
    sctp_common = sctp_common_header(3868, 3868)
    sctp_wire = sctp_common + chunk
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 132, len(sctp_wire))
           + sctp_wire)
    pcap_write(f, pkt, ts_us=0)
    # Truncated: diameter payload 3 bytes only -> length check must reject
    trunc_payload = d_payload[:3]
    chunk2, _ = sctp_data_chunk(trunc_payload, ppid=46, tsn=1001)
    sctp_wire2 = sctp_common_header(3868, 3868, vtag=0x12345679) + chunk2
    pkt2 = (eth_header()
            + ip_header(src_ip, dst_ip, 132, len(sctp_wire2))
            + sctp_wire2)
    pcap_write(f, pkt2, ts_us=1000)
    # PPID 0 with ports 3868/3868 + valid version/length — exercises _classify_by_sctp_ports fallback
    chunk3, _ = sctp_data_chunk(d_payload, ppid=0, tsn=1002)
    pkt3 = (eth_header()
            + ip_header(src_ip, dst_ip, 132, len(sctp_common_header(3868, 3868) + chunk3))
            + sctp_common_header(3868, 3868, vtag=0x1234567a) + chunk3)
    pcap_write(f, pkt3, ts_us=2000)
    f.close()
    print("wrote %s (Diameter/SCTP PPID 46 + truncated + PPID 0 fallback)" % path)


# --- S1AP over SCTP (PPID 18) ------------------------------------------------

def gen_s1ap_pcap(path):
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    # Use the real S1AP vector bytes for the valid packet
    chunk, _ = sctp_data_chunk(S1AP_VECTOR, ppid=18, tsn=2000)
    sctp_common = sctp_common_header(36412, 36412)
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 132, len(sctp_common + chunk))
           + sctp_common + chunk)
    pcap_write(f, pkt, ts_us=0)
    # Truncated S1AP payload (3 bytes) — guard must not fault
    trunc = S1AP_VECTOR[:3]
    chunk2, _ = sctp_data_chunk(trunc, ppid=18, tsn=2001)
    pkt2 = (eth_header()
            + ip_header(src_ip, dst_ip, 132, len(sctp_common_header(36412, 36412, vtag=0x12345679) + chunk2))
            + sctp_common_header(36412, 36412, vtag=0x12345679) + chunk2)
    pcap_write(f, pkt2, ts_us=1000)
    # Crafted outer-ok / inner-fail vector (craft_s1ap_inner_fail idiom):
    # 5-byte open-type header + 200 bytes 0xFF inner
    inner_fail = bytes([0x00, 0x0c, 0x00, 0x80, 0xc8]) + b"\xFF" * 200
    chunk3, _ = sctp_data_chunk(inner_fail, ppid=18, tsn=2002)
    pkt3 = (eth_header()
            + ip_header(src_ip, dst_ip, 132, len(sctp_common_header(36412, 36412, vtag=0x1234567a) + chunk3))
            + sctp_common_header(36412, 36412, vtag=0x1234567a) + chunk3)
    pcap_write(f, pkt3, ts_us=2000)
    f.close()
    print("wrote %s (S1AP/SCTP PPID 18 valid + truncated + inner-fail)" % path)


# --- NGAP over SCTP (PPID 60, plus PPID 0/port fallback) --------------------

def gen_ngap_pcap(path):
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    # For PPID 60 the classifier accepts any payload without decoding.
    # Use a small dummy that would also be rejected by try_decode_ngap if
    # we went via the PPID-0 path.
    dummy = b"\x00\x01\x02\x03\x04\x05\x06\x07"
    chunk, _ = sctp_data_chunk(dummy, ppid=60, tsn=3000)
    sctp_common = sctp_common_header(38412, 38412)
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 132, len(sctp_common + chunk))
           + sctp_common + chunk)
    pcap_write(f, pkt, ts_us=0)
    # PPID 60 with the S1AP vector as payload variant: still classified as NGAP
    # via PPID, but payload is at least non-empty for the guard.
    chunk2, _ = sctp_data_chunk(S1AP_VECTOR, ppid=60, tsn=3001)
    pkt2 = (eth_header()
            + ip_header(src_ip, dst_ip, 132, len(sctp_common_header(38412, 38412, vtag=0x12345679) + chunk2))
            + sctp_common_header(38412, 38412, vtag=0x12345679) + chunk2)
    pcap_write(f, pkt2, ts_us=1000)
    # Truncated: 2 bytes only
    trunc = dummy[:2]
    chunk3, _ = sctp_data_chunk(trunc, ppid=60, tsn=3002)
    pkt3 = (eth_header()
            + ip_header(src_ip, dst_ip, 132, len(sctp_common_header(38412, 38412, vtag=0x1234567a) + chunk3))
            + sctp_common_header(38412, 38412, vtag=0x1234567a) + chunk3)
    pcap_write(f, pkt3, ts_us=2000)
    # PPID 0 fallback: dst port 38412, dummy payload -> exercises _is_valid_by_sctp_ports
    # but try_decode_ngap will fail so this will NOT classify as NGAP (still no crash)
    chunk4, _ = sctp_data_chunk(dummy, ppid=0, tsn=3003)
    pkt4 = (eth_header()
            + ip_header(src_ip, dst_ip, 132, len(sctp_common_header(50000, 38412, vtag=0x1234567b) + chunk4))
            + sctp_common_header(50000, 38412, vtag=0x1234567b) + chunk4)
    pcap_write(f, pkt4, ts_us=3000)
    f.close()
    print("wrote %s (NGAP/SCTP PPID 60 + PPID 0 fallback + truncated)" % path)


# --- SCTP control (INIT / SACK) — exercise SCTP sub-protocols ---------------
def gen_sctp_pcap(path):
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    # INIT chunk: type 1, length 20, plus minimal init header bytes
    init_chunk = struct.pack("!BBHIIHHI", 1, 0, 20, 0x01020304, 8192, 10, 10, 1000)
    sctp_init = sctp_common_header(5000, 5000) + init_chunk
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 132, len(sctp_init))
           + sctp_init)
    pcap_write(f, pkt, ts_us=0)
    # SACK chunk: type 3, length 16
    sack_chunk = struct.pack("!BBHIIHH", 3, 0, 16, 1000, 8192, 0, 0)
    sctp_sack = sctp_common_header(5000, 5000, vtag=0x12345679) + sack_chunk
    pkt2 = (eth_header()
            + ip_header(src_ip, dst_ip, 132, len(sctp_sack))
            + sctp_sack)
    pcap_write(f, pkt2, ts_us=1000)
    # DATA chunk with small payload over SCTP (generic, PPID 0, not mobile)
    # exercises sctp_classify_next_chunk path for second chunk handling
    data_payload = b"hello"
    data_chunk, _ = sctp_data_chunk(data_payload, ppid=0, tsn=4000)
    # Prepend an INIT chunk then a DATA chunk in same SCTP packet to exercise multi-chunk
    # For simplicity keep second packet as SACK + DATA later, but now just generic DATA
    sctp_generic = sctp_common_header(5001, 5001, vtag=0x1234567a) + data_chunk
    pkt3 = (eth_header()
            + ip_header(src_ip, dst_ip, 132, len(sctp_generic))
            + sctp_generic)
    pcap_write(f, pkt3, ts_us=2000)
    f.close()
    print("wrote %s (SCTP INIT + SACK + DATA)" % path)


GENS = {
    "radius": gen_radius_pcap,
    "gtp": gen_gtp_pcap,
    "gtpv2": gen_gtpv2_pcap,
    "diameter": gen_diameter_pcap,
    "s1ap": gen_s1ap_pcap,
    "ngap": gen_ngap_pcap,
    "sctp": gen_sctp_pcap,
}


def main():
    ap = argparse.ArgumentParser(description="Generate mobile/security synthetic pcaps (issue #144)")
    ap.add_argument("--out-dir", default="/tmp/mobile-pcaps",
                    help="output directory (default: /tmp/mobile-pcaps)")
    ap.add_argument("--pcap", choices=list(GENS.keys()), default=None,
                    help="generate only this pcap type")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    targets = [args.pcap] if args.pcap else sorted(GENS.keys())
    for name in targets:
        out = os.path.join(args.out_dir, "%s.pcap" % name)
        GENS[name](out)
    total = len(targets)
    print("done: %d pcap(s) under %s" % (total, args.out_dir))


if __name__ == "__main__":
    main()

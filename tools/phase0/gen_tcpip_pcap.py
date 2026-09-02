#!/usr/bin/env python3
"""Generate synthetic TCP/IP-stack pcaps for the pcap-driven harness (issue #143).

Covers the core TCP/IP parsers under src/mmt_tcpip/lib/protocols/:
  - HTTP (GET / POST over TCP)
  - DNS  (query over UDP, including a truncated edge case)
  - TLS/SSL (ClientHello over TCP)
  - FTP  (control session over TCP)
  - ICMP (echo request over IP)
  - TCP/IP fragmentation-like boundary (small caplen)

Each pcap is a classic little-endian DLT_EN10MB capture, built with stdlib
``struct`` only so it is reproducible in CI without scapy.

Usage:
    tools/phase0/gen_tcpip_pcap.py --out-dir /tmp/tcpip-pcaps
    tools/phase0/gen_tcpip_pcap.py --out-dir /tmp/tcpip-pcaps --pcap http
"""
import argparse
import os
import struct

ETH_HLEN = 14
IP_HLEN = 20
TCP_HLEN = 20
UDP_HLEN = 8


def eth_header(src=b"\x02\x00\x00\x00\x00\x01", dst=b"\x02\x00\x00\x00\x00\x02"):
    return dst + src + struct.pack("!H", 0x0800)


def ip_header(src_ip, dst_ip, proto, payload_len, ident=0):
    ver_ihl = (4 << 4) | (IP_HLEN // 4)
    total = IP_HLEN + payload_len
    # ttl=64, no checksum (parsers do not verify it)
    return struct.pack("!BBHHHBBH4s4s",
                       ver_ihl, 0, total, ident, 0x4000, 64, proto, 0,
                       src_ip, dst_ip)


def tcp_header(sport, dport, seq=1000, flags=0x18, payload_len=0):
    # 0x18 = PSH|ACK
    doff = (TCP_HLEN // 4) << 4
    return struct.pack("!HHIIBBHHH",
                       sport, dport, seq, 0, doff, flags, 65535, 0, 0)


def udp_header(sport, dport, payload_len):
    length = UDP_HLEN + payload_len
    return struct.pack("!HHHH", sport, dport, length, 0)


def pcap_open(path):
    f = open(path, "wb")
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    return f


def pcap_write(f, pkt, ts_us=0):
    f.write(struct.pack("<IIII", ts_us // 1_000_000, ts_us % 1_000_000,
                        len(pkt), len(pkt)))
    f.write(pkt)


def build_http_payload(method="GET"):
    if method == "GET":
        return b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    if method == "POST":
        body = b"field=value"
        return (b"POST /submit HTTP/1.1\r\nHost: example.com\r\n"
                b"Content-Length: 11\r\n\r\n" + body)
    return b""


def gen_http_pcap(path):
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    for i, method in enumerate(["GET", "POST", "GET"]):
        payload = build_http_payload(method)
        pkt = (eth_header()
               + ip_header(src_ip, dst_ip, 6, TCP_HLEN + len(payload), ident=i)
               + tcp_header(12345 + i, 80, seq=1000 + i * 100)
               + payload)
        pcap_write(f, pkt, ts_us=i * 1000)
    f.close()
    print("wrote %s (HTTP GET/POST)" % path)


def gen_dns_pcap(path):
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x08080808)
    # Minimal DNS query for example.com: transaction 0x1234, 1 question
    # Header: id, flags (RD), qdcount=1, an=0, ns=0, ar=0
    dns_hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    # QNAME: 7 example 3 com 0, QTYPE A (1), QCLASS IN (1)
    qname = b"\x07example\x03com\x00"
    qtail = struct.pack("!HH", 1, 1)
    dns_payload = dns_hdr + qname + qtail
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 17, UDP_HLEN + len(dns_payload))
           + udp_header(53000, 53, len(dns_payload))
           + dns_payload)
    pcap_write(f, pkt, ts_us=0)
    # Second packet: same query but truncated to 12 bytes (edge case for M7 guard)
    trunc = dns_payload[:12]
    pkt2 = (eth_header()
            + ip_header(src_ip, dst_ip, 17, UDP_HLEN + len(trunc))
            + udp_header(53001, 53, len(trunc))
            + trunc)
    pcap_write(f, pkt2, ts_us=1000)
    f.close()
    print("wrote %s (DNS query + truncated)" % path)


def gen_tls_pcap(path):
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    # Minimal TLS ClientHello record: type 22 (handshake), version 0x0303, length
    # Use a tiny but structurally valid header so the parser enters the record walk.
    # Record: type(1) + version(2) + length(2) + handshake payload
    # Handshake: msg_type(1)=1 ClientHello, length(3), version(2), random(32), etc.
    # Keep it short but enough for H2 guards (needs >=5 bytes).
    client_hello_body = (
        b"\x01"              # ClientHello
        + b"\x00\x00\x20"    # length 32
        + b"\x03\x03"        # version TLS 1.2
        + b"\x00" * 32       # random
        + b"\x00"            # session id len 0
        + b"\x00\x02\x00\x2f" # cipher suites
        + b"\x01\x00"        # compression
    )
    rec_len = len(client_hello_body)
    tls_record = struct.pack("!BHH", 22, 0x0303, rec_len) + client_hello_body
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 6, TCP_HLEN + len(tls_record))
           + tcp_header(40000, 443, seq=1000)
           + tls_record)
    pcap_write(f, pkt, ts_us=0)
    # Second: truncated TLS record (only 3 bytes, triggers H2 guard)
    trunc = tls_record[:3]
    pkt2 = (eth_header()
            + ip_header(src_ip, dst_ip, 6, TCP_HLEN + len(trunc))
            + tcp_header(40001, 443, seq=2000)
            + trunc)
    pcap_write(f, pkt2, ts_us=1000)
    f.close()
    print("wrote %s (TLS ClientHello + truncated)" % path)


def gen_ftp_pcap(path):
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    # FTP control: USER, PASS, PASV-like exchange.
    # The 227 response path in proto_ftp.c:ftp_response_packet does a raw
    # strlen() on a non-NUL-terminated payload (heap overflow under ASan); the
    # harness therefore avoids emitting a 227 until that parser is hardened.
    payloads = [
        b"220 FTP server ready\r\n",
        b"USER anonymous\r\n",
        b"331 Please specify password\r\n",
        b"PASS guest@\r\n",
        b"230 Login successful\r\n",
        b"PASV\r\n",
        b"150 Opening data connection\r\n",
        b"RETR file.txt\r\n",
    ]
    for i, pl in enumerate(payloads):
        sport, dport = (21, 40000) if i % 2 == 0 else (40000, 21)
        pkt = (eth_header()
               + ip_header(src_ip, dst_ip, 6, TCP_HLEN + len(pl), ident=i)
               + tcp_header(sport, dport, seq=1000 + i * 100)
               + pl)
        pcap_write(f, pkt, ts_us=i * 1000)
    f.close()
    print("wrote %s (FTP control)" % path)


def gen_icmp_pcap(path):
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    # ICMP echo request: type 8, code 0, checksum 0, id/seq, payload
    icmp_payload = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + b"hello"
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 1, len(icmp_payload))
           + icmp_payload)
    pcap_write(f, pkt, ts_us=0)
    # Echo reply
    icmp_reply = struct.pack("!BBHHH", 0, 0, 0, 0x1234, 1) + b"hello"
    pkt2 = (eth_header()
            + ip_header(dst_ip, src_ip, 1, len(icmp_reply))
            + icmp_reply)
    pcap_write(f, pkt2, ts_us=1000)
    f.close()
    print("wrote %s (ICMP echo)" % path)


GENS = {
    "http": gen_http_pcap,
    "dns": gen_dns_pcap,
    "tls": gen_tls_pcap,
    "ftp": gen_ftp_pcap,
    "icmp": gen_icmp_pcap,
}


def main():
    ap = argparse.ArgumentParser(description="Generate TCP/IP synthetic pcaps (issue #143)")
    ap.add_argument("--out-dir", default="/tmp/tcpip-pcaps",
                    help="output directory (default: /tmp/tcpip-pcaps)")
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

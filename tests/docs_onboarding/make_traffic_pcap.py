#!/usr/bin/env python3
"""make_traffic_pcap.py — regenerate docs/first-run/traffic.pcap (issue #393).

The first-run capture published on the documentation site is synthetic, so it
is redistributable: every byte is produced here, the addresses come from the
RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
the MACs are locally administered and the hostname is the RFC 2606
example.com. Timestamps are fixed, so the output is byte-for-byte
reproducible — the docs_onboarding suite regenerates it and compares it with
the committed file.

It holds one short conversation, ten Ethernet/IPv4 packets:
  1-2   DNS query + answer for example.com (UDP 53)
  3-5   TCP three-way handshake to port 80
  6-7   HTTP GET / and a 200 OK response
  8-10  FIN/ACK teardown

Usage: python3 make_traffic_pcap.py [OUTPUT]   (default: stdout)
"""
import struct
import sys

CLIENT_MAC = bytes.fromhex("020000000001")
ROUTER_MAC = bytes.fromhex("020000000002")
CLIENT_IP = bytes([192, 0, 2, 10])
RESOLVER_IP = bytes([198, 51, 100, 53])
SERVER_IP = bytes([203, 0, 113, 80])
CLIENT_PORT = 49152
DNS_PORT_CLIENT = 53000
BASE_TS = 1767225600  # 2026-01-01T00:00:00Z


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(src, dst, proto, payload, ident):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident,
                         0x4000, 64, proto, 0, src, dst)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def l4_checksum(src, dst, proto, segment):
    pseudo = struct.pack("!4s4sBBH", src, dst, 0, proto, len(segment))
    return checksum(pseudo + segment)


def udp(src, dst, sport, dport, payload):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    csum = l4_checksum(src, dst, 17, seg) or 0xFFFF
    return seg[:6] + struct.pack("!H", csum) + seg[8:]


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b""):
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags,
                      64240, 0, 0) + payload
    csum = l4_checksum(src, dst, 6, seg)
    return seg[:16] + struct.pack("!H", csum) + seg[18:]


def ether(src_mac, dst_mac, payload):
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + payload


def dns_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


def packets():
    qname = dns_name("example.com")
    question = qname + struct.pack("!HH", 1, 1)
    query = struct.pack("!HHHHHH", 0x1d2c, 0x0100, 1, 0, 0, 0) + question
    answer = (struct.pack("!HHHHHH", 0x1d2c, 0x8180, 1, 1, 0, 0) + question
              + struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + SERVER_IP)
    get = (b"GET / HTTP/1.1\r\nHost: example.com\r\n"
           b"User-Agent: hello_packet\r\nAccept: */*\r\n\r\n")
    body = b"hello from MMT-DPI\n"
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    c_isn, s_isn = 1000, 5000
    c, s = CLIENT_IP, SERVER_IP
    cp, sp = CLIENT_PORT, 80
    out = [
        ether(CLIENT_MAC, ROUTER_MAC, ipv4(c, RESOLVER_IP, 17, udp(c, RESOLVER_IP, DNS_PORT_CLIENT, 53, query), 1)),
        ether(ROUTER_MAC, CLIENT_MAC, ipv4(RESOLVER_IP, c, 17, udp(RESOLVER_IP, c, 53, DNS_PORT_CLIENT, answer), 1)),
        ether(CLIENT_MAC, ROUTER_MAC, ipv4(c, s, 6, tcp(c, s, cp, sp, c_isn, 0, SYN), 2)),
        ether(ROUTER_MAC, CLIENT_MAC, ipv4(s, c, 6, tcp(s, c, sp, cp, s_isn, c_isn + 1, SYN | ACK), 2)),
        ether(CLIENT_MAC, ROUTER_MAC, ipv4(c, s, 6, tcp(c, s, cp, sp, c_isn + 1, s_isn + 1, ACK), 3)),
        ether(CLIENT_MAC, ROUTER_MAC, ipv4(c, s, 6, tcp(c, s, cp, sp, c_isn + 1, s_isn + 1, PSH | ACK, get), 4)),
        ether(ROUTER_MAC, CLIENT_MAC, ipv4(s, c, 6, tcp(s, c, sp, cp, s_isn + 1, c_isn + 1 + len(get), PSH | ACK, resp), 3)),
        ether(CLIENT_MAC, ROUTER_MAC, ipv4(c, s, 6, tcp(c, s, cp, sp, c_isn + 1 + len(get), s_isn + 1 + len(resp), FIN | ACK), 5)),
        ether(ROUTER_MAC, CLIENT_MAC, ipv4(s, c, 6, tcp(s, c, sp, cp, s_isn + 1 + len(resp), c_isn + 2 + len(get), FIN | ACK), 4)),
        ether(CLIENT_MAC, ROUTER_MAC, ipv4(c, s, 6, tcp(c, s, cp, sp, c_isn + 2 + len(get), s_isn + 2 + len(resp), ACK), 6)),
    ]
    return out


def pcap_bytes():
    # classic pcap, little-endian, microsecond timestamps, LINKTYPE_ETHERNET
    blob = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, frame in enumerate(packets()):
        blob += struct.pack("<IIII", BASE_TS, i * 10000, len(frame), len(frame))
        blob += frame
    return blob


def main():
    data = pcap_bytes()
    if len(sys.argv) > 1:
        with open(sys.argv[1], "wb") as fh:
            fh.write(data)
    else:
        sys.stdout.buffer.write(data)


if __name__ == "__main__":
    main()

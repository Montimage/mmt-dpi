#!/usr/bin/env python3
"""Generate synthetic TCP/IP-stack pcaps for the pcap-driven harness (issue #143).

Covers the core TCP/IP parsers under src/mmt_tcpip/lib/protocols/:
  - HTTP (GET / POST over TCP)
  - DNS  (query over UDP, including a truncated edge case; ``dns_query`` is
    the clean single-query variant used by the golden corpus)
  - TLS/SSL (ClientHello over TCP)
  - QUIC-IETF (long-header Initial over UDP)
  - HTTP/2 (connection preface + SETTINGS over TCP)
  - DICOM (A-ASSOCIATE-RQ over TCP/104)
  - syslog (RFC3164 over UDP/514), PTPv2 (Announce over UDP/319)
  - FTP  (control session over TCP, incl. PORT/EPRT commands and 227/228/229
         responses — issue #195 hardened those parsers to length-bounded
         helpers, so they are now emitted)
  - NDN  (NDN-TLV Interest/Data over TCP + a truncated/malformed TLV)
  - ICMP (echo request over IP)
  - IPS_DATA (business-app dissector, reached via a DLT 801 capture)
  - TCP/IP fragmentation-like boundary (small caplen)

Each pcap is a classic little-endian DLT_EN10MB capture, built with stdlib
``struct`` only so it is reproducible in CI without scapy — except the
IPS_DATA pcap which uses linktype 801 (PROTO_IPS_DATA's stack id). The
protocol generators also feed the golden classification corpus via
tools/phase0/ci/regen_pcaps.sh (issue #216).

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


def gen_dns_query_pcap(path):
    """Single clean DNS query — corpus entry for the DNS protocol."""
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x08080808)
    dns_hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"\x07example\x03com\x00"
    qtail = struct.pack("!HH", 1, 1)
    dns_payload = dns_hdr + qname + qtail
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 17, UDP_HLEN + len(dns_payload))
           + udp_header(53000, 53, len(dns_payload))
           + dns_payload)
    pcap_write(f, pkt, ts_us=0)
    f.close()
    print("wrote %s (DNS query)" % path)


def gen_tls_pcap(path):
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    # Minimal TLS ClientHello: the SSL classifier walks the record +
    # handshake headers, so both length fields must be consistent.
    # Handshake: type=1 ClientHello, length(3), version, random(32),
    #   session-id len, cipher-suites len+suites, compression len+methods,
    #   extensions len.
    client_hello_body = (
        b"\x01"               # ClientHello
        + b"\x00\x00\x00"     # length — patched below
        + b"\x03\x03"         # version TLS 1.2
        + b"\x00" * 32        # random
        + b"\x00"             # session id len 0
        + b"\x00\x02\x00\x2f" # cipher suites len=2, TLS_RSA_WITH_AES_128_CBC_SHA
        + b"\x01\x00"         # compression methods len=1, null
        + b"\x00\x00"         # extensions len 0
    )
    hs_len = len(client_hello_body) - 4
    client_hello_body = (client_hello_body[:1]
                         + struct.pack("!I", hs_len)[1:]
                         + client_hello_body[4:])
    tls_record = struct.pack("!BHH", 22, 0x0303, len(client_hello_body)) + client_hello_body
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


def gen_quic_pcap(path):
    """QUIC-IETF long-header Initial on UDP/443 (version 1)."""
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    # byte0: header_form(1)|fixed_bit(1)|long-packet-type(Initial=0)<<4 -> 0xC0
    payload = (b"\xc0" + struct.pack("!I", 1)     # long hdr, version 1
               + b"\x08" + b"\x11" * 8          # DCID len + DCID
               + b"\x04" + b"\x22" * 4          # SCID len + SCID
               + b"\x00"                        # token length 0
               + b"\x40\x40"                    # length varint (~64)
               + b"\x00\x00\x00\x01"            # packet number
               + b"\x00" * 32)                  # payload filler
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 17, UDP_HLEN + len(payload))
           + udp_header(54321, 443, len(payload))
           + payload)
    pcap_write(f, pkt, ts_us=0)
    f.close()
    print("wrote %s (QUIC-IETF Initial)" % path)


def gen_http2_pcap(path):
    """HTTP/2 client connection preface + empty SETTINGS frame over TCP/80."""
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings = struct.pack("!I", 0)[1:] + b"\x04\x00" + b"\x00\x00\x00\x00"
    payload = preface + settings
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 6, TCP_HLEN + len(payload))
           + tcp_header(50000, 80, seq=1000)
           + payload)
    pcap_write(f, pkt, ts_us=0)
    f.close()
    print("wrote %s (HTTP/2 preface+SETTINGS)" % path)


def gen_dicom_pcap(path):
    """DICOM A-ASSOCIATE-RQ over TCP/104 (port 104 = DICOM/ACR-NEMA)."""
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    # fixed body: protocol-version(2) + reserved(2) + called-AE(16) +
    #             calling-AE(16) + reserved(32) = 68 bytes
    body = (struct.pack("!H", 1) + b"\x00\x00"
            + b"CALLED-AE".ljust(16) + b"CALLING-AE".ljust(16) + b"\x00" * 32)
    pdu = b"\x01\x00" + struct.pack("!I", len(body)) + body
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 6, TCP_HLEN + len(pdu))
           + tcp_header(40000, 104, seq=1000)
           + pdu)
    pcap_write(f, pkt, ts_us=0)
    f.close()
    print("wrote %s (DICOM A-ASSOCIATE-RQ)" % path)


def gen_syslog_pcap(path):
    """RFC3164 syslog message on UDP/514."""
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    payload = (b"<134>Oct 11 22:14:15 myhost su[123]: "
               b"'su root' failed for user on /dev/pts/0")
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 17, UDP_HLEN + len(payload))
           + udp_header(40000, 514, len(payload))
           + payload)
    pcap_write(f, pkt, ts_us=0)
    f.close()
    print("wrote %s (syslog)" % path)


def gen_ptp_pcap(path):
    """PTPv2 Announce message on UDP/319 (IEEE 1588 event port)."""
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    # byte0 = transportSpecific(1)<<4 | messageType(Announce=0x0B) -> 0x1B;
    # a low messageType byte would be misread as a RADIUS code by the
    # detection order, so Announce is used rather than Sync (0x00).
    ptp = (bytes([0x1B, 0x02])           # announce, PTP version 2
           + struct.pack("!H", 44)       # messageLength
           + b"\x00" * 40)               # rest of the announce header
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 17, UDP_HLEN + len(ptp))
           + udp_header(40000, 319, len(ptp))
           + ptp)
    pcap_write(f, pkt, ts_us=0)
    f.close()
    print("wrote %s (PTPv2 Announce)" % path)


def gen_ftp_pcap(path):
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    # FTP control exchange exercising the parsers hardened for issue #195:
    # 227/228/229 passive-mode responses (parsed by the bounded subvalue
    # helpers) and PORT/EPRT/LPRT active-mode commands (delimiter scans over
    # the non-NUL-terminated payload). ("srv" = sport 21, "cli" = dport 21.)
    exchange = [
        ("srv", b"220 FTP server ready\r\n"),
        ("cli", b"USER anonymous\r\n"),
        ("srv", b"331 Please specify password\r\n"),
        ("cli", b"PASS guest@\r\n"),
        ("srv", b"230 Login successful\r\n"),
        ("cli", b"PORT 192,168,1,2,7,138\r\n"),
        ("srv", b"200 PORT command successful\r\n"),
        ("cli", b"EPRT |1|132.235.1.2|6275|\r\n"),
        ("srv", b"200 EPRT command successful\r\n"),
        ("cli", b"PASV\r\n"),
        ("srv", b"227 Entering Passive Mode (192,168,1,2,7,138)\r\n"),
        ("cli", b"EPSV\r\n"),
        ("srv", b"229 Entering Extended Passive Mode (|||6275|)\r\n"),
        ("srv", b"228 Entering Long Passive Mode (2002:5183:4383::5183:4383, 1031)\r\n"),
        ("srv", b"150 Opening data connection\r\n"),
        ("cli", b"RETR file.txt\r\n"),
        ("srv", b"226 Transfer complete\r\n"),
        # Malformed edge cases: truncated EPRT and a 227 without parentheses —
        # must not crash the bounded parsers.
        ("cli", b"EPRT |1|132\r\n"),
        ("srv", b"227 Entering Passive Mode\r\n"),
    ]
    for i, (side, pl) in enumerate(exchange):
        sport, dport = (21, 40000) if side == "srv" else (40000, 21)
        pkt = (eth_header()
               + ip_header(src_ip, dst_ip, 6, TCP_HLEN + len(pl), ident=i)
               + tcp_header(sport, dport, seq=1000 + i * 100)
               + pl)
        pcap_write(f, pkt, ts_us=i * 1000)
    # Second control session (client port 40001) exercising issue #206:
    #  - the server's first control packet is "213 x\r\n" — F-BUG-067's crash
    #    input (the 213 handler ran with last_command still NULL), and a bare
    #    "213 \r\n" reply after SIZE covers the response->value == NULL branch;
    #  - a bare 3-byte client payload and a 3-byte command with CRLF hit
    #    F-BUG-068's terminal else / short-command paths;
    #  - an LPRT with a forged port-address-length (2**30) — pre-fix,
    #    port_length * 2 overflowed int in ftp_get_data_client_port_from_LPRT.
    edge = [
        ("srv", b"213 x\r\n"),
        ("cli", b"SIZE f\r\n"),
        ("srv", b"213 \r\n"),
        ("cli", b"ABC\r\n"),
        ("cli", b"ABC"),
        ("cli", b"LPRT 6,4,10,0,0,1,1073741824,1,2\r\n"),
    ]
    for j, (side, pl) in enumerate(edge):
        sport, dport = (21, 40001) if side == "srv" else (40001, 21)
        pkt = (eth_header()
               + ip_header(src_ip, dst_ip, 6, TCP_HLEN + len(pl), ident=100 + j)
               + tcp_header(sport, dport, seq=5000 + j * 100)
               + pl)
        pcap_write(f, pkt, ts_us=(len(exchange) + j) * 1000)
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


def pcap_write_trunc(f, pkt, caplen, ts_us=0):
    """Write a truncated capture: incl_len < wire len, so the L4 payload
    length (IP tot_len) exceeds the captured bytes — the case the issue #195
    payload-length clamps protect against."""
    f.write(struct.pack("<IIII", ts_us // 1_000_000, ts_us % 1_000_000,
                        caplen, len(pkt)))
    f.write(pkt[:caplen])


def gen_ndn_pcap(path):
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)
    # NDN-TLV over TCP (port 6363). Interest = 0x05, Data = 0x06, Name = 0x07,
    # NameComponent = 0x08 — the TLV type bytes match the NDN_* enum values in
    # mmt_tcpip_attributes.h, which is what ndn_TLV_parser() decodes.
    def comp(s):
        return b"\x08" + bytes([len(s)]) + s

    name_tlv = lambda *cs: b"\x07" + bytes([sum(len(c) for c in cs)]) + b"".join(cs)
    interest = lambda name: b"\x05" + bytes([len(name)]) + name
    # Well-formed Interest: /ndn/GET — component index 1 is an HTTP method, so
    # mmt_check_payload_ndn_http() and the NDN_HTTP extractors walk the
    # component list through ndn_TLV_get_string().
    pl_interest = interest(name_tlv(comp(b"ndn"), comp(b"GET")))
    # Interest /a/req/x/POST — "req" at index 1, method at index 3 (the other
    # branch of mmt_check_payload_ndn_http), and 4 components so
    # ndn_TVL_get_name_components() iterates the ->next chain.
    pl_interest_req = interest(
        name_tlv(comp(b"a"), comp(b"req"), comp(b"x"), comp(b"POST")))
    # Data packet carrying a Content TLV (0x15) so the data-side extractors run.
    pl_data = (b"\x06" + bytes([len(name_tlv(comp(b"ndn"), comp(b"GET"))) + 6])
               + name_tlv(comp(b"ndn"), comp(b"GET"))
               + b"\x15\x04data")
    # Malformed TLVs: 0xFF length octet needs 8 length bytes the packet does
    # not have (pre-fix str_hex2int read past the buffer); a name component
    # containing a NUL byte made strlen() stop early so str_sub() returned
    # NULL and ndn_TLV_get_string() then wrote through it (F-BUG-066).
    pl_trunc_tlv = b"\x05\xff\x00\x64"
    pl_nul_comp = interest(name_tlv(comp(b"\x00dn"), comp(b"GET")))
    payloads = [pl_interest, pl_interest_req, pl_data, pl_trunc_tlv, pl_nul_comp]
    for i, pl in enumerate(payloads):
        pkt = (eth_header()
               + ip_header(src_ip, dst_ip, 6, TCP_HLEN + len(pl), ident=i)
               + tcp_header(55000 + i, 6363, seq=1000 + i * 100)
               + pl)
        pcap_write(f, pkt, ts_us=i * 1000)
    # Truncated capture: incl_len < wire len, cutting into the NDN payload —
    # payload_packet_len (from IP tot_len) then exceeds the captured bytes.
    pl = pl_interest
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 6, TCP_HLEN + len(pl), ident=100)
           + tcp_header(55010, 6363, seq=2000)
           + pl)
    pcap_write_trunc(f, pkt, len(pkt) - 5, ts_us=6000)
    f.close()
    print("wrote %s (NDN Interest/Data over TCP + malformed)" % path)


def gen_ips_data_pcap(path):
    """Business-app (IPS_DATA) dissector. The protocol is registered as its own
    protocol stack with id 801 (PROTO_IPS_DATA), so a capture whose global
    linktype is 801 lands every record on _ips_data_classify_next_proto() /
    _extraction_att() — the atol/atof/atoi sites hardened by issue #195."""
    f = open(path, "wb")
    # Classic LE pcap, network = 801 (PROTO_IPS_DATA stack id).
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 801))
    payloads = [
        # Well-formed CSV line (all six markers) — no NUL terminator.
        b"TrolleyPos: 32.981, Hoistpos: 38.042, NoOfMarkers: 3, "
        b"m1: (58901,70912) , m2: (72175,70950) , m3: (65803,71939) , "
        b"m4: (46930,65566) , m5: (65795,72047) , m6: (70644,58001)",
        # Numeric token runs to the very end of the buffer — atol()/atof() on
        # the raw pointer over-read the capture pre-fix (F-BUG-098).
        b"TrolleyPos: 32.9",
        # Key present but value empty — bounded copy of zero bytes.
        b"TrolleyPos:",
        # Shorter than the "TrolleyPos" marker — classify guard.
        b"Trolley",
        # Marker key but missing the "," the Y-coordinate search needs —
        # exercises the NULL-pointer guard on the second _get_pos().
        b"TrolleyPos: 1.0, m1: (12345",
    ]
    for i, pl in enumerate(payloads):
        pcap_write(f, pl, ts_us=i * 1000)
    f.close()
    print("wrote %s (IPS_DATA linktype 801)" % path)


GENS = {
    "http": gen_http_pcap,
    "dns": gen_dns_pcap,
    "dns_query": gen_dns_query_pcap,
    "tls": gen_tls_pcap,
    "ftp": gen_ftp_pcap,
    "ndn": gen_ndn_pcap,
    "icmp": gen_icmp_pcap,
    "ips_data": gen_ips_data_pcap,
    "quic": gen_quic_pcap,
    "http2": gen_http2_pcap,
    "dicom": gen_dicom_pcap,
    "syslog": gen_syslog_pcap,
    "ptp": gen_ptp_pcap,
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

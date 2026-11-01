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
  - DTLS (1.2 handshake + application-data records over UDP, plus a
         bogus-version datagram that must stay udp.unknown — issue #262)
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
    tools/phase0/gen_tcpip_pcap.py --out-dir tools/phase0/ci/accuracy --accuracy
    tools/phase0/gen_tcpip_pcap.py --out-dir /tmp/abstain --abstention   # issue #527
"""
import argparse
import hashlib
import hmac
import os
import struct
import zlib

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


def gen_dtls_pcap(path):
    """DTLS 1.2 over UDP (issue #262).

    Flow A (2 packets): a Handshake record (content type 22, version 0xFEFD)
    carrying a minimal ClientHello, then an Application-data record (type 23)
    on the same flow. Flow B (1 packet): a datagram with a valid DTLS content
    type but the bogus version 0x0100 — it must NOT classify as DTLS (the
    fingerprint records it as udp.unknown)."""
    f = pcap_open(path)
    src_ip = struct.pack("!I", 0x0A000001)
    dst_ip = struct.pack("!I", 0x0A000002)

    def dtls_record(content_type, version, epoch, seq, body):
        # dtls_header_t: content_type(1) version(2) epoch(2) seq(6) length(2)
        return (struct.pack("!BHH", content_type, version, epoch)
                + seq.to_bytes(6, "big")
                + struct.pack("!H", len(body)) + body)

    # Minimal ClientHello handshake body (draft-ietf-tls-dtls13-34, 5.3):
    # type(1) length(3) msg_seq(2) fragment_offset(3) fragment_length(3)
    # version(2) random(32) session_id cookie cipher_suites compression
    ch_body = (
        b"\xfe\xfd"                     # client version: DTLS 1.2
        + b"\x00" * 32                  # random
        + b"\x00"                       # session id len 0
        + b"\x00"                       # cookie len 0
        + b"\x00\x04\x00\x2f\x00\xff"   # cipher suites len=4: AES128-SHA, SCSV
        + b"\x01\x00"                   # compression methods len=1: null
    )
    client_hello = (b"\x01"             # handshake_type: client_hello
                    + struct.pack("!I", len(ch_body))[1:]
                    + b"\x00\x00"       # message_seq
                    + b"\x00\x00\x00"   # fragment_offset
                    + struct.pack("!I", len(ch_body))[1:]
                    + ch_body)
    rec_hello = dtls_record(22, 0xFEFD, 0, 0, client_hello)
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 17, UDP_HLEN + len(rec_hello))
           + udp_header(4433, 4433, len(rec_hello))
           + rec_hello)
    pcap_write(f, pkt, ts_us=0)

    rec_app = dtls_record(23, 0xFEFD, 1, 1, b"\x00" * 16)
    pkt = (eth_header()
           + ip_header(src_ip, dst_ip, 17, UDP_HLEN + len(rec_app), ident=1)
           + udp_header(4433, 4433, len(rec_app))
           + rec_app)
    pcap_write(f, pkt, ts_us=1000)

    # Bogus version 0x0100 (rejected by _is_dtls_version since issue #104) on
    # a different flow — exercises the version gate end to end.
    rec_bogus = dtls_record(22, 0x0100, 0, 0, b"\x00" * 16)
    pkt = (eth_header()
           + ip_header(dst_ip, src_ip, 17, UDP_HLEN + len(rec_bogus), ident=2)
           + udp_header(55555, 44444, len(rec_bogus))
           + rec_bogus)
    pcap_write(f, pkt, ts_us=2000)
    f.close()
    print("wrote %s (DTLS 1.2 hello+appdata + bogus-version reject)" % path)


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


# --- accuracy corpus (issue #389, F-TEST-003) --------------------------------
# Reviewed positive and negative/ambiguous cases for DNS, TLS, QUIC and HTTP/2,
# vendored under tools/phase0/ci/accuracy/ and listed (with expected handling,
# provenance and review notes) in tools/phase0/ci/accuracy/corpus.json. They are
# deliberately NOT part of ci/golden_pcaps.txt: the golden classification
# fingerprint's input set stays unchanged. Addresses are RFC 5737 documentation
# ranges and names are RFC 2606/6761 reserved, so the captures carry no real
# identity. Regenerate with:
#   tools/phase0/gen_tcpip_pcap.py --out-dir tools/phase0/ci/accuracy --accuracy

ACC_CLIENT = struct.pack("!I", 0xC0000201)   # 192.0.2.1   (TEST-NET-1)
ACC_SERVER = struct.pack("!I", 0xC6336402)   # 198.51.100.2 (TEST-NET-2)
ACC_CLIENT_MAC = b"\x02\x00\x00\x00\x02\x01"
ACC_SERVER_MAC = b"\x02\x00\x00\x00\x64\x02"


class _AccFlow:
    """One bidirectional flow with consistent addressing (and, for TCP,
    consistent sequence/acknowledgement numbers) between the accuracy client
    and server. Packets are written with strictly increasing timestamps."""

    def __init__(self, f, proto, cport, sport, ts_us=0, server=ACC_SERVER,
                 server_mac=ACC_SERVER_MAC):
        self.f, self.proto = f, proto
        self.cport, self.sport = cport, sport
        self.server, self.server_mac = server, server_mac
        self.seq = {"cli": 1000, "srv": 50000}
        self.ts_us = ts_us
        self.ident = 0

    def _l3l4(self, side, payload, flags):
        if side == "cli":
            smac, dmac = ACC_CLIENT_MAC, self.server_mac
            sip, dip, sp, dp = ACC_CLIENT, self.server, self.cport, self.sport
        else:
            smac, dmac = self.server_mac, ACC_CLIENT_MAC
            sip, dip, sp, dp = self.server, ACC_CLIENT, self.sport, self.cport
        other = "srv" if side == "cli" else "cli"
        if self.proto == 6:
            l4 = struct.pack("!HHIIBBHHH", sp, dp, self.seq[side],
                             self.seq[other] if flags & 0x10 else 0,
                             (TCP_HLEN // 4) << 4, flags, 65535, 0, 0)
            self.seq[side] += len(payload) + (1 if flags & 0x03 else 0)
        else:
            l4 = udp_header(sp, dp, len(payload))
        return (eth_header(smac, dmac)
                + ip_header(sip, dip, self.proto, len(l4) + len(payload),
                            ident=self.ident)
                + l4 + payload)

    def send(self, side, payload=b"", flags=0x18):
        pcap_write(self.f, self._l3l4(side, payload, flags), ts_us=self.ts_us)
        self.ts_us += 1000
        self.ident += 1

    def handshake(self):
        self.send("cli", flags=0x02)   # SYN
        self.send("srv", flags=0x12)   # SYN|ACK
        self.send("cli", flags=0x10)   # ACK


def _dns_message(ident, flags, qname, answers=b"", ancount=0):
    labels = b"".join(bytes([len(p)]) + p for p in qname.split(b".")) + b"\x00"
    return (struct.pack("!HHHHHH", ident, flags, 1, ancount, 0, 0)
            + labels + struct.pack("!HH", 1, 1) + answers)


def gen_acc_dns_positive_pcap(path):
    """DNS query + response over UDP/53: A record for accuracy.example."""
    f = pcap_open(path)
    flow = _AccFlow(f, 17, 53124, 53)
    flow.send("cli", _dns_message(0x3a51, 0x0100, b"accuracy.example"))
    # answer: name pointer to offset 12, TYPE A, CLASS IN, TTL 300, 192.0.2.10
    answer = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4)
              + bytes([192, 0, 2, 10]))
    flow.send("srv", _dns_message(0x3a51, 0x8180, b"accuracy.example",
                                  answer, ancount=1))
    f.close()
    print("wrote %s (accuracy: DNS query+response)" % path)


def gen_acc_dns_negative_pcap(path):
    """Plain text over UDP/53 in both directions — port 53 alone must not
    yield a DNS verdict."""
    f = pcap_open(path)
    flow = _AccFlow(f, 17, 53125, 53)
    flow.send("cli", b"hello, this datagram is not a DNS message at all\n")
    flow.send("srv", b"and neither is this reply, despite the port\n")
    f.close()
    print("wrote %s (accuracy: non-DNS text on UDP/53)" % path)


def _tls_client_hello(sni):
    body = (b"\x03\x03" + bytes(range(32))            # version, random
            + b"\x00"                                  # session id len 0
            + b"\x00\x04\x00\x2f\x00\x35"              # 2 TLS 1.2 suites
            + b"\x01\x00")                             # null compression
    ext = b""
    if sni is not None:
        host = sni.encode()
        sni_list = b"\x00" + struct.pack("!H", len(host)) + host
        sni_ext = struct.pack("!H", len(sni_list)) + sni_list
        ext += struct.pack("!HH", 0, len(sni_ext)) + sni_ext
    body += struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return struct.pack("!BHH", 22, 0x0301, len(hs)) + hs


def _tls_server_hello():
    body = (b"\x03\x03" + bytes(range(32, 64)) + b"\x00"   # version, random, sid
            + b"\x00\x2f" + b"\x00" + b"\x00\x00")         # suite, comp, no ext
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return struct.pack("!BHH", 22, 0x0303, len(hs)) + hs


def _acc_tls_pcap(path, sni, note):
    f = pcap_open(path)
    flow = _AccFlow(f, 6, 49321, 443)
    flow.handshake()
    flow.send("cli", _tls_client_hello(sni))
    flow.send("srv", _tls_server_hello())
    f.close()
    print("wrote %s (accuracy: %s)" % (path, note))


def gen_acc_tls_positive_pcap(path):
    """TCP/443 handshake + TLS ClientHello (SNI accuracy.example) and
    ServerHello."""
    _acc_tls_pcap(path, "accuracy.example", "TLS ClientHello+ServerHello")


def gen_acc_tls_sni_attribution_pcap(path):
    """Same TLS exchange, SNI www.google.com: the wire protocol is still TLS;
    any application name the SDK derives from the SNI is heuristic attribution
    and is reported separately by the accuracy oracle."""
    _acc_tls_pcap(path, "www.google.com", "TLS with attributable SNI")


def gen_acc_tls_sni_teams_pcap(path):
    """Same TLS exchange, SNI teams.microsoft.com (issue #566): Microsoft
    Teams, which the hostname table labelled livemail until then."""
    _acc_tls_pcap(path, "teams.microsoft.com", "TLS with Teams SNI")


def gen_acc_tls_sni_sharepoint_pcap(path):
    """Same TLS exchange, SNI contoso.sharepoint.com (issue #566): a
    SharePoint Online tenant, which the hostname table labelled livemail
    until then."""
    _acc_tls_pcap(path, "contoso.sharepoint.com", "TLS with SharePoint SNI")


def gen_acc_tls_negative_pcap(path):
    """Plaintext HTTP/1.1 on TCP/443 — port 443 alone must not yield a TLS
    verdict."""
    f = pcap_open(path)
    flow = _AccFlow(f, 6, 49322, 443)
    flow.handshake()
    flow.send("cli", b"GET / HTTP/1.1\r\nHost: accuracy.example\r\n\r\n")
    flow.send("srv", b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
    f.close()
    print("wrote %s (accuracy: plaintext HTTP on TCP/443)" % path)


def _quic_long_header(version, ptype, dcid, scid, fill, initial=False,
                      pad_to=0):
    """Long-header packet; `initial` adds the Initial-only Token Length field
    (the Initial type code differs per version: 0b00 in v1, 0b01 in v2).
    `pad_to` pads the payload so the datagram reaches that many bytes (RFC
    9000 §14.1: client Initial datagrams carry at least 1200 bytes)."""
    # byte0: header form (1) | fixed bit (1) | long packet type (2 bits) | pn
    # length - 1 (2 bits, here 3 -> 4-byte packet number)
    first = 0xC0 | (ptype << 4) | 0x03
    head = (bytes([first]) + struct.pack("!I", version)
            + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
            + (b"\x00" if initial else b""))        # Initial: token length 0
    body = b"\x00\x00\x00\x01" + fill               # packet number + payload
    body += b"\x00" * max(0, pad_to - len(head) - 2 - len(body))  # PADDING
    return head + struct.pack("!H", 0x4000 | len(body)) + body


def gen_acc_quic_positive_pcap(path):
    """QUIC v1 (RFC 9000) over UDP/443: client Initial, server Initial, then
    one client short-header (1-RTT) packet on the same flow."""
    f = pcap_open(path)
    flow = _AccFlow(f, 17, 51820, 443)
    dcid, scid = bytes(range(0xA0, 0xA8)), bytes(range(0xB0, 0xB8))
    flow.send("cli", _quic_long_header(1, 0, dcid, scid, b"\x5a" * 40,
                                       initial=True, pad_to=1200))
    # the server's Initial carries its chosen connection ID (dcid) as SCID
    flow.send("srv", _quic_long_header(1, 0, scid, dcid, b"\x5b" * 40,
                                       initial=True))
    # short header: form 0, fixed bit 1, DCID (8 bytes, the server-chosen
    # connection ID), 4-byte packet number, protected payload
    flow.send("cli", b"\x43" + dcid + b"\x00\x00\x00\x02" + b"\x5c" * 24)
    f.close()
    print("wrote %s (accuracy: QUIC v1 Initial x2 + 1-RTT)" % path)


def gen_acc_quic_v2_positive_pcap(path):
    """QUIC version 2 (RFC 9369, version 0x6b3343cf) Initial exchange on
    UDP/443 -- recognised alongside version 1 since issue #333."""
    f = pcap_open(path)
    flow = _AccFlow(f, 17, 51821, 443)
    dcid, scid = bytes(range(0xC0, 0xC8)), bytes(range(0xD0, 0xD8))
    # QUIC v2 encodes Initial as long packet type 0b01
    flow.send("cli", _quic_long_header(0x6B3343CF, 1, dcid, scid,
                                       b"\x6a" * 40, initial=True,
                                       pad_to=1200))
    flow.send("srv", _quic_long_header(0x6B3343CF, 1, scid, dcid,
                                       b"\x6b" * 40, initial=True))
    f.close()
    print("wrote %s (accuracy: QUIC v2 Initial x2)" % path)


def gen_acc_quic_draft29_ambiguous_pcap(path):
    """QUIC draft-29 (version 0xff00001d) Initial exchange on UDP/443. It is
    genuine (pre-RFC) QUIC, but the SDK recognises only the final versions 1
    and 2, so the expected handling is an abstention -- ambiguous, not a
    false negative the gate should hide."""
    f = pcap_open(path)
    flow = _AccFlow(f, 17, 51822, 443)
    dcid, scid = bytes(range(0xE0, 0xE8)), bytes(range(0xF0, 0xF8))
    # draft-29 uses the v1 long packet types: Initial is 0b00
    flow.send("cli", _quic_long_header(0xFF00001D, 0, dcid, scid,
                                       b"\x7a" * 40, initial=True,
                                       pad_to=1200))
    flow.send("srv", _quic_long_header(0xFF00001D, 0, scid, dcid,
                                       b"\x7b" * 40, initial=True))
    f.close()
    print("wrote %s (accuracy: QUIC draft-29 Initial x2)" % path)


def _h2_frame(ftype, flags, stream, payload):
    return (struct.pack("!I", len(payload))[1:] + bytes([ftype, flags])
            + struct.pack("!I", stream) + payload)


def gen_acc_http2_positive_pcap(path):
    """Prior-knowledge cleartext HTTP/2 (RFC 9113 §3.3) on TCP/8080: client
    preface+SETTINGS+HEADERS, server SETTINGS+SETTINGS-ACK."""
    f = pcap_open(path)
    flow = _AccFlow(f, 6, 49323, 8080)
    flow.handshake()
    # HPACK static-table indices: :method GET (2), :scheme http (6), :path /
    # (4), :authority literal (1) "accuracy.example"
    hpack = b"\x82\x86\x84\x41" + bytes([16]) + b"accuracy.example"
    flow.send("cli", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
              + _h2_frame(4, 0, 0, struct.pack("!HI", 3, 100))
              + _h2_frame(1, 0x05, 1, hpack))
    flow.send("srv", _h2_frame(4, 0, 0, b"") + _h2_frame(4, 0x01, 0, b""))
    f.close()
    print("wrote %s (accuracy: HTTP/2 prior knowledge on TCP/8080)" % path)


def gen_acc_http2_negative_pcap(path):
    """HTTP/1.1 request offering an h2c upgrade (RFC 7540 §3.2) that the
    server declines — the flow stays HTTP/1.1 and must not be labelled
    HTTP/2."""
    f = pcap_open(path)
    flow = _AccFlow(f, 6, 49324, 80)
    flow.handshake()
    flow.send("cli", b"GET / HTTP/1.1\r\nHost: accuracy.example\r\n"
              b"Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n"
              b"HTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n")
    flow.send("srv", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    f.close()
    print("wrote %s (accuracy: declined h2c upgrade)" % path)


def _acc_opaque(label, n):
    """n deterministic high-entropy bytes (SHA-256 counter stream): payload
    that matches no protocol grammar and carries no plaintext."""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(b"mmt-accuracy-unknown:%s:%d"
                              % (label.encode(), i)).digest()
        i += 1
    return out[:n]


def gen_acc_unknown_udp_pcap(path):
    """Opaque bytes both ways between unassigned UDP ports (issue #390): no
    protocol grammar, no well-known port -- the SDK must abstain."""
    f = pcap_open(path)
    flow = _AccFlow(f, 17, 47801, 47802)
    flow.send("cli", _acc_opaque("udp-cli", 96))
    flow.send("srv", _acc_opaque("udp-srv", 64))
    f.close()
    print("wrote %s (accuracy: opaque UDP on unassigned ports)" % path)


def gen_acc_unknown_tcp_pcap(path):
    """TCP handshake then opaque bytes both ways between unassigned ports
    (issue #390) -- the SDK must abstain on every packet."""
    f = pcap_open(path)
    flow = _AccFlow(f, 6, 47803, 47804)
    flow.handshake()
    flow.send("cli", _acc_opaque("tcp-cli", 120))
    flow.send("srv", _acc_opaque("tcp-srv", 80))
    f.close()
    print("wrote %s (accuracy: opaque TCP on unassigned ports)" % path)


# --- accuracy corpus: default-chain classifiers (issue #527) ---------------
# One positive and one negative capture per classifier family of the default
# TCP/UDP chains (src/mmt_tcpip/lib/inter_proto_classif_list.def). Each case is
# a table row -- transport, client/server ports, whether a TCP handshake
# precedes the payload, the (side, payload) exchange and, where the protocol
# requires one, the server address (multicast for mDNS and SSDP). Positives
# are protocol-conformant messages; negatives put plain text (or another
# protocol's message) on the classifier's well-known port, so a port-only
# verdict shows up as a false accept.

MDNS_GROUP = struct.pack("!I", 0xE00000FB)   # 224.0.0.251
SSDP_GROUP = struct.pack("!I", 0xEFFFFFFA)   # 239.255.255.250
BROADCAST = struct.pack("!I", 0xFFFFFFFF)


def _mcast_mac(addr):
    """RFC 1112 §6.4 multicast MAC for an IPv4 group (01:00:5e + low 23 bits)."""
    low = struct.unpack("!I", addr)[0] & 0x7FFFFF
    return b"\x01\x00\x5e" + struct.pack("!I", low)[1:]


def _text(lines):
    return b"".join(x + b"\r\n" for x in lines)


def _der(tag, content):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    elif n < 0x100:
        length = b"\x81" + bytes([n])
    else:
        length = b"\x82" + struct.pack("!H", n)
    return bytes([tag]) + length + content


def _der_int(v):
    body = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")
    return _der(0x02, body)


def _krb_principal(ntype, *names):
    return _der(0x30, _der(0xA0, _der_int(ntype))
                + _der(0xA1, _der(0x30, b"".join(_der(0x1B, n)
                                                for n in names))))


def _krb_as_req():
    """RFC 4120 §5.4.1 AS-REQ for alice@ACCURACY.EXAMPLE with a
    PA-PAC-REQUEST pre-auth element, framed for TCP (§7.2.2: 4-byte length)."""
    body = _der(0x30,
                _der(0xA0, _der(0x03, b"\x00\x50\x80\x00\x10"))   # kdc-options
                + _der(0xA1, _krb_principal(1, b"alice"))
                + _der(0xA2, _der(0x1B, b"ACCURACY.EXAMPLE"))
                + _der(0xA3, _krb_principal(2, b"krbtgt", b"ACCURACY.EXAMPLE"))
                + _der(0xA5, _der(0x18, b"20370913024805Z"))
                + _der(0xA7, _der_int(0x2F1D3A55))
                + _der(0xA8, _der(0x30, _der_int(18) + _der_int(17)
                                  + _der_int(23))))
    pa_pac = _der(0x30, _der(0xA1, _der_int(128))
                  + _der(0xA2, _der(0x04, _der(0x30, _der(0xA0, _der(
                      0x01, b"\xff"))))))
    req = _der(0x6A, _der(0x30, _der(0xA1, _der_int(5))
                          + _der(0xA2, _der_int(10))
                          + _der(0xA3, _der(0x30, pa_pac))
                          + _der(0xA4, body)))
    return struct.pack("!I", len(req)) + req


def _krb_error():
    """RFC 4120 §5.9.1 KRB-ERROR KDC_ERR_PREAUTH_REQUIRED (25), TCP-framed."""
    err = _der(0x7E, _der(0x30,
                          _der(0xA0, _der_int(5)) + _der(0xA1, _der_int(30))
                          + _der(0xA4, _der(0x18, b"20260923120000Z"))
                          + _der(0xA5, _der_int(0))
                          + _der(0xA6, _der_int(25))
                          + _der(0xA9, _der(0x1B, b"ACCURACY.EXAMPLE"))
                          + _der(0xAA, _krb_principal(2, b"krbtgt",
                                                      b"ACCURACY.EXAMPLE"))))
    return struct.pack("!I", len(err)) + err


def _netbios_name(name, suffix=0x20):
    """RFC 1001 §14.1 first-level encoding of a 16-byte NetBIOS name."""
    raw = name.ljust(15, b" ")[:15] + bytes([suffix])
    enc = b"".join(bytes([0x41 + (c >> 4), 0x41 + (c & 0x0F)]) for c in raw)
    return b"\x20" + enc + b"\x00"


def _nbss_session_request():
    """RFC 1002 §4.3.2 SESSION REQUEST: called *SMBSERVER, calling CLIENT."""
    names = _netbios_name(b"*SMBSERVER") + _netbios_name(b"ACCCLIENT", 0x00)
    return struct.pack("!BBH", 0x81, 0, len(names)) + names


def _nbns_query():
    """RFC 1002 §4.2.12 NAME QUERY REQUEST (broadcast) for ACCURACY<20>."""
    return (struct.pack("!HHHHHH", 0x6A21, 0x0110, 1, 0, 0, 0)
            + _netbios_name(b"ACCURACY") + struct.pack("!HH", 0x20, 1))


def _nbns_response():
    """Positive NAME QUERY RESPONSE: ACCURACY<20> -> 198.51.100.2."""
    return (struct.pack("!HHHHHH", 0x6A21, 0x8500, 0, 1, 0, 0)
            + _netbios_name(b"ACCURACY") + struct.pack("!HHIH", 0x20, 1,
                                                       300000, 6)
            + b"\x00\x00" + ACC_SERVER)


def _smb1_negotiate():
    """NBSS-framed SMB1 NEGOTIATE request (MS-SMB §2.2.4.52) offering the
    NT LM 0.12 dialect, on TCP/445."""
    hdr = (b"\xffSMB" + b"\x72" + b"\x00" * 4 + b"\x18" + b"\x01\xc8"
           + b"\x00" * 12 + b"\x00\x00" + b"\xff\xfe" + b"\x00\x00"
           + b"\x01\x00")
    dialects = b"\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
    msg = hdr + b"\x00" + struct.pack("<H", len(dialects)) + dialects
    return struct.pack("!I", len(msg)) + msg


def _smb1_negotiate_response():
    """SMB1 NEGOTIATE response selecting dialect index 0 (NT LM 0.12)."""
    hdr = (b"\xffSMB" + b"\x72" + b"\x00" * 4 + b"\x98" + b"\x01\xc8"
           + b"\x00" * 12 + b"\x00\x00" + b"\xff\xfe" + b"\x00\x00"
           + b"\x01\x00")
    words = (struct.pack("<HBHHIIIIQhB", 0, 0x03, 50, 1, 0x10000, 0x10000,
                         0, 0x8000E3FD, 0, 0, 8))
    msg = hdr + bytes([17]) + words + struct.pack("<H", 8) + bytes(range(8))
    return struct.pack("!I", len(msg)) + msg


def _rpc_call(xid, prog, vers, proc, tcp):
    """ONC RPC (RFC 5531) CALL with AUTH_NONE credentials and verifier."""
    msg = struct.pack("!IIIIIIIIII", xid, 0, 2, prog, vers, proc, 0, 0, 0, 0)
    return (struct.pack("!I", 0x80000000 | len(msg)) + msg) if tcp else msg


def _rpc_reply(xid, tcp):
    """MSG_ACCEPTED / SUCCESS reply to an RPC NULL procedure."""
    msg = struct.pack("!IIIIII", xid, 1, 0, 0, 0, 0)
    return (struct.pack("!I", 0x80000000 | len(msg)) + msg) if tcp else msg


def _mysql_greeting():
    """MySQL protocol-10 initial handshake as sent by a 5.0 server
    (pre-plugin-auth layout: capability upper half and the 13 trailing bytes
    are zero, the second scramble part follows)."""
    body = (b"\x0a" + b"5.0.96\x00" + struct.pack("<I", 42)
            + b"Acc0rAcY" + b"\x00" + struct.pack("<H", 0xA22C) + b"\x08"
            + struct.pack("<H", 0x0002) + b"\x00" * 13
            + b"y.Exampl3Scr\x00")
    return struct.pack("<I", len(body))[:3] + b"\x00" + body


def _mysql8_greeting():
    """MySQL 8.0 protocol-10 initial handshake: CLIENT_PLUGIN_AUTH set in the
    capability upper half, 21-byte scramble, caching_sha2_password plugin."""
    body = (b"\x0a" + b"8.0.36\x00" + struct.pack("<I", 43)
            + b"Acc0rAcY" + b"\x00" + struct.pack("<H", 0xFFFF) + b"\xff"
            + struct.pack("<H", 0x0002) + struct.pack("<H", 0xDFFF) + b"\x15"
            + b"\x00" * 10 + b"y.Exampl3Scr\x00"
            + b"caching_sha2_password\x00")
    return struct.pack("<I", len(body))[:3] + b"\x00" + body


def _mysql_login():
    """HandshakeResponse41 for user alice with a 20-byte scramble reply."""
    body = (struct.pack("<IIB", 0x0003A68D, 16777216, 8) + b"\x00" * 23
            + b"alice\x00" + b"\x14" + bytes(range(20)) + b"accuracy\x00")
    return struct.pack("<I", len(body))[:3] + b"\x01" + body


def _pg_startup():
    """PostgreSQL v3.0 StartupMessage (user alice, database accuracy)."""
    params = b"user\x00alice\x00database\x00accuracy\x00\x00"
    return struct.pack("!II", 8 + len(params), 196608) + params


def _pg_auth_md5():
    """AuthenticationMD5Password request (code 5) with a 4-byte salt."""
    return b"R" + struct.pack("!II", 12, 5) + b"\x5a\xcc\x0d\x01"


def _pg_password():
    """PasswordMessage carrying an md5-hashed password."""
    pw = b"md5" + hashlib.md5(b"accuracy").hexdigest().encode() + b"\x00"
    return b"p" + struct.pack("!I", 4 + len(pw)) + pw


def _pg_auth_ok():
    """AuthenticationOk + ReadyForQuery (idle)."""
    return b"R" + struct.pack("!II", 8, 0) + b"Z" + struct.pack("!I", 5) + b"I"


def _tns_connect():
    """Oracle TNS CONNECT packet (type 1) carrying a connect descriptor."""
    desc = (b"(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=accuracy.example)"
            b"(CID=(PROGRAM=sqlplus)(HOST=client)(USER=alice)))"
            b"(ADDRESS=(PROTOCOL=TCP)(HOST=198.51.100.2)(PORT=1521))"
            b"(SERVER=DEDICATED)(INSTANCE_NAME=accuracy))")
    fixed = struct.pack("!HHHHHHHHHHIBB", 0x013A, 0x012C, 0, 0x0800, 0x7FFF,
                        0x7F08, 0, 1, len(desc), 58, 0, 0x41, 0x41)
    fixed += b"\x00" * (58 - 8 - len(fixed))
    total = 8 + len(fixed) + len(desc)
    return struct.pack("!HHBBH", total, 0, 1, 0, 0) + fixed + desc


def _tns_accept():
    """TNS ACCEPT packet (type 2)."""
    fixed = struct.pack("!HHHHHHBB", 0x0136, 0, 0x0800, 0x7FFF, 0, 0, 0x41,
                        0x41) + b"\x00" * 8
    total = 8 + len(fixed)
    return struct.pack("!HHBBH", total, 0, 2, 0, 0) + fixed


def _bt_handshake(peer):
    """BEP 3 peer-wire handshake: pstrlen 19, 'BitTorrent protocol', 8
    reserved bytes (extension protocol bit), info_hash, peer_id."""
    return (b"\x13BitTorrent protocol" + b"\x00\x00\x00\x00\x00\x10\x00\x05"
            + hashlib.sha1(b"accuracy.example torrent").digest()
            + b"-AC0001-" + peer.ljust(12, b"0")[:12])


def _utp(ptype, conn_id, seq, ack, payload=b""):
    """BEP 29 uTP header (version 1, no extension) followed by `payload`."""
    return (struct.pack("!BBHIIIHH", (ptype << 4) | 1, 0, conn_id,
                        0x01020300 + seq, 2000, 1048576, seq, ack) + payload)


def _dht_node_id(label):
    return hashlib.sha1(b"mmt-accuracy-dht:" + label).digest()


def _dht_ping():
    """BEP 5 KRPC ping query (bencoded)."""
    return (b"d1:ad2:id20:" + _dht_node_id(b"cli") + b"e1:q4:ping1:t2:aa"
            b"1:y1:qe")


def _dht_pong():
    return b"d1:rd2:id20:" + _dht_node_id(b"srv") + b"e1:t2:aa1:y1:re"


def _ntp(mode, stratum, ref, ts):
    """RFC 5905 §7.3 48-byte NTPv4 header; `ts` fills the transmit stamp."""
    return (struct.pack("!BBbbII", (0 << 6) | (4 << 3) | mode, stratum, 6,
                        -20, 0x00000100, 0x00000200) + ref
            + struct.pack("!QQQQ", ts if mode == 4 else 0, 0,
                          ts if mode == 4 else 0, ts))


def _dhcp(op, msg_type, xid, yiaddr=b"\x00" * 4):
    """RFC 2131 BOOTP/DHCP message with the magic cookie; option 53 is the
    first option (offset 240), as clients and servers emit it."""
    chaddr = ACC_CLIENT_MAC + b"\x00" * 10
    fixed = (struct.pack("!BBBBIHH", op, 1, 6, 0, xid, 0, 0x8000)
             + b"\x00" * 4 + yiaddr + b"\x00" * 8 + chaddr + b"\x00" * 192)
    opts = (b"\x63\x82\x53\x63" + bytes([53, 1, msg_type])
            + bytes([55, 4, 1, 3, 6, 15]))
    if op == 2:
        opts += bytes([54, 4]) + ACC_SERVER + bytes([51, 4]) + struct.pack(
            "!I", 86400)
    return fixed + opts + b"\xff"


def _netflow_v5():
    """NetFlow v5 export datagram: 24-byte header + one 48-byte flow record
    (192.0.2.1:49321 -> 198.51.100.2:443, 10 packets)."""
    hdr = struct.pack("!HHIIIIBBH", 5, 1, 360000, 1790000000, 0, 1, 0, 0, 0)
    rec = (ACC_CLIENT + ACC_SERVER + b"\x00" * 4
           + struct.pack("!HHIIIIHHBBBBHHBBH", 1, 2, 10, 4200, 359000, 359900,
                         49321, 443, 0, 0x1B, 6, 0, 0, 0, 24, 24, 0))
    return hdr + rec


def _sflow_v5():
    """sFlow v5 datagram header (IPv4 agent 198.51.100.2) carrying one
    counters sample with an empty generic-interface record list."""
    sample = struct.pack("!III", 1, 0x00000001, 0)       # seq, source, records
    return (struct.pack("!III", 5, 1, 0) + ACC_SERVER[:0]
            + ACC_CLIENT + struct.pack("!IIII", 0, 7, 360000, 1)
            + struct.pack("!II", 2, len(sample)) + sample)


def _vmware_hb():
    """66-byte datagram to UDP/902 starting with 0xA4 -- the VMware
    ESX/vCenter heartbeat shape the classifier keys on."""
    return b"\xa4" + hashlib.sha256(b"mmt-accuracy-vmware").digest() * 2 \
        + b"\x00"


def _mdns_query():
    """RFC 6762 one-shot query: PTR _http._tcp.local, QU bit clear."""
    q = b"".join(bytes([len(p)]) + p for p in (b"_http", b"_tcp", b"local"))
    return struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + q + b"\x00" \
        + struct.pack("!HH", 12, 1)


def _mdns_answer():
    """Unsolicited mDNS response announcing accuracy._http._tcp.local."""
    q = b"".join(bytes([len(p)]) + p for p in (b"_http", b"_tcp", b"local"))
    target = b"\x08accuracy\xc0\x0c"
    return (struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + q + b"\x00"
            + struct.pack("!HHIH", 12, 1, 4500, len(target)) + target)


def _snmp(pdu_tag, request_id, value=None):
    """SNMPv2c (RFC 3416) message, community "public", one varbind
    sysDescr.0 (NULL in a request, an OCTET STRING in the response)."""
    oid = _der(0x06, b"\x2b\x06\x01\x02\x01\x01\x01\x00")
    val = _der(0x05, b"") if value is None else _der(0x04, value)
    pdu = _der(pdu_tag, _der_int(request_id) + _der_int(0) + _der_int(0)
               + _der(0x30, _der(0x30, oid + val)))
    return _der(0x30, _der_int(1) + _der(0x04, b"public") + pdu)


def _radius(code, ident, attrs):
    """RFC 2865 §3 RADIUS packet with a fixed request authenticator."""
    body = b"".join(bytes([t, 2 + len(v)]) + v for t, v in attrs)
    auth = hashlib.md5(b"mmt-accuracy-radius:%d" % code).digest()
    return struct.pack("!BBH", code, ident, 20 + len(body)) + auth + body


def _gtpv1_echo(msg_type, seq):
    """GTPv1-C (3GPP TS 29.060 §7.2) Echo Request/Response with the S flag
    set (sequence number present); the response carries Recovery (IE 14)."""
    ies = b"" if msg_type == 1 else b"\x0e\x00"
    body = struct.pack("!HBB", seq, 0, 0) + ies
    return struct.pack("!BBHI", 0x32, msg_type, len(body), 0) + body


def _tds_prelogin():
    """TDS 7 PRELOGIN (MS-TDS §2.2.6.5): VERSION, ENCRYPTION, TERMINATOR."""
    opts = (b"\x00" + struct.pack("!HH", 11, 6) + b"\x01"
            + struct.pack("!HH", 17, 1) + b"\xff"
            + b"\x10\x00\x07\xd0\x00\x00" + b"\x02")
    return struct.pack("!BBHHBB", 0x12, 0x01, 8 + len(opts), 0, 1, 0) + opts


def _tds_prelogin_response():
    opts = (b"\x00" + struct.pack("!HH", 11, 6) + b"\x01"
            + struct.pack("!HH", 17, 1) + b"\xff"
            + b"\x10\x00\x07\xd0\x00\x00" + b"\x02")
    return struct.pack("!BBHHBB", 0x04, 0x01, 8 + len(opts), 0, 1, 0) + opts


def _rdp_cr():
    """TPKT + X.224 Connection Request with an mstshash cookie and an RDP
    Negotiation Request (MS-RDPBCGR §2.2.1.1)."""
    x224 = (b"\xe0\x00\x00\x00\x00\x00" + b"Cookie: mstshash=alice\r\n"
            + b"\x01\x00\x08\x00\x03\x00\x00\x00")
    return struct.pack("!BBHB", 3, 0, 5 + len(x224), len(x224)) + x224


def _rdp_cc():
    x224 = b"\xd0\x00\x00\x12\x34\x00" + b"\x02\x00\x08\x00\x02\x00\x00\x00"
    return struct.pack("!BBHB", 3, 0, 5 + len(x224), len(x224)) + x224


def _bgp_open():
    """RFC 4271 §4.2 OPEN: version 4, AS 64496 (RFC 5398), hold 180,
    BGP identifier 198.51.100.2, no optional parameters."""
    body = struct.pack("!BHH", 4, 64496, 180) + ACC_SERVER + b"\x00"
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), 1) + body


def _bgp_keepalive():
    return b"\xff" * 16 + struct.pack("!HB", 19, 4)


def _pptp_sccrq(ctrl_type):
    """RFC 2637 Start-Control-Connection-Request (1) / -Reply (2)."""
    body = (struct.pack("!HHHBBII", ctrl_type, 0, 0x0100,
                        1 if ctrl_type == 2 else 0, 0, 1, 1)
            + struct.pack("!HH", 1, 0x0A00)
            + b"accuracy".ljust(64, b"\x00") + b"mmt".ljust(64, b"\x00"))
    return struct.pack("!HHI", 8 + len(body), 1, 0x1A2B3C4D) + body


def _stun(msg_type, txid, attrs=b""):
    """RFC 8489 STUN header with the magic cookie 0x2112A442."""
    return struct.pack("!HHI", msg_type, len(attrs), 0x2112A442) + txid + attrs


def _stun_xor_mapped():
    port = 49451 ^ 0x2112
    addr = struct.unpack("!I", ACC_CLIENT)[0] ^ 0x2112A442
    return struct.pack("!HHBBHI", 0x0020, 8, 0, 1, port, addr)


def _rtp(seq, ts, ssrc, fill):
    """RFC 3550 RTP: version 2, PT 0 (PCMU), 20 ms of audio (160 bytes)."""
    return struct.pack("!BBHII", 0x80, 0, seq, ts, ssrc) + bytes([fill]) * 160


def _sip_options():
    return _text([b"OPTIONS sip:bob@accuracy.example SIP/2.0",
                  b"Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKacc1",
                  b"Max-Forwards: 70", b"To: <sip:bob@accuracy.example>",
                  b"From: <sip:alice@accuracy.example>;tag=acc1",
                  b"Call-ID: acc1@192.0.2.1", b"CSeq: 1 OPTIONS",
                  b"Contact: <sip:alice@192.0.2.1>", b"Accept: application/sdp",
                  b"Content-Length: 0", b""])


def _sip_ok():
    return _text([b"SIP/2.0 200 OK",
                  b"Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKacc1",
                  b"To: <sip:bob@accuracy.example>;tag=acc2",
                  b"From: <sip:alice@accuracy.example>;tag=acc1",
                  b"Call-ID: acc1@192.0.2.1", b"CSeq: 1 OPTIONS",
                  b"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE",
                  b"Content-Length: 0", b""])


def _ndn_tlv(t, v):
    """NDN Packet Format v0.3 sec. 1.2: TLV with 1-octet TYPE and LENGTH (< 253)."""
    return bytes([t, len(v)]) + v


def _ndn_name(*comps):
    """NDN Packet Format v0.3 sec. 2.1: Name (0x07) of GenericNameComponents (0x08)."""
    return _ndn_tlv(0x07, b"".join(_ndn_tlv(0x08, c) for c in comps))


def _ndn_interest(name):
    """NDN Packet Format v0.3 sec. 5.1: Interest (0x05) = Name, Nonce, InterestLifetime."""
    return _ndn_tlv(0x05, name + _ndn_tlv(0x0A, b"\x5a\x5a\x5a\x5a")
                    + _ndn_tlv(0x0C, struct.pack("!H", 4000)))


def _ndn_data(name, content):
    """NDN Packet Format v0.3 sec. 6.1/7.3: Data (0x06) signed with DigestSha256."""
    signed = (name + _ndn_tlv(0x14, _ndn_tlv(0x18, b"\x00"))
              + _ndn_tlv(0x15, content)
              + _ndn_tlv(0x16, _ndn_tlv(0x1B, b"\x00")))
    return _ndn_tlv(0x06, signed
                    + _ndn_tlv(0x17, hashlib.sha256(signed).digest()))


ICE_TXID = bytes(range(0x40, 0x4C))
ICE_PWD = b"accuracyIcePasswordRemote1"


def _rfc4571(msg):
    """RFC 4571 §2 framing: a 16-bit length before each RTP/STUN message
    (the framing ICE-TCP uses for STUN and media, RFC 6544 §3)."""
    return struct.pack("!H", len(msg)) + msg


def _stun_attr(atype, value):
    """RFC 8489 §14 attribute TLV, value padded to a 4-byte boundary."""
    return (struct.pack("!HH", atype, len(value)) + value
            + b"\x00" * (-len(value) % 4))


def _stun_ice(msg_type, attrs):
    """RFC 8489 STUN message ending in MESSAGE-INTEGRITY (§14.5, HMAC-SHA1
    over the message with the length covering it) and FINGERPRINT (§14.7,
    CRC-32 XOR 0x5354554e)."""
    def hdr(n):
        return struct.pack("!HHI", msg_type, n, 0x2112A442) + ICE_TXID
    mi = hmac.new(ICE_PWD, hdr(len(attrs) + 24) + attrs, "sha1").digest()
    attrs += _stun_attr(0x0008, mi)
    crc = zlib.crc32(hdr(len(attrs) + 8) + attrs) ^ 0x5354554E
    attrs += _stun_attr(0x8028, struct.pack("!I", crc))
    return hdr(len(attrs)) + attrs


def _ice_check():
    """RFC 8445 §7.2.2 ICE connectivity check: Binding request with USERNAME
    (rfrag:lfrag), PRIORITY and ICE-CONTROLLING, framed for ICE-TCP."""
    return _rfc4571(_stun_ice(0x0001,
                              _stun_attr(0x0006, b"ACCR:ACCL")
                              + _stun_attr(0x0024, struct.pack("!I", 0x6E7F00FF))
                              + _stun_attr(0x802A, b"\x5a\xcc" * 4)))


def _ice_check_ok(port):
    """Binding success response carrying the client's XOR-MAPPED-ADDRESS."""
    xaddr = struct.unpack("!I", ACC_CLIENT)[0] ^ 0x2112A442
    return _rfc4571(_stun_ice(0x0101, _stun_attr(
        0x0020, struct.pack("!BBHI", 0, 1, port ^ 0x2112, xaddr))))


def _iax_full(scall, dcall, oseq, iseq, subclass, ies):
    """RFC 5456 §8.1.1 IAX2 full frame of type IAX (6) with its IEs (§8.6)."""
    body = b"".join(struct.pack("!BB", t, len(v)) + v for t, v in ies)
    return struct.pack("!HHIBBBB", 0x8000 | scall, dcall, 3, oseq, iseq, 6,
                       subclass) + body


def _iax_new():
    """RFC 5456 §6.2.2 NEW: VERSION 2, called/calling numbers, calling name,
    username, desired FORMAT (u-law) and CAPABILITY (u-law|a-law)."""
    return _iax_full(1, 0, 0, 0, 0x01, [
        (0x0B, struct.pack("!H", 2)), (0x01, b"100"), (0x02, b"200"),
        (0x04, b"Alice"), (0x06, b"alice"), (0x09, struct.pack("!I", 4)),
        (0x08, struct.pack("!I", 0x0C))])


def _iax_accept():
    """RFC 5456 §6.2.3 ACCEPT answering the NEW with the chosen FORMAT."""
    return _iax_full(2, 1, 0, 1, 0x07, [(0x09, struct.pack("!I", 4))])


def _tcf_udp(code, attrs=b""):
    """Eclipse TCF UDP discovery (port 1534) packet: "TCF2" magic and
    version, the 1-byte code, 3 reserved zero bytes, then NUL-terminated
    name=value peer attributes."""
    return b"TCF2" + bytes([code, 0, 0, 0]) + attrs


def _tcf_peer_info():
    """TCF Locator peer attributes (ID, Name, OSName, TransportName, Host,
    Port) of an agent at 198.51.100.2:1534 (code 2, ACK_INFO)."""
    return _tcf_udp(2, b"".join(x + b"\x00" for x in (
        b"ID=TCP:198.51.100.2:1534", b"Name=TCF Agent",
        b"OSName=Linux", b"TransportName=TCP",
        b"Host=198.51.100.2", b"Port=1534")))


def _mqtt_connect():
    """MQTT 3.1.1 §3.1 CONNECT: protocol name MQTT, level 4, clean session,
    keep-alive 60 s, client identifier acc-client."""
    var = b"\x00\x04MQTT" + struct.pack("!BBH", 4, 0x02, 60)
    payload = struct.pack("!H", 10) + b"acc-client"
    return bytes([0x10, len(var) + len(payload)]) + var + payload


def _x11_setup():
    """X11 core protocol connection setup (X Window System Protocol,
    "Connection Setup"): LSB-first 'l', version 11.0, MIT-MAGIC-COOKIE-1
    with a 16-byte cookie -- 48 bytes."""
    return (b"l\x00" + struct.pack("<HHHH", 11, 0, 18, 16) + b"\x00\x00"
            + b"MIT-MAGIC-COOKIE-1\x00\x00" + bytes(range(0xA0, 0xB0)))


def _x11_setup_failed():
    """X11 connection setup Failed reply (code 0) with its reason string."""
    reason = b"Invalid MIT-MAGIC-COOKIE-1 key"
    pad = b"\x00" * (-len(reason) % 4)
    return (struct.pack("<BBHHH", 0, len(reason), 11, 0,
                        (len(reason) + len(pad)) // 4) + reason + pad)


def _array8(data):
    """XDMCP 1.1 ARRAY8: CARD16 length, then the bytes."""
    return struct.pack("!H", len(data)) + data


def _xdmcp(opcode, body):
    """XDMCP 1.1 header: version 1, opcode, length of the rest."""
    return struct.pack("!HHH", 1, opcode, len(body)) + body


DCE_NDR_SYNTAX = bytes.fromhex("045d888aeb1cc9119fe808002b104860")  # 8a885d04-1ceb-11c9-9fe8-08002b104860 v2
DCE_EPM_IFACE = bytes.fromhex("0883afe11f5dc91191a408002b14a0fa")   # e1af8308-5d1f-11c9-91a4-08002b14a0fa v3


def _dce_header(ptype, body):
    """DCE 1.1 RPC (C706 §12.6.3.1) connection-oriented common header:
    v5.0, first+last fragment, little-endian NDR data representation."""
    return (struct.pack("<BBBB4sHHI", 5, 0, ptype, 0x03, b"\x10\x00\x00\x00",
                        16 + len(body), 0, 1) + body)


def _dce_bind():
    """C706 §12.6.4.3 bind: one presentation context for the endpoint
    mapper interface (v3.0) with the NDR transfer syntax, on TCP/135."""
    ctx = (struct.pack("<HBB", 0, 1, 0) + DCE_EPM_IFACE
           + struct.pack("<HH", 3, 0) + DCE_NDR_SYNTAX + struct.pack("<I", 2))
    return _dce_header(11, struct.pack("<HHIB3x", 4280, 4280, 0, 1) + ctx)


def _dce_bind_ack():
    """C706 §12.6.4.4 bind_ack: secondary address "135", padded to 4 bytes,
    one result accepting the NDR transfer syntax."""
    sec = b"135\x00"
    body = (struct.pack("<HHIH", 4280, 4280, 0x00012345, len(sec)) + sec
            + b"\x00\x00" + struct.pack("<B3xHH", 1, 0, 0)
            + DCE_NDR_SYNTAX + struct.pack("<I", 2))
    return _dce_header(12, body)


def _dsi_open_session(flags, option):
    """DSI (AFP over TCP, Apple AFP Programming Guide, DSI header) OpenSession
    command 4, request ID 1, carrying one session option."""
    return struct.pack("!BBHIII", flags, 0x04, 1, 0, len(option), 0) + option


def _ica_detect():
    """Citrix ICA connection detect string 7F 7F 'ICA' 00 (nDPI citrix.c)."""
    return b"\x7f\x7fICA\x00"


def _rtmp_c0c1():
    """RTMP 1.0 §5.2.2-5.2.3 C0 (version 3) + C1 (time, zero, 1528 random
    bytes), sent as one 1537-byte segment."""
    return (b"\x03" + struct.pack("!II", 0, 0)
            + bytes((i * 7) & 0xFF for i in range(1528)))


def _rtmp_s0s1s2():
    """RTMP 1.0 §5.2.2-5.2.4 S0 + S1 + S2 (S2 echoes C1's time and random)."""
    return (b"\x03" + struct.pack("!II", 0, 0)
            + bytes((i * 11) & 0xFF for i in range(1528))
            + struct.pack("!II", 0, 1)
            + bytes((i * 7) & 0xFF for i in range(1528)))


def _teamviewer_cmd(cmd, body):
    """TeamViewer command: protocol version 0x1724 in the first two bytes and
    the command in the third (the reverse-engineered OpenDPI/nDPI signature
    proto_teamviewer.c:21 keys on; 0x12 = CMD_MASTERCOMMAND), then an assumed
    little-endian 32-bit body length and the body."""
    return b"\x17\x24" + bytes([cmd]) + struct.pack("<I", len(body)) + body


def _teamviewer_udp(seq, cmd, body):
    """TeamViewer UDP datagram: an 11-byte prefix whose first byte is the
    sequence counter (0 on the first datagram), then the 0x1724 command."""
    return (bytes([seq]) + b"\x00" * 10) + _teamviewer_cmd(cmd, body)


def _steam_version(v):
    """Legacy Steam directory/content-server handshake (the reverse-engineered
    OpenDPI/nDPI signature proto_steam.c:20-33 applies): the client opens the
    connection with its protocol version as a 4-byte big-endian integer."""
    return struct.pack("!I", v)


def _steam_accept():
    """Server accept: 0x01 followed by the client's external IPv4 address."""
    return b"\x01" + ACC_CLIENT


def _wow_logon_challenge(account):
    """CMD_AUTH_LOGON_CHALLENGE client message (wowdev.wiki Login): opcode 0,
    protocol 8, LE size, "WoW", client 3.3.5 build 12340, platform x86, OS
    Win, locale enUS (the four-char codes stored reversed), timezone, IP,
    account name length and the upper-case account name."""
    body = (b"WoW\x00" + bytes([3, 3, 5]) + struct.pack("<H", 12340)
            + b"68x\x00" + b"niW\x00" + b"SUne" + struct.pack("<I", 0)
            + ACC_CLIENT + bytes([len(account)]) + account)
    return b"\x00\x08" + struct.pack("<H", len(body)) + body


def _wow_logon_challenge_reply():
    """CMD_AUTH_LOGON_CHALLENGE server reply, WOW_SUCCESS: SRP6 B, g = 7, the
    32-byte WoW N (little-endian on the wire), salt, CRC salt, flags 0."""
    n = bytes.fromhex("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8F"
                      "AB3C82872A3E9BB7")[::-1]
    return (b"\x00\x00\x00" + bytes(range(0x40, 0x60)) + b"\x01\x07"
            + b"\x20" + n + bytes(range(0x60, 0x80))
            + bytes(range(0x80, 0x90)) + b"\x00")


def _xbox_udp(msg_type, length):
    """Xbox UDP message shape the classifier keys on (OpenDPI/nDPI
    signature, proto_xbox.c:32-40): four zero bytes, type, 0x58 ('X'),
    the datagram length, three zero bytes, zero padding to `length`."""
    hdr = b"\x00" * 4 + bytes([msg_type, 0x58, length]) + b"\x00" * 3
    return hdr + b"\x00" * (length - len(hdr))


ACC_SYSLOG = b"<34>Sep 23 12:00:00 accuracy su: 'su root' failed for alice"


ACC_CLASSIFIER_FLOWS = {
    # name: (proto, cport, sport, handshake, [(side, payload)...], extra)
    "acc_http_positive": (6, 49401, 80, True, [
        ("cli", _text([b"GET /index.html HTTP/1.1", b"Host: accuracy.example",
                       b"User-Agent: accuracy/1.0", b"Accept: */*", b""])),
        ("srv", _text([b"HTTP/1.1 200 OK", b"Content-Type: text/plain",
                       b"Content-Length: 2", b""]) + b"ok")], {}),
    "acc_http_negative": (6, 49402, 80, True, [
        ("cli", b"hello, this stream is not an HTTP request\n"),
        ("srv", b"and this reply is not an HTTP response either\n")], {}),
    "acc_imap_positive": (6, 49403, 143, True, [
        ("srv", b"* OK [CAPABILITY IMAP4rev1 STARTTLS] accuracy.example "
                b"IMAP4rev1 ready\r\n"),
        ("cli", b"a001 CAPABILITY\r\n"),
        ("srv", b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n"
                b"a001 OK CAPABILITY completed\r\n"),
        ("cli", b"a002 LOGIN alice secret\r\n"),
        ("srv", b"a002 OK LOGIN completed\r\n"),
        ("cli", b"a003 LOGOUT\r\n"),
        ("srv", b"* BYE accuracy.example IMAP4rev1 logging out\r\n"
                b"a003 OK LOGOUT completed\r\n")], {}),
    "acc_imap_negative": (6, 49404, 143, True, [
        ("srv", b"welcome, this banner is not an IMAP greeting\r\n"),
        ("cli", b"please send the weather report\r\n")], {}),
    "acc_smtp_positive": (6, 49405, 25, True, [
        ("srv", b"220 accuracy.example ESMTP ready\r\n"),
        ("cli", b"EHLO client.accuracy.example\r\n"),
        ("srv", b"250-accuracy.example Hello\r\n250-SIZE 10240000\r\n"
                b"250 STARTTLS\r\n"),
        ("cli", b"MAIL FROM:<alice@accuracy.example>\r\n"),
        ("srv", b"250 2.1.0 Ok\r\n"),
        ("cli", b"QUIT\r\n"),
        ("srv", b"221 2.0.0 Bye\r\n")], {}),
    "acc_smtp_negative": (6, 49406, 25, True, [
        ("srv", b"welcome, this banner is not an SMTP greeting\r\n"),
        ("cli", b"please send the weather report\r\n")], {}),
    "acc_pop_positive": (6, 49407, 110, True, [
        ("srv", b"+OK POP3 accuracy.example server ready\r\n"),
        ("cli", b"USER alice\r\n"),
        ("srv", b"+OK\r\n"),
        ("cli", b"PASS secret\r\n"),
        ("srv", b"+OK maildrop has 0 messages\r\n"),
        ("cli", b"QUIT\r\n"),
        ("srv", b"+OK bye\r\n")], {}),
    "acc_pop_negative": (6, 49408, 110, True, [
        ("srv", b"welcome, this banner is not a POP3 greeting\r\n"),
        ("cli", b"please send the weather report\r\n")], {}),
    "acc_jabber_positive": (6, 49409, 5222, True, [
        ("cli", b"<?xml version='1.0'?><stream:stream to='accuracy.example' "
                b"xmlns='jabber:client' "
                b"xmlns:stream='http://etherx.jabber.org/streams' "
                b"version='1.0'>"),
        ("srv", b"<?xml version='1.0'?><stream:stream from='accuracy.example'"
                b" id='acc1' xmlns='jabber:client' "
                b"xmlns:stream='http://etherx.jabber.org/streams' "
                b"version='1.0'>")], {}),
    "acc_jabber_negative": (6, 49410, 5222, True, [
        ("cli", b"<?xml version='1.0'?><note><to>alice</to>"
                b"<body>not an XMPP stream</body></note>"),
        ("srv", b"<?xml version='1.0'?><ack/>")], {}),
    "acc_netbios_tcp_positive": (6, 49411, 139, True, [
        ("cli", _nbss_session_request()),
        ("srv", b"\x82\x00\x00\x00")], {}),
    "acc_netbios_udp_positive": (17, 137, 137, False, [
        ("cli", _nbns_query()),
        ("srv", _nbns_response())], {}),
    "acc_netbios_tcp_negative": (6, 49447, 139, True, [
        ("cli", b"hello, this stream is not a NetBIOS session request\n"),
        ("srv", b"and this reply is not a session response\n")], {}),
    "acc_netbios_udp_negative": (17, 49412, 137, False, [
        ("cli", b"hello, this datagram is not a NetBIOS name query at all\n"),
        ("srv", b"and neither is this reply, despite the port\n")], {}),
    "acc_ftp_positive": (6, 49413, 21, True, [
        ("srv", b"220 accuracy.example FTP server ready\r\n"),
        ("cli", b"USER anonymous\r\n"),
        ("srv", b"331 Please specify the password.\r\n"),
        ("cli", b"PASS guest@accuracy.example\r\n"),
        ("srv", b"230 Login successful.\r\n"),
        ("cli", b"QUIT\r\n"),
        ("srv", b"221 Goodbye.\r\n")], {}),
    "acc_ftp_negative": (6, 49414, 21, True, [
        ("srv", b"welcome, this banner is not an FTP greeting\r\n"),
        ("cli", b"please send the weather report\r\n")], {}),
    "acc_bittorrent_tcp_positive": (6, 49415, 6881, True, [
        ("cli", _bt_handshake(b"cli")),
        ("srv", _bt_handshake(b"srv"))], {}),
    "acc_bittorrent_udp_positive": (17, 49416, 6881, False, [
        ("cli", _utp(4, 0x5ACC, 1, 0)),                    # ST_SYN
        ("srv", _utp(2, 0x5ACC, 7, 1)),                    # ST_STATE
        ("cli", _utp(0, 0x5ACD, 2, 7, _bt_handshake(b"cli"))),   # ST_DATA
        ("srv", _utp(0, 0x5ACC, 8, 2, _bt_handshake(b"srv")))], {}),
    "acc_bittorrent_udp_negative": (17, 49448, 6881, False, [
        ("cli", b"hello, this datagram is not a uTP or DHT message at all\n"),
        ("srv", b"and neither is this reply, despite the port\n")], {}),
    "acc_bittorrent_dht_ambiguous": (17, 49450, 6881, False, [
        ("cli", _dht_ping()),
        ("srv", _dht_pong())], {}),
    "acc_bittorrent_tcp_negative": (6, 49417, 6881, True, [
        ("cli", b"hello, this stream is not a BitTorrent handshake\n"),
        ("srv", b"and this reply is not one either\n")], {}),
    "acc_ssh_positive": (6, 49418, 22, True, [
        ("srv", b"SSH-2.0-OpenSSH_9.6 accuracy\r\n"),
        ("cli", b"SSH-2.0-OpenSSH_9.6\r\n")], {}),
    "acc_ssh_negative": (6, 49419, 22, True, [
        ("srv", b"welcome, this banner is not an SSH identification\r\n"),
        ("cli", b"please send the weather report\r\n")], {}),
    "acc_smb_positive": (6, 49420, 445, True, [
        ("cli", _smb1_negotiate()),
        ("srv", _smb1_negotiate_response())], {}),
    "acc_smb_negative": (6, 49421, 445, True, [
        ("cli", b"hello, this stream is not an SMB negotiate request\n"),
        ("srv", b"and this reply is not an SMB response\n")], {}),
    "acc_nfs_positive": (6, 49422, 2049, True, [
        ("cli", _rpc_call(0x5ACC0001, 100003, 3, 0, True)),
        ("srv", _rpc_reply(0x5ACC0001, True))], {}),
    "acc_nfs_udp_positive": (17, 49423, 2049, False, [
        ("cli", _rpc_call(0x5ACC0002, 100003, 3, 0, False)),
        ("srv", _rpc_reply(0x5ACC0002, False))], {}),
    "acc_nfs_negative": (6, 49424, 2049, True, [
        ("cli", b"hello, this stream is not an ONC RPC call at all\n"),
        ("srv", b"and this reply is not an RPC reply\n")], {}),
    "acc_mysql_positive": (6, 49425, 3306, True, [
        ("srv", _mysql_greeting()),
        ("cli", _mysql_login()),
        ("srv", b"\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00")], {}),
    "acc_mysql8_ambiguous": (6, 49449, 3306, True, [
        ("srv", _mysql8_greeting()),
        ("cli", _mysql_login())], {}),
    "acc_mysql_negative": (6, 49426, 3306, True, [
        ("srv", b"welcome, this banner is not a MySQL handshake packet\n"),
        ("cli", b"please send the weather report\n")], {}),
    "acc_postgres_positive": (6, 49427, 5432, True, [
        ("cli", _pg_startup()),
        ("srv", _pg_auth_md5()),
        ("cli", _pg_password()),
        ("srv", _pg_auth_ok())], {}),
    "acc_postgres_negative": (6, 49428, 5432, True, [
        ("cli", b"hello, this stream is not a PostgreSQL startup\n"),
        ("srv", b"and this reply is not a backend message\n")], {}),
    "acc_kerberos_positive": (6, 49429, 88, True, [
        ("cli", _krb_as_req()),
        ("srv", _krb_error())], {}),
    "acc_kerberos_negative": (6, 49430, 88, True, [
        ("cli", b"hello, this stream is not a Kerberos request\n"),
        ("srv", b"and this reply is not a KDC reply\n")], {}),
    "acc_redis_positive": (6, 49431, 6379, True, [
        ("cli", b"*1\r\n$4\r\nPING\r\n"),
        ("srv", b"+PONG\r\n"),
        ("cli", b"*2\r\n$3\r\nGET\r\n$8\r\naccuracy\r\n"),
        ("srv", b"$-1\r\n")], {}),
    "acc_redis_negative": (6, 49432, 6379, True, [
        ("cli", b"hello, this stream is not a RESP command\n"),
        ("srv", b"and this reply is not a RESP reply\n")], {}),
    "acc_oracle_positive": (6, 49433, 1521, True, [
        ("cli", _tns_connect()),
        ("srv", _tns_accept())], {}),
    "acc_oracle_negative": (6, 49434, 1521, True, [
        ("cli", b"hello, this stream is not a TNS connect packet\n"),
        ("srv", b"and this reply is not a TNS packet either\n")], {}),
    "acc_mdns_positive": (17, 5353, 5353, False, [
        ("cli", _mdns_query()),
        ("cli", _mdns_answer())],
        {"server": MDNS_GROUP, "server_mac": _mcast_mac(MDNS_GROUP)}),
    "acc_mdns_negative": (17, 5353, 5353, False, [
        ("cli", b"hello, this datagram is not an mDNS message at all\n")],
        {"server": MDNS_GROUP, "server_mac": _mcast_mac(MDNS_GROUP)}),
    "acc_dhcp_positive": (17, 68, 67, False, [
        ("cli", _dhcp(1, 1, 0x5ACC0DC9)),
        ("srv", _dhcp(2, 2, 0x5ACC0DC9, bytes([192, 0, 2, 77])))], {}),
    "acc_dhcp_negative": (17, 68, 67, False, [
        ("cli", b"hello, this datagram is not a DHCP message at all\n"),
        ("srv", b"and neither is this reply, despite the port\n")], {}),
    "acc_dropbox_positive": (17, 17500, 17500, False, [
        ("cli", b'{"host_int": 123456789012345, "version": [2, 0], '
                b'"displayname": "", "port": 17500, "namespaces": '
                b'[1234567, 2345678]}')],
        {"server": BROADCAST, "server_mac": b"\xff" * 6}),
    "acc_dropbox_negative": (17, 17500, 17500, False, [
        ("cli", b"hello, this datagram is not a LAN sync announcement\n")],
        {"server": BROADCAST, "server_mac": b"\xff" * 6}),
    "acc_ntp_positive": (17, 49435, 123, False, [
        ("cli", _ntp(3, 0, b"\x00" * 4, 0xEC6E1A0000000000)),
        ("srv", _ntp(4, 2, ACC_SERVER, 0xEC6E1A0080000000))], {}),
    "acc_ntp_negative": (17, 49436, 123, False, [
        ("cli", b"hello, this datagram is not an NTP packet at all, no!\n"),
        ("srv", b"and neither is this reply, despite the port number\n")], {}),
    "acc_ssdp_positive": (17, 49437, 1900, False, [
        ("cli", _text([b"M-SEARCH * HTTP/1.1", b"HOST: 239.255.255.250:1900",
                       b'MAN: "ssdp:discover"', b"MX: 1", b"ST: ssdp:all",
                       b""]))],
        {"server": SSDP_GROUP, "server_mac": _mcast_mac(SSDP_GROUP)}),
    "acc_ssdp_negative": (17, 49438, 1900, False, [
        ("cli", b"hello, this datagram is not an SSDP search request at "
                b"all, despite its group and port\n")],
        {"server": SSDP_GROUP, "server_mac": _mcast_mac(SSDP_GROUP)}),
    "acc_syslog_positive": (17, 49439, 514, False, [
        ("cli", ACC_SYSLOG)], {}),
    "acc_syslog_negative": (17, 49440, 514, False, [
        ("cli", b"hello, this datagram is not a syslog message at all\n")],
        {}),
    "acc_netflow_positive": (17, 49441, 2055, False, [
        ("cli", _netflow_v5())], {}),
    "acc_netflow_negative": (17, 49442, 2055, False, [
        ("cli", b"hello, this datagram is not a NetFlow export at all\n")],
        {}),
    "acc_sflow_positive": (17, 49443, 6343, False, [
        ("cli", _sflow_v5())], {}),
    "acc_sflow_negative": (17, 49444, 6343, False, [
        ("cli", b"hello, this datagram is not an sFlow datagram at all\n")],
        {}),
    "acc_vmware_positive": (17, 49445, 902, False, [
        ("cli", _vmware_hb())], {}),
    "acc_vmware_negative": (17, 49446, 902, False, [
        ("cli", b"hello, this datagram is not a VMware heartbeat at all\n")],
        {}),
    "acc_telnet_positive": (6, 49452, 23, True, [
        ("srv", b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27"),
        ("cli", b"\xff\xfb\x18\xff\xfb\x20\xff\xfb\x23\xff\xfb\x27"),
        ("srv", b"\xff\xfa\x18\x01\xff\xf0\xff\xfb\x03\xff\xfd\x01"),
        ("cli", b"\xff\xfa\x18\x00VT100\xff\xf0"),
        ("srv", b"accuracy.example login: ")], {}),
    "acc_telnet_negative": (6, 49453, 23, True, [
        ("srv", b"welcome, this banner carries no telnet negotiation\r\n"),
        ("cli", b"please send the weather report\r\n")], {}),
    "acc_rdp_positive": (6, 49454, 3389, True, [
        ("cli", _rdp_cr()),
        ("srv", _rdp_cc())], {}),
    "acc_rdp_negative": (6, 49455, 3389, True, [
        ("cli", b"hello, this stream is not an X.224 connection request\n"),
        ("srv", b"and this reply is not a connection confirm\n")], {}),
    "acc_ldap_positive": (6, 49456, 389, True, [
        ("cli", b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"),
        ("srv", b"\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00")],
        {}),
    "acc_ldap_negative": (6, 49457, 389, True, [
        ("cli", b"hello, this stream is not an LDAP bind request\n"),
        ("srv", b"and this reply is not an LDAP message\n")], {}),
    "acc_bgp_positive": (6, 49458, 179, True, [
        ("cli", _bgp_open()),
        ("srv", _bgp_open()),
        ("cli", _bgp_keepalive()),
        ("srv", _bgp_keepalive())], {}),
    "acc_bgp_negative": (6, 49459, 179, True, [
        ("cli", b"hello, this stream is not a BGP OPEN message at all\n"),
        ("srv", b"and this reply is not a BGP message either\n")], {}),
    "acc_pptp_positive": (6, 49460, 1723, True, [
        ("cli", _pptp_sccrq(1)),
        ("srv", _pptp_sccrq(2))], {}),
    "acc_pptp_negative": (6, 49461, 1723, True, [
        ("cli", b"hello, this stream is not a PPTP control message\n"),
        ("srv", b"and this reply is not one either\n")], {}),
    "acc_mssql_positive": (6, 49464, 1433, True, [
        ("cli", _tds_prelogin()),
        ("srv", _tds_prelogin_response())], {}),
    "acc_mssql_negative": (6, 49465, 1433, True, [
        ("cli", b"hello, this stream is not a TDS pre-login packet\n"),
        ("srv", b"and this reply is not a TDS response\n")], {}),
    "acc_irc_positive": (6, 49468, 6667, True, [
        ("cli", b"NICK alice\r\nUSER alice 0 * :Alice Accuracy\r\n"),
        ("srv", b":irc.accuracy.example 001 alice :Welcome to the Accuracy "
                b"IRC Network alice\r\n"),
        ("cli", b"JOIN #accuracy\r\n"),
        ("srv", b":alice!alice@192.0.2.1 JOIN #accuracy\r\n"),
        ("cli", b"PRIVMSG #accuracy :hello\r\n")], {}),
    "acc_irc_negative": (6, 49469, 6667, True, [
        ("cli", b"hello, this stream is not an IRC registration\r\n"),
        ("srv", b"and this reply is not an IRC numeric\r\n")], {}),
    "acc_rtsp_positive": (6, 49470, 554, True, [
        ("cli", _text([b"OPTIONS rtsp://accuracy.example/stream RTSP/1.0",
                       b"CSeq: 1", b"User-Agent: accuracy/1.0", b""])),
        ("srv", _text([b"RTSP/1.0 200 OK", b"CSeq: 1",
                       b"Public: DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE",
                       b""]))], {}),
    "acc_rtsp_negative": (6, 49471, 554, True, [
        ("cli", b"hello, this stream is not an RTSP request\r\n"),
        ("srv", b"and this reply is not an RTSP response\r\n")], {}),
    "acc_unknown_mqtt_port": (6, 49473, 1883, True, [
        ("cli", b"hello, this stream is not an MQTT CONNECT packet\n"),
        ("srv", b"and this reply is not a CONNACK\n")], {}),
    "acc_sip_positive": (17, 5060, 5060, False, [
        ("cli", _sip_options()),
        ("srv", _sip_ok())], {}),
    "acc_sip_negative": (17, 49474, 5060, False, [
        ("cli", b"hello, this datagram is not a SIP request at all\r\n"),
        ("srv", b"and neither is this reply, despite the port\r\n")], {}),
    "acc_stun_positive": (17, 49451, 3478, False, [
        ("cli", _stun(0x0001, bytes(range(0x30, 0x3C)))),
        ("srv", _stun(0x0101, bytes(range(0x30, 0x3C)), _stun_xor_mapped()))],
        {}),
    "acc_stun_negative": (17, 49475, 3478, False, [
        ("cli", b"hello, this datagram is not a STUN binding request\n"),
        ("srv", b"and neither is this reply, despite the port\n")], {}),
    "acc_rtp_positive": (17, 16384, 16386, False, [
        (side, _rtp(seq, seq * 160, ssrc, fill))
        for seq in range(0x2a10, 0x2a14)
        for side, ssrc, fill in (("cli", 0x5ACC0001, 0xFF),
                                 ("srv", 0x5ACC0002, 0x7F))], {}),
    "acc_rtp_negative": (17, 16388, 16390, False, [
        ("cli", b"hello, this datagram is not an RTP packet at all\n"),
        ("srv", b"and neither is this reply on the media port pair\n")], {}),
    "acc_snmp_positive": (17, 49476, 161, False, [
        ("cli", _snmp(0xA0, 0x5ACC)),
        ("srv", _snmp(0xA2, 0x5ACC, b"accuracy test agent"))], {}),
    "acc_snmp_negative": (17, 49477, 161, False, [
        ("cli", b"hello, this datagram is not an SNMP GetRequest at all\n"),
        ("srv", b"and neither is this reply, despite the port\n")], {}),
    "acc_tftp_positive": (17, 49478, 49479, False, [
        ("srv", struct.pack("!HH", 3, 1) + b"accuracy corpus file\n"),
        ("cli", struct.pack("!HH", 4, 1))], {}),
    "acc_tftp_negative": (17, 49480, 69, False, [
        ("cli", b"hello, this datagram is not a TFTP request at all\n"),
        ("srv", b"and neither is this reply, despite the port\n")], {}),
    "acc_radius_positive": (17, 49481, 1812, False, [
        ("cli", _radius(1, 7, [(1, b"alice"), (2, b"\x00" * 16),
                               (4, ACC_CLIENT), (5, b"\x00\x00\x00\x01")])),
        ("srv", _radius(3, 7, [(18, b"denied")]))], {}),
    "acc_radius_negative": (17, 49482, 1812, False, [
        ("cli", b"hello, this datagram is not a RADIUS request at all\n"),
        ("srv", b"and neither is this reply, despite the port\n")], {}),
    "acc_gtp_positive": (17, 2123, 2123, False, [
        ("cli", _gtpv1_echo(1, 0x5ACC)),
        ("srv", _gtpv1_echo(2, 0x5ACC))], {}),
    "acc_gtp_negative": (17, 49483, 2152, False, [
        ("cli", b"hello, this datagram is not a GTP message at all\n"),
        ("srv", b"and neither is this reply, despite the port\n")], {}),
    "acc_mgcp_positive": (17, 2727, 2427, False, [
        ("cli", _text([b"AUEP 1201 aaln/1@gw.accuracy.example MGCP 1.0",
                       b"F: A"])),
        ("srv", _text([b"200 1201 OK", b"A: a:PCMU"]))], {}),
    "acc_mgcp_negative": (17, 49484, 2427, False, [
        ("cli", b"hello, this datagram is not an MGCP command at all\n"),
        ("srv", b"and neither is this reply, despite the port\n")], {}),
    "acc_ipp_positive": (17, 631, 631, False, [
        ("cli", b'1006 3 ipp://198.51.100.2:631/printers/accuracy '
                b'"Lab" "Accuracy printer" "Generic PostScript"\n')],
        {"server": BROADCAST, "server_mac": b"\xff" * 6}),
    "acc_ipp_negative": (17, 631, 631, False, [
        ("cli", b"hello, this datagram is not a printer browse packet\n")],
        {"server": BROADCAST, "server_mac": b"\xff" * 6}),
    "acc_usenet_positive": (6, 49500, 119, True, [
        ("srv", b"200 accuracy.example NNTP service ready, posting allowed\r\n"),
        ("cli", b"MODE READER\r\n"),
        ("srv", b"200 Reader mode, posting allowed\r\n"),
        ("cli", b"QUIT\r\n"),
        ("srv", b"205 Connection closing\r\n")], {}),
    "acc_usenet_negative": (6, 49501, 119, True, [
        ("cli", b"hello, this stream is not an NNTP request\n"),
        ("srv", b"and this reply is not an NNTP response\n")], {}),
    "acc_activesync_positive": (6, 49502, 80, True, [
        ("cli", _text([b"OPTIONS /Microsoft-Server-ActiveSync?User=alice"
                       b"&DeviceId=ACC0000000000001&DeviceType=SmartPhone "
                       b"HTTP/1.1",
                       b"Host: mail.accuracy.example",
                       b"User-Agent: accuracy/1.0",
                       b"Authorization: Basic YWxpY2U6c2VjcmV0",
                       b"Content-Length: 0", b""])),
        ("srv", _text([b"HTTP/1.1 200 OK",
                       b"MS-Server-ActiveSync: 16.1",
                       b"MS-ASProtocolVersions: 2.5,12.0,12.1,14.0,14.1,"
                       b"16.0,16.1",
                       b"MS-ASProtocolCommands: Sync,SendMail,SmartForward,"
                       b"SmartReply,GetAttachment,FolderSync,Ping",
                       b"Content-Length: 0", b""]))], {}),
    "acc_activesync_negative": (6, 49503, 80, True, [
        ("cli", b"hello, this stream is not an ActiveSync request\n"),
        ("srv", b"and this reply is not an ActiveSync response\n")], {}),
    "acc_icecast_positive": (6, 49504, 8000, True, [
        ("cli", _text([b"SOURCE /live.mp3 HTTP/1.0",
                       b"Authorization: Basic c291cmNlOmFjY3VyYWN5",
                       b"User-Agent: accuracy/1.0",
                       b"Content-Type: audio/mpeg",
                       b"ice-name: accuracy test stream",
                       b"ice-public: 0", b""])),
        ("srv", _text([b"HTTP/1.0 200 OK", b""]))], {}),
    "acc_icecast_negative": (6, 49505, 8000, True, [
        ("cli", b"hello, this stream is not an Icecast request\n"),
        ("srv", b"and this reply is not an Icecast response\n")], {}),
    "acc_shoutcast_positive": (6, 49506, 8001, True, [
        ("cli", b"123456\r\n"),
        ("srv", b"OK2\r\nicy-caps:11\r\n\r\n"),
        ("cli", _text([b"icy-name:accuracy test stream", b"icy-genre:test",
                       b"icy-pub:0", b"icy-br:128",
                       b"icy-url:http://radio.accuracy.example/",
                       b"content-type:audio/mpeg", b""]))], {}),
    "acc_shoutcast_negative": (6, 49507, 8001, True, [
        ("cli", b"hello, this stream is not a SHOUTcast request\n"),
        ("srv", b"and this reply is not a SHOUTcast response\n")], {}),
    "acc_ndn_http_positive": (17, 49508, 6363, False, [
        ("cli", _ndn_interest(_ndn_name(b"accuracy.example", b"GET",
                                        b"index.html"))),
        ("srv", _ndn_data(_ndn_name(b"accuracy.example", b"GET",
                                    b"index.html"), b"ok"))], {}),
    "acc_ndn_http_negative": (17, 49509, 6363, False, [
        ("cli", b"hello, this datagram is not an NDN Interest\n"),
        ("srv", b"and this reply is not an NDN Data packet\n")], {}),
    "acc_dcerpc_positive": (6, 49530, 135, True, [
        ("cli", _dce_bind()),
        ("srv", _dce_bind_ack())], {}),
    "acc_dcerpc_negative": (6, 49531, 135, True, [
        ("cli", b"hello, this stream is not a DCE/RPC bind request\n"),
        ("srv", b"and this reply is not a DCE/RPC bind_ack\n")], {}),
    "acc_afp_positive": (6, 49532, 548, True, [
        ("cli", _dsi_open_session(0x00, struct.pack("!BBI", 0x01, 4, 1024))),
        ("srv", _dsi_open_session(0x01, struct.pack("!BBI", 0x00, 4,
                                                     0x00100000)))], {}),
    "acc_afp_negative": (6, 49533, 548, True, [
        ("cli", b"hello, this stream is not a DSI OpenSession request\n"),
        ("srv", b"and this reply is not a DSI response\n")], {}),
    "acc_citrix_positive": (6, 49534, 1494, True, [
        ("srv", _ica_detect()),
        ("cli", _ica_detect())], {}),
    "acc_citrix_negative": (6, 49535, 1494, True, [
        ("cli", b"hello, this stream is not a Citrix ICA handshake\n"),
        ("srv", b"and this reply is not an ICA response\n")], {}),
    "acc_flash_positive": (6, 49536, 1935, True, [
        ("cli", _rtmp_c0c1()),
        ("srv", _rtmp_s0s1s2())], {}),
    "acc_flash_negative": (6, 49537, 1935, True, [
        ("cli", b"hello, this stream is not an RTMP handshake\n"),
        ("srv", b"and this reply is not an RTMP response\n")], {}),
    "acc_stun_tcp_positive": (6, 49560, 3478, True, [
        ("cli", _ice_check()),
        ("srv", _ice_check_ok(49560))], {}),
    "acc_stun_tcp_negative": (6, 49561, 3478, True, [
        ("cli", b"hello, this stream is not a STUN binding request\n"),
        ("srv", b"and this reply is not a STUN response\n")], {}),
    "acc_iax_positive": (17, 49564, 4569, False, [
        ("cli", _iax_new()),
        ("srv", _iax_accept())], {}),
    "acc_iax_negative": (17, 49565, 4569, False, [
        ("cli", b"hello, this datagram is not an IAX2 NEW frame\n"),
        ("srv", b"and neither is this reply, despite the port\n")], {}),
    "acc_eclipse_tcf_positive": (17, 49566, 1534, False, [
        ("cli", _tcf_udp(1)),
        ("srv", _tcf_peer_info())], {}),
    "acc_eclipse_tcf_negative": (17, 49567, 1534, False, [
        ("cli", b"hello, this datagram is not a TCF discovery packet\n"),
        ("srv", b"and neither is this reply, despite the port\n")], {}),
    "acc_mqtt_positive": (6, 49568, 1883, True, [
        ("cli", _mqtt_connect()),
        ("srv", b"\x20\x02\x00\x00"),          # CONNACK, return code 0
        ("cli", b"\xc0\x00"),                  # PINGREQ
        ("srv", b"\xd0\x00")], {}),            # PINGRESP
    "acc_mqtt_negative": (6, 49569, 1883, True, [
        ("cli", b"\x05\x01\x00"),              # SOCKS5 greeting, no-auth
        ("srv", b"\x05\x00")], {}),            # SOCKS5 method selection
    "acc_xdmcp_tcp_positive": (6, 49570, 6000, True, [
        ("cli", _x11_setup()),
        ("srv", _x11_setup_failed())], {}),
    "acc_xdmcp_tcp_negative": (6, 49571, 6000, True, [
        ("cli", b"hello, this stream is not an X11 connection setup\n"),
        ("srv", b"and this reply is not an X11 setup reply\n")], {}),
    "acc_xdmcp_udp_positive": (17, 49572, 177, False, [
        ("cli", _xdmcp(2, b"\x00")),
        ("srv", _xdmcp(5, _array8(b"") + _array8(b"accuracy.example")
                       + _array8(b"Linux 6.1")))], {}),
    "acc_xdmcp_udp_negative": (17, 49573, 177, False, [
        ("cli", b"hello, this datagram is not an XDMCP Query\n"),
        ("srv", b"and neither is this reply, despite the port\n")], {}),
    "acc_teamviewer_tcp_positive": (6, 49590, 5938, True, [
        ("cli", _teamviewer_cmd(0x12, b"\x00" * 4 + b"accuracy.example\x00")),
        ("srv", _teamviewer_cmd(0x12, b"\x00" * 8))], {}),
    "acc_teamviewer_tcp_negative": (6, 49591, 5938, True, [
        ("cli", b"hello, this stream is not a TeamViewer command\n"),
        ("srv", b"and this reply is not a TeamViewer response\n")], {}),
    "acc_teamviewer_udp_positive": (17, 49592, 5938, False, [
        ("cli", _teamviewer_udp(0, 0x12, b"\x00" * 4
                                + b"accuracy.example\x00")),
        ("srv", _teamviewer_udp(0, 0x12, b"\x00" * 8))], {}),
    "acc_teamviewer_udp_negative": (17, 49593, 5938, False, [
        ("cli", b"hello, this datagram is not a TeamViewer command\n"),
        ("srv", b"and neither is this reply, despite the port\n")], {}),
    "acc_steam_positive": (6, 49594, 27030, True, [
        ("cli", _steam_version(2)),
        ("srv", _steam_accept())], {}),
    "acc_steam_negative": (6, 49595, 27030, True, [
        ("cli", b"hello, this stream is not a Steam handshake\n"),
        ("srv", b"and this reply is not a Steam accept\n")], {}),
    "acc_worldofwarcraft_positive": (6, 49596, 3724, True, [
        ("cli", _wow_logon_challenge(b"ACCURACY")),
        ("srv", _wow_logon_challenge_reply())], {}),
    "acc_worldofwarcraft_negative": (6, 49597, 3724, True, [
        ("cli", b"hello, this stream is not a WoW logon challenge\n"),
        ("srv", b"and this reply is not a WoW logon response\n")], {}),
    "acc_xbox_positive": (17, 49598, 3074, False, [
        ("cli", _xbox_udp(0x02, 0x18)),
        ("srv", _xbox_udp(0x03, 0x40))], {}),
    "acc_xbox_negative": (17, 49599, 3074, False, [
        ("cli", b"hello, this datagram is not an Xbox Live packet\n"),
        ("srv", b"and neither is this reply, despite the port\n")], {}),
}


def _acc_classifier_gen(name):
    proto, cport, sport, handshake, exchange, extra = \
        ACC_CLASSIFIER_FLOWS[name]

    def gen(path):
        f = pcap_open(path)
        flow = _AccFlow(f, proto, cport, sport, **extra)
        if handshake:
            flow.handshake()
        for side, payload in exchange:
            flow.send(side, payload)
        f.close()
        print("wrote %s (accuracy: %s)" % (path, name))
    return gen


ACC_GENS = {
    "acc_dns_positive": gen_acc_dns_positive_pcap,
    "acc_dns_negative": gen_acc_dns_negative_pcap,
    "acc_tls_positive": gen_acc_tls_positive_pcap,
    "acc_tls_sni_attribution": gen_acc_tls_sni_attribution_pcap,
    "acc_tls_sni_teams": gen_acc_tls_sni_teams_pcap,
    "acc_tls_sni_sharepoint": gen_acc_tls_sni_sharepoint_pcap,
    "acc_tls_negative": gen_acc_tls_negative_pcap,
    "acc_quic_positive": gen_acc_quic_positive_pcap,
    "acc_quic_v2_positive": gen_acc_quic_v2_positive_pcap,
    "acc_quic_draft29_ambiguous": gen_acc_quic_draft29_ambiguous_pcap,
    "acc_http2_positive": gen_acc_http2_positive_pcap,
    "acc_http2_negative": gen_acc_http2_negative_pcap,
    "acc_unknown_udp": gen_acc_unknown_udp_pcap,
    "acc_unknown_tcp": gen_acc_unknown_tcp_pcap,
}
ACC_GENS.update((name, _acc_classifier_gen(name))
                for name in ACC_CLASSIFIER_FLOWS)


# --- abstention set (issue #527) --------------------------------------------
# Seeded random payloads swept over lengths, run by tools/phase0/ci/
# check_precision.sh: no capture carries an application protocol, so every
# packet should get no application verdict and the committed precision
# baseline records the share that does (the unknown rate). The bytes, ports
# and server addresses all derive from ABSTENTION_SEED through a SHA-256
# counter stream, so the set is identical on every host and Python version;
# changing the seed, the lengths or the flow count changes the baseline.
# Generated at gate time, never committed:
#   tools/phase0/gen_tcpip_pcap.py --out-dir DIR --abstention

ABSTENTION_SEED = b"mmt-dpi abstention set v1 (issue #527)"
ABSTENTION_LENGTHS = (1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 1400)
ABSTENTION_FLOWS = 8


def _seeded(label, n):
    """n bytes of the SHA-256 counter stream keyed by ABSTENTION_SEED."""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(ABSTENTION_SEED + b":" + label
                              + b":%d" % i).digest()
        i += 1
    return out[:n]


def _gen_abstention_pcap(path, proto, length):
    f = pcap_open(path)
    tag = b"%s:%d" % (b"tcp" if proto == 6 else b"udp", length)
    for k in range(ABSTENTION_FLOWS):
        r = _seeded(tag + b":flow%d" % k, 6)
        cport = 49152 + struct.unpack("!H", r[0:2])[0] % 16384
        sport = 1024 + struct.unpack("!H", r[2:4])[0] % 64512
        server = bytes([198, 51, 100, 1 + r[4] % 254])
        flow = _AccFlow(f, proto, cport, sport, ts_us=k * 1_000_000,
                        server=server)
        if proto == 6:
            flow.handshake()
        flow.send("cli", _seeded(tag + b":flow%d:cli" % k, length))
        flow.send("srv", _seeded(tag + b":flow%d:srv" % k, length))
    f.close()


ABSTENTION_GENS = {
    "abstain_%s_%04d" % (name, length):
        (lambda path, proto=proto, length=length:
         _gen_abstention_pcap(path, proto, length))
    for name, proto in (("tcp", 6), ("udp", 17))
    for length in ABSTENTION_LENGTHS
}


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
    "dtls": gen_dtls_pcap,
}


def main():
    ap = argparse.ArgumentParser(description="Generate TCP/IP synthetic pcaps (issue #143)")
    ap.add_argument("--out-dir", default="/tmp/tcpip-pcaps",
                    help="output directory (default: /tmp/tcpip-pcaps)")
    sel = ap.add_mutually_exclusive_group()
    sel.add_argument("--pcap", choices=list(GENS.keys()) + list(ACC_GENS.keys())
                     + list(ABSTENTION_GENS.keys()),
                     nargs="+", default=None,
                     help="generate only these pcap types")
    sel.add_argument("--accuracy", action="store_true",
                     help="generate every TCP/IP accuracy-corpus capture (issues #389, #390) "
                          "instead of the default harness set")
    sel.add_argument("--abstention", action="store_true",
                     help="generate the seeded random-payload abstention set "
                          "run by ci/check_precision.sh (issue #527)")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    gens = dict(GENS, **ACC_GENS, **ABSTENTION_GENS)
    if args.pcap:
        targets = args.pcap
    elif args.accuracy:
        targets = sorted(ACC_GENS.keys())
    elif args.abstention:
        targets = sorted(ABSTENTION_GENS.keys())
    else:
        targets = sorted(GENS.keys())
    for name in targets:
        out = os.path.join(args.out_dir, "%s.pcap" % name)
        gens[name](out)
    total = len(targets)
    print("done: %d pcap(s) under %s" % (total, args.out_dir))


if __name__ == "__main__":
    main()

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
"""
import argparse
import hashlib
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

    def __init__(self, f, proto, cport, sport, ts_us=0):
        self.f, self.proto = f, proto
        self.cport, self.sport = cport, sport
        self.seq = {"cli": 1000, "srv": 50000}
        self.ts_us = ts_us
        self.ident = 0

    def _l3l4(self, side, payload, flags):
        if side == "cli":
            smac, dmac = ACC_CLIENT_MAC, ACC_SERVER_MAC
            sip, dip, sp, dp = ACC_CLIENT, ACC_SERVER, self.cport, self.sport
        else:
            smac, dmac = ACC_SERVER_MAC, ACC_CLIENT_MAC
            sip, dip, sp, dp = ACC_SERVER, ACC_CLIENT, self.sport, self.cport
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


def gen_acc_quic_v2_ambiguous_pcap(path):
    """QUIC version 2 (RFC 9369, version 0x6b3343cf) Initial exchange on
    UDP/443. It is genuine QUIC, but the SDK only recognises version 1
    (TODO #333), so the expected handling is an abstention — ambiguous, not a
    false negative the gate should hide."""
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


ACC_GENS = {
    "acc_dns_positive": gen_acc_dns_positive_pcap,
    "acc_dns_negative": gen_acc_dns_negative_pcap,
    "acc_tls_positive": gen_acc_tls_positive_pcap,
    "acc_tls_sni_attribution": gen_acc_tls_sni_attribution_pcap,
    "acc_tls_negative": gen_acc_tls_negative_pcap,
    "acc_quic_positive": gen_acc_quic_positive_pcap,
    "acc_quic_v2_ambiguous": gen_acc_quic_v2_ambiguous_pcap,
    "acc_http2_positive": gen_acc_http2_positive_pcap,
    "acc_http2_negative": gen_acc_http2_negative_pcap,
    "acc_unknown_udp": gen_acc_unknown_udp_pcap,
    "acc_unknown_tcp": gen_acc_unknown_tcp_pcap,
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
    sel.add_argument("--pcap", choices=list(GENS.keys()) + list(ACC_GENS.keys()),
                     default=None, help="generate only this pcap type")
    sel.add_argument("--accuracy", action="store_true",
                     help="generate every TCP/IP accuracy-corpus capture (issues #389, #390) "
                          "instead of the default harness set")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    gens = dict(GENS, **ACC_GENS)
    if args.pcap:
        targets = [args.pcap]
    elif args.accuracy:
        targets = sorted(ACC_GENS.keys())
    else:
        targets = sorted(GENS.keys())
    for name in targets:
        out = os.path.join(args.out_dir, "%s.pcap" % name)
        gens[name](out)
    total = len(targets)
    print("done: %d pcap(s) under %s" % (total, args.out_dir))


if __name__ == "__main__":
    main()

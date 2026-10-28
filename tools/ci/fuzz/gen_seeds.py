#!/usr/bin/env python3
"""Generate the libFuzzer seed captures for tools/ci/fuzz/packet_fuzzer.c.

Issue #530 (F-TEST-013): one capture per dissector family the audit found
unfuzzed — SMB, NFS, IRC, IMAP, POP, SMTP and NetBIOS. No tracked capture
carries any of them, so each one is synthesised here: a classic
little-endian DLT_EN10MB pcap holding a short, well-formed exchange (TCP
handshake, then the protocol's opening lines in both directions, or one UDP
datagram) that the SDK classifies as that family. libFuzzer mutates from
these, so the dissector's own code is reached on the first iterations.

The output is byte-for-byte deterministic (fixed addresses, ports, sequence
numbers and timestamps; stdlib struct only), so the committed files can be
checked against this script: tools/ci/run-fuzz.sh --libfuzzer runs it with
--check and refuses to fuzz from seeds that drifted from it.

Usage:
    tools/ci/fuzz/gen_seeds.py [--out-dir DIR]   write <family>.pcap files
    tools/ci/fuzz/gen_seeds.py --check [--out-dir DIR]
        exit 0 when DIR holds exactly the generated files, byte for byte;
        exit 1 naming each missing, extra or differing file
    tools/ci/fuzz/gen_seeds.py --list            print "<family> <expected
        protocol>" lines (the protocol name the SDK must classify)
"""
import argparse
import os
import struct
import sys

DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seeds")

CLIENT_MAC = b"\x02\x00\x00\x00\x00\x01"
SERVER_MAC = b"\x02\x00\x00\x00\x00\x02"
CLIENT_IP = bytes([10, 0, 0, 1])
SERVER_IP = bytes([10, 0, 0, 2])

SYN, ACK, PSH = 0x02, 0x10, 0x08


def _ip(src, dst, proto, payload, ident):
    total = 20 + len(payload)
    # Header checksum left 0: the SDK's parsers do not verify it.
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000, 64,
                       proto, 0, src, dst) + payload


def _eth(src_mac, dst_mac, l3):
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + l3


def _pcap(packets):
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for i, pkt in enumerate(packets):
        ts_us = 1_000_000 + i * 1000
        out.append(struct.pack("<IIII", ts_us // 1_000_000, ts_us % 1_000_000,
                               len(pkt), len(pkt)))
        out.append(pkt)
    return b"".join(out)


def tcp_session(cport, sport, exchanges):
    """Handshake, then each (from_client, payload) segment with its ACK."""
    cseq, sseq = 1000, 5000
    ident = [0]
    packets = []

    def seg(from_client, flags, payload=b""):
        src, dst = (CLIENT_IP, SERVER_IP) if from_client else (SERVER_IP, CLIENT_IP)
        smac, dmac = (CLIENT_MAC, SERVER_MAC) if from_client else (SERVER_MAC, CLIENT_MAC)
        p_src, p_dst = (cport, sport) if from_client else (sport, cport)
        seq, ack = (cseq, sseq) if from_client else (sseq, cseq)
        tcp = struct.pack("!HHIIBBHHH", p_src, p_dst, seq, ack if flags & ACK else 0,
                          5 << 4, flags, 65535, 0, 0)
        ident[0] += 1
        packets.append(_eth(smac, dmac, _ip(src, dst, 6, tcp + payload, ident[0])))

    seg(True, SYN)
    cseq += 1
    seg(False, SYN | ACK)
    sseq += 1
    seg(True, ACK)
    for from_client, payload in exchanges:
        seg(from_client, PSH | ACK, payload)
        if from_client:
            cseq += len(payload)
        else:
            sseq += len(payload)
        seg(not from_client, ACK)
    return packets


def udp_datagram(cport, sport, payload):
    udp = struct.pack("!HHHH", cport, sport, 8 + len(payload), 0) + payload
    return [_eth(CLIENT_MAC, SERVER_MAC, _ip(CLIENT_IP, SERVER_IP, 17, udp, 1))]


def smb():
    # NetBIOS session message (type 0, 24-bit length) carrying an SMBv1
    # NEGOTIATE request (proto_smb.c: \xffSMB at payload[4], NBSS length ==
    # payload length - 4, payload > 40 bytes).
    dialects = b"\x02NT LM 0.12\x00"
    smb_hdr = (b"\xffSMB" + b"\x72" + b"\x00" * 4 + b"\x18" + b"\x01\x28"
               + b"\x00" * 12 + b"\xff\xfe" + b"\x00\x00" + b"\x00\x00"
               + b"\x01\x00")
    body = b"\x00" + struct.pack("<H", len(dialects)) + dialects
    msg = smb_hdr + body
    return tcp_session(49152, 445, [(True, struct.pack("!I", len(msg)) + msg)])


def nfs():
    # ONC RPC CALL over TCP (record mark, last fragment) to NFSv3 NULL
    # (proto_nfs.c: msgtype 0, rpcvers 2, program 100003, version <= 4).
    call = struct.pack("!IIIIII", 0x1234, 0, 2, 100003, 3, 0)
    call += struct.pack("!IIII", 0, 0, 0, 0)  # AUTH_NULL cred + verifier
    return tcp_session(800, 2049, [(True, struct.pack("!I", 0x80000000 | len(call)) + call)])


def irc():
    return tcp_session(49153, 6667, [
        (True, b"NICK alice\r\nUSER alice 0 * :Alice\r\n"),
        (False, b":irc.example.net 001 alice :Welcome to the network alice\r\n"),
    ])


def imap():
    return tcp_session(49154, 143, [
        (False, b"* OK [CAPABILITY IMAP4rev1] server ready\r\n"),
        (True, b"a001 CAPABILITY\r\n"),
        (False, b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\na001 OK done\r\n"),
        (True, b"a002 LOGIN alice secret\r\n"),
        (False, b"a002 OK LOGIN completed\r\n"),
    ])


def pop():
    return tcp_session(49155, 110, [
        (False, b"+OK POP3 server ready\r\n"),
        (True, b"USER alice\r\n"),
        (False, b"+OK\r\n"),
        (True, b"PASS secret\r\n"),
        (False, b"+OK maildrop has 0 messages\r\n"),
    ])


def smtp():
    return tcp_session(49156, 25, [
        (False, b"220 mail.example.net ESMTP ready\r\n"),
        (True, b"EHLO client.example.net\r\n"),
        (False, b"250-mail.example.net\r\n250 SIZE 10240000\r\n"),
        (True, b"MAIL FROM:<alice@example.net>\r\n"),
        (False, b"250 OK\r\n"),
    ])


def netbios():
    # NetBIOS name-service query (proto_netbios.c: udp/137, >= 50 bytes):
    # header + one question for the first-level-encoded name "WORKGROUP".
    name = b"WORKGROUP".ljust(15) + b"\x00"
    encoded = bytes([0x20]) + bytes(c for b in name
                                     for c in (0x41 + (b >> 4), 0x41 + (b & 0x0F))) + b"\x00"
    query = struct.pack("!HHHHHH", 0x4242, 0x0110, 1, 0, 0, 0) + encoded + struct.pack("!HH", 0x20, 1)
    return udp_datagram(137, 137, query)


# family -> (builder, protocol name the SDK reports for it)
FAMILIES = {
    "smb": (smb, "smb"),
    "nfs": (nfs, "nfs"),
    "irc": (irc, "irc"),
    "imap": (imap, "imap"),
    "pop": (pop, "pop"),
    "smtp": (smtp, "smtp"),
    "netbios": (netbios, "netbios"),
}


def generated():
    return {f"{name}.pcap": _pcap(build()) for name, (build, _) in FAMILIES.items()}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out-dir", default=DEFAULT_OUT)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list:
        for name, (_, proto) in FAMILIES.items():
            print(f"{name} {proto}")
        return 0

    files = generated()
    if args.check:
        problems = []
        present = set(os.listdir(args.out_dir)) if os.path.isdir(args.out_dir) else set()
        for fname, data in files.items():
            path = os.path.join(args.out_dir, fname)
            if fname not in present:
                problems.append(f"missing {fname}")
            else:
                with open(path, "rb") as f:
                    if f.read() != data:
                        problems.append(f"differs {fname}")
        for fname in sorted(present - set(files)):
            problems.append(f"unexpected {fname}")
        for p in problems:
            print(f"✗ seed {p} (regenerate: python3 {os.path.relpath(__file__)})", file=sys.stderr)
        return 1 if problems else 0

    os.makedirs(args.out_dir, exist_ok=True)
    for fname, data in files.items():
        with open(os.path.join(args.out_dir, fname), "wb") as f:
            f.write(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())

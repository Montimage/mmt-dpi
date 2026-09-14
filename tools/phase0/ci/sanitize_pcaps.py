#!/usr/bin/env python3
#
# sanitize_pcaps.py — scrub real credentials/identifiers out of the vendored
# phase0 CI captures (issue #214, F-SEC-014).
#
# Several captures under tools/phase0/ci/pcaps/ were recorded on a real
# Montimage test LAN and carry live data: FTP USER/PASS logins, the account's
# home-directory listing (usernames, a real name inside a test source file),
# and a BBC-UID tracking cookie issued by the real www.bbc.com. The scan
# allowlist exempted the whole directory, so nothing would have caught a new
# capture committed with real secrets.
#
# The substitutions below replace every such token with a synthetic identity
# of the SAME byte length, applied inside TCP payload bytes only. Keeping the
# length constant means TCP sequence/acknowledgement numbers still line up;
# IP/TCP checksums are recomputed afterwards so the files stay wire-valid.
# Nothing else in the captures (5-tuples, flags, timing, response text) is
# touched, and the phase0 classification fingerprint is unchanged — the
# classifier keys on protocol structure, not on credential values.
#
# Usage: python3 tools/phase0/ci/sanitize_pcaps.py [--check]
#   no args   rewrite the captures in place (idempotent)
#   --check   exit 1 if any real-identity token is still present (CI guard)

import sys

from scapy.all import IP, TCP, UDP, Raw, rdpcap, wrpcap

PCAP_DIR = "tools/phase0/ci/pcaps"

# {pcap name: [(real bytes, synthetic bytes), ...]} — order matters where one
# token is a prefix of another (percevio@ before percevio). Every pair is the
# same byte length.
SUBSTITUTIONS = {
    "ftp_login_fail.pcap": [
        (b"percevio", b"mmtuser1"),  # USER percevio  -> USER mmtuser1
        (b"montimage", b"testuser1"),
        (b"mmt-u14", b"test-u1"),
        (b"mmtbox", b"pw-001"),
        (b"280189", b"pw-002"),
    ],
    "ftp_multiple_session.pcap": [
        (b"mmt-u14", b"test-u1"),    # USER + "/home/mmt-u14" PWD/listing paths
        (b"280189", b"pw-002"),
        (b"luongnv89", b"devuser01"),            # real account name in listing
        (b"Nguyen Van Luong", b"MMT Test User   "),  # real name in testjson.c
    ],
    "ftp_txt.pcap": [
        (b"percevio@", b"noreply@x"),  # anonymous-login "password" email
    ],
    "tcp_bbc-out-of-order.pcap": [
        # BBC-UID=<65-char token> — a real tracking-cookie value issued by
        # www.bbc.com. Replaced with an obviously synthetic pattern.
        # (gitleaks:allow — this is the token being REMOVED, not a live secret)
        (b"a5155a36a1f87de510e2812271804f0fd38c2e5883081693fbabd4e3966911240",  # gitleaks:allow
         b"0" + b"0123456789abcdef" * 4),
    ],
}


def sanitize_file(path, subs, check_only):
    """Apply same-length substitutions inside packet payloads; recompute sums."""
    dirty = False
    for real, _synthetic in subs:
        if len(real) != len(_synthetic):
            raise ValueError(f"{path}: substitution length mismatch for {real!r}")
    with open(path, "rb") as fh:
        raw = fh.read()
    for real, _synthetic in subs:
        if real in raw:
            dirty = True
            if check_only:
                print(f"  still contains {real!r}: {path}")
    if check_only:
        return dirty
    if not dirty:
        print(f"  already clean: {path}")
        return False

    packets = rdpcap(path)
    for pkt in packets:
        if Raw not in pkt:
            continue
        payload = bytes(pkt[Raw].load)
        new_payload = payload
        for real, synthetic in subs:
            new_payload = new_payload.replace(real, synthetic)
        if new_payload == payload:
            continue
        pkt[Raw].load = new_payload
        # Force checksum/length recomputation on the modified layers. Same
        # length in/out keeps seq/ack numbering valid, so only the sums and
        # the UDP length field need a rebuild.
        if IP in pkt:
            del pkt[IP].len
            del pkt[IP].chksum
        if TCP in pkt:
            del pkt[TCP].chksum
        if UDP in pkt:
            del pkt[UDP].len
            del pkt[UDP].chksum
    wrpcap(path, packets)
    print(f"  sanitized: {path}")
    return True


def main():
    check_only = "--check" in sys.argv
    dirty = False
    for name, subs in SUBSTITUTIONS.items():
        dirty |= sanitize_file(f"{PCAP_DIR}/{name}", subs, check_only)
    if check_only:
        if dirty:
            print("FAIL: real-identity token(s) still present in CI captures")
            return 1
        print("OK: CI captures carry only synthetic identities")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())

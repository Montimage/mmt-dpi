# Phase-0 CI captures — provenance and sanitization record

Issue #214 (F-SEC-014) required every vendored capture that carried real
credentials or identifiers to be regenerated with synthetic identities, and
required this file to record where each capture came from. Captures are
exempted from the gitleaks scan **individually** in `.gitleaks.toml` — the
directory-wide exemption that used to cover this tree would have silently
allowed a future capture committed *with* real secrets.

## Provenance

| File | Origin | Content notes |
|------|--------|---------------|
| `arp_padding.pcap` | Montimage test LAN | ARP frames; padding-byte handling fixture. No credentials. |
| `ftp_login_fail.pcap` | Montimage test LAN | Real FTP login attempts captured on the LAN — carried live `USER`/`PASS` pairs. **Sanitized** (see below). |
| `ftp_multiple_session.pcap` | Montimage test LAN | Several real FTP sessions including a home-directory listing (account names, a real name inside a test source file). **Sanitized.** |
| `ftp_txt.pcap` | Montimage test LAN | Real FTP session carrying an email address as the anonymous-login password. **Sanitized.** |
| `ip_ping_local_ip_fragmentation.pcap` | Montimage test LAN | Synthetic ICMP fragmentation exercise. No credentials. |
| `ip_teardrop_overlaping_ip_fragments.pcap` | Montimage test LAN | Teardrop-style overlapping fragments. No credentials. |
| `tcp_bbc-out-of-order.pcap` | Montimage test LAN | Real out-of-order TCP stream against `www.bbc.com` — carried a live `BBC-UID` tracking-cookie value. **Sanitized.** |
| `tcp_ecn_sample.pcap` | Montimage test LAN | ECN flag fixture. No credentials. |
| `tcp_tpncp_tcp.pcap` | Montimage test LAN | TCP stream fixture. No credentials. |

`src/examples/google-fr.pcap` (outside this directory, covered by its own
allowlist line) is a real browsing capture from the same test LAN; it carries
no credentials and is left as recorded.

## Sanitization (issue #214)

`tools/phase0/ci/sanitize_pcaps.py` replaces every real identity token in the
captures above with a synthetic value of the **same byte length**, inside TCP
payloads only, then recomputes IP/UDP/TCP checksums. Same-length substitution
keeps the TCP sequence/acknowledgement arithmetic valid and leaves everything
else (5-tuples, flags, timing, response text) untouched, so the phase0
golden-pcap classification fingerprint is unchanged — the classifier keys on
protocol structure, not on credential values.

Run it to re-verify or re-apply:

```sh
python3 tools/phase0/ci/sanitize_pcaps.py           # rewrite in place (idempotent)
python3 tools/phase0/ci/sanitize_pcaps.py --check   # fail if a real token is still present
```

What was scrubbed (the real values are deliberately **not** repeated here —
they are the byte strings the script replaces):

| Capture | Category of real data removed | Replacement |
|---------|------------------------------|-------------|
| `ftp_login_fail.pcap` | Three FTP `USER` account names (a personal handle, an org name, a test-LAN account) and two `PASS` values | `mmtuser1`, `testuser1`, `test-u1`, `pw-001`, `pw-002` |
| `ftp_multiple_session.pcap` | A `USER` name plus its `/home/<user>` paths in the directory listing, a `PASS` value, a developer account name, and a real personal name inside a transferred test file (`testjson.c`) | `test-u1`, `pw-002`, `devuser01`, `MMT Test User   ` |
| `ftp_txt.pcap` | An email address sent as the anonymous-login password | `noreply@x` |
| `tcp_bbc-out-of-order.pcap` | A live 65-char `BBC-UID` tracking-cookie value issued by `www.bbc.com` | `0` + `0123456789abcdef`×4 |

## Adding a capture

1. Record its origin in the provenance table above.
2. If it was recorded on a live network, scrub identities first — extend
   `sanitize_pcaps.py` with a same-length substitution (do not shorten or
   renumber: TCP streams break).
3. Add the file **by name** to the `paths` allowlist in `.gitleaks.toml` —
   never widen the allowlist to a directory.

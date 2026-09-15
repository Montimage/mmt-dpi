/*
 * ext_attribution_test — unit test for the externally-updatable IP-range / port
 * attribution loaders (issue #26, M9) and their IPv6 + override extensions
 * (issue #74, M9 follow-up).
 *
 * M9 moves IP-range/port attribution out of the compiled-in tables and into
 * optional, operator-supplied data files. The compiled-in tables remain the
 * default/fallback, so with no data file the classification is byte-identical
 * to the baseline (that invariant is gated separately by the golden
 * classification fingerprint). This test pins down the loaders themselves:
 *
 *   mmt_tcpip_load_ip_ranges_file(path) — parse CIDR->proto rules into the IPv4
 *                                         AVL trees and the IPv6 range list,
 *                                         honouring the optional 'override' flag
 *   mmt_tcpip_load_port_map_file(path)  — parse "<tcp|udp> <port> <proto>
 *                                         [override]" rules
 *   _find_proto_id_by_address(src,dst)  — host-order IPv4 AVL lookup (override
 *                                         set first, then the extend/built-in)
 *   _find_proto_id_by_address6(src,dst) — 128-bit IPv6 longest-prefix lookup
 *
 * The loaders are exported (non-static) from libmmt_tcpip but live in an
 * internal header that is not installed, so they are re-declared here and the
 * test links libmmt_tcpip directly. A clean exit 0 with every CHECK passing is
 * the success condition.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"

/* Loaders / lookup under test — exported from libmmt_tcpip, declared in the
 * shared internal header (issue #186). */
#include "internal_decls.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, msg) do {                                         \
        g_checks++;                                                   \
        if (cond) {                                                   \
            printf("  PASS: %s\n", (msg));                            \
        } else {                                                      \
            printf("  FAIL: %s\n", (msg));                            \
            g_failures++;                                             \
        }                                                             \
    } while (0)

/* Write `content` to a unique temp file; returns a malloc'd path (caller frees). */
static char *write_tmp(const char *content)
{
    char *path = strdup("/tmp/mmt_ext_attr_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        free(path);
        return NULL;
    }
    FILE *fp = fdopen(fd, "w");
    fputs(content, fp);
    fclose(fp);
    return path;
}

/* 198.51.100.0/24 (TEST-NET-2, RFC 5737) and 203.0.113.0/24 (TEST-NET-3) are
 * reserved-for-documentation ranges that never appear in the bundled table. */
#define TESTNET2_HOST 0xC6336405u   /* 198.51.100.5 in host byte order */
#define TESTNET3_HOST 0xCB007105u   /* 203.0.113.5   in host byte order */

static void test_ip_ranges(void)
{
    printf("[1] external IP-range loading\n");

    uint32_t http_id = get_protocol_id_by_name("HTTP");
    CHECK(http_id != 0, "HTTP protocol id resolves (registry initialised)");

    /* The documentation ranges are unknown before any file is loaded. */
    CHECK(_find_proto_id_by_address(TESTNET2_HOST, 0) == -1,
          "198.51.100.5 unknown before loading (built-in fallback only)");

    /* A non-existent file is reported as an error, not a silent success. */
    CHECK(mmt_tcpip_load_ip_ranges_file("/no/such/mmt/ranges.txt") == -1,
          "missing IP-range file returns -1");

    /* A file with comments, blanks and malformed lines loads only the valid
     * rule and reports the exact count. */
    char *f1 = write_tmp(
        "# M9 external IP ranges (issue #26)\n"
        "\n"
        "198.51.100.0/24   HTTP\n"
        "999.1.2.3/24      HTTP        # invalid address -> skipped\n"
        "203.0.113.0/40    HTTP        # prefix out of range -> skipped\n"
        "203.0.113.0/24    NOSUCHPROTO # unknown protocol -> skipped\n"
        "10.0.0.0          HTTP        # missing /prefix -> skipped\n");
    CHECK(f1 != NULL, "temp IP-range file created");
    int n1 = mmt_tcpip_load_ip_ranges_file(f1);
    CHECK(n1 == 1, "exactly one valid IP-range rule loaded (others skipped)");

    /* The loaded /24 now resolves to HTTP for an address inside it ... */
    CHECK((uint32_t) _find_proto_id_by_address(TESTNET2_HOST, 0) == http_id,
          "198.51.100.5 now attributed to HTTP via the loaded range");
    /* ... and also when it appears as the destination address. */
    CHECK((uint32_t) _find_proto_id_by_address(0, TESTNET2_HOST) == http_id,
          "loaded range also matches on the destination address");
    /* An address outside the loaded range is still unknown. */
    CHECK(_find_proto_id_by_address(TESTNET3_HOST, 0) == -1,
          "203.0.113.5 (not loaded) stays unknown");

    /* A bare numeric protocol id is accepted as a fallback token. */
    char numbuf[64];
    snprintf(numbuf, sizeof(numbuf), "203.0.113.0/24 %u\n", http_id);
    char *f2 = write_tmp(numbuf);
    int n2 = mmt_tcpip_load_ip_ranges_file(f2);
    CHECK(n2 == 1, "numeric protocol-id token accepted");
    CHECK((uint32_t) _find_proto_id_by_address(TESTNET3_HOST, 0) == http_id,
          "203.0.113.5 attributed via numeric proto-id rule");

    if (f1) { unlink(f1); free(f1); }
    if (f2) { unlink(f2); free(f2); }
}

/* M9 (issue #74): operator override rules win over the compiled-in table and
 * over plain "extend" rules at the same CIDR. We can demonstrate this without
 * depending on any specific built-in entry by loading an extend rule and an
 * override rule for the same documentation range and observing the override. */
static void test_ipv4_override(void)
{
    printf("[3] IPv4 override semantics (issue #74)\n");

    uint32_t http_id = get_protocol_id_by_name("HTTP");
    uint32_t ssl_id  = get_protocol_id_by_name("SSL");
    CHECK(http_id != 0 && ssl_id != 0 && http_id != ssl_id,
          "HTTP and SSL ids resolve and differ");

    /* 192.0.2.0/24 is TEST-NET-1 (RFC 5737), never in the bundled table. */
    const uint32_t TESTNET1_HOST = 0xC0000205u; /* 192.0.2.5 host order */

    char *f = write_tmp(
        "192.0.2.0/24 HTTP            # extend rule\n"
        "192.0.2.0/24 SSL  override   # override wins over the extend rule\n");
    CHECK(f != NULL, "temp override file created");
    int n = mmt_tcpip_load_ip_ranges_file(f);
    CHECK(n == 2, "both the extend and the override rule loaded");
    CHECK((uint32_t) _find_proto_id_by_address(TESTNET1_HOST, 0) == ssl_id,
          "override rule (SSL) wins over the same-CIDR extend rule (HTTP)");

    if (f) { unlink(f); free(f); }

    /* Two rules for the SAME prefix+network in the SAME class must not corrupt
     * the AVL tree (the duplicate-key insert path); last rule wins. */
    char *f2 = write_tmp(
        "203.0.113.0/24 HTTP   # first\n"
        "203.0.113.0/24 SSL    # same CIDR, same class -> last wins\n");
    const uint32_t TESTNET3_HOST2 = 0xCB007107u; /* 203.0.113.7 host order */
    int n2 = mmt_tcpip_load_ip_ranges_file(f2);
    CHECK(n2 == 2, "both same-CIDR extend rules accepted");
    CHECK((uint32_t) _find_proto_id_by_address(TESTNET3_HOST2, 0) == ssl_id,
          "duplicate same-CIDR rule resolves to the last rule (no corruption)");
    if (f2) { unlink(f2); free(f2); }

    /* Contract (docs/External-Attribution.md): an *extend* rule must NOT displace
     * a compiled-in entry at the same prefix+network — only `override` may. This
     * needs a real built-in /24; 1.201.0.0/24 is a bundled entry. The check is
     * self-validating: if the table changes so this is no longer a built-in
     * (or already maps to HTTP), the precondition CHECK below fails loudly. */
    const uint32_t BUILTIN_24_HOST = 0x01C90001u; /* 1.201.0.1 host order */
    int builtin_id = _find_proto_id_by_address(BUILTIN_24_HOST, 0);
    CHECK(builtin_id != -1 && (uint32_t) builtin_id != http_id,
          "precondition: 1.201.0.0/24 is a built-in entry distinct from HTTP");

    char *f3 = write_tmp(
        "1.201.0.0/24 HTTP   # extend rule colliding with a built-in /24\n");
    int n3 = mmt_tcpip_load_ip_ranges_file(f3);
    CHECK(n3 == 1, "same-CIDR-as-built-in extend rule accepted (as a no-op)");
    CHECK(_find_proto_id_by_address(BUILTIN_24_HOST, 0) == builtin_id,
          "extend rule does NOT displace the built-in attribution");
    if (f3) { unlink(f3); free(f3); }

    /* The same CIDR tagged `override` DOES replace the built-in mapping. */
    char *f4 = write_tmp(
        "1.201.0.0/24 HTTP   override   # override replaces the built-in\n");
    int n4 = mmt_tcpip_load_ip_ranges_file(f4);
    CHECK(n4 == 1, "same-CIDR-as-built-in override rule loaded");
    CHECK((uint32_t) _find_proto_id_by_address(BUILTIN_24_HOST, 0) == http_id,
          "override rule replaces the built-in attribution (HTTP wins)");
    if (f4) { unlink(f4); free(f4); }
}

/* M9 (issue #74): externally-loaded IPv6 ranges (there is no compiled-in IPv6
 * table, so these are the whole IPv6 attribution path). */
static void test_ipv6_ranges(void)
{
    printf("[4] IPv6 external range loading (issue #74)\n");

    uint32_t http_id = get_protocol_id_by_name("HTTP");
    uint32_t ssl_id  = get_protocol_id_by_name("SSL");

    /* 2001:db8::/32 is the RFC 3849 documentation prefix. */
    uint8_t in_range[16]  = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    uint8_t out_range[16] = {0x20,0x01,0x0d,0xb9,0,0,0,0,0,0,0,0,0,0,0,1};

    CHECK(_find_proto_id_by_address6(in_range, out_range) == -1,
          "2001:db8::1 unknown before loading any IPv6 range");

    char *f = write_tmp(
        "2001:db8::/32      HTTP            # IPv6 extend rule\n"
        "2001:db8:1::/48    SSL             # more-specific extend rule\n"
        "bad:address/64     HTTP            # invalid IPv6 -> skipped\n"
        "2001:db8::/200     HTTP            # prefix out of range -> skipped\n");
    CHECK(f != NULL, "temp IPv6 range file created");
    int n = mmt_tcpip_load_ip_ranges_file(f);
    CHECK(n == 2, "exactly two valid IPv6 rules loaded (others skipped)");

    CHECK((uint32_t) _find_proto_id_by_address6(in_range, out_range) == http_id,
          "2001:db8::1 attributed to HTTP via the /32 range");
    /* Also matches when the in-range address is the destination. */
    CHECK((uint32_t) _find_proto_id_by_address6(out_range, in_range) == http_id,
          "IPv6 range also matches on the destination address");
    CHECK(_find_proto_id_by_address6(out_range, out_range) == -1,
          "address outside every loaded IPv6 range stays unknown");

    /* Longest-prefix-first: an address inside the /48 resolves to SSL. */
    uint8_t in_48[16] = {0x20,0x01,0x0d,0xb8,0,0x01,0,0,0,0,0,0,0,0,0,1};
    CHECK((uint32_t) _find_proto_id_by_address6(in_48, out_range) == ssl_id,
          "more-specific /48 IPv6 rule wins over the broader /32");

    if (f) { unlink(f); free(f); }

    /* An IPv6 override rule wins over an extend rule regardless of prefix. */
    char *fo = write_tmp(
        "2001:db8:2::/48    HTTP                 # extend\n"
        "2001:db8::/32      SSL        override  # override wins over extend\n");
    int no = mmt_tcpip_load_ip_ranges_file(fo);
    CHECK(no == 2, "IPv6 extend + override rules loaded");
    uint8_t in_48b[16] = {0x20,0x01,0x0d,0xb8,0,0x02,0,0,0,0,0,0,0,0,0,1};
    CHECK((uint32_t) _find_proto_id_by_address6(in_48b, out_range) == ssl_id,
          "IPv6 override (/32 SSL) wins over the more-specific /48 extend (HTTP)");
    if (fo) { unlink(fo); free(fo); }
}

/* Issue #212 (F-BUG-028): NETMASK_MAX_NB was 31, so external IPv4 /31 and /32
 * attribution rules were rejected while IPv6 accepted up to /128. They must
 * now load and match by longest-prefix, while /0 and /33 stay rejected. */
static void test_host_bit_prefixes(void)
{
    printf("[5] IPv4 /31 and /32 external rules (issue #212)\n");

    uint32_t dns_id  = get_protocol_id_by_name("DNS");
    uint32_t http_id = get_protocol_id_by_name("HTTP");
    CHECK(dns_id != 0 && http_id != 0 && dns_id != http_id,
          "DNS and HTTP protocol ids resolve and differ");

    /* 198.51.100.0/24 extend->HTTP was loaded by test_ip_ranges(); the /32 and
     * /31 rules below are more specific and must win by longest-prefix. */
    char *f = write_tmp(
        "198.51.100.250/32  DNS    # host route\n"
        "198.51.100.252/31  DNS    # pair route\n"
        "198.51.100.0/33    DNS    # out of range -> skipped\n"
        "198.51.100.0/0     DNS    # catch-all rejected -> skipped\n");
    CHECK(f != NULL, "temp host-prefix file created");
    int n = mmt_tcpip_load_ip_ranges_file(f);
    CHECK(n == 2, "/32 and /31 rules loaded; /33 and /0 skipped");

    CHECK((uint32_t) _find_proto_id_by_address(0xC63364FAu, 0) == dns_id,
          "198.51.100.250 attributed via the /32 host route");
    CHECK((uint32_t) _find_proto_id_by_address(0xC63364FCu, 0) == dns_id &&
          (uint32_t) _find_proto_id_by_address(0xC63364FDu, 0) == dns_id,
          "198.51.100.252 and .253 attributed via the /31 pair route");
    CHECK((uint32_t) _find_proto_id_by_address(0xC63364FEu, 0) == http_id,
          "198.51.100.254 (outside /31) still resolved by the broader /24");
    CHECK((uint32_t) _find_proto_id_by_address(TESTNET2_HOST, 0) == http_id,
          "198.51.100.5 still resolved by the broader /24 rule");

    if (f) { unlink(f); free(f); }
}

static void test_port_map(void)
{
    printf("[2] external port-map loading\n");

    CHECK(mmt_tcpip_load_port_map_file("/no/such/mmt/ports.txt") == -1,
          "missing port-map file returns -1");

    char *f = write_tmp(
        "# M9 external port hints (issue #26 / #74)\n"
        "tcp 9999 HTTP\n"
        "udp 8888 DNS\n"
        "tcp 443  SSL  override   # override hint (issue #74)\n"
        "sctp 1 HTTP    # unsupported L4 -> skipped\n"
        "tcp 70000 HTTP # port out of range -> skipped\n"
        "tcp 1234 NOPE  # unknown protocol -> skipped\n"
        "garbage line\n");
    CHECK(f != NULL, "temp port-map file created");
    int n = mmt_tcpip_load_port_map_file(f);
    CHECK(n == 3, "two extend + one override port rule loaded (others skipped)");

    if (f) { unlink(f); free(f); }
}

int main(void)
{
    printf("== ext_attribution_test (issue #26) ==\n");

    /* init_extraction() loads the protocol plugins and registers every tcpip
     * protocol, so the loaders can resolve protocol names via
     * get_protocol_id_by_name(). It must run from the install prefix so the
     * SDK's CWD-relative "plugins/" lookup resolves (see the runner script). */
    if (!init_extraction()) {
        fprintf(stderr, "init_extraction failed\n");
        return 2;
    }

    test_ip_ranges();
    test_ipv4_override();
    test_ipv6_ranges();
    test_port_map();
    test_host_bit_prefixes();

    close_extraction();

    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    if (g_failures) {
        printf("RESULT: FAIL (%d failure(s))\n", g_failures);
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}

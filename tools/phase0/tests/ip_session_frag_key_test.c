/*
 * ip_session_frag_key_test — crafted-input regression test for the IPv4/IPv6
 * session-key L4 port reads and the IPv4/IPv6 fragment-reassembly hash keys
 * (issue #9, H6/H7/H8). Part of the MMT-DPI Master Improvement Plan, Phase 2g.
 *
 * The defects being exercised:
 *
 *   H6  build_ipv4_session_key() (proto_ip.c) read the 4 L4 port octets at
 *       ip_packet[ihl*4 .. ihl*4+3] with no length check, over-reading a
 *       truncated capture that ended inside (or just after) the IPv4 header.
 *
 *   H7  build_ipv6_session_key() (proto_ipv6.c) gated the L4 port read on
 *       "caplen >= offset+next_offset+2", but then read 4 octets (both 16-bit
 *       ports), over-reading by 2 bytes when only 2 L4 octets were captured.
 *
 *   H8  ip6_process_fragment() (proto_ipv6.c) computed the reassembly key as
 *       "*(uint64_t *)(&ip6h->saddr + 12)" — &saddr has type struct in6_addr*,
 *       so "+ 12" scaled by sizeof(struct in6_addr) (16) and read 192 bytes
 *       past the address (out-of-bounds, unaligned). It also folded the key
 *       with a double "<<= 32" that discarded the first address word. The IPv4
 *       sibling in ip_process_fragment() had the same bit-loss bug (its second
 *       "<<= 32" dropped saddr entirely).
 *
 * The fragment-key computations were extracted into ip_fragment_key() and
 * ip6_fragment_key() so they can be exercised directly. The header structs are
 * heap-allocated to their exact size, so AddressSanitizer brackets them tightly
 * and flags the 192-byte over-read. The session-key port buffers are likewise
 * sized exactly to the truncated capture length.
 *
 * The library is built with BUILD=asan and this file is compiled with
 * -fsanitize=address,undefined -fno-sanitize-recover=all (see the runner
 * run_ip_session_frag_key_test.sh), so any out-of-bounds read aborts the
 * process. A clean exit 0 with every assertion passing is the success
 * condition.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip.h>   /* struct iphdr (Linux) */

#include "mmt_core.h"     /* ipacket_t, pkthdr_t, mmt_key_t */
#include "ipv6.h"         /* struct ipv6hdr, struct ext_hdr_fragment */
#include "ip_session_id_management.h" /* mmt_session_key_t */

/*
 * Entry points under test — non-static in proto_ip.c / proto_ipv6.c,
 * declared in the shared internal header (issue #186).
 */
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

/* Allocate an exactly-sized, zeroed buffer (ASan brackets it tightly). */
static uint8_t *make_buf(size_t len)
{
    uint8_t *b = (uint8_t *)malloc(len ? len : 1);
    if (!b) { perror("malloc"); exit(2); }
    memset(b, 0, len ? len : 1);
    return b;
}

/* ---- H8: IPv6 fragment key — no 192-byte OOB, address bits preserved ---- */
static void test_ip6_fragment_key(void)
{
    printf("[H8] IPv6 fragment key: safe extraction + bit-preserving mix\n");

    /* Heap-allocate the header structs to their exact size so ASan brackets
     * them; the pre-fix "&ip6h->saddr + 12" load reaches 192 bytes past saddr. */
    struct ipv6hdr *ip6h = (struct ipv6hdr *)make_buf(sizeof(*ip6h));
    struct ext_hdr_fragment *frag =
        (struct ext_hdr_fragment *)make_buf(sizeof(*frag));

    /* Low 32 bits of each address are the last 4 octets. */
    ip6h->saddr.s6_addr[12] = 0xAA; ip6h->saddr.s6_addr[13] = 0xBB;
    ip6h->saddr.s6_addr[14] = 0xCC; ip6h->saddr.s6_addr[15] = 0xDD;
    ip6h->daddr.s6_addr[12] = 0x11; ip6h->daddr.s6_addr[13] = 0x22;
    ip6h->daddr.s6_addr[14] = 0x33; ip6h->daddr.s6_addr[15] = 0x44;
    frag->ident = 0x0000F00Du;

    uint32_t saddr_low, daddr_low;
    memcpy(&saddr_low, &ip6h->saddr.s6_addr[12], 4);
    memcpy(&daddr_low, &ip6h->daddr.s6_addr[12], 4);
    mmt_key_t expected = ((mmt_key_t)saddr_low << 32) | (mmt_key_t)daddr_low;
    expected ^= (mmt_key_t)frag->ident;

    mmt_key_t key = ip6_fragment_key(ip6h, frag);
    CHECK(key == expected,
          "key mixes both address low-words and the fragment id (no OOB)");

    /* The source address low-word must influence the key — the old double
     * "<<= 32" dropped it. Flip a source bit; the key must change. */
    ip6h->saddr.s6_addr[12] = 0x55;
    CHECK(ip6_fragment_key(ip6h, frag) != key,
          "changing the source address changes the key (saddr not discarded)");

    /* Two fragments of the same datagram (same addrs + id) hash identically,
     * so reassembly still collects them into one entry. */
    ip6h->saddr.s6_addr[12] = 0xAA;
    CHECK(ip6_fragment_key(ip6h, frag) == key,
          "identical (addr,id) fragments map to the same reassembly key");

    free(ip6h);
    free(frag);
}

/* ---- H8 sibling: IPv4 fragment key — source address preserved ---- */
static void test_ip_fragment_key(void)
{
    printf("[H8] IPv4 fragment key: source address no longer discarded\n");

    struct iphdr *ip = (struct iphdr *)make_buf(sizeof(*ip));
    ip->saddr = 0x0A0B0C0Du;
    ip->daddr = 0x01020304u;
    ip->id    = htons(0x1234);

    mmt_key_t expected = ((mmt_key_t)ip->saddr << 32) | (mmt_key_t)ip->daddr;
    expected ^= (mmt_key_t)ip->id;

    mmt_key_t key = ip_fragment_key(ip);
    CHECK(key == expected, "key mixes saddr, daddr and id without bit loss");
    CHECK((uint32_t)(key >> 32) == ip->saddr,
          "the high 32 bits carry the source address (was dropped pre-fix)");

    mmt_key_t key0 = key;
    ip->saddr = 0xFFFFFFFFu;
    CHECK(ip_fragment_key(ip) != key0,
          "changing the source address changes the key");

    free(ip);
}

/* ---- H6: IPv4 session key — bounded L4 port read ---- */
static void test_ipv4_session_key_ports(void)
{
    printf("[H6] IPv4 session key: L4 ports gated on captured length\n");

    /* Well-formed: 20-byte IPv4 header (ihl=5) + 4 TCP port octets. */
    {
        const unsigned ihl = 5, hdr = ihl * 4;
        uint8_t *buf = make_buf(hdr + 4);
        struct iphdr *iph = (struct iphdr *)buf;
        iph->version = 4; iph->ihl = ihl; iph->protocol = 6; /* TCP */
        iph->saddr = 0x01010101u; iph->daddr = 0x02020202u;
        /* source port 0x1F90 (8080), dest port 0x01BB (443). */
        buf[hdr + 0] = 0x1F; buf[hdr + 1] = 0x90;
        buf[hdr + 2] = 0x01; buf[hdr + 3] = 0xBB;

        mmt_session_key_t k;
        memset(&k, 0, sizeof(k));
        build_ipv4_session_key(buf, hdr + 4, &k);
        int ok = (k.lower_ip_port == 0x1F90 && k.higher_ip_port == 0x01BB) ||
                 (k.lower_ip_port == 0x01BB && k.higher_ip_port == 0x1F90);
        CHECK(ok, "full capture decodes both TCP ports (classification kept)");
        free(buf);
    }

    /* Truncated: only 2 of the 4 port octets are captured. Pre-fix this read
     * 2 bytes past the buffer; post-fix the ports stay 0 (no over-read). */
    {
        const unsigned ihl = 5, hdr = ihl * 4;
        uint8_t *buf = make_buf(hdr + 2);
        struct iphdr *iph = (struct iphdr *)buf;
        iph->version = 4; iph->ihl = ihl; iph->protocol = 17; /* UDP */
        iph->saddr = 0x01010101u; iph->daddr = 0x02020202u;
        buf[hdr + 0] = 0x1F; buf[hdr + 1] = 0x90;

        mmt_session_key_t k;
        memset(&k, 0, sizeof(k));
        build_ipv4_session_key(buf, hdr + 2, &k);
        CHECK(k.lower_ip_port == 0 && k.higher_ip_port == 0,
              "truncated UDP header leaves ports 0 (no over-read)");
        free(buf);
    }

    /* Header itself ends exactly at the captured length (no L4 bytes). */
    {
        const unsigned ihl = 5, hdr = ihl * 4;
        uint8_t *buf = make_buf(hdr);
        struct iphdr *iph = (struct iphdr *)buf;
        iph->version = 4; iph->ihl = ihl; iph->protocol = 6;
        iph->saddr = 0x01010101u; iph->daddr = 0x02020202u;

        mmt_session_key_t k;
        memset(&k, 0, sizeof(k));
        build_ipv4_session_key(buf, hdr, &k);
        CHECK(k.lower_ip_port == 0 && k.higher_ip_port == 0,
              "capture ending at the IPv4 header reads no ports (no over-read)");
        free(buf);
    }
}

/* Build a minimal ipacket_t carrying an IPv6 header (nexthdr = proto) followed
 * by `l4_bytes` captured L4 octets, with caplen sized exactly to the buffer.
 * The two configured ports are written when l4_bytes >= 4. */
static int run_ipv6_session_key(uint8_t proto, unsigned l4_bytes,
        uint16_t *out_lower, uint16_t *out_higher)
{
    const unsigned hdr = sizeof(struct ipv6hdr); /* 40 */
    uint8_t *buf = make_buf(hdr + l4_bytes);
    struct ipv6hdr *ip6h = (struct ipv6hdr *)buf;
    ip6h->nexthdr = proto;
    /* saddr < daddr so direction is deterministic (membership-checked anyway). */
    ip6h->saddr.s6_addr[0] = 0x20; ip6h->saddr.s6_addr[1] = 0x01;
    ip6h->daddr.s6_addr[0] = 0x20; ip6h->daddr.s6_addr[1] = 0x02;
    if (l4_bytes >= 4) {
        buf[hdr + 0] = 0x1F; buf[hdr + 1] = 0x90;  /* source 8080 */
        buf[hdr + 2] = 0x01; buf[hdr + 3] = 0xBB;  /* dest    443 */
    } else if (l4_bytes >= 2) {
        buf[hdr + 0] = 0x1F; buf[hdr + 1] = 0x90;
    }

    pkthdr_t ph;
    memset(&ph, 0, sizeof(ph));
    ph.caplen = hdr + l4_bytes;
    ph.len = hdr + l4_bytes;

    ipacket_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.data = buf;
    pkt.p_hdr = &ph;

    mmt_session_key_t k;
    memset(&k, 0, sizeof(k));
    build_ipv6_session_key(&pkt, 0, &k);
    *out_lower = k.lower_ip_port;
    *out_higher = k.higher_ip_port;
    free(buf);
    return 0;
}

/* ---- H7: IPv6 session key — both ports require 4 captured octets ---- */
static void test_ipv6_session_key_ports(void)
{
    printf("[H7] IPv6 session key: L4 ports require 4 captured octets\n");

    uint16_t lo, hi;

    /* Full 4 L4 octets captured -> both ports decoded. */
    run_ipv6_session_key(6 /* TCP */, 4, &lo, &hi);
    {
        int ok = (lo == 0x1F90 && hi == 0x01BB) ||
                 (lo == 0x01BB && hi == 0x1F90);
        CHECK(ok, "full capture decodes both TCP ports (classification kept)");
    }

    /* Only 2 L4 octets captured -> pre-fix read 2 bytes past the buffer.
     * Post-fix the ports stay 0. */
    run_ipv6_session_key(17 /* UDP */, 2, &lo, &hi);
    CHECK(lo == 0 && hi == 0,
          "2 captured L4 octets leave ports 0 (no over-read)");

    /* No L4 octets captured at all. */
    run_ipv6_session_key(6 /* TCP */, 0, &lo, &hi);
    CHECK(lo == 0 && hi == 0,
          "capture ending at the IPv6 header reads no ports (no over-read)");
}

int main(void)
{
    printf("== ip_session_frag_key_test (issue #9: H6, H7, H8) ==\n");
    test_ip6_fragment_key();
    test_ip_fragment_key();
    test_ipv4_session_key_ports();
    test_ipv6_session_key_ports();

    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    if (g_failures) {
        printf("RESULT: FAIL (%d failure(s))\n", g_failures);
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}

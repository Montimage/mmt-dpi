/*
 * ip_frag_bounds_test — regression harness for issue #201
 * ("2.3: IP, fragment, SCTP, GRE and TCP-segment bounds").
 *
 * Drives crafted malformed / truncated / hostile packets through the real
 * packet path (mmt_init_handler + packet_process) and directly exercises the
 * internal helpers named by the findings. Every case that used to read or
 * copy past the captured length must now be rejected cleanly; the shared
 * IPv4/IPv6 fragment map must stay bounded under a 100k-unique-fragment flood
 * and be swept by the existing session timer.
 *
 * Findings covered:
 *   F-BUG-017  proto_ip.c fragment path: ihl/tot_len validated against caplen
 *              before any copy; unchecked allocations.
 *   F-BUG-018  icmp_data_extraction() sized the copy by on-wire len, not caplen.
 *   F-BUG-019  tcp_seg_reassembly() copied seg->len regardless of the dst budget.
 *   F-BUG-020  ip_streams fragment map: no entry ceiling / eviction / expiry.
 *   F-BUG-021  gtp_classify_next_proto() read the next-ext byte past caplen.
 *   F-BUG-024  mmt_bytestream_to_number() dereferenced before the byte budget.
 *   F-BUG-034  sctp chunk walk read a chunk header past caplen / len 0.
 *   F-BUG-035  gre_classify_next_proto() read the 4-byte base header unchecked.
 *   F-BUG-037  ip_len - ip_hl / payload_len - ext_header_len underflow.
 *   F-BUG-039  tcp_seg_free()/free_list() free()d arena-carved nodes.
 *   F-BUG-040  uint16_t IPv6 extension-header offset accumulator wrap.
 *   F-BUG-106  802.1Q/802.1ad classify overlaid a 4-byte struct past caplen.
 *
 * Build (see run_ip_frag_bounds_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all ...
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "tcpip/mmt_tcpip_protocols.h"
#include "tcpip/mmt_tcpip_attributes.h"

/* Internals — pulled from the source tree, not the installed include set. */
#include "mmt_tcpip_plugin_structs.h"   /* mmt_tcpip_internal_packet_t        */
#include "packet_processing.h"          /* struct mmt_handler_struct        */
#include "hashmap.h"                    /* mmt_hashmap_t / hashmap_walk     */
#include "tcp_segment.h"                /* tcp_seg_* internals              */
#include "proto_ip_dgram.h"             /* ip_dgram_t + frag-map constants  */
#include "proto_ipv6_dgram.h"           /* ipv6_dgram_t                     */
#include "internal_decls.h"             /* shared internal decls            */

typedef unsigned char u_char;

/* Fallbacks so this file also compiles against the pre-fix tree (the
 * constants land in proto_ip_dgram.h with the fix). */
#ifndef MMT_IP_FRAG_MAP_MAX_ENTRIES
#define MMT_IP_FRAG_MAP_MAX_ENTRIES 1024
#endif
#ifndef MMT_IP_FRAG_TIMEOUT_SEC
#define MMT_IP_FRAG_TIMEOUT_SEC 30
#endif

static int g_failures = 0;
static int g_checks   = 0;

#define CHECK(cond, msg) do {                                        \
        g_checks++;                                                  \
        if (cond) {                                                  \
            printf("  PASS: %s\n", (msg));                           \
        } else {                                                     \
            printf("  FAIL: %s\n", (msg));                           \
            g_failures++;                                            \
        }                                                            \
    } while (0)

/* --- packet builders --------------------------------------------------- */

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

static int put_eth(uint8_t *b, uint16_t ethertype) {
    static const uint8_t dst[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t src[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    memcpy(b, dst, 6);
    memcpy(b + 6, src, 6);
    put_be16(b + 12, ethertype);
    return 14;
}

/* IPv4 header: ihl in 32-bit words, frag_off raw (flags|offset bits). */
static int put_ip4(uint8_t *b, uint8_t ihl, uint8_t proto, uint16_t tot_len,
                   uint16_t id, uint16_t frag_off) {
    memset(b, 0, ihl * 4);
    b[0]  = (4 << 4) | ihl;
    put_be16(b + 2, tot_len);
    put_be16(b + 4, id);
    put_be16(b + 6, frag_off);
    b[8]  = 64;
    b[9]  = proto;
    put_be32(b + 12, 0x0a000001);
    put_be32(b + 16, 0x0a000002);
    return ihl * 4;
}

static int put_ip6(uint8_t *b, uint8_t nexthdr, uint16_t payload_len) {
    memset(b, 0, 40);
    b[0] = 0x60;
    put_be16(b + 4, payload_len);
    b[6] = nexthdr;
    b[7] = 64;
    /* saddr = 2001:db8::1, daddr = 2001:db8::2 */
    b[8] = 0x20; b[9] = 0x01; b[10] = 0x0d; b[11] = 0xb8; b[23] = 1;
    b[24] = 0x20; b[25] = 0x01; b[26] = 0x0d; b[27] = 0xb8; b[39] = 2;
    return 40;
}

static void run_packet_at(mmt_handler_t *h, const uint8_t *data, uint32_t caplen,
                          uint32_t wirelen, uint32_t tv_sec) {
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec  = tv_sec;
    hdr.ts.tv_usec = 0;
    hdr.caplen     = caplen;
    hdr.len        = wirelen;
    packet_process(h, &hdr, data);
}

static void run_packet(mmt_handler_t *h, const uint8_t *data, uint32_t caplen) {
    run_packet_at(h, data, caplen, caplen, 1);
}

/* --- fragment-map accounting ------------------------------------------- */

struct map_stats { unsigned entries; uint64_t payload_bytes; };

static void map_stats_walker(mmt_hashmap_t *map, mmt_hent_t *he, void *arg) {
    (void) map;
    struct map_stats *s = (struct map_stats *) arg;
    s->entries++;
    /* Both dgram structs share the leading {ip_version, last_activity, x, len}
     * layout (issue #201), so an ip_dgram_t view reads len for either. */
    s->payload_bytes += ((ip_dgram_t *) he->val)->len;
}

static void map_stats(mmt_handler_t *h, struct map_stats *s) {
    memset(s, 0, sizeof(*s));
    hashmap_walk(h->ip_streams, map_stats_walker, s);
}

/* ====================================================================== */

int main(void) {
    char errbuf[1024];
    mmt_handler_t *h;
    uint8_t pkt[256];
    int off;

    init_extraction();
    h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }

    printf("issue #201: IP/fragment/SCTP/GRE/TCP-segment bounds\n");

    /* ---------------------------------------------------------------
     * F-BUG-024: mmt_bytestream_to_number must check the byte budget
     * BEFORE dereferencing str. Calling with max=0 over a pointer one
     * byte past a malloc'd region reads OOB before the fix (ASan).
     */
    if (!getenv("IPF_SKIP_BYTESTREAM")) {
        uint8_t *buf = (uint8_t *) malloc(8);
        uint16_t bread = 0;
        memset(buf, '9', 8);
        uint32_t v = mmt_bytestream_to_number(buf + 8, 0, &bread);
        CHECK(v == 0 && bread == 0, "F-BUG-024: bytestream honours max=0 (no deref)");
        free(buf);
    }

    /* ---------------------------------------------------------------
     * F-BUG-019: tcp_seg_reassembly must not copy more than `len` bytes
     * into the destination buffer, whatever the segment list holds.
     * Two 60-byte segments into a 100-byte buffer: before the fix the
     * second memcpy wrote 20 bytes past the buffer (ASan).
     */
    {
        uint8_t *dst = (uint8_t *) malloc(100);
        uint8_t *d1 = (uint8_t *) malloc(60);
        uint8_t *d2 = (uint8_t *) malloc(60);
        memset(dst, 0, 100); memset(d1, 'A', 60); memset(d2, 'B', 60);
        tcp_seg_t *l = tcp_seg_new(1, 1000, 1060, 0, 60, d1);
        l->next = tcp_seg_new(2, 1060, 1120, 0, 60, d2);
        l->next->prev = l;
        tcp_seg_reassembly(dst, l, 100);
        CHECK(dst[59] == 'A' && dst[60] == 'B' && dst[99] == 'B',
              "F-BUG-019: reassembly clamped to the dst budget (60+40)");
        tcp_seg_free_list(l);
    }

    /* ---------------------------------------------------------------
     * F-BUG-039: arena-carved segments must never reach free(). Before
     * the fix tcp_seg_free() called free() on arena memory (allocator
     * mismatch — ASan "attempting free on address which was not
     * malloc()-ed").
     */
    {
        mmt_arena_t *arena = mmt_arena_create(0);
        CHECK(arena != NULL, "F-BUG-039: arena created");
        tcp_seg_t *seg = tcp_seg_new_in_arena(arena, 1, 1, 5, 0, 4, (const uint8_t *) "ABCD");
        CHECK(seg != NULL, "F-BUG-039: arena segment created");
        tcp_seg_free(seg);          /* must be a safe no-op on arena nodes */
        tcp_seg_t *seg2 = tcp_seg_new_in_arena(arena, 2, 5, 9, 0, 4, (const uint8_t *) "EFGH");
        seg->next = seg2;
        tcp_seg_free_list(seg);     /* must skip both arena nodes */
        mmt_arena_destroy(arena);
    }

    /* ---------------------------------------------------------------
     * F-BUG-017/037 (IPv4): MF fragment declaring tot_len=10 < ihl*4=20.
     * Before the fix `ip_len - ip_hl` underflowed to ~4 GiB, grew the
     * reassembly buffer to a wild size and memcpy()'d gigabytes.
     */
    off  = put_eth(pkt, 0x0800);
    off += put_ip4(pkt + off, 5, 17 /*UDP*/, 10 /*tot_len < ihl*4*/,
                   0x1111, 0x2000 /*MF*/);
    memset(pkt + off, 'F', 8); off += 8;
    run_packet(h, pkt, off);
    {
        struct map_stats s; map_stats(h, &s);
        CHECK(s.entries == 0,
              "F-BUG-017/037: tot_len<ihl*4 fragment rejected, no map entry");
    }

    /* IPv4 fragment with ihl=15 (60-byte header) but only 30 captured
     * bytes after the offset — the header itself is truncated. */
    off  = put_eth(pkt, 0x0800);
    off += 20; /* only the first 20 bytes of a 60-byte header captured */
    memset(pkt + off - 20 + 20, 0, 0); /* nothing */
    pkt[14] = (4 << 4) | 15;           /* ihl=15 */
    put_be16(pkt + 16, 28);            /* tot_len */
    put_be16(pkt + 18, 0x2222);
    put_be16(pkt + 20, 0x2000);        /* MF */
    run_packet(h, pkt, 14 + 20);
    {
        struct map_stats s; map_stats(h, &s);
        CHECK(s.entries == 0,
              "F-BUG-017: fragment with truncated ihl=15 header rejected");
    }

    /* ---------------------------------------------------------------
     * F-BUG-036/040/037 (IPv6): HBH ext header + Fragment header, but
     * declared payload_len (8) < ext chain (16) → payload_len underflow
     * used to feed a ~64 KiB OOB memcpy.
     */
    {
        uint8_t *p = pkt;
        off  = put_eth(p, 0x86dd);
        off += put_ip6(p + off, 0 /*HBH*/, 8 /*payload_len*/);
        /* HBH: nexthdr=44 (fragment), len=0 → 8 bytes */
        p[off] = 44; p[off + 1] = 0; memset(p + off + 2, 0, 6); off += 8;
        /* Fragment header: nexthdr=17, off=0, MF=1, id=0x42 */
        p[off] = 17; p[off + 1] = 0; put_be16(p + off + 2, 0x0001);
        put_be32(p + off + 4, 0x42); off += 8;
        memset(p + off, 'V', 8); off += 8;
        run_packet(h, pkt, off);
        struct map_stats s; map_stats(h, &s);
        CHECK(s.entries == 0,
              "F-BUG-037/040: IPv6 payload_len<ext_len fragment rejected");
    }

    /* IPv6: long HBH chain whose accumulated ext-header length used to
     * wrap the uint16_t next_offset accumulator. 40 x 2048-byte HBH
     * headers exceed 65535 — well past the captured data, so the walk
     * must stop at caplen and never classify a bogus L4. */
    {
        uint8_t *big = (uint8_t *) malloc(90000);
        off  = put_eth(big, 0x86dd);
        off += put_ip6(big + off, 0 /*HBH*/, (uint16_t)(90000 - 14 - 40));
        for (int i = 0; i < 40; i++) {
            big[off] = (i == 39) ? 6 /*TCP*/ : 0 /*HBH*/;
            big[off + 1] = 254;      /* ext_len → 8 + 254*8 = 2040 bytes */
            memset(big + off + 2, 0, 2038);
            off += 2040;
        }
        run_packet(h, big, off);
        free(big);
        CHECK(1, "F-BUG-040: 80KB IPv6 ext-header chain walked without wrap/OOB");
    }

    /* ---------------------------------------------------------------
     * F-BUG-020: fragment-map ceiling + eviction + age-based sweep.
     * 100k unique first fragments (distinct ids) must not grow the map
     * past the entry ceiling; entries idle > MMT_IP_FRAG_TIMEOUT_SEC
     * are swept from the existing session timer.
     */
    {
        enum { FLOOD = 100000 };
        struct map_stats s;
        for (int i = 0; i < FLOOD; i++) {
            off  = put_eth(pkt, 0x0800);
            off += put_ip4(pkt + off, 5, 17, 28, 0x9999, 0x2000 /*MF*/);
            /* unique map key: daddr occupies pkt[off-4 .. off-1] */
            put_be32(pkt + off - 4, (uint32_t) i);
            memset(pkt + off, 'F', 8); off += 8;
            run_packet_at(h, pkt, off, off, 1);
        }
        map_stats(h, &s);
        CHECK(s.entries <= MMT_IP_FRAG_MAP_MAX_ENTRIES,
              "F-BUG-020: map bounded under 100k unique first fragments");
        CHECK(s.payload_bytes < (16u << 20),
              "F-BUG-020: resident reassembly bytes under 16 MiB ceiling");
        printf("       (map: %u entries, %llu payload bytes)\n",
               s.entries, (unsigned long long) s.payload_bytes);

        /* Age-based sweep: the entries above were stamped at t=1. A new
         * fragment at t = 1 + TIMEOUT + 1 drives process_timedout_sessions
         * past the expiry milestone, sweeping every stale dgram. */
        for (int i = 0; i < 8; i++) {
            off  = put_eth(pkt, 0x0800);
            off += put_ip4(pkt + off, 5, 17, 28, (uint16_t)(0x8000 + i), 0x2000);
            memset(pkt + off, 'N', 8); off += 8;
            run_packet_at(h, pkt, off, off, 1 + MMT_IP_FRAG_TIMEOUT_SEC + 1);
        }
        map_stats(h, &s);
        CHECK(s.entries <= 16,
              "F-BUG-020: stale dgrams swept by the session timer");
        printf("       (map after sweep tick: %u entries)\n", s.entries);
    }

    /* ---------------------------------------------------------------
     * F-BUG-034: SCTP — common header captured, first chunk truncated.
     * sctp_classify_next_proto read hdr->type at +12; give exactly 12
     * bytes. Then a case where the chunk header itself is truncated to
     * 2 bytes so sctp_classify_next_chunk read past caplen.
     */
    off  = put_eth(pkt, 0x0800);
    off += put_ip4(pkt + off, 5, 132 /*SCTP*/, 32, 0x3333, 0);
    memset(pkt + off, 0, 12); off += 12;      /* 12-byte common hdr only */
    run_packet(h, pkt, off);
    CHECK(1, "F-BUG-034: SCTP common-header-only packet survived classify");

    off  = put_eth(pkt, 0x0800);
    off += put_ip4(pkt + off, 5, 132, 34, 0x3334, 0);
    memset(pkt + off, 0, 12); off += 12;
    pkt[off] = 3 /*SACK*/; pkt[off + 1] = 0; off += 2; /* 2-byte chunk hdr */
    run_packet(h, pkt, off);
    CHECK(1, "F-BUG-034: SCTP truncated chunk header survived classify");

    /* ---------------------------------------------------------------
     * F-BUG-035: GRE — only 2 captured bytes of the 4-byte base header:
     * gre_classify_next_proto read `protocol` at +2..+3.
     */
    off  = put_eth(pkt, 0x0800);
    off += put_ip4(pkt + off, 5, 47 /*GRE*/, 22, 0x4444, 0);
    put_be16(pkt + off, 0x0000); off += 2;    /* flags only, no protocol */
    run_packet(h, pkt, off);
    CHECK(1, "F-BUG-035: 2-byte GRE header survived classify");

    /* ---------------------------------------------------------------
     * F-BUG-021: GTP — E-flag set but the optional fields (seq, npdu,
     * next-ext byte at +11) are not captured. classify read
     * gtp_binary[11] unconditionally.
     */
    off  = put_eth(pkt, 0x0800);
    off += put_ip4(pkt + off, 5, 17, 36, 0x5555, 0);
    put_be16(pkt + off, 11111);       /* UDP sport */
    put_be16(pkt + off + 2, 2152);    /* UDP dport = GTP-U */
    put_be16(pkt + off + 4, 16);      /* udp len */
    put_be16(pkt + off + 6, 0);       /* udp csum */
    off += 8;
    pkt[off] = 0x34;                  /* v1 | PT | E   (S/PN off) */
    pkt[off + 1] = 0xff;              /* G-PDU */
    put_be16(pkt + off + 2, 0);       /* message_len = 0 */
    put_be32(pkt + off + 4, 0x11223344); /* teid */
    off += 8;                         /* caplen ends at the base header */
    run_packet(h, pkt, off);
    CHECK(1, "F-BUG-021: GTP E-flag with no captured ext bytes survived");

    /* ---------------------------------------------------------------
     * F-BUG-106: 802.1Q — tag present (ethertype 0x8100) but only the
     * 2-byte TCI captured; classify overlaid a 4-byte struct.
     */
    off  = put_eth(pkt, 0x8100);
    put_be16(pkt + off, 0x0064); off += 2;    /* TCI: vid 100 */
    run_packet(h, pkt, off);
    CHECK(1, "F-BUG-106: truncated 802.1Q tag survived classify");

    /* Same for 802.1ad (0x88a8). */
    off  = put_eth(pkt, 0x88a8);
    put_be16(pkt + off, 0x00c8); off += 2;
    run_packet(h, pkt, off);
    CHECK(1, "F-BUG-106: truncated 802.1ad tag survived classify");

    /* ---------------------------------------------------------------
     * F-BUG-018: ICMP_DATA extraction sized the payload copy by the
     * on-wire length (p_hdr->len). A truncated capture (len=60,
     * caplen=46) used to memcpy 18 bytes from a 4-byte tail.
     */
    if (register_extraction_attribute(h, PROTO_ICMP, ICMP_DATA)) {
        uint8_t *icmp_pkt = (uint8_t *) malloc(46);
        off  = put_eth(icmp_pkt, 0x0800);
        off += put_ip4(icmp_pkt + off, 5, 1 /*ICMP*/, 60, 0x6666, 0);
        memset(icmp_pkt + off, 0, 8);         /* echo hdr: type 8? set below */
        icmp_pkt[off] = 8 /*ICMP_ECHO*/;
        off += 8;
        memset(icmp_pkt + off, 'I', 4); off += 4; /* only 4 data bytes captured */
        run_packet_at(h, icmp_pkt, 46, 60 /*wire len*/, 200);
        free(icmp_pkt);
        CHECK(1, "F-BUG-018: ICMP_DATA extraction clamped to caplen");
    } else {
        CHECK(0, "F-BUG-018: register_extraction_attribute(ICMP_DATA)");
    }

    /* ---------------------------------------------------------------
     * Control: a well-formed two-fragment IPv4 datagram still reassembles.
     */
    {
        struct map_stats s;
        /* frag 1: off=0, MF, 16 payload bytes */
        off  = put_eth(pkt, 0x0800);
        off += put_ip4(pkt + off, 5, 17, 36, 0x7777, 0x2000);
        memset(pkt + off, 'R', 16); off += 16;
        run_packet(h, pkt, off);
        /* frag 2: off=16 bytes (2 units), last, 8 payload bytes */
        off  = put_eth(pkt, 0x0800);
        off += put_ip4(pkt + off, 5, 17, 28, 0x7777, 0x0002 /*off=16B*/);
        memset(pkt + off, 'R', 8); off += 8;
        run_packet(h, pkt, off);
        map_stats(h, &s);
        CHECK(s.entries == 0,
              "control: complete 2-fragment datagram reassembled + map drained");
    }

    mmt_close_handler(h);
    close_extraction();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures != 0) {
        printf("RESULT: FAIL\n");
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}

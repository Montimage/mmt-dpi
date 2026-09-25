/*
 * test_tcp_options_bounds.c — crafted-fixture test for issue #331: the TCP
 * options extractor (tcp_option_extraction() in
 * src/mmt_tcpip/lib/protocols/proto_tcp.c) now reports the MSS (kind 2),
 * window-scale (kind 3) and SACK-permitted (kind 4) options as the appended
 * tcp.mss / tcp.wscale / tcp.sack_permitted attributes, and tcp.syn_received
 * stores the SYN bit at its declared 4-byte width (tcp_syn_rcv_extraction).
 *
 *   - the new attributes are registered under their names with the declared
 *     data types, after the pre-existing tcp.tsecr id (append-only);
 *   - a complete SYN option block extracts MSS 1460, wscale 7, SACK
 *     permitted and the timestamps — including an MSS at an odd offset;
 *   - every truncation of the TCP header (caplen inside the options) yields
 *     "not extracted", never a read past caplen;
 *   - a mis-sized option (MSS of length 3, window scale of length 4) is
 *     skipped, not read, and later options still parse;
 *   - an option length running past the header end rejects;
 *   - tcp.syn_received overwrites all four bytes of its result.
 *
 * The capture buffer is heap-allocated at exactly caplen bytes so ASan
 * (SANITIZE=asan) brackets it. The test links the built SDK and calls the
 * exported extractors directly (same convention as
 * test_nfs_rpc_header_bounds.c).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mmt_core.h"
#include "packet_processing.h"          /* ipacket wiring, attribute_t */
#include "mmt_tcpip_plugin_structs.h"   /* mmt_tcpip_internal_packet_t */
#include "mmt_tcpip_attributes.h"       /* TCP_* attribute ids */

/* Exported non-static but absent from the installed headers. */
typedef int (*tcp_extractor_t)(const ipacket_t *, unsigned, attribute_t *);
int tcp_option_extraction(const ipacket_t *, unsigned, attribute_t *);
int tcp_syn_rcv_extraction(const ipacket_t *, unsigned, attribute_t *);

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, ...) do {                                        \
        g_checks++;                                                  \
        if (!(cond)) {                                               \
            printf("  FAIL: ");                                      \
            printf(__VA_ARGS__);                                     \
            printf("\n");                                            \
            g_failures++;                                            \
        }                                                            \
    } while (0)

/* TCP header offset inside the capture (Ethernet + IPv4). */
#define TCP_OFF 34u

typedef struct {
    ipacket_t pkt;
    proto_hierarchy_t offsets;
    proto_hierarchy_t hier;
    pkthdr_t hdr;
    mmt_tcpip_internal_packet_t ipkt;
    u_char *buf;
} fixture_t;

/* SYN with a 20-byte option block (doff 10): MSS 1460 | SACK-permitted |
 * timestamps 0x01020304/0x0a0b0c0d | NOP | window scale 7. The window-scale
 * option starts at the odd TCP offset 37. */
static const uint8_t syn_opts[] = {
    0x30, 0x39, 0x00, 0x50,   /* ports 12345 -> 80 */
    0x00, 0x00, 0x00, 0x01,   /* seq */
    0x00, 0x00, 0x00, 0x00,   /* ack */
    0xa0, 0x02,               /* doff 10, flags SYN */
    0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x04, 0x05, 0xb4,   /* +20 MSS 1460 */
    0x04, 0x02,               /* +24 SACK permitted */
    0x08, 0x0a, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d, /* +26 TS */
    0x01,                     /* +36 NOP */
    0x03, 0x03, 0x07,         /* +37 window scale 7 */
};

/* Capture holds the first tcp_bytes of tmpl; the buffer is exactly caplen. */
static void fixture_init(fixture_t *f, const uint8_t *tmpl, size_t tmpl_len,
                         unsigned tcp_bytes) {
    unsigned caplen = TCP_OFF + tcp_bytes;
    memset(f, 0, sizeof(*f));
    f->buf = (u_char *)malloc(caplen);
    if (!f->buf) { perror("malloc"); exit(2); }
    memset(f->buf, 0, caplen);
    memcpy(f->buf + TCP_OFF, tmpl, tcp_bytes < tmpl_len ? tcp_bytes : tmpl_len);
    f->offsets.proto_path[0] = TCP_OFF;
    f->offsets.len = 1;
    f->hier.len = 1;
    f->hdr.caplen = caplen;
    f->hdr.len = caplen;
    f->pkt.p_hdr = &f->hdr;
    f->pkt.data = f->buf;
    f->pkt.proto_headers_offset = &f->offsets;
    f->pkt.proto_hierarchy = &f->hier;
    f->pkt.internal_cumulative_offset_valid = 0;
    f->pkt.internal_packet = &f->ipkt;
}

/* Runs fn for field_id over the first tcp_bytes of tmpl. The result buffer
 * is pre-filled with 0xa5 so a partial write is visible. */
static int run(tcp_extractor_t fn, int field_id, const uint8_t *tmpl,
               size_t tmpl_len, unsigned tcp_bytes, uint32_t *value) {
    uint8_t scratch[8];
    fixture_t f;
    attribute_t attr;
    memset(&attr, 0, sizeof(attr));
    memset(scratch, 0xa5, sizeof(scratch));
    attr.data = scratch;
    attr.field_id = field_id;
    attr.position_in_packet = -1;
    fixture_init(&f, tmpl, tmpl_len, tcp_bytes);
    int rc = fn(&f.pkt, 0, &attr);
    free(f.buf);
    if (value) {
        switch (field_id) {
        case TCP_OPT_MSS: { uint16_t v; memcpy(&v, scratch, sizeof(v)); *value = v; break; }
        case TCP_OPT_WSCALE:
        case TCP_OPT_SACK_PERMITTED: *value = scratch[0]; break;
        default: { uint32_t v; memcpy(&v, scratch, sizeof(v)); *value = v; break; }
        }
    }
    return rc;
}

static void check_registration(void) {
    static const struct { const char *name; uint32_t id; long type; } attrs[] = {
        { "mss",            TCP_OPT_MSS,            MMT_U16_DATA },
        { "wscale",         TCP_OPT_WSCALE,         MMT_U8_DATA },
        { "sack_permitted", TCP_OPT_SACK_PERMITTED, MMT_U8_DATA },
    };
    CHECK(TCP_OPT_MSS == TCP_TSECR + 1 && TCP_OPT_SACK_PERMITTED == TCP_ATTRIBUTES_NB,
          "TCP option ids must be appended after tcp.tsecr");
    CHECK(get_attribute_id_by_protocol_and_attribute_names("tcp", "tsecr") == TCP_TSECR,
          "tcp.tsecr id must not move");
    for (size_t i = 0; i < sizeof(attrs) / sizeof(attrs[0]); i++) {
        uint32_t id = get_attribute_id_by_protocol_and_attribute_names("tcp", attrs[i].name);
        CHECK(id == attrs[i].id, "tcp.%s must be registered as id %u (got %u)",
              attrs[i].name, attrs[i].id, id);
        CHECK(get_attribute_data_type(PROTO_TCP, attrs[i].id) == attrs[i].type,
              "tcp.%s has the wrong data type", attrs[i].name);
    }
    CHECK(get_attribute_data_type(PROTO_TCP, TCP_SYN_RCV) == MMT_U32_DATA,
          "tcp.syn_received must stay MMT_U32_DATA");
}

static void check_syn_options(void) {
    const size_t full = sizeof(syn_opts);
    static const struct { const char *name; int field; uint32_t expect; } cases[] = {
        { "mss",            TCP_OPT_MSS,            1460 },
        { "wscale",         TCP_OPT_WSCALE,         7 },
        { "sack_permitted", TCP_OPT_SACK_PERMITTED, 1 },
        { "tsval",          TCP_TSVAL,              0x01020304 },
        { "tsecr",          TCP_TSECR,              0x0a0b0c0d },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        for (unsigned n = 0; n <= full; n++) {
            uint32_t v = 0;
            int rc = run(tcp_option_extraction, cases[i].field, syn_opts, full, n, &v);
            if (n < full) {
                CHECK(rc == 0, "%s: %u captured TCP bytes (header is %zu) must not extract",
                      cases[i].name, n, full);
            } else {
                CHECK(rc == 1 && v == cases[i].expect,
                      "%s: full header must extract %u (rc %d, got %u)",
                      cases[i].name, cases[i].expect, rc, v);
            }
        }
    }
}

static void check_malformed(void) {
    uint8_t pkt[sizeof(syn_opts)];
    uint32_t v;

    /* MSS at the odd offset 21 (a NOP first) still extracts byte-wise. */
    memcpy(pkt, syn_opts, sizeof(pkt));
    static const uint8_t odd[] = { 0x01, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x01 };
    memcpy(pkt + 20, odd, sizeof(odd));   /* replaces MSS + SACK-permitted + 2 TS bytes */
    memset(pkt + 28, 0x01, 9);            /* rest of the old TS option -> NOPs */
    CHECK(run(tcp_option_extraction, TCP_OPT_MSS, pkt, sizeof(pkt), sizeof(pkt), &v) == 1
          && v == 1460, "MSS at an odd offset must extract 1460 (got %u)", v);
    CHECK(run(tcp_option_extraction, TCP_OPT_WSCALE, pkt, sizeof(pkt), sizeof(pkt), &v) == 1
          && v == 7, "window scale after NOP padding must extract 7 (got %u)", v);
    CHECK(run(tcp_option_extraction, TCP_OPT_SACK_PERMITTED, pkt, sizeof(pkt), sizeof(pkt), &v) == 0
          && v == 0, "absent SACK-permitted must not extract and must read 0");

    /* Mis-sized MSS (length 3) is skipped, not read; later options parse. */
    memcpy(pkt, syn_opts, sizeof(pkt));
    pkt[21] = 3; pkt[23] = 0x01;          /* MSS len 3, then a NOP */
    CHECK(run(tcp_option_extraction, TCP_OPT_MSS, pkt, sizeof(pkt), sizeof(pkt), &v) == 0,
          "MSS with length 3 must not extract");
    CHECK(run(tcp_option_extraction, TCP_OPT_SACK_PERMITTED, pkt, sizeof(pkt), sizeof(pkt), &v) == 1
          && v == 1, "SACK-permitted after a mis-sized MSS must still extract");

    /* Mis-sized window scale (length 4 would end at the header end + 1). */
    memcpy(pkt, syn_opts, sizeof(pkt));
    pkt[38] = 4;
    CHECK(run(tcp_option_extraction, TCP_OPT_WSCALE, pkt, sizeof(pkt), sizeof(pkt), &v) == 0,
          "window scale running past the header end must not extract");

    /* Fully captured header, but the option's declared length crosses the
     * data-offset end: the per-option cursor check (not the header-level
     * caplen gate) must reject. MSS at +38 (len 4 -> ends at +42 > +40). */
    memcpy(pkt, syn_opts, sizeof(pkt));
    memset(pkt + 20, 0x01, 18);           /* NOPs up to +37 */
    pkt[38] = 0x02; pkt[39] = 0x04;
    CHECK(run(tcp_option_extraction, TCP_OPT_MSS, pkt, sizeof(pkt), sizeof(pkt), &v) == 0,
          "MSS whose length crosses the header end must not extract");
    /* Timestamps at +32 (len 10 -> ends at +42 > +40). */
    memcpy(pkt, syn_opts, sizeof(pkt));
    memset(pkt + 20, 0x01, 12);
    pkt[32] = 0x08; pkt[33] = 0x0a;
    CHECK(run(tcp_option_extraction, TCP_TSVAL, pkt, sizeof(pkt), sizeof(pkt), &v) == 0,
          "timestamps whose length crosses the header end must not extract");

    /* Window scale of length 2 (no shift byte) is skipped, never read. */
    memcpy(pkt, syn_opts, sizeof(pkt));
    pkt[38] = 2; pkt[39] = 0x00;          /* then end-of-options */
    CHECK(run(tcp_option_extraction, TCP_OPT_WSCALE, pkt, sizeof(pkt), sizeof(pkt), &v) == 0,
          "window scale with length 2 must not extract");

    /* Option length 0 / 1 rejects instead of looping. */
    memcpy(pkt, syn_opts, sizeof(pkt));
    pkt[21] = 1;
    CHECK(run(tcp_option_extraction, TCP_OPT_WSCALE, pkt, sizeof(pkt), sizeof(pkt), &v) == 0,
          "option length 1 must reject");

    /* No options at all (doff 5). */
    memcpy(pkt, syn_opts, 20);
    pkt[12] = 0x50;
    CHECK(run(tcp_option_extraction, TCP_OPT_MSS, pkt, 20, 20, &v) == 0,
          "doff 5 (no options) must not extract an MSS");
}

static void check_syn_received(void) {
    uint8_t pkt[20];
    uint32_t v = 0;
    memcpy(pkt, syn_opts, sizeof(pkt));
    CHECK(run(tcp_syn_rcv_extraction, TCP_SYN_RCV, pkt, sizeof(pkt), sizeof(pkt), &v) == 1
          && v == 1, "syn_received on a SYN must store the full u32 1 (got 0x%08x)", v);
    pkt[13] = 0x10;                        /* ACK only */
    CHECK(run(tcp_syn_rcv_extraction, TCP_SYN_RCV, pkt, sizeof(pkt), sizeof(pkt), &v) == 1
          && v == 0, "syn_received without SYN must store the full u32 0 (got 0x%08x)", v);
    CHECK(run(tcp_syn_rcv_extraction, TCP_SYN_RCV, pkt, sizeof(pkt), 13, &v) == 0,
          "syn_received with the flags byte not captured must not extract");
}

int main(void) {
    init_extraction();
    printf("issue #331: TCP option attributes and syn_received width\n");
    check_registration();
    check_syn_options();
    check_malformed();
    check_syn_received();
    close_extraction();
    printf("  %d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}

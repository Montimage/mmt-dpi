/*
 * ndn_test.c — crafted-input test for the NDN dissector
 * (src/mmt_tcpip/lib/protocols/ndn.c), issue #215.
 *
 * Coverage per the issue acceptance criteria:
 *   - TLV bounds:   every well-formed length form (1-octet, 0xfd/0xfe/0xff),
 *                   length overruns, zero-length nodes, bad types, and the
 *                   node-data bound inside ndn_TLV_get_int/get_string.
 *   - Multi-octet length form: 0xfd (2-octet), 0xfe (4-octet), 0xff (8-octet)
 *                   length encodings round-trip through ndn_TLV_parser().
 *   - Recursion depth: a deep chain of name components drives the recursive
 *                   ndn_TLV_parser_name_comp() and the recursive ndn_TLV_free()
 *                   on the sibling list.
 *
 * The payload-level entry points are exercised directly on crafted buffers;
 * the ipacket-typed *_extraction functions are driven on a fabricated ipacket
 * (same fixture pattern as position_unknown_guard_test.c) so the caplen
 * guards added by issue #146 (commit 10afc854) are covered — reverting them
 * turns the offset>caplen cases here into an ASan heap-buffer-overflow.
 *
 * Deferred to issue #205 (Task 2.7, PR #289 — not yet merged): truncated
 * multi-octet length headers (e.g. "05 fd" cut inside the 2 length octets)
 * and a find_node parse starting at the last payload byte over-read on main
 * inside str_hex2int()/payload[offset+1]. Those inputs live behind the
 * MMT_PENDING_FIXES=1 env gate below so this harness stays green on main
 * while still proving the cases catch the bug class: on a tree carrying the
 * #205 fix the gated block must go green; reverting the fix turns it red.
 *
 * Exit 0 == clean. Any ASan/UBSan report aborts under -fno-sanitize-recover.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "mmt_tcpip_plugin_structs.h"   /* mmt_tcpip_internal_packet_struct — in-tree header */
#include "packet_processing.h"        /* struct mmt_handler_struct — in-tree header */
#include "internal_decls.h"

/* NDN wire/attribute constants — mirror the enum in
 * src/mmt_tcpip/include/mmt_tcpip_attributes.h (attribute ids double as the
 * on-wire TLV types for the common fields). */
enum {
    T_INTEREST = 5, T_DATA = 6, T_NAME = 7, T_NAME_COMP = 8,
    T_SELECTORS = 9, T_NONCE = 10, T_LIFETIME = 12,
    T_MIN_SUFFIX = 13, T_MAX_SUFFIX = 14, T_PUBLISHER = 15, T_EXCLUDE = 16,
    T_CHILD_SELECTOR = 17, T_MUST_BE_FRESH = 18, T_ANY = 19,
    T_METAINFO = 20, T_CONTENT = 21, T_SIGINFO = 22, T_SIGVALUE = 23,
    T_CONTENT_TYPE = 24, T_FRESHNESS = 25, T_FINAL_BLOCK = 26,
    T_SIG_TYPE = 27, T_KEY_LOCATOR = 28, T_KEY_DIGEST = 29
};

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

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

/* A heap-allocated buffer holding exactly `len` payload bytes plus one
 * trailing NUL at [len]. The extra byte is invisible to the dissector (every
 * entry point takes an explicit length) but bounds str_sub()'s strlen() scan
 * inside ndn_TLV_get_string — that helper measures the C-string rather than
 * the field window, so on a NUL-free binary buffer it reads past the end
 * (latent over-read of the #205 class). The pending block below exercises
 * the raw case on a deliberately un-backstopped allocation. */
static char *dup_payload(const uint8_t *src, int len) {
    char *p = (char *)malloc(len + 1);
    if (!p) { perror("malloc"); exit(2); }
    memcpy(p, src, len);
    p[len] = '\0';
    return p;
}

static void put_u16be(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_u32be(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

/* ------------------------------------------------------------------ */
/* Part 1 — TLV type gate                                              */
/* ------------------------------------------------------------------ */
static void test_tlv_check_type(void) {
    printf("ndn_TLV_check_type:\n");
    CHECK(ndn_TLV_check_type(1) == 1, "type 1 (ImplicitSha256DigestComponent) accepted");
    CHECK(ndn_TLV_check_type(4) == 0, "type 4 rejected (gap below Interest)");
    CHECK(ndn_TLV_check_type(5) == 1, "type 5 (Interest) accepted");
    CHECK(ndn_TLV_check_type(11) == 0, "type 11 rejected (reserved gap)");
    CHECK(ndn_TLV_check_type(29) == 1, "type 29 (KeyDigest) accepted");
    CHECK(ndn_TLV_check_type(30) == 0, "type 30 rejected (above KeyDigest)");
    CHECK(ndn_TLV_check_type(0) == 0, "type 0 rejected");
    CHECK(ndn_TLV_check_type(-1) == 0, "negative type rejected");
    CHECK(ndn_TLV_check_type(255) == 0, "type 255 rejected");
}

/* ------------------------------------------------------------------ */
/* Part 2 — ndn_TLV_parser: length forms, bounds, edge offsets          */
/* ------------------------------------------------------------------ */
static void test_tlv_parser(void) {
    printf("ndn_TLV_parser length forms and bounds:\n");

    /* 1-octet length form: Interest(len=3) Name... minimal */
    {
        uint8_t wire[] = { 0x05, 0x03, 0x07, 0x01, 0x08 };
        char *p = dup_payload(wire, sizeof(wire));
        ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
        CHECK(n != NULL && n->type == 5 && n->length == 3 && n->data_offset == 2
                && n->nb_octets == 0, "1-octet length form parses");
        ndn_TLV_free(n);
        free(p);
    }
    /* 0xfd multi-octet length: Interest(len=0x0100) */
    {
        uint8_t wire[260];
        memset(wire, 0, sizeof(wire));
        wire[0] = 0x05; wire[1] = 0xfd; put_u16be(wire + 2, 256);
        /* value of 256 bytes follows (zeros) */
        char *p = dup_payload(wire, sizeof(wire));
        ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
        CHECK(n != NULL && n->type == 5 && n->length == 256 && n->nb_octets == 2
                && n->data_offset == 4, "0xfd 2-octet length form parses (len 256)");
        ndn_TLV_free(n);
        free(p);
    }
    /* 0xfd multi-octet length with overrun: declares 256, only 8 captured */
    {
        uint8_t wire[8];
        memset(wire, 0, sizeof(wire));
        wire[0] = 0x05; wire[1] = 0xfd; put_u16be(wire + 2, 256);
        char *p = dup_payload(wire, sizeof(wire));
        ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
        CHECK(n == NULL, "0xfd length overrun -> NULL");
        free(p);
    }
    /* 0xfe 4-octet length form: len 0x00010000=65536 > captured -> NULL;
     * then a well-formed one: len 3 */
    {
        uint8_t wire[9];
        memset(wire, 0, sizeof(wire));
        wire[0] = 0x05; wire[1] = 0xfe; put_u32be(wire + 2, 0x00010000);
        char *p = dup_payload(wire, sizeof(wire));
        ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
        CHECK(n == NULL, "0xfe length overrun (declared 65536) -> NULL");
        free(p);
    }
    {
        uint8_t wire[9];
        memset(wire, 0, sizeof(wire));
        wire[0] = 0x05; wire[1] = 0xfe; put_u32be(wire + 2, 3);
        wire[6] = 0x07; wire[7] = 0x01; wire[8] = 0x08;
        char *p = dup_payload(wire, sizeof(wire));
        ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
        CHECK(n != NULL && n->type == 5 && n->length == 3 && n->nb_octets == 4
                && n->data_offset == 6, "0xfe 4-octet length form parses (len 3)");
        ndn_TLV_free(n);
        free(p);
    }
    /* 0xff 8-octet length form */
    {
        uint8_t wire[13];
        memset(wire, 0, sizeof(wire));
        wire[0] = 0x05; wire[1] = 0xff;
        put_u32be(wire + 2, 0); put_u32be(wire + 6, 3);
        wire[10] = 0x07; wire[11] = 0x01; wire[12] = 0x08;
        char *p = dup_payload(wire, sizeof(wire));
        ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
        CHECK(n != NULL && n->type == 5 && n->length == 3 && n->nb_octets == 8
                && n->data_offset == 10, "0xff 8-octet length form parses (len 3)");
        ndn_TLV_free(n);
        free(p);
    }
    /* zero-length node at exact end: first_octet == 0 && offset+2 == len */
    {
        uint8_t wire[] = { 0x05, 0x00 };
        char *p = dup_payload(wire, sizeof(wire));
        ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
        CHECK(n != NULL && n->type == 5 && n->length == 0, "zero-length node at end parses");
        ndn_TLV_free(n);
        free(p);
    }
    /* zero-length node NOT at end -> rejected */
    {
        uint8_t wire[] = { 0x05, 0x00, 0xAA };
        char *p = dup_payload(wire, sizeof(wire));
        ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
        CHECK(n == NULL, "zero-length node not at end -> NULL");
        free(p);
    }
    /* invalid type */
    {
        uint8_t wire[] = { 0x03, 0x01, 0x00 };
        char *p = dup_payload(wire, sizeof(wire));
        ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
        CHECK(n == NULL, "invalid type 3 -> NULL");
        free(p);
    }
    /* length overrun, 1-octet form */
    {
        uint8_t wire[] = { 0x05, 0x10, 0x07 };
        char *p = dup_payload(wire, sizeof(wire));
        ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
        CHECK(n == NULL, "declared len 16 over 3 captured bytes -> NULL");
        free(p);
    }
    /* NULL payload */
    CHECK(ndn_TLV_parser(NULL, 0, 10) == NULL, "NULL payload -> NULL");
}

/* ------------------------------------------------------------------ */
/* Part 3 — get_int / get_string bounds (revert anchor: the node-data    */
/* bound guards the str_hex2int/str_sub window).                        */
/* ------------------------------------------------------------------ */
static void test_tlv_get_bounds(void) {
    printf("ndn_TLV_get_int/get_string bounds:\n");
    uint8_t wire[] = { 0x05, 0x03, 0x07, 0x01, 0x08 };
    char *p = dup_payload(wire, sizeof(wire));

    /* real node from the parser */
    ndn_tlv_t *n = ndn_TLV_parser(p, 0, sizeof(wire));
    CHECK(n != NULL, "root node parses for get_*");
    /* node data is 3 bytes at offset 2: get_string returns "...\x08"-ish */
    char *s = ndn_TLV_get_string(n, p, sizeof(wire));
    CHECK(s != NULL, "get_string on in-bounds node returns value");
    free(s);

    /* hand-built node whose declared window exceeds the payload: the
     * data_offset + length > payload_len bound must refuse (issue #146 class) */
    ndn_tlv_t evil = {0};
    evil.type = 5; evil.nb_octets = 0;
    evil.node_offset = 0; evil.data_offset = 2; evil.length = 64; /* > 5 */
    CHECK(ndn_TLV_get_int(&evil, p, sizeof(wire)) == -1,
            "get_int on overrun node -> -1 (bound refused)");
    CHECK(ndn_TLV_get_string(&evil, p, sizeof(wire)) == NULL,
            "get_string on overrun node -> NULL (bound refused)");
    CHECK(ndn_TLV_get_int(NULL, p, sizeof(wire)) == -1, "get_int NULL node -> -1");
    CHECK(ndn_TLV_get_string(NULL, p, sizeof(wire)) == NULL, "get_string NULL node -> NULL");
    CHECK(ndn_TLV_get_int(n, NULL, sizeof(wire)) == -1, "get_int NULL payload -> -1");

    ndn_TLV_free(n);
    free(p);
}

/* ------------------------------------------------------------------ */
/* Part 4 — mmt_check_ndn_payload classification                       */
/* ------------------------------------------------------------------ */
static void test_check_ndn_payload(void) {
    printf("mmt_check_ndn_payload:\n");
    char b1[2] = { 0x05, 0x00 };
    CHECK(mmt_check_ndn_payload(b1, 2) == 0, "len < 3 rejected");
    char b2[4] = { 0x04, 0x02, 0x07, 0x00 };
    CHECK(mmt_check_ndn_payload(b2, 4) == 0, "first byte not 5/6 rejected");
    char b3[10] = { 0x05, 0x08, 0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't' };
    CHECK(mmt_check_ndn_payload(b3, 10) == 1, "well-formed Interest accepted");
    char b4[10] = { 0x06, 0x08, 0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't' };
    CHECK(mmt_check_ndn_payload(b4, 10) == 1, "well-formed Data accepted");
    char b5[11] = { 0x05, 0x08, 0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't', 0x00 };
    CHECK(mmt_check_ndn_payload(b5, 11) == 0, "declared len != packet len rejected");
    char b6[10] = { 0x05, 0x08, 0x09, 0x06, 0x08, 0x04, 't', 'e', 's', 't' };
    CHECK(mmt_check_ndn_payload(b6, 10) == 0, "missing Name node (0x09) rejected");
    /* NULL payload: dereferences payload[0] on main — lives in the
     * pending-#205 block (missing NULL guard before the type check). */
}

/* ------------------------------------------------------------------ */
/* Part 5 — find_node over sibling TLVs                                */
/* ------------------------------------------------------------------ */
static void test_find_node(void) {
    printf("ndn_find_node:\n");
    /* Interest{ Name{comp} , Nonce(4)=0x01020304 , Lifetime(2)=1000 } */
    uint8_t wire[] = {
        0x05, 0x0E,                 /* Interest, len 14 */
        0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't',   /* Name node, len 6 */
        0x0A, 0x04, 0x01, 0x02, 0x03, 0x04            /* Nonce, len 4 */
    };
    /* wait — len must equal bytes after the 2-octet header: 8+6 = 14 ✓ */
    char *p = dup_payload(wire, sizeof(wire));
    ndn_tlv_t *root = ndn_TLV_parser(p, 0, sizeof(wire));
    CHECK(root != NULL && root->type == 5, "interest root parses");
    ndn_tlv_t *nonce = ndn_find_node(p, sizeof(wire), root, T_NONCE);
    CHECK(nonce != NULL && nonce->type == T_NONCE && nonce->length == 4,
            "find_node locates Nonce TLV");
    int nonce_v = ndn_TLV_get_int(nonce, p, sizeof(wire));
    CHECK(nonce_v == 0x01020304, "nonce value decodes big-endian");
    ndn_TLV_free(nonce);
    ndn_tlv_t *absent = ndn_find_node(p, sizeof(wire), root, T_LIFETIME);
    CHECK(absent == NULL, "absent node -> NULL");
    CHECK(ndn_find_node(p, sizeof(wire), NULL, T_NONCE) == NULL, "NULL root -> NULL");
    CHECK(ndn_find_node(NULL, sizeof(wire), root, T_NONCE) == NULL, "NULL payload -> NULL");
    ndn_TLV_free(root);
    free(p);
}

/* ------------------------------------------------------------------ */
/* Part 6 — name components + recursion depth                          */
/* ------------------------------------------------------------------ */
static void test_name_components(void) {
    printf("name components and recursion depth:\n");

    /* Interest{ Name{ 08 04 'test' , 08 03 'abc' , 08 01 'x' } }
     * Name value = 6+5+3 = 14 bytes; Interest value = 2+14 = 16. */
    uint8_t wire[] = {
        0x05, 0x10,
        0x07, 0x0E,
        0x08, 0x04, 't', 'e', 's', 't',
        0x08, 0x03, 'a', 'b', 'c',
        0x08, 0x01, 'x'
    };
    char *p = dup_payload(wire, sizeof(wire));
    char *c0 = ndn_name_components_at_index(p, sizeof(wire), 0);
    CHECK(c0 != NULL, "component 0 present");
    char *c1 = ndn_name_components_at_index(p, sizeof(wire), 1);
    CHECK(c1 != NULL, "component 1 present");
    char *c2 = ndn_name_components_at_index(p, sizeof(wire), 2);
    CHECK(c2 != NULL, "component 2 present");
    char *c9 = ndn_name_components_at_index(p, sizeof(wire), 9);
    CHECK(c9 == NULL, "out-of-range component -> NULL");
    free(c0); free(c1); free(c2); free(c9);

    char *all = ndn_name_components_extraction_payload(p, sizeof(wire));
    CHECK(all != NULL, "joined name components present");
    if (all) printf("  info: name_components = '%s'\n", all);
    free(all);
    free(p);

    /* deep chain: N copies of 08 01 'c' inside one Name — recursion in
     * ndn_TLV_parser_name_comp() and in ndn_TLV_free() on ->next. */
    enum { DEPTH = 300 };
    int comp_len = 3;                     /* 08 01 'c' */
    int name_len = DEPTH * comp_len;
    int total = 8 + name_len;             /* 05 fd xx xx | 07 fd xx xx | value */
    uint8_t *deep = malloc(total);
    if (!deep) { perror("malloc"); exit(2); }
    int n = 0;
    deep[n++] = 0x05;
    deep[n++] = 0xfd;                     /* multi-octet length */
    put_u16be(deep + n, (uint16_t)(2 + name_len)); n += 2;
    deep[n++] = 0x07;
    deep[n++] = 0xfd;
    put_u16be(deep + n, (uint16_t)name_len); n += 2;
    for (int i = 0; i < DEPTH; i++) { deep[n++] = 0x08; deep[n++] = 0x01; deep[n++] = 'c'; }
    char *dp = dup_payload(deep, n);
    free(deep);
    ndn_tlv_t *chain = ndn_TLV_parser_name_comp(dp, n, 8, name_len);
    CHECK(chain != NULL, "300-deep name-component chain parses (recursion)");
    int counted = 0;
    for (ndn_tlv_t *t = chain; t; t = t->next) counted++;
    CHECK(counted == DEPTH, "chain holds all 300 components");
    ndn_TLV_free(chain);
    free(dp);
}

/* ------------------------------------------------------------------ */
/* Part 7 — extraction_payload functions on crafted packets            */
/* ------------------------------------------------------------------ */
static void test_extraction_payload(void) {
    printf("extraction_payload functions:\n");

    /* Interest with name + nonce + lifetime + selectors(min/max):
     * content = Name(8) + Nonce(6) + Lifetime(4) + Selectors(2+6) = 26. */
    uint8_t interest[] = {
        0x05, 0x1A,                                   /* len 26 */
        0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't',   /* Name */
        0x0A, 0x04, 0x01, 0x02, 0x03, 0x04,           /* Nonce = 0x01020304 */
        0x0C, 0x02, 0x03, 0xE8,                       /* Lifetime = 1000 */
        0x09, 0x06,                                   /* Selectors len 6 */
        0x0D, 0x01, 0x02,                             /* MinSuffix = 2 */
        0x0E, 0x01, 0x05                              /* MaxSuffix = 5 */
    };
    char *ip = dup_payload(interest, sizeof(interest));
    CHECK(ndn_packet_length_extraction_payload(ip, sizeof(interest)) == 26,
            "packet_length returns Interest length");
    int nonce = ndn_interest_nonce_extraction_payload(ip, sizeof(interest));
    CHECK(nonce == 0x01020304, "nonce extraction = 0x01020304");
    int life = ndn_interest_lifetime_extraction_payload(ip, sizeof(interest));
    CHECK(life == 1000, "lifetime extraction = 1000");
    int mins = ndn_interest_min_suffix_component_extraction_payload(ip, sizeof(interest));
    CHECK(mins == 2, "min suffix components = 2");
    int maxs = ndn_interest_max_suffix_component_extraction_payload(ip, sizeof(interest));
    CHECK(maxs == 5, "max suffix components = 5");
    free(ip);

    /* Interest without optional fields -> extractors return -1 */
    uint8_t interest_bare[] = {
        0x05, 0x08, 0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't'
    };
    char *ib = dup_payload(interest_bare, sizeof(interest_bare));
    CHECK(ndn_interest_nonce_extraction_payload(ib, sizeof(interest_bare)) == -1,
            "absent nonce -> -1");
    CHECK(ndn_interest_lifetime_extraction_payload(ib, sizeof(interest_bare)) == -1,
            "absent lifetime -> -1");
    free(ib);

    /* Data packet for the get_int()-based fields: MetaInfo{ContentType,
     * Freshness, FinalBlockId} + SigInfo{SigType}. content = 8+14+5 = 27.
     * (The 0x00 ContentType value embeds a NUL — safe here because these
     * extractors use the index-bounded get_int path only.) */
    uint8_t data[] = {
        0x06, 0x1B,                                   /* len 27 */
        0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't',   /* Name */
        0x14, 0x0C,                                   /* MetaInfo len 12 */
        0x18, 0x01, 0x00,                             /* ContentType = BLOB(0) */
        0x19, 0x02, 0x13, 0x88,                       /* Freshness = 5000 */
        0x1A, 0x03, 'a', 'b', 'c',                    /* FinalBlockId = "abc" */
        0x16, 0x03, 0x1B, 0x01, 0x01                  /* SigInfo{ SigType len1 =1 } */
    };
    char *dp = dup_payload(data, sizeof(data));
    CHECK(ndn_data_content_type_extraction_payload(dp, sizeof(data)) == 0,
            "content type = BLOB(0)");
    CHECK(ndn_data_freshness_period_extraction_payload(dp, sizeof(data)) == 5000,
            "freshness period = 5000");
    int sigt = ndn_data_signature_type_extraction_payload(dp, sizeof(data));
    CHECK(sigt == 1, "signature type = SignatureSha256WithRsa(1)");
    free(dp);

    /* Data packet for get_string()-based content extraction — no embedded
     * NUL bytes anywhere (str_sub strlen()s the whole payload on main). */
    uint8_t data_c[] = {
        0x06, 0x0E,                                   /* len 14 */
        0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't',   /* Name */
        0x15, 0x04, 'D', 'A', 'T', 'A'                /* Content */
    };
    char *dcp = dup_payload(data_c, sizeof(data_c));
    char *content = ndn_data_content_extraction_payload(dcp, sizeof(data_c));
    CHECK(content != NULL && memcmp(content, "DATA", 4) == 0,
            "content extraction returns 'DATA'");
    free(content);
    free(dcp);

    /* NDN-over-HTTP detection: name containing the "req" component */
    uint8_t http_name[] = {
        0x05, 0x10,
        0x07, 0x0E,
        0x08, 0x03, 'r', 'e', 'q',
        0x08, 0x07, 'G', 'E', 'T', ' ', '/', ' ', ' '
    };
    char *hn = dup_payload(http_name, sizeof(http_name));
    int http = mmt_check_payload_ndn_http(hn, sizeof(http_name));
    printf("  info: mmt_check_payload_ndn_http = %d\n", http);
    CHECK(http == 0 || http == 1, "ndn_http check returns a verdict without crashing");
    free(hn);
}

/* ------------------------------------------------------------------ */
/* Part 8 — ipacket-typed *_extraction on a fabricated packet           */
/*         (issue #146 offset>caplen guards — the revert anchor)        */
/* ------------------------------------------------------------------ */

/* Fabricated ipacket: same wiring internal_extract_attribute() reads —
 * p_hdr, data, proto_headers_offset (per-layer sizes), proto_hierarchy,
 * internal_packet, mmt_handler (zeroed). */
typedef struct {
    ipacket_t pkt;
    proto_hierarchy_t offsets;
    proto_hierarchy_t hier;
    pkthdr_t hdr;
    mmt_tcpip_internal_packet_t internal;
    mmt_handler_t *hdlr;
    u_char *buf;
} ndn_fixture_t;

static void ndn_fixture_init(ndn_fixture_t *f, const int *layer_sizes,
        int nlayers, const uint8_t *payload, unsigned caplen) {
    memset(f, 0, sizeof(*f));
    f->buf = (u_char *)malloc(caplen ? caplen : 1);
    if (!f->buf) { perror("malloc"); exit(2); }
    memset(f->buf, 0, caplen ? caplen : 1);
    if (payload) memcpy(f->buf, payload, caplen);
    f->hdlr = (mmt_handler_t *)calloc(1, sizeof(mmt_handler_t));
    if (!f->hdlr) { perror("calloc"); exit(2); }
    for (int i = 0; i < nlayers && i < PROTO_PATH_SIZE; i++) {
        f->offsets.proto_path[i] = layer_sizes[i];
        f->hier.proto_path[i] = 1;
    }
    f->offsets.len = f->hier.len = nlayers;
    f->hdr.caplen = caplen;
    f->hdr.len = caplen;
    f->pkt.p_hdr = &f->hdr;
    f->pkt.data = f->buf;
    f->pkt.proto_headers_offset = &f->offsets;
    f->pkt.proto_hierarchy = &f->hier;
    f->pkt.internal_cumulative_offset_valid = 0;
    f->pkt.internal_packet = &f->internal;
    f->pkt.mmt_handler = f->hdlr;
}

static void ndn_fixture_free(ndn_fixture_t *f) {
    free(f->buf);
    free(f->hdlr);
}

static void test_ipacket_extraction(void) {
    printf("ipacket-typed extraction (offset>caplen guards):\n");

    uint8_t interest[] = {
        0x05, 0x0E,
        0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't',
        0x0A, 0x04, 0x01, 0x02, 0x03, 0x04
    };

    /* proto_index == 2 => "NDN over Ethernet": payload_len = caplen-offset.
     * Layers {0,0,14} put the payload start at offset 14 inside the buffer;
     * build the captured buffer accordingly. */
    uint8_t frame[14 + sizeof(interest)];
    memset(frame, 0, 14);
    memcpy(frame + 14, interest, sizeof(interest));

    ndn_fixture_t f;
    int layers[3] = { 0, 0, 14 };
    attribute_t attr; uint8_t u8v; uint32_t u32v;

    ndn_fixture_init(&f, layers, 3, frame, sizeof(frame));
    memset(&attr, 0, sizeof(attr)); attr.data = &u8v; u8v = 0;
    CHECK(ndn_packet_type_extraction(&f.pkt, 2, &attr) == 1 && u8v == 5,
            "packet_type extraction (offset<=caplen) = Interest(5)");
    memset(&attr, 0, sizeof(attr)); attr.data = &u32v; u32v = 0;
    CHECK(ndn_packet_length_extraction(&f.pkt, 2, &attr) == 1 && u32v == 14,
            "packet_length extraction = 14");
    ndn_fixture_free(&f);

    /* offset > caplen: the #146 guard must refuse BEFORE data[offset] is
     * dereferenced. Revert of 10afc854 turns this into an ASan read OOB. */
    int deep_layers[3] = { 0, 0, 4000 };
    ndn_fixture_init(&f, deep_layers, 3, frame, sizeof(frame));
    memset(&attr, 0, sizeof(attr)); attr.data = &u8v; u8v = 0;
    CHECK(ndn_packet_type_extraction(&f.pkt, 2, &attr) == 0,
            "packet_type extraction (offset>caplen) refused -> 0");
    memset(&attr, 0, sizeof(attr)); attr.data = &u32v; u32v = 0;
    CHECK(ndn_packet_length_extraction(&f.pkt, 2, &attr) == 0,
            "packet_length extraction (offset>caplen) refused -> 0");
    memset(&attr, 0, sizeof(attr)); attr.data = NULL;
    CHECK(ndn_name_components_extraction(&f.pkt, 2, &attr) == 0,
            "name_components extraction (offset>caplen) refused -> 0");
    memset(&attr, 0, sizeof(attr)); attr.data = &u32v; u32v = 0;
    CHECK(ndn_interest_nonce_extraction(&f.pkt, 2, &attr) == 0,
            "nonce extraction (offset>caplen) refused -> 0");
    ndn_fixture_free(&f);
}

/* ------------------------------------------------------------------ */
/* Part 9 — full packet path: real classification of an Interest        */
/* ------------------------------------------------------------------ */
static int g_last_proto = -1;
static int ph_last_proto(const ipacket_t *ipacket, void *u) {
    (void)u;
    if (ipacket->proto_hierarchy && ipacket->proto_hierarchy->len > 0)
        g_last_proto = ipacket->proto_hierarchy->proto_path[ipacket->proto_hierarchy->len - 1];
    return 0;
}

static void test_full_path_classification(void) {
    printf("full-path classification (Eth/IP/TCP carrying an Interest):\n");
    char errbuf[1024];
    if (!init_extraction()) { printf("  info: init_extraction unavailable — skipping\n"); return; }
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (!h) { printf("  info: mmt_init_handler failed — skipping\n"); close_extraction(); return; }
    register_packet_handler(h, 1, ph_last_proto, NULL);

    uint8_t ndn[] = { 0x05, 0x08, 0x07, 0x06, 0x08, 0x04, 't', 'e', 's', 't' };
    /* Heap buffer with a trailing NUL: the session-analysis path reaches
     * ndn_TVL_get_name_components -> str_sub -> strlen(), which scans to the
     * first NUL — the backstop keeps that scan inside the allocation on
     * main (the raw over-read is in the pending-#205 block). */
    int flen = 14 + 20 + 20 + (int)sizeof(ndn);
    uint8_t *pkt = malloc(flen + 1);
    if (!pkt) { perror("malloc"); exit(2); }
    int off = 0;
    /* eth */
    memset(pkt, 0, 14); pkt[12] = 0x08; pkt[13] = 0x00; off = 14;
    /* ipv4: ihl 5, proto 6, tot_len = 20+20+ndn */
    memset(pkt + off, 0, 20);
    pkt[off] = 0x45; put_u16be(pkt + off + 2, 20 + 20 + sizeof(ndn));
    pkt[off + 8] = 64; pkt[off + 9] = 6;
    pkt[off + 12] = 10; pkt[off + 15] = 1; pkt[off + 16] = 10; pkt[off + 19] = 2;
    off += 20;
    /* tcp */
    put_u16be(pkt + off, 12345); put_u16be(pkt + off + 2, 6363);
    memset(pkt + off + 4, 0, 8); pkt[off + 12] = 0x50; pkt[off + 13] = 0x18;
    put_u16be(pkt + off + 14, 0xffff);
    off += 20;
    memcpy(pkt + off, ndn, sizeof(ndn)); off += sizeof(ndn);
    pkt[off] = 0;

    struct pkthdr hdr; memset(&hdr, 0, sizeof hdr);
    hdr.caplen = off; hdr.len = off;
    g_last_proto = -1;
    packet_process(h, &hdr, pkt);
    /* PROTO_NDN = 625, PROTO_NDN_HTTP = 626 — an Interest without the "req"
     * marker may classify to either; the point is it leaves TCP. */
    CHECK(g_last_proto == 625 || g_last_proto == 626,
            "Interest classified past TCP (NDN/NDN_HTTP)");
    free(pkt);
    mmt_close_handler(h);
    close_extraction();
}

/* ------------------------------------------------------------------ */
/* Part 10 — session helpers (pure allocation/compare paths)            */
/* ------------------------------------------------------------------ */
static void test_session_helpers(void) {
    printf("ndn session helpers:\n");
    ndn_tuple3_t *a = ndn_new_tuple3();
    ndn_tuple3_t *b = ndn_new_tuple3();
    CHECK(a != NULL && b != NULL, "tuple3 allocation");
    /* ndn_free_tuple3 releases name via free() but src_MAC/dst_MAC via
     * mmt_free() (which walks back a hidden size header) — so name comes
     * from strdup() and the MAC strings from mmt_malloc(). */
    a->name = strdup("x");
    a->src_MAC = mmt_malloc(3); strcpy(a->src_MAC, "m1");
    a->dst_MAC = mmt_malloc(3); strcpy(a->dst_MAC, "m2");
    b->name = strdup("x");
    b->src_MAC = mmt_malloc(3); strcpy(b->src_MAC, "m1");
    b->dst_MAC = mmt_malloc(3); strcpy(b->dst_MAC, "m2");
    CHECK(ndn_compare_tupe3(a, b) == 1, "identical tuples compare equal (1)");
    mmt_free(b->src_MAC); mmt_free(b->dst_MAC);
    b->src_MAC = mmt_malloc(3); strcpy(b->src_MAC, "m2");
    b->dst_MAC = mmt_malloc(3); strcpy(b->dst_MAC, "m1");
    CHECK(ndn_compare_tupe3(a, b) == 2, "mirrored MACs compare equal (2)");
    b->src_MAC[0] = 'z';                  /* "z2" vs a's "m1"/"m2" — no match */
    CHECK(ndn_compare_tupe3(a, b) == 0, "mismatched MACs -> 0");
    CHECK(ndn_compare_tupe3(NULL, NULL) == 3, "two NULLs compare (3)");
    CHECK(ndn_compare_tupe3(a, NULL) == 0, "tuple vs NULL -> 0");

    ndn_session_t *s = ndn_new_session();
    CHECK(s != NULL, "session allocation");
    s->tuple3 = a;                        /* hand ownership of a to the session */
    ndn_session_t *found = ndn_find_session_by_tuple3(a, s);
    CHECK(found == s, "find_session_by_tuple3 locates the session");
    CHECK(ndn_find_session_by_tuple3(NULL, s) == NULL, "NULL tuple -> NULL");
    CHECK(ndn_find_session_by_tuple3(a, NULL) == NULL, "NULL list -> NULL");
    ndn_free_session(s);                  /* frees a via tuple3 */
    ndn_free_tuple3(b);                   /* frees b's members + the struct */
}

/* ------------------------------------------------------------------ */
/* Part 11 — pending-#205 inputs (env-gated; red on main today)          */
/* ------------------------------------------------------------------ */
static void test_pending_205(void) {
    if (!getenv("MMT_PENDING_FIXES")) {
        printf("pending-#205 cases: skipped (set MMT_PENDING_FIXES=1 to arm)\n");
        return;
    }
    printf("pending-#205 cases (must go green only on a tree carrying the #205 fix):\n");

    /* truncated multi-octet length headers: the length octets are cut —
     * today str_hex2int over-reads; post-fix these must return NULL. */
    uint8_t t_fd2[] = { 0x05, 0xfd };            /* 0 of 2 length octets */
    uint8_t t_fd3[] = { 0x05, 0xfd, 0x01 };      /* 1 of 2 */
    uint8_t t_fe[]  = { 0x05, 0xfe, 0x00, 0x00 };/* 2 of 4 */
    uint8_t t_ff[]  = { 0x05, 0xff, 0x00, 0x00, 0x00, 0x00 }; /* 4 of 8 */
    const struct { const uint8_t *w; int len; const char *d; } cases[] = {
        { t_fd2, sizeof(t_fd2), "05 fd (0/2 len octets) -> NULL" },
        { t_fd3, sizeof(t_fd3), "05 fd xx (1/2 len octets) -> NULL" },
        { t_fe,  sizeof(t_fe),  "05 fe xx xx (2/4 len octets) -> NULL" },
        { t_ff,  sizeof(t_ff),  "05 ff xxxx (4/8 len octets) -> NULL" },
    };
    for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        char *p = dup_payload(cases[i].w, cases[i].len);
        ndn_tlv_t *n = ndn_TLV_parser(p, 0, cases[i].len);
        CHECK(n == NULL, cases[i].d);
        ndn_TLV_free(n);
        free(p);
    }

    /* find_node parsing at the last payload byte: the Name child ends one
     * byte before the end, so the sibling walk calls ndn_TLV_parser() at
     * offset == total_length-1 — payload[offset+1] over-reads on main. */
    uint8_t wire[] = {
        0x05, 0x06,                       /* Interest, len 6 -> data [2..7] */
        0x07, 0x03, 0x08, 0x01, 'a',      /* Name: one component, ends at 7 */
        0x08                              /* trailing type byte at offset 7 */
    };
    char *p = dup_payload(wire, sizeof(wire));
    ndn_tlv_t *root = ndn_TLV_parser(p, 0, sizeof(wire));
    CHECK(root != NULL, "root parses for last-byte find_node");
    ndn_tlv_t *res = ndn_find_node(p, sizeof(wire), root, T_NONCE);
    CHECK(res == NULL, "find_node child at last byte -> NULL (bounded)");
    ndn_TLV_free(res);
    ndn_TLV_free(root);
    free(p);

    /* get_string on a NUL-free buffer: str_sub() strlen()s the raw binary
     * and reads past the end on main; post-fix it must be bounded. The
     * dup_payload backstop is deliberately not used here. */
    uint8_t nonul[] = { 0x05, 0x03, 0x07, 0x01, 0x08 };
    char *raw = (char *)malloc(sizeof(nonul));
    memcpy(raw, nonul, sizeof(nonul));
    ndn_tlv_t *nn = ndn_TLV_parser(raw, 0, sizeof(nonul));
    if (nn) {
        /* reaching this call without an ASan report is the assertion:
         * on main strlen() in str_sub() over-reads before any value check. */
        char *s = ndn_TLV_get_string(nn, raw, sizeof(nonul));
        CHECK(s == NULL || s != NULL, "get_string on NUL-free buffer returns (bounded post-#205)");
        free(s);
        ndn_TLV_free(nn);
    }
    free(raw);

    /* NULL payload to the classifier: payload[0] is dereferenced before any
     * NULL guard on main (ndn.c:214). Post-fix must refuse cleanly. */
    CHECK(mmt_check_ndn_payload(NULL, 10) == 0,
            "mmt_check_ndn_payload(NULL) refused (post-#205)");
}

int main(void) {
    printf("=== NDN dissector crafted-input test (issue #215) ===\n");
    test_tlv_check_type();
    test_tlv_parser();
    test_tlv_get_bounds();
    test_check_ndn_payload();
    test_find_node();
    test_name_components();
    test_extraction_payload();
    test_ipacket_extraction();
    test_full_path_classification();
    test_session_helpers();
    test_pending_205();

    printf("=== %d checks, %d failures ===\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}

/*
 * test_radius_hardening.c — regression for #128 (RADIUS parser hardening),
 * driven through the SHIPPED parser (issue #526, F-TEST-008).
 *
 * The suite used to replicate the parsing/extraction logic of
 * src/mmt_tcpip/lib/protocols/proto_radius.c in this file and grep the
 * source for the guards; a regression in the shipped parser could leave
 * both green. Every case below instead feeds a crafted
 * Ethernet/IPv4/UDP/RADIUS frame through the installed SDK —
 * mmt_init_handler + register_extraction_attribute + packet_process — and
 * asserts what get_attribute_extracted_data() reports for it, so
 * radius_session_data_analysis(), radius_vendor_specific_fields_analysis()
 * and the extractors run exactly as shipped:
 *
 *   A. TLV length < 2 (F-BUG-102): a len-1 or len-0 attribute ends the
 *      walk — the bytes after it are never parsed as attributes (a len-0
 *      attribute used to spin the walk forever: run_tests.sh bounds the
 *      binary with `timeout`); a len-2 attribute (empty value) is accepted.
 *   B. value clamps: User-Name values over 64 bytes are clamped to 64,
 *      Called-Station-Id to 63 bytes plus a NUL.
 *   C. 32-bit attributes: NAS-IP-Address shorter than 6 bytes is rejected;
 *      a 6-byte one reads 100.64.1.10, and 192.168.1.10 — a first octet
 *      >= 0x80, which read_be32() once shifted into the int sign bit.
 *   D. 3GPP vendor-specific attribute (type 26): IMSI extracted from a valid
 *      sub-attribute; not reported for a VSA too short for vendor id +
 *      sub-header, an over-long sub-attribute, a len-1 sub-attribute, a
 *      foreign vendor id or a sub-type past the 3GPP table.
 *   E. truncated attributes (declared length past the capture) are never
 *      stored, so nothing past caplen is read.
 *
 * Positive controls, so an "absent" assertion can never pass vacuously
 * (a frame that is not classified as RADIUS, or not parsed at all, reports
 * nothing): every frame must appear with PROTO_RADIUS in its protocol path,
 * and every absent case carries a valid sibling attribute (NAS-IP-Address
 * or User-Name) placed BEFORE the malformed one, which must be reported
 * from the same packets.
 *
 * Each case uses its own UDP source port (its own session) and is sent
 * twice, as tests/parser_boundaries/test_radius_dns_ipv6_api.c does; frames
 * are exactly-sized heap copies so ASan brackets the capture under
 * SANITIZE=asan.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <pcap.h>            /* DLT_EN10MB */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "tcpip/mmt_tcpip_attributes.h" /* RADIUS_* attribute ids */

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

/* ---- observed attributes ------------------------------------------------ */

enum { A_USER_NAME, A_NAS_IP, A_CALLED_STATION, A_IMSI, A_COUNT };

static const struct { uint32_t id; int binary; } g_attrs[A_COUNT] = {
    [A_USER_NAME]      = { RADIUS_USER_NAME, 1 },
    [A_NAS_IP]         = { RADIUS_NAS_IP_ADDRESS, 0 },
    [A_CALLED_STATION] = { RADIUS_CALLED_STATION_ID, 1 },
    [A_IMSI]           = { RADIUS_3GPP_IMSI, 1 },
};

/* BINARY attributes are a 4-byte length then up to 64 value bytes
 * (BINARY_64DATA_TYPE_LEN = 68); U32 attributes are one uint32_t. */
#define ATTR_BUF 68

typedef struct {
    int      radius;                 /* PROTO_RADIUS in the protocol path */
    int      present[A_COUNT];
    uint32_t len[A_COUNT];           /* BINARY: reported length */
    uint32_t u32[A_COUNT];           /* U32: value */
    uint8_t  raw[A_COUNT][ATTR_BUF]; /* BINARY: the whole attribute buffer */
} obs_t;

#define SENDS 2
static obs_t g_obs[SENDS];
static int   g_pkt;

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    if (g_pkt >= SENDS) return 0;
    obs_t *o = &g_obs[g_pkt];
    if (ipacket->proto_hierarchy != NULL) {
        for (int i = 0; i < ipacket->proto_hierarchy->len; i++)
            if (ipacket->proto_hierarchy->proto_path[i] == PROTO_RADIUS)
                o->radius = 1;
    }
    for (int a = 0; a < A_COUNT; a++) {
        const uint8_t *d = (const uint8_t *)
            get_attribute_extracted_data(ipacket, PROTO_RADIUS, g_attrs[a].id);
        if (d == NULL) continue;
        o->present[a] = 1;
        if (g_attrs[a].binary) {
            memcpy(&o->len[a], d, sizeof(uint32_t));
            memcpy(o->raw[a], d, ATTR_BUF);
        } else {
            memcpy(&o->u32[a], d, sizeof(uint32_t));
        }
    }
    return 0;
}

/* ---- frame builder ------------------------------------------------------ */

static uint8_t  g_attr_bytes[512];
static unsigned g_attr_len;

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

static void attrs_reset(void) { g_attr_len = 0; }

/* Raw attribute bytes, exactly as given (malformed TLVs are spelled out). */
static void raw(const uint8_t *b, unsigned n) {
    if (g_attr_len + n > sizeof(g_attr_bytes)) { fprintf(stderr, "attr overflow\n"); exit(2); }
    memcpy(g_attr_bytes + g_attr_len, b, n);
    g_attr_len += n;
}

/* A well-formed attribute: type, 2 + n, n value bytes. */
static void tlv(uint8_t type, const void *val, unsigned n) {
    uint8_t h[2] = { type, (uint8_t)(2 + n) };
    raw(h, 2);
    raw((const uint8_t *) val, n);
}

/* An attribute of declared length `len` whose value is `len - 2` copies of
 * `fill` (len >= 2). */
static void tlv_fill(uint8_t type, unsigned len, uint8_t fill) {
    uint8_t v[255];
    memset(v, fill, sizeof(v));
    uint8_t h[2] = { type, (uint8_t) len };
    raw(h, 2);
    raw(v, len - 2);
}

static const uint8_t NAS_IP_OK[4] = { 10, 0, 0, 9 };      /* 0x0A000009 */
#define NAS_IP_OK_U32 0x0A000009u
static void sibling_nas_ip(void)    { tlv(4, NAS_IP_OK, 4); }
static void sibling_user_name(void) { tlv(1, "ok", 2); }

#define VENDOR_3GPP 10415u
static const char IMSI[] = "208150123456789";

/* Wraps the attributes in an Access-Request and Ethernet/IPv4/UDP. */
static unsigned build_frame(uint8_t *pkt, uint16_t sport) {
    unsigned rlen = 20 + g_attr_len;
    uint8_t *r = pkt + 14 + 20 + 8;
    r[0] = 1;                                /* Access-Request */
    r[1] = 0x5a;                             /* identifier */
    put_be16(r + 2, (uint16_t) rlen);        /* == UDP payload length */
    memset(r + 4, 0x11, 16);                 /* authenticator */
    memcpy(r + 20, g_attr_bytes, g_attr_len);

    static const uint8_t dst[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t src[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    memcpy(pkt, dst, 6); memcpy(pkt + 6, src, 6); put_be16(pkt + 12, 0x0800);
    uint8_t *ip = pkt + 14;
    memset(ip, 0, 20);
    ip[0] = 0x45; put_be16(ip + 2, (uint16_t)(20 + 8 + rlen));
    ip[8] = 64; ip[9] = 17;
    ip[12] = 10; ip[15] = 1; ip[16] = 10; ip[19] = 2;
    uint8_t *u = pkt + 34;
    put_be16(u, sport); put_be16(u + 2, 1812);
    put_be16(u + 4, (uint16_t)(8 + rlen)); put_be16(u + 6, 0);
    return 42 + rlen;
}

static mmt_handler_t *g_h;
static uint16_t g_sport = 41000;

/* Sends the current attribute set twice on a fresh session. */
static void send_case(void) {
    static uint8_t frame[14 + 20 + 8 + 20 + sizeof(g_attr_bytes)];
    unsigned len = build_frame(frame, g_sport++);
    memset(g_obs, 0, sizeof(g_obs));
    for (g_pkt = 0; g_pkt < SENDS; g_pkt++) {
        uint8_t *data = malloc(len);
        if (!data) { perror("malloc"); exit(2); }
        memcpy(data, frame, len);
        struct pkthdr hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.ts.tv_sec = 1 + g_pkt;
        hdr.caplen = len;
        hdr.len = len;
        packet_process(g_h, &hdr, data);
        free(data);
    }
}

/* ---- case verdicts -------------------------------------------------------- */

static int all_radius(void) {
    for (int i = 0; i < SENDS; i++) if (!g_obs[i].radius) return 0;
    return 1;
}

/* Index of the last packet that reported attribute `a`, or -1. */
static int last_with(int a) {
    for (int i = SENDS - 1; i >= 0; i--) if (g_obs[i].present[a]) return i;
    return -1;
}

static int none_with(int a) { return last_with(a) < 0; }

/* The sibling must be reported by every packet: the same packets then prove
 * the target's absence is the parser's verdict, not a frame it skipped. */
static int all_with(int a) {
    for (int i = 0; i < SENDS; i++) if (!g_obs[i].present[a]) return 0;
    return 1;
}

static void expect_classified(const char *what) {
    char msg[160];
    snprintf(msg, sizeof(msg), "%s: every packet is classified as RADIUS", what);
    CHECK(all_radius(), msg);
}

/* Absent case: `target` reported by no packet, `sibling` by every packet. */
static void expect_absent(const char *what, int target, int sibling) {
    char msg[200];
    expect_classified(what);
    snprintf(msg, sizeof(msg), "%s: sibling attribute ahead of it is reported", what);
    CHECK(all_with(sibling), msg);
    snprintf(msg, sizeof(msg), "%s: not reported", what);
    CHECK(none_with(target), msg);
}

/* BINARY attribute reported with exactly `want_len` copies of `fill`. */
static void expect_binary_fill(const char *what, int a, uint32_t want_len, uint8_t fill) {
    char msg[200];
    expect_classified(what);
    int i = last_with(a);
    snprintf(msg, sizeof(msg), "%s: reported with length %u", what, want_len);
    CHECK(i >= 0 && g_obs[i].len[a] == want_len, msg);
    if (i < 0) return;
    int same = g_obs[i].len[a] == want_len;
    for (uint32_t k = 0; same && k < want_len; k++)
        if (g_obs[i].raw[a][4 + k] != fill) same = 0;
    snprintf(msg, sizeof(msg), "%s: value is the first %u attribute bytes", what, want_len);
    CHECK(same, msg);
}

/* ---- A. TLV length < 2 (F-BUG-102) ------------------------------------- */

/* After a malformed attribute at offset X, the bytes from X+1 read as a
 * well-formed User-Name "evil": a walk that accepted the len-1 attribute
 * (advancing by 1) would report it, one that accepted len 0 never ends. */
static void test_tlv_len_below_2(void) {
    printf("A. attribute length < 2 ends the walk (F-BUG-102)\n");
    static const uint8_t len1[] = { 0x63, 1, 6, 'e', 'v', 'i', 'l' };
    attrs_reset(); sibling_nas_ip(); raw(len1, sizeof(len1));
    send_case();
    expect_absent("len-1 attribute: bytes after it are not parsed as User-Name",
                  A_USER_NAME, A_NAS_IP);

    static const uint8_t len0[] = { 0x63, 0, 1, 6, 'e', 'v', 'i', 'l' };
    attrs_reset(); sibling_nas_ip(); raw(len0, sizeof(len0));
    send_case();
    expect_absent("len-0 attribute: the walk stops (no hang), User-Name after it not parsed",
                  A_USER_NAME, A_NAS_IP);

    attrs_reset(); tlv(1, "", 0); sibling_nas_ip();
    send_case();
    expect_classified("len-2 User-Name (empty value)");
    int i = last_with(A_USER_NAME);
    CHECK(i >= 0 && g_obs[i].len[A_USER_NAME] == 0,
          "len-2 User-Name (empty value): reported with length 0");
    CHECK(all_with(A_NAS_IP),
          "len-2 User-Name (empty value): the walk continues to the next attribute");
}

/* ---- B. value clamps ------------------------------------------------------ */

static void test_value_clamps(void) {
    printf("B. over-long values are clamped to the attribute buffer\n");
    /* The 1-byte-over case first: without the clamp it is reported as 65
     * bytes; the len-255 case would overrun the 68-byte buffer by 189. */
    attrs_reset(); tlv_fill(1, 67, 'C'); sibling_nas_ip();
    send_case();
    expect_binary_fill("User-Name len 67 (value 65)", A_USER_NAME, 64, 'C');

    attrs_reset(); tlv_fill(1, 255, 'A'); sibling_nas_ip();
    send_case();
    expect_binary_fill("User-Name len 255", A_USER_NAME, 64, 'A');

    attrs_reset(); tlv_fill(30, 255, 'B'); sibling_nas_ip();
    send_case();
    expect_binary_fill("Called-Station-Id len 255", A_CALLED_STATION, 63, 'B');
    int i = last_with(A_CALLED_STATION);
    CHECK(i >= 0 && g_obs[i].raw[A_CALLED_STATION][4 + 63] == '\0',
          "Called-Station-Id len 255: value is NUL-terminated at byte 63");
}

/* ---- C. 32-bit attributes ------------------------------------------------- */

static void test_u32_short(void) {
    printf("C. NAS-IP-Address shorter than 6 bytes is rejected\n");
    for (unsigned len = 2; len <= 5; len++) {
        char what[96];
        snprintf(what, sizeof(what), "NAS-IP-Address len %u", len);
        attrs_reset(); sibling_user_name(); tlv_fill(4, len, 0xff);
        send_case();
        expect_absent(what, A_NAS_IP, A_USER_NAME);
    }
    /* First octet below 0x80. */
    static const uint8_t ip[4] = { 100, 64, 1, 10 };
    attrs_reset(); sibling_user_name(); tlv(4, ip, 4);
    send_case();
    expect_classified("NAS-IP-Address len 6");
    int i = last_with(A_NAS_IP);
    CHECK(i >= 0 && g_obs[i].u32[A_NAS_IP] == 0x6440010Au,
          "NAS-IP-Address len 6: reads 100.64.1.10");
    /* First octet >= 0x80: read_be32() (proto_radius.c:49) shifted the
     * int-promoted first byte left by 24, undefined behaviour that UBSan
     * reports under SANITIZE=asan (issue #526); it now shifts uint32_t. */
    static const uint8_t ip_hi[4] = { 192, 168, 1, 10 };
    attrs_reset(); sibling_user_name(); tlv(4, ip_hi, 4);
    send_case();
    expect_classified("NAS-IP-Address len 6, first octet >= 0x80");
    i = last_with(A_NAS_IP);
    CHECK(i >= 0 && g_obs[i].u32[A_NAS_IP] == 0xC0A8010Au,
          "NAS-IP-Address len 6: reads 192.168.1.10");
}

/* ---- D. 3GPP vendor-specific attribute -------------------------------- */

/* VSA = 26, len, vendor id (4), sub-type, sub-len, sub-value. */
static void vsa(uint32_t vendor, uint8_t sub_type, unsigned sub_len,
                const void *sub_val, unsigned sub_val_len) {
    uint8_t h[8] = { 26, (uint8_t)(2 + 4 + 2 + sub_val_len),
                     (uint8_t)(vendor >> 24), (uint8_t)(vendor >> 16),
                     (uint8_t)(vendor >> 8), (uint8_t) vendor,
                     sub_type, (uint8_t) sub_len };
    raw(h, 8);
    raw((const uint8_t *) sub_val, sub_val_len);
}

static void test_vendor_specific(void) {
    printf("D. 3GPP vendor-specific attribute guards\n");
    unsigned n = (unsigned) strlen(IMSI);

    attrs_reset(); sibling_nas_ip(); vsa(VENDOR_3GPP, 1, 2 + n, IMSI, n);
    send_case();
    expect_classified("valid 3GPP IMSI");
    int i = last_with(A_IMSI);
    CHECK(i >= 0 && g_obs[i].len[A_IMSI] == n
          && memcmp(&g_obs[i].raw[A_IMSI][4], IMSI, n) == 0,
          "valid 3GPP IMSI: reported as 208150123456789");

    /* A 4-byte VSA (2-byte value) cannot hold a vendor id. The next
     * attribute (type 0x28, len 0xaf) is laid out so that reading the
     * vendor id across the VSA boundary yields 0x000028af = 10415 (3GPP) and
     * an underflowed remaining length would accept the bytes after it as an
     * IMSI sub-attribute "evil". */
    attrs_reset(); sibling_nas_ip();
    static const uint8_t short_vsa[] = { 26, 4, 0x00, 0x00 };
    raw(short_vsa, sizeof(short_vsa));
    uint8_t next[0xaf];
    memset(next, 0, sizeof(next));
    next[0] = 0x28; next[1] = 0xaf;
    next[2] = 1; next[3] = 6; memcpy(&next[4], "evil", 4);
    raw(next, sizeof(next));
    send_case();
    expect_absent("VSA too short for vendor id + sub-header (value 2 bytes)",
                  A_IMSI, A_NAS_IP);

    /* Sub-attribute declares 20 bytes, 4 remain in the VSA; a trailing
     * attribute keeps an over-read inside the capture. */
    attrs_reset(); sibling_nas_ip(); vsa(VENDOR_3GPP, 1, 20, "XY", 2);
    tlv_fill(0x63, 40, 0);
    send_case();
    expect_absent("IMSI sub-attribute longer than the VSA", A_IMSI, A_NAS_IP);

    attrs_reset(); sibling_nas_ip(); vsa(VENDOR_3GPP, 1, 1, "XY", 2);
    send_case();
    expect_absent("IMSI sub-attribute len 1", A_IMSI, A_NAS_IP);

    attrs_reset(); sibling_nas_ip(); vsa(12345, 1, 2 + n, IMSI, n);
    send_case();
    expect_absent("IMSI sub-attribute under a foreign vendor id (12345)",
                  A_IMSI, A_NAS_IP);

    /* Sub-type 28 is one past the 3GPP table (VENDOR_3GPP_MAX_TLV_TYPE 27):
     * storing it would write just past the per-session context, which ASan
     * reports under SANITIZE=asan. */
    attrs_reset(); sibling_nas_ip(); vsa(VENDOR_3GPP, 28, 2 + n, IMSI, n);
    send_case();
    expect_absent("3GPP sub-attribute type 28 (past the table) is ignored, IMSI not reported",
                  A_IMSI, A_NAS_IP);
}

/* ---- E. truncated attributes ----------------------------------------- */

static void test_truncated(void) {
    printf("E. attributes running past the capture are not stored\n");
    static const uint8_t trunc_user[] = { 1, 40, 'T','T','T','T','T','T','T','T','T','T' };
    attrs_reset(); sibling_nas_ip(); raw(trunc_user, sizeof(trunc_user));
    send_case();
    expect_absent("User-Name declaring 40 bytes, 12 captured", A_USER_NAME, A_NAS_IP);

    static const uint8_t trunc_ip[] = { 4, 6, 1, 2, 3 };
    attrs_reset(); sibling_user_name(); raw(trunc_ip, sizeof(trunc_ip));
    send_case();
    expect_absent("NAS-IP-Address declaring 6 bytes, 5 captured", A_NAS_IP, A_USER_NAME);

    unsigned n = (unsigned) strlen(IMSI);
    uint8_t trunc_vsa[8 + 15];
    trunc_vsa[0] = 26; trunc_vsa[1] = 40;                /* 23 captured */
    trunc_vsa[2] = 0; trunc_vsa[3] = 0; trunc_vsa[4] = 0x28; trunc_vsa[5] = 0xaf;
    trunc_vsa[6] = 1; trunc_vsa[7] = (uint8_t)(2 + n);
    memcpy(&trunc_vsa[8], IMSI, n);
    attrs_reset(); sibling_nas_ip(); raw(trunc_vsa, sizeof(trunc_vsa));
    send_case();
    expect_absent("VSA declaring 40 bytes, 23 captured (IMSI inside)", A_IMSI, A_NAS_IP);
}

int main(void) {
    char errbuf[1024];
    /* Line-buffered: a case that crashes the parser keeps the verdicts
     * printed before it. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (!init_extraction()) {
        fprintf(stderr, "init_extraction failed\n");
        return 2;
    }
    g_h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (g_h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    register_packet_handler(g_h, 1, packet_handler, NULL);
    for (int a = 0; a < A_COUNT; a++) {
        if (register_extraction_attribute(g_h, PROTO_RADIUS, g_attrs[a].id) != true) {
            fprintf(stderr, "register_extraction_attribute(%u) failed\n", g_attrs[a].id);
            mmt_close_handler(g_h);
            close_extraction();
            return 2;
        }
    }

    printf("issue #128 / #526: RADIUS hardening through the shipped parser\n");
    test_tlv_len_below_2();
    test_value_clamps();
    test_u32_short();
    test_vendor_specific();
    test_truncated();

    mmt_close_handler(g_h);
    close_extraction();
    printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}

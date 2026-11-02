/*
 * test_quic_hello_attrs_api.c — quic_ietf.server_name, tls_alpn and tls_ja4
 * from the ClientHello of a client Initial, and the application its SNI
 * names (issue #571).
 *
 * Accuracy-corpus captures (tools/phase0/ci/accuracy/, MMT_ACCURACY_DIR
 * overrides the directory) and crafted frames go through mmt_init_handler +
 * packet_process; per packet the test records the three attributes, the
 * protocol after quic_ietf and the session's classification method:
 *
 *   acc_quic_initial_sni_h3   v1: www.google.com, h3, JA4
 *                             q13d1517h3_8daaf6152771_c39a3682006c (worked
 *                             out from the JA4 specification, not from the
 *                             SDK) on the Initial only; google after
 *                             the last quic_ietf layer on every packet,
 *                             the coalesced server datagram included
 *                             (quic_ietf.quic_ietf.google, then back to
 *                             quic_ietf.google), method HOSTNAME
 *   acc_quic_v2_initial_sni   the same over QUIC v2
 *   acc_quic_initial_split_reordered  nothing on the first Initial (half
 *                             the hello) nor on the server's datagram; the
 *                             facts and google from the second Initial on
 *   hostname_classify off     the facts are reported, no application
 *   acc_quic_positive         filler Initials: no fact, no application
 *   acc_quic_short_header_midflow  1-RTT packets only: quic_ietf from the
 *                             fourth client packet (the sixth packet) on
 *   negatives                 unstable DCID, constant-size TURN ChannelData
 *                             on 443, and the same with an FCS trailer or a
 *                             snap length: no packet is quic_ietf
 *   cleanup (T2)              200 more replays of acc_quic_initial_sni_h3
 *                             leave the heap where 20 did: the session
 *                             cleanup frees the ClientHello facts (glibc
 *                             mallinfo2; under ASan the counter reads 0)
 *   udp->len (B4)             the RFC 9001 A.2 Initial behind UDP lengths
 *                             1208, 0 and 0xffff (bounded by the IP length),
 *                             IPv6, and 7 and 1108 (a datagram below 1,200
 *                             bytes although 1,200 are captured): the SNI
 *                             comes from the UDP length, never caplen
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <pcap.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "protocols/proto_quic_ietf.h"   /* QUIC_IETF_* ids — source tree, not installed */
#include "quic_initial_vectors.h"

static int g_failures = 0;
static int g_checks   = 0;

#define CHECK(cond, ...) do {                                        \
        g_checks++;                                                  \
        if (cond) {                                                  \
            printf("  PASS: ");                                      \
        } else {                                                     \
            printf("  FAIL: ");                                      \
            g_failures++;                                            \
        }                                                            \
        printf(__VA_ARGS__);                                         \
        printf("\n");                                                \
    } while (0)

#define MAX_PACKETS 32
#define JA4_QUIC "q13d1517h3_8daaf6152771_c39a3682006c"

typedef struct {
    char sni[300];
    char alpn[160];
    char ja4[64];
    int quic;          /* quic_ietf layers in the path */
    uint32_t after;    /* protocol after the last quic_ietf layer, 0 = none */
    int tail;          /* layers after the last quic_ietf layer */
    int method;
} seen_t;

static seen_t g_seen[MAX_PACKETS];
static unsigned g_n;

static void copy_line(const mmt_header_line_t *l, char *out, size_t cap) {
    out[0] = '\0';
    if (l != NULL && l->ptr != NULL) {
        size_t n = l->len < cap - 1 ? l->len : cap - 1;
        memcpy(out, l->ptr, n);
        out[n] = '\0';
    }
}

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    if (g_n >= MAX_PACKETS) {
        return 0;
    }
    seen_t *s = &g_seen[g_n++];
    copy_line(get_attribute_extracted_data(ipacket, PROTO_QUIC_IETF, QUIC_IETF_SERVER_NAME), s->sni, sizeof s->sni);
    copy_line(get_attribute_extracted_data(ipacket, PROTO_QUIC_IETF, QUIC_IETF_TLS_ALPN), s->alpn, sizeof s->alpn);
    copy_line(get_attribute_extracted_data(ipacket, PROTO_QUIC_IETF, QUIC_IETF_TLS_JA4), s->ja4, sizeof s->ja4);
    const proto_hierarchy_t *p = ipacket->proto_hierarchy;
    for (int i = 0; p != NULL && i < p->len && i < PROTO_PATH_SIZE; i++) {
        if (p->proto_path[i] == PROTO_QUIC_IETF) {
            s->quic++;
            s->after = (i + 1 < p->len) ? p->proto_path[i + 1] : 0;
            s->tail = p->len - i - 1;
        }
    }
    s->method = get_session_classification_method(ipacket->session);
    return 0;
}

static mmt_handler_t *open_handler(int linktype, int hostname) {
    char errbuf[1024];
    mmt_handler_t *h = mmt_init_handler(linktype, 0, errbuf);
    if (h == NULL) {
        CHECK(0, "mmt_init_handler: %s", errbuf);
        return NULL;
    }
    static const unsigned attrs[] = {QUIC_IETF_SERVER_NAME, QUIC_IETF_TLS_ALPN, QUIC_IETF_TLS_JA4};
    for (size_t i = 0; i < sizeof attrs / sizeof attrs[0]; i++) {
        if (register_extraction_attribute(h, PROTO_QUIC_IETF, attrs[i]) != 1) {
            CHECK(0, "register quic_ietf attribute %u", attrs[i]);
        }
    }
    if (!hostname) {
        disable_hostname_classify(h);
    }
    register_packet_handler(h, 1, packet_handler, NULL);
    memset(g_seen, 0, sizeof g_seen);
    g_n = 0;
    return h;
}

static const char *accuracy_dir(void) {
    static char dir[4096];
    const char *env = getenv("MMT_ACCURACY_DIR");
    if (env != NULL && env[0] != '\0') return env;
    /* __FILE__ = <repo>/tests/parser_boundaries/test_quic_hello_attrs_api.c */
    snprintf(dir, sizeof dir, "%s", __FILE__);
    for (int up = 0; up < 3; up++) {
        char *slash = strrchr(dir, '/');
        if (slash == NULL) return NULL;
        *slash = '\0';
    }
    strncat(dir, "/tools/phase0/ci/accuracy", sizeof(dir) - strlen(dir) - 1);
    return dir;
}

static int g_quiet;

/* Replays one capture through a fresh handler; returns the packets read. */
static unsigned replay(const char *name, int hostname) {
    char path[4200], errbuf[PCAP_ERRBUF_SIZE > 1024 ? PCAP_ERRBUF_SIZE : 1024];
    const char *dir = accuracy_dir();
    snprintf(path, sizeof path, "%s/%s", dir != NULL ? dir : ".", name);
    if (!g_quiet) {
        printf("case %s%s\n", name, hostname ? "" : " (hostname_classify off)");
    }
    pcap_t *pc = pcap_open_offline(path, errbuf);
    if (pc == NULL) {
        CHECK(0, "cannot open %s: %s", path, errbuf);
        return 0;
    }
    mmt_handler_t *h = open_handler(pcap_datalink(pc), hostname);
    if (h == NULL) {
        pcap_close(pc);
        return 0;
    }
    struct pcap_pkthdr ph;
    const u_char *data;
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof hdr);
    while ((data = pcap_next(pc, &ph)) != NULL) {
        hdr.ts = ph.ts;
        hdr.caplen = ph.caplen;
        hdr.len = ph.len;
        packet_process(h, &hdr, data);
    }
    mmt_close_handler(h);
    pcap_close(pc);
    return g_n;
}

static int no_facts(const seen_t *s) {
    return s->sni[0] == '\0' && s->alpn[0] == '\0' && s->ja4[0] == '\0';
}

static int google_facts(const seen_t *s) {
    return strcmp(s->sni, "www.google.com") == 0 && strcmp(s->alpn, "h3") == 0 && strcmp(s->ja4, JA4_QUIC) == 0;
}

static void test_single(const char *name, unsigned packets) {
    unsigned n = replay(name, 1);
    CHECK(n == packets, "%u packets (got %u)", packets, n);
    const seen_t *in = &g_seen[0];
    CHECK(google_facts(in), "client Initial: server_name www.google.com, tls_alpn h3, tls_ja4 %s (got '%s' '%s' '%s')",
          JA4_QUIC, in->sni, in->alpn, in->ja4);
    int later = 1, app = 1;
    for (unsigned i = 0; i < n; i++) {
        later = later && (i == 0 || no_facts(&g_seen[i]));
        app = app && g_seen[i].quic && g_seen[i].after == PROTO_GOOGLE && g_seen[i].tail == 1
              && g_seen[i].method == MMT_CLASSIFICATION_METHOD_HOSTNAME;
    }
    CHECK(later, "the facts are reported on the completing packet only");
    CHECK(app, "every packet: quic_ietf then google, and nothing after it, method HOSTNAME");
    if (packets == 4) {
        CHECK(g_seen[1].quic == 2 && g_seen[2].quic == 1 && g_seen[3].quic == 1,
              "server Initial + Handshake: quic_ietf.quic_ietf.google; the next datagrams quic_ietf.google "
              "(got %d, %d, %d QUIC layers)", g_seen[1].quic, g_seen[2].quic, g_seen[3].quic);
    }
}

static void test_split(void) {
    unsigned n = replay("acc_quic_initial_split_reordered.pcap", 1);
    CHECK(n == 4, "4 packets (got %u)", n);
    CHECK(no_facts(&g_seen[0]) && g_seen[0].quic && g_seen[0].after == 0
          && g_seen[0].method == MMT_CLASSIFICATION_METHOD_DPI,
          "first Initial (bytes 0-200, reversed frames): no fact, no application, method DPI");
    CHECK(no_facts(&g_seen[1]) && g_seen[1].quic == 2 && g_seen[1].after == 0,
          "server Initial + Handshake: coalesced quic_ietf.quic_ietf, no fact");
    CHECK(google_facts(&g_seen[2]) && g_seen[2].after == PROTO_GOOGLE
          && g_seen[2].method == MMT_CLASSIFICATION_METHOD_HOSTNAME,
          "second client Initial completes the hello after the server's datagram: facts, google, HOSTNAME "
          "(got '%s', after %u)", g_seen[2].sni, g_seen[2].after);
    CHECK(no_facts(&g_seen[3]) && g_seen[3].after == PROTO_GOOGLE, "1-RTT packet: google kept, no fact");
}

static void test_hostname_off(void) {
    unsigned n = replay("acc_quic_initial_sni_h3.pcap", 0);
    CHECK(n == 4 && google_facts(&g_seen[0]), "facts reported without hostname classification");
    int app = 0;
    for (unsigned i = 0; i < n; i++) {
        app |= g_seen[i].after != 0;
    }
    CHECK(!app && g_seen[0].method == MMT_CLASSIFICATION_METHOD_DPI, "no application after quic_ietf, method DPI");
}

static void test_filler(void) {
    unsigned n = replay("acc_quic_positive.pcap", 1);
    int quiet = n == 3;
    for (unsigned i = 0; i < n; i++) {
        quiet = quiet && no_facts(&g_seen[i]) && g_seen[i].quic && g_seen[i].after == 0;
    }
    CHECK(quiet, "filler Initials (not ciphertext): quic_ietf, no fact, no application");
}

static void test_midflow(void) {
    unsigned n = replay("acc_quic_short_header_midflow.pcap", 1);
    int early = 0, late = 1;
    for (unsigned i = 0; i < n; i++) {
        if (i < 5) {
            early |= g_seen[i].quic;
        } else {
            late = late && g_seen[i].quic && g_seen[i].method == MMT_CLASSIFICATION_METHOD_DPI;
        }
    }
    CHECK(n == 9 && !early && late, "9 packets: none quic_ietf before the 4th client packet, all from it (DPI)");
}

static void test_negative(const char *name, unsigned packets) {
    unsigned n = replay(name, 1);
    int any = 0;
    for (unsigned i = 0; i < n; i++) {
        any |= g_seen[i].quic;
    }
    CHECK(n == packets && !any, "%u packets, none quic_ietf (got %u packets)", packets, n);
}

/* A session that timed out or outlived its handler is cleaned up by
 * _quic_ietf_session_data_cleanup(), which must free the CRYPTO buffer and
 * the facts (428 B per flow here): 200 more flows must not grow the heap. */
static void test_cleanup(void) {
    printf("case cleanup\n");
    g_quiet = 1;
    for (int i = 0; i < 20; i++) {
        replay("acc_quic_initial_sni_h3.pcap", 1);
    }
    size_t before = mallinfo2().uordblks;
    for (int i = 0; i < 200; i++) {
        replay("acc_quic_initial_sni_h3.pcap", 1);
    }
    size_t after = mallinfo2().uordblks;
    g_quiet = 0;
    size_t grown = after > before ? after - before : 0;
    CHECK(grown < 200 * 428 / 4, "200 more QUIC flows with a ClientHello: the heap grew %zu bytes (< %d)",
          grown, 200 * 428 / 4);
}

/* ---- udp->len (B4) -------------------------------------------------------- */

static uint8_t g_initial[1200];

static void put_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t) (v >> 8); p[1] = (uint8_t) v; }

/* The A.2 Initial behind Ethernet/IPv4 (or IPv6)/UDP with the given UDP
 * length field, in an exact-size heap frame. */
static void run_initial(uint16_t udp_len, int ipv6, const char *what, int want_sni) {
    size_t ipl = ipv6 ? 40 : 20;
    size_t len = 14 + ipl + 8 + sizeof g_initial;
    uint8_t *f = calloc(1, len);
    if (f == NULL) {
        perror("calloc");
        exit(2);
    }
    static const uint8_t mac_a[6] = {0x02, 0, 0, 0, 0, 1}, mac_b[6] = {0x02, 0, 0, 0, 0, 2};
    memcpy(f, mac_b, 6);
    memcpy(f + 6, mac_a, 6);
    put_be16(f + 12, ipv6 ? 0x86dd : 0x0800);
    uint8_t *ip = f + 14;
    if (ipv6) {
        ip[0] = 0x60;
        put_be16(ip + 4, (uint16_t) (8 + sizeof g_initial));
        ip[6] = 17;
        ip[7] = 64;
        ip[8] = 0x20; ip[9] = 0x01; ip[10] = 0x0d; ip[11] = 0xb8; ip[23] = 1;
        ip[24] = 0x20; ip[25] = 0x01; ip[26] = 0x0d; ip[27] = 0xb8; ip[39] = 2;
    } else {
        ip[0] = 0x45;
        put_be16(ip + 2, (uint16_t) (20 + 8 + sizeof g_initial));
        ip[8] = 64;
        ip[9] = 17;
        ip[12] = 10; ip[15] = 1;
        ip[16] = 10; ip[19] = 2;
    }
    uint8_t *udp = ip + ipl;
    put_be16(udp, 50000);
    put_be16(udp + 2, 443);
    put_be16(udp + 4, udp_len);
    memcpy(udp + 8, g_initial, sizeof g_initial);
    mmt_handler_t *h = open_handler(DLT_EN10MB, 1);
    if (h == NULL) {
        free(f);
        return;
    }
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.ts.tv_sec = 1;
    hdr.caplen = (unsigned) len;
    hdr.len = (unsigned) len;
    packet_process(h, &hdr, f);
    mmt_close_handler(h);
    free(f);
    int got = g_n == 1 && strcmp(g_seen[0].sni, "example.com") == 0 && strcmp(g_seen[0].alpn, "alpn") == 0;
    CHECK(g_n == 1 && got == want_sni, "%s: %s (got '%s')", what, want_sni ? "SNI example.com" : "no SNI",
          g_n ? g_seen[0].sni : "");
}

static void test_udp_len(void) {
    printf("case udp->len\n");
    run_initial(1208, 0, "UDP length 1208 (the datagram)", 1);
    run_initial(0, 0, "UDP length 0: the IP payload bounds the datagram", 1);
    run_initial(0xffff, 0, "UDP length 0xffff > IP payload: bounded by the IP payload", 1);
    run_initial(1208, 1, "IPv6, UDP length 1208", 1);
    run_initial(7, 0, "UDP length 7 (below its own header): no datagram", 0);
    run_initial(1108, 0, "UDP length 1108: a 1,100-byte datagram although 1,200 bytes are captured", 0);
}

static void unhex(const char *s, uint8_t *out, size_t cap) {
    size_t n = 0;
    for (; s[0] != '\0' && s[1] != '\0' && n < cap; s += 2) {
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) {
            break;
        }
        out[n++] = (uint8_t) v;
    }
    if (n != cap) {
        fprintf(stderr, "bad test vector\n");
        exit(2);
    }
}

int main(void) {
    unhex(RFC_V1_PROTECTED, g_initial, sizeof g_initial);
    init_extraction();
    printf("issue #571: SNI, ALPN and JA4 from QUIC client Initials\n");
    test_single("acc_quic_initial_sni_h3.pcap", 4);
    test_single("acc_quic_v2_initial_sni.pcap", 2);
    test_split();
    test_hostname_off();
    test_filler();
    test_midflow();
    test_negative("acc_quic_neg_short_header_unstable_dcid.pcap", 10);
    test_negative("acc_quic_neg_turn_channeldata_443.pcap", 12);
    test_negative("acc_quic_neg_turn_channeldata_trailer.pcap", 16);
    test_udp_len();
    test_cleanup();
    close_extraction();
    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    return g_failures == 0 ? 0 : 1;
}

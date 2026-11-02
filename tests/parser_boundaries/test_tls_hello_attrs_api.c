/*
 * test_tls_hello_attrs_api.c — ssl.tls_version, tls_alpn, tls_sni_hidden
 * and tls_ja4 on the packet that carries a ClientHello or ServerHello
 * (issue #569, F-BUG-309).
 *
 * Accuracy-corpus captures (tools/phase0/ci/accuracy/, MMT_ACCURACY_DIR
 * overrides the directory) go through mmt_init_handler + packet_process with
 * the four attributes and ssl.server_name registered; per packet the test
 * records what was extracted:
 *
 *   acc_tls13_alpn_h2       TLS 1.3 ClientHello with the suites, extensions
 *                           and signature algorithms of the FoxIO JA4
 *                           specification example: ALPN h2,http/1.1, version
 *                           0x0304 from supported_versions (the record says
 *                           0x0301), not sni-hidden, the published JA4
 *                           t13d1516h2_8daaf6152771_e5627efa2ab1; the
 *                           ServerHello negotiates 0x0304 (legacy 0x0303)
 *   acc_tls_ech             the same hello with an outer
 *                           encrypted_client_hello: sni-hidden, server_name
 *                           the ECH public name, ECH counted in the JA4
 *   acc_tls_positive        TLS 1.2: version 0x0303 both ways, no ALPN
 *   acc_tls_split_clienthello  a ClientHello over two segments: nothing on
 *                           the first (its record is incomplete), the
 *                           reassembled hello's facts on the second
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

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

#define MAX_PACKETS 16

/* What each packet of the replay carried (-1 / "" when not extracted). */
typedef struct {
    int version;
    int sni_hidden;
    char alpn[160];
    char ja4[64];
    char sni[300];
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
    const uint16_t *v = get_attribute_extracted_data(ipacket, PROTO_SSL, TLS_VERSION);
    const uint8_t *hidden = get_attribute_extracted_data(ipacket, PROTO_SSL, TLS_SNI_HIDDEN);
    s->version = v != NULL ? *v : -1;
    s->sni_hidden = hidden != NULL ? *hidden : -1;
    copy_line(get_attribute_extracted_data(ipacket, PROTO_SSL, TLS_ALPN), s->alpn, sizeof s->alpn);
    copy_line(get_attribute_extracted_data(ipacket, PROTO_SSL, TLS_JA4), s->ja4, sizeof s->ja4);
    copy_line(get_attribute_extracted_data(ipacket, PROTO_SSL, SSL_SERVER_NAME), s->sni, sizeof s->sni);
    return 0;
}

static const char *accuracy_dir(void) {
    static char dir[4096];
    const char *env = getenv("MMT_ACCURACY_DIR");
    if (env != NULL && env[0] != '\0') return env;
    /* __FILE__ = <repo>/tests/parser_boundaries/test_tls_hello_attrs_api.c */
    snprintf(dir, sizeof dir, "%s", __FILE__);
    for (int up = 0; up < 3; up++) {
        char *slash = strrchr(dir, '/');
        if (slash == NULL) return NULL;
        *slash = '\0';
    }
    strncat(dir, "/tools/phase0/ci/accuracy", sizeof(dir) - strlen(dir) - 1);
    return dir;
}

/* Replays one capture through a fresh handler; returns the packets read. */
static unsigned replay(const char *name) {
    char path[4200], errbuf[PCAP_ERRBUF_SIZE > 1024 ? PCAP_ERRBUF_SIZE : 1024];
    const char *dir = accuracy_dir();
    snprintf(path, sizeof path, "%s/%s", dir != NULL ? dir : ".", name);
    printf("case %s\n", name);
    memset(g_seen, 0, sizeof g_seen);
    g_n = 0;
    pcap_t *pc = pcap_open_offline(path, errbuf);
    if (pc == NULL) {
        CHECK(0, "cannot open %s: %s", path, errbuf);
        return 0;
    }
    mmt_handler_t *h = mmt_init_handler(pcap_datalink(pc), 0, errbuf);
    if (h == NULL) {
        CHECK(0, "mmt_init_handler: %s", errbuf);
        pcap_close(pc);
        return 0;
    }
    static const unsigned attrs[] = {TLS_VERSION, TLS_ALPN, TLS_SNI_HIDDEN, TLS_JA4, SSL_SERVER_NAME};
    for (size_t i = 0; i < sizeof attrs / sizeof attrs[0]; i++) {
        if (register_extraction_attribute(h, PROTO_SSL, attrs[i]) != 1) {
            CHECK(0, "register ssl attribute %u", attrs[i]);
        }
    }
    register_packet_handler(h, 1, packet_handler, NULL);
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

/* The three-way handshake carries no TLS: nothing is extracted. */
static void check_handshake_quiet(void) {
    int quiet = 1;
    for (unsigned i = 0; i < 3; i++) {
        quiet = quiet && g_seen[i].version == -1 && g_seen[i].alpn[0] == '\0'
                && g_seen[i].ja4[0] == '\0' && g_seen[i].sni_hidden == -1;
    }
    CHECK(quiet, "SYN / SYN-ACK / ACK: no TLS attribute");
}

static void test_tls13_alpn_h2(void) {
    unsigned n = replay("acc_tls13_alpn_h2.pcap");
    CHECK(n == 5, "5 packets (got %u)", n);
    check_handshake_quiet();
    const seen_t *ch = &g_seen[3], *sh = &g_seen[4];
    CHECK(strcmp(ch->alpn, "h2,http/1.1") == 0, "ClientHello ALPN h2,http/1.1 (got '%s')", ch->alpn);
    CHECK(ch->version == 0x0304, "ClientHello version 0x0304 from supported_versions (got 0x%04x)", ch->version);
    CHECK(ch->sni_hidden == 0, "ClientHello not sni-hidden (got %d)", ch->sni_hidden);
    CHECK(strcmp(ch->ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1") == 0,
          "JA4 = the specification's t13d1516h2_8daaf6152771_e5627efa2ab1 (got '%s')", ch->ja4);
    CHECK(strcmp(ch->sni, "accuracy.example") == 0, "server_name accuracy.example (got '%s')", ch->sni);
    CHECK(sh->version == 0x0304, "ServerHello negotiates 0x0304 (legacy_version 0x0303; got 0x%04x)", sh->version);
    CHECK(sh->alpn[0] == '\0' && sh->ja4[0] == '\0' && sh->sni_hidden == -1,
          "ServerHello: no ALPN (TLS 1.3 sends it encrypted), no JA4, no sni_hidden");
}

static void test_tls_ech(void) {
    unsigned n = replay("acc_tls_ech.pcap");
    CHECK(n == 5, "5 packets (got %u)", n);
    const seen_t *ch = &g_seen[3], *sh = &g_seen[4];
    CHECK(ch->sni_hidden == 1, "ClientHello with an outer ECH is sni-hidden (got %d)", ch->sni_hidden);
    CHECK(strcmp(ch->sni, "public.example") == 0, "server_name is the ECH public name (got '%s')", ch->sni);
    CHECK(strcmp(ch->ja4, "t13d1517h2_8daaf6152771_b1ff8ab2d16f") == 0,
          "JA4 counts encrypted_client_hello (got '%s')", ch->ja4);
    CHECK(ch->version == 0x0304 && sh->version == 0x0304, "TLS 1.3 both ways");
}

static void test_tls12(void) {
    unsigned n = replay("acc_tls_positive.pcap");
    CHECK(n == 5, "5 packets (got %u)", n);
    const seen_t *ch = &g_seen[3], *sh = &g_seen[4];
    CHECK(ch->version == 0x0303 && sh->version == 0x0303,
          "TLS 1.2 hello without supported_versions: 0x0303 both ways (record says 0x0301; got 0x%04x / 0x%04x)",
          ch->version, sh->version);
    CHECK(ch->alpn[0] == '\0' && sh->alpn[0] == '\0', "no ALPN extension: no tls_alpn");
    CHECK(ch->sni_hidden == 0, "no ECH: tls_sni_hidden 0");
    CHECK(strcmp(ch->ja4, "t12d020100_f54dd463d39b_000000000000") == 0,
          "JA4 of a 2-suite, SNI-only hello (got '%s')", ch->ja4);
}

static void test_split(void) {
    unsigned n = replay("acc_tls_split_clienthello.pcap");
    CHECK(n == 6, "6 packets (got %u)", n);
    const seen_t *first = &g_seen[3], *second = &g_seen[4];
    CHECK(first->version == -1 && first->ja4[0] == '\0' && first->sni_hidden == -1 && first->alpn[0] == '\0',
          "first segment (record incomplete): no TLS attribute (got version %d, '%s')", first->version, first->ja4);
    CHECK(strcmp(second->ja4, "t12d020200_f54dd463d39b_4298e3b3ed58") == 0 && second->version == 0x0303
          && second->sni_hidden == 0,
          "completing segment: the reassembled hello's JA4 and version (got '%s', 0x%04x)",
          second->ja4, second->version);
    CHECK(strcmp(second->sni, "www.google.com") == 0, "and its server_name (got '%s')", second->sni);
}

int main(void) {
    printf("=== TLS hello attributes: version, ALPN, ECH, JA4 (issue #569) ===\n");
    init_extraction();
    test_tls13_alpn_h2();
    test_tls_ech();
    test_tls12();
    test_split();
    close_extraction();
    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}

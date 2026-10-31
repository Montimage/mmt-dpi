/*
 * test_classification_method_api.c — how each verdict was reached
 * (issue #567, F-BUG-306).
 *
 * A DPI match, a hostname-table attribution, a correlated inference, an
 * IP-range attribution and a port guess all set the session status to
 * Classified. get_session_classification_method() and the
 * meta.classification_method session attribute tell them apart. Each case
 * replays a capture of the reviewed accuracy corpus
 * (tools/phase0/ci/accuracy/) through mmt_init_handler + packet_process and
 * checks the method of the application verdict it names:
 *
 *   dpi        acc_http_positive         http, matched by its own classifier
 *   hostname   acc_tls_sni_attribution   google, from the TLS SNI
 *   correlated acc_icecast_positive      icecast, inferred beneath HTTP
 *   port       acc_http_negative         http, port 80 guess (port_classify on)
 *   none       acc_unknown_tcp           no application verdict at all
 *   dpi        acc_quic_positive         quic_ietf, a dissector claiming the
 *                                        layer itself (set_classified_proto)
 *   port->dpi  acc_http_positive         port_classify on: the handshake is
 *                                        port-guessed, the request replaces
 *                                        the guess with a DPI match
 *
 * The corpus carries no capture to an address of the compiled-in IP-range
 * table (its captures use RFC 5737 documentation addresses), so the "ip" case
 * is a crafted UDP flow to 66.249.64.10, a PROTO_GOOGLE range of
 * mmt_tcpip_classif_proto_ip_address.inc.
 *
 * On every packet that has a session the attribute must equal the accessor.
 * The corpus is located from this file's path (the runner compiles it by its
 * absolute path); MMT_ACCURACY_DIR overrides it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>

#include <pcap.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

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

/* Link/network/transport layers and the no-verdict marker: never an
 * application verdict (the list of tools/phase0/phase0_precision.c). */
static const char *g_ignore[] = {
    "meta", "ethernet", "ip", "ipv4", "ipv6", "arp", "rarp",
    "tcp", "udp", "sctp", "icmp", "icmpv6", "igmp", "gre",
    "ppp", "pppoe", "vlan", "mpls", "sll", "ipsec", "esp", "ah",
    "unknown", "?", NULL,
};

static int is_ignored(const char *name) {
    for (int i = 0; g_ignore[i] != NULL; i++) {
        if (strcasecmp(name, g_ignore[i]) == 0) return 1;
    }
    return 0;
}

/* Per-case observations. */
static unsigned g_verdicts;       /* packets with an application verdict */
static unsigned g_attr_mismatch;  /* attribute != accessor */
static unsigned g_attr_reads;     /* packets whose attribute was extracted */
static char     g_last_app[64];
static uint8_t  g_last_method;    /* method on the last verdict packet */
static uint8_t  g_max_method;     /* strongest method seen on any packet */
static unsigned g_seen_methods;   /* bit m set: method m seen on some packet */

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    const mmt_session_t *session = get_session_from_packet(ipacket);
    const uint8_t method = get_session_classification_method(session);
    const char *app = NULL;

    if (session != NULL) {
        const uint8_t *attr = get_attribute_extracted_data(
                ipacket, PROTO_META, META_CLASSIFICATION_METHOD);
        if (attr != NULL) {
            g_attr_reads++;
            if (*attr != method) g_attr_mismatch++;
        }
    }
    if (method > g_max_method) g_max_method = method;
    if (method < 32) g_seen_methods |= 1u << method;

    if (ipacket->proto_hierarchy != NULL) {
        for (int i = 0; i < ipacket->proto_hierarchy->len && i < PROTO_PATH_SIZE; i++) {
            const char *name = get_protocol_name_by_id(ipacket->proto_hierarchy->proto_path[i]);
            if (name != NULL && !is_ignored(name)) app = name; /* deepest */
        }
    }
    if (app != NULL) {
        g_verdicts++;
        snprintf(g_last_app, sizeof(g_last_app), "%s", app);
        g_last_method = method;
    }
    return 0;
}

static void reset_case(void) {
    g_verdicts = g_attr_mismatch = g_attr_reads = 0;
    g_last_app[0] = '\0';
    g_last_method = g_max_method = MMT_CLASSIFICATION_METHOD_NONE;
    g_seen_methods = 0;
}

static mmt_handler_t *new_handler(int datalink, int port_classify) {
    char errbuf[1024];
    mmt_handler_t *h = mmt_init_handler(datalink, 0, errbuf);
    if (h == NULL) {
        printf("  FAIL: mmt_init_handler: %s\n", errbuf);
        return NULL;
    }
    if (port_classify) enable_port_classify(h);
    register_extraction_attribute(h, PROTO_META, META_CLASSIFICATION_METHOD);
    register_packet_handler(h, 1, packet_handler, NULL);
    return h;
}

/* Checks the verdict and its method after a case ran. want_app NULL: the case
 * must abstain on every packet and keep the method "none". */
static void check_case(const char *label, const char *want_app, uint8_t want) {
    char msg[256];
    if (want_app == NULL) {
        snprintf(msg, sizeof msg, "%s: no application verdict (%u)", label, g_verdicts);
        CHECK(g_verdicts == 0, msg);
        snprintf(msg, sizeof msg, "%s: method stays none on every packet (max %s)",
                 label, get_classification_method_name(g_max_method));
        CHECK(g_max_method == MMT_CLASSIFICATION_METHOD_NONE, msg);
    } else {
        snprintf(msg, sizeof msg, "%s: verdict %s (got %s)", label, want_app,
                 g_last_app[0] ? g_last_app : "-");
        CHECK(strcasecmp(g_last_app, want_app) == 0, msg);
        snprintf(msg, sizeof msg, "%s: method %s (got %s)", label,
                 get_classification_method_name(want),
                 get_classification_method_name(g_last_method));
        CHECK(g_last_method == want, msg);
    }
    snprintf(msg, sizeof msg, "%s: meta.classification_method read on %u packet(s), "
             "equals the accessor on each (%u mismatch)", label, g_attr_reads, g_attr_mismatch);
    CHECK(g_attr_reads > 0 && g_attr_mismatch == 0, msg);
}

static const char *accuracy_dir(void) {
    static char dir[4096];
    const char *env = getenv("MMT_ACCURACY_DIR");
    if (env != NULL && env[0] != '\0') return env;
    /* __FILE__ = <repo>/tests/parser_boundaries/test_classification_method_api.c */
    snprintf(dir, sizeof dir, "%s", __FILE__);
    for (int up = 0; up < 3; up++) {
        char *slash = strrchr(dir, '/');
        if (slash == NULL) return NULL;
        *slash = '\0';
    }
    strncat(dir, "/tools/phase0/ci/accuracy", sizeof(dir) - strlen(dir) - 1);
    return dir;
}

static void run_pcap(const char *dir, const char *pcap_name, int port_classify,
                     const char *want_app, uint8_t want) {
    char path[4096], errbuf[PCAP_ERRBUF_SIZE];
    snprintf(path, sizeof path, "%s/%s", dir, pcap_name);
    printf("case %s (%s%s)\n", pcap_name, get_classification_method_name(want),
           port_classify ? ", port_classify on" : "");
    pcap_t *pc = pcap_open_offline(path, errbuf);
    if (pc == NULL) {
        printf("  FAIL: cannot open %s: %s\n", path, errbuf);
        g_failures++;
        return;
    }
    reset_case();
    mmt_handler_t *h = new_handler(pcap_datalink(pc), port_classify);
    if (h != NULL) {
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
        check_case(pcap_name, want_app, want);
        mmt_close_handler(h);
    } else {
        g_failures++;
    }
    pcap_close(pc);
}

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

/* The "ip" case: two UDP datagrams 10.9.0.1:40000 <-> 66.249.64.10:40001
 * carrying bytes no classifier claims — only the IP-range table names them. */
static void run_ip_range_case(void) {
    static const uint8_t payload[] = {
        0x8f, 0x13, 0x5a, 0xc4, 0x27, 0x9e, 0x61, 0x0b,
        0xd2, 0x4c, 0xb7, 0x38, 0xe5, 0x70, 0x1f, 0xa9,
    };
    static const uint8_t ip_a[4] = {10, 9, 0, 1}, ip_b[4] = {66, 249, 64, 10};
    uint8_t frame[14 + 20 + 8 + sizeof(payload)];
    printf("case crafted UDP flow to 66.249.64.10 (ip)\n");
    reset_case();
    mmt_handler_t *h = new_handler(DLT_EN10MB, 0);
    if (h == NULL) { g_failures++; return; }
    for (int i = 0; i < 2; i++) {
        const int to_server = (i == 0);
        uint8_t *ip = frame + 14, *udp = frame + 34;
        memset(frame, 0, sizeof frame);
        frame[0] = to_server ? 0x02 : 0x04; frame[6] = to_server ? 0x04 : 0x02;
        put_be16(frame + 12, 0x0800);
        ip[0] = 0x45;
        put_be16(ip + 2, (uint16_t)(20 + 8 + sizeof(payload)));
        ip[8] = 64;
        ip[9] = 17;
        memcpy(ip + 12, to_server ? ip_a : ip_b, 4);
        memcpy(ip + 16, to_server ? ip_b : ip_a, 4);
        put_be16(udp, to_server ? 40000 : 40001);
        put_be16(udp + 2, to_server ? 40001 : 40000);
        put_be16(udp + 4, (uint16_t)(8 + sizeof(payload)));
        memcpy(udp + 8, payload, sizeof(payload));

        struct pkthdr hdr;
        memset(&hdr, 0, sizeof hdr);
        hdr.ts.tv_sec = 1700000000 + i;
        hdr.caplen = hdr.len = sizeof frame;
        packet_process(h, &hdr, frame);
    }
    check_case("crafted ip-range flow", "google", MMT_CLASSIFICATION_METHOD_IP);
    mmt_close_handler(h);
}

int main(void) {
    const char *dir = accuracy_dir();
    if (dir == NULL) {
        fprintf(stderr, "cannot locate the accuracy corpus (set MMT_ACCURACY_DIR)\n");
        return 2;
    }
    init_extraction();

    printf("case accessor and names\n");
    CHECK(get_session_classification_method(NULL) == MMT_CLASSIFICATION_METHOD_NONE,
          "NULL session -> none");
    {
        static const char *names[MMT_CLASSIFICATION_METHOD_NB] = {
            "none", "port", "ip", "correlated", "hostname", "dpi",
        };
        int ok = 1;
        for (int m = 0; m < MMT_CLASSIFICATION_METHOD_NB; m++) {
            const char *n = get_classification_method_name((uint8_t) m);
            if (n == NULL || strcmp(n, names[m]) != 0) ok = 0;
        }
        CHECK(ok, "method names none/port/ip/correlated/hostname/dpi in confidence order");
        CHECK(get_classification_method_name(MMT_CLASSIFICATION_METHOD_NB) == NULL,
              "an out-of-range method has no name");
    }
    {
        const char *attr_name = get_attribute_name_by_protocol_and_attribute_ids(
                PROTO_META, META_CLASSIFICATION_METHOD);
        CHECK(attr_name != NULL && strcmp(attr_name, META_CLASSIFICATION_METHOD_ALIAS) == 0,
              "meta.classification_method is registered under its alias");
    }

    run_pcap(dir, "acc_http_positive.pcap", 0, "http", MMT_CLASSIFICATION_METHOD_DPI);
    run_pcap(dir, "acc_tls_sni_attribution.pcap", 0, "google", MMT_CLASSIFICATION_METHOD_HOSTNAME);
    run_pcap(dir, "acc_icecast_positive.pcap", 0, "icecast", MMT_CLASSIFICATION_METHOD_CORRELATED);
    run_pcap(dir, "acc_http_negative.pcap", 1, "http", MMT_CLASSIFICATION_METHOD_PORT);
    run_pcap(dir, "acc_unknown_tcp.pcap", 0, NULL, MMT_CLASSIFICATION_METHOD_NONE);
    run_pcap(dir, "acc_quic_positive.pcap", 0, "quic_ietf", MMT_CLASSIFICATION_METHOD_DPI);
    run_pcap(dir, "acc_http_positive.pcap", 1, "http", MMT_CLASSIFICATION_METHOD_DPI);
    CHECK(g_seen_methods & (1u << MMT_CLASSIFICATION_METHOD_PORT),
          "acc_http_positive.pcap (port_classify on): an earlier packet was port-guessed "
          "before the DPI match replaced it");
    run_ip_range_case();

    close_extraction();
    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    return g_failures == 0 ? 0 : 1;
}

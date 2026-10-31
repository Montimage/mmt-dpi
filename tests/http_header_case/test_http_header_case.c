/*
 * test_http_header_case.c — regression test for issue #24 (M8):
 *   "Make HTTP header matching case-insensitive".
 *
 * RFC 7230 §3.2 makes HTTP field names case-insensitive, but the line parser
 * in src/mmt_tcpip/lib/mmt_tcpip_utils.c (_mmt_parse_packet_line_info) used to
 * dispatch on the raw first byte and compare the rest of the name with a
 * case-SENSITIVE mmt_memcmp(). A lower- or mixed-case "host:" header therefore
 * never populated packet->host_line, so host-based protocol classification
 * (e.g. recognising "www.facebook.com" -> FACEBOOK) was silently skipped.
 *
 * This test drives synthetic HTTP requests through the real, installed SDK and
 * asserts that the host-based classification fires for ALL of:
 *     "Host:"  (canonical) , "host:" (lower) , "HoSt:" (mixed)
 * On the pre-fix library only the canonical-cased request reaches FACEBOOK; the
 * lower/mixed ones stop at HTTP. On the fixed library all three reach FACEBOOK.
 *
 * It links the installed shared library and is driven by run_tests.sh, which
 * builds+installs the SDK to an isolated prefix and sets up a CWD-relative
 * "plugins/" dir so the freshly built protocol plugins are loaded.
 *
 * Issue #558 adds two checks of the line splitter (now memchr-driven) and of
 * the stream parser (now allocated on the session's first payload packet):
 * a stray CR or a bare LF splits no line — only CRLF does — and the parser
 * still reports every header of the request as an HTTP_HEADER event.
 *
 * Exit status: 0 = all cases classified as expected, non-zero = regression.
 */
#include <stdio.h>
#include <string.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

/* Per-packet observation, refreshed before each packet_process() call. */
static int  g_saw_facebook;
static int  g_saw_http;
static char g_path[512];

/* HTTP_HEADER events of the last packet (issue #558), as "field: value". */
static int  g_nb_headers;
static char g_headers[512];

static void header_handler(const ipacket_t *ipacket, attribute_t *attribute,
                           void *user) {
    const mmt_generic_header_line_t *hdr =
        (const mmt_generic_header_line_t *) attribute->data;
    size_t len = strlen(g_headers);
    (void) ipacket; (void) user;
    if (hdr == NULL || hdr->hfield == NULL || hdr->hvalue == NULL) return;
    g_nb_headers++;
    snprintf(g_headers + len, sizeof(g_headers) - len, "%s%s: %s",
             len ? "|" : "", hdr->hfield, hdr->hvalue);
}

static int classification_handler(const ipacket_t *ipacket, void *user) {
    (void) user;
    const proto_hierarchy_t *ph = ipacket->proto_hierarchy;
    int len = 0, i;
    if (ph == NULL) return 0;
    g_path[0] = '\0';
    for (i = 0; i < ph->len && i < PROTO_PATH_SIZE; i++) {
        const char *name = get_protocol_name_by_id(ph->proto_path[i]);
        if (name == NULL) name = "?";
        len += snprintf(g_path + len, sizeof(g_path) - len,
                        (i == 0) ? "%s" : ".%s", name);
        if (ph->proto_path[i] == PROTO_FACEBOOK) g_saw_facebook = 1;
        if (ph->proto_path[i] == PROTO_HTTP)     g_saw_http     = 1;
        if (len >= (int) sizeof(g_path)) break;
    }
    return 0;
}

/* Build a minimal Ethernet/IPv4/TCP frame carrying the given HTTP payload.
 * src_port is varied per case so each request lands in its own session. */
static int build_frame(unsigned char *buf, const char *payload, int plen,
                       int src_port) {
    int o = 0;
    const unsigned char eth[14] = {
        0,0,0,0,0,1,  0,0,0,0,0,2,  0x08,0x00 };          /* dst, src, IPv4 */
    const int ip_total = 20 + 20 + plen;
    const unsigned char ip[20] = {
        0x45,0x00,(unsigned char)((ip_total>>8)&0xff),(unsigned char)(ip_total&0xff),
        0x00,0x00,0x40,0x00, 0x40,0x06,0x00,0x00,          /* ttl=64, proto=TCP */
        10,0,0,1,  10,0,0,2 };                             /* src/dst IP */
    const unsigned char tcp[20] = {
        (unsigned char)((src_port>>8)&0xff),(unsigned char)(src_port&0xff),
        0x00,0x50,                                          /* dst port 80 */
        0,0,0,1,  0,0,0,0,  0x50,0x18,0xff,0xff, 0,0,0,0 }; /* PSH+ACK */
    memcpy(buf + o, eth, 14); o += 14;
    memcpy(buf + o, ip, 20);  o += 20;
    memcpy(buf + o, tcp, 20); o += 20;
    memcpy(buf + o, payload, plen); o += plen;
    return o;
}

static int classify_request(mmt_handler_t *h, const char *payload, int src_port) {
    unsigned char buf[2048];
    struct pkthdr hdr;
    int n;
    g_saw_facebook = 0;
    g_saw_http     = 0;
    g_path[0]      = '\0';
    g_nb_headers   = 0;
    g_headers[0]   = '\0';
    memset(&hdr, 0, sizeof(hdr));
    n = build_frame(buf, payload, (int) strlen(payload), src_port);
    hdr.len = n;
    hdr.caplen = n;
    packet_process(h, &hdr, buf);
    return g_saw_facebook;
}

struct testcase {
    const char *label;
    const char *payload;
    int         src_port;
    int         facebook; /* expected: the Host header was parsed */
};

int main(void) {
    char errbuf[1024];
    mmt_handler_t *h;
    int failures = 0;
    size_t i;

    /* Only the Host header case differs across the three cases. */
    static const struct testcase cases[] = {
        { "canonical Host:", "GET / HTTP/1.1\r\nHost: www.facebook.com\r\n\r\n", 1001, 1 },
        { "lower   host:",   "GET / HTTP/1.1\r\nhost: www.facebook.com\r\n\r\n", 1002, 1 },
        { "mixed   HoSt:",   "GET / HTTP/1.1\r\nHoSt: www.facebook.com\r\n\r\n", 1003, 1 },
        /* Issue #558: a CR without its LF ends no line, so the next CRLF
         * still starts the Host line ... */
        { "stray CR",        "GET / HTTP/1.1\r\nX-N: a\rb\r\r\nHost: www.facebook.com\r\n\r\n", 1004, 1 },
        /* ... and a bare LF is not a line break: Host stays inside X-N. */
        { "bare LF",         "GET / HTTP/1.1\r\nX-N: a\nHost: www.facebook.com\r\n\r\n", 1005, 0 },
    };

    init_extraction();
    h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "FAIL: mmt_init_handler: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    register_packet_handler(h, 1, classification_handler, NULL);
    if (!register_attribute_handler(h, PROTO_HTTP, HTTP_HEADER, header_handler,
                                    NULL, NULL)) {
        fprintf(stderr, "FAIL: register_attribute_handler(HTTP_HEADER)\n");
        failures++;
    }

    printf("== HTTP case-insensitive header matching (issue #24 / M8) ==\n");
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int ok = classify_request(h, cases[i].payload, cases[i].src_port)
                 == cases[i].facebook;
        printf("  %-16s -> %-40s [%s]\n",
               cases[i].label, g_path, ok ? "PASS" : "FAIL");
        if (!ok) {
            failures++;
            fprintf(stderr,
                "  ✗ %s: expected %s, got '%s'\n", cases[i].label,
                cases[i].facebook ? "FACEBOOK classification"
                                  : "no Host-based classification", g_path);
        }
    }

    /* Issue #558: the stream parser is created on the session's first
     * payload packet and still reports each header of that packet. */
    {
        static const char *want =
            "Host: www.facebook.com|User-Agent: t|Accept: */*";
        classify_request(h, "GET /a HTTP/1.1\r\nHost: www.facebook.com\r\n"
                            "User-Agent: t\r\nAccept: */*\r\n\r\n", 1006);
        int ok = g_nb_headers == 3 && strcmp(g_headers, want) == 0;
        printf("  %-16s -> %-40s [%s]\n", "HTTP_HEADER", g_headers,
               ok ? "PASS" : "FAIL");
        if (!ok) {
            failures++;
            fprintf(stderr, "  ✗ HTTP_HEADER events: got %d '%s', expected 3 '%s'\n",
                    g_nb_headers, g_headers, want);
        }
    }

    mmt_close_handler(h);
    close_extraction();

    if (failures) {
        printf("\n✗ %d/%zu case(s) failed: HTTP header matching is not "
               "case-insensitive, or a line break other than CRLF split a "
               "line\n", failures, sizeof(cases) / sizeof(cases[0]) + 1);
        return 1;
    }
    printf("\n✓ all cases classified as expected — HTTP header matching is "
           "case-insensitive and only CRLF ends a line\n");
    return 0;
}

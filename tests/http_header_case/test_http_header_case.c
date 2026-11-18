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
 * Issue #92: an Icecast or SHOUTcast listener stream — an HTTP request
 * answered by `Server: Icecast...` or by an `ICY 200 OK` status line — is
 * labelled icecast / shoutcast, not http.mpeg: the HTTP checker owns the flow
 * before the Icecast and SHOUTcast checkers see the answer.
 *
 * Issue #116: a session HTTP classified is handed to another protocol after
 * an Upgrade answered by 101 Switching Protocols, and given back. An
 * in-process fake plugin protocol (ce_upgrade, id 990 in the plugin range
 * 950-999) claims the session through an upgrade classifier registered for
 * PROTO_HTTP; its session data carries a canary checked on every call. The
 * cases: the handover itself, an Upgrade after earlier requests, a refused
 * upgrade (HTTP events identical to a run with no plugin), declining and
 * ordered classifiers, the path splice of a VLAN tag appearing and going
 * (IPv4 and IPv6) on a handed-over flow and between the 101 and the packet
 * that applies the handover, and the give-back to HTTP.
 *
 * Issue #115: a child classifier registered under a plugin protocol that a
 * classifier claims above TCP or UDP (fake ids 991-994). Without the opt-in
 * (the control arms) the child is first called once TCP/UDP give up
 * classifying the flow, after 40 packets; with
 * mmt_protocol_set_process_claimed_layer() it is called once on every packet
 * from the claiming one, across that give-up.
 *
 * Exit status: 0 = all cases classified as expected, non-zero = regression.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
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

/* Build a minimal Ethernet[/802.1Q]/IPv4-or-IPv6/TCP frame carrying the
 * given payload. src_port is varied per case so each request lands in its
 * own session. reply: the server's answer on that session (addresses and
 * ports swapped). vlan: an 802.1Q tag before the IP header (issue #116).
 * seq: the TCP sequence number. */
static int build_frame_ex(unsigned char *buf, const char *payload, int plen,
                          int src_port, int reply, int vlan, int ipv6, uint32_t seq) {
    int o = 0, l3, l4;
    const unsigned char eth[12] = { 0,0,0,0,0,1,  0,0,0,0,0,2 };  /* dst, src */
    const unsigned char tag[4] = { 0x81,0x00, 0x00,0x64 };         /* 802.1Q, VLAN 100 */
    const int ip_total = 20 + 20 + plen;
    const unsigned char ip[20] = {
        0x45,0x00,(unsigned char)((ip_total>>8)&0xff),(unsigned char)(ip_total&0xff),
        0x00,0x00,0x40,0x00, 0x40,0x06,0x00,0x00,          /* ttl=64, proto=TCP */
        10,0,0,1,  10,0,0,2 };                             /* src/dst IP */
    const int ip6_payload = 20 + plen;
    const unsigned char ip6[40] = {
        0x60,0x00,0x00,0x00,
        (unsigned char)((ip6_payload>>8)&0xff),(unsigned char)(ip6_payload&0xff),
        0x06,0x40,                                          /* next=TCP, hop limit 64 */
        0xfd,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1,                /* src fd00::1 */
        0xfd,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,2 };              /* dst fd00::2 */
    const unsigned char tcp[20] = {
        (unsigned char)((src_port>>8)&0xff),(unsigned char)(src_port&0xff),
        0x00,0x50,                                          /* dst port 80 */
        (unsigned char)(seq>>24),(unsigned char)(seq>>16),(unsigned char)(seq>>8),(unsigned char)seq,
        0,0,0,0,  0x50,0x18,0xff,0xff, 0,0,0,0 };           /* PSH+ACK */
    memcpy(buf + o, eth, 12); o += 12;
    if (vlan) { memcpy(buf + o, tag, 4); o += 4; }
    buf[o++] = ipv6 ? 0x86 : 0x08;                          /* ethertype */
    buf[o++] = ipv6 ? 0xdd : 0x00;
    l3 = o;
    if (ipv6) { memcpy(buf + o, ip6, 40); o += 40; }
    else      { memcpy(buf + o, ip, 20);  o += 20; }
    l4 = o;
    memcpy(buf + o, tcp, 20); o += 20;
    memcpy(buf + o, payload, plen); o += plen;
    if (reply) {
        unsigned char t[16];
        const int a = ipv6 ? 16 : 4, src = l3 + (ipv6 ? 8 : 12);
        memcpy(t, buf + src, a); memcpy(buf + src, buf + src + a, a); memcpy(buf + src + a, t, a);
        memcpy(t, buf + l4, 2); memcpy(buf + l4, buf + l4 + 2, 2); memcpy(buf + l4 + 2, t, 2);
    }
    return o;
}

static int build_frame(unsigned char *buf, const char *payload, int plen,
                       int src_port, int reply) {
    return build_frame_ex(buf, payload, plen, src_port, reply, 0, 0, 1);
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
    n = build_frame(buf, payload, (int) strlen(payload), src_port, 0);
    hdr.len = n;
    hdr.caplen = n;
    packet_process(h, &hdr, buf);
    return g_saw_facebook;
}

/* Issue #92: a listener's request, then the server's answer on the same
 * session; g_path is the answer's protocol path. */
static void classify_listener(mmt_handler_t *h, const char *request,
                              const char *answer, int src_port) {
    unsigned char buf[2048];
    struct pkthdr hdr;
    int n;
    classify_request(h, request, src_port);
    g_path[0] = '\0';
    memset(&hdr, 0, sizeof(hdr));
    n = build_frame(buf, answer, (int) strlen(answer), src_port, 1);
    hdr.len = n;
    hdr.caplen = n;
    packet_process(h, &hdr, buf);
}

/* ---------------- issue #116: HTTP upgrade hand-off ---------------------- */

#define UPG_PROTO  990        /* plugin id range 950-999 (docs/Add-New-Protocol.md) */
#define UPG_NAME   "ce_upgrade"
#define UPG_MAGIC  0x55504721u

/* The fake plugin's session data: a canary HTTP's parser would overwrite if
 * it ever ran on the plugin's slot. */
typedef struct upg_data {
    uint32_t magic;
    struct upg_data *self;
    int calls;
} upg_data_t;

static int g_upg_init, g_upg_cleanup, g_upg_analyse, g_upg_bad;
static upg_data_t *g_upg_last;      /* the block the last analysis saw */
static unsigned g_upg_last_index;   /* and its index */
static int g_upg_give_back;         /* the next analysis hands back to HTTP */
static int g_upg_gave_back;         /* mmt_session_handover()'s result */

static void upg_init(ipacket_t *ipacket, unsigned index) {
    upg_data_t *d;
    if (get_proto_session_data(ipacket->session, index) != NULL) return;
    d = (upg_data_t *) calloc(1, sizeof(*d));
    if (d == NULL) return;
    d->magic = UPG_MAGIC;
    d->self = d;
    set_proto_session_data(ipacket->session, d, index);
    g_upg_init++;
}

static void upg_cleanup(mmt_session_t *session, unsigned index) {
    upg_data_t *d = (upg_data_t *) get_proto_session_data(session, index);
    if (d == NULL) return; /* cleanup hooks tolerate an empty slot */
    if (d->magic != UPG_MAGIC || d->self != d) g_upg_bad++;
    d->magic = 0;
    free(d);
    set_proto_session_data(session, NULL, index);
    g_upg_cleanup++;
}

static int upg_analyse(ipacket_t *ipacket, unsigned index) {
    upg_data_t *d = (upg_data_t *) get_proto_session_data(ipacket->session, index);
    g_upg_analyse++;
    if (d == NULL || d->magic != UPG_MAGIC || d->self != d) {
        g_upg_bad++;
        return MMT_CONTINUE;
    }
    d->calls++;
    g_upg_last = d;
    g_upg_last_index = index;
    if (g_upg_give_back) {
        g_upg_give_back = 0;
        g_upg_gave_back = mmt_session_handover(ipacket, index, PROTO_HTTP);
    }
    return MMT_CONTINUE;
}

static int register_upgrade_protocol(void) {
    protocol_t *p = init_protocol_struct_for_registration(UPG_PROTO, UPG_NAME);
    if (p == NULL) return 0;
    register_session_data_initialization_function(p, upg_init);
    register_session_data_cleanup_function(p, upg_cleanup);
    register_session_data_analysis_function(p, upg_analyse);
    return register_protocol(p, UPG_PROTO) == PROTO_REGISTERED;
}

/* Upgrade classifiers: they are process-wide and cannot be unregistered, so
 * the test registers them one by one and they decide by test-controlled
 * state. g_order records the call order. */
static int  g_cls_decline, g_cls_claim, g_cls_third, g_claim_enabled;
static char g_order[16];

static void order_add(char c) {
    size_t n = strlen(g_order);
    if (n + 1 < sizeof(g_order)) { g_order[n] = c; g_order[n + 1] = '\0'; }
}
static int cls_decline(ipacket_t *ipacket, unsigned index) {
    (void) ipacket; (void) index;
    g_cls_decline++;
    order_add('D');
    return 0;
}
static int cls_claim(ipacket_t *ipacket, unsigned index) {
    g_cls_claim++;
    order_add('C');
    if (g_claim_enabled) (void) mmt_session_handover(ipacket, index, UPG_PROTO);
    return MMT_CLASSIFY_MATCHED;
}
static int cls_third(ipacket_t *ipacket, unsigned index) {
    (void) ipacket; (void) index;
    g_cls_third++;
    order_add('T');
    return 0;
}

/* One direction-aware TCP flow: the sequence number advances per direction. */
typedef struct {
    int port;
    int ipv6;
    uint32_t seq[2];
} upg_flow_t;

static char g_log[4096]; /* path{headers}; per packet, for the refused-upgrade comparison */

/* Sends one segment; g_path / g_headers then describe that packet. */
static void upg_send(mmt_handler_t *h, upg_flow_t *f, int reply, int vlan,
                     const char *payload, int plen, int log) {
    unsigned char buf[2048];
    struct pkthdr hdr;
    int n;
    g_path[0] = '\0';
    g_nb_headers = 0;
    g_headers[0] = '\0';
    memset(&hdr, 0, sizeof(hdr));
    n = build_frame_ex(buf, payload, plen, f->port, reply, vlan, f->ipv6, f->seq[reply]);
    f->seq[reply] += (uint32_t) plen;
    hdr.len = n;
    hdr.caplen = n;
    packet_process(h, &hdr, buf);
    if (log) {
        size_t len = strlen(g_log);
        snprintf(g_log + len, sizeof(g_log) - len, "%s{%s};", g_path, g_headers);
    }
}

static int ends_with(const char *s, const char *suffix) {
    size_t a = strlen(s), b = strlen(suffix);
    return a >= b && strcmp(s + a - b, suffix) == 0;
}
static int path_depth(const char *s) {
    int d = 1;
    for (; *s; s++) d += (*s == '.');
    return d;
}

static const char UPG_REQ[] =
    "GET /chat HTTP/1.1\r\nHost: ws.example\r\nUpgrade: websocket\r\n"
    "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n\r\n";
static const char UPG_101[] =
    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
    "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
static const char UPG_200[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
static const char UPG_NEXT[] = "GET /next HTTP/1.1\r\nHost: ws.example\r\n\r\n";
static const char WS_SERVER[] = "\x81\x0bhello world";                        /* text frame */
static const char WS_CLIENT[] = "\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58"; /* masked "Hello" */

#define UPG_SEND(h, f, reply, vlan, msg, log) \
    upg_send((h), (f), (reply), (vlan), (msg), (int) sizeof(msg) - 1, (log))

static int upg_failures;
#define UPG_CHECK(cond, label) do { \
        int ok_ = (cond) ? 1 : 0; \
        printf("  %-16s -> %-40s [%s]\n", "upgrade", (label), ok_ ? "PASS" : "FAIL"); \
        if (!ok_) { upg_failures++; fprintf(stderr, "  ✗ %s (path '%s')\n", (label), g_path); } \
    } while (0)

/* An Upgrade request refused with 200, then another request on the same
 * connection; g_log gets each packet's path and HTTP_HEADER events. */
static void refused_upgrade(mmt_handler_t *h, int port) {
    upg_flow_t f = { port, 0, { 1000, 5000 } };
    g_log[0] = '\0';
    UPG_SEND(h, &f, 0, 0, UPG_REQ, 1);
    UPG_SEND(h, &f, 1, 0, UPG_200, 1);
    UPG_SEND(h, &f, 0, 0, UPG_NEXT, 1);
}

/* Upgrade + 101, then one server frame: the frame is the plugin's. */
static void claimed_upgrade(mmt_handler_t *h, upg_flow_t *f) {
    UPG_SEND(h, f, 0, 0, UPG_REQ, 0);
    UPG_SEND(h, f, 1, 0, UPG_101, 0);
    UPG_SEND(h, f, 1, 0, WS_SERVER, 0);
}

/* T1': the IP layer of a handed-over flow moves (a VLAN tag appears, then
 * goes): the plugin keeps its own block at the shifted index. */
static void splice_case(mmt_handler_t *h, int port, int ipv6, const char *label) {
    char msg[128];
    upg_flow_t f = { port, ipv6, { 1000, 5000 } };
    int bad = g_upg_bad;
    claimed_upgrade(h, &f);
    UPG_SEND(h, &f, 0, 0, WS_CLIENT, 0);
    upg_data_t *mine = g_upg_last;
    unsigned index = g_upg_last_index;
    int depth = path_depth(g_path);
    snprintf(msg, sizeof(msg), "%s handed over", label);
    UPG_CHECK(ends_with(g_path, ".tcp." UPG_NAME) && mine != NULL, msg);
    UPG_SEND(h, &f, 1, 1, WS_SERVER, 0);
    snprintf(msg, sizeof(msg), "%s + VLAN: same block, index+1", label);
    UPG_CHECK(ends_with(g_path, ".tcp." UPG_NAME) && path_depth(g_path) == depth + 1
              && g_upg_last == mine && g_upg_last_index == index + 1 && g_upg_bad == bad, msg);
    UPG_SEND(h, &f, 0, 1, WS_CLIENT, 0);
    UPG_CHECK(g_upg_last == mine && g_upg_last_index == index + 1 && g_upg_bad == bad,
              "the tagged flow stays the plugin's");
    UPG_SEND(h, &f, 1, 0, WS_SERVER, 0);
    snprintf(msg, sizeof(msg), "%s untagged again: index", label);
    UPG_CHECK(ends_with(g_path, ".tcp." UPG_NAME) && path_depth(g_path) == depth
              && g_upg_last == mine && g_upg_last_index == index && g_upg_bad == bad
              && mine->magic == UPG_MAGIC, msg);
}

/* The two directions differ in encapsulation: the Upgrade and the 101 travel
 * untagged, the client's frames tagged. The 101 queues the handover; the
 * next client frame makes the IP sessionizer splice the path before the
 * handover is applied, so it must apply on that frame, at the moved index. */
static void pending_splice_case(mmt_handler_t *h, int port, int ipv6, const char *label) {
    char msg[128];
    upg_flow_t f = { port, ipv6, { 1000, 5000 } };
    int bad = g_upg_bad, init = g_upg_init, analysed, depth, ok;
    unsigned index;
    upg_data_t *mine;
    UPG_SEND(h, &f, 0, 0, UPG_REQ, 0);
    UPG_SEND(h, &f, 1, 0, UPG_101, 0);
    depth = path_depth(g_path);
    index = (unsigned) depth - 1; /* http's index on the untagged path */
    snprintf(msg, sizeof(msg), "%s 101 untagged is http", label);
    UPG_CHECK(ends_with(g_path, ".tcp.http") && g_upg_init == init, msg);
    analysed = g_upg_analyse;
    g_upg_last = NULL;
    UPG_SEND(h, &f, 0, 1, WS_CLIENT, 0);
    mine = g_upg_last;
    snprintf(msg, sizeof(msg), "%s tagged next frame applies it", label);
    UPG_CHECK(ends_with(g_path, ".tcp." UPG_NAME) && path_depth(g_path) == depth + 1
              && g_upg_init == init + 1 && g_upg_analyse == analysed + 1
              && mine != NULL && g_upg_last_index == index + 1 && g_upg_bad == bad, msg);
    ok = 1;
    UPG_SEND(h, &f, 1, 0, WS_SERVER, 0);
    ok = ok && ends_with(g_path, ".tcp." UPG_NAME) && path_depth(g_path) == depth
         && g_upg_last == mine && g_upg_last_index == index;
    UPG_SEND(h, &f, 0, 1, WS_CLIENT, 0);
    ok = ok && ends_with(g_path, ".tcp." UPG_NAME) && path_depth(g_path) == depth + 1
         && g_upg_last == mine && g_upg_last_index == index + 1;
    UPG_SEND(h, &f, 1, 0, WS_SERVER, 0);
    ok = ok && ends_with(g_path, ".tcp." UPG_NAME) && g_upg_last == mine && g_upg_last_index == index;
    snprintf(msg, sizeof(msg), "%s both ways stay the plugin's (canary)", label);
    UPG_CHECK(ok && g_upg_init == init + 1 && g_upg_bad == bad && mine != NULL
              && mine->magic == UPG_MAGIC && mine->self == mine && mine->calls == 4, msg);
}

static void upgrade_tests(mmt_handler_t *h, const char *baseline) {
    upg_flow_t f;
    int n;

    printf("== HTTP upgrade hand-off (issue #116) ==\n");
    /* Q3': a refused upgrade with the plugin protocol registered but no
     * upgrade classifier, then with one that declines */
    refused_upgrade(h, 2002);
    printf("  baseline: %s\n", baseline);
    UPG_CHECK(strstr(baseline, "Upgrade: websocket") != NULL && strstr(baseline, ".tcp.http{") != NULL,
              "baseline recorded the refused upgrade");
    /* llhttp is not resumed: the request parser paused by the Upgrade
     * request reports nothing for the next request, as before #116 */
    UPG_CHECK(ends_with(baseline, ".tcp.http{};"), "baseline: no events after the Upgrade request");
    UPG_CHECK(strcmp(g_log, baseline) == 0, "refused, no classifier = no plugin");
    if (!register_upgrade_classification_function(PROTO_HTTP, cls_decline, 10)) upg_failures++;
    refused_upgrade(h, 2003);
    UPG_CHECK(strcmp(g_log, baseline) == 0 && g_cls_decline == 0,
              "refused, declining classifier = no plugin, not offered");

    /* T2: a 101 the only classifier declines stays HTTP and is offered once */
    f = (upg_flow_t) { 2004, 0, { 1000, 5000 } };
    UPG_SEND(h, &f, 0, 0, UPG_REQ, 0);
    UPG_SEND(h, &f, 1, 0, UPG_101, 0);
    UPG_SEND(h, &f, 1, 0, WS_SERVER, 0);
    n = ends_with(g_path, ".tcp.http");
    UPG_SEND(h, &f, 1, 0, WS_SERVER, 0);
    n = n && ends_with(g_path, ".tcp.http");
    UPG_SEND(h, &f, 1, 0, WS_SERVER, 0);
    UPG_CHECK(n && ends_with(g_path, ".tcp.http") && g_cls_decline == 1,
              "declined 101: offered once, stays http");

    /* (a) + T2: two more classifiers; the first declines, the second claims,
     * the third (registered after the claimer) is never called */
    if (!register_upgrade_classification_function(PROTO_HTTP, cls_claim, 20)) upg_failures++;
    if (!register_upgrade_classification_function(PROTO_HTTP, cls_third, 30)) upg_failures++;
    g_claim_enabled = 1;
    g_cls_decline = 0;
    g_order[0] = '\0';
    f = (upg_flow_t) { 2005, 0, { 1000, 5000 } };
    UPG_SEND(h, &f, 0, 0, UPG_REQ, 0);
    UPG_CHECK(ends_with(g_path, ".tcp.http"), "Upgrade request is http");
    UPG_SEND(h, &f, 1, 0, UPG_101, 0);
    UPG_CHECK(ends_with(g_path, ".tcp.http"), "the 101 itself is still http");
    UPG_CHECK(g_cls_decline == 1 && g_cls_claim == 1 && g_cls_third == 0 && strcmp(g_order, "DC") == 0,
              "weight order, stop on the claim");
    UPG_CHECK(g_upg_init == 0, "only queued: no plugin init yet");
    UPG_SEND(h, &f, 1, 0, WS_SERVER, 0);
    upg_data_t *mine = g_upg_last;
    UPG_CHECK(ends_with(g_path, ".tcp." UPG_NAME) && g_upg_init == 1 && mine != NULL
              && mine->calls == 1, "next packet is the plugin's");
    UPG_SEND(h, &f, 0, 0, WS_CLIENT, 0);
    UPG_SEND(h, &f, 1, 0, WS_SERVER, 0);
    UPG_CHECK(ends_with(g_path, ".tcp." UPG_NAME) && g_upg_last == mine && mine->calls == 3
              && g_upg_init == 1 && g_upg_bad == 0, "plugin keeps its own data (canary)");
    UPG_CHECK(g_cls_decline == 1 && g_cls_claim == 1 && g_cls_third == 0, "never offered again");

    /* (b) an Upgrade after an earlier request on the same connection */
    f = (upg_flow_t) { 2006, 0, { 1000, 5000 } };
    UPG_SEND(h, &f, 0, 0, UPG_NEXT, 0);
    UPG_SEND(h, &f, 1, 0, UPG_200, 0);
    n = ends_with(g_path, ".tcp.http");
    claimed_upgrade(h, &f);
    UPG_CHECK(n && ends_with(g_path, ".tcp." UPG_NAME) && g_cls_claim == 2,
              "Upgrade after a request is handed over");

    /* (e) T1': the IP layer moves under a handed-over flow */
    splice_case(h, 2007, 0, "IPv4");
    splice_case(h, 2008, 1, "IPv6");
    pending_splice_case(h, 2010, 0, "IPv4");
    pending_splice_case(h, 2011, 1, "IPv6");

    /* (f) give-back: the plugin hands the session back to HTTP, which starts
     * on a fresh parser (the request parser it had was paused by the
     * Upgrade request, so only a new one reports headers) */
    f = (upg_flow_t) { 2009, 0, { 1000, 5000 } };
    claimed_upgrade(h, &f);
    int cleaned = g_upg_cleanup;
    g_upg_give_back = 1;
    UPG_SEND(h, &f, 0, 0, WS_CLIENT, 0);
    UPG_CHECK(g_upg_gave_back == 1 && ends_with(g_path, ".tcp." UPG_NAME) && g_upg_cleanup == cleaned,
              "give-back queued on the plugin's packet");
    UPG_SEND(h, &f, 0, 0, "GET /back HTTP/1.1\r\nHost: ws.example\r\nX-Back: 1\r\n\r\n", 0);
    UPG_CHECK(ends_with(g_path, ".tcp.http") && g_upg_cleanup == cleaned + 1,
              "given back: http, plugin data released");
    UPG_CHECK(g_nb_headers == 2 && strcmp(g_headers, "Host: ws.example|X-Back: 1") == 0,
              "HTTP parses again on a fresh parser");
}

/* ------- issue #115: a child classifier under a plugin protocol ----------- */

/* Fake plugin protocols P (plugin range 950-999) claimed above TCP or UDP by
 * one classifier, which recognises "MMT115-<id>" anywhere in the frame and
 * declines everything else; one child classifier registered under every P
 * counts its calls per packet. The opted-in arms set
 * mmt_protocol_set_process_claimed_layer(). */
#define CH_TCP      991   /* above TCP, not opted in (control) */
#define CH_TCP_OPT  992   /* above TCP, opted in */
#define CH_UDP      993   /* above UDP, not opted in (control) */
#define CH_UDP_OPT  994   /* above UDP, opted in */
#define CH_PACKETS  45    /* crosses the 2 * CFG_CLASSIFICATION_THRESHOLD = 40 give-up */
#define CH_MAX_ID   995

static int g_ch_pkt;                         /* 1-based packet number of the flow */
static int g_ch_child[CH_PACKETS + 1];       /* child calls per packet */
static int g_ch_claim[CH_PACKETS + 1];       /* P claims per packet */
static int g_ch_analyse[CH_PACKETS + 1];     /* P layer analyses per packet */
static int g_ch_init[CH_PACKETS + 1];        /* P session-data inits per packet */
static int g_ch_init_late;                   /* an analysis that ran before any init */
static int g_ch_failures;

static int ch_parent_id(const ipacket_t *ipacket) {
    const unsigned char *d = ipacket->data;
    unsigned n = ipacket->p_hdr->caplen, i;
    for (i = 0; i + 10 <= n; i++) {
        if (memcmp(d + i, "MMT115-", 7) == 0) {
            int id = (d[i + 7] - '0') * 100 + (d[i + 8] - '0') * 10 + (d[i + 9] - '0');
            return (id >= CH_TCP && id <= CH_MAX_ID) ? id : 0;
        }
    }
    return 0;
}

/* P's classifier, registered under PROTO_TCP and PROTO_UDP: even ids sit on
 * one transport, odd on the other (CH_TCP / CH_TCP + 1 above TCP, CH_UDP /
 * CH_UDP + 1 above UDP). */
static int ch_claim(ipacket_t *ipacket, unsigned index) {
    int id = ch_parent_id(ipacket);
    int on_tcp = ipacket->proto_hierarchy->proto_path[index] == PROTO_TCP;
    classified_proto_t c;
    if (id == 0 || on_tcp != (id < CH_UDP)) return 0;
    c.proto_id = (mmt_proto_id_t) id;
    c.offset = on_tcp ? 20 : 8;
    c.status = Classified;
    if (!set_classified_proto(ipacket, index + 1, c)) return 0;
    if (g_ch_pkt > 0 && g_ch_pkt <= CH_PACKETS) g_ch_claim[g_ch_pkt]++;
    return MMT_CLASSIFY_MATCHED;
}

/* The child: registered under every P, it only counts (and declines). */
static int ch_child(ipacket_t *ipacket, unsigned index) {
    (void) ipacket; (void) index;
    if (g_ch_pkt > 0 && g_ch_pkt <= CH_PACKETS) g_ch_child[g_ch_pkt]++;
    return 0;
}

static int ch_analyse(ipacket_t *ipacket, unsigned index) {
    int i, inits = 0;
    (void) ipacket; (void) index;
    if (g_ch_pkt > 0 && g_ch_pkt <= CH_PACKETS) {
        g_ch_analyse[g_ch_pkt]++;
        for (i = 1; i <= g_ch_pkt; i++) inits += g_ch_init[i];
        if (inits == 0) g_ch_init_late++;
    }
    return MMT_CONTINUE;
}

static void ch_init(ipacket_t *ipacket, unsigned index) {
    (void) ipacket; (void) index;
    if (g_ch_pkt > 0 && g_ch_pkt <= CH_PACKETS) g_ch_init[g_ch_pkt]++;
}

static int ch_register(int id, const char *name, int opt_in) {
    protocol_t *p = init_protocol_struct_for_registration(id, name);
    if (p == NULL) return 0;
    if (opt_in && !mmt_protocol_set_process_claimed_layer(p, true)) return 0;
    register_session_data_initialization_function(p, ch_init);
    register_session_data_analysis_function(p, ch_analyse);
    if (register_protocol(p, id) != PROTO_REGISTERED) return 0;
    return register_classification_function_with_parent_protocol(id, ch_child, 10);
}

static int ch_register_all(void) {
    int ok = ch_register(CH_TCP, "ch_tcp", 0) && ch_register(CH_TCP_OPT, "ch_tcp_opt", 1)
        && ch_register(CH_UDP, "ch_udp", 0) && ch_register(CH_UDP_OPT, "ch_udp_opt", 1);
    /* weight 1: P's classifier is tried before the in-tree checkers */
    return ok && register_classification_function_with_parent_protocol(PROTO_TCP, ch_claim, 1)
              && register_classification_function_with_parent_protocol(PROTO_UDP, ch_claim, 1);
}

/* Ethernet/IPv4/TCP-or-UDP frame, client 10.0.0.1:sport -> 10.0.0.2:dport. */
static int build_l4_frame(unsigned char *buf, const char *payload, int plen,
                          int sport, int dport, int udp, uint32_t seq) {
    int o = 0, l4len = udp ? 8 : 20;
    const int ip_total = 20 + l4len + plen;
    const unsigned char eth[14] = { 0,0,0,0,0,1, 0,0,0,0,0,2, 0x08,0x00 };
    const unsigned char ip[20] = {
        0x45,0x00,(unsigned char)((ip_total>>8)&0xff),(unsigned char)(ip_total&0xff),
        0x00,0x00,0x40,0x00, 0x40,(unsigned char)(udp ? 0x11 : 0x06),0x00,0x00,
        10,0,0,1,  10,0,0,2 };
    memcpy(buf + o, eth, 14); o += 14;
    memcpy(buf + o, ip, 20);  o += 20;
    buf[o++] = (unsigned char)(sport >> 8); buf[o++] = (unsigned char) sport;
    buf[o++] = (unsigned char)(dport >> 8); buf[o++] = (unsigned char) dport;
    if (udp) {
        buf[o++] = (unsigned char)((8 + plen) >> 8); buf[o++] = (unsigned char)(8 + plen);
        buf[o++] = 0; buf[o++] = 0;
    } else {
        const unsigned char rest[16] = {
            (unsigned char)(seq>>24),(unsigned char)(seq>>16),(unsigned char)(seq>>8),(unsigned char)seq,
            0,0,0,0, 0x50,0x18,0xff,0xff, 0,0,0,0 };      /* PSH+ACK */
        memcpy(buf + o, rest, 16); o += 16;
    }
    memcpy(buf + o, payload, plen); o += plen;
    return o;
}

/* Sends CH_PACKETS packets of one flow claimed by P = id and checks where
 * the child was called. opted_in: the child must run on every packet; else
 * (today's behaviour) on none of packets 1-40 and only after the give-up. */
static void ch_flow(mmt_handler_t *h, int id, int sport, int opted_in, const char *label) {
    unsigned char buf[256];
    char payload[64], want[32];
    struct pkthdr hdr;
    int udp = id >= CH_UDP, i, n, plen, path_ok = 1, first = 0, early = 0, late = 0;
    int claims = 0, analysed_early = 0, every = 1, inits = 0;
    uint32_t seq = 1000;
    memset(g_ch_child, 0, sizeof(g_ch_child));
    memset(g_ch_claim, 0, sizeof(g_ch_claim));
    memset(g_ch_analyse, 0, sizeof(g_ch_analyse));
    memset(g_ch_init, 0, sizeof(g_ch_init));
    g_ch_init_late = 0;
    snprintf(want, sizeof(want), ".%s.%s", udp ? "udp" : "tcp", get_protocol_name_by_id(id));
    for (i = 1; i <= CH_PACKETS; i++) {
        plen = snprintf(payload, sizeof(payload), "MMT115-%d packet %02d", id, i);
        memset(&hdr, 0, sizeof(hdr));
        n = build_l4_frame(buf, payload, plen, sport, 40000 + id, udp, seq);
        seq += (uint32_t) plen;
        hdr.len = n;
        hdr.caplen = n;
        g_path[0] = '\0';
        g_ch_pkt = i;
        packet_process(h, &hdr, buf);
        g_ch_pkt = 0;
        if (!ends_with(g_path, want)) path_ok = 0;
        claims += g_ch_claim[i];
        inits += g_ch_init[i];
        if (g_ch_child[i] && first == 0) first = i;
        if (i <= 40) { early += g_ch_child[i]; analysed_early += g_ch_analyse[i]; }
        else late += g_ch_child[i];
        if (g_ch_child[i] != 1) every = 0; /* once per packet, never twice */
    }
    printf("  %-16s -> P claims %d, P inits %d (packet 1: %d, analysis before init: %d), "
           "P analysed on 1-40: %d, child on 1-40: %d, after: %d, first: %d\n",
           label, claims, inits, g_ch_init[1], g_ch_init_late, analysed_early, early, late, first);
    int ok = path_ok && g_ch_claim[1] == 1;
    /* the layer's session data is initialised on the claiming packet, before
     * its first analysis (init runs again on each re-claim: it is idempotent) */
    if (opted_in) ok = ok && every && first == 1 && analysed_early == 40
                     && g_ch_init[1] == 1 && g_ch_init_late == 0;
    else ok = ok && early == 0 && analysed_early == 0 && late > 0 && first > 40;
    printf("  %-16s -> %-40s [%s]\n", label, opted_in ? "child on every packet from the claim"
           : "child only after the give-up (control)", ok ? "PASS" : "FAIL");
    if (!ok) {
        g_ch_failures++;
        fprintf(stderr, "  ✗ %s: path %s (want *%s), claim on packet 1: %d\n",
                label, path_ok ? "ok" : g_path, want, g_ch_claim[1]);
    }
}

static void child_tests(mmt_handler_t *h) {
    printf("== a child classifier under a plugin protocol (issue #115) ==\n");
    ch_flow(h, CH_TCP, 3001, 0, "TCP, no opt-in");
    ch_flow(h, CH_UDP, 3003, 0, "UDP, no opt-in");
    ch_flow(h, CH_TCP_OPT, 3002, 1, "TCP, opted in");
    ch_flow(h, CH_UDP_OPT, 3004, 1, "UDP, opted in");
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

    setvbuf(stdout, NULL, _IOLBF, 0); /* the case lines survive a crash */
    init_extraction();

    /* Issue #116: the refused-upgrade baseline, before any plugin protocol
     * or upgrade classifier is registered (a handler snapshots the protocols
     * at init, so the fake plugin is registered after this one closes). */
    static char baseline[sizeof(g_log)];
    h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "FAIL: mmt_init_handler (baseline): %s\n", errbuf);
        close_extraction();
        return 2;
    }
    register_packet_handler(h, 1, classification_handler, NULL);
    register_attribute_handler(h, PROTO_HTTP, HTTP_HEADER, header_handler, NULL, NULL);
    refused_upgrade(h, 2001);
    memcpy(baseline, g_log, sizeof(baseline));
    mmt_close_handler(h);
    if (!register_upgrade_protocol()) {
        fprintf(stderr, "FAIL: registering the fake plugin protocol\n");
        failures++;
    }
    if (!ch_register_all()) {
        fprintf(stderr, "FAIL: registering the issue #115 plugin protocols\n");
        failures++;
    }

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

    /* Issue #92: the listener's answer names the streaming server */
    {
        static const char *get = "GET /live HTTP/1.0\r\nHost: radio.example\r\n"
                                  "Icy-MetaData: 1\r\n\r\n";
        static const struct { const char *label, *answer, *want; int port; } l[] = {
            { "Icecast",   "HTTP/1.0 200 OK\r\nServer: Icecast 2.4.4\r\n"
                           "Content-Type: audio/mpeg\r\n\r\n", "icecast", 1010 },
            { "SHOUTcast", "ICY 200 OK\r\nicy-name: test\r\n"
                           "content-type: audio/mpeg\r\n\r\n", "shoutcast", 1011 },
            { "other",     "HTTP/1.0 200 OK\r\nServer: example-httpd\r\n"
                           "Content-Type: audio/mpeg\r\n\r\n", NULL, 1012 },
        };
        for (i = 0; i < sizeof(l) / sizeof(l[0]); i++) {
            classify_listener(h, get, l[i].answer, l[i].port);
            const char *last = strrchr(g_path, '.');
            last = (last != NULL) ? last + 1 : g_path;
            int ok = (l[i].want != NULL) ? strcmp(last, l[i].want) == 0
                                         : strcmp(last, "mpeg") == 0;
            printf("  %-16s -> %-40s [%s]\n", l[i].label, g_path, ok ? "PASS" : "FAIL");
            if (!ok) {
                failures++;
                fprintf(stderr, "  ✗ %s listener: expected %s, got '%s'\n", l[i].label,
                        l[i].want != NULL ? l[i].want : "http.mpeg", g_path);
            }
        }
    }

    upgrade_tests(h, baseline);
    failures += upg_failures;
    child_tests(h);
    failures += g_ch_failures;

    mmt_close_handler(h); /* expires the sessions the plugin still holds */
    {
        int ok = g_upg_init > 0 && g_upg_cleanup == g_upg_init && g_upg_bad == 0;
        printf("  %-16s -> %-40s [%s]\n", "upgrade", "expiry: each plugin block freed once",
               ok ? "PASS" : "FAIL");
        if (!ok) {
            failures++;
            fprintf(stderr, "  ✗ plugin blocks: %d allocated, %d freed, %d bad\n",
                    g_upg_init, g_upg_cleanup, g_upg_bad);
        }
    }
    close_extraction();

    if (failures) {
        printf("\n✗ %d case(s) failed: HTTP header matching is not "
               "case-insensitive, a line break other than CRLF split a "
               "line, a streaming listener was mislabelled, or the HTTP "
               "upgrade hand-off failed\n", failures);
        return 1;
    }
    printf("\n✓ all cases classified as expected — HTTP header matching is "
           "case-insensitive and only CRLF ends a line\n");
    return 0;
}

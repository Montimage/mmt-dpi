/*
 * test_ftp_session_attrs_api.c — the FTP session attributes, read from both
 * connections of one transfer (issue #544).
 *
 * proto_ftp_extract.c resolves every FTP session attribute through one
 * helper: the session_data slot holds a control session on the control
 * connection (server port 21) and a data session on a data connection, and
 * each side reaches the other through current_data_session / control_session.
 * The 25 session extractors used to carry their own copy of that resolution
 * block; this test pins what they return from each side, so the fold is
 * checked attribute by attribute.
 *
 * One passive-mode download is replayed through mmt_init_handler +
 * packet_process: the control connection logs in, sets the type, the current
 * directory, the file's size and date, enters passive mode (227) and starts
 * a RETR; the data connection to the announced port then carries the file.
 * The attributes are read on
 *   - a data-connection packet (the data branch: control attributes through
 *     the data session's control_session),
 *   - the next control-connection packet (the control branch: data
 *     attributes through current_data_session),
 *   - a control-connection packet before the RETR (no direction yet),
 *   - a data-connection packet after the 226 reply, whose data session was
 *     reset in place and detached from the flow (issue #487): nothing
 *     session-scoped resolves.
 * FTP_DATA_DIRECTION keeps its asymmetry: on the control connection it is
 * reported whatever its value, on a data connection only when non-zero (a
 * data session starts at MMT_FTP_PACKET_UNKNOWN_DIRECTION, 3).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>       /* htons */
#include <pcap.h>            /* DLT_EN10MB */

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

/* Values of ftp.h the test reads back (ftp.h is internal to the plugin). */
#define FTP_CONTROL_CONNECTION  1
#define FTP_DATA_PASSIVE_MODE   2
#define FTP_DATA_TYPE_FILE      1
#define FTP_DATA_DOWNLOAD       2
#define FTP_STATUS_DATA_OPENED  3
#define FTP_UNKNOWN_DIRECTION   3

/* One snapshot of every FTP session attribute, taken on a probe packet. */
typedef struct {
    int      seen;                  /* the probe packet carried FTP */
    int      has[FTP_FILE_LAST_MODIFIED + 1];
    uint32_t u32[FTP_FILE_LAST_MODIFIED + 1];
    uint64_t u64[FTP_FILE_LAST_MODIFIED + 1];
    char     str[FTP_FILE_LAST_MODIFIED + 1][64];
} snapshot_t;

enum { PROBE_NONE = 0, PROBE_UNSET, PROBE_DATA, PROBE_CONTROL, PROBE_DETACHED, PROBE_COUNT };
static int g_probe = PROBE_NONE;
static snapshot_t g_snap[PROBE_COUNT];

static void take_snapshot(const ipacket_t *ipacket, snapshot_t *s) {
    memset(s, 0, sizeof(*s));
    s->seen = 1;
    for (int id = FTP_SESSION_CONN_TYPE; id <= FTP_FILE_LAST_MODIFIED; id++) {
        void *v = get_attribute_extracted_data(ipacket, PROTO_FTP, (uint32_t) id);
        if (v == NULL)
            continue;
        s->has[id] = 1;
        switch (id) {
        case FTP_SESSION_CONN_TYPE: case FTP_DATA_TYPE: case FTP_DATA_MODE:
        case FTP_DATA_DIRECTION:
            s->u32[id] = *(uint8_t *) v; break;
        case FTP_SERVER_CONT_PORT: case FTP_CLIENT_CONT_PORT: case FTP_STATUS:
        case FTP_SERVER_DATA_PORT: case FTP_CLIENT_DATA_PORT:
            s->u32[id] = *(uint16_t *) v; break;
        case FTP_SERVER_CONT_ADDR: case FTP_CLIENT_CONT_ADDR:
        case FTP_SERVER_DATA_ADDR: case FTP_CLIENT_DATA_ADDR: case FTP_FILE_SIZE:
            s->u32[id] = *(uint32_t *) v; break;
        case FTP_CONT_IP_SESSION_ID: case FTP_DATA_IP_SESSION_ID:
            s->u64[id] = *(uint64_t *) v; break;
        case FTP_USERNAME: case FTP_PASSWORD: case FTP_SESSION_FEATURES:
        case FTP_SYST: case FTP_CURRENT_DIR: case FTP_DATA_TRANSFER_TYPE:
        case FTP_FILE_NAME: case FTP_FILE_LAST_MODIFIED:
            snprintf(s->str[id], sizeof(s->str[id]), "%s", (const char *) v); break;
        default:                    /* FTP_LAST_COMMAND / _RESPONSE_CODE */
            break;
        }
    }
}

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    if (g_probe == PROBE_NONE || ipacket->proto_hierarchy == NULL)
        return 0;
    for (int i = 0; i < ipacket->proto_hierarchy->len && i < PROTO_PATH_SIZE; i++) {
        if (ipacket->proto_hierarchy->proto_path[i] == PROTO_FTP) {
            take_snapshot(ipacket, &g_snap[g_probe]);
            break;
        }
    }
    return 0;
}

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

#define TH_SYN 0x02
#define TH_PSH 0x08
#define TH_ACK 0x10

/* The client 10.0.44.1 and the server 10.0.44.2. The address and port
 * attributes carry network byte order. */
static const uint8_t CLIENT_IP[4] = {10, 0, 44, 1};
static const uint8_t SERVER_IP[4] = {10, 0, 44, 2};
#define CLIENT_CTRL_PORT 40000
#define CLIENT_DATA_PORT 40001
#define DATA_PORT        1025       /* 4 * 256 + 1, the 227 reply below */

static uint32_t ip_attr(const uint8_t ip[4]) {
    uint32_t v;
    memcpy(&v, ip, 4);
    return v;
}

/* Ethernet + IPv4 + TCP + payload between the client cport and the server
 * sport. Returns the frame length. */
static int build(uint8_t *pkt, uint16_t cport, uint16_t sport, int to_server,
                 uint8_t flags, uint32_t seq, uint32_t ack,
                 const char *pl, unsigned plen) {
    static const uint8_t mac_a[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t mac_b[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    uint8_t *ip = pkt + 14, *l4 = pkt + 34;

    memcpy(pkt, to_server ? mac_a : mac_b, 6);
    memcpy(pkt + 6, to_server ? mac_b : mac_a, 6);
    put_be16(pkt + 12, 0x0800);

    memset(ip, 0, 20);
    ip[0] = 0x45;
    put_be16(ip + 2, (uint16_t)(40 + plen));
    ip[8] = 64;
    ip[9] = 6;
    memcpy(ip + 12, to_server ? CLIENT_IP : SERVER_IP, 4);
    memcpy(ip + 16, to_server ? SERVER_IP : CLIENT_IP, 4);

    put_be16(l4, to_server ? cport : sport);
    put_be16(l4 + 2, to_server ? sport : cport);
    memset(l4 + 4, 0, 16);
    put_be32(l4 + 4, seq);
    put_be32(l4 + 8, ack);
    l4[12] = 0x50;                          /* data offset 5 */
    l4[13] = flags;
    put_be16(l4 + 14, 0xffff);
    if (plen)
        memcpy(l4 + 20, pl, plen);
    return (int)(54 + plen);
}

static unsigned g_ts;

static void send_frame(mmt_handler_t *h, const uint8_t *frame, int len) {
    /* An exactly-sized heap copy lets ASan bracket the capture. */
    uint8_t *data = malloc((size_t) len);
    if (!data) { perror("malloc"); exit(2); }
    memcpy(data, frame, (size_t) len);
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = ++g_ts;
    hdr.caplen = (unsigned) len;
    hdr.len = (unsigned) len;
    packet_process(h, &hdr, data);
    free(data);
}

/* One TCP connection: a handshake, then segments in either direction. */
typedef struct {
    uint16_t cport, sport;
    uint32_t cseq, sseq;            /* next sequence number per side */
} conn_t;

static void conn_open(mmt_handler_t *h, conn_t *c, uint16_t cport, uint16_t sport) {
    static uint8_t frame[256];
    int n;
    c->cport = cport; c->sport = sport; c->cseq = 1000; c->sseq = 5000;
    n = build(frame, cport, sport, 1, TH_SYN, c->cseq++, 0, NULL, 0);
    send_frame(h, frame, n);
    n = build(frame, cport, sport, 0, TH_SYN | TH_ACK, c->sseq++, c->cseq, NULL, 0);
    send_frame(h, frame, n);
    n = build(frame, cport, sport, 1, TH_ACK, c->cseq, c->sseq, NULL, 0);
    send_frame(h, frame, n);
}

static void conn_send(mmt_handler_t *h, conn_t *c, int to_server, const char *pl) {
    static uint8_t frame[2048];
    const unsigned plen = (unsigned) strlen(pl);
    int n;
    if (to_server) {
        n = build(frame, c->cport, c->sport, 1, TH_PSH | TH_ACK, c->cseq, c->sseq, pl, plen);
        c->cseq += plen;
    } else {
        n = build(frame, c->cport, c->sport, 0, TH_PSH | TH_ACK, c->sseq, c->cseq, pl, plen);
        c->sseq += plen;
    }
    send_frame(h, frame, n);
}

#define C2S(pl) conn_send(h, &ctrl, 1, (pl))
#define S2C(pl) conn_send(h, &ctrl, 0, (pl))

/* The control-connection attributes, identical from either connection. */
static void check_control_attrs(const snapshot_t *s, const char *side) {
    char msg[160];
#define CTRL_CHECK(cond, what) do {                                  \
        snprintf(msg, sizeof(msg), "%s: %s", side, (what));          \
        CHECK((cond), msg);                                          \
    } while (0)
    CTRL_CHECK(s->has[FTP_SERVER_CONT_ADDR] && s->u32[FTP_SERVER_CONT_ADDR] == ip_attr(SERVER_IP),
               "server control address is the server");
    CTRL_CHECK(s->has[FTP_SERVER_CONT_PORT] && s->u32[FTP_SERVER_CONT_PORT] == htons(21),
               "server control port is 21");
    CTRL_CHECK(s->has[FTP_CLIENT_CONT_ADDR] && s->u32[FTP_CLIENT_CONT_ADDR] == ip_attr(CLIENT_IP),
               "client control address is the client");
    CTRL_CHECK(s->has[FTP_CLIENT_CONT_PORT] && s->u32[FTP_CLIENT_CONT_PORT] == htons(CLIENT_CTRL_PORT),
               "client control port is the control connection's");
    CTRL_CHECK(s->has[FTP_CONT_IP_SESSION_ID] && s->u64[FTP_CONT_IP_SESSION_ID] != 0,
               "control IP session id is set");
    CTRL_CHECK(s->has[FTP_USERNAME] && strcmp(s->str[FTP_USERNAME], "anonymous") == 0,
               "username is the USER parameter");
    CTRL_CHECK(s->has[FTP_PASSWORD] && strcmp(s->str[FTP_PASSWORD], "mmt@example.org") == 0,
               "password is the PASS parameter");
    CTRL_CHECK(s->has[FTP_SYST] && strcmp(s->str[FTP_SYST], "UNIX Type: L8") == 0,
               "syst is the 215 reply");
    CTRL_CHECK(s->has[FTP_STATUS] && s->u32[FTP_STATUS] == FTP_STATUS_DATA_OPENED,
               "status is data-opened after the 150 reply");
    CTRL_CHECK(s->has[FTP_LAST_COMMAND], "last command resolves");
    CTRL_CHECK(s->has[FTP_LAST_RESPONSE_CODE], "last response resolves");
    CTRL_CHECK(s->has[FTP_CURRENT_DIR] && strstr(s->str[FTP_CURRENT_DIR], "/pub") != NULL,
               "current dir is the 257 reply");
    CTRL_CHECK(!s->has[FTP_SESSION_FEATURES], "features stay absent without a FEAT listing");
#undef CTRL_CHECK
}

/* The current data-connection attributes, identical from either connection
 * but for the direction (see the header comment). */
static void check_data_attrs(const snapshot_t *s, const char *side) {
    char msg[160];
#define DATA_CHECK(cond, what) do {                                  \
        snprintf(msg, sizeof(msg), "%s: %s", side, (what));          \
        CHECK((cond), msg);                                          \
    } while (0)
    DATA_CHECK(s->has[FTP_SERVER_DATA_ADDR] && s->u32[FTP_SERVER_DATA_ADDR] == ip_attr(SERVER_IP),
               "server data address is the 227 address");
    DATA_CHECK(s->has[FTP_SERVER_DATA_PORT] && s->u32[FTP_SERVER_DATA_PORT] == htons(DATA_PORT),
               "server data port is the 227 port");
    DATA_CHECK(s->has[FTP_CLIENT_DATA_ADDR] && s->u32[FTP_CLIENT_DATA_ADDR] == ip_attr(CLIENT_IP),
               "client data address is the client");
    DATA_CHECK(s->has[FTP_DATA_TYPE] && s->u32[FTP_DATA_TYPE] == FTP_DATA_TYPE_FILE,
               "data type is a file transfer");
    DATA_CHECK(s->has[FTP_DATA_TRANSFER_TYPE] && strcmp(s->str[FTP_DATA_TRANSFER_TYPE], "I") == 0,
               "transfer type is the TYPE parameter");
    DATA_CHECK(s->has[FTP_DATA_MODE] && s->u32[FTP_DATA_MODE] == FTP_DATA_PASSIVE_MODE,
               "data mode is passive");
    DATA_CHECK(s->has[FTP_DATA_DIRECTION] && s->u32[FTP_DATA_DIRECTION] == FTP_DATA_DOWNLOAD,
               "direction is a download");
    DATA_CHECK(s->has[FTP_FILE_NAME] && strcmp(s->str[FTP_FILE_NAME], "file.bin") == 0,
               "file name is the RETR parameter");
    DATA_CHECK(s->has[FTP_FILE_SIZE] && s->u32[FTP_FILE_SIZE] == 1024,
               "file size is the SIZE reply");
    DATA_CHECK(s->has[FTP_FILE_LAST_MODIFIED]
               && strcmp(s->str[FTP_FILE_LAST_MODIFIED], "20261028061309") == 0,
               "last modified is the MDTM reply");
#undef DATA_CHECK
}

int main(void) {
    if (!init_extraction()) {
        fprintf(stderr, "init_extraction failed\n");
        return 2;
    }
    char errbuf[1024];
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    for (int id = FTP_SESSION_CONN_TYPE; id <= FTP_FILE_LAST_MODIFIED; id++)
        register_extraction_attribute(h, PROTO_FTP, (uint32_t) id);
    register_packet_handler(h, 1, packet_handler, NULL);

    printf("=== FTP session attributes from both connections (issue #544) ===\n");

    conn_t ctrl, data;
    conn_open(h, &ctrl, CLIENT_CTRL_PORT, 21);
    S2C("220 mmt FTP server ready\r\n");
    C2S("USER anonymous\r\n");
    S2C("331 Please specify the password.\r\n");
    C2S("PASS mmt@example.org\r\n");
    S2C("230 Login successful.\r\n");
    C2S("SYST\r\n");
    S2C("215 UNIX Type: L8\r\n");
    C2S("CWD pub\r\n");
    S2C("250 Directory successfully changed.\r\n");
    C2S("PWD\r\n");
    S2C("257 \"/pub\" is the current directory\r\n");
    C2S("TYPE I\r\n");
    S2C("200 Switching to Binary mode.\r\n");
    C2S("SIZE file.bin\r\n");
    S2C("213 1024\r\n");
    C2S("MDTM file.bin\r\n");
    S2C("213 20261028061309\r\n");
    g_probe = PROBE_UNSET;
    C2S("PASV\r\n");
    g_probe = PROBE_NONE;
    S2C("227 Entering Passive Mode (10,0,44,2,4,1)\r\n");
    C2S("RETR file.bin\r\n");
    S2C("150 Opening BINARY mode data connection for file.bin (1024 bytes).\r\n");

    conn_open(h, &data, CLIENT_DATA_PORT, DATA_PORT);
    conn_send(h, &data, 0, "first block of file.bin\n");
    g_probe = PROBE_DATA;
    conn_send(h, &data, 0, "second block of file.bin\n");
    g_probe = PROBE_CONTROL;
    C2S("NOOP\r\n");
    g_probe = PROBE_NONE;
    S2C("226 Transfer complete.\r\n");
    g_probe = PROBE_DETACHED;
    conn_send(h, &data, 0, "late block of file.bin\n");
    g_probe = PROBE_NONE;

    const snapshot_t *u = &g_snap[PROBE_UNSET];
    const snapshot_t *d = &g_snap[PROBE_DATA];
    const snapshot_t *c = &g_snap[PROBE_CONTROL];
    const snapshot_t *x = &g_snap[PROBE_DETACHED];

    CHECK(u->seen, "control connection before RETR: the probe packet is classified FTP");
    CHECK(u->has[FTP_DATA_DIRECTION] && u->u32[FTP_DATA_DIRECTION] == FTP_UNKNOWN_DIRECTION,
          "control connection before RETR: the direction is still unknown");
    CHECK(!u->has[FTP_FILE_NAME], "control connection before RETR: no file name yet");

    CHECK(d->seen, "data connection: the probe packet is classified FTP");
    CHECK(d->has[FTP_SESSION_CONN_TYPE] && d->u32[FTP_SESSION_CONN_TYPE] != FTP_CONTROL_CONNECTION,
          "data connection: connection type is not the control connection");
    check_control_attrs(d, "data connection");
    check_data_attrs(d, "data connection");
    CHECK(d->has[FTP_CLIENT_DATA_PORT] && d->u32[FTP_CLIENT_DATA_PORT] == htons(CLIENT_DATA_PORT),
          "data connection: client data port is the data flow's");
    CHECK(d->has[FTP_DATA_IP_SESSION_ID] && d->u64[FTP_DATA_IP_SESSION_ID] != 0
          && d->u64[FTP_DATA_IP_SESSION_ID] != d->u64[FTP_CONT_IP_SESSION_ID],
          "data connection: data IP session id is the data flow's own");

    CHECK(c->seen, "control connection: the probe packet is classified FTP");
    CHECK(c->has[FTP_SESSION_CONN_TYPE] && c->u32[FTP_SESSION_CONN_TYPE] == FTP_CONTROL_CONNECTION,
          "control connection: connection type is the control connection");
    check_control_attrs(c, "control connection");
    check_data_attrs(c, "control connection");
    CHECK(c->has[FTP_CLIENT_DATA_PORT] == d->has[FTP_CLIENT_DATA_PORT]
          && c->u32[FTP_CLIENT_DATA_PORT] == d->u32[FTP_CLIENT_DATA_PORT],
          "control connection: client data port matches the data connection's");
    CHECK(c->has[FTP_DATA_IP_SESSION_ID]
          && c->u64[FTP_DATA_IP_SESSION_ID] == d->u64[FTP_DATA_IP_SESSION_ID],
          "control connection: data IP session id matches the data connection's");

    CHECK(x->seen, "detached data flow: the probe packet is classified FTP");
    int resolved = 0;
    for (int id = FTP_SERVER_CONT_ADDR; id <= FTP_FILE_LAST_MODIFIED; id++)
        resolved += x->has[id];
    CHECK(resolved == 0, "detached data flow: no session attribute resolves after the 226 reset");

    mmt_close_handler(h);
    close_extraction();

    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    return g_failures == 0 ? 0 : 1;
}

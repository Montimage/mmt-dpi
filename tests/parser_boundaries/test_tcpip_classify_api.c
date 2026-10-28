/*
 * test_tcpip_classify_api.c — packet/API-path classifier sweep for issue #531
 * (plan task 9.2: raise tcpip coverage on the dissectors that classify).
 *
 * Each case replays the canonical opening exchange of one TCP/IP protocol —
 * a TCP three-way handshake first, then the payloads in order, each in its
 * direction — through mmt_init_handler + packet_process, and checks that the
 * protocol appears in the classified path. The cases were chosen by the
 * uncovered lines of their classifier bodies (src/mmt_tcpip/lib/protocols/)
 * in tests/coverage/coverage-combined.info; each one drives the classifier
 * through its payload checks to its add-connection call. Port-based
 * classification is off by default (packet_registry.c), so only the payload
 * checks can put the protocol in the path, and reverting one fails the case.
 * Payloads avoid the earlier classifiers that would claim them first (FTP
 * for "USER", DICOM for a leading 0x01, DNS for query-shaped headers).
 *
 * Every attribute of the case's protocol is registered for extraction and
 * read back on each packet of that protocol, so the extractors run over the
 * same crafted payloads. Every case uses its own host pair (classifiers keep
 * per-IP state such as learned ports) and its own client port, and every
 * capture is an exactly-sized heap copy so ASan brackets it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

enum { S2C = 0, C2S = 1 };

typedef struct {
    int         dir;        /* C2S or S2C */
    const char *data;
    unsigned    len;
} seg_t;

/* A payload from a string literal (embedded NULs allowed). */
#define SEG(dir, lit) { (dir), (lit), (unsigned) (sizeof(lit) - 1) }

typedef struct {
    const char  *name;
    int          want;      /* PROTO_* id expected in the path */
    int          tcp;       /* 1: TCP with a handshake, 0: UDP */
    uint16_t     dport;     /* server port */
    const seg_t *segs;
    unsigned     nsegs;
} case_t;

#define CASE(name, want, tcp, dport, segs) \
    { (name), (want), (tcp), (dport), (segs), (unsigned) (sizeof(segs) / sizeof((segs)[0])) }

static int g_want;          /* protocol looked for in the path */
static int g_seen;          /* g_want was in the path of some packet */
static unsigned g_reads;    /* attributes read back while g_want was seen */

static void read_attribute(attribute_metadata_t *attr, uint32_t proto_id, void *args) {
    const ipacket_t *ipacket = args;
    if (get_attribute_extracted_data(ipacket, proto_id, attr->id) != NULL)
        g_reads++;
}

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void) user_args;
    if (ipacket->proto_hierarchy == NULL)
        return 0;
    for (int i = 0; i < ipacket->proto_hierarchy->len && i < PROTO_PATH_SIZE; i++) {
        if (ipacket->proto_hierarchy->proto_path[i] == g_want) {
            g_seen = 1;
            iterate_through_protocol_attributes((uint32_t) g_want, read_attribute,
                                                (void *) ipacket);
            break;
        }
    }
    return 0;
}

static void register_attribute(attribute_metadata_t *attr, uint32_t proto_id, void *args) {
    register_extraction_attribute((mmt_handler_t *) args, proto_id, attr->id);
}

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

static unsigned g_net;      /* host pair of the current case */

#define TH_SYN 0x02
#define TH_PSH 0x08
#define TH_ACK 0x10

/* Builds Ethernet + IPv4 + TCP or UDP + payload between the client
 * 10.<net>.1:sport and the server 10.<net>.2:dport. Returns the frame length. */
static int build(uint8_t *pkt, int tcp, uint16_t sport, uint16_t dport, int to_server,
                 uint8_t flags, uint32_t seq, uint32_t ack,
                 const uint8_t *pl, unsigned plen) {
    static const uint8_t mac_a[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t mac_b[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    const unsigned l4len = (tcp ? 20u : 8u) + plen;
    uint8_t *ip = pkt + 14, *l4 = pkt + 34;

    memcpy(pkt, to_server ? mac_a : mac_b, 6);
    memcpy(pkt + 6, to_server ? mac_b : mac_a, 6);
    put_be16(pkt + 12, 0x0800);

    memset(ip, 0, 20);
    ip[0] = 0x45;
    put_be16(ip + 2, (uint16_t)(20 + l4len));
    ip[8] = 64;
    ip[9] = tcp ? 6 : 17;
    /* 10.<net>.1 -> 10.<net>.2: per-IP classifier state never leaks
     * between cases, and the client is the lower address (direction 1). */
    ip[12] = 10; ip[13] = g_net >> 8; ip[14] = g_net & 0xff; ip[15] = to_server ? 1 : 2;
    ip[16] = 10; ip[17] = g_net >> 8; ip[18] = g_net & 0xff; ip[19] = to_server ? 2 : 1;

    put_be16(l4, to_server ? sport : dport);
    put_be16(l4 + 2, to_server ? dport : sport);
    if (tcp) {
        memset(l4 + 4, 0, 16);
        put_be32(l4 + 4, seq);
        put_be32(l4 + 8, ack);
        l4[12] = 0x50;                      /* data offset 5 */
        l4[13] = flags;
        put_be16(l4 + 14, 0xffff);
        if (plen)                           /* handshake: no payload */
            memcpy(l4 + 20, pl, plen);
    } else {
        put_be16(l4 + 4, (uint16_t) l4len);
        put_be16(l4 + 6, 0);
        if (plen)
            memcpy(l4 + 8, pl, plen);
    }
    return (int)(34 + l4len);
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

/* Replays one case on its own session and reports whether its protocol was
 * in the path of some packet. */
static int replay(mmt_handler_t *h, const case_t *c, uint16_t sport) {
    static uint8_t frame[2048];
    uint32_t cseq = 1000, sseq = 5000;      /* next sequence number per side */
    int n;

    iterate_through_protocol_attributes((uint32_t) c->want, register_attribute, h);
    g_net++;
    g_want = c->want;
    g_seen = 0;
    if (c->tcp) {
        n = build(frame, 1, sport, c->dport, 1, TH_SYN, cseq++, 0, NULL, 0);
        send_frame(h, frame, n);
        n = build(frame, 1, sport, c->dport, 0, TH_SYN | TH_ACK, sseq++, cseq, NULL, 0);
        send_frame(h, frame, n);
        n = build(frame, 1, sport, c->dport, 1, TH_ACK, cseq, sseq, NULL, 0);
        send_frame(h, frame, n);
    }
    for (unsigned i = 0; i < c->nsegs; i++) {
        const seg_t *s = &c->segs[i];
        const uint8_t *pl = (const uint8_t *) s->data;
        if (s->dir == C2S) {
            n = build(frame, c->tcp, sport, c->dport, 1, TH_PSH | TH_ACK, cseq, sseq, pl, s->len);
            cseq += s->len;
        } else {
            n = build(frame, c->tcp, sport, c->dport, 0, TH_PSH | TH_ACK, sseq, cseq, pl, s->len);
            sseq += s->len;
        }
        send_frame(h, frame, n);
    }
    return g_seen;
}

/* ---- cases ------------------------------------------------------------ */

static const seg_t mqtt_segs[] = {
    SEG(C2S, "\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x04mmt!"),
};
/* FTP control session (proto_ftp.c): the banner and login classify it, the
 * later commands and replies run ftp_get_command() / ftp_set_command_id()
 * and the reply-code parser over every command family. */
static const seg_t ftp_segs[] = {
    SEG(S2C, "220 mmt FTP server ready\r\n"),
    SEG(C2S, "USER anonymous\r\n"),
    SEG(S2C, "331 Please specify the password.\r\n"),
    SEG(C2S, "PASS mmt@example.org\r\n"),
    SEG(S2C, "230 Login successful.\r\n"),
    SEG(C2S, "SYST\r\n"),
    SEG(S2C, "215 UNIX Type: L8\r\n"),
    SEG(C2S, "FEAT\r\n"),
    SEG(S2C, "211 End\r\n"),
    SEG(C2S, "PWD\r\n"),
    SEG(S2C, "257 \"/\" is the current directory\r\n"),
    SEG(C2S, "TYPE I\r\n"),
    SEG(S2C, "200 Switching to Binary mode.\r\n"),
    SEG(C2S, "CWD pub\r\n"),
    SEG(S2C, "250 Directory successfully changed.\r\n"),
    SEG(C2S, "PASV\r\n"),
    SEG(S2C, "227 Entering Passive Mode (10,0,0,2,4,1)\r\n"),
    SEG(C2S, "LIST\r\n"),
    SEG(S2C, "150 Here comes the directory listing.\r\n"),
    SEG(S2C, "226 Directory send OK.\r\n"),
    SEG(C2S, "SIZE file.bin\r\n"),
    SEG(S2C, "213 1024\r\n"),
    SEG(C2S, "MDTM file.bin\r\n"),
    SEG(S2C, "213 20261028061309\r\n"),
    SEG(C2S, "PORT 10,0,0,1,4,2\r\n"),
    SEG(S2C, "200 PORT command successful.\r\n"),
    SEG(C2S, "RETR file.bin\r\n"),
    SEG(S2C, "150 Opening BINARY mode data connection for file.bin (1024 bytes).\r\n"),
    SEG(S2C, "226 Transfer complete.\r\n"),
    SEG(C2S, "EPSV\r\n"),
    SEG(S2C, "229 Entering Extended Passive Mode (|||1027|)\r\n"),
    SEG(C2S, "STOR upload.bin\r\n"),
    SEG(S2C, "150 Ok to send data.\r\n"),
    SEG(S2C, "226 Transfer complete.\r\n"),
    SEG(C2S, "MKD newdir\r\n"),
    SEG(S2C, "257 \"/pub/newdir\" created\r\n"),
    SEG(C2S, "RNFR upload.bin\r\n"),
    SEG(S2C, "350 Ready for RNTO.\r\n"),
    SEG(C2S, "RNTO renamed.bin\r\n"),
    SEG(S2C, "250 Rename successful.\r\n"),
    SEG(C2S, "DELE renamed.bin\r\n"),
    SEG(S2C, "250 Delete operation successful.\r\n"),
    SEG(C2S, "RMD newdir\r\n"),
    SEG(S2C, "250 Remove directory operation successful.\r\n"),
    SEG(C2S, "CDUP\r\n"),
    SEG(S2C, "250 Directory successfully changed.\r\n"),
    SEG(C2S, "REST 100\r\n"),
    SEG(S2C, "350 Restart position accepted (100).\r\n"),
    SEG(C2S, "NOOP\r\n"),
    SEG(S2C, "200 NOOP ok.\r\n"),
    SEG(C2S, "ABOR\r\n"),
    SEG(S2C, "225 No transfer to ABOR.\r\n"),
    SEG(C2S, "QUIT\r\n"),
    SEG(S2C, "221 Goodbye.\r\n"),
};
static const seg_t sip_segs[] = {
    SEG(C2S, "INVITE sip:bob@example.org SIP/2.0\r\n"
             "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\n"
             "Max-Forwards: 70\r\nTo: Bob <sip:bob@example.org>\r\n"
             "From: Alice <sip:alice@example.org>;tag=1928301774\r\n"
             "Call-ID: a84b4c76e66710@10.0.0.1\r\nCSeq: 314159 INVITE\r\n"
             "Contact: <sip:alice@10.0.0.1>\r\nContent-Length: 0\r\n\r\n"),
    SEG(S2C, "SIP/2.0 200 OK\r\n"
             "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\n"
             "To: Bob <sip:bob@example.org>;tag=a6c85cf\r\n"
             "From: Alice <sip:alice@example.org>;tag=1928301774\r\n"
             "Call-ID: a84b4c76e66710@10.0.0.1\r\nCSeq: 314159 INVITE\r\n"
             "Content-Length: 0\r\n\r\n"),
};
static const seg_t pop_segs[] = {
    SEG(S2C, "+OK POP3 server ready <1896.697170952@mmt.example.org>\r\n"),
    SEG(C2S, "USER alice\r\n"),
    SEG(S2C, "+OK\r\n"),
    SEG(C2S, "PASS secret\r\n"),
    SEG(S2C, "+OK maildrop has 2 messages\r\n"),
    SEG(C2S, "STAT\r\n"),
    SEG(S2C, "+OK 2 320\r\n"),
    SEG(C2S, "LIST\r\n"),
    SEG(S2C, "+OK 2 messages\r\n1 120\r\n2 200\r\n.\r\n"),
    SEG(C2S, "UIDL\r\n"),
    SEG(S2C, "+OK\r\n1 whqtswO00WBw418f9t5JxYwZ\r\n.\r\n"),
    SEG(C2S, "RETR 1\r\n"),
    SEG(S2C, "+OK 120 octets\r\nFrom: bob@example.org\r\n\r\nhi\r\n.\r\n"),
    SEG(C2S, "DELE 1\r\n"),
    SEG(S2C, "+OK message 1 deleted\r\n"),
    SEG(C2S, "QUIT\r\n"),
    SEG(S2C, "+OK bye\r\n"),
};
static const seg_t smtp_segs[] = {
    SEG(S2C, "220 mx.example.org ESMTP ready\r\n"),
    SEG(C2S, "EHLO client.example.org\r\n"),
    SEG(S2C, "250-mx.example.org\r\n250-SIZE 35882577\r\n250 HELP\r\n"),
    SEG(C2S, "MAIL FROM:<alice.smith@example.org>\r\n"),
    SEG(S2C, "250 2.1.0 Ok\r\n"),
    SEG(C2S, "RCPT TO:<bob_jones-1@mail.example.com>\r\n"),
    SEG(S2C, "250 2.1.5 Ok\r\n"),
    SEG(C2S, "DATA\r\n"),
    SEG(S2C, "354 End data with <CR><LF>.<CR><LF>\r\n"),
    SEG(C2S, "From: alice.smith@example.org\r\nTo: bob_jones-1@mail.example.com\r\n"
             "Subject: test\r\n\r\nhello\r\n.\r\n"),
    SEG(S2C, "250 2.0.0 Ok: queued as 12345\r\n"),
    SEG(C2S, "QUIT\r\n"),
    SEG(S2C, "221 2.0.0 Bye\r\n"),
};
static const seg_t stun_segs[] = {
    SEG(C2S, "\x00\x01\x00\x14" "\x21\x12\xa4\x42"
             "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
             "\x00\x06\x00\x05" "abcde" "\x00\x00\x00"
             "\x80\x28\x00\x04" "\xde\xad\xbe\xef"),
};
static const seg_t qq_segs[] = {
    SEG(C2S, "\x02\x0d\x55\x00\x91\x00\x01\x00\x00\x00\x00\x03"),
    SEG(S2C, "\x02\x0d\x55\x00\x91\x00\x01\x00\x00\x00\x00\x03"),
    SEG(C2S, "\x02\x0d\x55\x00\x91\x00\x01\x00\x00\x00\x00\x03"),
};
static const seg_t qq_tcp_segs[] = {
    SEG(C2S, "\x00\x0c\x02\x0b\x37\x00\x91\x00\x00\x00\x00\x03"),
    SEG(S2C, "\x00\x0c\x02\x0b\x37\x00\x91\x00\x00\x00\x00\x03"),
    SEG(C2S, "\x00\x0c\x02\x0b\x37\x00\x91\x00\x00\x00\x00\x03"),
};
#define Z10 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define Z50 Z10 Z10 Z10 Z10 Z10
static const seg_t gadugadu_segs[] = {
    /* 0x12 (not 0x01, which DICOM claims as an A-ASSOCIATE-RQ) */
    SEG(C2S, "\x12\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"),
    SEG(C2S, "\x19\x00\x00\x00\x6a\x00\x00\x00" "\x01\x02\x03\x04" Z50 Z50 "\x00\x00"),
};
static const seg_t soulseek_segs[] = {
    SEG(C2S, "\x20\x00\x00\x00" "\x01\x00\x00\x00" "\x02\x00\x00\x00" "ab"
             "\x02\x00\x00\x00" "cd" "\x9d\x00\x00\x00" "\x04\x00\x00\x00" "efgh"
             "\x11\x00\x00\x00" "\x04\x00\x00\x00\x20\x00\x00\x00"),
};
static const seg_t pplive_segs[] = {
    SEG(C2S, "\x50\x00\x00\x00"),
    SEG(C2S, "012345678901234" "X" Z50 Z10 "\x00\x00\x00\x00"),
};
#define RTP_PKT(seq) SEG(C2S, "\x80\x08" seq "\x00\x00\x00\xa0" "\x12\x34\x56\x78" \
    "\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5\xd5")
static const seg_t rtp_segs[] = {
    RTP_PKT("\x00\x64"), RTP_PKT("\x00\x65"), RTP_PKT("\x00\x63"),
    RTP_PKT("\x00\x63"), RTP_PKT("\x00\x64"),
};
/* get_u16() reads host order: "06 00" is 6 on the little-endian hosts CI runs on */
static const seg_t imesh_segs[] = {
    SEG(C2S, "\x06\x00\xee\x00\x00\x00"),
    SEG(S2C, "\x06\x00\xee\x00\x00\x00"),
};
static const seg_t aimini_segs[] = {
    SEG(C2S, "\x01\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    SEG(C2S, "\x01\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    SEG(C2S, "\x01\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    SEG(C2S, "\x01\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
};
static const seg_t oscar_segs[] = {
    SEG(C2S, Z10 Z10 Z10 Z10 "\x00\x00\x00\x00"
             "\x67\x00\x65\x00\x74\x00\x43\x00\x61\x00\x74\x00\x61\x00\x6c\x00\x6f\x00\x67"
             "\x00\x00\x00\x00\x00\x00\x00"),
};
static const seg_t oscar_flap_segs[] = {
    SEG(C2S, "\x2a\x01\x00\x01\x00\x04\x00\x00\x00\x01"),
};
static const seg_t zattoo_segs[] = {
    SEG(C2S, "\x03\x04\x00\x04\x0a\x00" Z10 Z10 Z10 Z10 "\x00\x00\x00\x00\x00"),
    SEG(C2S, Z50 Z50 Z50 Z50 Z50 Z50 Z50 Z50 Z50 Z50 "\x00"),
    SEG(S2C, "\x03\x04" Z10 Z10 Z10 Z10 "\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
};
static const seg_t sopcast_segs[] = {
    SEG(C2S, "\x00\x36\x10\x14\x11\x00\x00\x00" "\x00\x00\x00\x00\x00\x00\x00\x00"
             "\x00\x00\x00\x00\x00\x00\x00\x00" "\x00\x14\x00\x00\x11\x00\x11\x11"
             "\x11\x11\x11\x11\x00\x00\x00\x00" "\x00\x00\x00\x00\x00\x05\x04\x00"
             "\x00\x05\x04\x00\x00\x00"),
};
static const seg_t imap_segs[] = {
    SEG(S2C, "* OK IMAP4rev1 Service Ready\r\n"),
    SEG(C2S, "a001 LOGIN alice secret\r\n"),
    SEG(S2C, "* 1 RECENT\r\n"),
    SEG(C2S, "a002 SELECT "),           /* split command: stage 4 */
    SEG(C2S, "FETCH 1 (FLAGS)\r\n"),
};
static const seg_t irc_segs[] = {
    SEG(C2S, "NICK alice\r\n"),
    SEG(S2C, ":irc.example.net NOTICE * :*** Looking up your hostname\r\n"),
    SEG(S2C, ":bob!bob@10.0.0.9 PRIVMSG alice :\x01" "DCC SEND file.txt 167772162 5000 1024\x01\r\n"),
};
static const seg_t smb_segs[] = {
    SEG(C2S, "\x00\x00\x00\x2f" "\xff" "SMB" "\x72" "\x00\x00\x00\x00" "\x18" "\x01\x28"
             "\x00\x00" "\x00\x00\x00\x00\x00\x00\x00\x00" "\x00\x00" "\x00\x00" "\x2f\x4b"
             "\x00\x00" "\xc5\x5e" "\x00" "\x0c\x00" "\x02" "NT LM 0.12" "\x00"),
};
static const seg_t gnutella_segs[] = {
    SEG(C2S, "PUSH guid:0123456789ABCDEF0123456789ABCDEF\r\n\r\n"),
};
static const seg_t gnutella_connect_segs[] = {
    SEG(C2S, "GNUTELLA CONNECT/0.6\r\nUser-Agent: LimeWire/4.0\r\n\r\n"),
};
#define BT_HANDSHAKE "BitTorrent protocol" "\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14" \
    "-TR2940-abcdefghijkl"
static const seg_t bittorrent_segs[] = {
    SEG(C2S, "\x13"),
    SEG(C2S, BT_HANDSHAKE),
};
static const seg_t edonkey_segs[] = {
    SEG(C2S, "\xe3\x22\x00\x00\x00" "\x01" "\x10"
             "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
             "\x0a\x00\x00\x01" "\x36\x12" "\x00\x00\x00\x00" "\x00\x00\x00\x00" "\x00\x00"),
    SEG(S2C, "\xe3\x22\x00\x00\x00" "\x4c" "\x10"
             "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
             "\x0a\x00\x00\x02" "\x36\x12" "\x00\x00\x00\x00" "\x00\x00\x00\x00" "\x00\x00"),
};
static const seg_t yahoo_segs[] = {
    /* two YMSG messages in one segment: the first length (10) is not the
     * segment's, so check_ymsg() walks to the second header */
    SEG(C2S, "YMSG" "\x00\x10\x00\x00\x00\x0a\x00\x18" "\x00\x00\x00\x00\x00\x00\x00\x00"
             "1" "\xc0\x80" "alice" "\xc0\x80"
             "YMSG" "\x00\x10\x00\x00\x00\x00\x00\x4c" "\x00\x00\x00\x00\x00\x00\x00\x00"),
};
static const seg_t msn_segs[] = {
    SEG(C2S, "USR 1 TWN I alice@hotmail.com 1\r\n"),
};
static const seg_t msn_ver_segs[] = {
    SEG(C2S, "VER 1 MSNP8 CVR0\r\n"),
};
static const seg_t jabber_segs[] = {
    SEG(C2S, "<?xml version='1.0'?><stream:stream to='example.com' xmlns='jabber:client' "
             "xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"),
    SEG(C2S, "<iq type='set' to='bob@example.com/home' id='s5b1'><query "
             "xmlns='http://jabber.org/protocol/bytestreams' sid='s1'><streamhost "
             "jid='alice@example.com/res' host='10.0.0.1' port='6000'/></query></iq>"),
};
static const seg_t directconnect_segs[] = {
    SEG(S2C, "$Lock EXTENDEDPROTOCOL_verlihub Pk=version0.9.8e|"),
    SEG(C2S, "$Key abcdefghijklmnop|$ValidateNick alice|"),
};
static const seg_t directconnect_peer_segs[] = {
    SEG(C2S, "$MyNick alice|$Lock EXTENDEDPROTOCOLABC Pk=DCPLUSPLUS0.868|"),
    SEG(S2C, "$MyNick bob|$Lock EXTENDEDPROTOCOLXYZ Pk=DCPLUSPLUS0.868|"),
};
static const seg_t netbios_segs[] = {
    /* name-query response (flags 0x8000): a query would satisfy the DNS
     * heuristic first */
    SEG(C2S, "\x12\x34" "\x80\x00" "\x00\x00" "\x00\x01" "\x00\x00" "\x00\x00"
             "\x20" "CK" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "\x00"
             "\x00\x20" "\x00\x01" "\x00\x04\x93\xe0" "\x00\x06" "\x00\x00" "\x0a\x00\x00\x02"),
};
static const seg_t netbios_tcp_segs[] = {
    SEG(C2S, "\x81\x00\x00\x44" "\x20" "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP" "\x00"
             "\x20" "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP" "\x00"),
};
static const case_t g_cases[] = {
    CASE("IMAP", PROTO_IMAP, 1, 143, imap_segs),
    CASE("IRC with a DCC SEND", PROTO_IRC, 1, 6667, irc_segs),
    CASE("SMB1 Negotiate", PROTO_SMB, 1, 445, smb_segs),
    CASE("Gnutella PUSH", PROTO_GNUTELLA, 1, 6346, gnutella_segs),
    CASE("Gnutella CONNECT", PROTO_GNUTELLA, 1, 6346, gnutella_connect_segs),
    CASE("BitTorrent handshake", PROTO_BITTORRENT, 1, 6881, bittorrent_segs),
    CASE("eDonkey Hello", PROTO_EDONKEY, 1, 4662, edonkey_segs),
    CASE("Yahoo YMSG", PROTO_YAHOO, 1, 5050, yahoo_segs),
    CASE("MSN USR", PROTO_MSN, 1, 1863, msn_segs),
    CASE("MSN VER", PROTO_MSN, 1, 1863, msn_ver_segs),
    CASE("Jabber stream", PROTO_UNENCRYPED_JABBER, 1, 5222, jabber_segs),
    CASE("DirectConnect hub", PROTO_DIRECTCONNECT, 1, 411, directconnect_segs),
    CASE("DirectConnect peer", PROTO_DIRECTCONNECT, 1, 8008, directconnect_peer_segs),
    CASE("NetBIOS name response", PROTO_NETBIOS, 0, 137, netbios_segs),
    CASE("NetBIOS session request", PROTO_NETBIOS, 1, 139, netbios_tcp_segs),
    CASE("STUN binding request", PROTO_STUN, 0, 3478, stun_segs),
    CASE("QQ", PROTO_QQ, 0, 8001, qq_segs),
    CASE("QQ over TCP", PROTO_QQ, 1, 8002, qq_tcp_segs),
    CASE("Gadu-Gadu", PROTO_GADUGADU, 1, 8074, gadugadu_segs),
    CASE("Soulseek login", PROTO_SOULSEEK, 1, 2242, soulseek_segs),
    CASE("PPLive", PROTO_PPLIVE, 1, 8003, pplive_segs),
    CASE("RTP", PROTO_RTP, 0, 30000, rtp_segs),
    CASE("iMesh", PROTO_IMESH, 1, 8004, imesh_segs),
    CASE("AIMini", PROTO_AIMINI, 0, 8005, aimini_segs),
    CASE("Oscar file transfer", PROTO_OSCAR, 1, 5190, oscar_segs),
    CASE("Oscar FLAP", PROTO_OSCAR, 1, 5190, oscar_flap_segs),
    CASE("Zattoo", PROTO_ZATTOO, 1, 8006, zattoo_segs),
    CASE("SopCast", PROTO_SOPCAST, 1, 8007, sopcast_segs),
    CASE("SIP", PROTO_SIP, 0, 5060, sip_segs),
    CASE("POP3", PROTO_POP, 1, 110, pop_segs),
    CASE("SMTP", PROTO_SMTP, 1, 25, smtp_segs),
    CASE("MQTT", PROTO_MQTT, 1, 1883, mqtt_segs),
    CASE("FTP", PROTO_FTP, 1, 21, ftp_segs),
};

/* Direct download links (proto_direct_download_link.c): search_ddl_domains()
 * is a generated suffix matcher over the HTTP Host line; each host below
 * ends one of its branches (a ":port" suffix is stripped first). */
static const char *const ddl_hosts[] = {
    "www.4shared.com", "www.filecloud.com", "www.files-upload.com",
    "www.megaupload.com", "www.rapidupload.com", "www.turboupload.com",
    "www.badongo.com", "www.fileho.com", "www.bestsharing.com",
    "www.quicksharing.com", "www.uploading.com", "www.sharebig.com",
    "www.bigfilez.com", "www.chinamofile.com", "www.mofile.com",
    "www.hotfile.com", "www.keepmyfile.com", "www.savefile.com",
    "www.sendmefile.com", "www.sharebigfile.com", "www.up-file.com",
    "www.ftp2share.com", "www.gigeshare.com", "www.megashare.com",
    "www.rapidshare.com", "www.mediafire.com", "www.gigasize.com",
    "www.sendspace.com", "www.sharebee.com", "www.sharebigflie.com",
    "www.fileserve.com", "www.megashares.com", "www.fileupyours.com",
    "www.filefactory.com", "www.filefront.com", "www.uploadingit.com",
    "www.yourfilehost.com", "www.mytempdir.com", "www.uploadpower.com",
    "www.mega.1280.com", "www.filesonic.com", "www.badongo.net",
    "www.fast-load.net", "www.file-upload.net", "www.wiiupload.net",
    "www.filesend.net", "www.filer.net", "www.livedepot.net",
    "www.mofile.net", "www.zshare.net", "www.data.hu", "www.filearchiv.ru",
    "www.filepost.ru", "www.ifolder.ru", "www.filehost.tv",
    "www.filesafe.to", "www.sharebase.to", "www.files.to",
    "www.file-upload.to", "www.load.to", "www.uploaded.to",
    "www.leteckaposta.cz", "www.yourfiles.biz", "www.netload.in",
    "www.4shared.vn", "www.megashare.vn", "www.rapidshare.de",
    "www.ultrashare.de", "www.uploadyourfiles.de", "www.speedshare.org",
    "www.rapidshare.com:8080",
};

static void test_ddl(mmt_handler_t *h) {
    char req[512], msg[160];
    int ok = 0;
    const unsigned n = (unsigned) (sizeof ddl_hosts / sizeof ddl_hosts[0]);
    for (unsigned i = 0; i < n; i++) {
        int len = snprintf(req, sizeof req,
                           "GET /files/archive-%u.zip HTTP/1.1\r\n"
                           "Host: %s\r\n"
                           "User-Agent: mmt-dpi-test/1.0\r\n"
                           "Accept: */*\r\n\r\n", i, ddl_hosts[i]);
        if (len < 0 || (size_t) len >= sizeof req) {
            fprintf(stderr, "DDL request for %s does not fit\n", ddl_hosts[i]);
            exit(2);
        }
        const seg_t seg = { C2S, req, (unsigned) len };
        const case_t c = { "DDL", PROTO_DIRECT_DOWNLOAD_LINK, 1, 80, &seg, 1 };
        if (replay(h, &c, (uint16_t)(47000 + i)))
            ok++;
        else
            printf("  (Host: %s not classified as DDL)\n", ddl_hosts[i]);
    }
    snprintf(msg, sizeof msg, "%d/%u direct-download hosts are classified as DDL", ok, n);
    CHECK(ok == (int) n, msg);
}

int main(void) {
    char errbuf[1024];
    char msg[160];
    init_extraction();
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        close_extraction();
        return 2;
    }
    register_packet_handler(h, 1, packet_handler, NULL);

    printf("issue #531: tcpip classifier sweep (%u cases)\n",
           (unsigned) (sizeof g_cases / sizeof g_cases[0]));
    for (unsigned i = 0; i < sizeof g_cases / sizeof g_cases[0]; i++) {
        const case_t *c = &g_cases[i];
        snprintf(msg, sizeof msg, "%s exchange on %s port %u is classified as %s",
                 c->name, c->tcp ? "TCP" : "UDP", (unsigned) c->dport,
                 get_protocol_name_by_id((uint32_t) c->want));
        CHECK(replay(h, c, (uint16_t)(46000 + i)), msg);
    }
    test_ddl(h);
    CHECK(g_reads > 0, "attributes of the classified protocols are extracted");

    mmt_close_handler(h);
    close_extraction();
    printf("  %d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}

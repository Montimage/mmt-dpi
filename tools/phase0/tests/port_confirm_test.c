/*
 * port_confirm_test — unit test for the payload-confirmed port-only demotion
 * predicate (issue #75, M9 round 3).
 *
 * When an operator enables enable_port_classify_payload_confirm(), a port-based
 * protocol guess is only accepted if the packet payload carries a signature
 * consistent with the guessed protocol. The gate itself lives in
 * mmt_guess_protocol_by_port_number(); the reusable, side-effect-free decision
 * is mmt_payload_confirms_proto(proto_id, payload, len), exported from
 * libmmt_tcpip. This test pins that predicate down directly:
 *
 *   - a matching leading-byte signature CONFIRMS  (returns 1)
 *   - a mismatching / empty / NULL payload         does NOT confirm (returns 0)
 *   - a protocol with no known signature           does NOT confirm (conservative
 *                                                   demotion)
 *
 * The predicate is exported (non-static) but lives in an internal header that is
 * not installed, so it is re-declared here and the test links libmmt_tcpip
 * directly. A clean exit 0 with every CHECK passing is the success condition.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip_protocols.h"   /* PROTO_HTTP, PROTO_SSL, ... */

/* Predicate under test — exported from libmmt_tcpip, declared in the shared
 * internal header (issue #186). */
#include "internal_decls.h"

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

/* Helper: call with a C-string payload (length excludes the NUL). */
static int confirms(uint32_t proto, const char *s) {
    return mmt_payload_confirms_proto(proto, (const unsigned char *) s,
                                      (int) strlen(s));
}

int main(void) {
    printf("port_confirm_test: payload-confirmed port-only demotion (issue #75)\n");

    /* --- positive cases: a matching signature confirms the guess --- */
    CHECK(confirms(PROTO_HTTP, "GET / HTTP/1.1\r\n"),    "HTTP request line confirms HTTP");
    CHECK(confirms(PROTO_HTTP, "POST /x HTTP/1.0\r\n"),  "HTTP POST confirms HTTP");
    CHECK(confirms(PROTO_HTTP, "HTTP/1.1 200 OK\r\n"),   "HTTP status line confirms HTTP");
    CHECK(confirms(PROTO_SSH,  "SSH-2.0-OpenSSH_9.6"),   "SSH banner confirms SSH");
    CHECK(confirms(PROTO_SMTP, "220 mail.example ESMTP"),"SMTP greeting confirms SMTP");
    CHECK(confirms(PROTO_SMTP, "EHLO client"),           "SMTP EHLO confirms SMTP");
    CHECK(confirms(PROTO_POP,  "+OK POP3 ready"),        "POP +OK confirms POP");
    CHECK(confirms(PROTO_IMAP, "* OK IMAP4 ready"),      "IMAP * OK confirms IMAP");
    CHECK(confirms(PROTO_FTP,  "220 FTP server ready"),  "FTP greeting confirms FTP");
    CHECK(confirms(PROTO_FTP,  "220-multiline banner"),  "FTP multiline greeting confirms FTP");

    /* TLS handshake record: type 0x16, version 0x03 0x03 (TLS 1.2) */
    {
        const unsigned char tls[] = { 0x16, 0x03, 0x03, 0x00, 0x2f };
        CHECK(mmt_payload_confirms_proto(PROTO_SSL, tls, (int) sizeof(tls)),
              "TLS handshake record confirms SSL");
    }

    /* --- negative cases: wrong payload does NOT confirm --- */
    CHECK(!confirms(PROTO_HTTP, "SSH-2.0-OpenSSH"),  "SSH banner does not confirm HTTP");
    CHECK(!confirms(PROTO_SSH,  "GET / HTTP/1.1"),   "HTTP request does not confirm SSH");
    CHECK(!confirms(PROTO_SSL,  "GET / HTTP/1.1"),   "HTTP request does not confirm SSL");
    CHECK(!confirms(PROTO_HTTP, "random junk bytes"),"random payload does not confirm HTTP");
    CHECK(!confirms(PROTO_POP,  "-ERR no"),          "POP -ERR does not confirm POP");

    /* --- boundary cases --- */
    CHECK(!mmt_payload_confirms_proto(PROTO_HTTP, NULL, 10), "NULL payload does not confirm");
    CHECK(!confirms(PROTO_HTTP, ""),                  "empty payload does not confirm");
    CHECK(!mmt_payload_confirms_proto(PROTO_HTTP, (const unsigned char *) "GET ", 0),
          "zero length does not confirm");
    CHECK(!confirms(PROTO_HTTP, "GE"),                "truncated method does not confirm HTTP");

    /* --- conservative default: a protocol with no signature is not confirmed --- */
    CHECK(!confirms(PROTO_DNS, "anything at all"),    "unknown-signature proto (DNS) is not confirmed");
    CHECK(!confirms(PROTO_UNKNOWN, "anything"),       "PROTO_UNKNOWN is not confirmed");

    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    if (g_failures == 0) {
        printf("\xe2\x9c\x93 port_confirm_test: PASS\n");
        return 0;
    }
    printf("\xe2\x9c\x97 port_confirm_test: FAIL (%d failures)\n", g_failures);
    return 1;
}

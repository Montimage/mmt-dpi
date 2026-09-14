/*
 * ndn_tlv_bounds_test — regression for issue #205 (F-BUG-065, F-BUG-076):
 *
 *   F-BUG-065  ndn_TLV_parser() read the 2-byte TLV header without checking
 *              that two octets remained, and accumulated the multi-octet
 *              length through str_hex2int()'s pow(16, ...) arithmetic — an
 *              int overflow for >= 5 length octets that produced negative or
 *              garbage lengths. The fix accumulates the length in a checked
 *              uint64_t and rejects values above the remaining total_length.
 *
 *   F-BUG-076  mmt_check_ndn_payload() dereferenced payload[root->data_offset]
 *              after accepting a zero-length root TLV whose data_offset sits
 *              exactly one past the last captured byte.
 *
 * Style: direct calls on exactly-sized heap buffers — ASan brackets the
 * reads. Entry points are exported internals declared in internal_decls.h.
 *
 * Build (see run_ndn_tlv_bounds_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -o ndn_tlv_bounds_test ndn_tlv_bounds_test.c \
 *       -I<prefix>/dpi/include -I<repo>/src/mmt_tcpip/lib \
 *       -I<repo>/src/mmt_core/public_include -I<repo>/tools/phase0/tests \
 *       -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpthread -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mmt_core.h"
#include "internal_decls.h"

static int g_failures = 0;
static int g_checks   = 0;

#define CHECK(cond, msg) do {                                       \
        g_checks++;                                                 \
        if (cond) {                                                 \
            printf("  PASS: %s\n", (msg));                          \
        } else {                                                    \
            printf("  FAIL: %s\n", (msg));                          \
            g_failures++;                                           \
        }                                                           \
    } while (0)

static uint8_t *make_buf(const uint8_t *src, size_t len)
{
    uint8_t *b = (uint8_t *)malloc(len ? len : 1);
    if (!b) { perror("malloc"); exit(2); }
    memset(b, 0, len ? len : 1);
    if (src) memcpy(b, src, len);
    return b;
}

int main(void)
{
    printf("issue #205: NDN TLV bounds\n");

    /* --- F-BUG-065: 1-byte buffer — the TLV header read at offset+1 must not
     * run past the end. Pre-fix: payload[1] is out of bounds (ASan abort). */
    {
        uint8_t *b = make_buf(NULL, 1);
        b[0] = 0x05;
        struct ndn_tlv_struct *n = ndn_TLV_parser((char *)b, 0, 1);
        CHECK(n == NULL, "TLV header on a 1-byte buffer is rejected");
        if (n) ndn_TLV_free(n);
        free(b);
    }

    /* --- F-BUG-065: 8-octet length overflowing int --------------------------
     * type 0x05, length marker 0xff, length = 0xffffffffffffffff — the
     * declared length must be rejected against total_length, not wrapped. */
    {
        static const uint8_t pkt[] = {
            0x05, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        };
        uint8_t *b = make_buf(pkt, sizeof(pkt));
        struct ndn_tlv_struct *n = ndn_TLV_parser((char *)b, 0, sizeof(pkt));
        CHECK(n == NULL, "8-octet length > total_length is rejected");
        if (n) ndn_TLV_free(n);
        free(b);
    }

    /* --- F-BUG-076: zero-length root TLV one-past read ----------------------
     * {0x05, 0xfd, 0x00, 0x00}: type 5, 2-octet length = 0 — data_offset == 4
     * == packet_len, so payload[data_offset] reads one byte past the buffer.
     * Pre-fix: ASan abort inside mmt_check_ndn_payload. Post-fix: returns 0. */
    {
        static const uint8_t pkt[] = { 0x05, 0xfd, 0x00, 0x00 };
        uint8_t *b = make_buf(pkt, sizeof(pkt));
        int r = mmt_check_ndn_payload((char *)b, sizeof(pkt));
        CHECK(r == 0, "zero-length root TLV is not NDN (no one-past read)");
        free(b);
    }

    /* --- control: a minimal valid NDN interest still classifies -------------
     * {0x05, 0x03, 0x07, 0x01, 'x'}: type 5 len 3, name TLV 07 len 1 'x'. */
    {
        static const uint8_t pkt[] = { 0x05, 0x03, 0x07, 0x01, 'x' };
        uint8_t *b = make_buf(pkt, sizeof(pkt));
        int r = mmt_check_ndn_payload((char *)b, sizeof(pkt));
        CHECK(r == 1, "minimal valid NDN interest is still detected");
        free(b);
    }

    /* --- control: non-NDN is still rejected --------------------------------- */
    {
        static const uint8_t pkt[] = { 0x30, 0x03, 0x07, 0x01, 'x' };
        uint8_t *b = make_buf(pkt, sizeof(pkt));
        int r = mmt_check_ndn_payload((char *)b, sizeof(pkt));
        CHECK(r == 0, "non-NDN leading type is still rejected");
        free(b);
    }

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures != 0) {
        printf("RESULT: FAIL\n");
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}

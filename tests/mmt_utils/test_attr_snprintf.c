/*
 * test_attr_snprintf.c — public attribute formatters in packet_processing.c
 * (issue #505, F-BUG-007).
 *
 * mmt_header_line_pointer_snprintf() computed copy_len = len - 1 and wrote
 * buff[copy_len], so len <= 0 wrote buff[-1] (and len < 0 handed memcpy a
 * negative, i.e. huge, length). It now refuses len <= 0 and a NULL buffer or
 * attribute with -1, like the other *_snprintf formatters, and prints an
 * empty string for a header line with no data.
 *
 * packet_processing.c is compiled from source; the two registry lookups it
 * needs for the fprintf helpers are stubbed below (never reached here).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "packet_processing.h"
#include "mmt_core.h"

int mmt_header_line_pointer_snprintf(char *buff, int len, attribute_internal_t *attr);
/* No public header declares it; GCC >= 14 errors on implicit declarations (#514). */
int mmt_attr_snprintf(char *buff, int len, attribute_t *a);

const char *get_protocol_name_by_id(mmt_proto_id_t proto_id)
{ (void) proto_id; return "stub"; }
const char *get_attribute_name_by_protocol_and_attribute_ids(mmt_proto_id_t proto_id,
                                                             uint32_t attribute_id)
{ (void) proto_id; (void) attribute_id; return "stub"; }

static int g_failures;
#define CHECK(cond, msg) do { if (!(cond)) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); g_failures++; } } while (0)

int main(void)
{
    fprintf(stderr, "attribute snprintf test suite (#505)\n");

    static const char line[] = "Host: example.org";
    mmt_header_line_t hl = { line, (uint16_t) (sizeof line - 1) };
    attribute_internal_t attr;
    memset(&attr, 0, sizeof attr);
    attr.data_type = MMT_HEADER_LINE;
    attr.data = &hl;

    /* Guard bytes around a one-byte buffer catch a buff[-1] write under any
     * profile; ASan additionally reports it as a stack-buffer-underflow. */
    struct { char before; char buf[8]; char after; } g;
    for (int len = 0; len >= -3; len--) {
        memset(&g, 'G', sizeof g);
        int r = mmt_header_line_pointer_snprintf(g.buf, len, &attr);
        CHECK(r == -1, "len <= 0 returns -1");
        CHECK(g.before == 'G' && g.buf[0] == 'G', "len <= 0 writes nothing");
        memset(&g, 'G', sizeof g);
        r = mmt_attr_snprintf(g.buf, len, (attribute_t *) &attr);
        CHECK(r == -1, "mmt_attr_snprintf(MMT_HEADER_LINE, len <= 0) returns -1");
        CHECK(g.before == 'G' && g.buf[0] == 'G', "dispatcher len <= 0 writes nothing");
    }

    CHECK(mmt_header_line_pointer_snprintf(NULL, 8, &attr) == -1, "NULL buffer");
    CHECK(mmt_header_line_pointer_snprintf(g.buf, 8, NULL) == -1, "NULL attribute");

    /* len == 1: room for the terminator only. */
    memset(&g, 'G', sizeof g);
    CHECK(mmt_header_line_pointer_snprintf(g.buf, 1, &attr) == 0 && g.buf[0] == '\0'
          && g.buf[1] == 'G', "len 1 writes the terminator only");

    /* Truncation keeps the terminator inside len. */
    memset(&g, 'G', sizeof g);
    CHECK(mmt_header_line_pointer_snprintf(g.buf, (int) sizeof g.buf, &attr) == 7
          && strcmp(g.buf, "Host: e") == 0 && g.after == 'G', "truncated copy");

    /* Header line attribute with no data prints an empty string. */
    attr.data = NULL;
    memset(&g, 'G', sizeof g);
    CHECK(mmt_header_line_pointer_snprintf(g.buf, 8, &attr) == 0 && g.buf[0] == '\0',
          "NULL data prints an empty string");
    mmt_header_line_t empty = { NULL, 4 };
    attr.data = &empty;
    memset(&g, 'G', sizeof g);
    CHECK(mmt_header_line_pointer_snprintf(g.buf, 8, &attr) == 0 && g.buf[0] == '\0',
          "NULL line pointer prints an empty string");

    /* Full copy. */
    char big[64];
    attr.data = &hl;
    CHECK(mmt_header_line_pointer_snprintf(big, (int) sizeof big, &attr) == (int) hl.len
          && strcmp(big, line) == 0, "full copy");

    if (g_failures == 0) {
        fprintf(stderr, "ALL CHECKS PASSED\n");
        return 0;
    }
    fprintf(stderr, "%d CHECK(S) FAILED\n", g_failures);
    return 1;
}

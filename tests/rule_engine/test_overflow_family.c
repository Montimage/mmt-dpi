/*
 * test_overflow_family.c — regression tests for the tips.c overflow family
 * (issue #137): F-BUG-212 (zero divisor in COMPUTE) and F-BUG-208 (>99-byte
 * header line copied into get_my_data()'s 100-byte buffer).
 *
 * Both entry points are exported by libmmt_security (non-static in
 * src/mmt_security/tips.c) and are driven directly here, the same way the
 * phase0 harnesses drive individual classifiers:
 *
 *   void *compute(compare_value v1, compare_value v2, short operator);
 *   char *get_my_data(void *data1, short size, long type);
 *
 * Before F-BUG-212, a packet-forced divisor of 0 on the u64/u32/u16 COMPUTE
 * paths raised SIGFPE and killed the analyser (only the u8 path was guarded).
 * Before F-BUG-208, a header line longer than 99 bytes overflowed the
 * 100-byte heap buffer (caught by ASan when the suite runs under
 * SANITIZE=asan). Each check prints "ok - ..." on success; any failure is
 * reported and the process exits non-zero.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mmt_core.h"

/* Mirrors `struct COMPARE_VALUE_struct` in src/mmt_security/tips.c (not part
 * of the installed headers). Keep the field order in sync. */
typedef struct {
    int type;
    int size;
    int found;
    void *data;
} compare_value;

extern void *compute(compare_value v1, compare_value v2, short operator);
extern char *get_my_data(void *data1, short size, long type);

/* Rule-operator codes: mirrors the anonymous operator enum in
 * src/mmt_security/struct_defs.h (not installed, and it defines file-scope
 * variables so it cannot be included cleanly). Keep in sync. */
enum {
    OR, AND, NOT, REPEAT, NEQ, EQ, GT, GTE, LT, LTE,
    THEN, COMPUTE, COMPARE, XC, XCE, XD, XDE, XE, ADD, SUB,
    MUL, DIV
};

static int failures = 0;

#define CHECK(cond, msg) do {                                   \
    if (cond) { printf("ok - %s\n", (msg)); }                    \
    else { printf("FAIL - %s\n", (msg)); failures++; }          \
} while (0)

static compare_value make_value(int type, void *storage)
{
    compare_value v;
    memset(&v, 0, sizeof(v));
    v.type = type;
    v.found = 1;
    v.data = storage;
    switch (type) {
    case MMT_U8_DATA:  v.size = 1; break;
    case MMT_U16_DATA: v.size = 2; break;
    case MMT_U32_DATA: v.size = 4; break;
    default:           v.size = 8; break;
    }
    return v;
}

/* F-BUG-212: a divisor of 0 must yield NULL (no SIGFPE) on every unsigned
 * width, and a non-zero divisor must still produce the quotient so the same
 * code path is proven to be exercised.
 *
 * compute() has two families of paths:
 *   - the promoted path, taken when both operands are MMT_U8/U16/U32/U64_DATA
 *     (operands widened to unsigned long long, result unsigned long long);
 *   - the per-type switch, reached through the type codes that share a case
 *     label with a width: MMT_DATA_LAYERID (unsigned short, u16 path),
 *     MMT_DATA_PORT (unsigned long, u32 path), MMT_DATA_POINT (unsigned
 *     long long, u64 path). F-BUG-212 added the zero-divisor guard to these
 *     three; the u8 case already had one. */
static void *divide(int type, void *dividend, void *divisor)
{
    return compute(make_value(type, dividend), make_value(type, divisor), DIV);
}

static void test_compute_zero_divisor(void)
{
    char msg[160];
    void *result;

    /* --- promoted path: result is always unsigned long long --- */
    {
        static const struct { int type; const char *name; } widths[] = {
            { MMT_U64_DATA, "u64" }, { MMT_U32_DATA, "u32" },
            { MMT_U16_DATA, "u16" }, { MMT_U8_DATA,  "u8"  },
        };
        uint64_t d64 = 84, z64 = 0, t64 = 2;
        uint32_t d32 = 84, z32 = 0, t32 = 2;
        uint16_t d16 = 84, z16 = 0, t16 = 2;
        uint8_t  d8  = 84, z8  = 0, t8  = 2;
        size_t i;

        for (i = 0; i < sizeof(widths) / sizeof(widths[0]); i++) {
            void *dp = &d64, *zp = &z64, *tp = &t64;
            if (widths[i].type == MMT_U32_DATA) { dp = &d32; zp = &z32; tp = &t32; }
            if (widths[i].type == MMT_U16_DATA) { dp = &d16; zp = &z16; tp = &t16; }
            if (widths[i].type == MMT_U8_DATA)  { dp = &d8;  zp = &z8;  tp = &t8;  }

            result = divide(widths[i].type, dp, zp);
            snprintf(msg, sizeof(msg), "COMPUTE %s / 0 (promoted path) returns NULL instead of raising SIGFPE",
                     widths[i].name);
            CHECK(result == NULL, msg);
            free(result);

            result = divide(widths[i].type, dp, tp);
            snprintf(msg, sizeof(msg), "COMPUTE %s 84 / 2 == 42 (promoted path exercised)",
                     widths[i].name);
            CHECK(result != NULL && *(unsigned long long *)result == 42, msg);
            free(result);
        }

        /* Mixed widths also take the promoted path: u16 dividend / u32 zero. */
        result = compute(make_value(MMT_U16_DATA, &d16), make_value(MMT_U32_DATA, &z32), DIV);
        CHECK(result == NULL, "COMPUTE mixed-width u16 / u32(0) returns NULL");
        free(result);
    }

    /* --- per-type switch: u16 path (MMT_DATA_LAYERID reads unsigned short) --- */
    {
        unsigned short d = 84, z = 0, t = 2;
        result = divide(MMT_DATA_LAYERID, &d, &z);
        CHECK(result == NULL, "COMPUTE u16 path (LAYERID) / 0 returns NULL instead of raising SIGFPE");
        free(result);
        result = divide(MMT_DATA_LAYERID, &d, &t);
        CHECK(result != NULL && *(unsigned short *)result == 42, "COMPUTE u16 path (LAYERID) 84 / 2 == 42");
        free(result);
    }

    /* --- per-type switch: u32 path (MMT_DATA_PORT reads unsigned long) --- */
    {
        unsigned long d = 84, z = 0, t = 2;
        result = divide(MMT_DATA_PORT, &d, &z);
        CHECK(result == NULL, "COMPUTE u32 path (PORT) / 0 returns NULL instead of raising SIGFPE");
        free(result);
        result = divide(MMT_DATA_PORT, &d, &t);
        CHECK(result != NULL && *(unsigned long *)result == 42, "COMPUTE u32 path (PORT) 84 / 2 == 42");
        free(result);
    }

    /* --- per-type switch: u64 path (MMT_DATA_POINT reads unsigned long long) --- */
    {
        unsigned long long d = 84, z = 0, t = 2;
        result = divide(MMT_DATA_POINT, &d, &z);
        CHECK(result == NULL, "COMPUTE u64 path (POINT) / 0 returns NULL instead of raising SIGFPE");
        free(result);
        result = divide(MMT_DATA_POINT, &d, &t);
        CHECK(result != NULL && *(unsigned long long *)result == 42, "COMPUTE u64 path (POINT) 84 / 2 == 42");
        free(result);
    }
}

/* F-BUG-208: header lines longer than 99 bytes are clamped to 99 bytes and
 * NUL-terminated inside get_my_data()'s 100-byte buffer. */
static void test_header_line_clamped(void)
{
    enum { LONG_LEN = 150 };
    char *line = malloc(LONG_LEN); /* exactly LONG_LEN bytes: no NUL, ASan-fenced */
    mmt_header_line_t hl;
    char *out;
    int i;

    for (i = 0; i < LONG_LEN; i++)
        line[i] = (char)('a' + (i % 26));

    hl.ptr = line;
    hl.len = LONG_LEN;
    out = get_my_data(&hl, 0, MMT_HEADER_LINE);
    CHECK(out != NULL, "get_my_data(MMT_HEADER_LINE) returns a buffer for a 150-byte line");
    CHECK(out != NULL && strlen(out) == 99,
          "150-byte header line is clamped to 99 bytes + NUL");
    CHECK(out != NULL && memcmp(out, line, 99) == 0,
          "clamped copy preserves the first 99 bytes");
    free(out);

    hl.len = 99;
    out = get_my_data(&hl, 0, MMT_HEADER_LINE);
    CHECK(out != NULL && strlen(out) == 99 && memcmp(out, line, 99) == 0,
          "99-byte header line (boundary) is copied in full");
    free(out);

    hl.len = 0;
    out = get_my_data(&hl, 0, MMT_HEADER_LINE);
    CHECK(out != NULL && out[0] == '\0', "0-byte header line yields an empty string");
    free(out);

    free(line);
}

int main(void)
{
    test_compute_zero_divisor();
    test_header_line_clamped();

    if (failures) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    return 0;
}

/*
 * test_overflow_family.c — regression tests for the tips_extract.c
 * overflow family
 * (issue #137): F-BUG-212 (zero divisor in COMPUTE) and F-BUG-208 (>99-byte
 * header line copied into get_my_data()'s 100-byte buffer).
 *
 * Both entry points are exported by libmmt_security (non-static in
 * src/mmt_security/tips_extract.c) and are driven directly here, the same
 * way the
 * phase0 harnesses drive individual classifiers:
 *
 *   void *compute(compare_value v1, compare_value v2, enum_operation operator);
 *   char *get_my_data(void *data1, short size, long type);
 *
 * Before F-BUG-212, a packet-forced divisor of 0 on the u64/u32/u16 COMPUTE
 * paths raised SIGFPE and killed the analyser (only the u8 path was guarded).
 * Before F-BUG-208, a header line longer than 99 bytes overflowed the
 * 100-byte heap buffer (caught by ASan when the suite runs under
 * SANITIZE=asan). Each check prints "ok - ..." on success; any failure is
 * reported and the process exits non-zero.
 */
/* RTLD_NEXT (used by the fault-injection dlsym interposer below) is a GNU
 * extension — the feature-test macro must precede every libc include or the
 * floor toolchain (glibc 2.34/2.35) hides it. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "mmt_core.h"

/* Internal rule/tuple layouts — not installed headers, but including them keeps
 * this test in lock-step with src/mmt_security/tips_extract.c (same way
 * compare_value
 * is mirrored below for the #137 checks). */
#include "struct_defs.h"

/* verify_ctx_t and the prototypes of the functions exercised below come
 * from the real internal header (the suite adds -I src/mmt_security). */
#include "tips_internal.h"

/* Mirrors `struct COMPARE_VALUE_struct` in src/mmt_security/tips_extract.c
 * (not part
 * of the installed headers). Keep the field order in sync. */
typedef struct {
    int type;
    int size;
    int found;
    void *data;
} compare_value;

extern void *compute(compare_value v1, compare_value v2, enum_operation operator);
extern char *get_my_data(void *data1, short size, long type);

/* Rule-operator codes (OR/AND/.../MUL/DIV) come from struct_defs.h above. */

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

/* ======================================================================
 * Issue #209 — second tips_*.c overflow family
 * (F-BUG-091, F-BUG-092, F-BUG-093, F-BUG-095, F-BUG-096, F-BUG-102, F-BUG-103)
 *
 * Entry points are exported by libmmt_security (non-static in the tips_*.c
 * units) and are
 * driven directly here. For the allocation-failure and command-buffer checks
 * this binary interposes the libc-level symbols the engine bottoms out at —
 * xmalloc/xcalloc/xfree are engine-internal helpers (tips.c) that the
 * -flto shared
 * build binds invisibly, but their malloc/calloc/realloc/free (and fopen via
 * open_file) stay PLT-preemptible, so these definitions win process-wide:
 *   malloc/calloc/realloc/free — fault injection + live-allocation tracking
 *   fopen                    — returns tmpfile() while armed (no /opt/mmt needed)
 *   get_attribute_extracted_data — returns fabricated META_UTIME / header line
 * ====================================================================== */

extern char *convert_string_to_json_compatible(char *p, int size);
extern char *tokenize(char *temp, char **ltoken2, char **ltoken3, short *ref);
extern char *generate_command(const ipacket_t *pkt, rule *r, char *input);
extern char *xml_summary(void);

static int fi_tracking = 0;
static unsigned long fi_alloc_fail_after = 0; /* 0 = never fail; N = fail Nth alloc */
static unsigned long fi_alloc_seen = 0;
static void *fi_live[1024];
static int fi_live_n = 0;
static int fi_double_free = 0;
static int fi_open_tmpfile = 0;
static int fi_fake_extract = 0;
static struct timeval fi_tvp;
static mmt_header_line_t fi_hl;
static char fi_hl_bytes[512];
/* #510: one extra fabricated attribute (a string record) at fi_str_proto.
 * fi_str_field; every other non-META attribute stays the header line. */
static uint32_t fi_str_proto, fi_str_field;
static void *fi_str_rec;
/* and a pointer-typed string (MMT_STRING_DATA_POINTER) at fi_ptr_proto.fi_ptr_field */
static uint32_t fi_ptr_proto, fi_ptr_field;
static void *fi_ptr_val;

static void fi_track(void *p)
{
    if (fi_tracking && p != NULL && fi_live_n < (int)(sizeof(fi_live) / sizeof(fi_live[0])))
        fi_live[fi_live_n++] = p;
}

static void fi_untrack(void *p)
{
    int i;
    if (!fi_tracking || p == NULL) return;
    for (i = 0; i < fi_live_n; i++) {
        if (fi_live[i] == p) {
            fi_live[i] = fi_live[--fi_live_n];
            return;
        }
    }
    /* freeing a pointer that was never live-tracked = double free / foreign */
    fi_double_free = 1;
}

static void fi_reset(void)
{
    fi_live_n = 0;
    fi_double_free = 0;
    fi_alloc_fail_after = 0;
    fi_alloc_seen = 0;
    fi_tracking = 1;
}

/* --- interposed C-allocation family ----------------------------------------
 * the tips_*.c units' helper calls (xmalloc -> malloc etc.) are bound
 * internally by -flto in the shared build, but the libc symbols they bottom
 * out at stay PLT-preemptible — so the shims below see every allocation the
 * rule engine makes. The real targets are resolved once through
 * dlsym(RTLD_NEXT), which lands on libasan's interceptors when the shared
 * library is ASan-instrumented (so ASan keeps fencing the library's writes)
 * and on libc otherwise. A bump allocator covers allocations that occur while
 * dlsym itself runs (dlsym can call calloc). */
#include <dlfcn.h>

static void *(*real_malloc_fn)(size_t);
static void *(*real_calloc_fn)(size_t, size_t);
static void *(*real_realloc_fn)(void *, size_t);
static void (*real_free_fn)(void *);
static FILE *(*real_fopen_fn)(const char *, const char *);
static void *(*real_extract_fn)(const ipacket_t *, uint32_t, uint32_t);
static int fi_resolving = 0;
static char fi_boot[1 << 16];
static size_t fi_boot_off;

static void *fi_bump(size_t n)
{
    size_t off = (fi_boot_off + 15) & ~(size_t)15;
    if (off + n > sizeof(fi_boot)) return NULL;
    fi_boot_off = off + n;
    return fi_boot + off;
}

static int fi_is_boot(void *p)
{
    return p >= (void *)fi_boot && p < (void *)(fi_boot + sizeof(fi_boot));
}

static void fi_resolve(void)
{
    if (real_malloc_fn != NULL || fi_resolving) return;
    fi_resolving = 1;
    real_malloc_fn  = dlsym(RTLD_NEXT, "malloc");
    real_calloc_fn  = dlsym(RTLD_NEXT, "calloc");
    real_realloc_fn = dlsym(RTLD_NEXT, "realloc");
    real_free_fn    = dlsym(RTLD_NEXT, "free");
    real_fopen_fn   = dlsym(RTLD_NEXT, "fopen");
    real_extract_fn = dlsym(RTLD_NEXT, "get_attribute_extracted_data");
    fi_resolving = 0;
}

void *malloc(size_t n)
{
    void *p;
    if (fi_resolving || real_malloc_fn == NULL) {
        if (fi_resolving) return fi_bump(n);
        fi_resolve();
        if (real_malloc_fn == NULL) return fi_bump(n);
    }
    fi_alloc_seen++;
    if (fi_alloc_fail_after && --fi_alloc_fail_after == 0) return NULL;
    p = real_malloc_fn(n);
    fi_track(p);
    return p;
}

void *calloc(size_t a, size_t b)
{
    void *p;
    if (fi_resolving || real_calloc_fn == NULL) {
        if (fi_resolving) return fi_bump(a * b);
        fi_resolve();
        if (real_calloc_fn == NULL) return fi_bump(a * b);
    }
    fi_alloc_seen++;
    if (fi_alloc_fail_after && --fi_alloc_fail_after == 0) return NULL;
    p = real_calloc_fn(a, b);
    fi_track(p);
    return p;
}

void *realloc(void *p, size_t n)
{
    void *q;
    if (fi_is_boot(p)) return fi_bump(n);
    if (fi_resolving || real_realloc_fn == NULL) {
        fi_resolve();
        if (real_realloc_fn == NULL) return NULL;
    }
    q = real_realloc_fn(p, n);
    if (fi_tracking && q != NULL && q != p) {
        fi_untrack(p);
        fi_track(q);
    }
    return q;
}

void free(void *p)
{
    if (p == NULL || fi_is_boot(p)) return;
    if (real_free_fn == NULL) {
        fi_resolve();
        if (real_free_fn == NULL) return;
    }
    fi_untrack(p);
    real_free_fn(p);
}

FILE *fopen(const char *name, const char *mode)
{
    if (fi_open_tmpfile) return tmpfile();
    if (real_fopen_fn == NULL) {
        fi_resolve();
        if (real_fopen_fn == NULL) return NULL;
    }
    return real_fopen_fn(name, mode);
}

/* Armed only around store_history(): proto 1 (PROTO_META) is the UTIME read —
 * anything else is the fabricated header line. Unarmed calls fall through to
 * the real libmmt_core implementation. */
void *get_attribute_extracted_data(const ipacket_t *ipacket, uint32_t proto_id, uint32_t field_id)
{
    if (fi_fake_extract) {
        if (proto_id == 1) return &fi_tvp;
        if (fi_str_rec != NULL && proto_id == fi_str_proto && field_id == fi_str_field)
            return fi_str_rec;
        if (fi_ptr_val != NULL && proto_id == fi_ptr_proto && field_id == fi_ptr_field)
            return fi_ptr_val;
        return &fi_hl;
    }
    if (real_extract_fn == NULL) fi_resolve();
    if (real_extract_fn == NULL) return NULL;
    return real_extract_fn(ipacket, proto_id, field_id);
}

/* F-BUG-091: a declared 1504-byte, non-NUL-terminated MMT_STRING_LONG_DATA
 * attribute must be clamped into get_my_data()'s 100-byte buffer instead of
 * being sprintf("%s")'d over it. */
static void test_string_long_bounded(void)
{
    /* field layout handed down by get_value(): [int declared_len][bytes] */
    struct { int len; unsigned char data[1504]; } field;
    char *out;
    int i;

    field.len = 1504;
    for (i = 0; i < 1504; i++) field.data[i] = (unsigned char)('A' + (i % 26));

    out = get_my_data(&field, field.len, MMT_STRING_LONG_DATA);
    CHECK(out != NULL, "get_my_data(MMT_STRING_LONG_DATA) returns a buffer");
    CHECK(out != NULL && strlen(out) <= 99,
          "1504-byte string is clamped inside the 100-byte buffer");
    CHECK(out != NULL && memcmp(out, field.data, strlen(out)) == 0,
          "clamped string preserves the leading bytes");
    free(out);
}

/* F-BUG-093: a MMT_DATA_PATH of 19 elements including INT_MIN must not
 * overflow the 10-byte element buffer or the 100-byte result. */
static void test_data_path_bounded(void)
{
    int path[20];
    char *out;
    int i;

    path[0] = 19;
    for (i = 1; i < 20; i++) path[i] = (i == 10) ? (-2147483647 - 1) : i;

    out = get_my_data(path, 20, MMT_DATA_PATH);
    CHECK(out != NULL, "get_my_data(MMT_DATA_PATH) returns a buffer");
    CHECK(out != NULL && strlen(out) <= 99,
          "19-element path with INT_MIN stays inside the 100-byte buffer");
    free(out);
}

/* F-BUG-092: convert_string_to_json_compatible allocates size*6+1 (worst case
 * \u + 4 hex digits per byte), rejects non-positive sizes, and never writes
 * past it. */
static void test_json_escape_bounded(void)
{
    char raw[64];
    char *out;
    size_t i;

    for (i = 0; i < sizeof(raw); i++) raw[i] = (char)(i % 32); /* control bytes */

    out = convert_string_to_json_compatible(raw, (int)sizeof(raw));
    CHECK(out != NULL, "control-byte payload converts");
    if (out != NULL) {
        CHECK(strlen(out) <= 6 * sizeof(raw),
              "escaped output fits the size*6+1 allocation");
        CHECK(strchr(out, '"') == NULL && strstr(out, "\\u") != NULL,
              "control bytes emitted as escapes");
        free(out);
    }
    CHECK(convert_string_to_json_compatible(raw, 0) == NULL, "size 0 rejected");
    CHECK(convert_string_to_json_compatible(raw, -8) == NULL, "negative size rejected");
}

/* F-BUG-095: get_value() must read the header-line length from the
 * mmt_header_line_t before ->ptr is used — reading it from the contents gave a
 * contents-derived size. Assert *size equals the declared attribute length. */
static void test_get_value_header_line_length(void)
{
    char line[] = "Host: www.example.org";
    mmt_header_line_t hl;
    tuple t;
    short jump = 0, size = 0;
    char *out;
    long proto, field;

    CHECK(init_extraction() != 0, "init_extraction() registers protocols");
    proto = get_protocol_id_by_name("http");
    field = get_attribute_id_by_protocol_id_and_attribute_name((uint32_t)proto, "Host");
    CHECK(proto > 0 && field > 0, "http.Host resolves in the protocol table");
    if (!(proto > 0 && field > 0)) return;

    memset(&t, 0, sizeof t);
    hl.ptr = line;
    hl.len = (uint16_t)(sizeof(line) - 1);
    t.event_id = 7;
    t.data_size = (int)sizeof hl;
    t.valid = FOUND;
    t.protocol_id = proto;
    t.field_id = field;
    t.data_type_id = MMT_HEADER_LINE;
    t.data = &hl;

    out = get_value((const ipacket_t *)NULL, "http.Host.7", &jump, &size, &t);
    CHECK(out != NULL, "get_value(http.Host.7) returns a buffer");
    CHECK(size == (int)hl.len,
          "header-line length equals the declared attribute length");
    if (out != NULL) {
        CHECK(strcmp(out, "Host: www.example.org") == 0,
              "substituted value is the header-line contents");
        free(out);
    }
}

/* F-BUG-096: the header-line allocation failure inside store_history must
 * take the single cleanup exit — before the fix it broke out of the switch,
 * kept using json_buff (use-after-free) and freed both JSON buffers twice. */
static void test_store_history_alloc_failure(void)
{
    rule root, curr;
    tuple print_attr;
    long proto, field;

    proto = get_protocol_id_by_name("http");
    field = get_attribute_id_by_protocol_id_and_attribute_name((uint32_t)proto, "Host");
    if (!(proto > 0 && field > 0)) {
        printf("FAIL - cannot build header-line attribute without http.Host\n");
        failures++;
        return;
    }

    memset(&root, 0, sizeof root);
    memset(&curr, 0, sizeof curr);
    memset(&print_attr, 0, sizeof print_attr);
    print_attr.protocol_id = proto;
    print_attr.field_id = field;
    print_attr.data_type_id = MMT_HEADER_LINE;
    root.list_of_tuples_to_print = &print_attr;
    curr.json_history = NULL;

    memset(fi_hl_bytes, 'q', sizeof fi_hl_bytes);
    fi_hl.ptr = fi_hl_bytes;
    fi_hl.len = 200;
    fi_tvp.tv_sec = 1;
    fi_tvp.tv_usec = 2;

    fi_fake_extract = 1;
    fi_reset();
    /* allocation order inside store_history: xcalloc(json_buff),
     * xcalloc(json_buff1), then xmalloc(buff) in the MMT_HEADER_LINE case —
     * failing the 3rd exercises the F-BUG-096 cleanup-exit path. */
    fi_alloc_fail_after = 3;
    verify_ctx_t hctx = { NULL, &root, NULL, NULL, { 0, 0 }, NO, NO };
    store_history(&hctx, SAME, &curr, "test-cause", 3);
    CHECK(fi_alloc_seen >= 3, "fault injection reached the failing allocation");
    CHECK(!fi_double_free,
          "allocation-failure path frees each JSON buffer exactly once");
    CHECK(fi_live_n == 0,
          "allocation-failure path reaches one cleanup exit (nothing leaked)");

    /* sunny path: substitution path runs end-to-end under ASan */
    fi_reset();
    store_history(&hctx, SAME, &curr, "test-cause", 3);
    CHECK(curr.json_history != NULL && strstr(curr.json_history, "timestamp") != NULL,
          "store_history records the substituted attribute");
    CHECK(!fi_double_free, "sunny path frees each JSON buffer exactly once");
    fi_fake_extract = 0;
    fi_tracking = 0;
    free(curr.json_history);
}

/* F-BUG-209 (#510): store_history() wrote header-line and string values
 * (and the cause) into the verdict JSON raw — a quote ended the JSON string
 * early and a control byte made the document invalid. The values below
 * carry a quote, a backslash and control bytes; the history must hold them
 * escaped. The third one is a 1504-byte control-byte string whose escaped
 * form (9024 bytes) is longer than store_history()'s 8192-byte formatting
 * buffer: it must be appended whole, not cut. With OVERFLOW_JSON_OUT set, the verdict document the callback
 * would get ("{" history "}") is written there for run_tests.sh's jq pass. */
static void test_store_history_escapes_strings(void)
{
    static const char hl_raw[] = "Host: \"evil\"\\\n\x01\t";
    static const char str_raw[] = "tok\"en\x1f";
    char cause[] = "cause \"q\"\x02";
    rule root, curr;
    tuple attrs[3];
    mmt_string_data_t *rec;
    char *hl_buf, *doc, *long_str;
    const unsigned char *c;
    long hproto, hfield, sproto, sfield, pproto, pfield;
    int raw_ctl = 0;
    size_t n;

    hproto = get_protocol_id_by_name("http");
    hfield = get_attribute_id_by_protocol_id_and_attribute_name((uint32_t)hproto, "Host");
    sproto = get_protocol_id_by_name("quic_ietf");
    sfield = get_attribute_id_by_protocol_id_and_attribute_name((uint32_t)sproto, "token");
    pproto = get_protocol_id_by_name("ftp");
    pfield = get_attribute_id_by_protocol_id_and_attribute_name((uint32_t)pproto, "user_name");
    if (!(hproto > 0 && hfield > 0 && sproto > 0 && sfield > 0 && pproto > 0 && pfield > 0)) {
        printf("FAIL - cannot resolve http.Host / quic_ietf.token / ftp.user_name\n");
        failures++;
        return;
    }

    memset(&root, 0, sizeof root);
    memset(&curr, 0, sizeof curr);
    memset(attrs, 0, sizeof attrs);
    attrs[0].protocol_id = hproto;
    attrs[0].field_id = hfield;
    attrs[0].data_type_id = MMT_HEADER_LINE;
    attrs[0].next = &attrs[1];
    attrs[1].protocol_id = sproto;
    attrs[1].field_id = sfield;
    attrs[1].data_type_id = MMT_STRING_LONG_DATA;
    attrs[1].next = &attrs[2];
    attrs[2].protocol_id = pproto;
    attrs[2].field_id = pfield;
    attrs[2].data_type_id = MMT_STRING_DATA_POINTER;
    root.list_of_tuples_to_print = &attrs[0];

    /* header line: exactly its bytes, no terminator */
    hl_buf = malloc(sizeof hl_raw - 1);
    rec = calloc(1, sizeof *rec);
    long_str = malloc(STRING_DATA_LEN + 1);
    if (hl_buf == NULL || rec == NULL || long_str == NULL) {
        printf("FAIL - allocation for the escaping test\n");
        failures++;
        free(hl_buf); free(rec); free(long_str);
        return;
    }
    memset(long_str, 0x01, STRING_DATA_LEN);
    long_str[STRING_DATA_LEN] = '\0';
    fi_ptr_proto = (uint32_t)pproto;
    fi_ptr_field = (uint32_t)pfield;
    fi_ptr_val = long_str;
    memcpy(hl_buf, hl_raw, sizeof hl_raw - 1);
    fi_hl.ptr = hl_buf;
    fi_hl.len = (uint16_t)(sizeof hl_raw - 1);
    rec->len = (uint32_t)(sizeof str_raw - 1);
    memcpy(rec->data, str_raw, sizeof str_raw - 1);
    fi_str_proto = (uint32_t)sproto;
    fi_str_field = (uint32_t)sfield;
    fi_str_rec = rec;
    fi_tvp.tv_sec = 1;
    fi_tvp.tv_usec = 2;

    fi_fake_extract = 1;
    fi_reset();
    verify_ctx_t hctx = { NULL, &root, NULL, NULL, { 0, 0 }, NO, NO };
    store_history(&hctx, SAME, &curr, cause, 4);
    fi_fake_extract = 0;
    fi_tracking = 0;
    fi_str_rec = NULL;
    fi_ptr_val = NULL;

    CHECK(curr.json_history != NULL, "store_history records a history for string attributes");
    if (curr.json_history != NULL) {
        for (c = (const unsigned char *)curr.json_history; *c != '\0'; c++)
            if (*c < 0x20) raw_ctl = 1;
        CHECK(!raw_ctl, "history carries no raw control byte");
        CHECK(strstr(curr.json_history, "Host: \\\"evil\\\"\\\\\\n\\u0001\\t") != NULL,
              "header-line quote, backslash and control bytes are escaped");
        CHECK(strstr(curr.json_history, "tok\\\"en\\u001f") != NULL,
              "string-record quote and control byte are escaped");
        CHECK(strstr(curr.json_history, "\"description\":\"cause \\\"q\\\"\\u0002\"") != NULL,
              "the cause is escaped");
        {
            /* 1504 escaped 0x01 bytes, then the closing quote and brace */
            const char *v = strstr(curr.json_history, "\\u0001\\u0001");
            size_t run = 0;
            while (v != NULL && strncmp(v + run * 6, "\\u0001", 6) == 0) run++;
            CHECK(run == STRING_DATA_LEN && v != NULL &&
                  strncmp(v + run * 6, "\"},", 3) == 0,
                  "a value escaped past the 8192-byte formatting buffer is appended whole");
        }
        /* the document rule_is_satisfied_or_not() hands the callback */
        n = strlen(curr.json_history);
        if (n > 0 && curr.json_history[n - 1] == ',') curr.json_history[n - 1] = '\0';
        doc = malloc(strlen(curr.json_history) + 3);
        if (doc != NULL) {
            const char *out = getenv("OVERFLOW_JSON_OUT");
            sprintf(doc, "{%s}", curr.json_history);
            if (out != NULL && *out != '\0') {
                FILE *f = fopen(out, "w");
                CHECK(f != NULL, "verdict document written for jq");
                if (f != NULL) { fprintf(f, "%s\n", doc); fclose(f); }
            }
            free(doc);
        }
        free(curr.json_history);
    }
    free(hl_buf);
    free(rec);
    free(long_str);
}

/* F-BUG-210 (#510): get_data_from_pcap() copied each operand by length into
 * a buffer of exactly that length, then XC/XCE/XD/XDE ran strstr() on it —
 * reading past the allocation (an ASan heap-buffer-overflow) whenever the
 * packet bytes or the rule constant carry no terminator. Both operands here
 * are unterminated: the packet header line (exactly 8 bytes, ASan-fenced)
 * and the rule's string constant. */
static void test_contains_unterminated_operands(void)
{
    static const struct { int op; const char *constant; int expect; const char *msg; } cases[] = {
        { XC,  "def",          VALID,     "XC: unterminated header line contains the constant" },
        { XCE, "xyz",          NOT_VALID, "XCE: unterminated header line lacks the constant" },
        { XD,  "--abcdefgh--", VALID,     "XD: the constant contains the unterminated header line" },
        { XDE, "abc",          NOT_VALID, "XDE: a shorter constant cannot contain the header line" },
    };
    static const char hay[] = "abcdefgh";
    long proto, field;
    char *hl_buf;
    size_t i;

    proto = get_protocol_id_by_name("http");
    field = get_attribute_id_by_protocol_id_and_attribute_name((uint32_t)proto, "Host");
    hl_buf = malloc(sizeof hay - 1);
    if (!(proto > 0 && field > 0) || hl_buf == NULL) {
        printf("FAIL - cannot build the XC/XD operands\n");
        failures++;
        free(hl_buf);
        return;
    }
    memcpy(hl_buf, hay, sizeof hay - 1);

    for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        rule packet_leaf, const_leaf, root;
        size_t clen = strlen(cases[i].constant);
        /* rule constant record: [int len][bytes], no terminator */
        char *crec = malloc(sizeof(int) + clen);
        int len_prefix = (int)clen, ret;
        if (crec == NULL) { printf("FAIL - %s: allocation\n", cases[i].msg); failures++; continue; }
        memcpy(crec, &len_prefix, sizeof len_prefix);
        memcpy(crec + sizeof(int), cases[i].constant, clen);

        memset(&packet_leaf, 0, sizeof packet_leaf);
        memset(&const_leaf, 0, sizeof const_leaf);
        memset(&root, 0, sizeof root);
        packet_leaf.value = XVAR;
        packet_leaf.t.protocol_id = proto;
        packet_leaf.t.field_id = field;
        packet_leaf.t.data_type_id = MMT_HEADER_LINE;
        const_leaf.value = XCON;
        const_leaf.t.data_type_id = MMT_STRING_DATA;
        const_leaf.t.data_size = (int)(sizeof(int) + clen);
        const_leaf.t.data = crec;

        fi_hl.ptr = hl_buf;
        fi_hl.len = (uint16_t)(sizeof hay - 1);
        fi_fake_extract = 1;
        verify_ctx_t cctx = { NULL, &root, NULL, NULL, { 0, 0 }, NO, NO };
        ret = get_data_from_pcap(&cctx, COMPARE, NULL, (enum_operation)cases[i].op,
                                 &packet_leaf, &const_leaf);
        fi_fake_extract = 0;
        CHECK(ret == cases[i].expect, cases[i].msg);
        free(crec);
    }
    free(hl_buf);
}

/* F-BUG-102: generate_command sized its buffer from the parameter names while
 * substitutions append escaped values; with 40 header-line substitutions the
 * old fixed buffer overflows. Malformed input must return NULL without
 * leaking the command buffer. Since #512 the detection_<n>.data file goes
 * to MMT_SEC_REACTION_DIR — a scratch folder here — and a failed command
 * removes the one it claimed. */
static void test_generate_command_bounded(void)
{
    rule r;
    tuple t;
    mmt_header_line_t hl;
    char line[100];
    char input[1024];
    char dir[] = "/tmp/mmt-reaction.XXXXXX";
    char path[sizeof dir + 32];
    struct stat st;
    char *cmd;
    long proto, field;
    size_t pos;
    int i;

    if (mkdtemp(dir) == NULL || setenv("MMT_SEC_REACTION_DIR", dir, 1) != 0) {
        printf("FAIL - cannot create a scratch reaction folder\n");
        failures++;
        return;
    }

    proto = get_protocol_id_by_name("http");
    field = get_attribute_id_by_protocol_id_and_attribute_name((uint32_t)proto, "Host");
    if (!(proto > 0 && field > 0)) {
        printf("FAIL - cannot build header-line attribute without http.Host\n");
        failures++;
        return;
    }

    memset(line, '\'', 99); /* worst case: every byte expands to '\'' */
    hl.ptr = line;
    hl.len = 99;
    memset(&t, 0, sizeof t);
    t.event_id = 7;
    t.data_size = (int)sizeof hl;
    t.valid = FOUND;
    t.protocol_id = proto;
    t.field_id = field;
    t.data_type_id = MMT_HEADER_LINE;
    t.data = &hl;

    memset(&r, 0, sizeof r);
    r.list_of_tuples = &t;
    r.type_rule = ATTACK;
    r.property_id = 42;
    r.description = (char *)"desc";

    pos = (size_t)snprintf(input, sizeof input, "dummy(");
    for (i = 0; i < 40; i++)
        pos += (size_t)snprintf(input + pos, sizeof input - pos, "%shttp.Host.7", i ? "," : "");
    input[pos++] = ')';
    input[pos] = '\0';

    fi_reset();
    fi_open_tmpfile = 1;
    cmd = generate_command((const ipacket_t *)NULL, &r, input);
    fi_open_tmpfile = 0;
    CHECK(cmd != NULL, "generate_command returns a command");
    if (cmd != NULL) {
        CHECK(strlen(cmd) > 6000,
              "substituted output exceeds the legacy fixed buffer (grew, no overflow)");
        CHECK(strstr(cmd, "\\''") != NULL,
              "packet-derived value is single-quote escaped");
        free(cmd); /* goes through the free() shim -> untracked, keeps balance */
    }
    CHECK(!fi_double_free, "generate_command frees each buffer exactly once");
    CHECK(fi_live_n == 0, "generate_command leaves no leaked buffers");

    fi_reset();
    fi_open_tmpfile = 1;
    cmd = generate_command((const ipacket_t *)NULL, &r, "dummy(1,http.Host.7"); /* missing ')' */
    fi_open_tmpfile = 0;
    CHECK(cmd == NULL, "malformed reaction returns NULL");
    CHECK(fi_live_n == 0 && !fi_double_free,
          "error path frees the command buffer (no leak)");
    fi_tracking = 0;

    snprintf(path, sizeof path, "%s/detection_1.data", dir);
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600,
          "detection_1.data is created in MMT_SEC_REACTION_DIR with mode 0600");
    unlink(path);
    snprintf(path, sizeof path, "%s/detection_2.data", dir);
    CHECK(stat(path, &st) != 0, "the failed command removes the detection file it claimed");
    unsetenv("MMT_SEC_REACTION_DIR");
    CHECK(rmdir(dir) == 0, "the reaction folder holds nothing else");
}

/* compare_in_table (reached via compare_values when a rule uses XIN on a
 * MMT_BINARY_VAR_DATA operand) used the byte offset i as the element index —
 * reading up to 8x past the operand buffer for u64 and never comparing
 * odd-indexed elements. Elements must be scanned by element number, and only
 * complete elements inside v2.size. */
extern int compare_values(compare_value v1, compare_value v2, enum_operation ope);

static void test_compare_in_table_bounded(void)
{
    compare_value v1, v2;
    /* 3 complete u64 elements + a 4-byte partial tail (28-byte table). */
    unsigned long long table[3] = {
        0xAAAAAAAAAAAAAAAAULL, 0x1122334455667788ULL, 0xCCCCCCCCCCCCCCCCULL
    };
    unsigned long long needle = 0x1122334455667788ULL; /* at element index 1 */
    unsigned long long absent = 0x8877665544332211ULL;
    /* u16 table with the needle at element index 1 (skipped before the fix). */
    unsigned short table16[4] = { 0x0001, 0xBEEF, 0x0003, 0x0004 };
    unsigned short needle16 = 0xBEEF;
    void *heap28 = malloc(28);

    memset(&v1, 0, sizeof v1);
    memset(&v2, 0, sizeof v2);
    v1.type = MMT_U64_DATA;
    v1.found = FOUND;
    v1.size = (int)sizeof(unsigned long long);
    v1.data = &needle;
    v2.type = MMT_BINARY_VAR_DATA;
    v2.found = FOUND;
    v2.size = 28; /* 3 complete u64 elements + partial tail */
    v2.data = heap28;
    memcpy(heap28, table, sizeof table);
    memcpy((char *)heap28 + 24, &absent, 4); /* partial tail: must not match */

    CHECK(compare_values(v1, v2, XIN) == VALID,
          "XIN u64 finds the value at element index 1 (was skipped by the byte-offset index)");
    v1.data = &absent;
    CHECK(compare_values(v1, v2, XIN) == NOT_VALID,
          "XIN u64 does not match the partial 4-byte tail");
    free(heap28);

    memset(&v1, 0, sizeof v1);
    memset(&v2, 0, sizeof v2);
    v1.type = MMT_U16_DATA;
    v1.found = FOUND;
    v1.size = (int)sizeof(unsigned short);
    v1.data = &needle16;
    v2.type = MMT_BINARY_VAR_DATA;
    v2.found = FOUND;
    v2.size = (int)sizeof table16;
    v2.data = malloc(sizeof table16);
    memcpy(v2.data, table16, sizeof table16);
    CHECK(compare_values(v1, v2, XIN) == VALID,
          "XIN u16 finds the value at element index 1 (was skipped by the byte-offset index)");
    needle16 = 0xDEAD;
    CHECK(compare_values(v1, v2, XIN) == NOT_VALID,
          "XIN u16 returns NOT_VALID for an absent value");
    free(v2.data);
}

/* F-BUG-103: the 30-byte token buffers in tokenize() and the trailing-comma
 * reads on an empty history are fixed; exercise the token bounds plus the
 * rewritten bounded appends in xml_summary(). */
static void test_tokenize_and_summary_bounded(void)
{
    char *t2 = malloc(30), *t3 = malloc(30);
    short ref = 0;
    char long_names[] = "PROTOCOLNAMEOVER30CHARSLONGZZZZZZZZZZZZZZZZZZZZZZZZZ.FIELDNAMEOVER30CHARSLONGYYYYYYYYYYYYYYYY.12345";
    char mega_digits[] = "a.b.9999999999999999999999999999999999999999";
    char *summary;

    memset(t2, 0, 30);
    memset(t3, 0, 30);
    tokenize(long_names, &t2, &t3, &ref);
    CHECK(strlen(t2) <= 29 && strlen(t3) <= 29,
          "long PROTO.FIELD names are bounded to 29 bytes");
    CHECK(ref == 12345, "event id still parses after truncated names");

    memset(t2, 0, 30);
    memset(t3, 0, 30);
    ref = 0;
    tokenize(mega_digits, &t2, &t3, &ref);
    CHECK(strlen(t2) <= 29 && strlen(t3) <= 29,
          "40-digit event id is bounded to the 30-byte token buffer");

    free(t2);
    free(t3);

    summary = xml_summary();
    CHECK(summary != NULL && strstr(summary, "</results>") != NULL,
          "xml_summary produces a bounded document");
    free(summary);
}

/* ======================================================================
 * Issue #326 — fill-in/prune of the security-engine branches
 *
 * The branches this issue implemented are driven directly:
 *   - get_my_data(): IPv6 / float / string-pointer / generic header line
 *     formatting, and the intentionally-unsupported types returning the
 *     empty string instead of reaching the fatal default;
 *   - compare_values(): string-pointer operands compare by contents, and
 *     the fixed-width XIN membership walk covers IP/MAC/timeval records;
 *   - compute(): float arithmetic incl. the zero-divisor guard;
 *   - get_xdata() (tips_xml.c): IPv4/IPv6/float/string-pointer constants;
 *   - check_for_countout() (tips_eval.c): the counter window increments
 *     once per call and honours the positive bounds.
 * ====================================================================== */

extern void *get_xdata(long type, int size, void *str, short is_string_data);
extern int check_for_countout(rule *r, int count);

static void test_get_my_data_filled_branches(void)
{
    char *out;
    unsigned char ip6[16] = { 0 };
    float fval = 1.5f;
    struct timeval tv = { .tv_sec = 1, .tv_usec = 2 };
    char *sptr = (char *)"ndn-name-component";
    mmt_generic_header_line_t ghl;
    unsigned long ignored = 0;

    /* ::1 -> all-zero 16-byte address except the last byte */
    ip6[15] = 1;
    out = get_my_data(ip6, 16, MMT_DATA_IP6_ADDR);
    CHECK(out != NULL && strcmp(out, "::1") == 0,
          "get_my_data(MMT_DATA_IP6_ADDR) formats ::1");
    free(out);

    out = get_my_data(&fval, (short)sizeof fval, MMT_DATA_FLOAT);
    CHECK(out != NULL && strcmp(out, "1.500000") == 0,
          "get_my_data(MMT_DATA_FLOAT) formats the float value");
    free(out);

    out = get_my_data(&tv, (short)sizeof tv, MMT_DATA_TIMEVAL);
    CHECK(out != NULL && strcmp(out, "1.000002") == 0,
          "get_my_data(MMT_DATA_TIMEVAL) formats sec.usec");
    free(out);

    out = get_my_data(sptr, (short)sizeof sptr, MMT_STRING_DATA_POINTER);
    CHECK(out != NULL && strcmp(out, "ndn-name-component") == 0,
          "get_my_data(MMT_STRING_DATA_POINTER) prints the pointed-to string");
    free(out);

    ghl.hfield = "Host";
    ghl.hvalue = "www.example.org";
    out = get_my_data(&ghl, (short)sizeof ghl, MMT_GENERIC_HEADER_LINE);
    CHECK(out != NULL && strcmp(out, "Host: www.example.org") == 0,
          "get_my_data(MMT_GENERIC_HEADER_LINE) formats 'field: value'");
    free(out);

    /* Intentionally unsupported types return the empty string — the fatal
     * default (Error 15.1 -> exit) must not be reached. */
    out = get_my_data(&ignored, 0, MMT_DATA_PORT);
    CHECK(out != NULL && out[0] == '\0',
          "get_my_data(MMT_DATA_PORT) is intentionally unsupported (empty)");
    free(out);
    out = get_my_data(&ignored, 0, MMT_DATA_FILTER_STATE);
    CHECK(out != NULL && out[0] == '\0',
          "get_my_data(MMT_DATA_FILTER_STATE) is intentionally unsupported (empty)");
    free(out);
}

static void test_string_pointer_compare(void)
{
    compare_value v1, v2;
    char *s1 = (char *)"content-name";
    char *s2 = (char *)"content-name";
    char *s3 = (char *)"different";
    char *s4 = (char *)"name";

    memset(&v1, 0, sizeof v1);
    memset(&v2, 0, sizeof v2);
    v1.type = MMT_STRING_DATA_POINTER;
    v1.found = FOUND;
    v1.size = (int)sizeof(char *);
    v1.data = &s1; /* the operand buffer holds the string pointer */
    v2 = v1;

    v2.data = &s2;
    CHECK(compare_values(v1, v2, EQ) == VALID,
          "string-pointer EQ compares contents, not pointer values");
    CHECK(compare_values(v1, v2, NEQ) == NOT_VALID,
          "string-pointer NEQ on equal contents is NOT_VALID");

    v2.data = &s3;
    CHECK(compare_values(v1, v2, NEQ) == VALID,
          "string-pointer NEQ on different contents is VALID");
    CHECK(compare_values(v1, v2, EQ) == NOT_VALID,
          "string-pointer EQ on different contents is NOT_VALID");

    v2.data = &s4;
    CHECK(compare_values(v1, v2, XC) == VALID,
          "string-pointer XC finds the substring inside the contents");
    CHECK(compare_values(v1, v2, LT) == VALID,
          "string-pointer LT uses lexicographic contents order");
}

static void test_xin_fixed_width_membership(void)
{
    compare_value v1, v2;
    unsigned char table[32];
    unsigned char needle[16];
    unsigned char absent[16];
    struct timeval tvt[2] = { { 5, 500 }, { 9, 900 } };
    struct timeval tv_needle = { 9, 900 };

    memset(table, 0, sizeof table);
    table[15] = 1;                 /* element 0 = ::1 */
    memset(needle, 0, sizeof needle);
    needle[0] = 0x20; needle[1] = 0x01;
    memcpy(table + 16, needle, 16); /* element 1 = needle */

    memset(&v1, 0, sizeof v1);
    memset(&v2, 0, sizeof v2);
    v1.type = MMT_DATA_IP6_ADDR;
    v1.found = FOUND;
    v1.size = 16;
    v1.data = needle;
    v2.type = MMT_BINARY_VAR_DATA;
    v2.found = FOUND;
    v2.size = (int)sizeof table;
    v2.data = table;

    CHECK(compare_values(v1, v2, XIN) == VALID,
          "XIN IPv6 finds the address at element index 1");
    memset(absent, 0, sizeof absent);
    absent[0] = 0xfe; absent[1] = 0x80;
    v1.data = absent;
    CHECK(compare_values(v1, v2, XIN) == NOT_VALID,
          "XIN IPv6 returns NOT_VALID for an absent address");

    memset(&v1, 0, sizeof v1);
    memset(&v2, 0, sizeof v2);
    v1.type = MMT_DATA_TIMEVAL;
    v1.found = FOUND;
    v1.size = (int)sizeof(struct timeval);
    v1.data = &tv_needle;
    v2.type = MMT_BINARY_VAR_DATA;
    v2.found = FOUND;
    v2.size = (int)sizeof tvt;
    v2.data = tvt;
    CHECK(compare_values(v1, v2, XIN) == VALID,
          "XIN timeval finds the value at element index 1");
    tv_needle.tv_sec = 7;
    CHECK(compare_values(v1, v2, XIN) == NOT_VALID,
          "XIN timeval returns NOT_VALID for an absent value");
}

static void test_compute_float(void)
{
    float a = 1.5f, b = 0.5f, z = 0.0f;
    void *result;

    result = compute(make_value(MMT_DATA_FLOAT, &a), make_value(MMT_DATA_FLOAT, &b), ADD);
    CHECK(result != NULL && *(float *)result == 2.0f,
          "COMPUTE float 1.5 + 0.5 == 2.0");
    free(result);

    result = compute(make_value(MMT_DATA_FLOAT, &a), make_value(MMT_DATA_FLOAT, &b), SUB);
    CHECK(result != NULL && *(float *)result == 1.0f,
          "COMPUTE float 1.5 - 0.5 == 1.0");
    free(result);

    result = compute(make_value(MMT_DATA_FLOAT, &a), make_value(MMT_DATA_FLOAT, &b), MUL);
    CHECK(result != NULL && *(float *)result == 0.75f,
          "COMPUTE float 1.5 * 0.5 == 0.75");
    free(result);

    result = compute(make_value(MMT_DATA_FLOAT, &a), make_value(MMT_DATA_FLOAT, &b), DIV);
    CHECK(result != NULL && *(float *)result == 3.0f,
          "COMPUTE float 1.5 / 0.5 == 3.0");
    free(result);

    result = compute(make_value(MMT_DATA_FLOAT, &a), make_value(MMT_DATA_FLOAT, &z), DIV);
    CHECK(result == NULL,
          "COMPUTE float / 0.0 returns NULL instead of raising SIGFPE");
    free(result);
}

static void test_get_xdata_filled_branches(void)
{
    void *data;
    char ip4tok[] = "10.0.0.1";
    char flttok[] = "1.5";
    /* quoted constants arrive as an mmt_string_data_t record */
    struct { uint32_t len; char data[64]; } ip6_rec;
    struct { uint32_t len; char data[64]; } str_rec;

    data = get_xdata(MMT_DATA_IP_ADDR, 4, ip4tok, NO);
    CHECK(data != NULL && ((unsigned char *)data)[0] == 10 &&
          ((unsigned char *)data)[3] == 1,
          "get_xdata parses a dotted-quad IPv4 constant");
    free(data);

    memset(&ip6_rec, 0, sizeof ip6_rec);
    strcpy(ip6_rec.data, "::1");
    ip6_rec.len = (uint32_t)strlen(ip6_rec.data) + 1;
    data = get_xdata(MMT_DATA_IP6_ADDR, 16, &ip6_rec, YES);
    CHECK(data != NULL && memcmp((char *)data + 15, "\x01", 1) == 0,
          "get_xdata parses a quoted IPv6 constant");
    free(data);

    data = get_xdata(MMT_DATA_FLOAT, (int)sizeof(float), flttok, NO);
    CHECK(data != NULL && *(float *)data == 1.5f,
          "get_xdata parses a float constant");
    free(data);

    memset(&str_rec, 0, sizeof str_rec);
    strcpy(str_rec.data, "quoted-name");
    str_rec.len = (uint32_t)strlen(str_rec.data) + 1;
    data = get_xdata(MMT_STRING_DATA_POINTER, (int)sizeof(char *), &str_rec, YES);
    CHECK(data != NULL && *(char **)data != NULL &&
          strcmp(*(char **)data, "quoted-name") == 0,
          "get_xdata stores a private copy of a string-pointer constant");
    if (data != NULL) {
        free(*(char **)data);
        free(data);
    }

    CHECK(get_xdata(MMT_U16_DATA, -1, flttok, NO) == NULL,
          "get_xdata rejects a negative declared size");
}

/* #506: store_tuples() kept the raw char* of a MMT_STRING_DATA_POINTER
 * reference (ftp.packet_request.2). The handler releases that string when
 * the next packet starts, so a later event's comparison and substitution
 * read freed memory (an ASan heap-use-after-free). The rule instance must
 * hold its own copy of the string. */
static void test_reference_string_outlives_packet(void)
{
    static const char req[] = "RETR secret.txt";
    struct { uint32_t len; char data[64]; } same_rec, other_rec;
    rule root, inst, ref_leaf, const_leaf;
    tuple ref;
    void *same, *other;
    char *pkt_str, *out;
    short jump = 0, size = 0;
    long proto, field;
    int ret;

    proto = get_protocol_id_by_name("ftp");
    field = get_attribute_id_by_protocol_id_and_attribute_name((uint32_t)proto, "packet_request");
    pkt_str = malloc(sizeof req);
    if (!(proto > 0 && field > 0) || pkt_str == NULL) {
        printf("FAIL - cannot build the ftp.packet_request reference\n");
        failures++;
        free(pkt_str);
        return;
    }
    memcpy(pkt_str, req, sizeof req);

    memset(&root, 0, sizeof root);
    memset(&inst, 0, sizeof inst);
    memset(&ref, 0, sizeof ref);
    ref.protocol_id = proto;
    ref.field_id = field;
    ref.data_type_id = MMT_STRING_DATA_POINTER;
    ref.data_size = (int)sizeof(char *);
    ref.event_id = 2;
    inst.list_of_tuples = &ref;

    /* event 2's packet: the extractor hands out the heap string */
    fi_ptr_proto = (uint32_t)proto;
    fi_ptr_field = (uint32_t)field;
    fi_ptr_val = pkt_str;
    fi_tvp.tv_sec = 1;
    fi_tvp.tv_usec = 2;
    fi_fake_extract = 1;
    verify_ctx_t sctx = { NULL, &root, NULL, NULL, { 0, 0 }, NO, NO };
    store_tuples(&sctx, SAME, &inst, 2, "test-cause");
    fi_fake_extract = 0;
    fi_ptr_val = NULL;
    CHECK(ref.valid == FOUND && ref.data != NULL,
          "store_tuples stores the referenced pointer string");

    /* the next packet starts: the handler releases the string */
    memset(pkt_str, 'X', sizeof req - 1);
    free(pkt_str);

    memset(&same_rec, 0, sizeof same_rec);
    strcpy(same_rec.data, req);
    same_rec.len = (uint32_t)sizeof req;
    memset(&other_rec, 0, sizeof other_rec);
    strcpy(other_rec.data, "RETR other.txt");
    other_rec.len = (uint32_t)strlen(other_rec.data) + 1;
    same = get_xdata(MMT_STRING_DATA_POINTER, (int)sizeof(char *), &same_rec, YES);
    other = get_xdata(MMT_STRING_DATA_POINTER, (int)sizeof(char *), &other_rec, YES);
    if (same == NULL || other == NULL) {
        printf("FAIL - string-pointer constants for the reference test\n");
        failures++;
    } else {
        verify_ctx_t cctx = { NULL, &root, &ref, NULL, { 0, 0 }, NO, NO };
        memset(&ref_leaf, 0, sizeof ref_leaf);
        memset(&const_leaf, 0, sizeof const_leaf);
        ref_leaf.value = XVAR;
        ref_leaf.t.protocol_id = proto;
        ref_leaf.t.field_id = field;
        ref_leaf.t.data_type_id = MMT_STRING_DATA_POINTER;
        ref_leaf.t.event_id = 2;
        const_leaf.value = XCON;
        const_leaf.t.data_type_id = MMT_STRING_DATA_POINTER;
        const_leaf.t.data_size = (int)sizeof(char *);

        const_leaf.t.data = same;
        ret = get_data_from_pcap(&cctx, COMPARE, NULL, EQ, &ref_leaf, &const_leaf);
        CHECK(ret == VALID,
              "a reference to an earlier packet's pointer string equals its value");
        const_leaf.t.data = other;
        ret = get_data_from_pcap(&cctx, COMPARE, NULL, EQ, &ref_leaf, &const_leaf);
        CHECK(ret == NOT_VALID,
              "a reference to an earlier packet's pointer string differs from another value");
    }

    out = get_value((const ipacket_t *)NULL, "ftp.packet_request.2", &jump, &size, &ref);
    CHECK(out != NULL && strcmp(out, req) == 0,
          "get_value substitutes the stored copy of an earlier packet's pointer string");
    free(out);

    if (same != NULL) { free(*(char **)same); free(same); }
    if (other != NULL) { free(*(char **)other); free(other); }
    free(ref.data);
    free(inst.json_history);
}

static void test_countout_window(void)
{
    rule r;

    memset(&r, 0, sizeof r);
    r.counter = 0;                 /* fresh node — init_time bumps it to 1 */
    r.counter_max = 3;
    r.counter_min = 2;

    /* counter 1: still before the minimum */
    CHECK(check_for_countout(&r, r.counter) == TIMEIN,
          "counter 1 with min=2 is still inside the minimum (TIMEIN)");
    /* counter 2: inside the window */
    CHECK(check_for_countout(&r, r.counter) == NOT_YET,
          "counter 2 at min=2 is inside the window (NOT_YET)");
    /* counter 3: at the max edge, still inside */
    CHECK(check_for_countout(&r, r.counter) == NOT_YET,
          "counter 3 at max=3 stays inside the window (NOT_YET)");
    /* counter 4: past the max */
    CHECK(check_for_countout(&r, r.counter) == COUNTOUT,
          "counter 4 beyond max=3 closes the window (COUNTOUT)");
}

static void test_path_xc_membership(void)
{
    compare_value v1, v2;
    int path[5] = { 3, 17, 42, 8, 90 };
    char needle_last[] = "90";
    char needle_first[] = "3";
    char absent[] = "4";

    memset(&v1, 0, sizeof v1);
    memset(&v2, 0, sizeof v2);
    /* the operand carries the byte size of the int element array —
     * count*sizeof(int) — so XC can scan every element */
    v1.type = MMT_DATA_PATH;
    v1.found = FOUND;
    v1.size = (int)sizeof path;
    v1.data = path;
    v2 = v1;

    v2.data = needle_last;
    CHECK(compare_values(v1, v2, XC) == VALID,
          "path XC finds the needle at the last element");
    v2.data = needle_first;
    CHECK(compare_values(v1, v2, XC) == VALID,
          "path XC finds the needle at element 0");
    v2.data = absent;
    CHECK(compare_values(v1, v2, XC) == NOT_VALID,
          "path XC returns NOT_VALID for an absent needle");
}

/* #548: characterisation of compare_values() before it is split into
 * per-type helpers. Each row pins the verdict for the six relational
 * operators in the order NEQ EQ LT LTE GT GTE ('V' = VALID, '.' =
 * NOT_VALID), quirks included — the rows are the current behaviour, not a
 * specification. */
static compare_value cv(int type, void *data, int size)
{
    compare_value v;
    memset(&v, 0, sizeof v);
    v.type = type;
    v.found = FOUND;
    v.size = size;
    v.data = data;
    return v;
}

static const char *cmp_row(compare_value v1, compare_value v2)
{
    static char row[7];
    static const enum_operation ops[6] = { NEQ, EQ, LT, LTE, GT, GTE };
    int k;
    for (k = 0; k < 6; k++)
        row[k] = compare_values(v1, v2, ops[k]) == VALID ? 'V' : '.';
    row[6] = '\0';
    return row;
}

#define CHECK_ROW(v1, v2, want, msg) do {                              \
    const char *got_ = cmp_row((v1), (v2));                            \
    if (strcmp(got_, (want)) == 0) { printf("ok - %s\n", (msg)); }     \
    else { printf("FAIL - %s (got %s, want %s)\n", (msg), got_, (want)); failures++; } \
} while (0)

static void test_compare_values_integers(void)
{
    uint8_t u8a = 5, u8b = 5;
    uint16_t u16a = 3, u16b = 9;
    uint32_t u32a = 70000, u32b = 7;
    uint64_t u64a = 0x100000000ULL, u64b = 0x100000000ULL;
    char ca = 'a', cb = 'b', chi = (char) 0x80, clo = 0x01;

    /* both operands unsigned of any width: widened to 64 bits */
    CHECK_ROW(cv(MMT_U8_DATA, &u8a, 1), cv(MMT_U32_DATA, &u32b, 4), "V.VV..",
              "u8 5 vs u32 7 compares widened");
    CHECK_ROW(cv(MMT_U32_DATA, &u32a, 4), cv(MMT_U16_DATA, &u16b, 2), "V...VV",
              "u32 70000 vs u16 9 compares widened");
    CHECK_ROW(cv(MMT_U64_DATA, &u64a, 8), cv(MMT_U64_DATA, &u64b, 8), ".V.V.V",
              "u64 equal operands");
    CHECK(compare_values(cv(MMT_U8_DATA, &u8a, 1), cv(MMT_U8_DATA, &u8b, 1), XC) == NOT_VALID,
          "a non-relational operator on unsigned operands is NOT_VALID");
    /* per-type cases: reached when v2 is not one of the four unsigned types */
    CHECK_ROW(cv(MMT_U16_DATA, &u16a, 2), cv(MMT_DATA_LAYERID, &u16b, 2), "V.VV..",
              "u16 3 vs layer id 9 reads both as u16");
    CHECK_ROW(cv(MMT_DATA_LAYERID, &u16b, 2), cv(MMT_DATA_LAYERID, &u16a, 2), "V...VV",
              "layer id 9 vs layer id 3");
    CHECK_ROW(cv(MMT_U32_DATA, &u32b, 4), cv(MMT_DATA_PORT, &u32a, 4), "V.VV..",
              "u32 7 vs a port-typed operand reads both as u32");
    CHECK_ROW(cv(MMT_DATA_POINT, &u64a, 8), cv(MMT_DATA_POINT, &u64b, 8), ".V.V.V",
              "point operands compare as u64");
    CHECK_ROW(cv(MMT_U64_DATA, &u64a, 8), cv(MMT_DATA_POINT, &u64b, 8), ".V.V.V",
              "u64 vs point compares as u64");
    CHECK_ROW(cv(MMT_U8_DATA, &u8a, 1), cv(MMT_DATA_CHAR, &cb, 1), "V.VV..",
              "u8 5 vs char 'b' reads both as u8");
    CHECK_ROW(cv(MMT_DATA_CHAR, &ca, 1), cv(MMT_DATA_CHAR, &cb, 1), "V.VV..",
              "char 'a' vs char 'b'");
    CHECK_ROW(cv(MMT_DATA_CHAR, &chi, 1), cv(MMT_DATA_CHAR, &clo, 1), "V...VV",
              "char 0x80 vs 0x01 compares unsigned");
}

static void test_compare_values_float(void)
{
    float fa = 1.5f, fb = 2.5f, fc = 1.5f;
    CHECK_ROW(cv(MMT_DATA_FLOAT, &fa, 4), cv(MMT_DATA_FLOAT, &fb, 4), "V.VV..",
              "float 1.5 vs 2.5");
    CHECK_ROW(cv(MMT_DATA_FLOAT, &fb, 4), cv(MMT_DATA_FLOAT, &fa, 4), "V...VV",
              "float 2.5 vs 1.5");
    CHECK_ROW(cv(MMT_DATA_FLOAT, &fa, 4), cv(MMT_DATA_FLOAT, &fc, 4), ".V.V.V",
              "float equal operands");
    CHECK(compare_values(cv(MMT_DATA_FLOAT, &fa, 4), cv(MMT_DATA_FLOAT, &fc, 4), XC) == NOT_VALID,
          "float XC is NOT_VALID");
}

static void test_compare_values_time(void)
{
    struct timeval t0 = { 10, 500 }, t_usec = { 10, 900 }, t_sec = { 11, 0 }, t_eq = { 10, 500 };
    mmt_date_t d0, d_eq, d_sec, d_year, d_wday;

    CHECK_ROW(cv(MMT_DATA_TIMEVAL, &t0, sizeof t0), cv(MMT_DATA_TIMEVAL, &t_eq, sizeof t0), ".V.V.V",
              "timeval equal operands");
    CHECK_ROW(cv(MMT_DATA_TIMEVAL, &t0, sizeof t0), cv(MMT_DATA_TIMEVAL, &t_usec, sizeof t0), "V.VV..",
              "timeval earlier by usec");
    CHECK_ROW(cv(MMT_DATA_TIMEVAL, &t_sec, sizeof t0), cv(MMT_DATA_TIMEVAL, &t_usec, sizeof t0), "V...VV",
              "timeval later by sec");

    memset(&d0, 0, sizeof d0);
    d0.sec = 30; d0.min = 20; d0.hour = 10; d0.mday = 5; d0.month = 6; d0.year = 2020; d0.wday = 3;
    d_eq = d0;
    d_sec = d0; d_sec.sec = 31;
    d_year = d0; d_year.year = 2021;
    d_wday = d0; d_wday.wday = 4;
    CHECK_ROW(cv(MMT_DATA_DATE, &d0, sizeof d0), cv(MMT_DATA_DATE, &d_eq, sizeof d0), ".V.V.V",
              "date equal operands");
    CHECK_ROW(cv(MMT_DATA_DATE, &d0, sizeof d0), cv(MMT_DATA_DATE, &d_sec, sizeof d0), "V.VV..",
              "date earlier by one second");
    CHECK_ROW(cv(MMT_DATA_DATE, &d_sec, sizeof d0), cv(MMT_DATA_DATE, &d0, sizeof d0), "V...VV",
              "date later by one second");
    /* quirk: the GT/GTE year test is `<`, so an earlier year is both
     * lower and greater, and a later year is neither */
    CHECK_ROW(cv(MMT_DATA_DATE, &d0, sizeof d0), cv(MMT_DATA_DATE, &d_year, sizeof d0), "V.VVVV",
              "date earlier by a year (GT/GTE year quirk)");
    CHECK_ROW(cv(MMT_DATA_DATE, &d_year, sizeof d0), cv(MMT_DATA_DATE, &d0, sizeof d0), "V.....",
              "date later by a year (GT/GTE year quirk)");
    CHECK_ROW(cv(MMT_DATA_DATE, &d0, sizeof d0), cv(MMT_DATA_DATE, &d_wday, sizeof d0), "V.....",
              "date differing only in week day is unordered");
}

static void test_compare_values_bytes(void)
{
    char abc[] = "abc", abd[] = "abd", abc2[] = "abc", ab[] = "ab", bc[] = "bc";
    unsigned char bin1[4] = { 1, 2, 3, 4 }, bin2[4] = { 1, 2, 3, 4 };

    CHECK_ROW(cv(MMT_STRING_DATA, abc, 3), cv(MMT_STRING_DATA, abd, 3), "V.VV..",
              "string 'abc' vs 'abd' byte order");
    CHECK_ROW(cv(MMT_STRING_DATA, abd, 3), cv(MMT_STRING_DATA, abc, 3), "V...VV",
              "string 'abd' vs 'abc' byte order");
    CHECK_ROW(cv(MMT_STRING_DATA, abc, 3), cv(MMT_STRING_DATA, abc2, 3), ".V.V.V",
              "string equal operands");
    /* different sizes: EQ/NEQ decide on the size, the others compare the
     * common prefix */
    CHECK_ROW(cv(MMT_STRING_DATA, ab, 2), cv(MMT_STRING_DATA, abc, 3), "V..V.V",
              "string 'ab' vs 'abc' (size mismatch)");
    CHECK_ROW(cv(MMT_STRING_DATA, ab, 0), cv(MMT_STRING_DATA, abc, 0), "......",
              "zero-size strings never compare");
    CHECK(compare_values(cv(MMT_STRING_DATA, abc, 3), cv(MMT_STRING_DATA, bc, 2), XC) == VALID,
          "string XC finds the substring");
    CHECK(compare_values(cv(MMT_STRING_DATA, abc, 3), cv(MMT_STRING_DATA, abd, 3), XCE) == NOT_VALID,
          "string XCE without the substring is NOT_VALID");
    CHECK(compare_values(cv(MMT_STRING_DATA, bc, 2), cv(MMT_STRING_DATA, abc, 3), XD) == VALID,
          "string XD finds the first operand inside the second");
    CHECK(compare_values(cv(MMT_STRING_DATA, abd, 3), cv(MMT_STRING_DATA, abc, 3), XDE) == NOT_VALID,
          "string XDE without the substring is NOT_VALID");
    CHECK(compare_values(cv(MMT_STRING_DATA, abc, 3), cv(MMT_STRING_DATA, abc2, 3), XE) == VALID,
          "string XE on identical strings");
    CHECK(compare_values(cv(MMT_STRING_DATA, abc, 3), cv(MMT_STRING_DATA, abd, 3), XE) == NOT_VALID,
          "string XE on different strings");
    CHECK(compare_values(cv(MMT_STRING_DATA, abc, 3), cv(MMT_STRING_DATA, abd, 3), XIN) == NOT_VALID,
          "string XIN against a non-table operand is NOT_VALID");
    CHECK_ROW(cv(MMT_BINARY_DATA, bin1, 4), cv(MMT_BINARY_DATA, bin2, 4), ".V.V.V",
              "binary equal operands compare byte-wise");
    CHECK_ROW(cv(MMT_DATA_IP_ADDR, bin1, 4), cv(MMT_DATA_IP_ADDR, abc, 3), "V.VV..",
              "IPv4 operands of different sizes");
}

static void test_compare_values_unordered_types(void)
{
    int path[2] = { 7, 9 };
    char needle[] = "9";
    char *s1 = (char *) "beta", *s2 = (char *) "alpha", *snull = NULL;
    uint32_t port = 80;

    CHECK(compare_values(cv(MMT_DATA_PATH, path, (int) sizeof path), cv(MMT_DATA_PATH, needle, 2), EQ) == NOT_VALID,
          "path EQ is NOT_VALID");
    CHECK(compare_values(cv(MMT_DATA_PATH, path, 0), cv(MMT_DATA_PATH, needle, 2), XC) == NOT_VALID,
          "path XC on an empty path is NOT_VALID");
    CHECK(compare_values(cv(MMT_DATA_PATH, path, (int) sizeof path), cv(MMT_DATA_PATH, needle, 2), XCE) == VALID,
          "path XCE finds the needle");
    CHECK_ROW(cv(MMT_STRING_DATA_POINTER, &s1, sizeof s1), cv(MMT_STRING_DATA_POINTER, &s2, sizeof s2), "V...VV",
              "string-pointer contents order");
    CHECK(compare_values(cv(MMT_STRING_DATA_POINTER, &s2, sizeof s2), cv(MMT_STRING_DATA_POINTER, &s1, sizeof s1), XE) == NOT_VALID,
          "string-pointer XE on different contents");
    CHECK(compare_values(cv(MMT_STRING_DATA_POINTER, &s1, sizeof s1), cv(MMT_STRING_DATA_POINTER, &s1, sizeof s1), XDE) == VALID,
          "string-pointer XDE on identical contents");
    CHECK(compare_values(cv(MMT_STRING_DATA_POINTER, &s1, sizeof s1), cv(MMT_STRING_DATA_POINTER, &snull, sizeof s1), NEQ) == NOT_VALID,
          "string-pointer with a NULL operand is NOT_VALID");
    CHECK(compare_values(cv(MMT_STRING_DATA_POINTER, &s1, sizeof s1), cv(MMT_STRING_DATA_POINTER, &s1, sizeof s1), XIN) == NOT_VALID,
          "string-pointer XIN is NOT_VALID");
    CHECK_ROW(cv(MMT_DATA_PORT, &port, 4), cv(MMT_DATA_PORT, &port, 4), "......",
              "port operands have no comparison");
    CHECK_ROW(cv(MMT_DATA_TIMEARG, &port, 4), cv(MMT_DATA_TIMEARG, &port, 4), "......",
              "time-argument operands have no comparison");
}

int main(void)
{
    test_compute_zero_divisor();
    test_header_line_clamped();

    test_string_long_bounded();
    test_data_path_bounded();
    test_json_escape_bounded();
    test_get_value_header_line_length();
    test_store_history_alloc_failure();
    test_store_history_escapes_strings();
    test_contains_unterminated_operands();
    test_generate_command_bounded();
    test_compare_in_table_bounded();
    test_tokenize_and_summary_bounded();

    /* #326: fill-in/prune branches */
    test_get_my_data_filled_branches();
    test_string_pointer_compare();
    test_xin_fixed_width_membership();
    test_compute_float();
    test_get_xdata_filled_branches();
    test_reference_string_outlives_packet();
    test_countout_window();
    test_path_xc_membership();

    /* #548: compare_values() characterisation before its split */
    test_compare_values_integers();
    test_compare_values_float();
    test_compare_values_time();
    test_compare_values_bytes();
    test_compare_values_unordered_types();

    if (failures) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    return 0;
}

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
#include <sys/time.h>

#include "mmt_core.h"

/* Internal rule/tuple layouts — not installed headers, but including them keeps
 * this test in lock-step with src/mmt_security/tips.c (same way compare_value
 * is mirrored below for the #137 checks). */
#include "struct_defs.h"

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
 * Issue #209 — second tips.c overflow family
 * (F-BUG-091, F-BUG-092, F-BUG-093, F-BUG-095, F-BUG-096, F-BUG-102, F-BUG-103)
 *
 * Entry points are exported by libmmt_security (non-static in tips.c) and are
 * driven directly here. For the allocation-failure and command-buffer checks
 * this binary interposes the libc-level symbols the engine bottoms out at —
 * xmalloc/xcalloc/xfree are tips.c-internal helpers that the -flto shared
 * build binds invisibly, but their malloc/calloc/realloc/free (and fopen via
 * open_file) stay PLT-preemptible, so these definitions win process-wide:
 *   malloc/calloc/realloc/free — fault injection + live-allocation tracking
 *   fopen                    — returns tmpfile() while armed (no /opt/mmt needed)
 *   get_attribute_extracted_data — returns fabricated META_UTIME / header line
 * ====================================================================== */

extern char *get_value(const ipacket_t *pkt, char *input, short *jump, short *size, tuple *list_of_tuples);
extern char *convert_string_to_json_compatible(char *p, int size);
extern char *tokenize(char *temp, char **ltoken2, char **ltoken3, short *ref);
extern char *generate_command(const ipacket_t *pkt, rule *r, char *input);
extern void store_history(const ipacket_t *pkt, short context, rule *curr_root, rule *curr_rule, char *cause, short event_id);
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
 * tips.c's intra-TU helper calls (xmalloc -> malloc etc.) are bound
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
    store_history((const ipacket_t *)NULL, SAME, &root, &curr, "test-cause", 3);
    CHECK(fi_alloc_seen >= 3, "fault injection reached the failing allocation");
    CHECK(!fi_double_free,
          "allocation-failure path frees each JSON buffer exactly once");
    CHECK(fi_live_n == 0,
          "allocation-failure path reaches one cleanup exit (nothing leaked)");

    /* sunny path: substitution path runs end-to-end under ASan */
    fi_reset();
    store_history((const ipacket_t *)NULL, SAME, &root, &curr, "test-cause", 3);
    CHECK(curr.json_history != NULL && strstr(curr.json_history, "timestamp") != NULL,
          "store_history records the substituted attribute");
    CHECK(!fi_double_free, "sunny path frees each JSON buffer exactly once");
    fi_fake_extract = 0;
    fi_tracking = 0;
    free(curr.json_history);
}

/* F-BUG-102: generate_command sized its buffer from the parameter names while
 * substitutions append escaped values; with 40 header-line substitutions the
 * old fixed buffer overflows. Malformed input must return NULL without
 * leaking the command buffer. */
static void test_generate_command_bounded(void)
{
    rule r;
    tuple t;
    mmt_header_line_t hl;
    char line[100];
    char input[1024];
    char *cmd;
    long proto, field;
    size_t pos;
    int i;

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
}

/* compare_in_table (reached via comp2 when a rule uses XIN on a
 * MMT_BINARY_VAR_DATA operand) used the byte offset i as the element index —
 * reading up to 8x past the operand buffer for u64 and never comparing
 * odd-indexed elements. Elements must be scanned by element number, and only
 * complete elements inside v2.size. */
extern int comp2(compare_value v1, compare_value v2, short ope);

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

    CHECK(comp2(v1, v2, XIN) == VALID,
          "XIN u64 finds the value at element index 1 (was skipped by the byte-offset index)");
    v1.data = &absent;
    CHECK(comp2(v1, v2, XIN) == NOT_VALID,
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
    CHECK(comp2(v1, v2, XIN) == VALID,
          "XIN u16 finds the value at element index 1 (was skipped by the byte-offset index)");
    needle16 = 0xDEAD;
    CHECK(comp2(v1, v2, XIN) == NOT_VALID,
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

int main(void)
{
    test_compute_zero_divisor();
    test_header_line_clamped();

    test_string_long_bounded();
    test_data_path_bounded();
    test_json_escape_bounded();
    test_get_value_header_line_length();
    test_store_history_alloc_failure();
    test_generate_command_bounded();
    test_compare_in_table_bounded();
    test_tokenize_and_summary_bounded();

    if (failures) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    return 0;
}

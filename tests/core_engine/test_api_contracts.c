/*
 * test_api_contracts.c — compiled public-API contract tests (issue #525,
 * F-TEST-011).
 *
 * Exactly one table entry (api_contract.h) per MMTAPI function declared in
 * the public headers under src/mmt_core/public_include, grouped by header
 * in declaration order.
 * Every entry runs a behaviour assertion; every CONTRACT entry also runs an
 * error-path assertion that feeds the function a real invalid input and
 * checks its failure result. NO_ERROR_PATH entries carry the reason the
 * function has none, and are ratcheted by api-contract-waivers.txt.
 *
 *   test_api_contracts          run every entry; exit 1 on any failure
 *   test_api_contracts --list   print "<CONTRACT|NO_ERROR_PATH> <name>"
 *
 * Linked from the library objects tests/core_engine/run_tests.sh already
 * compiles (no --wrap allocator hooks), plus mmt_attr_sprintf_compat.c.
 * Runs from a scratch directory: load_plugins() then finds no ./plugins.
 *
 * Fixture: one link-layer stack (AC_STACK_ID) whose classifier yields the
 * session-bearing protocol A, so every fixture packet has the path
 * meta.ac_proto_a (indexes 0 and 1) and one session keyed on its first four
 * bytes. Protocol C is registered but never on a packet path: the
 * registration contracts mutate it. Accessors of session and attribute
 * records are checked against fabricated records with a distinct value in
 * every field.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "mmt_core.h"
#include "proto_meta.h"
#include "data_defs.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "mmt_utils.h"
#include "packet_processing.h" /* private: handler/session/attribute layouts */
#include "hash_utils.h"        /* private: session store of the sessionizer */
#include "cfg_defaults.h"      /* private: CFG_CLASSIFICATION_THRESHOLD */

#include "api_contract.h"

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
/* sanitizer allocator interface (sanitizer/allocator_interface.h is not
 * installed everywhere the runtime is) */
size_t __sanitizer_get_current_allocated_bytes(void);
#else
#include <malloc.h>
#endif

#define AC_ALLOW_DEPRECATED_BEGIN \
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#define AC_ALLOW_DEPRECATED_END _Pragma("GCC diagnostic pop")

/* ------------------------------------------------------------------------ */
/* assertion bookkeeping                                                     */

static int g_checks;
static int g_failures;
#define CHECK(cond, msg) do { g_checks++; if (!(cond)) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); \
        g_failures++; } } while (0)

/* ------------------------------------------------------------------------ */
/* fixture identifiers                                                       */

#define AC_STACK_ID       97
#define AC_STACK_AUX      95   /* registered/unregistered by the stack contracts */
#define AC_PROTO_A        613  /* session-bearing, on every fixture packet path */
#define AC_PROTO_C        620  /* registered, never on a path: registration target */
#define AC_FREE_ID        700  /* never taken */
#define AC_UNREG_ID       999  /* valid id, never registered */
#define AC_HANDLER_ID     1    /* fixture packet handler id */
#define AC_PKT_LEN        64
#define AC_KEY            0x11223344u
#define AC_SEC            1000
#define AC_USEC           250
#define AC_DIR_REPLY      0xD1 /* byte 4 of a packet travelling against the setup direction */

#define AC_ATTR_U32       1    /* U32 at offset 0: the session key */
#define AC_ATTR_U16       2    /* U16 at offset 6 */
#define AC_ATTR_EVENT     3    /* event-scoped U32 */
#define AC_ATTR_NONE      0x7fff

/* ------------------------------------------------------------------------ */
/* heap accounting (mmt_free / arena release assertions)                     */

static size_t heap_in_use(void) {
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
    return __sanitizer_get_current_allocated_bytes();
#else
    struct mallinfo2 mi = mallinfo2();
    return mi.uordblks + mi.hblkhd;
#endif
}

/* ------------------------------------------------------------------------ */
/* stdout capture (functions that print through mmt_stream_printf(stdout))   */

typedef struct { FILE *tmp; int saved; } capture_t;

static int capture_begin(capture_t *c) {
    fflush(stdout);
    c->tmp = tmpfile();
    c->saved = dup(STDOUT_FILENO);
    if (c->tmp == NULL || c->saved < 0) return 0;
    return dup2(fileno(c->tmp), STDOUT_FILENO) >= 0;
}

static size_t capture_end(capture_t *c, char *buf, size_t cap) {
    size_t n = 0;
    fflush(stdout);
    if (c->saved >= 0) { dup2(c->saved, STDOUT_FILENO); close(c->saved); }
    if (c->tmp != NULL) {
        rewind(c->tmp);
        n = fread(buf, 1, cap - 1, c->tmp);
        fclose(c->tmp);
    }
    buf[n] = '\0';
    return n;
}

/* ------------------------------------------------------------------------ */
/* engine fixture                                                            */

static int g_init_result;
static mmt_handler_t *g_h;   /* processes the fixture packets */
static mmt_handler_t *g_cfg; /* configuration target, never sees a packet */
static protocol_t *g_pa;
static protocol_t *g_pc;
static void (*g_probe)(const ipacket_t *);
static int g_probe_ran;

static void *ac_sessionize(void *protocol_context, ipacket_t *ipacket,
                           unsigned previous_index, int *is_new) {
    (void) previous_index;
    uint32_t k;
    memcpy(&k, ipacket->data, sizeof(k));
    /* Packet direction, as the IP sessionizer sets it (proto_ip.c): byte 4
     * equal to AC_DIR_REPLY marks a reply; every other packet travels in the
     * session's setup direction. */
    const unsigned dir = ipacket->data[4] == AC_DIR_REPLY;
    mmt_session_t *s = (mmt_session_t *)
            get_session_from_protocol_context_by_session_key(protocol_context, &k);
    if (s != NULL) { *is_new = 0; s->last_packet_direction = dir; return s; }
    s = (mmt_session_t *) mmt_malloc(sizeof(*s) + sizeof(uint32_t));
    *is_new = 1;
    if (s == NULL) return NULL;
    memset(s, 0, sizeof(*s));
    s->setup_packet_direction = dir;
    s->last_packet_direction = dir;
    s->session_key = (void *) (s + 1);
    *(uint32_t *) s->session_key = k;
    if (insert_session_into_protocol_context(protocol_context, s->session_key, s) == 0) {
        mmt_free(s);
        return NULL;
    }
    return s;
}

static int ac_session_ctx_cleanup(void *protocol_context, mmt_session_t *session, void *args) {
    (void) args;
    delete_session_from_protocol_context(protocol_context, session->session_key);
    mmt_free(session->children_stats);
    mmt_free(session);
    return 1;
}

static bool ac_key_comp(void *a, void *b) { return *(uint32_t *) a < *(uint32_t *) b; }
static uint64_t ac_key_hash(void *k) { return (uint64_t) *(uint32_t *) k; }

static classified_proto_t ac_stack_classify(ipacket_t *ipacket) {
    classified_proto_t r;
    (void) ipacket;
    r.offset = 0;
    r.proto_id = AC_PROTO_A;
    r.status = Classified;
    return r;
}

static int fixture_packet_handler(const ipacket_t *ipacket, void *args) {
    (void) args;
    if (g_probe != NULL) {
        g_probe(ipacket);
        g_probe_ran++;
    }
    return 0;
}

static int send_packet_dir(mmt_handler_t *h, uint32_t key, long sec, long usec, int reply) {
    u_char buf[AC_PKT_LEN];
    pkthdr_t hdr;
    for (size_t i = 0; i < sizeof(buf); i++) buf[i] = (u_char) i;
    memcpy(buf, &key, sizeof(key));
    if (reply) buf[4] = AC_DIR_REPLY;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = sec;
    hdr.ts.tv_usec = usec;
    hdr.caplen = hdr.len = (unsigned) sizeof(buf);
    return packet_process(h, &hdr, buf);
}

static int send_packet(mmt_handler_t *h, uint32_t key, long sec, long usec) {
    return send_packet_dir(h, key, sec, usec, 0);
}

/* Runs probe inside the fixture handler's packet callback, where the
 * ipacket (path meta.ac_proto_a, session AC_KEY) is live. */
static int run_probe(void (*probe)(const ipacket_t *)) {
    g_probe = probe;
    g_probe_ran = 0;
    int ok = send_packet(g_h, AC_KEY, AC_SEC, AC_USEC);
    g_probe = NULL;
    return ok == 1 && g_probe_ran == 1;
}

static mmt_handler_t *new_handler(void) {
    char errbuf[256];
    return mmt_init_handler(AC_STACK_ID, 0, errbuf);
}

static int add_attribute(protocol_t *p, uint32_t id, const char *alias, int type,
                         int len, int pos, int scope, generic_attribute_extraction_function fn) {
    attribute_metadata_t meta;
    memset(&meta, 0, sizeof(meta));
    meta.id = id;
    strncpy(meta.alias, alias, Max_Alias_Len);
    meta.data_type = type;
    meta.data_len = len;
    meta.position_in_packet = pos;
    meta.scope = scope;
    meta.extraction_function = fn;
    return register_attribute_with_protocol(p, &meta);
}

static int fixture_setup(void) {
    g_init_result = init_extraction();
    if (!g_init_result) return 0;
    if (!register_protocol_stack(AC_STACK_ID, (char *) "ac_stack", ac_stack_classify)) return 0;

    g_pa = init_protocol_struct_for_registration(AC_PROTO_A, "ac_proto_a");
    if (g_pa == NULL) return 0;
    register_sessionizer_function(g_pa, ac_sessionize, ac_session_ctx_cleanup, ac_key_comp);
    register_session_hash_function(g_pa, ac_key_hash);
    if (!add_attribute(g_pa, AC_ATTR_U32, "ac_u32", MMT_U32_DATA, 4, 0, SCOPE_PACKET,
                       general_int_extraction)) return 0;
    if (!add_attribute(g_pa, AC_ATTR_U16, "ac_u16", MMT_U16_DATA, 2, 6, SCOPE_PACKET,
                       general_short_extraction)) return 0;
    if (!add_attribute(g_pa, AC_ATTR_EVENT, "ac_event", MMT_U32_DATA, 4, POSITION_NOT_KNOWN,
                       SCOPE_EVENT, silent_extraction)) return 0;
    if (register_protocol(g_pa, AC_PROTO_A) != PROTO_REGISTERED) return 0;

    g_pc = init_protocol_struct_for_registration(AC_PROTO_C, "ac_proto_c");
    if (g_pc == NULL || register_protocol(g_pc, AC_PROTO_C) != PROTO_REGISTERED) return 0;

    g_h = new_handler();
    g_cfg = new_handler();
    if (g_h == NULL || g_cfg == NULL) return 0;
    if (!register_extraction_attribute(g_h, PROTO_META, META_P_LEN)) return 0;
    if (!register_extraction_attribute(g_h, AC_PROTO_A, AC_ATTR_U32)) return 0;
    if (!register_packet_handler(g_h, AC_HANDLER_ID, fixture_packet_handler, NULL)) return 0;
    /* first packet: creates the AC_KEY session */
    return send_packet(g_h, AC_KEY, AC_SEC, AC_USEC) == 1;
}

/* ------------------------------------------------------------------------ */
/* fabricated records                                                        */

typedef struct {
    ipacket_internal_t ip;
    pkthdr_t hdr;
    u_char buf[AC_PKT_LEN];
} fake_packet_t;

/* A packet with n layers ids[]/offsets[], no session and no handler;
 * buf[i] == i. */
static ipacket_t *fake_packet(fake_packet_t *f, unsigned n, const uint32_t *ids,
                              const int *offsets) {
    memset(f, 0, sizeof(*f));
    f->ip.proto_hierarchy = &f->ip.internal_proto_hierarchy;
    f->ip.proto_headers_offset = &f->ip.internal_proto_headers_offset;
    f->ip.proto_classif_status = &f->ip.internal_proto_classif_status;
    f->ip.proto_hierarchy->len = (int) n;
    f->ip.proto_headers_offset->len = (int) n;
    f->ip.proto_classif_status->len = (int) n;
    for (unsigned i = 0; i < n; i++) {
        f->ip.proto_hierarchy->proto_path[i] = (int) ids[i];
        f->ip.proto_headers_offset->proto_path[i] = offsets[i];
    }
    for (size_t i = 0; i < sizeof(f->buf); i++) f->buf[i] = (u_char) i;
    f->hdr.caplen = f->hdr.len = (unsigned) sizeof(f->buf);
    f->hdr.ts.tv_sec = AC_SEC;
    f->ip.p_hdr = &f->hdr;
    f->ip.data = f->ip.original_data = f->buf;
    return &f->ip.pub;
}

static const uint32_t k_path_ma[] = { PROTO_META, AC_PROTO_A };
static const int k_off_ma[] = { 0, 10 };

static mmt_session_t g_fs;
static mmt_session_children_stats_t g_fcs;

/* A tunnel-parent session record: every counter distinct, every subsession
 * counter non-zero and distinct, setup direction 1 (uplink = slot 1). */
static mmt_session_t *fake_session(void) {
    uint64_t v = 0;
    memset(&g_fs, 0, sizeof(g_fs));
    memset(&g_fcs, 0, sizeof(g_fcs));
#define AC_FILL(f) do { v += 1000; g_fs.f = v; g_fcs.sub_##f = v / 1000; } while (0)
#define AC_FILL2(f) do { AC_FILL(f[0]); AC_FILL(f[1]); } while (0)
    AC_FILL(packet_count);
    AC_FILL(packet_cap_count);
    AC_FILL(data_cap_volume);
    AC_FILL(data_volume);
    AC_FILL(data_packet_count);
    AC_FILL(data_byte_volume);
    AC_FILL2(packet_count_direction);
    AC_FILL2(data_volume_direction);
    AC_FILL2(packet_cap_count_direction);
    AC_FILL2(data_cap_volume_direction);
    AC_FILL2(data_packet_count_direction);
    AC_FILL2(data_byte_volume_direction);
#undef AC_FILL
#undef AC_FILL2
    g_fs.children_stats = &g_fcs;
    g_fs.setup_packet_direction = 1;
    g_fs.last_packet_direction = 1;
    g_fs.session_id = 77;
    g_fs.session_protocol_index = 3;
    g_fs.s_init_time.tv_sec = 11; g_fs.s_init_time.tv_usec = 12;
    g_fs.s_last_activity_time.tv_sec = 21; g_fs.s_last_activity_time.tv_usec = 22;
    g_fs.s_last_data_packet_time[0].tv_sec = 31; g_fs.s_last_data_packet_time[0].tv_usec = 32;
    g_fs.s_last_data_packet_time[1].tv_sec = 41; g_fs.s_last_data_packet_time[1].tv_usec = 42;
    g_fs.rtt.tv_sec = 51; g_fs.rtt.tv_usec = 52;
    g_fs.content_info.content_class = 61;
    g_fs.content_info.content_type = 62;
    g_fs.content_flags = 63;
    g_fs.tcp_retransmissions = 64;
    g_fs.tcp_outoforders = 65;
    g_fs.proto_path.len = 2;
    g_fs.proto_path.proto_path[0] = PROTO_META;
    g_fs.proto_path.proto_path[1] = AC_PROTO_A;
    g_fcs.proto_path_direction[0].len = 1;
    g_fcs.proto_path_direction[1].len = 2;
    return &g_fs;
}

static int same_tv(struct timeval a, long sec, long usec) {
    return a.tv_sec == sec && a.tv_usec == usec;
}

/* An attribute record with a distinct value in every public field. */
static attribute_internal_t g_fa;
static uint32_t g_fa_value;
static attribute_t *fake_attribute(int data_type) {
    memset(&g_fa, 0, sizeof(g_fa));
    g_fa_value = 42;
    g_fa.protocol_index = 5;
    g_fa.status = ATTRIBUTE_SET;
    g_fa.data_type = data_type;
    g_fa.data_len = 4;
    g_fa.position_in_packet = 9;
    g_fa.scope = SCOPE_PACKET;
    g_fa.proto_id = PROTO_META;
    g_fa.field_id = META_P_LEN;
    g_fa.data = &g_fa_value;
    return (attribute_t *) &g_fa;
}

/* ------------------------------------------------------------------------ */
/* shared callbacks                                                          */

static int g_count_calls;
static void *g_count_args;
static int count_handler(const ipacket_t *ipacket, void *args) {
    (void) ipacket;
    g_count_calls++;
    g_count_args = args;
    return 0;
}

static mmt_session_t *g_captured[8];
static int g_captured_n;
static int capture_handler(const ipacket_t *ipacket, void *args) {
    (void) args;
    if (g_captured_n < 8) g_captured[g_captured_n++] = ipacket->session;
    return 0;
}

static int g_attr_calls;
static uint32_t g_attr_value;
static const void *g_attr_data;
static void *g_attr_user;
static void attr_cb(const ipacket_t *ipacket, attribute_t *attribute, void *user) {
    (void) ipacket;
    g_attr_calls++;
    g_attr_data = attribute->data;
    g_attr_user = user;
    if (attribute->data != NULL) memcpy(&g_attr_value, attribute->data, sizeof(g_attr_value));
}
static void attr_cb_other(const ipacket_t *ipacket, attribute_t *attribute, void *user) {
    (void) ipacket; (void) attribute; (void) user;
}

static int g_evasion_calls;
static unsigned g_evasion_id;
static void *g_evasion_data;
static void *g_evasion_args;
static void evasion_cb(const ipacket_t *ipacket, mmt_proto_id_t proto_id, mmt_proto_index_t index,
                       unsigned evasion_id, void *data, void *args) {
    (void) ipacket; (void) proto_id; (void) index;
    g_evasion_calls++;
    g_evasion_id = evasion_id;
    g_evasion_data = data;
    g_evasion_args = args;
}

static int g_expiry_calls;
static uint64_t g_expiry_id;
static void expiry_cb(const mmt_session_t *expired, void *args) {
    (void) args;
    g_expiry_calls++;
    g_expiry_id = expired->session_id;
}

static int g_timer_calls;
static const mmt_session_t *g_timer_last;
static void *g_timer_args;
static void timer_cb(const mmt_session_t *session, void *args) {
    g_timer_calls++;
    g_timer_last = session;
    g_timer_args = args;
}

static int g_release_calls;
static void release_cb(void *value) {
    g_release_calls++;
    mmt_free(value);
}

/* distinct classification/analysis callbacks: their addresses identify the
 * chain nodes the registration contracts look for */
static int g_cb_hits[8];
static int cls1(ipacket_t *p, unsigned i) { (void) p; (void) i; g_cb_hits[1]++; return 0; }
static int cls2(ipacket_t *p, unsigned i) { (void) p; (void) i; g_cb_hits[2]++; return 0; }
static int cls3(ipacket_t *p, unsigned i) { (void) p; (void) i; g_cb_hits[3]++; return 0; }
static int cls4(ipacket_t *p, unsigned i) { (void) p; (void) i; g_cb_hits[4]++; return 0; }
static int cls5(ipacket_t *p, unsigned i) { (void) p; (void) i; g_cb_hits[5]++; return 0; }
static int cls6(ipacket_t *p, unsigned i) { (void) p; (void) i; g_cb_hits[6]++; return 0; }
static int cls7(ipacket_t *p, unsigned i) { (void) p; (void) i; g_cb_hits[7]++; return 0; }

static mmt_classify_proto_t *classify_node(protocol_t *p, generic_classification_function fn) {
    for (mmt_classify_proto_t *n = p->classify_next.classify_protos; n != NULL; n = n->next)
        if (n->classify_me == fn) return n;
    return NULL;
}
static mmt_analyse_me_t *analyse_node(protocol_t *p, generic_session_data_analysis_function fn) {
    for (mmt_analyse_me_t *n = p->data_analyser.analyse; n != NULL; n = n->next)
        if (n->analyse_me == fn) return n;
    return NULL;
}

/* ======================================================================== */
/*                               data_defs.h                                */
/* ======================================================================== */

static void b_get_protocol_name_by_id(void) {
    const char *n = get_protocol_name_by_id(PROTO_META);
    CHECK(n != NULL && strcmp(n, "meta") == 0, "PROTO_META is named meta");
    n = get_protocol_name_by_id(AC_PROTO_A);
    CHECK(n != NULL && strcmp(n, "ac_proto_a") == 0, "a registered protocol reports its name");
}
static void e_get_protocol_name_by_id(void) {
    CHECK(get_protocol_name_by_id(AC_UNREG_ID) == NULL, "unregistered id has no name");
    CHECK(get_protocol_name_by_id(PROTO_MAX_IDENTIFIER) == NULL, "out-of-range id has no name");
}

static void b_get_attribute_name_by_protocol_and_attribute_ids(void) {
    const char *n = get_attribute_name_by_protocol_and_attribute_ids(PROTO_META, META_P_LEN);
    CHECK(n != NULL && strcmp(n, "packet_len") == 0, "meta.packet_len name");
}
static void e_get_attribute_name_by_protocol_and_attribute_ids(void) {
    CHECK(get_attribute_name_by_protocol_and_attribute_ids(AC_UNREG_ID, 1) == NULL,
          "unregistered protocol -> NULL");
    CHECK(get_attribute_name_by_protocol_and_attribute_ids(PROTO_META, AC_ATTR_NONE) == NULL,
          "unknown attribute -> NULL");
}

static void b_get_packet_offset_at_index(void) {
    static const uint32_t ids[] = { PROTO_META, AC_PROTO_A, AC_PROTO_C };
    static const int offs[] = { 0, 14, 20 };
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 3, ids, offs);
    CHECK(get_packet_offset_at_index(p, 2) == 34, "offset of layer 2 is the prefix sum 0+14+20");
    CHECK(get_packet_offset_at_index(p, 1) == 14, "offset of layer 1");
}
static void e_get_packet_offset_at_index(void) {
    static const uint32_t ids[] = { PROTO_META, AC_PROTO_A, AC_PROTO_C };
    static const int offs[] = { 0, 14, 20 };
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 3, ids, offs);
    CHECK(get_packet_offset_at_index(p, PROTO_PATH_SIZE + 5) == 34,
          "an index past PROTO_PATH_SIZE is clamped to the last slot");
}

static void b_invalidate_packet_offset_cache(void) {
    static const uint32_t ids[] = { PROTO_META, AC_PROTO_A, AC_PROTO_C };
    static const int offs[] = { 0, 14, 20 };
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 3, ids, offs);
    CHECK(get_packet_offset_at_index(p, 2) == 34, "offset cached as 0+14+20");
    p->proto_headers_offset->proto_path[2] = 26; /* a plugin's in-place write */
    invalidate_packet_offset_cache(p);
    CHECK(get_packet_offset_at_index(p, 2) == 40, "dropped cache rebuilt: 0+14+26");
    invalidate_packet_offset_cache(NULL); /* NULL is accepted and ignored */
}

static void b_get_protocol_id_at_index(void) {
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(get_protocol_id_at_index(p, 1) == AC_PROTO_A, "id at index 1");
    CHECK(get_protocol_id_at_index(p, 0) == PROTO_META, "id at index 0");
}
static void e_get_protocol_id_at_index(void) {
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(get_protocol_id_at_index(p, 2) == (uint32_t) -1, "index past the path -> -1");
    CHECK(get_protocol_id_at_index(p, PROTO_PATH_SIZE) == (uint32_t) -1, "index past PROTO_PATH_SIZE -> -1");
    /* Issue #546: the named sentinel is the value -1 used to produce. */
    CHECK(get_protocol_id_at_index(p, 2) == MMT_NO_PROTO_ID && MMT_NO_PROTO_ID == (uint32_t) -1,
          "index past the path -> MMT_NO_PROTO_ID");
}

static void b_get_protocol_index_by_id(void) {
    static const uint32_t ids[] = { PROTO_META, AC_PROTO_A, AC_PROTO_A };
    static const int offs[] = { 0, 0, 0 };
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 3, ids, offs);
    CHECK(get_protocol_index_by_id(p, AC_PROTO_A) == 2, "last occurrence of the id");
    CHECK(get_protocol_index_by_id(p, PROTO_META) == 0, "index of meta");
}
static void e_get_protocol_index_by_id(void) {
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(get_protocol_index_by_id(p, AC_PROTO_C) == (unsigned) -1, "absent id -> -1");
    CHECK(get_protocol_index_by_id(p, AC_PROTO_C) == MMT_NO_PROTO_INDEX && MMT_NO_PROTO_INDEX == (unsigned) -1,
          "absent id -> MMT_NO_PROTO_INDEX (#546)");
    int as_int = (int) get_protocol_index_by_id(p, AC_PROTO_C);
    CHECK(as_int == -1, "callers storing the index in an int still see -1");
}

static void b_get_protocol_index_by_name(void) {
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(get_protocol_index_by_name(p, "ac_proto_a") == 1, "index by name");
    CHECK(get_protocol_index_by_name(p, "META") == 0, "name lookup is case-insensitive");
}
static void e_get_protocol_index_by_name(void) {
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(get_protocol_index_by_name(p, "no_such_proto") == (unsigned) -1, "unknown name -> -1");
    CHECK(get_protocol_index_by_name(p, "ac_proto_c") == (unsigned) -1, "registered but absent -> -1");
    CHECK(get_protocol_index_by_name(p, "no_such_proto") == MMT_NO_PROTO_INDEX,
          "unknown name -> MMT_NO_PROTO_INDEX (#546)");
}

static void b_get_session_id_from_packet(void) {
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    p->session = fake_session();
    CHECK(get_session_id_from_packet(p) == 77, "session id of the packet's session");
}
static void e_get_session_id_from_packet(void) {
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(get_session_id_from_packet(p) == (uint64_t) -1, "sessionless packet -> -1");
    CHECK(get_session_id_from_packet(p) == MMT_NO_SESSION_ID && MMT_NO_SESSION_ID == (uint64_t) -1,
          "sessionless packet -> MMT_NO_SESSION_ID (#546)");
}

static void b_get_user_session_context_from_packet(void) {
    fake_packet_t f;
    int ctx;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    p->session = fake_session();
    p->session->user_data = &ctx;
    CHECK(get_user_session_context_from_packet(p) == &ctx, "user context of the packet's session");
}
static void e_get_user_session_context_from_packet(void) {
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(get_user_session_context_from_packet(p) == NULL, "sessionless packet -> NULL");
}

static void b_set_user_session_context_for_packet(void) {
    fake_packet_t f;
    int ctx;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    p->session = fake_session();
    set_user_session_context_for_packet(p, &ctx);
    CHECK(g_fs.user_data == &ctx, "context stored on the packet's session");
}
static void e_set_user_session_context_for_packet(void) {
    fake_packet_t f;
    int ctx;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    set_user_session_context_for_packet(p, &ctx);
    CHECK(p->session == NULL && get_user_session_context_from_packet(p) == NULL,
          "sessionless packet: nothing stored, no session conjured");
}

static void b_get_proto_session_data_from_packet(void) {
    fake_packet_t f;
    int d;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    p->session = fake_session();
    g_fs.session_data[1] = &d;
    CHECK(get_proto_session_data_from_packet(p, 1) == &d, "slot 1 of the packet's session");
}
static void e_get_proto_session_data_from_packet(void) {
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    p->session = fake_session();
    for (int i = 0; i < PROTO_PATH_SIZE; i++) g_fs.session_data[i] = &g_fs;
    CHECK(get_proto_session_data_from_packet(p, PROTO_PATH_SIZE) == NULL, "index past PROTO_PATH_SIZE -> NULL");
    p->session = NULL;
    CHECK(get_proto_session_data_from_packet(p, 1) == NULL, "sessionless packet -> NULL");
}

static void b_get_session_from_packet(void) {
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    p->session = fake_session();
    CHECK(get_session_from_packet(p) == &g_fs, "the packet's session");
}
static void e_get_session_from_packet(void) {
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(get_session_from_packet(p) == NULL, "sessionless packet -> NULL");
}

static void b_get_session_parent(void) {
    mmt_session_t child;
    memset(&child, 0, sizeof(child));
    child.parent_session = fake_session();
    CHECK(get_session_parent(&child) == &g_fs, "child reports its tunnel parent");
}
static void e_get_session_parent(void) {
    CHECK(get_session_parent(fake_session()) == NULL, "root session has no parent -> NULL");
}

static void b_get_session_handler(void) {
    mmt_session_t *s = fake_session();
    s->mmt_handler = g_cfg;
    CHECK(get_session_handler(s) == g_cfg, "owning handler");
}

static void b_get_session_protocol_index(void) {
    CHECK(get_session_protocol_index(fake_session()) == 3, "session protocol index");
}

static void b_get_session_protocol_hierarchy(void) {
    mmt_session_t *s = fake_session();
    const proto_hierarchy_t *h = get_session_protocol_hierarchy(s);
    CHECK(h == &s->proto_path && h->len == 2 && h->proto_path[1] == AC_PROTO_A,
          "the session's own protocol path");
}

static void b_get_session_id(void) {
    CHECK(get_session_id(fake_session()) == 77, "session id");
}

/* Issue #567: how the session's verdict was reached. */
static void b_get_session_classification_method(void) {
    mmt_session_t *s = fake_session();
    CHECK(get_session_classification_method(s) == MMT_CLASSIFICATION_METHOD_NONE,
          "a fresh session has no verdict method");
    s->classification_method = MMT_CLASSIFICATION_METHOD_HOSTNAME;
    CHECK(get_session_classification_method(s) == MMT_CLASSIFICATION_METHOD_HOSTNAME,
          "the recorded method");
}
static void e_get_session_classification_method(void) {
    CHECK(get_session_classification_method(NULL) == MMT_CLASSIFICATION_METHOD_NONE,
          "NULL session -> none");
}

static void b_get_classification_method_name(void) {
    CHECK(strcmp(get_classification_method_name(MMT_CLASSIFICATION_METHOD_NONE), "none") == 0
          && strcmp(get_classification_method_name(MMT_CLASSIFICATION_METHOD_PORT), "port") == 0
          && strcmp(get_classification_method_name(MMT_CLASSIFICATION_METHOD_IP), "ip") == 0
          && strcmp(get_classification_method_name(MMT_CLASSIFICATION_METHOD_CORRELATED), "correlated") == 0
          && strcmp(get_classification_method_name(MMT_CLASSIFICATION_METHOD_HOSTNAME), "hostname") == 0
          && strcmp(get_classification_method_name(MMT_CLASSIFICATION_METHOD_DPI), "dpi") == 0,
          "every method has its name");
}
static void e_get_classification_method_name(void) {
    CHECK(get_classification_method_name(MMT_CLASSIFICATION_METHOD_NB) == NULL
          && get_classification_method_name(255) == NULL,
          "not a method -> NULL");
}

static void b_get_user_session_context(void) {
    mmt_session_t *s = fake_session();
    int ctx;
    CHECK(get_user_session_context(s) == NULL, "no context before one is set");
    s->user_data = &ctx;
    CHECK(get_user_session_context(s) == &ctx, "stored context");
}

static void b_get_proto_session_data(void) {
    mmt_session_t *s = fake_session();
    int d;
    s->session_data[4] = &d;
    CHECK(get_proto_session_data(s, 4) == &d, "slot 4");
}
static void e_get_proto_session_data(void) {
    mmt_session_t *s = fake_session();
    for (int i = 0; i < PROTO_PATH_SIZE; i++) s->session_data[i] = s;
    CHECK(get_proto_session_data(s, PROTO_PATH_SIZE) == NULL, "index past PROTO_PATH_SIZE -> NULL");
}

static void b_set_proto_session_data(void) {
    mmt_session_t *s = fake_session();
    int d;
    set_proto_session_data(s, &d, 2);
    CHECK(s->session_data[2] == &d, "slot 2 written");
}
static void e_set_proto_session_data(void) {
    mmt_session_t *s = fake_session();
    int d, untouched = 1;
    set_proto_session_data(s, &d, PROTO_PATH_SIZE);
    for (int i = 0; i < PROTO_PATH_SIZE; i++) if (s->session_data[i] != NULL) untouched = 0;
    CHECK(untouched, "index past PROTO_PATH_SIZE writes nothing");
}

static void b_set_user_session_context(void) {
    mmt_session_t *s = fake_session();
    int ctx;
    set_user_session_context(s, &ctx);
    CHECK(s->user_data == &ctx, "context stored");
}

/* --- session counters: the per-session getters subtract the subsession
 * (tunnel-children) share, the _total_ getters report the raw counter. --- */
#define AC_SUB(fn, field) \
static void b_##fn(void) { \
    mmt_session_t *s = fake_session(); \
    CHECK(s->children_stats->sub_##field != 0 && \
          fn(s) == s->field - s->children_stats->sub_##field, \
          #fn ": tunnel parent excludes its children's share"); \
    s->children_stats = NULL; \
    CHECK(fn(s) == s->field, #fn ": leaf session reports the raw counter"); \
}
#define AC_SUB_DIR(fn, field, dir) \
static void b_##fn(void) { \
    mmt_session_t *s = fake_session(); \
    CHECK(fn(s) == s->field[dir] - s->children_stats->sub_##field[dir], \
          #fn ": slot of the setup direction 1, minus the children's share"); \
    s->setup_packet_direction = 0; \
    CHECK(fn(s) == s->field[!(dir)] - s->children_stats->sub_##field[!(dir)], \
          #fn ": follows the setup direction"); \
}
#define AC_TOTAL(fn, field) \
static void b_##fn(void) { \
    mmt_session_t *s = fake_session(); \
    CHECK(fn(s) == s->field && s->children_stats->sub_##field != 0, \
          #fn ": raw counter, children included"); \
}
#define AC_TOTAL_DIR(fn, field, dir) \
static void b_##fn(void) { \
    mmt_session_t *s = fake_session(); \
    CHECK(fn(s) == s->field[dir], #fn ": raw slot of the setup direction 1"); \
    s->setup_packet_direction = 0; \
    CHECK(fn(s) == s->field[!(dir)], #fn ": follows the setup direction"); \
}
#define UL 1 /* uplink = the setup direction slot (setup_packet_direction == 1) */
#define DL 0
AC_SUB(get_session_packet_count, packet_count)
AC_SUB(get_session_packet_cap_count, packet_cap_count)
AC_SUB(get_session_data_cap_volume, data_cap_volume)
AC_SUB_DIR(get_session_ul_packet_count, packet_count_direction, UL)
AC_SUB_DIR(get_session_ul_cap_packet_count, packet_cap_count_direction, UL)
AC_SUB_DIR(get_session_dl_packet_count, packet_count_direction, DL)
AC_SUB_DIR(get_session_dl_cap_packet_count, packet_cap_count_direction, DL)
AC_SUB(get_session_byte_count, data_volume)
AC_SUB_DIR(get_session_ul_byte_count, data_volume_direction, UL)
AC_SUB_DIR(get_session_dl_byte_count, data_volume_direction, DL)
AC_SUB_DIR(get_session_ul_cap_byte_count, data_cap_volume_direction, UL)
AC_SUB_DIR(get_session_dl_cap_byte_count, data_cap_volume_direction, DL)
AC_SUB(get_session_data_packet_count, data_packet_count)
AC_SUB_DIR(get_session_ul_data_packet_count, data_packet_count_direction, UL)
AC_SUB_DIR(get_session_dl_data_packet_count, data_packet_count_direction, DL)
AC_SUB(get_session_data_byte_count, data_byte_volume)
AC_SUB_DIR(get_session_ul_data_byte_count, data_byte_volume_direction, UL)
AC_SUB_DIR(get_session_dl_data_byte_count, data_byte_volume_direction, DL)
AC_TOTAL(get_session_total_packet_count, packet_count)
AC_TOTAL(get_session_total_packet_cap_count, packet_cap_count)
AC_TOTAL(get_session_total_data_cap_volume, data_cap_volume)
AC_TOTAL_DIR(get_session_total_ul_packet_count, packet_count_direction, UL)
AC_TOTAL_DIR(get_session_total_ul_cap_packet_count, packet_cap_count_direction, UL)
AC_TOTAL_DIR(get_session_total_dl_packet_count, packet_count_direction, DL)
AC_TOTAL_DIR(get_session_total_dl_cap_packet_count, packet_cap_count_direction, DL)
AC_TOTAL(get_session_total_byte_count, data_volume)
AC_TOTAL_DIR(get_session_total_ul_byte_count, data_volume_direction, UL)
AC_TOTAL_DIR(get_session_total_dl_byte_count, data_volume_direction, DL)
AC_TOTAL_DIR(get_session_total_ul_cap_byte_count, data_cap_volume_direction, UL)
AC_TOTAL_DIR(get_session_total_dl_cap_byte_count, data_cap_volume_direction, DL)
AC_TOTAL(get_session_total_data_packet_count, data_packet_count)
AC_TOTAL_DIR(get_session_total_ul_data_packet_count, data_packet_count_direction, UL)
AC_TOTAL_DIR(get_session_total_dl_data_packet_count, data_packet_count_direction, DL)
AC_TOTAL(get_session_total_data_byte_count, data_byte_volume)
AC_TOTAL_DIR(get_session_total_ul_data_byte_count, data_byte_volume_direction, UL)
AC_TOTAL_DIR(get_session_total_dl_data_byte_count, data_byte_volume_direction, DL)

static void b_get_session_init_time(void) {
    CHECK(same_tv(get_session_init_time(fake_session()), 11, 12), "session start time");
}
static void b_get_session_last_activity_time(void) {
    CHECK(same_tv(get_session_last_activity_time(fake_session()), 21, 22), "last activity time");
}

static void b_get_session_last_data_packet_time_by_direction(void) {
    mmt_session_t *s = fake_session();
    CHECK(same_tv(get_session_last_data_packet_time_by_direction(s, 0), 31, 32), "initiator slot");
    CHECK(same_tv(get_session_last_data_packet_time_by_direction(s, 1), 41, 42), "remote slot");
}
static void e_get_session_last_data_packet_time_by_direction(void) {
    CHECK(same_tv(get_session_last_data_packet_time_by_direction(fake_session(), 2), 0, 0),
          "direction 2 (no such slot) -> zero timestamp");
    CHECK(same_tv(get_session_last_data_packet_time_by_direction(NULL, 0), 0, 0),
          "NULL session -> zero timestamp");
}

static void b_get_session_rtt(void) {
    CHECK(same_tv(get_session_rtt(fake_session()), 51, 52), "session RTT");
}
static void b_get_session_content_class_id(void) {
    CHECK(get_session_content_class_id(fake_session()) == 61, "content class");
}
static void b_get_session_content_type_id(void) {
    CHECK(get_session_content_type_id(fake_session()) == 62, "content type");
}
static void b_get_session_content_flags(void) {
    CHECK(get_session_content_flags(fake_session()) == 63, "content flags");
}
static void b_get_session_retransmission_count(void) {
    CHECK(get_session_retransmission_count(fake_session()) == 64, "TCP retransmissions");
}
static void b_get_session_outoforder_count(void) {
    CHECK(get_session_outoforder_count(fake_session()) == 65, "TCP out-of-order segments");
}

static void b_get_session_next(void) {
    mmt_session_t other;
    mmt_session_t *s = fake_session();
    s->next = &other;
    CHECK(get_session_next(s) == &other, "next session in the list");
}
static void e_get_session_next(void) {
    CHECK(get_session_next(fake_session()) == NULL, "last session: no next -> NULL");
}

static void b_get_session_previous(void) {
    mmt_session_t other;
    mmt_session_t *s = fake_session();
    s->previous = &other;
    CHECK(get_session_previous(s) == &other, "previous session in the list");
}
static void e_get_session_previous(void) {
    CHECK(get_session_previous(fake_session()) == NULL, "first session: no previous -> NULL");
}

static void b_get_session_proto_path_direction(void) {
    mmt_session_t *s = fake_session(); /* tunnel parent, setup 1, last 1 */
    CHECK(get_session_proto_path_direction(s, MMT_SESSION_DIRECTION_UPLINK) == &g_fcs.proto_path_direction[1],
          "uplink path of a tunnel parent is the setup-direction copy");
    CHECK(get_session_proto_path_direction(s, MMT_SESSION_DIRECTION_DOWNLINK) == &g_fcs.proto_path_direction[0],
          "downlink path of a tunnel parent is the other copy");
    s->children_stats = NULL;
    CHECK(get_session_proto_path_direction(s, MMT_SESSION_DIRECTION_DOWNLINK) == &s->proto_path,
          "a leaf session shares its proto_path for both directions");
}

static void b_get_session_setup_direction(void) {
    mmt_session_t *s = fake_session();
    CHECK(get_session_setup_direction(s) == 1, "setup direction");
    s->setup_packet_direction = 0;
    CHECK(get_session_setup_direction(s) == 0, "setup direction follows the record");
}
static void b_get_session_last_packet_direction(void) {
    mmt_session_t *s = fake_session();
    s->last_packet_direction = 0;
    CHECK(get_session_last_packet_direction(s) == 0, "last packet direction 0");
    s->last_packet_direction = 1;
    CHECK(get_session_last_packet_direction(s) == 1, "last packet direction 1");
}

static void b_get_attr_protocol_id(void) {
    CHECK(get_attr_protocol_id(fake_attribute(MMT_U32_DATA)) == PROTO_META, "attribute protocol id");
}
static void b_get_attr_id(void) {
    CHECK(get_attr_id(fake_attribute(MMT_U32_DATA)) == META_P_LEN, "attribute id");
}
static void b_get_attr_protocol_index(void) {
    CHECK(get_attr_protocol_index(fake_attribute(MMT_U32_DATA)) == 5, "attribute protocol index");
}
static void b_get_attr_status(void) {
    CHECK(get_attr_status(fake_attribute(MMT_U32_DATA)) == ATTRIBUTE_SET, "attribute status");
}
static void b_get_attr_data_type(void) {
    CHECK(get_attr_data_type(fake_attribute(MMT_U16_DATA)) == MMT_U16_DATA, "attribute data type");
}
static void b_get_attr_data_len(void) {
    CHECK(get_attr_data_len(fake_attribute(MMT_U32_DATA)) == 4, "attribute data length");
}
static void b_get_attr_offset(void) {
    CHECK(get_attr_offset(fake_attribute(MMT_U32_DATA)) == 9, "attribute position in packet");
}
static void b_get_attr_scope(void) {
    CHECK(get_attr_scope(fake_attribute(MMT_U32_DATA)) == SCOPE_PACKET, "attribute scope");
}
static void b_get_attr_data(void) {
    CHECK(get_attr_data(fake_attribute(MMT_U32_DATA)) == &g_fa_value, "attribute data pointer");
}

static void b_get_last_activity_time(void) {
    CHECK(send_packet(g_h, AC_KEY, AC_SEC + 1, 777) == 1, "fixture packet processed");
    CHECK(same_tv(get_last_activity_time(g_h), AC_SEC + 1, 777),
          "timestamp of the last packet the handler processed");
    CHECK(send_packet(g_h, AC_KEY, AC_SEC, AC_USEC) == 1, "fixture clock restored");
}

static void b_htoi(void) {
    char out[4] = { 0 };
    CHECK(htoi(out, sizeof(out), "0aFf", 2) == 2, "two bytes converted");
    CHECK((unsigned char) out[0] == 0x0a && (unsigned char) out[1] == 0xff, "mixed-case hex digits");
    CHECK(htoi(out, 1, "1234", 2) == 1, "capacity bounds the write");
}
static void e_htoi(void) {
    char out[4];
    CHECK(htoi(NULL, sizeof(out), "0a", 1) == 0, "NULL destination -> 0 bytes");
    CHECK(htoi(out, 0, "0a", 1) == 0, "zero capacity -> 0 bytes");
    CHECK(htoi(out, sizeof(out), "zz", 1) == 0, "non-hex input -> 0 bytes");
}

static void b_get_data_size_by_proto_and_field_ids(void) {
    CHECK(get_data_size_by_proto_and_field_ids(PROTO_META, META_P_LEN) == (int) sizeof(int), "meta.packet_len size");
    CHECK(get_data_size_by_proto_and_field_ids(AC_PROTO_A, AC_ATTR_U16) == 2, "registered attribute length");
}
static void e_get_data_size_by_proto_and_field_ids(void) {
    CHECK(get_data_size_by_proto_and_field_ids(AC_UNREG_ID, 1) == 0, "unregistered protocol -> 0");
    CHECK(get_data_size_by_proto_and_field_ids(AC_PROTO_A, AC_ATTR_NONE) == 0, "unknown attribute -> 0");
}

static void b_get_data_size_by_data_type(void) {
    CHECK(get_data_size_by_data_type(MMT_U32_DATA) == 4, "U32 is 4 bytes");
    CHECK(get_data_size_by_data_type(MMT_DATA_IP6_ADDR) == 16, "IPv6 address is 16 bytes");
}
static void e_get_data_size_by_data_type(void) {
    CHECK(get_data_size_by_data_type(0xffffu) == 0, "unknown data type -> 0");
    CHECK(get_data_size_by_data_type(MMT_UNDEFINED_TYPE) == 0, "undefined type -> 0");
}

static void b_get_field_position_by_protocol_and_field_ids(void) {
    CHECK(get_field_position_by_protocol_and_field_ids(AC_PROTO_A, AC_ATTR_U16) == 6, "declared position");
}
static void e_get_field_position_by_protocol_and_field_ids(void) {
    CHECK(get_field_position_by_protocol_and_field_ids(AC_UNREG_ID, 1) == POSITION_NOT_KNOWN,
          "unregistered protocol -> POSITION_NOT_KNOWN");
    CHECK(get_field_position_by_protocol_and_field_ids(AC_PROTO_A, AC_ATTR_NONE) == POSITION_NOT_KNOWN,
          "unknown attribute -> POSITION_NOT_KNOWN");
}

static void b_is_protocol_attribute(void) {
    CHECK(is_protocol_attribute(PROTO_META, META_P_LEN) == true, "meta.packet_len exists");
}
static void e_is_protocol_attribute(void) {
    CHECK(is_protocol_attribute(PROTO_META, AC_ATTR_NONE) == false, "unknown attribute -> false");
    CHECK(is_protocol_attribute(AC_UNREG_ID, 1) == false, "unregistered protocol -> false");
}

static void b_get_protocol_id_by_name(void) {
    CHECK(get_protocol_id_by_name("meta") == PROTO_META, "meta");
    CHECK(get_protocol_id_by_name("AC_PROTO_A") == AC_PROTO_A, "case-insensitive");
}
static void e_get_protocol_id_by_name(void) {
    CHECK(get_protocol_id_by_name("no_such_proto") == 0, "unknown name -> 0");
    CHECK(get_protocol_id_by_name(NULL) == 0, "NULL name -> 0");
}

static void b_get_attribute_id_by_protocol_and_attribute_names(void) {
    CHECK(get_attribute_id_by_protocol_and_attribute_names("meta", "packet_len") == META_P_LEN, "meta.packet_len");
    CHECK(get_attribute_id_by_protocol_and_attribute_names("ac_proto_a", "ac_u16") == AC_ATTR_U16, "custom attribute");
}
static void e_get_attribute_id_by_protocol_and_attribute_names(void) {
    CHECK(get_attribute_id_by_protocol_and_attribute_names("meta", "no_such_attr") == 0, "unknown attribute -> 0");
    CHECK(get_attribute_id_by_protocol_and_attribute_names("no_such_proto", "packet_len") == 0, "unknown protocol -> 0");
}

static void b_get_attribute_id_by_protocol_id_and_attribute_name(void) {
    CHECK(get_attribute_id_by_protocol_id_and_attribute_name(PROTO_META, "packet_len") == META_P_LEN, "meta.packet_len");
}
static void e_get_attribute_id_by_protocol_id_and_attribute_name(void) {
    CHECK(get_attribute_id_by_protocol_id_and_attribute_name(PROTO_META, "no_such_attr") == 0, "unknown attribute -> 0");
    CHECK(get_attribute_id_by_protocol_id_and_attribute_name(AC_UNREG_ID, "packet_len") == 0, "unregistered protocol -> 0");
}

static void b_get_attribute_data_type(void) {
    CHECK(get_attribute_data_type(PROTO_META, META_P_LEN) == MMT_U32_DATA, "meta.packet_len is U32");
    CHECK(get_attribute_data_type(AC_PROTO_A, AC_ATTR_U16) == MMT_U16_DATA, "custom attribute type");
}
static void e_get_attribute_data_type(void) {
    CHECK(get_attribute_data_type(AC_UNREG_ID, 1) == MMT_UNDEFINED_TYPE, "unregistered protocol -> MMT_UNDEFINED_TYPE");
    CHECK(get_attribute_data_type(PROTO_META, AC_ATTR_NONE) == MMT_UNDEFINED_TYPE, "unknown attribute -> MMT_UNDEFINED_TYPE");
}

static void b_get_attribute_scope(void) {
    CHECK(get_attribute_scope(PROTO_META, META_P_LEN) == SCOPE_PACKET, "packet scope");
    CHECK(get_attribute_scope(AC_PROTO_A, AC_ATTR_EVENT) == SCOPE_EVENT, "event scope");
}
static void e_get_attribute_scope(void) {
    CHECK(get_attribute_scope(AC_UNREG_ID, 1) == 0, "unregistered protocol -> 0");
    CHECK(get_attribute_scope(PROTO_META, AC_ATTR_NONE) == 0, "unknown attribute -> 0");
}

static void b_short_time_diff(void) {
    struct timeval a = { 10, 250000 }, b = { 11, 750000 };
    CHECK(short_time_diff(&a, &b) == 1500000u, "1.5 s in microseconds");
    CHECK(short_time_diff(&a, &a) == 0u, "no time elapsed");
}

static void b_get_classification_threshold(void) {
    CHECK(get_classification_threshold() == CFG_CLASSIFICATION_THRESHOLD, "configured threshold");
}

static void b_proto_hierarchy_to_str_with_size(void) {
    proto_hierarchy_t h = { 2, { PROTO_META, AC_PROTO_A } };
    char buf[64];
    int n = proto_hierarchy_to_str_with_size(&h, buf, sizeof(buf));
    CHECK(n == (int) strlen("meta.ac_proto_a") && strcmp(buf, "meta.ac_proto_a") == 0, "dotted path");
    n = proto_hierarchy_to_str_with_size(&h, buf, 5);
    CHECK(n == 4 && strcmp(buf, "meta") == 0, "truncated to the buffer");
}
static void e_proto_hierarchy_to_str_with_size(void) {
    proto_hierarchy_t h = { 2, { PROTO_META, AC_PROTO_A } };
    char buf[8] = "x";
    CHECK(proto_hierarchy_to_str_with_size(&h, NULL, sizeof(buf)) == 0, "NULL destination -> 0");
    CHECK(proto_hierarchy_to_str_with_size(&h, buf, 0) == 0 && buf[0] == 'x', "zero size -> 0, nothing written");
    CHECK(proto_hierarchy_to_str_with_size(NULL, buf, sizeof(buf)) == 0, "NULL path -> 0");
}

static void b_proto_hierarchy_to_str(void) {
    proto_hierarchy_t h = { 2, { PROTO_META, AC_PROTO_A } };
    char buf[PROTO_PATH_SIZE * (Max_Alias_Len + 1)];
    AC_ALLOW_DEPRECATED_BEGIN
    int n = proto_hierarchy_to_str(&h, buf);
    AC_ALLOW_DEPRECATED_END
    CHECK(n == (int) strlen("meta.ac_proto_a") && strcmp(buf, "meta.ac_proto_a") == 0, "dotted path");
}
static void e_proto_hierarchy_to_str(void) {
    char buf[PROTO_PATH_SIZE * (Max_Alias_Len + 1)];
    proto_hierarchy_t empty = { 0, { 0 } };
    buf[0] = 'x';
    AC_ALLOW_DEPRECATED_BEGIN
    int n_null = proto_hierarchy_to_str(NULL, buf);
    int n_empty = proto_hierarchy_to_str(&empty, buf);
    AC_ALLOW_DEPRECATED_END
    CHECK(n_null == 0, "NULL path -> 0");
    CHECK(n_empty == 0 && buf[0] == '\0', "empty path -> 0 and an empty string");
}

static void b_get_application_name(void) {
    proto_hierarchy_t h = { 2, { PROTO_META, AC_PROTO_A } };
    const char *n = get_application_name(&h);
    CHECK(n != NULL && strcmp(n, "ac_proto_a") == 0, "name of the innermost layer");
}
static void e_get_application_name(void) {
    proto_hierarchy_t empty = { 0, { 0 } };
    CHECK(get_application_name(NULL) == NULL, "NULL path -> NULL");
    CHECK(get_application_name(&empty) == NULL, "empty path -> NULL");
}

static void b_mmt_toupper(void) {
    CHECK(mmt_toupper('a') == 'A' && mmt_toupper('z') == 'Z', "lowercase letters fold up");
    CHECK(mmt_toupper('Q') == 'Q' && mmt_toupper('1') == '1', "other characters pass through");
}
static void b_mmt_tolower(void) {
    CHECK(mmt_tolower('A') == 'a' && mmt_tolower('Z') == 'z', "uppercase letters fold down");
    CHECK(mmt_tolower('q') == 'q' && mmt_tolower('@') == '@', "other characters pass through");
}
static void b_mmt_strcasecmp(void) {
    CHECK(mmt_strcasecmp("Meta", "mETA") == 0, "equal ignoring case");
    CHECK(mmt_strcasecmp("abc", "ABD") < 0 && mmt_strcasecmp("abd", "ABC") > 0, "orders case-insensitively");
}
static void b_mmt_strncasecmp(void) {
    CHECK(mmt_strncasecmp("MetaX", "metaY", 4) == 0, "equal over the first 4 characters");
    CHECK(mmt_strncasecmp("MetaX", "metaY", 5) < 0, "differs at the 5th character");
}
/* Finding (issue #525): data_defs.h documents mmt_strcmp as case-insensitive;
 * the implementation is case-sensitive. The contract pins the code. */
static void b_mmt_strcmp(void) {
    CHECK(mmt_strcmp("meta", "meta") == 0, "equal strings");
    CHECK(mmt_strcmp("meta", "META") > 0, "case-sensitive: 'm' > 'M'");
    CHECK(mmt_strcmp("abc", "abd") < 0, "orders by the first difference");
}
static void b_mmt_strncmp(void) {
    CHECK(mmt_strncmp("abcX", "abcY", 3) == 0, "equal over the first 3 characters");
    CHECK(mmt_strncmp("abcX", "abcY", 4) < 0, "differs at the 4th character");
    CHECK(mmt_strncmp("abc", "ABC", 3) > 0, "case-sensitive");
}

static void b_mmt_attr_format(void) {
    FILE *f = tmpfile();
    char buf[128] = { 0 };
    CHECK(f != NULL, "tmpfile");
    if (f == NULL) return;
    int n = mmt_attr_format(f, fake_attribute(MMT_U32_DATA));
    rewind(f);
    size_t got = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    CHECK(n > 0 && (size_t) n == got && strcmp(buf, "Attribute meta.packet_len = 42\n") == 0,
          "labelled line with the decimal value");
}
static void e_mmt_attr_format(void) {
    FILE *f = tmpfile();
    CHECK(f != NULL, "tmpfile");
    if (f == NULL) return;
    int n = mmt_attr_format(f, fake_attribute(MMT_UNDEFINED_TYPE));
    long pos = ftell(f);
    fclose(f);
    CHECK(n == -1 && pos == 0, "no text form for the data type -> -1, nothing written");
}

static void b_mmt_attr_fprintf(void) {
    FILE *f = tmpfile();
    char buf[64] = { 0 };
    CHECK(f != NULL, "tmpfile");
    if (f == NULL) return;
    int n = mmt_attr_fprintf(f, fake_attribute(MMT_U32_DATA));
    rewind(f);
    size_t got = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    CHECK(n == 2 && got == 2 && strcmp(buf, "42") == 0, "decimal value");
}
static void e_mmt_attr_fprintf(void) {
    FILE *f = tmpfile();
    CHECK(f != NULL, "tmpfile");
    if (f == NULL) return;
    int n = mmt_attr_fprintf(f, fake_attribute(MMT_UNDEFINED_TYPE));
    long pos = ftell(f);
    fclose(f);
    CHECK(n == -1 && pos == 0, "no text form for the data type -> -1, nothing written");
}

static void b_mmt_attr_sprintf(void) {
    char buf[32];
    CHECK(mmt_attr_sprintf(buf, sizeof(buf), fake_attribute(MMT_U32_DATA)) == 2 && strcmp(buf, "42") == 0,
          "decimal value");
}
static void e_mmt_attr_sprintf(void) {
    char buf[32] = "x";
    CHECK(mmt_attr_sprintf(buf, sizeof(buf), fake_attribute(MMT_UNDEFINED_TYPE)) == -1 && buf[0] == '\0',
          "no text form -> -1 and an empty string");
    CHECK(mmt_attr_sprintf(buf, 2, fake_attribute(MMT_U32_DATA)) == -1, "buffer too small -> -1");
}

static void b_mmt_inet_ntop(void) {
    uint8_t v4[4] = { 10, 0, 0, 1 };
    uint8_t v6[16] = { 0 };
    char buf[INET6_ADDRSTRLEN];
    v6[15] = 1;
    CHECK(mmt_inet_ntop(AF_INET, v4, buf, sizeof(buf)) == buf && strcmp(buf, "10.0.0.1") == 0, "IPv4");
    CHECK(mmt_inet_ntop(AF_INET6, v6, buf, sizeof(buf)) == buf && strcmp(buf, "::1") == 0, "IPv6");
}
static void e_mmt_inet_ntop(void) {
    uint8_t v4[4] = { 10, 0, 0, 1 };
    char buf[INET6_ADDRSTRLEN];
    CHECK(mmt_inet_ntop(AF_UNIX, v4, buf, sizeof(buf)) == NULL, "unsupported family -> NULL");
    CHECK(mmt_inet_ntop(AF_INET, v4, NULL, sizeof(buf)) == NULL, "NULL buffer -> NULL");
    CHECK(mmt_inet_ntop(AF_INET, NULL, buf, sizeof(buf)) == NULL, "NULL address -> NULL");
    CHECK(mmt_inet_ntop(AF_INET, v4, buf, 4) == NULL, "buffer too small -> NULL");
}

/* ======================================================================== */
/*                             extraction_lib.h                             */
/* ======================================================================== */

/* The fake packet places layer 1 at offset 10; the attribute sits at
 * position 2 of that layer, i.e. bytes 12.. (buf[i] == i). */
static attribute_t *extract_target(attribute_t *a, uint8_t *out, int len, int pos) {
    memset(a, 0, sizeof(*a));
    memset(out, 0xee, 8);
    a->data = out;
    a->data_len = len;
    a->position_in_packet = pos;
    return a;
}

static void b_silent_extraction(void) {
    fake_packet_t f;
    attribute_t a;
    uint8_t out[8];
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(silent_extraction(p, 1, extract_target(&a, out, 4, 2)) == 0 && out[0] == 0xee,
          "extracts nothing and leaves the buffer untouched");
}
static void e_silent_extraction(void) {
    attribute_t a;
    uint8_t out[8];
    CHECK(silent_extraction(NULL, 1, extract_target(&a, out, 4, 2)) == 0, "NULL packet -> 0");
}

static void b_general_byte_to_byte_extraction(void) {
    fake_packet_t f;
    attribute_t a;
    uint8_t out[8];
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(general_byte_to_byte_extraction(p, 1, extract_target(&a, out, 4, 2)) == 1 &&
          memcmp(out, f.buf + 12, 4) == 0 && out[4] == 0xee, "copies data_len bytes at layer offset + position");
}
static void e_general_byte_to_byte_extraction(void) {
    fake_packet_t f;
    attribute_t a;
    uint8_t out[8];
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(general_byte_to_byte_extraction(p, 1, extract_target(&a, out, 4, 52)) == 0 && out[0] == 0xee,
          "span past caplen -> 0, nothing copied");
    CHECK(general_byte_to_byte_extraction(NULL, 1, extract_target(&a, out, 4, 2)) == 0, "NULL packet -> 0");
}

static void b_general_short_extraction_with_ordering_change(void) {
    fake_packet_t f;
    attribute_t a;
    uint8_t out[8];
    uint16_t v;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(general_short_extraction_with_ordering_change(p, 1, extract_target(&a, out, 2, 2)) == 1, "extracted");
    memcpy(&v, out, sizeof(v));
    CHECK(v == 0x0c0d, "network-order bytes 12,13 -> host value 0x0c0d");
}
static void e_general_short_extraction_with_ordering_change(void) {
    fake_packet_t f;
    attribute_t a;
    uint8_t out[8];
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(general_short_extraction_with_ordering_change(p, 1, extract_target(&a, out, 2, 53)) == 0 &&
          out[0] == 0xee, "span past caplen -> 0, nothing written");
}

static void b_general_int_extraction_with_ordering_change(void) {
    fake_packet_t f;
    attribute_t a;
    uint8_t out[8];
    uint32_t v;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(general_int_extraction_with_ordering_change(p, 1, extract_target(&a, out, 4, 2)) == 1, "extracted");
    memcpy(&v, out, sizeof(v));
    CHECK(v == 0x0c0d0e0fu, "network-order bytes 12..15 -> host value 0x0c0d0e0f");
}
static void e_general_int_extraction_with_ordering_change(void) {
    fake_packet_t f;
    attribute_t a;
    uint8_t out[8];
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(general_int_extraction_with_ordering_change(p, 1, extract_target(&a, out, 4, 51)) == 0 &&
          out[0] == 0xee, "span past caplen -> 0, nothing written");
}

static void b_general_char_extraction(void) {
    fake_packet_t f;
    attribute_t a;
    uint8_t out[8];
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(general_char_extraction(p, 1, extract_target(&a, out, 1, 2)) == 1 && out[0] == 12 && out[1] == 0xee,
          "one byte at offset 12");
}
static void e_general_char_extraction(void) {
    fake_packet_t f;
    attribute_t a;
    uint8_t out[8];
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(general_char_extraction(p, 1, extract_target(&a, out, 1, 54)) == 0 && out[0] == 0xee,
          "position past caplen -> 0, nothing written");
}

static void b_general_short_extraction(void) {
    fake_packet_t f;
    attribute_t a;
    uint8_t out[8];
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(general_short_extraction(p, 1, extract_target(&a, out, 2, 2)) == 1 &&
          memcmp(out, f.buf + 12, 2) == 0 && out[2] == 0xee, "two bytes in packet byte order");
}
static void e_general_short_extraction(void) {
    fake_packet_t f;
    attribute_t a;
    uint8_t out[8];
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(general_short_extraction(p, 1, extract_target(&a, out, 2, 53)) == 0 && out[0] == 0xee,
          "span past caplen -> 0, nothing written");
}

static void b_general_int_extraction(void) {
    fake_packet_t f;
    attribute_t a;
    uint8_t out[8];
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    CHECK(general_int_extraction(p, 1, extract_target(&a, out, 4, 2)) == 1 &&
          memcmp(out, f.buf + 12, 4) == 0 && out[4] == 0xee, "four bytes in packet byte order");
}
static void e_general_int_extraction(void) {
    fake_packet_t f;
    attribute_t a;
    uint8_t out[8];
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    a.data = NULL;
    CHECK(general_int_extraction(p, 1, extract_target(&a, out, 4, 51)) == 0 && out[0] == 0xee,
          "span past caplen -> 0, nothing written");
    extract_target(&a, out, 4, 2);
    a.data = NULL;
    CHECK(general_int_extraction(p, 1, &a) == 0, "NULL destination -> 0");
}

/* ======================================================================== */
/*                                mmt_core.h                                */
/* ======================================================================== */

static void b_process_packet_handler(void) {
    mmt_handler_t *h = new_handler();
    fake_packet_t f;
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    register_packet_handler(h, 5, count_handler, (void *) &f);
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    p->mmt_handler = h;
    g_count_calls = 0;
    process_packet_handler(p);
    CHECK(g_count_calls == 1 && g_count_args == (void *) &f, "registered handler ran with its argument");
    CHECK(p->last_callback_fct_id == 5, "dispatch position recorded");
    mmt_close_handler(h);
}
static void e_process_packet_handler(void) {
    mmt_handler_t *h = new_handler();
    fake_packet_t f;
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    register_packet_handler(h, 5, count_handler, NULL);
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    p->mmt_handler = h;
    p->last_callback_fct_id = 4242; /* resume point naming no registered handler */
    g_count_calls = 0;
    process_packet_handler(p);
    CHECK(g_count_calls == 0, "stale resume id: no handler runs twice or out of order");
    mmt_close_handler(h);
}

static void b_mmt_drop_packet(void) {
    mmt_handler_t *h = new_handler();
    fake_packet_t f;
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    register_session_timeout_handler(h, expiry_cb, NULL);
    CHECK(send_packet(h, 0xD0D0D0D0u, AC_SEC, 0) == 1 && get_active_session_count(h) == 1, "session created");
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    p->mmt_handler = h;
    f.hdr.ts.tv_sec = AC_SEC + 1000000; /* far past the session timeout */
    p->data = (const u_char *) mmt_malloc(AC_PKT_LEN); /* reassembled-data stand-in */
    g_expiry_calls = 0;
    mmt_drop_packet(p);
    CHECK(g_expiry_calls == 1 && get_active_session_count(h) == 0, "timed-out session swept");
    CHECK(p->data == ipacket_internal(p)->original_data, "packet cleaned: owned data released");
    mmt_close_handler(h);
}

static void b_init_extraction(void) {
    CHECK(g_init_result == 1, "init_extraction reported success");
    CHECK(is_registered_protocol(PROTO_META) && is_registered_protocol(PROTO_UNKNOWN),
          "meta and unknown protocols registered");
}

static int g_update_last;
static int ac_update(int action) { g_update_last = action; return action == 3; }
static void b_update_protocol(void) {
    g_pc->update_protocol_fct = ac_update;
    CHECK(update_protocol(AC_PROTO_C, 3) == 1 && g_update_last == 3, "protocol hook ran: success");
    CHECK(update_protocol(AC_PROTO_C, 4) == 0 && g_update_last == 4, "hook result propagated");
    g_pc->update_protocol_fct = NULL;
}
static void e_update_protocol(void) {
    CHECK(update_protocol(AC_UNREG_ID, 3) == 0, "unregistered protocol -> 0");
    CHECK(update_protocol(AC_PROTO_C, 3) == 0, "protocol without an update hook -> 0");
}

static void b_close_extraction(void) {
    close_extraction();
    CHECK(!is_registered_protocol(PROTO_META) && get_protocol_id_by_name("meta") == 0,
          "registry emptied");
    CHECK(get_protocol_stack_name(AC_STACK_ID) == NULL, "protocol stacks cleared");
    CHECK(fixture_setup(), "a second init_extraction cycle rebuilds the fixture");
}

static void b_mmt_init_handler(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL && get_data_link_type(h) == AC_STACK_ID, "handler on the requested stack");
    CHECK(h != NULL && get_active_session_count(h) == 0, "fresh handler holds no session");
    if (h != NULL) mmt_close_handler(h);
}
static void e_mmt_init_handler(void) {
    char errbuf[256] = "";
    CHECK(mmt_init_handler(4242, 0, errbuf) == NULL && strcmp(errbuf, "Unsupported stack type") == 0,
          "unknown stack -> NULL with the error text");
}

static int g_handler_seen;
static void count_handler_iter(mmt_handler_t *h, void *want) { if (h == want) g_handler_seen++; }
static void b_mmt_close_handler(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    CHECK(send_packet(h, 0xE0E0E0E0u, AC_SEC, 0) == 1, "session created");
    g_expiry_calls = 0;
    register_session_timeout_handler(h, expiry_cb, NULL);
    g_handler_seen = 0;
    iterate_through_mmt_handlers(count_handler_iter, h);
    CHECK(g_handler_seen == 1, "handler is live");
    mmt_close_handler(h);
    CHECK(g_expiry_calls == 1, "live sessions expired on close");
    g_handler_seen = 0;
    iterate_through_mmt_handlers(count_handler_iter, h);
    CHECK(g_handler_seen == 0, "handler gone from the registry");
}

static void b_get_active_session_count(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    send_packet(h, 1, AC_SEC, 0);
    send_packet(h, 2, AC_SEC, 0);
    send_packet(h, 1, AC_SEC, 0);
    CHECK(get_active_session_count(h) == 2, "two keys -> two live sessions");
    mmt_close_handler(h);
}
static void e_get_active_session_count(void) {
    CHECK(get_active_session_count(NULL) == (uint64_t) -1, "NULL handler -> -1");
    CHECK(get_active_session_count(NULL) == MMT_INVALID_SESSION_COUNT, "NULL handler -> MMT_INVALID_SESSION_COUNT (#546)");
}

static void b_get_protocol_stack_name(void) {
    const char *n = get_protocol_stack_name(AC_STACK_ID);
    CHECK(n != NULL && strcmp(n, "ac_stack") == 0, "registered stack name");
}
static void e_get_protocol_stack_name(void) {
    CHECK(get_protocol_stack_name(4242) == NULL, "unknown stack -> NULL");
}

static void b_is_registered_packet_handler(void) {
    CHECK(is_registered_packet_handler(g_h, AC_HANDLER_ID) == 1, "fixture handler id registered");
}
static void e_is_registered_packet_handler(void) {
    CHECK(is_registered_packet_handler(g_h, 4242) == 0, "unknown id -> 0");
}

static void b_register_packet_handler(void) {
    mmt_handler_t *h = new_handler();
    int tag;
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    CHECK(register_packet_handler(h, 5, count_handler, &tag) == 1, "registered");
    g_count_calls = 0;
    send_packet(h, 1, AC_SEC, 0);
    CHECK(g_count_calls == 1 && g_count_args == &tag, "called once per packet with its argument");
    mmt_close_handler(h);
}
static void e_register_packet_handler(void) {
    CHECK(register_packet_handler(NULL, 5, count_handler, NULL) == 0, "NULL handler -> 0");
}

static void b_unregister_packet_handler(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    register_packet_handler(h, 6, count_handler, NULL);
    CHECK(unregister_packet_handler(h, 6) > 0 && is_registered_packet_handler(h, 6) == 0, "removed");
    g_count_calls = 0;
    send_packet(h, 1, AC_SEC, 0);
    CHECK(g_count_calls == 0, "no longer called");
    mmt_close_handler(h);
}
static void e_unregister_packet_handler(void) {
    CHECK(unregister_packet_handler(g_h, 4242) > 0, "unknown id -> positive (documented not an error)");
    CHECK(is_registered_packet_handler(g_h, AC_HANDLER_ID) == 1, "registered handlers untouched");
}

static void b_register_session_timeout_handler(void) {
    mmt_handler_t *h = new_handler();
    int tag;
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    CHECK(register_session_timeout_handler(h, expiry_cb, &tag) > 0, "registered");
    CHECK(h->session_expiry_handler.args == &tag, "argument kept");
    send_packet(h, 1, AC_SEC, 0);
    g_expiry_calls = 0;
    send_packet(h, 2, AC_SEC + 1000000, 0); /* sweeps session 1 */
    CHECK(g_expiry_calls == 1 && g_expiry_id == 1, "called for the expired session");
    mmt_close_handler(h);
}

static int fill_sessions(mmt_handler_t *h, int n) {
    g_captured_n = 0;
    register_packet_handler(h, 50, capture_handler, NULL);
    for (int i = 0; i < n; i++) send_packet(h, 0xC0DE0000u + (uint32_t) i, AC_SEC, 0);
    unregister_packet_handler(h, 50);
    return g_captured_n == n && g_captured[0] != NULL && g_captured[n - 1] != NULL;
}

static void b_register_session_timer_handler(void) {
    mmt_handler_t *h = new_handler();
    int tag;
    CHECK(h != NULL && fill_sessions(h, 2), "two sessions");
    if (h == NULL) return;
    g_captured[0]->is_fragmenting = 1;
    CHECK(register_session_timer_handler(h, timer_cb, &tag, 1) > 0, "registered with no_fragmented");
    g_timer_calls = 0;
    process_session_timer_handler(h);
    CHECK(g_timer_calls == 1 && g_timer_last == g_captured[1] && g_timer_args == &tag,
          "fragmenting session skipped, the other visited with the argument");
    g_captured[0]->is_fragmenting = 0;
    mmt_close_handler(h);
}

static void b_is_registered_attribute(void) {
    CHECK(is_registered_attribute(g_h, PROTO_META, META_P_LEN) == 1, "meta.packet_len registered");
    CHECK(is_registered_attribute(g_h, AC_PROTO_A, AC_ATTR_U32) == 1, "custom attribute registered");
}
static void e_is_registered_attribute(void) {
    CHECK(is_registered_attribute(g_h, AC_PROTO_A, AC_ATTR_U16) == 0, "declared but not registered -> 0");
    CHECK(is_registered_attribute(g_h, AC_PROTO_A, AC_ATTR_NONE) == 0, "unknown attribute -> 0");
}

static void b_register_evasion_handler(void) {
    mmt_handler_t *h = new_handler();
    fake_packet_t f;
    int tag, data;
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    CHECK(register_evasion_handler(h, evasion_cb, &tag) == 1, "registered");
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    p->mmt_handler = h;
    g_evasion_calls = 0;
    fire_evasion_event(p, AC_PROTO_A, 1, 9, &data);
    CHECK(g_evasion_calls == 1 && g_evasion_args == &tag, "registered callback receives events");
    mmt_close_handler(h);
}
static void e_register_evasion_handler(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    CHECK(register_evasion_handler(NULL, evasion_cb, NULL) == 0, "NULL handler -> 0");
    CHECK(register_evasion_handler(h, evasion_cb, NULL) == 1, "first registration");
    CHECK(register_evasion_handler(h, evasion_cb, NULL) == 0, "second registration refused -> 0");
    mmt_close_handler(h);
}

static void b_register_extraction_attribute(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    CHECK(register_extraction_attribute(h, AC_PROTO_A, AC_ATTR_U16) == 1, "registered");
    CHECK(is_registered_attribute(h, AC_PROTO_A, AC_ATTR_U16) == 1, "visible as registered");
    mmt_close_handler(h);
}
static void e_register_extraction_attribute(void) {
    CHECK(register_extraction_attribute(g_cfg, AC_UNREG_ID, 1) == 0, "unregistered protocol -> 0");
}

static void b_register_extraction_attribute_by_name(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    CHECK(register_extraction_attribute_by_name(h, "ac_proto_a", "ac_u16") == 1, "registered");
    CHECK(is_registered_attribute(h, AC_PROTO_A, AC_ATTR_U16) == 1, "visible as registered");
    mmt_close_handler(h);
}
static void e_register_extraction_attribute_by_name(void) {
    CHECK(register_extraction_attribute_by_name(g_cfg, "no_such_proto", "ac_u16") == 0, "unknown protocol -> 0");
    CHECK(register_extraction_attribute_by_name(g_cfg, "ac_proto_a", "no_such_attr") == 0, "unknown attribute -> 0");
}

static void b_unregister_extraction_attribute(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    register_extraction_attribute(h, AC_PROTO_A, AC_ATTR_U16);
    CHECK(unregister_extraction_attribute(h, AC_PROTO_A, AC_ATTR_U16) > 0 &&
          is_registered_attribute(h, AC_PROTO_A, AC_ATTR_U16) == 0, "removed");
    mmt_close_handler(h);
}
static void e_unregister_extraction_attribute(void) {
    CHECK(unregister_extraction_attribute(g_h, AC_PROTO_A, AC_ATTR_NONE) > 0,
          "never-registered attribute -> positive (documented)");
    CHECK(is_registered_attribute(g_h, AC_PROTO_A, AC_ATTR_U32) == 1, "registered attributes untouched");
}

static void b_unregister_extraction_attribute_by_name(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    register_extraction_attribute(h, AC_PROTO_A, AC_ATTR_U16);
    CHECK(unregister_extraction_attribute_by_name(h, "ac_proto_a", "ac_u16") > 0 &&
          is_registered_attribute(h, AC_PROTO_A, AC_ATTR_U16) == 0, "removed");
    mmt_close_handler(h);
}
static void e_unregister_extraction_attribute_by_name(void) {
    CHECK(unregister_extraction_attribute_by_name(g_h, "no_such_proto", "x") > 0,
          "unknown names -> positive (documented)");
    CHECK(is_registered_attribute(g_h, AC_PROTO_A, AC_ATTR_U32) == 1, "registered attributes untouched");
}

static void b_has_registered_attribute_handler(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    CHECK(has_registered_attribute_handler(h, AC_PROTO_A, AC_ATTR_U32) == 0, "none before registration");
    register_attribute_handler(h, AC_PROTO_A, AC_ATTR_U32, attr_cb, NULL, NULL);
    CHECK(has_registered_attribute_handler(h, AC_PROTO_A, AC_ATTR_U32) == 1, "one after registration");
    mmt_close_handler(h);
}
static void e_has_registered_attribute_handler(void) {
    CHECK(has_registered_attribute_handler(g_h, PROTO_MAX_IDENTIFIER, 1) == 0, "invalid protocol id -> 0");
}

static void b_is_registered_attribute_handler(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    register_attribute_handler(h, AC_PROTO_A, AC_ATTR_U32, attr_cb, NULL, NULL);
    CHECK(is_registered_attribute_handler(h, AC_PROTO_A, AC_ATTR_U32, attr_cb) == 1, "that callback is registered");
    CHECK(is_registered_attribute_handler(h, AC_PROTO_A, AC_ATTR_U32, attr_cb_other) == 0, "another callback is not");
    mmt_close_handler(h);
}
static void e_is_registered_attribute_handler(void) {
    CHECK(is_registered_attribute_handler(g_h, PROTO_MAX_IDENTIFIER, 1, attr_cb) == 0, "invalid protocol id -> 0");
}

static void b_register_attribute_handler(void) {
    mmt_handler_t *h = new_handler();
    int tag;
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    CHECK(register_attribute_handler(h, AC_PROTO_A, AC_ATTR_U32, attr_cb, NULL, &tag) == 1, "registered");
    g_attr_calls = 0;
    send_packet(h, 0xABCD1234u, AC_SEC, 0);
    CHECK(g_attr_calls == 1 && g_attr_value == 0xABCD1234u && g_attr_user == &tag,
          "called with the extracted value and its argument");
    mmt_close_handler(h);
}
static void e_register_attribute_handler(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    register_attribute_handler(h, AC_PROTO_A, AC_ATTR_U32, attr_cb, NULL, NULL);
    CHECK(register_attribute_handler(h, AC_PROTO_A, AC_ATTR_U32, attr_cb, NULL, NULL) == 0, "duplicate -> 0");
    CHECK(register_attribute_handler(h, AC_UNREG_ID, 1, attr_cb, NULL, NULL) == 0, "unregistered protocol -> 0");
    mmt_close_handler(h);
}

static void b_register_attribute_handler_by_name(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    CHECK(register_attribute_handler_by_name(h, "ac_proto_a", "ac_u32", attr_cb, NULL, NULL) == 1, "registered");
    g_attr_calls = 0;
    send_packet(h, 0x55667788u, AC_SEC, 0);
    CHECK(g_attr_calls == 1 && g_attr_value == 0x55667788u, "called with the extracted value");
    mmt_close_handler(h);
}
static void e_register_attribute_handler_by_name(void) {
    CHECK(register_attribute_handler_by_name(g_cfg, "no_such_proto", "ac_u32", attr_cb, NULL, NULL) == 0,
          "unknown protocol -> 0");
    CHECK(register_attribute_handler_by_name(g_cfg, "ac_proto_a", "no_such_attr", attr_cb, NULL, NULL) == 0,
          "unknown attribute -> 0");
}

static void b_unregister_attribute_handler(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    register_attribute_handler(h, AC_PROTO_A, AC_ATTR_U32, attr_cb, NULL, NULL);
    CHECK(unregister_attribute_handler(h, AC_PROTO_A, AC_ATTR_U32, attr_cb) > 0 &&
          is_registered_attribute_handler(h, AC_PROTO_A, AC_ATTR_U32, attr_cb) == 0, "removed");
    g_attr_calls = 0;
    send_packet(h, 1, AC_SEC, 0);
    CHECK(g_attr_calls == 0, "no longer called");
    mmt_close_handler(h);
}
static void e_unregister_attribute_handler(void) {
    CHECK(unregister_attribute_handler(g_h, AC_PROTO_A, AC_ATTR_U32, attr_cb_other) > 0,
          "never-registered callback -> positive (documented: always succeeds)");
    CHECK(is_registered_attribute(g_h, AC_PROTO_A, AC_ATTR_U32) == 1, "attribute registration untouched");
}

static void b_unregister_attribute_handler_by_name(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    register_attribute_handler(h, AC_PROTO_A, AC_ATTR_U32, attr_cb, NULL, NULL);
    CHECK(unregister_attribute_handler_by_name(h, "ac_proto_a", "ac_u32", attr_cb) > 0 &&
          is_registered_attribute_handler(h, AC_PROTO_A, AC_ATTR_U32, attr_cb) == 0, "removed");
    mmt_close_handler(h);
}
static void e_unregister_attribute_handler_by_name(void) {
    CHECK(unregister_attribute_handler_by_name(g_h, "no_such_proto", "ac_u32", attr_cb) > 0,
          "unknown protocol -> positive (documented)");
    CHECK(unregister_attribute_handler_by_name(g_h, "ac_proto_a", "no_such_attr", attr_cb) > 0,
          "unknown attribute -> positive (documented)");
}

/* --- per-handler configuration setters (target: g_cfg) --- */
#define AC_SETTER(fn, field, value) \
static void b_##fn(void) { \
    CHECK(fn(g_cfg, (value)) == 1 && g_cfg->field == (value), #fn " stores the value"); \
} \
static void e_##fn(void) { \
    CHECK(fn(NULL, (value)) == 0, #fn ": NULL handler -> 0"); \
}
AC_SETTER(set_default_session_timed_out, default_session_timed_out, 31u)
AC_SETTER(set_long_session_timed_out, long_session_timed_out, 601u)
AC_SETTER(set_short_session_timed_out, short_session_timed_out, 6u)
AC_SETTER(set_live_session_timed_out, live_session_timed_out, 3u)
AC_SETTER(set_fragment_in_packet, fragment_in_packet, 17u)
AC_SETTER(set_fragmented_packet_in_session, fragmented_packet_in_session, 18u)
AC_SETTER(set_fragment_in_session, fragment_in_session, 19u)

static void b_set_tcp_reassembly_limit(void) {
    CHECK(set_tcp_reassembly_limit(g_cfg, 4096) == 1 && g_cfg->tcp_reassembly_limit == 4096, "explicit limit");
    CHECK(set_tcp_reassembly_limit(g_cfg, 0) == 1 && g_cfg->tcp_reassembly_limit == MMT_TCP_REASSEMBLY_LIMIT_DEFAULT,
          "0 selects the default limit");
}
static void e_set_tcp_reassembly_limit(void) {
    CHECK(set_tcp_reassembly_limit(NULL, 4096) == 0, "NULL handler -> 0");
}

static void p_debug_printout(const ipacket_t *p) {
    capture_t c;
    char out[512];
    int quiet = 1;
    int ok = capture_begin(&c);
    int r = debug_extracted_attributes_printout_handler(p, &quiet);
    capture_end(&c, out, sizeof(out));
    char want[64];
    snprintf(want, sizeof(want), "Packet id: %" PRIu64 " - protocol hierarchy len: 2", p->packet_id);
    CHECK(ok && r == 0 && strstr(out, want) != NULL, "prints the packet header line and returns 0");
}
static void b_debug_extracted_attributes_printout_handler(void) {
    CHECK(run_probe(p_debug_printout), "probe ran");
}

static void b_fire_attribute_event(void) {
    mmt_handler_t *h = new_handler();
    fake_packet_t f;
    uint32_t v = 0x0BADF00Du;
    int tag;
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    register_attribute_handler(h, AC_PROTO_A, AC_ATTR_EVENT, attr_cb, NULL, &tag);
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    p->mmt_handler = h;
    g_attr_calls = 0;
    fire_attribute_event(p, AC_PROTO_A, AC_ATTR_EVENT, 1, &v);
    CHECK(g_attr_calls == 1 && g_attr_data == &v && g_attr_value == v && g_attr_user == &tag,
          "handler receives the event payload");
    mmt_close_handler(h);
}
static void e_fire_attribute_event(void) {
    mmt_handler_t *h = new_handler();
    fake_packet_t f;
    uint32_t v = 1;
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    register_attribute_handler(h, AC_PROTO_A, AC_ATTR_EVENT, attr_cb, NULL, NULL);
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    p->mmt_handler = h;
    g_attr_calls = 0;
    fire_attribute_event(p, AC_PROTO_A, AC_ATTR_U16, 1, &v);
    CHECK(g_attr_calls == 0, "unregistered attribute: documented no-op");
    mmt_close_handler(h);
}

static void b_fire_evasion_event(void) {
    mmt_handler_t *h = new_handler();
    fake_packet_t f;
    int data;
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    register_evasion_handler(h, evasion_cb, NULL);
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    p->mmt_handler = h;
    g_evasion_calls = 0;
    fire_evasion_event(p, AC_PROTO_A, 1, 7, &data);
    CHECK(g_evasion_calls == 1 && g_evasion_id == 7 && g_evasion_data == &data, "event delivered");
    mmt_close_handler(h);
}
static void e_fire_evasion_event(void) {
    mmt_handler_t *h = new_handler();
    fake_packet_t f;
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    ipacket_t *p = fake_packet(&f, 2, k_path_ma, k_off_ma);
    p->mmt_handler = h;
    g_evasion_calls = 0;
    fire_evasion_event(p, AC_PROTO_A, 1, 7, NULL);
    CHECK(g_evasion_calls == 0, "no evasion handler registered: event dropped");
    mmt_close_handler(h);
}

static void b_packet_process(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    register_packet_handler(h, 5, count_handler, NULL);
    g_count_calls = 0;
    CHECK(send_packet(h, 1, AC_SEC, 0) == 1 && g_count_calls == 1, "accepted and dispatched");
    CHECK(get_active_session_count(h) == 1, "sessionized");
    mmt_close_handler(h);
}
static void e_packet_process(void) {
    pkthdr_t hdr;
    u_char buf[AC_PKT_LEN] = { 0 };
    memset(&hdr, 0, sizeof(hdr));
    g_probe = NULL;
    CHECK(packet_process(g_h, NULL, buf) == 0, "NULL header -> 0");
    CHECK(packet_process(g_h, &hdr, NULL) == 0, "NULL data -> 0");
    hdr.caplen = 0; hdr.len = 10;
    CHECK(packet_process(g_h, &hdr, buf) == 0, "caplen 0 -> 0");
    hdr.caplen = 20; hdr.len = 10;
    CHECK(packet_process(g_h, &hdr, buf) == 0, "caplen > len -> 0");
}

static void b_mmt_print_all_protocols(void) {
    capture_t c;
    static char out[1 << 16];
    int ok = capture_begin(&c);
    AC_ALLOW_DEPRECATED_BEGIN
    mmt_print_all_protocols();
    AC_ALLOW_DEPRECATED_END
    capture_end(&c, out, sizeof(out));
    CHECK(ok && strstr(out, "MMT-SDK version: " MMT_VERSION) != NULL, "prints the SDK version");
    CHECK(strstr(out, "Proto ID: 613") != NULL && strstr(out, "Proto Name: PROTO_AC_PROTO_A") != NULL,
          "lists registered protocols");
}

static void b_process_session_timer_handler(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL && fill_sessions(h, 3), "three sessions");
    if (h == NULL) return;
    register_session_timer_handler(h, timer_cb, NULL, 0);
    g_timer_calls = 0;
    process_session_timer_handler(h);
    CHECK(g_timer_calls == 3, "timer callback ran once per live session");
    mmt_close_handler(h);
}

#define AC_TOGGLE(fn, field, value) \
static void b_##fn(void) { \
    g_cfg->field = !(value); \
    CHECK(fn(g_cfg) == 1 && g_cfg->field == (value), #fn " sets the flag"); \
} \
static void e_##fn(void) { \
    CHECK(fn(NULL) == 0, #fn ": NULL handler -> 0"); \
}
AC_TOGGLE(enable_mmt_reassembly, has_reassembly, 1)
AC_TOGGLE(disable_mmt_reassembly, has_reassembly, 0)
AC_TOGGLE(enable_port_classify, port_classify, 1)
AC_TOGGLE(disable_port_classify, port_classify, 0)
AC_TOGGLE(enable_port_classify_payload_confirm, port_classify_payload_confirm, 1)
AC_TOGGLE(disable_port_classify_payload_confirm, port_classify_payload_confirm, 0)
AC_TOGGLE(enable_hostname_classify, hostname_classify, 1)
AC_TOGGLE(disable_hostname_classify, hostname_classify, 0)
AC_TOGGLE(enable_ip_address_classify, ip_address_classify, 1)
AC_TOGGLE(disable_ip_address_classify, ip_address_classify, 0)

static void b_mmt_apply_dpi_profile(void) {
    mmt_dpi_profile_t prof = { 3, 0, 1, 0 };
    CHECK(mmt_apply_dpi_profile(g_cfg, &prof) == 1, "applied");
    CHECK(get_classification_max_depth(g_cfg) == 3 && g_cfg->hostname_classify == 0 &&
          g_cfg->port_classify == 1 && g_cfg->ip_address_classify == 0, "profile fields copied");
}
static void e_mmt_apply_dpi_profile(void) {
    mmt_dpi_profile_t prof = { 4, 1, 1, 1 };
    set_classification_max_depth(g_cfg, 9);
    CHECK(mmt_apply_dpi_profile(g_cfg, NULL) == 0 && get_classification_max_depth(g_cfg) == 9,
          "NULL profile -> 0, handler unchanged");
    CHECK(mmt_apply_dpi_profile(NULL, &prof) == 0, "NULL handler -> 0");
}

static void b_mmt_apply_dpi_profile_by_name(void) {
    CHECK(mmt_apply_dpi_profile_by_name(g_cfg, "MINIMAL") == 1, "predefined profile, case-insensitive");
    CHECK(get_classification_max_depth(g_cfg) == 3 && g_cfg->hostname_classify == 0, "minimal profile applied");
}
static void e_mmt_apply_dpi_profile_by_name(void) {
    set_classification_max_depth(g_cfg, 9);
    CHECK(mmt_apply_dpi_profile_by_name(g_cfg, "no_such_profile") == 0 && get_classification_max_depth(g_cfg) == 9,
          "unknown profile -> 0, handler unchanged");
    CHECK(mmt_apply_dpi_profile_by_name(NULL, "minimal") == 0, "NULL handler -> 0");
}

static void b_mmt_load_dpi_profiles_file(void) {
    char path[] = "./ac_profiles.XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0, "temp profiles file");
    if (fd < 0) return;
    FILE *f = fdopen(fd, "w");
    fputs("# contract test\nac_prof 4 1 0 1\nbad line\n", f);
    fclose(f);
    CHECK(mmt_load_dpi_profiles_file(path) == 1, "one valid line loaded, the malformed one skipped");
    unlink(path);
    CHECK(mmt_apply_dpi_profile_by_name(g_cfg, "ac_prof") == 1 && get_classification_max_depth(g_cfg) == 4 &&
          g_cfg->port_classify == 0, "loaded profile is applicable by name");
}
static void e_mmt_load_dpi_profiles_file(void) {
    CHECK(mmt_load_dpi_profiles_file("./no-such-dir/profiles.txt") == -1, "unopenable file -> -1");
    CHECK(mmt_load_dpi_profiles_file(NULL) == 0, "NULL path -> 0 (no-op)");
    CHECK(mmt_load_dpi_profiles_file("") == 0, "empty path -> 0 (no-op)");
}

static void b_set_classification_max_depth(void) {
    CHECK(set_classification_max_depth(g_cfg, 4) == 1 && g_cfg->classification_max_depth == 4, "stored");
    CHECK(set_classification_max_depth(g_cfg, 200) == 1 && g_cfg->classification_max_depth == PROTO_PATH_SIZE - 1,
          "clamped to PROTO_PATH_SIZE - 1");
}
static void e_set_classification_max_depth(void) {
    CHECK(set_classification_max_depth(NULL, 4) == 0, "NULL handler -> 0");
}

static void b_get_classification_max_depth(void) {
    g_cfg->classification_max_depth = 7;
    CHECK(get_classification_max_depth(g_cfg) == 7, "reports the handler bound");
}
static void e_get_classification_max_depth(void) {
    CHECK(get_classification_max_depth(NULL) == 0, "NULL handler -> 0");
}

static void b_set_session_timeout_delay(void) {
    mmt_session_t *s = fake_session();
    set_session_timeout_delay(s, 123);
    CHECK(s->session_timeout_delay == 123, "delay stored");
}

/* --- extracted-attribute getters: run inside the fixture packet --- */
static uint32_t u32_at(const void *d) { uint32_t v = 0; if (d) memcpy(&v, d, sizeof(v)); return v; }

static void p_get_attribute_extracted_data(const ipacket_t *p) {
    void *d = get_attribute_extracted_data(p, PROTO_META, META_P_LEN);
    CHECK(d != NULL && u32_at(d) == AC_PKT_LEN, "meta.packet_len is the packet length");
    CHECK(u32_at(get_attribute_extracted_data(p, AC_PROTO_A, AC_ATTR_U32)) == AC_KEY, "A's field is the key");
}
static void q_get_attribute_extracted_data(const ipacket_t *p) {
    CHECK(get_attribute_extracted_data(p, AC_PROTO_C, 1) == NULL, "protocol absent from the path -> NULL");
}
static void b_get_attribute_extracted_data(void) { CHECK(run_probe(p_get_attribute_extracted_data), "probe ran"); }
static void e_get_attribute_extracted_data(void) { CHECK(run_probe(q_get_attribute_extracted_data), "probe ran"); }

static void p_get_attribute_extracted_data_encap_index(const ipacket_t *p) {
    AC_ALLOW_DEPRECATED_BEGIN
    void *d = get_attribute_extracted_data_encap_index(p, AC_PROTO_A, AC_ATTR_U32, 0);
    AC_ALLOW_DEPRECATED_END
    CHECK(u32_at(d) == AC_KEY, "first occurrence of A");
}
static void q_get_attribute_extracted_data_encap_index(const ipacket_t *p) {
    AC_ALLOW_DEPRECATED_BEGIN
    void *d = get_attribute_extracted_data_encap_index(p, AC_PROTO_A, AC_ATTR_U32, 1);
    AC_ALLOW_DEPRECATED_END
    CHECK(d == NULL, "second occurrence of a once-encapsulated protocol -> NULL");
}
static void b_get_attribute_extracted_data_encap_index(void) {
    CHECK(run_probe(p_get_attribute_extracted_data_encap_index), "probe ran");
}
static void e_get_attribute_extracted_data_encap_index(void) {
    CHECK(run_probe(q_get_attribute_extracted_data_encap_index), "probe ran");
}

static void p_get_attribute_extracted_data_by_name(const ipacket_t *p) {
    CHECK(u32_at(get_attribute_extracted_data_by_name(p, "ac_proto_a", "ac_u32")) == AC_KEY, "by name");
}
static void q_get_attribute_extracted_data_by_name(const ipacket_t *p) {
    CHECK(get_attribute_extracted_data_by_name(p, "ac_proto_a", "no_such_attr") == NULL, "unknown attribute -> NULL");
    CHECK(get_attribute_extracted_data_by_name(p, "no_such_proto", "ac_u32") == NULL, "unknown protocol -> NULL");
}
static void b_get_attribute_extracted_data_by_name(void) { CHECK(run_probe(p_get_attribute_extracted_data_by_name), "probe ran"); }
static void e_get_attribute_extracted_data_by_name(void) { CHECK(run_probe(q_get_attribute_extracted_data_by_name), "probe ran"); }

static void p_get_attribute_extracted_data_at_index(const ipacket_t *p) {
    CHECK(u32_at(get_attribute_extracted_data_at_index(p, AC_PROTO_A, AC_ATTR_U32, 1)) == AC_KEY, "A at index 1");
}
static void q_get_attribute_extracted_data_at_index(const ipacket_t *p) {
    CHECK(get_attribute_extracted_data_at_index(p, AC_PROTO_A, AC_ATTR_U32, 0) == NULL,
          "index holding another protocol -> NULL");
    CHECK(get_attribute_extracted_data_at_index(p, AC_PROTO_A, AC_ATTR_U32, 9) == NULL, "index past the path -> NULL");
}
static void b_get_attribute_extracted_data_at_index(void) { CHECK(run_probe(p_get_attribute_extracted_data_at_index), "probe ran"); }
static void e_get_attribute_extracted_data_at_index(void) { CHECK(run_probe(q_get_attribute_extracted_data_at_index), "probe ran"); }

static void p_get_extracted_attribute(const ipacket_t *p) {
    attribute_t *a = get_extracted_attribute(p, AC_PROTO_A, AC_ATTR_U32);
    CHECK(a != NULL && a->proto_id == AC_PROTO_A && a->field_id == AC_ATTR_U32 && u32_at(a->data) == AC_KEY,
          "attribute record of A's field");
}
static void q_get_extracted_attribute(const ipacket_t *p) {
    CHECK(get_extracted_attribute(p, AC_PROTO_C, 1) == NULL, "protocol absent from the path -> NULL");
    CHECK(get_extracted_attribute(p, AC_PROTO_A, AC_ATTR_U16) == NULL, "attribute not registered -> NULL");
}
static void b_get_extracted_attribute(void) { CHECK(run_probe(p_get_extracted_attribute), "probe ran"); }
static void e_get_extracted_attribute(void) { CHECK(run_probe(q_get_extracted_attribute), "probe ran"); }

static void p_get_extracted_attribute_by_name(const ipacket_t *p) {
    attribute_t *a = get_extracted_attribute_by_name(p, "meta", "packet_len");
    CHECK(a != NULL && a->field_id == META_P_LEN && u32_at(a->data) == AC_PKT_LEN, "meta.packet_len record");
}
static void q_get_extracted_attribute_by_name(const ipacket_t *p) {
    CHECK(get_extracted_attribute_by_name(p, "no_such_proto", "packet_len") == NULL, "unknown protocol -> NULL");
    CHECK(get_extracted_attribute_by_name(p, "meta", "no_such_attr") == NULL, "unknown attribute -> NULL");
}
static void b_get_extracted_attribute_by_name(void) { CHECK(run_probe(p_get_extracted_attribute_by_name), "probe ran"); }
static void e_get_extracted_attribute_by_name(void) { CHECK(run_probe(q_get_extracted_attribute_by_name), "probe ran"); }

static void p_get_extracted_attribute_at_index(const ipacket_t *p) {
    attribute_t *a = get_extracted_attribute_at_index(p, AC_PROTO_A, AC_ATTR_U32, 1);
    CHECK(a != NULL && u32_at(a->data) == AC_KEY, "A's field at index 1");
}
static void q_get_extracted_attribute_at_index(const ipacket_t *p) {
    CHECK(get_extracted_attribute_at_index(p, AC_PROTO_A, AC_ATTR_U32, 7) == NULL, "index past the path -> NULL");
    CHECK(get_extracted_attribute_at_index(p, AC_PROTO_A, AC_ATTR_U32, 0) == NULL, "index holding meta -> NULL");
}
static void b_get_extracted_attribute_at_index(void) { CHECK(run_probe(p_get_extracted_attribute_at_index), "probe ran"); }
static void e_get_extracted_attribute_at_index(void) { CHECK(run_probe(q_get_extracted_attribute_at_index), "probe ran"); }

static void p_get_extracted_attribute_at_index_by_name(const ipacket_t *p) {
    attribute_t *a = get_extracted_attribute_at_index_by_name(p, "ac_proto_a", "ac_u32", 1);
    CHECK(a != NULL && u32_at(a->data) == AC_KEY, "A's field at index 1 by name");
}
static void q_get_extracted_attribute_at_index_by_name(const ipacket_t *p) {
    CHECK(get_extracted_attribute_at_index_by_name(p, "ac_proto_a", "ac_u32", 9) == NULL, "index past the path -> NULL");
    CHECK(get_extracted_attribute_at_index_by_name(p, "ac_proto_a", "no_such_attr", 1) == NULL, "unknown attribute -> NULL");
}
static void b_get_extracted_attribute_at_index_by_name(void) {
    CHECK(run_probe(p_get_extracted_attribute_at_index_by_name), "probe ran");
}
static void e_get_extracted_attribute_at_index_by_name(void) {
    CHECK(run_probe(q_get_extracted_attribute_at_index_by_name), "probe ran");
}

/* --- statistics (the fixture handler has processed several packets) --- */

/* Issue #546: the per-direction counters are written. A session-bearing
 * layer splits its totals by the session's setup direction ([0] = uplink);
 * meta, crossed before the session exists, counts the totals only. */
static void protocol_stats_direction(void) {
    mmt_handler_t *h = new_handler();
    CHECK(h != NULL, "handler");
    if (h == NULL) return;
    send_packet_dir(h, 0xD1D1D1D1u, AC_SEC, 0, 0);      /* setup: uplink */
    send_packet_dir(h, 0xD1D1D1D1u, AC_SEC, 1, 1);      /* reply: downlink */
    send_packet_dir(h, 0xD1D1D1D1u, AC_SEC, 2, 1);      /* reply: downlink */
    send_packet_dir(h, 0xD2D2D2D2u, AC_SEC, 3, 1);      /* a reply-marked first packet sets the setup direction */
    proto_statistics_t *meta = get_protocol_stats(h, PROTO_META);
    proto_statistics_t *a = get_protocol_stats(h, AC_PROTO_A);
    CHECK(meta != NULL && a != NULL && a->packets_count == 4, "four packets on A");
    if (meta == NULL || a == NULL) { mmt_close_handler(h); return; }
    CHECK(a->packets_count_direction[0] == 2 && a->packets_count_direction[1] == 2,
          "A: two uplink, two downlink packets");
    CHECK(a->data_volume_direction[0] == 2 * AC_PKT_LEN && a->data_volume_direction[1] == 2 * AC_PKT_LEN
          && a->data_volume_direction[0] + a->data_volume_direction[1] == a->data_volume,
          "A: data volume split by direction");
    CHECK(a->payload_volume_direction[0] + a->payload_volume_direction[1] == a->payload_volume
          && a->payload_volume_direction[1] > 0, "A: payload volume split by direction");
    CHECK(meta->packets_count == 4 && meta->packets_count_direction[0] == 0
          && meta->packets_count_direction[1] == 0 && meta->data_volume_direction[0] == 0,
          "meta has no session: totals only");
    proto_statistics_t kids;
    memset(&kids, 0xff, sizeof(kids));
    get_children_stats(meta, &kids);
    CHECK(kids.packets_count_direction[0] == 2 && kids.packets_count_direction[1] == 2
          && kids.payload_volume_direction[1] == a->payload_volume_direction[1],
          "children stats carry the direction split");
    mmt_close_handler(h);
}
static void b_get_protocol_stats(void) {
    proto_statistics_t *meta = get_protocol_stats(g_h, PROTO_META);
    proto_statistics_t *a = get_protocol_stats(g_h, AC_PROTO_A);
    CHECK(meta != NULL && meta->packets_count >= 1, "meta statistics count the fixture packets");
    CHECK(a != NULL && a->packets_count == meta->packets_count, "A sees every packet meta sees");
    protocol_stats_direction();
}
static void e_get_protocol_stats(void) {
    CHECK(get_protocol_stats(NULL, PROTO_META) == NULL, "NULL handler -> NULL");
    CHECK(get_protocol_stats(g_h, PROTO_MAX_IDENTIFIER) == NULL, "invalid protocol id -> NULL");
}

static void b_get_children_stats(void) {
    proto_statistics_t *meta = get_protocol_stats(g_h, PROTO_META);
    proto_statistics_t *a = get_protocol_stats(g_h, AC_PROTO_A);
    proto_statistics_t kids;
    memset(&kids, 0xff, sizeof(kids));
    CHECK(meta != NULL && a != NULL, "statistics instances");
    if (meta == NULL || a == NULL) return;
    get_children_stats(meta, &kids);
    CHECK(kids.packets_count == a->packets_count && kids.data_volume == a->data_volume,
          "children of meta sum to A's counters");
}

static void b_get_protocol_stats_path(void) {
    proto_statistics_t *a = get_protocol_stats(g_h, AC_PROTO_A);
    proto_hierarchy_t path;
    memset(&path, 0, sizeof(path));
    get_protocol_stats_path(g_h, a, &path);
    CHECK(path.len == 2 && path.proto_path[0] == PROTO_META && path.proto_path[1] == AC_PROTO_A,
          "path of A's statistics is meta.ac_proto_a");
}
static void e_get_protocol_stats_path(void) {
    proto_hierarchy_t path;
    path.len = 5;
    get_protocol_stats_path(g_h, NULL, &path);
    CHECK(path.len == 0, "NULL statistics -> empty path");
    path.len = 5;
    get_protocol_stats_path(NULL, get_protocol_stats(g_h, PROTO_META), &path);
    CHECK(path.len == 0, "NULL handler -> empty path");
}

static void b_reset_statistics(void) {
    proto_statistics_t st;
    memset(&st, 0, sizeof(st));
    st.touched = 1; st.packets_count = 5; st.data_volume = 6; st.payload_volume = 7;
    st.packets_count_direction[1] = 8; st.sessions_count = 9;
    reset_statistics(&st);
    CHECK(st.touched == 0 && st.packets_count == 0 && st.data_volume == 0 && st.payload_volume == 0 &&
          st.packets_count_direction[1] == 0, "traffic counters zeroed");
    CHECK(st.sessions_count == 9, "session count kept");
}

static void b_setDataLinkType(void) {
    AC_ALLOW_DEPRECATED_BEGIN
    setDataLinkType(g_cfg, AC_STACK_ID);
    AC_ALLOW_DEPRECATED_END
    CHECK(get_data_link_type(g_cfg) == AC_STACK_ID, "handler moved to the registered stack");
}
static void e_setDataLinkType(void) {
    AC_ALLOW_DEPRECATED_BEGIN
    setDataLinkType(g_cfg, 4242);
    int dlt = get_data_link_type(g_cfg);
    setDataLinkType(g_cfg, AC_STACK_ID);
    AC_ALLOW_DEPRECATED_END
    CHECK(dlt == 0, "unknown stack -> the dummy stack (id 0)");
}

static void b_get_data_link_type(void) {
    CHECK(get_data_link_type(g_h) == AC_STACK_ID, "fixture stack");
}
static void e_get_data_link_type(void) {
    CHECK(get_data_link_type(NULL) == -1, "NULL handler -> -1");
}

static void b_enable_protocol_statistics(void) {
    g_cfg->stats_reporting_status = 0;
    enable_protocol_statistics(g_cfg);
    CHECK(g_cfg->stats_reporting_status == 1, "reporting on");
}
static void e_enable_protocol_statistics(void) {
    g_cfg->stats_reporting_status = 0;
    enable_protocol_statistics(NULL);
    CHECK(g_cfg->stats_reporting_status == 0, "NULL handler: no effect");
}
static void b_disable_protocol_statistics(void) {
    g_cfg->stats_reporting_status = 1;
    disable_protocol_statistics(g_cfg);
    CHECK(g_cfg->stats_reporting_status == 0, "reporting off");
}
static void e_disable_protocol_statistics(void) {
    g_cfg->stats_reporting_status = 1;
    disable_protocol_statistics(NULL);
    CHECK(g_cfg->stats_reporting_status == 1, "NULL handler: no effect");
}

/* The analysis/classification switch lives on the handler's own protocol
 * snapshot (issue #549); each contract restores what it flips. */
#define AC_STATUS(enable, disable, member) \
static void b_##enable(void) { \
    int *st = &g_cfg->configured_protocols[AC_PROTO_C].member; \
    *st = 0; enable(g_cfg, AC_PROTO_C); \
    CHECK(*st == 1, #enable " sets the status"); \
} \
static void e_##enable(void) { \
    int *st = &g_cfg->configured_protocols[AC_PROTO_C].member; \
    *st = 0; enable(g_cfg, PROTO_MAX_IDENTIFIER); enable(NULL, AC_PROTO_C); \
    CHECK(*st == 0, #enable ": invalid id or NULL handler, no effect"); \
} \
static void b_##disable(void) { \
    int *st = &g_cfg->configured_protocols[AC_PROTO_C].member; \
    *st = 1; disable(g_cfg, AC_PROTO_C); \
    CHECK(*st == 0, #disable " clears the status"); \
} \
static void e_##disable(void) { \
    int *st = &g_cfg->configured_protocols[AC_PROTO_C].member; \
    *st = 1; disable(g_cfg, PROTO_MAX_IDENTIFIER); disable(NULL, AC_PROTO_C); \
    CHECK(*st == 1, #disable ": invalid id or NULL handler, no effect"); \
}
AC_STATUS(enable_protocol_analysis, disable_protocol_analysis, analysis_enabled)
AC_STATUS(enable_protocol_classification, disable_protocol_classification, classify_enabled)

static void b_is_valid_protocol_id(void) {
    CHECK(is_valid_protocol_id(0) && is_valid_protocol_id(PROTO_MAX_IDENTIFIER - 1), "range bounds");
}
static void e_is_valid_protocol_id(void) {
    CHECK(!is_valid_protocol_id(PROTO_MAX_IDENTIFIER), "PROTO_MAX_IDENTIFIER is invalid");
}

static void b_is_registered_protocol(void) {
    CHECK(is_registered_protocol(PROTO_META) && is_registered_protocol(AC_PROTO_A), "registered protocols");
}
static void e_is_registered_protocol(void) {
    CHECK(!is_registered_protocol(AC_UNREG_ID), "never registered -> 0");
    CHECK(!is_registered_protocol(PROTO_MAX_IDENTIFIER), "invalid id -> 0");
}

static int g_attr_iter_calls;
static int g_attr_iter_seen_u16;
static void attr_iter(attribute_metadata_t *attr, mmt_proto_id_t proto_id, void *args) {
    (void) args;
    g_attr_iter_calls++;
    if (proto_id == AC_PROTO_A && attr->id == AC_ATTR_U16 && strcmp(attr->alias, "ac_u16") == 0)
        g_attr_iter_seen_u16++;
}
static void b_iterate_through_protocol_attributes(void) {
    g_attr_iter_calls = g_attr_iter_seen_u16 = 0;
    iterate_through_protocol_attributes(AC_PROTO_A, attr_iter, NULL);
    CHECK(g_attr_iter_seen_u16 == 1 && g_attr_iter_calls >= 3, "every attribute of A visited once");
}
static void e_iterate_through_protocol_attributes(void) {
    g_attr_iter_calls = 0;
    iterate_through_protocol_attributes(AC_UNREG_ID, attr_iter, NULL);
    CHECK(g_attr_iter_calls == 0, "unregistered protocol: callback never runs");
}

static int g_proto_iter_meta, g_proto_iter_a, g_proto_iter_unreg;
static void proto_iter(mmt_proto_id_t id, void *args) {
    (void) args;
    if (id == PROTO_META) g_proto_iter_meta++;
    if (id == AC_PROTO_A) g_proto_iter_a++;
    if (id == AC_UNREG_ID) g_proto_iter_unreg++;
}
static void b_iterate_through_protocols(void) {
    g_proto_iter_meta = g_proto_iter_a = g_proto_iter_unreg = 0;
    iterate_through_protocols(proto_iter, NULL);
    CHECK(g_proto_iter_meta == 1 && g_proto_iter_a == 1 && g_proto_iter_unreg == 0,
          "each registered protocol once, unregistered ones never");
}

static void b_iterate_through_mmt_handlers(void) {
    g_handler_seen = 0;
    iterate_through_mmt_handlers(count_handler_iter, g_h);
    CHECK(g_handler_seen == 1, "fixture handler visited once");
}

static void b_mmt_version(void) {
    const char *v = mmt_version();
    CHECK(v != NULL && strcmp(v, MMT_VERSION) == 0, "MMT_VERSION string");
}

static void b_mmt_malloc(void) {
    unsigned char *p = (unsigned char *) mmt_malloc(64);
    CHECK(p != NULL, "64-byte block");
    if (p == NULL) return;
    memset(p, 0x5a, 64);
    CHECK(p[0] == 0x5a && p[63] == 0x5a, "block is writable end to end");
    mmt_free(p);
}
static void e_mmt_malloc(void) {
    void *p = mmt_malloc(0);
    CHECK(p != NULL, "size 0 is promoted to a 1-byte block, never NULL");
    mmt_free(p);
}

static void b_mmt_realloc(void) {
    char *p = (char *) mmt_malloc(8);
    CHECK(p != NULL, "block");
    if (p == NULL) return;
    memcpy(p, "abcdefg", 8);
    char *q = (char *) mmt_realloc(p, 4096);
    CHECK(q != NULL && strcmp(q, "abcdefg") == 0, "grown block keeps its content");
    q = (char *) mmt_realloc(q, 2);
    CHECK(q != NULL && q[0] == 'a' && q[1] == 'b', "shrunk block keeps its prefix");
    char *r = (char *) mmt_realloc(NULL, 16);
    CHECK(r != NULL, "NULL block: behaves as mmt_malloc");
    mmt_free(q);
    mmt_free(r);
}
static void e_mmt_realloc(void) {
    void *p = mmt_malloc(16);
    CHECK(mmt_realloc(NULL, 0) == NULL, "NULL block, size 0 -> NULL");
    CHECK(mmt_realloc(p, 0) == NULL, "size 0 frees the block -> NULL");
}

#define AC_BIG (1u << 20)
static void b_mmt_free(void) {
    void *p = mmt_malloc(AC_BIG);
    CHECK(p != NULL, "1 MiB block");
    if (p == NULL) return;
    memset(p, 1, AC_BIG);
    size_t before = heap_in_use();
    mmt_free(p);
    size_t after = heap_in_use();
    CHECK(before >= after + AC_BIG, "the block is returned to the allocator");
}
static void e_mmt_free(void) {
    size_t before = heap_in_use();
    mmt_free(NULL);
    CHECK(heap_in_use() == before, "NULL: no-op");
}

static void b_mmt_arena_create(void) {
    mmt_arena_t *a = mmt_arena_create(1000);
    CHECK(a != NULL, "arena");
    if (a == NULL) return;
    void *p = mmt_arena_alloc(a, 24);
    CHECK(p != NULL && ((uintptr_t) p % 16) == 0, "first slot is 16-byte aligned");
    mmt_arena_destroy(a);
    a = mmt_arena_create(0);
    CHECK(a != NULL && mmt_arena_alloc(a, 32) != NULL, "block size 0 selects the default block");
    mmt_arena_destroy(a);
}
static void e_mmt_arena_create(void) {
    CHECK(mmt_arena_create(SIZE_MAX) == NULL, "block size overflow -> NULL");
}

static void b_mmt_arena_alloc(void) {
    mmt_arena_t *a = mmt_arena_create(256);
    CHECK(a != NULL, "arena");
    if (a == NULL) return;
    unsigned char *p = (unsigned char *) mmt_arena_alloc(a, 40);
    unsigned char *q = (unsigned char *) mmt_arena_alloc(a, 40);
    CHECK(p != NULL && q != NULL && (q >= p + 40 || p >= q + 40), "disjoint slots");
    void *big = mmt_arena_alloc(a, 4096);
    CHECK(big != NULL && ((uintptr_t) big % 16) == 0, "oversized request gets its own aligned block");
    mmt_arena_destroy(a);
}
static void e_mmt_arena_alloc(void) {
    mmt_arena_t *a = mmt_arena_create(256);
    CHECK(mmt_arena_alloc(NULL, 16) == NULL, "NULL arena -> NULL");
    CHECK(a != NULL && mmt_arena_alloc(a, SIZE_MAX - 8) == NULL, "size overflow -> NULL");
    mmt_arena_destroy(a);
}

static void b_mmt_arena_reset(void) {
    mmt_arena_t *a = mmt_arena_create(128);
    CHECK(a != NULL, "arena");
    if (a == NULL) return;
    (void) mmt_arena_alloc(a, 100);          /* block 1 */
    void *head = mmt_arena_alloc(a, 100);    /* does not fit: block 2 becomes the head */
    mmt_arena_reset(a);
    CHECK(mmt_arena_alloc(a, 16) == head, "rewound: the kept head block is reused from its start");
    mmt_arena_destroy(a);
}
static void e_mmt_arena_reset(void) {
    size_t before = heap_in_use();
    mmt_arena_reset(NULL);
    CHECK(heap_in_use() == before, "NULL arena: no-op");
}

static void b_mmt_arena_destroy(void) {
    mmt_arena_t *a = mmt_arena_create(AC_BIG);
    CHECK(a != NULL && mmt_arena_alloc(a, 64) != NULL, "arena with a 1 MiB block");
    if (a == NULL) return;
    size_t before = heap_in_use();
    mmt_arena_destroy(a);
    CHECK(before >= heap_in_use() + AC_BIG, "every block released");
}
static void e_mmt_arena_destroy(void) {
    size_t before = heap_in_use();
    mmt_arena_destroy(NULL);
    CHECK(heap_in_use() == before, "NULL arena: no-op");
}

static void b_mmt_print_info(void) {
    capture_t c;
    char out[512];
    int ok = capture_begin(&c);
    mmt_print_info();
    capture_end(&c, out, sizeof(out));
    CHECK(ok && strcmp(out, MMT_PRINT_INFO) == 0, "prints the MMT_PRINT_INFO banner");
}

/* ======================================================================== */
/*                                mmt_utils.h                               */
/* ======================================================================== */

/* Issue #533: the string/hex utilities became MMTAPI (they were exported
 * through default visibility before the core was built hidden). Their
 * results are malloc()ed, so the caller releases them with free(). */

static void b_hex2int(void) {
    CHECK(hex2int('A') == 65 && hex2int((char) 0xff) == 255, "byte value 0..255");
}
static void b_str_hex2int(void) {
    char h[] = "\x01\x02\x03";
    AC_ALLOW_DEPRECATED_BEGIN
    CHECK(str_hex2int(h, 0, 1) == 0x0102, "big-endian bytes [0,1]");
    AC_ALLOW_DEPRECATED_END
}
static void e_str_hex2int(void) {
    char h[] = "\x01\x02";
    AC_ALLOW_DEPRECATED_BEGIN
    CHECK(str_hex2int(NULL, 0, 1) == -1, "NULL -> -1");
    CHECK(str_hex2int(h, 1, 0) == -1, "end < start -> -1");
    AC_ALLOW_DEPRECATED_END
}
static void b_str_hex2int_n(void) {
    char h[3] = { 0x01, 0x02, 0x03 }; /* not NUL-terminated */
    CHECK(str_hex2int_n(h, sizeof(h), 1, 2) == 0x0203, "big-endian bytes [1,2]");
}
static void e_str_hex2int_n(void) {
    char h[2] = { 0x01, 0x02 };
    CHECK(str_hex2int_n(h, sizeof(h), 0, 2) == -1, "end index past the buffer -> -1");
    CHECK(str_hex2int_n(NULL, 2, 0, 1) == -1, "NULL -> -1");
}
static void b_str_hex2str(void) {
    char h[] = "ab\x01" "c"; /* the split ends the \x escape */
    char *r = str_hex2str(h, 0, 3);
    CHECK(r != NULL && strcmp(r, "abc") == 0, "keeps the printable bytes");
    free(r);
}
static void e_str_hex2str(void) {
    char h[] = "abc";
    CHECK(str_hex2str(NULL, 0, 1) == NULL, "NULL -> NULL");
    CHECK(str_hex2str(h, 0, 3) == NULL, "end index past the string -> NULL");
}
static void b_hex2dec(void) {
    CHECK(hex2dec("ff") == 255 && hex2dec("000") == 0, "hex digits -> value");
}
static void e_hex2dec(void) {
    CHECK(hex2dec("fg") == (unsigned long) -1, "non-hex digit -> (unsigned long)-1");
    CHECK(hex2dec("fg") == MMT_HEX2DEC_ERROR && MMT_HEX2DEC_ERROR == (unsigned long) -1,
          "non-hex digit -> MMT_HEX2DEC_ERROR (#546)");
}
static void b_char2int(void) {
    CHECK(char2int('7') == 7 && char2int('a') == 10 && char2int('F') == 15, "hex digit -> 0..15");
}
static void e_char2int(void) {
    CHECK(char2int('g') == -1, "non-hex character -> -1");
}
static void b_hex2char(void) {
    CHECK(hex2char('4', '1') == 'A', "two hex digits -> one character");
}
static void e_hex2char(void) {
    CHECK(hex2char('z', '1') == '\0', "non-hex digit -> NUL");
}
static void b_hex2str(void) {
    char h[] = "41420a43";
    char *r = hex2str(h);
    CHECK(r != NULL && strcmp(r, "ABC") == 0, "hex pairs -> printable characters");
    free(r);
}
static void e_hex2str(void) {
    char h[] = "414";
    CHECK(hex2str(h) == NULL, "odd length -> NULL");
    CHECK(hex2str(NULL) == NULL, "NULL -> NULL");
}
static void b_str_compare(void) {
    char a[] = "mmt", b[] = "mmt", c[] = "dpi";
    CHECK(str_compare(a, b) == 1 && str_compare(a, c) == 0, "string equality");
    CHECK(str_compare(NULL, NULL) == 1 && str_compare(a, NULL) == 0, "NULL compares equal only to NULL");
}
static void b_str_index(void) {
    char s[] = "mmt-dpi", sub[] = "dpi";
    CHECK(str_index(s, sub) == 4, "index of the first occurrence");
}
static void e_str_index(void) {
    char s[] = "mmt-dpi", sub[] = "sdk";
    CHECK(str_index(s, sub) == -1, "absent substring -> -1");
    CHECK(str_index(NULL, sub) == -1, "NULL -> -1");
}
static void b_str_sub(void) {
    char s[] = "mmt-dpi";
    AC_ALLOW_DEPRECATED_BEGIN
    char *r = str_sub(s, 4, 6);
    AC_ALLOW_DEPRECATED_END
    CHECK(r != NULL && strcmp(r, "dpi") == 0, "inclusive [4,6]");
    free(r);
}
static void e_str_sub(void) {
    char s[] = "mmt";
    AC_ALLOW_DEPRECATED_BEGIN
    CHECK(str_sub(s, 2, 1) == NULL, "start > end -> NULL");
    CHECK(str_sub(s, 0, 3) == NULL, "end index past the string -> NULL");
    AC_ALLOW_DEPRECATED_END
}
static void b_str_sub_n(void) {
    char s[7] = { 'm', 'm', 't', '-', 'd', 'p', 'i' }; /* not NUL-terminated */
    char *r = str_sub_n(s, sizeof(s), 4, 6);
    CHECK(r != NULL && strcmp(r, "dpi") == 0, "inclusive [4,6] of a bounded buffer");
    free(r);
}
static void e_str_sub_n(void) {
    char s[3] = { 'm', 'm', 't' };
    CHECK(str_sub_n(s, sizeof(s), 0, 3) == NULL, "end index past the buffer -> NULL");
    CHECK(str_sub_n(NULL, 3, 0, 1) == NULL, "NULL -> NULL");
}
static void b_str_combine(void) {
    char a[] = "mmt-", b[] = "dpi";
    char *r = str_combine(a, b);
    CHECK(r != NULL && strcmp(r, "mmt-dpi") == 0, "concatenation");
    free(r);
    r = str_combine(NULL, b);
    CHECK(r != NULL && strcmp(r, "dpi") == 0, "NULL first operand -> copy of the second");
    free(r);
}
static void e_str_combine(void) {
    CHECK(str_combine(NULL, NULL) == NULL, "both NULL -> NULL");
}
static void b_str_get_indexes(void) {
    char s[] = "a,b,c", sep[] = ",";
    AC_ALLOW_DEPRECATED_BEGIN
    int *r = str_get_indexes(s, sep);
    AC_ALLOW_DEPRECATED_END
    CHECK(r != NULL && r[0] == 1 && r[1] == 3 && r[2] == -1, "indexes terminated by -1");
    free(r);
}
static void e_str_get_indexes(void) {
    char s[] = "abc", sep[] = ",";
    AC_ALLOW_DEPRECATED_BEGIN
    CHECK(str_get_indexes(s, sep) == NULL, "absent needle -> NULL");
    CHECK(str_get_indexes(NULL, sep) == NULL, "NULL -> NULL");
    AC_ALLOW_DEPRECATED_END
}
static void b_str_get_indexes_n(void) {
    char s[5] = { 'a', ',', 'b', ',', 'c' }; /* not NUL-terminated */
    char sep[1] = { ',' };
    int *r = str_get_indexes_n(s, sizeof(s), sep, sizeof(sep));
    CHECK(r != NULL && r[0] == 1 && r[1] == 3 && r[2] == -1, "indexes terminated by -1");
    free(r);
}
static void e_str_get_indexes_n(void) {
    char s[3] = { 'a', ',', 'b' };
    char sep[1] = { ',' };
    CHECK(str_get_indexes_n(s, sizeof(s), sep, 0) == NULL, "empty needle -> NULL");
    CHECK(str_get_indexes_n(s, 1, s, sizeof(s)) == NULL, "needle longer than the haystack -> NULL");
}
static void b_str_replace(void) {
    char s[] = "a,b,c", from[] = ",", to[] = "--";
    char *r = str_replace(s, from, to);
    CHECK(r != NULL && strcmp(r, "a--b--c") == 0, "every occurrence replaced");
    free(r);
}
static void e_str_replace(void) {
    char from[] = ",", to[] = "-";
    CHECK(str_replace(NULL, from, to) == NULL, "NULL string -> NULL");
}
static void b_str_subvalue(void) {
    char s[] = "key=[value];", begin[] = "[", end[] = "]";
    char *r = str_subvalue(s, begin, end);
    CHECK(r != NULL && strcmp(r, "value") == 0, "text between the delimiters");
    free(r);
}
static void e_str_subvalue(void) {
    char s[] = "key=value", begin[] = "[", end[] = "]";
    CHECK(str_subvalue(s, NULL, NULL) == NULL, "both delimiters NULL -> NULL");
    CHECK(str_subvalue(s, begin, end) == NULL, "absent delimiters -> NULL");
}
static void b_str_copy(void) {
    char s[] = "mmt";
    char *r = str_copy(s);
    CHECK(r != NULL && r != s && strcmp(r, s) == 0, "fresh copy");
    free(r);
}
static void e_str_copy(void) {
    CHECK(str_copy(NULL) == NULL, "NULL -> NULL");
}
static void b_str_print_array(void) {
    char a0[] = "mmt", a1[] = "dpi";
    char *arr[] = { a0, a1, NULL };
    capture_t c;
    char out[128];
    int ok = capture_begin(&c);
    str_print_array(arr);
    capture_end(&c, out, sizeof(out));
    CHECK(ok && strcmp(out, "Array[0]: mmt\nArray[1]: dpi\n") == 0, "one line per element up to NULL");
}

/* ======================================================================== */
/*                               plugin_defs.h                              */
/* ======================================================================== */

static void p_mmt_packet_scratch_adopt(const ipacket_t *p) {
    void *v = mmt_malloc(32);
    CHECK(mmt_packet_scratch_adopt(p, v, release_cb) == true, "handler adopts the value");
    CHECK(g_release_calls == 0, "value alive while the packet is processed");
}
static void b_mmt_packet_scratch_adopt(void) {
    g_release_calls = 0;
    CHECK(run_probe(p_mmt_packet_scratch_adopt), "probe ran");
    CHECK(send_packet(g_h, AC_KEY, AC_SEC, AC_USEC) == 1 && g_release_calls == 1,
          "released once when the next packet starts");
}
static void e_mmt_packet_scratch_adopt(void) {
    g_release_calls = 0;
    CHECK(mmt_packet_scratch_adopt(NULL, mmt_malloc(8), release_cb) == false && g_release_calls == 1,
          "no packet/handler -> false, value released immediately (documented)");
    CHECK(mmt_packet_scratch_adopt(NULL, NULL, release_cb) == false && g_release_calls == 1,
          "NULL value -> false, nothing released");
}

static void b_set_classified_proto(void) {
    static const uint32_t ids[] = { PROTO_META };
    static const int offs[] = { 0 };
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 1, ids, offs);
    classified_proto_t c = { 14, Classified, AC_PROTO_A };
    CHECK(set_classified_proto(p, 1, c) == PROTO_CLASSIFICATION_DETECTION, "append reports a detection");
    CHECK(p->proto_hierarchy->len == 2 && p->proto_hierarchy->proto_path[1] == AC_PROTO_A &&
          get_packet_offset_at_index(p, 1) == 14, "layer appended with its offset");
}
static void e_set_classified_proto(void) {
    static const uint32_t ids[] = { PROTO_META };
    static const int offs[] = { 0 };
    fake_packet_t f;
    ipacket_t *p = fake_packet(&f, 1, ids, offs);
    classified_proto_t bad = { 0, Classified, PROTO_MAX_IDENTIFIER };
    classified_proto_t ok = { 0, Classified, AC_PROTO_A };
    CHECK(set_classified_proto(p, 1, bad) == 0 && p->proto_hierarchy->len == 1, "invalid protocol id -> 0, path unchanged");
    CHECK(set_classified_proto(p, PROTO_PATH_SIZE, ok) == 0 && p->proto_hierarchy->len == 1,
          "index past PROTO_PATH_SIZE -> 0, path unchanged");
}

static void b_register_classification_function_with_parent_protocol(void) {
    CHECK(register_classification_function_with_parent_protocol(AC_PROTO_C, cls1, 30) == 1, "registered");
    mmt_classify_proto_t *n = classify_node(g_pc, cls1);
    CHECK(n != NULL && n->weight == 30, "chained on the parent with its weight");
}
static void e_register_classification_function_with_parent_protocol(void) {
    CHECK(register_classification_function_with_parent_protocol(AC_PROTO_C, NULL, 30) == 0, "NULL callback -> 0");
    CHECK(register_classification_function_with_parent_protocol(AC_UNREG_ID, cls2, 30) == 0, "unregistered parent -> 0");
    CHECK(classify_node(g_pc, NULL) == NULL, "nothing chained");
}

static void b_register_classification_function(void) {
    CHECK(register_classification_function(g_pc, cls3) == 1, "registered");
    mmt_classify_proto_t *n = classify_node(g_pc, cls3);
    CHECK(n != NULL && n->weight == 50, "chained with the default weight");
}
static void e_register_classification_function(void) {
    CHECK(register_classification_function(g_pc, NULL) == 0 && classify_node(g_pc, NULL) == NULL,
          "NULL callback -> 0, nothing chained");
}

static void b_register_classification_function_full(void) {
    CHECK(register_classification_function_full(g_pc, cls4, 40, cls5, cls6) == 1, "registered");
    mmt_classify_proto_t *n = classify_node(g_pc, cls4);
    CHECK(n != NULL && n->weight == 40, "chained with its weight");
    CHECK(g_pc->classify_next.pre_classify == cls5 && g_pc->classify_next.post_classify == cls6, "pre/post set");
}
static void e_register_classification_function_full(void) {
    CHECK(register_classification_function_full(g_pc, cls7, 500, NULL, NULL) == 1, "registered");
    mmt_classify_proto_t *n = classify_node(g_pc, cls7);
    CHECK(n != NULL && n->weight == 90, "out-of-range weight clamped to 90");
}

static void b_register_pre_post_classification_functions(void) {
    CHECK(register_pre_post_classification_functions(g_pc, cls1, cls2) == 1, "always succeeds");
    CHECK(g_pc->classify_next.pre_classify == cls1 && g_pc->classify_next.post_classify == cls2, "both stored");
}

static void b_register_sessionizer_function(void) {
    protocol_t *p = init_protocol_struct_for_registration(AC_FREE_ID + 1, "ac_proto_sess");
    CHECK(p != NULL, "scratch protocol struct");
    if (p == NULL) return;
    register_sessionizer_function(p, ac_sessionize, ac_session_ctx_cleanup, ac_key_comp);
    CHECK(p->sessionize == ac_sessionize && p->session_context_cleanup == ac_session_ctx_cleanup &&
          p->session_key_compare == ac_key_comp && p->has_session == HAS_SESSION_CONTEXT,
          "sessionizer wired and the protocol marked session-bearing");
}

static void b_register_session_hash_function(void) {
    register_session_hash_function(g_pc, ac_key_hash);
    CHECK(g_pc->session_key_hash == ac_key_hash, "hash stored");
}
static void b_register_session_equal_function(void) {
    register_session_equal_function(g_pc, ac_key_comp);
    CHECK(g_pc->session_key_equal == ac_key_comp, "equality stored");
}

static void *ctx_init(void *c, void *a) { (void) a; return c; }
static void ctx_cleanup(void *c, void *a) { (void) c; (void) a; }
static void b_register_proto_context_init_cleanup_function(void) {
    int tag;
    register_proto_context_init_cleanup_function(g_pc, ctx_init, ctx_cleanup, &tag);
    CHECK(g_pc->protocol_context_init == ctx_init && g_pc->protocol_context_cleanup == ctx_cleanup &&
          g_pc->protocol_context_args == &tag, "init/cleanup and argument stored");
    register_proto_context_init_cleanup_function(g_pc, NULL, NULL, NULL);
}

static void sd_init(ipacket_t *p, unsigned i) { (void) p; (void) i; }
static void sd_cleanup(mmt_session_t *s, unsigned i) { (void) s; (void) i; }
static void b_register_session_data_initialization_function(void) {
    register_session_data_initialization_function(g_pc, sd_init);
    CHECK(g_pc->session_data_init == sd_init, "stored");
}
static void b_register_session_data_cleanup_function(void) {
    register_session_data_cleanup_function(g_pc, sd_cleanup);
    CHECK(g_pc->session_data_cleanup == sd_cleanup, "stored");
}

static void b_register_session_data_analysis_function_with_protocol(void) {
    CHECK(register_session_data_analysis_function_with_protocol(AC_PROTO_C, cls1, 95) == 1, "registered");
    mmt_analyse_me_t *n = analyse_node(g_pc, cls1);
    CHECK(n != NULL && n->weight == 95, "chained with its weight");
    CHECK(register_session_data_analysis_function_with_protocol(AC_PROTO_C, cls2, 50) == 1 &&
          analyse_node(g_pc, cls2) != NULL && analyse_node(g_pc, cls2)->weight == 90,
          "mid-range weights map to 90");
}
static void e_register_session_data_analysis_function_with_protocol(void) {
    CHECK(register_session_data_analysis_function_with_protocol(AC_PROTO_C, NULL, 50) == 0, "NULL callback -> 0");
    CHECK(register_session_data_analysis_function_with_protocol(AC_UNREG_ID, cls3, 50) == 0, "unregistered protocol -> 0");
}

static void b_register_session_data_analysis_function(void) {
    CHECK(register_session_data_analysis_function(g_pc, cls4) == 1, "registered");
    mmt_analyse_me_t *n = analyse_node(g_pc, cls4);
    CHECK(n != NULL && n->weight == 50, "chained with the default weight");
}
static void e_register_session_data_analysis_function(void) {
    CHECK(register_session_data_analysis_function(g_pc, NULL) == 0 && analyse_node(g_pc, NULL) == NULL,
          "NULL callback -> 0, nothing chained");
}

static void b_register_session_data_analysis_function_full(void) {
    CHECK(register_session_data_analysis_function_full(g_pc, cls5, 40, cls6, cls7) == 1, "registered");
    mmt_analyse_me_t *n = analyse_node(g_pc, cls5);
    CHECK(n != NULL && n->weight == 40, "chained with its weight");
    CHECK(g_pc->data_analyser.pre_analyse == cls6 && g_pc->data_analyser.post_analyse == cls7, "pre/post set");
}
static void e_register_session_data_analysis_function_full(void) {
    CHECK(register_session_data_analysis_function_full(g_pc, cls3, -5, NULL, NULL) == 1, "registered");
    mmt_analyse_me_t *n = analyse_node(g_pc, cls3);
    CHECK(n != NULL && n->weight == 10, "out-of-range weight clamped to 10");
}

static void b_register_pre_post_analysis_functions(void) {
    CHECK(register_pre_post_analysis_functions(g_pc, cls2, cls3) == 1, "always succeeds");
    CHECK(g_pc->data_analyser.pre_analyse == cls2 && g_pc->data_analyser.post_analyse == cls3, "both stored");
}

static void b_register_protocol_stack(void) {
    CHECK(register_protocol_stack(AC_STACK_AUX, (char *) "ac_aux", ac_stack_classify) == 1, "registered");
    const char *n = get_protocol_stack_name(AC_STACK_AUX);
    CHECK(n != NULL && strcmp(n, "ac_aux") == 0, "named");
    unregister_protocol_stack(AC_STACK_AUX);
}
static void e_register_protocol_stack(void) {
    CHECK(register_protocol_stack(AC_STACK_ID, (char *) "dup", ac_stack_classify) == 0, "duplicate id -> 0");
    CHECK(strcmp(get_protocol_stack_name(AC_STACK_ID), "ac_stack") == 0, "existing stack untouched");
}

static int g_stack_cleanups;
static void *g_stack_cleanup_ctx;
static void stack_cleanup(void *ctx) { g_stack_cleanups++; g_stack_cleanup_ctx = ctx; }
static void b_register_protocol_stack_full(void) {
    int ctx;
    g_stack_cleanups = 0;
    CHECK(register_protocol_stack_full(AC_STACK_AUX, (char *) "ac_aux_full", ac_stack_classify,
                                       stack_cleanup, &ctx) == 1, "registered");
    CHECK(get_protocol_stack_name(AC_STACK_AUX) != NULL, "visible");
    unregister_protocol_stack(AC_STACK_AUX);
    CHECK(g_stack_cleanups == 1 && g_stack_cleanup_ctx == &ctx, "cleanup ran with its context on unregister");
}
static void e_register_protocol_stack_full(void) {
    CHECK(register_protocol_stack_full(AC_STACK_ID, (char *) "dup", ac_stack_classify, NULL, NULL) == 0,
          "duplicate id -> 0");
}

static void b_unregister_protocol_stack(void) {
    register_protocol_stack(AC_STACK_AUX, (char *) "ac_aux", ac_stack_classify);
    CHECK(unregister_protocol_stack(AC_STACK_AUX) > 0 && get_protocol_stack_name(AC_STACK_AUX) == NULL, "removed");
}
static void e_unregister_protocol_stack(void) {
    CHECK(unregister_protocol_stack(4242) > 0, "unknown stack -> positive (documented not a failure)");
    CHECK(get_protocol_stack_name(AC_STACK_ID) != NULL, "registered stacks untouched");
}

static void b_is_free_protocol_id_for_registration(void) {
    CHECK(is_free_protocol_id_for_registration(AC_FREE_ID) == 1, "unused id is free");
    CHECK(is_free_protocol_id_for_registration(AC_PROTO_A) == 0, "registered id is taken");
}
static void e_is_free_protocol_id_for_registration(void) {
    CHECK(is_free_protocol_id_for_registration(PROTO_MAX_IDENTIFIER) == 0, "invalid id -> 0");
}

/* Issue #546: the misspelled original stays exported, deprecated, and answers
 * exactly as the correctly spelled function. */
static void b_is_free_protocol_id_for_registractionl(void) {
    AC_ALLOW_DEPRECATED_BEGIN
    CHECK(is_free_protocol_id_for_registractionl(AC_FREE_ID) == 1, "unused id is free");
    CHECK(is_free_protocol_id_for_registractionl(AC_PROTO_A) == 0, "registered id is taken");
    AC_ALLOW_DEPRECATED_END
}
static void e_is_free_protocol_id_for_registractionl(void) {
    AC_ALLOW_DEPRECATED_BEGIN
    CHECK(is_free_protocol_id_for_registractionl(PROTO_MAX_IDENTIFIER) == 0, "invalid id -> 0");
    AC_ALLOW_DEPRECATED_END
}

static void b_get_protocol_struct_for_registration_if_free(void) {
    protocol_t *p = get_protocol_struct_for_registration_if_free(AC_FREE_ID + 2);
    CHECK(p != NULL && p->get_attribute_id_by_name != NULL && p->has_session == NO_SESSION_CONTEXT,
          "free slot handed out initialized");
}
static void e_get_protocol_struct_for_registration_if_free(void) {
    CHECK(get_protocol_struct_for_registration_if_free(PROTO_META) == NULL, "taken id -> NULL");
    CHECK(get_protocol_struct_for_registration_if_free(PROTO_MAX_IDENTIFIER) == NULL, "invalid id -> NULL");
}

static void b_init_protocol_struct_for_registration(void) {
    protocol_t *p = init_protocol_struct_for_registration(AC_FREE_ID + 3, "ac_proto_init");
    CHECK(p != NULL && p->proto_id == AC_FREE_ID + 3 && strcmp(p->protocol_name, "ac_proto_init") == 0,
          "identity stamped on the free slot");
}
static void e_init_protocol_struct_for_registration(void) {
    CHECK(init_protocol_struct_for_registration(AC_PROTO_A, "x") == NULL, "taken id -> NULL");
    CHECK(strcmp(get_protocol_name_by_id(AC_PROTO_A), "ac_proto_a") == 0, "existing protocol untouched");
}

static void b_register_attribute_with_protocol(void) {
    CHECK(add_attribute(g_pc, 1, "ac_c_attr", MMT_U8_DATA, 1, 0, SCOPE_PACKET, general_char_extraction) == 1,
          "registered");
    CHECK(is_protocol_attribute(AC_PROTO_C, 1) && get_attribute_id_by_protocol_id_and_attribute_name(AC_PROTO_C, "ac_c_attr") == 1,
          "visible by id and by name");
}
static void e_register_attribute_with_protocol(void) {
    CHECK(add_attribute(g_pc, 2, "ac_u32", MMT_U8_DATA, 1, 0, SCOPE_PACKET, NULL) == 1, "distinct attribute");
    CHECK(add_attribute(g_pc, 2, "ac_other", MMT_U8_DATA, 1, 0, SCOPE_PACKET, NULL) == 0, "duplicate id -> 0");
    CHECK(add_attribute(g_pc, 0, "ac_zero", MMT_U8_DATA, 1, 0, SCOPE_PACKET, NULL) == 0, "id 0 -> 0");
    CHECK(add_attribute(g_pc, 3, "ac_wide", MMT_U8_DATA, 8, 0, SCOPE_PACKET, NULL) == 0,
          "data_len wider than the type -> 0");
    CHECK(!is_protocol_attribute(AC_PROTO_C, 3), "rejected attribute absent");
}

static void b_register_protocol(void) {
    protocol_t *p = init_protocol_struct_for_registration(AC_FREE_ID + 4, "ac_proto_reg");
    CHECK(p != NULL && register_protocol(p, AC_FREE_ID + 4) == PROTO_REGISTERED, "registered");
    CHECK(is_registered_protocol(AC_FREE_ID + 4) && get_protocol_id_by_name("ac_proto_reg") == AC_FREE_ID + 4,
          "visible by id and by name");
    unregister_protocol_by_id(AC_FREE_ID + 4);
}
static void e_register_protocol(void) {
    protocol_t *p = init_protocol_struct_for_registration(AC_FREE_ID + 5, "ac_proto_mis");
    CHECK(p != NULL && register_protocol(p, AC_FREE_ID + 6) == PROTO_NOT_REGISTERED,
          "struct registered under another id -> PROTO_NOT_REGISTERED");
    CHECK(register_protocol(g_pa, AC_PROTO_A) == PROTO_NOT_REGISTERED, "already registered -> PROTO_NOT_REGISTERED");
    CHECK(!is_registered_protocol(AC_FREE_ID + 6), "nothing registered");
}

static void b_unregister_protocol_by_id(void) {
    protocol_t *p = init_protocol_struct_for_registration(AC_FREE_ID + 7, "ac_proto_unid");
    CHECK(p != NULL && register_protocol(p, AC_FREE_ID + 7) == PROTO_REGISTERED, "registered");
    CHECK(unregister_protocol_by_id(AC_FREE_ID + 7) == 1 && !is_registered_protocol(AC_FREE_ID + 7), "removed");
}
static void e_unregister_protocol_by_id(void) {
    /* Issue #673 (found by #525): an out-of-range id used to index past
     * configured_protocols[] and write through what it found there. */
    CHECK(unregister_protocol_by_id(PROTO_MAX_IDENTIFIER) == 0, "out-of-range id -> 0");
    CHECK(unregister_protocol_by_id(UINT32_MAX) == 0, "largest id -> 0");
    CHECK(unregister_protocol_by_id(AC_FREE_ID + 8) == 0, "never-registered id -> 0");
    CHECK(unregister_protocol_by_id(AC_UNREG_ID) == 0 && !is_registered_protocol(AC_UNREG_ID),
          "another never-registered id -> 0, nothing changed");
}

static void b_unregister_protocol_by_name(void) {
    protocol_t *p = init_protocol_struct_for_registration(AC_FREE_ID + 9, "ac_proto_unname");
    CHECK(p != NULL && register_protocol(p, AC_FREE_ID + 9) == PROTO_REGISTERED, "registered");
    CHECK(unregister_protocol_by_name((char *) "AC_PROTO_UNNAME") == 1 && !is_registered_protocol(AC_FREE_ID + 9),
          "removed, name matched case-insensitively");
}
static void e_unregister_protocol_by_name(void) {
    CHECK(unregister_protocol_by_name((char *) "no_such_proto") == 0, "unknown name -> 0");
    CHECK(is_registered_protocol(AC_PROTO_A), "registered protocols untouched");
}

static void b_get_protocol_struct_by_id(void) {
    protocol_t *p = get_protocol_struct_by_id(AC_PROTO_A);
    CHECK(p == g_pa && p->proto_id == AC_PROTO_A, "the registered struct");
}
static void e_get_protocol_struct_by_id(void) {
    CHECK(get_protocol_struct_by_id(AC_UNREG_ID) == NULL, "unregistered id -> NULL");
    CHECK(get_protocol_struct_by_id(PROTO_MAX_IDENTIFIER) == NULL, "invalid id -> NULL");
}

/* get_proto_attribute_*: dispatch through the protocol's metadata hooks
 * (the defaults read the attribute maps). Attribute 2 of A: U16, length 2,
 * position 6, packet scope. */
static void b_get_proto_attribute_position(void) {
    CHECK(get_proto_attribute_position(g_pa, AC_PROTO_A, AC_ATTR_U16) == 6, "declared position");
}
static void e_get_proto_attribute_position(void) {
    CHECK(get_proto_attribute_position(g_pa, AC_PROTO_A, AC_ATTR_NONE) == POSITION_NOT_KNOWN,
          "unknown attribute -> POSITION_NOT_KNOWN");
}
static void b_get_proto_attribute_length(void) {
    CHECK(get_proto_attribute_length(g_pa, AC_PROTO_A, AC_ATTR_U16) == 2, "declared length");
}
static void e_get_proto_attribute_length(void) {
    CHECK(get_proto_attribute_length(g_pa, AC_PROTO_A, AC_ATTR_NONE) == 0, "unknown attribute -> 0");
}
static void b_get_proto_attribute_id(void) {
    CHECK(get_proto_attribute_id(g_pa, AC_PROTO_A, "ac_u16") == AC_ATTR_U16, "id by name");
}
static void e_get_proto_attribute_id(void) {
    CHECK(get_proto_attribute_id(g_pa, AC_PROTO_A, "no_such_attr") == 0, "unknown name -> 0");
}
static void b_get_proto_attribute_name(void) {
    const char *n = get_proto_attribute_name(g_pa, AC_PROTO_A, AC_ATTR_U16);
    CHECK(n != NULL && strcmp(n, "ac_u16") == 0, "name by id");
}
static void e_get_proto_attribute_name(void) {
    CHECK(get_proto_attribute_name(g_pa, AC_PROTO_A, AC_ATTR_NONE) == NULL, "unknown attribute -> NULL");
}
static void b_get_proto_attribute_type(void) {
    CHECK(get_proto_attribute_type(g_pa, AC_PROTO_A, AC_ATTR_U16) == MMT_U16_DATA, "declared type");
}
static void e_get_proto_attribute_type(void) {
    CHECK(get_proto_attribute_type(g_pa, AC_PROTO_A, AC_ATTR_NONE) == MMT_UNDEFINED_TYPE,
          "unknown attribute -> MMT_UNDEFINED_TYPE");
}
static void b_get_proto_attribute_scope(void) {
    CHECK(get_proto_attribute_scope(g_pa, AC_PROTO_A, AC_ATTR_U16) == SCOPE_PACKET, "declared scope");
    CHECK(get_proto_attribute_scope(g_pa, AC_PROTO_A, AC_ATTR_EVENT) == SCOPE_EVENT, "event scope");
}
static void e_get_proto_attribute_scope(void) {
    CHECK(get_proto_attribute_scope(g_pa, AC_PROTO_A, AC_ATTR_NONE) == 0, "unknown attribute -> 0");
}
static void b_is_valid_proto_attribute(void) {
    CHECK(is_valid_proto_attribute(g_pa, AC_PROTO_A, AC_ATTR_U16) == true, "declared attribute");
}
static void e_is_valid_proto_attribute(void) {
    CHECK(is_valid_proto_attribute(g_pa, AC_PROTO_A, AC_ATTR_NONE) == false, "unknown attribute -> false");
}

/* ======================================================================== */
/*                              contract table                              */
/* ======================================================================== */

#define W_SESSION  "pure accessor of a caller-owned session record: dereferences it and defines no failure value (NULL is a precondition violation, not a reported error)"
#define W_ATTR     "pure accessor of an attribute record: dereferences it and defines no failure value"
#define W_NOARGS   "takes no input: there is no invalid argument to pass"
#define W_OOMONLY  "takes no input; its only failure value (0, mmt_core.h) is reached through allocation or plugin-init failure, which this binary cannot inject: it is linked without the --wrap allocator hooks"
#define W_TOTAL    "total function over its argument domain: every input has a defined result, none is a failure"
#define W_HANDLER  "takes a live handler and reports nothing: NULL or a closed handler is a dereferenced precondition violation"
#define W_NOREPORT "returns nothing and rejects nothing: NULL is accepted and ignored, any packet the library handed out is valid"
#define W_SETTER   "unconditional field store on a caller-owned record: no input is rejected and nothing is reported"

AC_ALLOW_DEPRECATED_BEGIN /* the deprecated APIs are under contract too */
static const api_contract_t k_contracts[] = {
    /* ---------------------------- data_defs.h ---------------------------- */
    CONTRACT(get_protocol_name_by_id, b_get_protocol_name_by_id, e_get_protocol_name_by_id),
    CONTRACT(get_attribute_name_by_protocol_and_attribute_ids, b_get_attribute_name_by_protocol_and_attribute_ids,
             e_get_attribute_name_by_protocol_and_attribute_ids),
    CONTRACT(get_packet_offset_at_index, b_get_packet_offset_at_index, e_get_packet_offset_at_index),
    NO_ERROR_PATH(invalidate_packet_offset_cache, b_invalidate_packet_offset_cache, W_NOREPORT),
    CONTRACT(get_protocol_id_at_index, b_get_protocol_id_at_index, e_get_protocol_id_at_index),
    CONTRACT(get_protocol_index_by_id, b_get_protocol_index_by_id, e_get_protocol_index_by_id),
    CONTRACT(get_protocol_index_by_name, b_get_protocol_index_by_name, e_get_protocol_index_by_name),
    CONTRACT(get_session_id_from_packet, b_get_session_id_from_packet, e_get_session_id_from_packet),
    CONTRACT(get_user_session_context_from_packet, b_get_user_session_context_from_packet,
             e_get_user_session_context_from_packet),
    CONTRACT(set_user_session_context_for_packet, b_set_user_session_context_for_packet,
             e_set_user_session_context_for_packet),
    CONTRACT(get_proto_session_data_from_packet, b_get_proto_session_data_from_packet,
             e_get_proto_session_data_from_packet),
    CONTRACT(get_session_from_packet, b_get_session_from_packet, e_get_session_from_packet),
    CONTRACT(get_session_parent, b_get_session_parent, e_get_session_parent),
    NO_ERROR_PATH(get_session_handler, b_get_session_handler, W_SESSION),
    NO_ERROR_PATH(get_session_protocol_index, b_get_session_protocol_index, W_SESSION),
    NO_ERROR_PATH(get_session_protocol_hierarchy, b_get_session_protocol_hierarchy, W_SESSION),
    NO_ERROR_PATH(get_session_id, b_get_session_id, W_SESSION),
    CONTRACT(get_session_classification_method, b_get_session_classification_method, e_get_session_classification_method),
    CONTRACT(get_classification_method_name, b_get_classification_method_name, e_get_classification_method_name),
    NO_ERROR_PATH(get_user_session_context, b_get_user_session_context, W_SESSION),
    CONTRACT(get_proto_session_data, b_get_proto_session_data, e_get_proto_session_data),
    CONTRACT(set_proto_session_data, b_set_proto_session_data, e_set_proto_session_data),
    NO_ERROR_PATH(set_user_session_context, b_set_user_session_context, W_SETTER),
    NO_ERROR_PATH(get_session_packet_count, b_get_session_packet_count, W_SESSION),
    NO_ERROR_PATH(get_session_packet_cap_count, b_get_session_packet_cap_count, W_SESSION),
    NO_ERROR_PATH(get_session_data_cap_volume, b_get_session_data_cap_volume, W_SESSION),
    NO_ERROR_PATH(get_session_ul_packet_count, b_get_session_ul_packet_count, W_SESSION),
    NO_ERROR_PATH(get_session_ul_cap_packet_count, b_get_session_ul_cap_packet_count, W_SESSION),
    NO_ERROR_PATH(get_session_dl_packet_count, b_get_session_dl_packet_count, W_SESSION),
    NO_ERROR_PATH(get_session_dl_cap_packet_count, b_get_session_dl_cap_packet_count, W_SESSION),
    NO_ERROR_PATH(get_session_byte_count, b_get_session_byte_count, W_SESSION),
    NO_ERROR_PATH(get_session_ul_byte_count, b_get_session_ul_byte_count, W_SESSION),
    NO_ERROR_PATH(get_session_dl_byte_count, b_get_session_dl_byte_count, W_SESSION),
    NO_ERROR_PATH(get_session_ul_cap_byte_count, b_get_session_ul_cap_byte_count, W_SESSION),
    NO_ERROR_PATH(get_session_dl_cap_byte_count, b_get_session_dl_cap_byte_count, W_SESSION),
    NO_ERROR_PATH(get_session_data_packet_count, b_get_session_data_packet_count, W_SESSION),
    NO_ERROR_PATH(get_session_ul_data_packet_count, b_get_session_ul_data_packet_count, W_SESSION),
    NO_ERROR_PATH(get_session_dl_data_packet_count, b_get_session_dl_data_packet_count, W_SESSION),
    NO_ERROR_PATH(get_session_data_byte_count, b_get_session_data_byte_count, W_SESSION),
    NO_ERROR_PATH(get_session_ul_data_byte_count, b_get_session_ul_data_byte_count, W_SESSION),
    NO_ERROR_PATH(get_session_dl_data_byte_count, b_get_session_dl_data_byte_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_packet_count, b_get_session_total_packet_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_packet_cap_count, b_get_session_total_packet_cap_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_data_cap_volume, b_get_session_total_data_cap_volume, W_SESSION),
    NO_ERROR_PATH(get_session_total_ul_packet_count, b_get_session_total_ul_packet_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_ul_cap_packet_count, b_get_session_total_ul_cap_packet_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_dl_packet_count, b_get_session_total_dl_packet_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_dl_cap_packet_count, b_get_session_total_dl_cap_packet_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_byte_count, b_get_session_total_byte_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_ul_byte_count, b_get_session_total_ul_byte_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_dl_byte_count, b_get_session_total_dl_byte_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_ul_cap_byte_count, b_get_session_total_ul_cap_byte_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_dl_cap_byte_count, b_get_session_total_dl_cap_byte_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_data_packet_count, b_get_session_total_data_packet_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_ul_data_packet_count, b_get_session_total_ul_data_packet_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_dl_data_packet_count, b_get_session_total_dl_data_packet_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_data_byte_count, b_get_session_total_data_byte_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_ul_data_byte_count, b_get_session_total_ul_data_byte_count, W_SESSION),
    NO_ERROR_PATH(get_session_total_dl_data_byte_count, b_get_session_total_dl_data_byte_count, W_SESSION),
    NO_ERROR_PATH(get_session_init_time, b_get_session_init_time, W_SESSION),
    NO_ERROR_PATH(get_session_last_activity_time, b_get_session_last_activity_time, W_SESSION),
    CONTRACT(get_session_last_data_packet_time_by_direction, b_get_session_last_data_packet_time_by_direction,
             e_get_session_last_data_packet_time_by_direction),
    NO_ERROR_PATH(get_session_rtt, b_get_session_rtt, W_SESSION),
    NO_ERROR_PATH(get_session_content_class_id, b_get_session_content_class_id, W_SESSION),
    NO_ERROR_PATH(get_session_content_type_id, b_get_session_content_type_id, W_SESSION),
    NO_ERROR_PATH(get_session_content_flags, b_get_session_content_flags, W_SESSION),
    NO_ERROR_PATH(get_session_retransmission_count, b_get_session_retransmission_count, W_SESSION),
    NO_ERROR_PATH(get_session_outoforder_count, b_get_session_outoforder_count, W_SESSION),
    CONTRACT(get_session_next, b_get_session_next, e_get_session_next),
    CONTRACT(get_session_previous, b_get_session_previous, e_get_session_previous),
    NO_ERROR_PATH(get_session_proto_path_direction, b_get_session_proto_path_direction,
                  "every direction value selects a path (non-uplink reads as downlink); the session is a dereferenced precondition"),
    NO_ERROR_PATH(get_session_setup_direction, b_get_session_setup_direction, W_SESSION),
    NO_ERROR_PATH(get_session_last_packet_direction, b_get_session_last_packet_direction, W_SESSION),
    NO_ERROR_PATH(get_attr_protocol_id, b_get_attr_protocol_id, W_ATTR),
    NO_ERROR_PATH(get_attr_id, b_get_attr_id, W_ATTR),
    NO_ERROR_PATH(get_attr_protocol_index, b_get_attr_protocol_index, W_ATTR),
    NO_ERROR_PATH(get_attr_status, b_get_attr_status, W_ATTR),
    NO_ERROR_PATH(get_attr_data_type, b_get_attr_data_type, W_ATTR),
    NO_ERROR_PATH(get_attr_data_len, b_get_attr_data_len, W_ATTR),
    NO_ERROR_PATH(get_attr_offset, b_get_attr_offset, W_ATTR),
    NO_ERROR_PATH(get_attr_scope, b_get_attr_scope, W_ATTR),
    NO_ERROR_PATH(get_attr_data, b_get_attr_data, W_ATTR),
    NO_ERROR_PATH(get_last_activity_time, b_get_last_activity_time,
                  "pure accessor of a live handler: dereferences it and defines no failure value"),
    CONTRACT(htoi, b_htoi, e_htoi),
    CONTRACT(get_data_size_by_proto_and_field_ids, b_get_data_size_by_proto_and_field_ids,
             e_get_data_size_by_proto_and_field_ids),
    CONTRACT(get_data_size_by_data_type, b_get_data_size_by_data_type, e_get_data_size_by_data_type),
    CONTRACT(get_field_position_by_protocol_and_field_ids, b_get_field_position_by_protocol_and_field_ids,
             e_get_field_position_by_protocol_and_field_ids),
    CONTRACT(is_protocol_attribute, b_is_protocol_attribute, e_is_protocol_attribute),
    CONTRACT(get_protocol_id_by_name, b_get_protocol_id_by_name, e_get_protocol_id_by_name),
    CONTRACT(get_attribute_id_by_protocol_and_attribute_names, b_get_attribute_id_by_protocol_and_attribute_names,
             e_get_attribute_id_by_protocol_and_attribute_names),
    CONTRACT(get_attribute_id_by_protocol_id_and_attribute_name, b_get_attribute_id_by_protocol_id_and_attribute_name,
             e_get_attribute_id_by_protocol_id_and_attribute_name),
    CONTRACT(get_attribute_data_type, b_get_attribute_data_type, e_get_attribute_data_type),
    CONTRACT(get_attribute_scope, b_get_attribute_scope, e_get_attribute_scope),
    NO_ERROR_PATH(short_time_diff, b_short_time_diff,
                  "arithmetic on two caller-owned timevals: no failure value (the header limits it to spans under ~4000 s)"),
    NO_ERROR_PATH(get_classification_threshold, b_get_classification_threshold, W_NOARGS),
    CONTRACT(proto_hierarchy_to_str_with_size, b_proto_hierarchy_to_str_with_size, e_proto_hierarchy_to_str_with_size),
    CONTRACT(proto_hierarchy_to_str, b_proto_hierarchy_to_str, e_proto_hierarchy_to_str),
    CONTRACT(get_application_name, b_get_application_name, e_get_application_name),
    NO_ERROR_PATH(mmt_toupper, b_mmt_toupper, W_TOTAL),
    NO_ERROR_PATH(mmt_tolower, b_mmt_tolower, W_TOTAL),
    NO_ERROR_PATH(mmt_strcasecmp, b_mmt_strcasecmp, W_TOTAL),
    NO_ERROR_PATH(mmt_strncasecmp, b_mmt_strncasecmp, W_TOTAL),
    NO_ERROR_PATH(mmt_strcmp, b_mmt_strcmp, W_TOTAL),
    NO_ERROR_PATH(mmt_strncmp, b_mmt_strncmp, W_TOTAL),
    CONTRACT(mmt_attr_format, b_mmt_attr_format, e_mmt_attr_format),
    CONTRACT(mmt_attr_fprintf, b_mmt_attr_fprintf, e_mmt_attr_fprintf),
    CONTRACT(mmt_attr_sprintf, b_mmt_attr_sprintf, e_mmt_attr_sprintf),
    CONTRACT(mmt_inet_ntop, b_mmt_inet_ntop, e_mmt_inet_ntop),

    /* -------------------------- extraction_lib.h ------------------------- */
    CONTRACT(silent_extraction, b_silent_extraction, e_silent_extraction),
    CONTRACT(general_byte_to_byte_extraction, b_general_byte_to_byte_extraction, e_general_byte_to_byte_extraction),
    CONTRACT(general_short_extraction_with_ordering_change, b_general_short_extraction_with_ordering_change,
             e_general_short_extraction_with_ordering_change),
    CONTRACT(general_int_extraction_with_ordering_change, b_general_int_extraction_with_ordering_change,
             e_general_int_extraction_with_ordering_change),
    CONTRACT(general_char_extraction, b_general_char_extraction, e_general_char_extraction),
    CONTRACT(general_short_extraction, b_general_short_extraction, e_general_short_extraction),
    CONTRACT(general_int_extraction, b_general_int_extraction, e_general_int_extraction),

    /* ----------------------------- mmt_core.h ---------------------------- */
    CONTRACT(process_packet_handler, b_process_packet_handler, e_process_packet_handler),
    NO_ERROR_PATH(mmt_drop_packet, b_mmt_drop_packet,
                  "takes the live packet being processed and reports nothing: no input is rejected"),
    NO_ERROR_PATH(init_extraction, b_init_extraction, W_OOMONLY),
    CONTRACT(update_protocol, b_update_protocol, e_update_protocol),
    NO_ERROR_PATH(close_extraction, b_close_extraction, W_NOARGS),
    CONTRACT(mmt_init_handler, b_mmt_init_handler, e_mmt_init_handler),
    NO_ERROR_PATH(mmt_close_handler, b_mmt_close_handler, W_HANDLER),
    CONTRACT(get_active_session_count, b_get_active_session_count, e_get_active_session_count),
    CONTRACT(get_protocol_stack_name, b_get_protocol_stack_name, e_get_protocol_stack_name),
    CONTRACT(is_registered_packet_handler, b_is_registered_packet_handler, e_is_registered_packet_handler),
    CONTRACT(register_packet_handler, b_register_packet_handler, e_register_packet_handler),
    CONTRACT(unregister_packet_handler, b_unregister_packet_handler, e_unregister_packet_handler),
    NO_ERROR_PATH(register_session_timeout_handler, b_register_session_timeout_handler,
                  "documented to always succeed: any callback, NULL included, replaces the previous one"),
    NO_ERROR_PATH(register_session_timer_handler, b_register_session_timer_handler,
                  "always succeeds: any callback, NULL included, replaces the previous one"),
    CONTRACT(is_registered_attribute, b_is_registered_attribute, e_is_registered_attribute),
    CONTRACT(register_evasion_handler, b_register_evasion_handler, e_register_evasion_handler),
    CONTRACT(register_extraction_attribute, b_register_extraction_attribute, e_register_extraction_attribute),
    CONTRACT(register_extraction_attribute_by_name, b_register_extraction_attribute_by_name,
             e_register_extraction_attribute_by_name),
    CONTRACT(unregister_extraction_attribute, b_unregister_extraction_attribute, e_unregister_extraction_attribute),
    CONTRACT(unregister_extraction_attribute_by_name, b_unregister_extraction_attribute_by_name,
             e_unregister_extraction_attribute_by_name),
    CONTRACT(has_registered_attribute_handler, b_has_registered_attribute_handler, e_has_registered_attribute_handler),
    CONTRACT(is_registered_attribute_handler, b_is_registered_attribute_handler, e_is_registered_attribute_handler),
    CONTRACT(register_attribute_handler, b_register_attribute_handler, e_register_attribute_handler),
    CONTRACT(register_attribute_handler_by_name, b_register_attribute_handler_by_name,
             e_register_attribute_handler_by_name),
    CONTRACT(unregister_attribute_handler, b_unregister_attribute_handler, e_unregister_attribute_handler),
    CONTRACT(unregister_attribute_handler_by_name, b_unregister_attribute_handler_by_name,
             e_unregister_attribute_handler_by_name),
    CONTRACT(set_default_session_timed_out, b_set_default_session_timed_out, e_set_default_session_timed_out),
    CONTRACT(set_tcp_reassembly_limit, b_set_tcp_reassembly_limit, e_set_tcp_reassembly_limit),
    CONTRACT(set_long_session_timed_out, b_set_long_session_timed_out, e_set_long_session_timed_out),
    CONTRACT(set_short_session_timed_out, b_set_short_session_timed_out, e_set_short_session_timed_out),
    CONTRACT(set_live_session_timed_out, b_set_live_session_timed_out, e_set_live_session_timed_out),
    CONTRACT(set_fragment_in_packet, b_set_fragment_in_packet, e_set_fragment_in_packet),
    CONTRACT(set_fragmented_packet_in_session, b_set_fragmented_packet_in_session, e_set_fragmented_packet_in_session),
    CONTRACT(set_fragment_in_session, b_set_fragment_in_session, e_set_fragment_in_session),
    NO_ERROR_PATH(debug_extracted_attributes_printout_handler, b_debug_extracted_attributes_printout_handler,
                  "debug packet callback: always returns 0 and takes the live packet being processed"),
    CONTRACT(fire_attribute_event, b_fire_attribute_event, e_fire_attribute_event),
    CONTRACT(fire_evasion_event, b_fire_evasion_event, e_fire_evasion_event),
    CONTRACT(packet_process, b_packet_process, e_packet_process),
    NO_ERROR_PATH(mmt_print_all_protocols, b_mmt_print_all_protocols, W_NOARGS),
    NO_ERROR_PATH(process_session_timer_handler, b_process_session_timer_handler, W_HANDLER),
    CONTRACT(enable_mmt_reassembly, b_enable_mmt_reassembly, e_enable_mmt_reassembly),
    CONTRACT(disable_mmt_reassembly, b_disable_mmt_reassembly, e_disable_mmt_reassembly),
    CONTRACT(enable_port_classify, b_enable_port_classify, e_enable_port_classify),
    CONTRACT(disable_port_classify, b_disable_port_classify, e_disable_port_classify),
    CONTRACT(enable_port_classify_payload_confirm, b_enable_port_classify_payload_confirm,
             e_enable_port_classify_payload_confirm),
    CONTRACT(disable_port_classify_payload_confirm, b_disable_port_classify_payload_confirm,
             e_disable_port_classify_payload_confirm),
    CONTRACT(enable_hostname_classify, b_enable_hostname_classify, e_enable_hostname_classify),
    CONTRACT(disable_hostname_classify, b_disable_hostname_classify, e_disable_hostname_classify),
    CONTRACT(enable_ip_address_classify, b_enable_ip_address_classify, e_enable_ip_address_classify),
    CONTRACT(disable_ip_address_classify, b_disable_ip_address_classify, e_disable_ip_address_classify),
    CONTRACT(mmt_apply_dpi_profile, b_mmt_apply_dpi_profile, e_mmt_apply_dpi_profile),
    CONTRACT(mmt_apply_dpi_profile_by_name, b_mmt_apply_dpi_profile_by_name, e_mmt_apply_dpi_profile_by_name),
    CONTRACT(mmt_load_dpi_profiles_file, b_mmt_load_dpi_profiles_file, e_mmt_load_dpi_profiles_file),
    CONTRACT(set_classification_max_depth, b_set_classification_max_depth, e_set_classification_max_depth),
    CONTRACT(get_classification_max_depth, b_get_classification_max_depth, e_get_classification_max_depth),
    NO_ERROR_PATH(set_session_timeout_delay, b_set_session_timeout_delay, W_SETTER),
    CONTRACT(get_attribute_extracted_data, b_get_attribute_extracted_data, e_get_attribute_extracted_data),
    CONTRACT(get_attribute_extracted_data_encap_index, b_get_attribute_extracted_data_encap_index,
             e_get_attribute_extracted_data_encap_index),
    CONTRACT(get_attribute_extracted_data_by_name, b_get_attribute_extracted_data_by_name,
             e_get_attribute_extracted_data_by_name),
    CONTRACT(get_attribute_extracted_data_at_index, b_get_attribute_extracted_data_at_index,
             e_get_attribute_extracted_data_at_index),
    CONTRACT(get_extracted_attribute, b_get_extracted_attribute, e_get_extracted_attribute),
    CONTRACT(get_extracted_attribute_by_name, b_get_extracted_attribute_by_name, e_get_extracted_attribute_by_name),
    CONTRACT(get_extracted_attribute_at_index, b_get_extracted_attribute_at_index, e_get_extracted_attribute_at_index),
    CONTRACT(get_extracted_attribute_at_index_by_name, b_get_extracted_attribute_at_index_by_name,
             e_get_extracted_attribute_at_index_by_name),
    CONTRACT(get_protocol_stats, b_get_protocol_stats, e_get_protocol_stats),
    NO_ERROR_PATH(get_children_stats, b_get_children_stats,
                  "reports into a caller-owned record and returns nothing: both statistics records are dereferenced preconditions"),
    CONTRACT(get_protocol_stats_path, b_get_protocol_stats_path, e_get_protocol_stats_path),
    NO_ERROR_PATH(reset_statistics, b_reset_statistics, W_SETTER),
    CONTRACT(setDataLinkType, b_setDataLinkType, e_setDataLinkType),
    CONTRACT(get_data_link_type, b_get_data_link_type, e_get_data_link_type),
    CONTRACT(enable_protocol_statistics, b_enable_protocol_statistics, e_enable_protocol_statistics),
    CONTRACT(disable_protocol_statistics, b_disable_protocol_statistics, e_disable_protocol_statistics),
    CONTRACT(enable_protocol_analysis, b_enable_protocol_analysis, e_enable_protocol_analysis),
    CONTRACT(disable_protocol_analysis, b_disable_protocol_analysis, e_disable_protocol_analysis),
    CONTRACT(enable_protocol_classification, b_enable_protocol_classification, e_enable_protocol_classification),
    CONTRACT(disable_protocol_classification, b_disable_protocol_classification, e_disable_protocol_classification),
    CONTRACT(is_valid_protocol_id, b_is_valid_protocol_id, e_is_valid_protocol_id),
    CONTRACT(is_registered_protocol, b_is_registered_protocol, e_is_registered_protocol),
    CONTRACT(iterate_through_protocol_attributes, b_iterate_through_protocol_attributes,
             e_iterate_through_protocol_attributes),
    NO_ERROR_PATH(iterate_through_protocols, b_iterate_through_protocols,
                  "visits the global registry and reports nothing: the callback is a dereferenced precondition"),
    NO_ERROR_PATH(iterate_through_mmt_handlers, b_iterate_through_mmt_handlers,
                  "visits the global handler registry and reports nothing: the callback is a dereferenced precondition"),
    NO_ERROR_PATH(mmt_version, b_mmt_version, W_NOARGS),
    CONTRACT(mmt_malloc, b_mmt_malloc, e_mmt_malloc),
    CONTRACT(mmt_realloc, b_mmt_realloc, e_mmt_realloc),
    CONTRACT(mmt_free, b_mmt_free, e_mmt_free),
    CONTRACT(mmt_arena_create, b_mmt_arena_create, e_mmt_arena_create),
    CONTRACT(mmt_arena_alloc, b_mmt_arena_alloc, e_mmt_arena_alloc),
    CONTRACT(mmt_arena_reset, b_mmt_arena_reset, e_mmt_arena_reset),
    CONTRACT(mmt_arena_destroy, b_mmt_arena_destroy, e_mmt_arena_destroy),
    NO_ERROR_PATH(mmt_print_info, b_mmt_print_info, W_NOARGS),

    /* ----------------------------- mmt_utils.h --------------------------- */
    NO_ERROR_PATH(hex2int, b_hex2int, W_TOTAL),
    CONTRACT(str_hex2int, b_str_hex2int, e_str_hex2int),
    CONTRACT(str_hex2int_n, b_str_hex2int_n, e_str_hex2int_n),
    CONTRACT(str_hex2str, b_str_hex2str, e_str_hex2str),
    CONTRACT(hex2dec, b_hex2dec, e_hex2dec),
    CONTRACT(char2int, b_char2int, e_char2int),
    CONTRACT(hex2char, b_hex2char, e_hex2char),
    CONTRACT(hex2str, b_hex2str, e_hex2str),
    NO_ERROR_PATH(str_compare, b_str_compare,
                  "total equality predicate: NULL operands have a defined result (equal only to NULL), none is a failure"),
    CONTRACT(str_index, b_str_index, e_str_index),
    CONTRACT(str_sub, b_str_sub, e_str_sub),
    CONTRACT(str_sub_n, b_str_sub_n, e_str_sub_n),
    CONTRACT(str_combine, b_str_combine, e_str_combine),
    CONTRACT(str_get_indexes, b_str_get_indexes, e_str_get_indexes),
    CONTRACT(str_get_indexes_n, b_str_get_indexes_n, e_str_get_indexes_n),
    CONTRACT(str_replace, b_str_replace, e_str_replace),
    CONTRACT(str_subvalue, b_str_subvalue, e_str_subvalue),
    CONTRACT(str_copy, b_str_copy, e_str_copy),
    NO_ERROR_PATH(str_print_array, b_str_print_array,
                  "prints a caller-owned NULL-terminated array and reports nothing: the array is a dereferenced precondition"),

    /* ---------------------------- plugin_defs.h -------------------------- */
    CONTRACT(mmt_packet_scratch_adopt, b_mmt_packet_scratch_adopt, e_mmt_packet_scratch_adopt),
    CONTRACT(set_classified_proto, b_set_classified_proto, e_set_classified_proto),
    CONTRACT(register_classification_function_with_parent_protocol,
             b_register_classification_function_with_parent_protocol,
             e_register_classification_function_with_parent_protocol),
    CONTRACT(register_classification_function, b_register_classification_function, e_register_classification_function),
    CONTRACT(register_classification_function_full, b_register_classification_function_full,
             e_register_classification_function_full),
    NO_ERROR_PATH(register_pre_post_classification_functions, b_register_pre_post_classification_functions,
                  "always succeeds: any pair of callbacks, NULL included, replaces the previous pair"),
    NO_ERROR_PATH(register_sessionizer_function, b_register_sessionizer_function, W_SETTER),
    NO_ERROR_PATH(register_session_hash_function, b_register_session_hash_function, W_SETTER),
    NO_ERROR_PATH(register_session_equal_function, b_register_session_equal_function, W_SETTER),
    NO_ERROR_PATH(register_proto_context_init_cleanup_function, b_register_proto_context_init_cleanup_function, W_SETTER),
    NO_ERROR_PATH(register_session_data_initialization_function, b_register_session_data_initialization_function,
                  W_SETTER),
    NO_ERROR_PATH(register_session_data_cleanup_function, b_register_session_data_cleanup_function, W_SETTER),
    CONTRACT(register_session_data_analysis_function_with_protocol,
             b_register_session_data_analysis_function_with_protocol,
             e_register_session_data_analysis_function_with_protocol),
    CONTRACT(register_session_data_analysis_function, b_register_session_data_analysis_function,
             e_register_session_data_analysis_function),
    CONTRACT(register_session_data_analysis_function_full, b_register_session_data_analysis_function_full,
             e_register_session_data_analysis_function_full),
    NO_ERROR_PATH(register_pre_post_analysis_functions, b_register_pre_post_analysis_functions,
                  "always succeeds: any pair of callbacks, NULL included, replaces the previous pair"),
    CONTRACT(register_protocol_stack, b_register_protocol_stack, e_register_protocol_stack),
    CONTRACT(register_protocol_stack_full, b_register_protocol_stack_full, e_register_protocol_stack_full),
    CONTRACT(unregister_protocol_stack, b_unregister_protocol_stack, e_unregister_protocol_stack),
    CONTRACT(is_free_protocol_id_for_registration, b_is_free_protocol_id_for_registration,
             e_is_free_protocol_id_for_registration),
    CONTRACT(is_free_protocol_id_for_registractionl, b_is_free_protocol_id_for_registractionl,
             e_is_free_protocol_id_for_registractionl),
    CONTRACT(get_protocol_struct_for_registration_if_free, b_get_protocol_struct_for_registration_if_free,
             e_get_protocol_struct_for_registration_if_free),
    CONTRACT(init_protocol_struct_for_registration, b_init_protocol_struct_for_registration,
             e_init_protocol_struct_for_registration),
    CONTRACT(register_attribute_with_protocol, b_register_attribute_with_protocol, e_register_attribute_with_protocol),
    CONTRACT(register_protocol, b_register_protocol, e_register_protocol),
    CONTRACT(unregister_protocol_by_id, b_unregister_protocol_by_id, e_unregister_protocol_by_id),
    CONTRACT(unregister_protocol_by_name, b_unregister_protocol_by_name, e_unregister_protocol_by_name),
    CONTRACT(get_protocol_struct_by_id, b_get_protocol_struct_by_id, e_get_protocol_struct_by_id),
    CONTRACT(get_proto_attribute_position, b_get_proto_attribute_position, e_get_proto_attribute_position),
    CONTRACT(get_proto_attribute_length, b_get_proto_attribute_length, e_get_proto_attribute_length),
    CONTRACT(get_proto_attribute_id, b_get_proto_attribute_id, e_get_proto_attribute_id),
    CONTRACT(get_proto_attribute_name, b_get_proto_attribute_name, e_get_proto_attribute_name),
    CONTRACT(get_proto_attribute_type, b_get_proto_attribute_type, e_get_proto_attribute_type),
    CONTRACT(get_proto_attribute_scope, b_get_proto_attribute_scope, e_get_proto_attribute_scope),
    CONTRACT(is_valid_proto_attribute, b_is_valid_proto_attribute, e_is_valid_proto_attribute),
};
AC_ALLOW_DEPRECATED_END

#define AC_CONTRACTS_N (sizeof(k_contracts) / sizeof(k_contracts[0]))

/* Runs one assertion function; returns its failure count, or -1 when it
 * asserted nothing (an assertion that checks no result is not a test). */
static int run_part(void (*fn)(void)) {
    int c0 = g_checks, f0 = g_failures;
    fn();
    if (g_checks == c0) return -1;
    return g_failures - f0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--list") == 0) {
        for (size_t i = 0; i < AC_CONTRACTS_N; i++)
            printf("%s %s\n", k_contracts[i].error_path ? "CONTRACT" : "NO_ERROR_PATH", k_contracts[i].name);
        return 0;
    }
    if (argc != 1) {
        fprintf(stderr, "usage: %s [--list]\n", argv[0]);
        return 2;
    }

    if (!fixture_setup()) {
        fprintf(stderr, "API contracts: fixture setup failed\n");
        return 1;
    }

    int bad_entries = 0;
    for (size_t i = 0; i < AC_CONTRACTS_N; i++) {
        const api_contract_t *c = &k_contracts[i];
        int bad = 0;
        if (c->symbol == NULL || c->behave == NULL) {
            fprintf(stderr, "  FAIL %s: entry without a symbol or behaviour assertion\n", c->name);
            bad = 1;
        } else {
            int r = run_part(c->behave);
            if (r != 0) {
                fprintf(stderr, "  FAIL %s: behaviour %s\n", c->name, r < 0 ? "asserted nothing" : "failed");
                bad = 1;
            }
        }
        if (c->error_path != NULL) {
            int r = run_part(c->error_path);
            if (r != 0) {
                fprintf(stderr, "  FAIL %s: error path %s\n", c->name, r < 0 ? "asserted nothing" : "failed");
                bad = 1;
            }
        } else if (c->waiver == NULL || c->waiver[0] == '\0') {
            fprintf(stderr, "  FAIL %s: NO_ERROR_PATH without a reason\n", c->name);
            bad = 1;
        }
        bad_entries += bad;
    }

    close_extraction();
    fprintf(stderr, "API contracts: %zu entries, %d failing, %d checks, %d check failures\n",
            AC_CONTRACTS_N, bad_entries, g_checks, g_failures);
    return (bad_entries == 0 && g_failures == 0) ? 0 : 1;
}

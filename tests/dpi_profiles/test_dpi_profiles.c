/*
 * test_dpi_profiles.c — DPI profile configuration tests (issue #87).
 *
 * Pins the profile feature end to end, driving the real engine:
 *
 *   src/mmt_core/src/dpi_profiles.c — the profile registry under test:
 *     predefined constants, mmt_apply_dpi_profile(), the by-name lookup,
 *     the profiles-file loader, the env hook (MMT_DPI_PROFILE(S)_FILE) and
 *     the depth setter/getter;
 *   src/mmt_core/src/packet_registry.c — handler defaults stay equivalent
 *     to MMT_DPI_PROFILE_DEFAULT, and the env hook applies at init;
 *   src/mmt_core/src/packet_pipeline.c — classification_max_depth gating in
 *     proto_packet_classify_next() (checker walk skipped) and
 *     set_classified_proto() (out-of-band appends refused).
 *
 * The fake protocol stack classifies META -> L1 -> L2 -> L3 -> L4, one
 * checker per layer appending the next — so proto_hierarchy->len after a
 * packet directly measures the honoured depth bound.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "mmt_core.h"
#include "proto_meta.h"
#include "data_defs.h"
#include "plugin_defs.h"
#include "packet_processing.h" /* private: mmt_handler_t internals */

static int g_failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); \
        g_failures++; } } while (0)

#define TEST_STACK_ID   97
#define TEST_PROTO_L1   620
#define TEST_PROTO_L2   621
#define TEST_PROTO_L3   622
#define TEST_PROTO_L4   623

#define DEPTH_UNLIMITED (PROTO_PATH_SIZE - 1)

/* ---------------- fake 4-layer classification chain ----------------------
 * stack_classify lands L1 at index 1; each layer's checker appends the next
 * layer at index+1. No sessions, no analyse — the purest possible path. */

static classified_proto_t test_stack_classify(ipacket_t *ipacket) {
    classified_proto_t r;
    (void) ipacket;
    r.offset = 0;
    r.proto_id = TEST_PROTO_L1;
    r.status = Classified;
    return r;
}

static int g_checker_calls;

/* One checker for L1..L3: at layer index i it appends proto 620+i (i.e.
 * L2/L3/L4) at index+1 — the chain hops one layer per classify_next call. */
static int test_chain_checker(ipacket_t *ipacket, unsigned index) {
    classified_proto_t r;
    g_checker_calls++;
    r.offset = 4;
    r.proto_id = TEST_PROTO_L1 + index;
    r.status = Classified;
    (void) set_classified_proto(ipacket, index + 1, r);
    return MMT_CLASSIFY_MATCHED;
}

/* Out-of-band writer: mimics a sessionizer/analyse path that appends a
 * layer without going through the classify walk — the set_classified_proto
 * gate must still honour the depth bound. Registered as L4's checker. */
static int test_oob_checker(ipacket_t *ipacket, unsigned index) {
    classified_proto_t r;
    g_checker_calls++;
    r.offset = 4;
    r.proto_id = TEST_PROTO_L4; /* reclassify own slot: always allowed */
    r.status = Classified;
    (void) set_classified_proto(ipacket, index, r);
    return MMT_CLASSIFY_MATCHED;
}

static protocol_t *register_layer(uint32_t proto_id, const char *name,
                                  generic_classification_function checker) {
    protocol_t *p = init_protocol_struct_for_registration(proto_id, (char *) name);
    if (p == NULL) return NULL;
    if (checker != NULL) {
        register_classification_function(p, checker);
    }
    if (register_protocol(p, proto_id) != PROTO_REGISTERED) return NULL;
    return p;
}

static void make_packet(pkthdr_t *hdr, u_char *buf, size_t len) {
    memset(buf, 0x5a, len);
    memset(hdr, 0, sizeof(*hdr));
    hdr->caplen = (unsigned) len;
    hdr->len = (unsigned) len;
}

static int path_len(mmt_handler_t *h) {
    return h->last_received_packet.proto_hierarchy.len;
}

/* Direct set_classified_proto unit test on a fabricated packet — the append
 * gate covers out-of-band writers (sessionizers, analyse paths) that the
 * classify_next gate never sees. */
static void test_append_gate(mmt_handler_t *h) {
    fprintf(stderr, "  test: set_classified_proto honours the bound\n");
    proto_hierarchy_t hier, off, stat;
    memset(&hier, 0, sizeof(hier));
    memset(&off, 0, sizeof(off));
    memset(&stat, 0, sizeof(stat));
    hier.len = 2;
    hier.proto_path[0] = PROTO_META;
    hier.proto_path[1] = TEST_PROTO_L1;

    ipacket_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.proto_hierarchy = &hier;
    pkt.proto_headers_offset = &off;
    pkt.proto_classif_status = &stat;
    pkt.mmt_handler = h;
    pkt.session = NULL;

    classified_proto_t r;
    r.offset = 4;
    r.status = Classified;
    r.proto_id = TEST_PROTO_L2;

    set_classification_max_depth(h, 1);
    CHECK(set_classified_proto(&pkt, 2, r) == 0 && hier.len == 2,
          "append at index 2 refused under depth 1");

    set_classification_max_depth(h, 2);
    CHECK(set_classified_proto(&pkt, 2, r) != 0 && hier.len == 3,
          "append at index 2 allowed under depth 2");
    CHECK(hier.proto_path[2] == TEST_PROTO_L2, "appended proto recorded");

    r.proto_id = TEST_PROTO_L3;
    CHECK(set_classified_proto(&pkt, 3, r) == 0 && hier.len == 3,
          "append at index 3 refused under depth 2");

    /* reclassification of an existing in-bound slot is still allowed */
    r.proto_id = TEST_PROTO_L4;
    CHECK(set_classified_proto(&pkt, 2, r) != 0 &&
          hier.proto_path[2] == TEST_PROTO_L4,
          "reclassification inside the bound unaffected");
    set_classification_max_depth(h, DEPTH_UNLIMITED);
}

/* ------------------------- the tests ------------------------------------ */

static void test_defaults(mmt_handler_t *h) {
    fprintf(stderr, "  test: stock defaults == MMT_DPI_PROFILE_DEFAULT\n");
    CHECK(h->hostname_classify == 1, "hostname classification on by default");
    CHECK(h->ip_address_classify == 1, "IP-range classification on by default");
    CHECK(h->port_classify == 0, "port classification off by default");
    CHECK(h->classification_max_depth == DEPTH_UNLIMITED,
          "inspection depth unlimited by default");
    /* the constant really is the stock configuration */
    CHECK(MMT_DPI_PROFILE_DEFAULT.classification_max_depth == DEPTH_UNLIMITED,
          "DEFAULT profile depth is unlimited");
    CHECK(MMT_DPI_PROFILE_DEFAULT.app_protocol_classify == 1 &&
          MMT_DPI_PROFILE_DEFAULT.port_classify == 0 &&
          MMT_DPI_PROFILE_DEFAULT.ip_address_classify == 1,
          "DEFAULT profile mirrors the stock flags");
    CHECK(get_classification_max_depth(h) == DEPTH_UNLIMITED,
          "getter returns the bound");
    CHECK(get_classification_max_depth(NULL) == 0, "getter on NULL handler");
}

static void test_apply_struct(mmt_handler_t *h) {
    fprintf(stderr, "  test: mmt_apply_dpi_profile\n");
    CHECK(mmt_apply_dpi_profile(h, &MMT_DPI_PROFILE_MINIMAL) == 1, "apply minimal");
    CHECK(h->classification_max_depth == 3 && h->hostname_classify == 0 &&
          h->ip_address_classify == 0 && h->port_classify == 0,
          "minimal profile flags applied");

    CHECK(mmt_apply_dpi_profile(h, &MMT_DPI_PROFILE_FULL) == 1, "apply full");
    CHECK(h->classification_max_depth == DEPTH_UNLIMITED &&
          h->hostname_classify == 1 && h->ip_address_classify == 1 &&
          h->port_classify == 1, "full profile flags applied");

    mmt_dpi_profile_t custom = { 7, 0, 1, 1 };
    CHECK(mmt_apply_dpi_profile(h, &custom) == 1, "apply caller-built profile");
    CHECK(h->classification_max_depth == 7 && h->hostname_classify == 0 &&
          h->port_classify == 1 && h->ip_address_classify == 1,
          "custom profile flags applied");

    CHECK(mmt_apply_dpi_profile(h, NULL) == 0, "NULL profile rejected");
    CHECK(mmt_apply_dpi_profile(NULL, &custom) == 0, "NULL handler rejected");

    /* out-of-range values are clamped/normalised, not stored raw */
    mmt_dpi_profile_t wild = { 200, 5, 9, 255 };
    CHECK(mmt_apply_dpi_profile(h, &wild) == 1, "wild profile applied");
    CHECK(h->classification_max_depth == DEPTH_UNLIMITED,
          "depth clamps to the ceiling");
    CHECK(h->hostname_classify == 1 && h->port_classify == 1 &&
          h->ip_address_classify == 1, "toggles normalise to 0/1");
    CHECK(mmt_apply_dpi_profile(h, &MMT_DPI_PROFILE_DEFAULT) == 1,
          "restore defaults");
}

static void test_apply_by_name(mmt_handler_t *h) {
    fprintf(stderr, "  test: mmt_apply_dpi_profile_by_name\n");
    CHECK(mmt_apply_dpi_profile_by_name(h, "minimal") == 1, "name: minimal");
    CHECK(h->classification_max_depth == 3 && h->hostname_classify == 0,
          "minimal applied by name");
    CHECK(mmt_apply_dpi_profile_by_name(h, "FULL") == 1,
          "names are case-insensitive");
    CHECK(h->port_classify == 1, "full applied by name");
    CHECK(mmt_apply_dpi_profile_by_name(h, "balanced") == 1, "name: balanced");
    CHECK(h->classification_max_depth == 5 && h->port_classify == 0 &&
          h->hostname_classify == 1, "balanced flags applied");
    CHECK(mmt_apply_dpi_profile_by_name(h, "default") == 1, "name: default");
    CHECK(h->classification_max_depth == DEPTH_UNLIMITED,
          "default restored by name");
    CHECK(mmt_apply_dpi_profile_by_name(h, "does-not-exist") == 0,
          "unknown name rejected");
    CHECK(mmt_apply_dpi_profile_by_name(h, NULL) == 0, "NULL name rejected");
    CHECK(mmt_apply_dpi_profile_by_name(NULL, "minimal") == 0,
          "NULL handler rejected");
}

static void test_depth_setter(mmt_handler_t *h) {
    fprintf(stderr, "  test: set/get_classification_max_depth\n");
    CHECK(set_classification_max_depth(h, 4) == 1, "set depth 4");
    CHECK(get_classification_max_depth(h) == 4, "depth 4 stored");
    CHECK(set_classification_max_depth(h, 255) == 1, "set depth 255");
    CHECK(get_classification_max_depth(h) == DEPTH_UNLIMITED,
          "depth clamps to unlimited");
    CHECK(set_classification_max_depth(h, 0) == 1, "depth 0 is a legal bound");
    CHECK(get_classification_max_depth(h) == 0, "depth 0 stored");
    CHECK(set_classification_max_depth(NULL, 4) == 0, "NULL handler rejected");
    CHECK(set_classification_max_depth(h, DEPTH_UNLIMITED) == 1, "restore");
}

/* One packet through the fake chain under a given depth bound. */
static int run_one_packet(mmt_handler_t *h) {
    pkthdr_t hdr;
    u_char pkt[128];
    make_packet(&hdr, pkt, sizeof(pkt));
    g_checker_calls = 0;
    CHECK(packet_process(h, &hdr, pkt) == 1, "packet processed");
    return path_len(h);
}

static void test_depth_gate(mmt_handler_t *h) {
    fprintf(stderr, "  test: classification_max_depth gates the walk\n");

    /* full chain META,L1,L2,L3,L4 = len 5 when unbounded */
    set_classification_max_depth(h, DEPTH_UNLIMITED);
    CHECK(run_one_packet(h) == 5, "unbounded: all 5 path entries");

    set_classification_max_depth(h, 3);
    CHECK(run_one_packet(h) == 4, "depth 3: path stops at L3");
    CHECK(h->last_received_packet.proto_hierarchy.proto_path[3] == TEST_PROTO_L3,
          "L3 recorded as the deepest layer");

    set_classification_max_depth(h, 1);
    CHECK(run_one_packet(h) == 2, "depth 1: only META + link layer");

    /* the out-of-band append path honours the same bound */
    set_classification_max_depth(h, 0);
    CHECK(run_one_packet(h) == 1, "depth 0: META only");
    CHECK(g_checker_calls == 0,
          "depth 0: no checker dispatched — the whole walk is skipped");

    /* no-session packet: hierarchy resets per packet, bound reapplies */
    set_classification_max_depth(h, 2);
    CHECK(run_one_packet(h) == 3, "depth 2: META + two layers");
    CHECK(run_one_packet(h) == 3, "bound is stable across packets");

    /* profile application reaches the same gate through the struct */
    CHECK(mmt_apply_dpi_profile(h, &MMT_DPI_PROFILE_MINIMAL) == 1,
          "apply minimal for gate check");
    CHECK(run_one_packet(h) == 4, "minimal profile caps at depth 3");

    set_classification_max_depth(h, DEPTH_UNLIMITED);
}

static void test_profiles_file(mmt_handler_t *h) {
    fprintf(stderr, "  test: mmt_load_dpi_profiles_file\n");
    char tmpl[] = "/tmp/mmt_dpi_profiles_XXXXXX";
    int fd = mkstemp(tmpl);
    CHECK(fd >= 0, "mkstemp for profiles file");
    if (fd < 0) return;
    FILE *fp = fdopen(fd, "w");
    CHECK(fp != NULL, "fdopen profiles file");
    if (fp == NULL) { unlink(tmpl); return; }
    fprintf(fp,
            "# a comment line\n"
            "\n"
            "edge 4 1 0 0\n"
            "  \n"
            "minimal 9 9 9 9   # predefined name - skipped\n"
            "broken 4 1 0\n"   /* too few fields - skipped */
            "badflags 4 2 0 0\n"
            "deep 99 0 1 0\n"
            "edge 5 1 1 1\n"); /* duplicate name - skipped */
    fclose(fp);

    CHECK(mmt_load_dpi_profiles_file(tmpl) == 2, "two valid profiles loaded");
    CHECK(mmt_apply_dpi_profile_by_name(h, "edge") == 1, "custom name applies");
    CHECK(h->classification_max_depth == 4 && h->hostname_classify == 1 &&
          h->port_classify == 0 && h->ip_address_classify == 0,
          "custom profile values applied");
    CHECK(mmt_apply_dpi_profile_by_name(h, "deep") == 1, "deep applies");
    CHECK(h->classification_max_depth == DEPTH_UNLIMITED,
          "file depth 99 clamps to unlimited");
    /* the reserved-name and duplicate lines were refused, not shadowed */
    CHECK(mmt_apply_dpi_profile_by_name(h, "minimal") == 1,
          "predefined name still resolves to the built-in");
    CHECK(h->classification_max_depth == 3 && h->port_classify == 0,
          "predefined minimal not shadowed by the file");
    CHECK(mmt_apply_dpi_profile(h, &MMT_DPI_PROFILE_DEFAULT) == 1, "restore");

    CHECK(mmt_load_dpi_profiles_file(tmpl) == 0,
          "reloading the same names loads nothing new");
    CHECK(mmt_load_dpi_profiles_file("/nonexistent/nope.txt") == -1,
          "missing file reports -1");
    CHECK(mmt_load_dpi_profiles_file(NULL) == 0, "NULL path is a no-op");
    unlink(tmpl);
}

static void test_env(char errbuf[256]) {
    fprintf(stderr, "  test: MMT_DPI_PROFILE(S)_FILE env selection\n");

    setenv("MMT_DPI_PROFILE", "minimal", 1);
    mmt_handler_t *h = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    CHECK(h != NULL, "handler init under env");
    if (h != NULL) {
        CHECK(h->classification_max_depth == 3 && h->hostname_classify == 0 &&
              h->port_classify == 0 && h->ip_address_classify == 0,
              "env-selected minimal profile applied at init");
        mmt_close_handler(h);
    }
    unsetenv("MMT_DPI_PROFILE");

    /* unknown env name: handler keeps the stock defaults */
    setenv("MMT_DPI_PROFILE", "bogus-name", 1);
    h = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    CHECK(h != NULL, "handler init under bogus env");
    if (h != NULL) {
        CHECK(h->classification_max_depth == DEPTH_UNLIMITED &&
              h->hostname_classify == 1 && h->ip_address_classify == 1 &&
              h->port_classify == 0, "unknown env profile keeps defaults");
        mmt_close_handler(h);
    }
    unsetenv("MMT_DPI_PROFILE");

    /* profiles file loaded via env, name applied in the same init */
    char tmpl[] = "/tmp/mmt_dpi_profiles_env_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) { CHECK(0, "mkstemp env profiles file"); return; }
    FILE *fp = fdopen(fd, "w");
    if (fp == NULL) { unlink(tmpl); CHECK(0, "fdopen env profiles file"); return; }
    fprintf(fp, "envprof 6 0 1 0\n");
    fclose(fp);
    setenv("MMT_DPI_PROFILES_FILE", tmpl, 1);
    setenv("MMT_DPI_PROFILE", "envprof", 1);
    h = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    if (h != NULL) {
        CHECK(h->classification_max_depth == 6 && h->hostname_classify == 0 &&
              h->port_classify == 1 && h->ip_address_classify == 0,
              "env file profile applied at init");
        mmt_close_handler(h);
    } else {
        CHECK(0, "handler init under env file");
    }
    unsetenv("MMT_DPI_PROFILES_FILE");
    unsetenv("MMT_DPI_PROFILE");
    unlink(tmpl);
}

int main(void) {
    fprintf(stderr, "dpi_profiles: named DPI profiles + depth bound\n");
    char errbuf[256];

    CHECK(init_extraction() == 1, "init_extraction succeeds");
    CHECK(register_protocol_stack(TEST_STACK_ID, (char *) "dpi_stack",
                                  test_stack_classify) == 1,
          "register test stack");
    /* Each of L1..L3 carries the chain checker: at layer index i it appends
     * proto 620+i at index+1, so the path hops one layer per classify_next
     * call and len after a packet == deepest honoured index + 1. */
    CHECK(register_layer(TEST_PROTO_L1, "dpi_l1", test_chain_checker) != NULL,
          "L1 checker registered");
    CHECK(register_layer(TEST_PROTO_L2, "dpi_l2", test_chain_checker) != NULL,
          "L2 checker registered");
    CHECK(register_layer(TEST_PROTO_L3, "dpi_l3", test_chain_checker) != NULL,
          "L3 checker registered");
    CHECK(register_layer(TEST_PROTO_L4, "dpi_l4", test_oob_checker) != NULL,
          "L4 checker registered");

    errbuf[0] = '\0';
    mmt_handler_t *h = mmt_init_handler(TEST_STACK_ID, 0, errbuf);
    CHECK(h != NULL, "mmt_init_handler succeeds");
    if (h == NULL) {
        fprintf(stderr, "  init error: %s\n", errbuf);
        return 1;
    }

    test_defaults(h);
    test_apply_struct(h);
    test_apply_by_name(h);
    test_depth_setter(h);
    test_append_gate(h);
    test_depth_gate(h);
    test_profiles_file(h);
    test_env(errbuf);

    mmt_close_handler(h);
    close_extraction(); /* void return — reaching here is the assertion */

    if (g_failures == 0) {
        fprintf(stderr, "  all checks passed\n");
        return 0;
    }
    fprintf(stderr, "  %d check(s) FAILED\n", g_failures);
    return 1;
}

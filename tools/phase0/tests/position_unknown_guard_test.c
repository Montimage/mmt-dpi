/*
 * position_unknown_guard_test — regression + coverage test for issue #193
 * (F-BUG-032): the central caplen guard in internal_extract_attribute()
 * (src/mmt_core/src/packet_processing.c) must apply to POSITION_NOT_KNOWN
 * attributes, not only to fixed-offset ones.
 *
 * Before the fix the guard was gated on `position_in_packet >= 0`, and
 * POSITION_NOT_KNOWN is -1 — so every variable-offset extractor (the ones
 * that compute their own offsets and read deepest: SMB, GRE, RTP, DNS, TLS,
 * QUIC, ...) received no bounds validation at all. The fix requires
 *   proto_offset + declared data_len <= caplen
 * as a floor for POSITION_NOT_KNOWN attributes too, evaluated through the
 * greppable mmt_have_bytes() helper (src/mmt_core/private_include/
 * packet_processing.h).
 *
 * Part 1 (unit) drives internal_extract_attribute() directly with crafted
 * attribute_internal_struct / ipacket_t instances — exactly what
 * register_extraction_attribute() produces — so no protocol registry or
 * plugin init is needed. The sentinel extraction function records whether
 * it ran: on the pre-fix tree every refused case below reaches the sentinel
 * (the test fails); post-fix the guard returns 0 first.
 *
 * Part 2 (corpus) replays the vendored golden pcap subset
 * (tools/phase0/ci/pcaps/) through a handler that registers an attribute
 * handler for every attribute of every registered protocol, then asserts
 * the debug-build tripwire counters in packet_processing.c: attributes that
 * reached an extractor with no caplen validation == 0, out of a non-zero
 * total. The counters are armed in assert-enabled / sanitizer-instrumented
 * builds — the runner builds the SDK with BUILD=asan, which doubles as a
 * memory-safety check on every extractor the corpus exercises.
 *
 * Build (see run_position_unknown_guard_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -o position_unknown_guard_test position_unknown_guard_test.c \
 *       -I<prefix>/dpi/include -Isrc/mmt_core/public_include \
 *       -Isrc/mmt_core/private_include \
 *       -L<prefix>/dpi/lib -lmmt_tcpip -lmmt_core -ldl -lpthread -lm -lpcap
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <dirent.h>

#include <pcap.h>            /* pcap_open_offline, pcap_datalink, pcap_next */

#include "mmt_core.h"
/* attribute_internal_struct + mmt_handler_struct live in the in-tree private
 * header; the layout matches the compiled library byte-for-byte (same
 * headers, same flags). */
#include "packet_processing.h"

/* internal_extract_attribute() and the mmt_caplen_guard_* accessors are
 * exported non-static but absent from the installed public headers — they
 * come from the shared internal header (issue #186 convention). The counter
 * accessors are additionally declared weak so this binary also links against
 * a library predating them: a NULL address then means "counters not armed",
 * which the corpus checks report as a failure rather than passing vacuously. */
#include "internal_decls.h"
extern uint64_t mmt_caplen_guard_total_count(void) __attribute__((weak));
extern uint64_t mmt_caplen_guard_refused_count(void) __attribute__((weak));
extern uint64_t mmt_caplen_guard_unvalidated_count(void) __attribute__((weak));
extern void mmt_caplen_guard_stats_reset(void) __attribute__((weak));

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

/* -------------------------------------------------------------------------
 * Part 1 — unit: crafted attribute + packet through internal_extract_attribute
 * ------------------------------------------------------------------------- */

static int g_extract_calls = 0;

/* Sentinel extraction function: records that it ran, then reports success so
 * the success path (status / packet_id writes) is exercised too. */
static int sentinel_extraction(const ipacket_t *packet, unsigned proto_index,
        attribute_t *extracted_data) {
    (void)packet; (void)proto_index; (void)extracted_data;
    g_extract_calls++;
    return 1;
}

/* A heap-allocated, exactly-sized captured buffer (ASan brackets it) plus the
 * ipacket wiring internal_extract_attribute() reads: p_hdr, data,
 * proto_headers_offset (per-layer header sizes — get_packet_offset_at_index()
 * sums them), proto_hierarchy and a zeroed mmt_handler for the success path. */
typedef struct {
    ipacket_t pkt;
    proto_hierarchy_t offsets;
    proto_hierarchy_t hier;
    pkthdr_t hdr;
    mmt_handler_t *hdlr;
    u_char *buf;
} fixture_t;

static void fixture_init(fixture_t *f, const int *layer_sizes, int nlayers,
        unsigned caplen, unsigned wirelen) {
    memset(f, 0, sizeof(*f));
    f->buf = (u_char *)malloc(caplen ? caplen : 1);
    if (!f->buf) { perror("malloc"); exit(2); }
    memset(f->buf, 0, caplen ? caplen : 1);
    f->hdlr = (mmt_handler_t *)calloc(1, sizeof(mmt_handler_t));
    if (!f->hdlr) { perror("calloc"); exit(2); }
    int i;
    for (i = 0; i < nlayers && i < PROTO_PATH_SIZE; i++) {
        f->offsets.proto_path[i] = layer_sizes[i];
        f->hier.proto_path[i] = 1; /* any proto id — the guard never reads it */
    }
    f->offsets.len = f->hier.len = nlayers;
    f->hdr.caplen = caplen;
    f->hdr.len = wirelen;
    f->pkt.p_hdr = &f->hdr;
    f->pkt.data = f->buf;
    f->pkt.proto_headers_offset = &f->offsets;
    f->pkt.proto_hierarchy = &f->hier;
    f->pkt.internal_cumulative_offset_valid = 0;
    f->pkt.mmt_handler = f->hdlr;
}

static void fixture_free(fixture_t *f) {
    free(f->buf);
    free(f->hdlr);
}

static void make_attr(struct attribute_internal_struct *a, int position, int data_len) {
    memset(a, 0, sizeof(*a));
    a->proto_id = 1;
    a->field_id = 7;
    a->position_in_packet = position;
    a->data_len = data_len;
    a->extraction_function = sentinel_extraction;
    a->status = ATTRIBUTE_UNSET;
}

/* Run one case: returns internal_extract_attribute()'s result; g_extract_calls
 * delta tells whether the extractor actually ran. */
static int run_case(fixture_t *f, struct attribute_internal_struct *a,
        unsigned index, int *extractor_ran) {
    int before = g_extract_calls;
    int r = internal_extract_attribute(&f->pkt, a, index);
    *extractor_ran = (g_extract_calls != before);
    return r;
}

static void test_unit_guard(void) {
    printf("[#193] central caplen guard — crafted attributes\n");

    /* caplen = 60 captured bytes of a 100-byte wire packet; the protocol at
     * index 2 starts at absolute offset 14 + 20 + 6 = 40, leaving exactly
     * 20 captured bytes for it. */
    const int layers_in[3]  = { 14, 20, 6 };   /* proto_offset = 40 */
    const int layers_past[3] = { 14, 20, 40 }; /* proto_offset = 74 > caplen */

    fixture_t f;
    struct attribute_internal_struct a;
    int ran, r;

    /* --- refused cases (all red on the pre-fix tree) --- */

    /* POSITION_NOT_KNOWN attr declaring 30 bytes when only 20 are captured:
     * proto_offset(40) + data_len(30) = 70 > caplen(60) — must be refused. */
    fixture_init(&f, layers_in, 3, 60, 100);
    make_attr(&a, POSITION_NOT_KNOWN, 30);
    r = run_case(&f, &a, 2, &ran);
    CHECK(r == 0 && !ran,
          "POSITION_NOT_KNOWN attr with declared extent past caplen is refused");
    fixture_free(&f);

    /* Same, with a declared length beyond the whole capture. */
    fixture_init(&f, layers_in, 3, 60, 100);
    make_attr(&a, POSITION_NOT_KNOWN, 100);
    r = run_case(&f, &a, 2, &ran);
    CHECK(r == 0 && !ran,
          "POSITION_NOT_KNOWN attr declaring more than caplen is refused");
    fixture_free(&f);

    /* POSITION_NOT_KNOWN attr on a protocol whose offset is past caplen
     * (truncated capture): even with no declared length, no captured byte of
     * the protocol exists — must be refused. */
    fixture_init(&f, layers_past, 3, 60, 100);
    make_attr(&a, POSITION_NOT_KNOWN, 0);
    r = run_case(&f, &a, 2, &ran);
    CHECK(r == 0 && !ran,
          "POSITION_NOT_KNOWN attr at proto_offset >= caplen is refused");
    fixture_free(&f);

    /* Fixed-offset attribute whose declared position lands past caplen:
     * refused too (pre-existing F-BUG-001 coverage kept as a control). */
    fixture_init(&f, layers_in, 3, 60, 100);
    make_attr(&a, 25, 10); /* 40 + 25 + 10 = 75 > 60 */
    r = run_case(&f, &a, 2, &ran);
    CHECK(r == 0 && !ran,
          "fixed-offset attr reading past caplen is refused (control)");
    fixture_free(&f);

    /* --- allowed cases (extractor must run) --- */

    /* POSITION_NOT_KNOWN attr declaring exactly the captured remainder:
     * 40 + 20 = 60 <= caplen — the floor is met, extraction proceeds. */
    fixture_init(&f, layers_in, 3, 60, 100);
    make_attr(&a, POSITION_NOT_KNOWN, 20);
    r = run_case(&f, &a, 2, &ran);
    CHECK(r == 1 && ran,
          "POSITION_NOT_KNOWN attr inside caplen is extracted");
    fixture_free(&f);

    /* POSITION_NOT_KNOWN attr with no declared length on a protocol that has
     * captured bytes: allowed. */
    fixture_init(&f, layers_in, 3, 60, 100);
    make_attr(&a, POSITION_NOT_KNOWN, 0);
    r = run_case(&f, &a, 2, &ran);
    CHECK(r == 1 && ran,
          "POSITION_NOT_KNOWN attr with no declared length inside caplen is extracted");
    fixture_free(&f);

    /* Fixed-offset attribute fully inside caplen: allowed. */
    fixture_init(&f, layers_in, 3, 60, 100);
    make_attr(&a, 5, 15); /* 40 + 5 + 15 = 60 <= 60 */
    r = run_case(&f, &a, 2, &ran);
    CHECK(r == 1 && ran,
          "fixed-offset attr inside caplen is extracted (control)");
    fixture_free(&f);
}

/* -------------------------------------------------------------------------
 * Part 2 — corpus: every attribute of every protocol over the golden pcaps
 * ------------------------------------------------------------------------- */

static void noop_attr_handler(const ipacket_t *ipacket, attribute_t *attribute,
        void *user_args) {
    (void)ipacket; (void)attribute; (void)user_args;
}

typedef struct {
    mmt_handler_t *hdlr;
    unsigned long registered;      /* attribute handlers successfully registered */
    unsigned long pos_unknown;     /*   of which declared POSITION_NOT_KNOWN */
    unsigned long skipped_null_fn; /*   skipped: metadata has no extraction_function */
} reg_ctx_t;

static void reg_attr_cb(attribute_metadata_t *attr, uint32_t proto_id, void *args) {
    reg_ctx_t *c = (reg_ctx_t *)args;
    if (attr == NULL) return;
    /* Some metadata entries declare no extraction_function at all (e.g. the
     * tail entries of http_attributes_info in src/mmt_tcpip/lib/protocols/
     * http.c). Registering one would leave a NULL call target in the
     * registered attribute — a pre-existing latent crash, out of scope here. */
    if (attr->extraction_function == NULL) {
        c->skipped_null_fn++;
        return;
    }
    if (register_attribute_handler(c->hdlr, proto_id, (uint32_t)attr->id,
            noop_attr_handler, NULL, NULL) == 1) {
        c->registered++;
        if (attr->position_in_packet == POSITION_NOT_KNOWN) c->pos_unknown++;
    }
}

static void reg_proto_cb(uint32_t proto_id, void *args) {
    iterate_through_protocol_attributes(proto_id, reg_attr_cb, args);
}

static int g_pcaps_seen = 0;
static int g_pcaps_replayed = 0;
static unsigned long g_packets = 0;
static reg_ctx_t g_reg;

/* Replay one pcap through a fresh handler with every attribute registered. */
static int replay_pcap(const char *path) {
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    char mmt_errbuf[1024];
    pcap_t *pcap;
    mmt_handler_t *hdlr;
    const u_char *data;
    struct pcap_pkthdr p_pkthdr;
    struct pkthdr header;
    int datalink;

    g_pcaps_seen++;
    pcap = pcap_open_offline(path, pcap_errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_offline(%s) failed: %s\n", path, pcap_errbuf);
        return -1;
    }
    datalink = pcap_datalink(pcap);

    hdlr = mmt_init_handler((uint32_t)datalink, 0, mmt_errbuf);
    if (hdlr == NULL) {
        /* Unsupported link-type is a stable boundary, not a failure — the
         * same stance tcpip_pcap_harness takes. */
        fprintf(stderr, "<unsupported link-type %s: %s>\n", path, mmt_errbuf);
        pcap_close(pcap);
        return 0;
    }

    memset(&g_reg, 0, sizeof(g_reg));
    g_reg.hdlr = hdlr;
    iterate_through_protocols(reg_proto_cb, &g_reg);

    memset(&header, 0, sizeof(header));
    while ((data = pcap_next(pcap, &p_pkthdr)) != NULL) {
        header.ts = p_pkthdr.ts;
        header.caplen = p_pkthdr.caplen;
        header.len = p_pkthdr.len;
        packet_process(hdlr, &header, data);
        g_packets++;
    }

    mmt_close_handler(hdlr);
    pcap_close(pcap);
    g_pcaps_replayed++;
    return 0;
}

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Replay every *.pcap directly under dir (sorted for determinism). */
static int replay_dir(const char *dir) {
    DIR *d = opendir(dir);
    if (d == NULL) {
        fprintf(stderr, "opendir(%s) failed\n", dir);
        return -1;
    }
    char **names = NULL;
    size_t n = 0, cap = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t len = strlen(de->d_name);
        if (len < 5 || strcmp(de->d_name + len - 5, ".pcap") != 0) continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 16;
            names = (char **)realloc(names, cap * sizeof(char *));
            if (!names) { perror("realloc"); closedir(d); exit(2); }
        }
        names[n++] = strdup(de->d_name);
    }
    closedir(d);
    qsort(names, n, sizeof(char *), cmp_str);

    int rc = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        size_t pathlen = strlen(dir) + strlen(names[i]) + 2;
        char *path = (char *)malloc(pathlen);
        if (!path) { perror("malloc"); exit(2); }
        snprintf(path, pathlen, "%s/%s", dir, names[i]);
        if (replay_pcap(path) != 0) rc = -1;
        free(path);
        free(names[i]);
    }
    free(names);
    return rc;
}

static void test_corpus(const char *pcap_dir) {
    printf("[#193] golden-corpus coverage — every registered attribute extracted\n");

    /* init_extraction() loads the protocol plugins and registers every tcpip
     * protocol; it must run from the install prefix so the CWD-relative
     * "plugins/" lookup resolves (see the runner script). */
    if (!init_extraction()) {
        fprintf(stderr, "init_extraction failed\n");
        exit(2);
    }

    int rc = replay_dir(pcap_dir);

    CHECK(rc == 0, "every golden pcap replayed without harness error");
    CHECK(g_pcaps_replayed > 0 && g_pcaps_replayed == g_pcaps_seen,
          "all vendored golden pcaps replayed");
    CHECK(g_packets > 0, "corpus produced packets");
    CHECK(g_reg.registered > 0,
          "attribute handlers registered (extraction actually exercised)");
    CHECK(g_reg.pos_unknown > 0,
          "POSITION_NOT_KNOWN attributes among the registered set");

    CHECK(mmt_caplen_guard_total_count != NULL
          && mmt_caplen_guard_refused_count != NULL
          && mmt_caplen_guard_unvalidated_count != NULL,
          "caplen-guard counter symbols present in the SDK under test");

    uint64_t total = mmt_caplen_guard_total_count
        ? mmt_caplen_guard_total_count() : 0;
    uint64_t refused = mmt_caplen_guard_refused_count
        ? mmt_caplen_guard_refused_count() : 0;
    uint64_t unvalidated = mmt_caplen_guard_unvalidated_count
        ? mmt_caplen_guard_unvalidated_count() : 0;

    printf("  guard counters: total=%llu refused=%llu unvalidated=%llu\n",
           (unsigned long long)total, (unsigned long long)refused,
           (unsigned long long)unvalidated);

    /* The counters are only armed in assert-enabled / sanitizer builds; a 0
     * total means the library under test was built without them — fail loudly
     * rather than pass vacuously. */
    CHECK(total > 0, "caplen-guard counters armed (instrumented SDK build)");
    CHECK(unvalidated == 0,
          "0 attributes reached an extractor with no caplen validation");

    close_extraction();
}

int main(int argc, char **argv) {
    printf("=== POSITION_NOT_KNOWN caplen-guard test (issue #193) ===\n");
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <golden-pcap-dir>\n", argv[0]);
        return 2;
    }

    test_unit_guard();
    test_corpus(argv[1]);

    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}

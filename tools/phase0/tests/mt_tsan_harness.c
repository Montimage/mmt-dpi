/**
 * mt_tsan_harness — multi-threaded thread-safety harness for Phase 6 (issue #65).
 *
 * Mechanically verifies the Phase 6 thread-safety work that was previously
 * "verified by construction" only:
 *   - #22  global registry mutexes (configured_protocols_mutex in
 *          packet_processing.c, plugin_handlers_list_mutex in plugins_engine.c)
 *   - #23  per-session RADIUS parser state (proto_radius.c)
 *   - #67  configured_handlers_map_mutex guarding the global handler bookkeeping
 *          map (mmt_configured_handlers_map) in packet_processing.c
 *
 * ThreadSanitizer only detects races in code built with -fsanitize=thread, so
 * this program is meant to be compiled AND linked against a BUILD=tsan SDK
 * (see tools/phase0/tests/run_mt_tsan_test.sh). A clean TSan run is the gate.
 *
 * Three modes (selected by argv[1]):
 *
 *   replay <file.pcap> [num_threads]   (default mode if argv[1] is a path)
 *       Honours the documented threading contract (docs/THREADING.md): all
 *       initialisation happens on the main thread before any worker starts -
 *       init_extraction(), and one OWN mmt_handler_t created per worker - then
 *       the workers run concurrently, each replaying the SAME read-only packet
 *       array through its own handler (the lock-free per-packet hot path). Each
 *       worker builds an order-independent classification fingerprint; the
 *       harness asserts every worker's fingerprint equals a single-thread
 *       baseline. Replaying a multi-flow RADIUS pcap exercises the per-session
 *       RADIUS parser state (#23) concurrently across threads.
 *
 *       NOTE: handlers are created on the main thread (the primary
 *       init-before-workers pattern in docs/THREADING.md) rather than inside the
 *       workers, so this mode exercises only the lock-free hot path. The
 *       concurrent create/destroy path itself is exercised by handler-churn
 *       mode (#67) below.
 *
 *   handler-churn [num_threads] [iterations]
 *       Spawns N threads that concurrently create AND destroy their own
 *       mmt_handler_t in a loop (mmt_init_handler() / mmt_close_handler()),
 *       hammering the global handler bookkeeping map (mmt_configured_handlers_map)
 *       which is guarded by configured_handlers_map_mutex (#67). Each iteration
 *       also registers a packet handler so the handler is fully wired before
 *       teardown. Without the #67 lock, the concurrent insert_key_value /
 *       delete_key_value mutations of the global map are a data race that TSan
 *       flags here; with it, the run is clean. init_extraction()/close_extraction()
 *       still bracket the run on the main thread (the map alloc/free stays
 *       single-threaded per the contract).
 *
 *       This mode also exercises the COLD concurrent-create path (#69):
 *       mmt_init_handler() enables analysis/classification for every protocol
 *       (enable_protocol_analysis / enable_protocol_classification write the
 *       analysis_enabled / classify_enabled switches — fields read lock-free on
 *       the per-packet hot path, so they cannot be mutex-guarded without
 *       defeating the lock-free read design). The workers are the FIRST callers
 *       after init_extraction() (no main-thread warmup), so they run those
 *       writes concurrently from cold. PR #68 dodged this with a warmup handler
 *       that finalised the flags single-threaded; #69 made the flag accesses
 *       atomic (relaxed) instead, and #549 moved the switches from the SHARED
 *       global protocol descriptors into each handler's own snapshot, so this
 *       mode proves the cold path is race-free.
 *
 *   registry-stress [num_threads] [iterations]
 *       Spawns N threads that concurrently HAMMER the global-registry mutation
 *       API (unregister_protocol_by_id / unregister_protocol_by_name), which is
 *       guarded by configured_protocols_mutex (#22). This is INTENTIONALLY NOT
 *       the normal runtime pattern — the documented contract completes all
 *       (un)registration before workers run. We drive the lock directly so that
 *       TSan can confirm the mutex actually serialises the registry mutations
 *       (without it, the concurrent writes to configured_protocols[i]->is_registered
 *       would be a data race). Only mutex-guarded mutation calls are made
 *       concurrently here; no unlocked reader runs alongside, so a TSan report in
 *       this mode would indicate a genuine missing/incorrect lock in #22. This
 *       mode corrupts the is_registered flags on purpose and is therefore run as
 *       its own throwaway process.
 *
 * Usage:
 *   mt_tsan_harness replay <file.pcap> [num_threads]
 *   mt_tsan_harness registry-stress [num_threads] [iterations]
 *   mt_tsan_harness handler-churn [num_threads] [iterations]
 *
 * Returns 0 on success, non-zero on any fingerprint mismatch or error (and TSan,
 * built with -fno-sanitize-recover=all, aborts the process on any detected race).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <pcap.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

#define MAX_PATH_STR    512
#define MAX_DISTINCT    4096
#define MAX_THREADS     64

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
/* Classification fingerprint (order-independent, per handler/thread).        */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

typedef struct {
    char          path[MAX_PATH_STR];
    unsigned long count;
} path_entry_t;

typedef struct {
    path_entry_t entries[MAX_DISTINCT];
    int          n;
} fingerprint_t;

static void fp_record(fingerprint_t *fp, const char *path) {
    int i;
    for (i = 0; i < fp->n; i++) {
        if (strcmp(fp->entries[i].path, path) == 0) {
            fp->entries[i].count++;
            return;
        }
    }
    if (fp->n >= MAX_DISTINCT) {
        fprintf(stderr, "mt_tsan_harness: distinct-path table full (%d)\n",
                MAX_DISTINCT);
        return;
    }
    snprintf(fp->entries[fp->n].path, MAX_PATH_STR, "%s", path);
    fp->entries[fp->n].count = 1;
    fp->n++;
}

static int fp_cmp_entry(const void *a, const void *b) {
    return strcmp(((const path_entry_t *)a)->path,
                  ((const path_entry_t *)b)->path);
}

static void fp_sort(fingerprint_t *fp) {
    qsort(fp->entries, fp->n, sizeof(fp->entries[0]), fp_cmp_entry);
}

/* Returns 0 if identical, non-zero otherwise (and prints a diff to stderr). */
static int fp_compare(const fingerprint_t *a, const fingerprint_t *b,
                      const char *label) {
    int i;
    int diff = 0;
    if (a->n != b->n) {
        fprintf(stderr, "[%s] distinct-path count differs: baseline=%d worker=%d\n",
                label, a->n, b->n);
        diff = 1;
    }
    {
        int n = (a->n < b->n) ? a->n : b->n;
        for (i = 0; i < n; i++) {
            if (strcmp(a->entries[i].path, b->entries[i].path) != 0 ||
                a->entries[i].count != b->entries[i].count) {
                fprintf(stderr, "[%s] mismatch at %d: baseline {%lu %s} worker {%lu %s}\n",
                        label, i,
                        a->entries[i].count, a->entries[i].path,
                        b->entries[i].count, b->entries[i].path);
                diff = 1;
            }
        }
    }
    return diff;
}

/* The packet handler aggregates into the fingerprint passed via user_args. */
static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    fingerprint_t *fp = (fingerprint_t *)user_args;
    char path[MAX_PATH_STR];
    int  len = 0;
    int  i;
    const proto_hierarchy_t *ph = ipacket->proto_hierarchy;

    if (ph == NULL || ph->len <= 0) {
        fp_record(fp, "<none>");
        return 0;
    }
    path[0] = '\0';
    for (i = 0; i < ph->len && i < PROTO_PATH_SIZE; i++) {
        const char *name = get_protocol_name_by_id(ph->proto_path[i]);
        int n;
        if (name == NULL) name = "?";
        n = snprintf(path + len, sizeof(path) - len,
                     (i == 0) ? "%s" : ".%s", name);
        if (n < 0 || n >= (int)(sizeof(path) - len)) {
            len = sizeof(path) - 1;
            break;
        }
        len += n;
    }
    fp_record(fp, path);
    return 0;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
/* In-memory packet array (read-only, shared across replay workers).          */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

typedef struct {
    struct pkthdr  hdr;
    u_char        *data;
} mem_packet_t;

static mem_packet_t *g_packets = NULL;
static size_t        g_npackets = 0;
static int           g_datalink = 0;
static uint32_t      g_max_caplen = 0;

/* Load the whole pcap into memory so workers replay identical, read-only data. */
static int load_pcap(const char *path) {
    char    errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(path, errbuf);
    const u_char       *data;
    struct pcap_pkthdr  ph;
    size_t cap = 1024;

    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_offline(%s) failed: %s\n", path, errbuf);
        return -1;
    }
    g_datalink = pcap_datalink(pcap);
    g_packets = (mem_packet_t *)malloc(cap * sizeof(mem_packet_t));
    if (g_packets == NULL) { pcap_close(pcap); return -1; }

    while ((data = pcap_next(pcap, &ph)) != NULL) {
        if (g_npackets == cap) {
            cap *= 2;
            mem_packet_t *grown = (mem_packet_t *)realloc(g_packets,
                                                  cap * sizeof(mem_packet_t));
            if (grown == NULL) { pcap_close(pcap); return -1; }
            g_packets = grown;
        }
        memset(&g_packets[g_npackets].hdr, 0, sizeof(struct pkthdr));
        g_packets[g_npackets].hdr.ts     = ph.ts;
        g_packets[g_npackets].hdr.caplen = ph.caplen;
        g_packets[g_npackets].hdr.len    = ph.len;
        g_packets[g_npackets].data = (u_char *)malloc(ph.caplen);
        if (g_packets[g_npackets].data == NULL) { pcap_close(pcap); return -1; }
        memcpy(g_packets[g_npackets].data, data, ph.caplen);
        if (ph.caplen > g_max_caplen) g_max_caplen = ph.caplen;
        g_npackets++;
    }
    pcap_close(pcap);
    return 0;
}

static void free_pcap(void) {
    size_t i;
    for (i = 0; i < g_npackets; i++) free(g_packets[i].data);
    free(g_packets);
    g_packets = NULL;
    g_npackets = 0;
}

/* Replay all packets through the given handler using a PRIVATE per-call copy of
 * each packet's bytes. This is required because some parsers rewrite the packet
 * payload in place (e.g. mmt_check_radius byte-swaps the RADIUS length field),
 * so a buffer shared between threads/replays would be corrupted for the others.
 * Returns 0 on success, -1 on allocation failure. */
static int process_all(mmt_handler_t *h) {
    u_char *scratch = (u_char *)malloc(g_max_caplen ? g_max_caplen : 1);
    size_t  i;
    if (scratch == NULL) return -1;
    for (i = 0; i < g_npackets; i++) {
        struct pkthdr hdr = g_packets[i].hdr;
        memcpy(scratch, g_packets[i].data, g_packets[i].hdr.caplen);
        packet_process(h, &hdr, scratch);
    }
    free(scratch);
    return 0;
}

/* Replay all packets through one fresh handler, filling the fingerprint. */
static int replay_once(fingerprint_t *fp) {
    char           errbuf[1024];
    mmt_handler_t *h;

    memset(fp, 0, sizeof(*fp));
    h = mmt_init_handler(g_datalink, 0, errbuf);
    if (h == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        return -1;
    }
    register_packet_handler(h, 1, packet_handler, fp);
    if (process_all(h) != 0) {
        mmt_close_handler(h);
        return -1;
    }
    mmt_close_handler(h);
    fp_sort(fp);
    return 0;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
/* replay mode                                                                */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

typedef struct {
    int            tid;
    mmt_handler_t *handler;   /* created on the main thread before spawning */
    fingerprint_t  fp;
    int            rc;
} replay_worker_t;

/* Worker: replay the shared packet array through this worker's own handler.
 * Only the lock-free per-packet hot path runs concurrently here; handler
 * creation/teardown is done on the main thread (see run_replay). */
static void *replay_worker(void *arg) {
    replay_worker_t *w = (replay_worker_t *)arg;
    w->rc = process_all(w->handler);
    if (w->rc == 0) fp_sort(&w->fp);
    return NULL;
}

static int run_replay(const char *pcap_path, int num_threads) {
    /* fingerprint_t is large (~2 MB); keep these off the stack to avoid blowing
     * the thread stack — heap-allocate the baseline and the worker array. */
    fingerprint_t   *baseline;
    replay_worker_t *workers;
    pthread_t        threads[MAX_THREADS];
    int              t;
    int              failures = 0;

    if (num_threads < 1) num_threads = 1;
    if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;

    baseline = (fingerprint_t *)malloc(sizeof(*baseline));
    workers  = (replay_worker_t *)malloc((size_t)num_threads * sizeof(*workers));
    if (baseline == NULL || workers == NULL) {
        fprintf(stderr, "out of memory allocating fingerprints\n");
        free(baseline); free(workers);
        return EXIT_FAILURE;
    }

    init_extraction();

    if (load_pcap(pcap_path) != 0) {
        free(baseline); free(workers);
        close_extraction();
        return EXIT_FAILURE;
    }
    printf("[replay] %s: %zu packets, datalink %d, %d worker threads\n",
           pcap_path, g_npackets, g_datalink, num_threads);

    /* Single-thread baseline (on the main thread, before any worker starts). */
    if (replay_once(baseline) != 0) {
        free_pcap();
        free(baseline); free(workers);
        close_extraction();
        return EXIT_FAILURE;
    }
    printf("[replay] single-thread baseline: %d distinct protocol paths\n",
           baseline->n);

    /* Guard against a degenerate baseline: if the pcap failed to generate, was
     * empty, or nothing classified beyond "<none>", every worker would trivially
     * match an empty/garbage baseline and the run would PASS while exercising
     * none of the #22/#23 code. Require at least one real classified path. */
    {
        int real = 0, i;
        for (i = 0; i < baseline->n; i++) {
            if (strcmp(baseline->entries[i].path, "<none>") != 0) { real = 1; break; }
        }
        if (g_npackets == 0 || baseline->n == 0 || !real) {
            fprintf(stderr, "[replay] FAIL: degenerate baseline (%zu packets, "
                    "%d paths, real-classification=%d) — nothing exercised\n",
                    g_npackets, baseline->n, real);
            free_pcap();
            free(baseline); free(workers);
            close_extraction();
            return EXIT_FAILURE;
        }
    }

    /* Init-before-workers: create each worker's OWN handler on the main thread
     * (one handler per worker, per docs/THREADING.md) so that only the lock-free
     * hot path runs concurrently once the workers start. */
    for (t = 0; t < num_threads; t++) {
        char errbuf[1024];
        memset(&workers[t], 0, sizeof(workers[t]));
        workers[t].tid = t;
        workers[t].handler = mmt_init_handler(g_datalink, 0, errbuf);
        if (workers[t].handler == NULL) {
            fprintf(stderr, "mmt_init_handler failed for worker %d: %s\n", t, errbuf);
            for (--t; t >= 0; t--) mmt_close_handler(workers[t].handler);
            free_pcap();
            free(baseline); free(workers);
            close_extraction();
            return EXIT_FAILURE;
        }
        register_packet_handler(workers[t].handler, 1, packet_handler, &workers[t].fp);
    }

    /* All init/registration/handler-creation is done; now spawn the workers. */
    for (t = 0; t < num_threads; t++) {
        if (pthread_create(&threads[t], NULL, replay_worker, &workers[t]) != 0) {
            fprintf(stderr, "pthread_create failed for worker %d\n", t);
            for (t = 0; t < num_threads; t++) mmt_close_handler(workers[t].handler);
            free_pcap();
            free(baseline); free(workers);
            close_extraction();
            return EXIT_FAILURE;
        }
    }
    for (t = 0; t < num_threads; t++) {
        pthread_join(threads[t], NULL);
    }

    /* Every worker fingerprint must equal the single-thread baseline. */
    for (t = 0; t < num_threads; t++) {
        char label[32];
        if (workers[t].rc != 0) { failures++; continue; }
        snprintf(label, sizeof(label), "worker %d", t);
        if (fp_compare(baseline, &workers[t].fp, label) != 0) {
            failures++;
        }
    }

    /* Teardown on the main thread, after all workers have joined. */
    for (t = 0; t < num_threads; t++) {
        mmt_close_handler(workers[t].handler);
    }

    free_pcap();
    free(baseline); free(workers);
    close_extraction();

    if (failures == 0) {
        printf("[replay] PASS: all %d worker fingerprints match the baseline\n",
               num_threads);
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "[replay] FAIL: %d worker(s) diverged from the baseline\n",
            failures);
    return EXIT_FAILURE;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
/* registry-stress mode (targets #22 configured_protocols_mutex directly)     */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#define REGISTRY_STRESS_MAX_ID 512

typedef struct {
    int tid;
    int iterations;
} registry_worker_t;

static void *registry_worker(void *arg) {
    registry_worker_t *w = (registry_worker_t *)arg;
    int it, id;
    static const char *names[] = { "radius", "tcp", "udp", "ip", "http" };
    for (it = 0; it < w->iterations; it++) {
        /* Concurrent writes to configured_protocols[id]->is_registered, all
         * routed through configured_protocols_mutex (#22). If the mutex were
         * missing/incorrect, TSan would flag these as a data race. */
        for (id = 1; id < REGISTRY_STRESS_MAX_ID; id++) {
            unregister_protocol_by_id((uint32_t)id);
        }
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
            unregister_protocol_by_name((char *)names[i]);
        }
    }
    return NULL;
}

static int run_registry_stress(int num_threads, int iterations) {
    registry_worker_t workers[MAX_THREADS];
    pthread_t         threads[MAX_THREADS];
    int               t;

    if (num_threads < 2) num_threads = 2;     /* need >1 to actually contend */
    if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
    if (iterations < 1) iterations = 1;

    init_extraction();
    printf("[registry-stress] %d threads x %d iterations hammering "
           "configured_protocols_mutex (#22)\n", num_threads, iterations);

    for (t = 0; t < num_threads; t++) {
        workers[t].tid = t;
        workers[t].iterations = iterations;
        if (pthread_create(&threads[t], NULL, registry_worker, &workers[t]) != 0) {
            fprintf(stderr, "pthread_create failed for registry worker %d\n", t);
            close_extraction();
            return EXIT_FAILURE;
        }
    }
    for (t = 0; t < num_threads; t++) {
        pthread_join(threads[t], NULL);
    }

    close_extraction();
    printf("[registry-stress] PASS: no data race on the registry mutex\n");
    return EXIT_SUCCESS;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
/* handler-churn mode (targets #67 configured_handlers_map_mutex directly)     */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

typedef struct {
    int tid;
    int iterations;
    int rc;
} churn_worker_t;

/* Worker: repeatedly create and destroy its OWN handler, concurrently with the
 * other workers. This drives the global mmt_configured_handlers_map mutations
 * (insert_key_value in mmt_init_handler, delete_key_value in mmt_close_handler),
 * which are serialised by configured_handlers_map_mutex (#67). Without the lock,
 * the concurrent map mutations would be a data race that TSan flags. */
static void *churn_worker(void *arg) {
    churn_worker_t *w = (churn_worker_t *)arg;
    int it;
    /* DLT_EN10MB(1): a valid datalink so the handler initialises fully. */
    const int datalink = 1;
    w->rc = 0;
    for (it = 0; it < w->iterations; it++) {
        char           errbuf[1024];
        mmt_handler_t *h = mmt_init_handler(datalink, 0, errbuf);
        if (h == NULL) {
            fprintf(stderr, "[handler-churn] mmt_init_handler failed "
                    "(tid %d, it %d): %s\n", w->tid, it, errbuf);
            w->rc = -1;
            return NULL;
        }
        /* Fully wire the handler before tearing it down, matching real usage. */
        register_packet_handler(h, 1, packet_handler, NULL);
        mmt_close_handler(h);
    }
    return NULL;
}

static int run_handler_churn(int num_threads, int iterations) {
    churn_worker_t workers[MAX_THREADS];
    pthread_t      threads[MAX_THREADS];
    int            t;
    int            failures = 0;

    if (num_threads < 2) num_threads = 2;     /* need >1 to actually contend */
    if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
    if (iterations < 1) iterations = 1;

    init_extraction();
    printf("[handler-churn] %d threads x %d iterations concurrently "
           "create/destroy handlers from COLD, hammering configured_handlers_map_mutex (#67) "
           "and the per-handler protocol switches (#69/#549)\n",
           num_threads, iterations);

    /* Issue #69: NO main-thread warmup handler. The workers below are the very
     * first callers of mmt_init_handler() after init_extraction(), so they run
     * enable_protocol_analysis()/enable_protocol_classification() concurrently
     * from cold. Before #549 those wrote status flags on the SHARED global
     * protocol descriptors (read lock-free on the per-packet hot path); PR #68
     * papered over that race with a warmup handler, #69 made the accesses
     * atomic, and #549 moved the switches into each handler's own
     * configured_protocols[] snapshot. The warmup stays removed so this mode
     * keeps exercising the cold concurrent-create path under TSan. */

    for (t = 0; t < num_threads; t++) {
        workers[t].tid = t;
        workers[t].iterations = iterations;
        workers[t].rc = 0;
        if (pthread_create(&threads[t], NULL, churn_worker, &workers[t]) != 0) {
            fprintf(stderr, "pthread_create failed for churn worker %d\n", t);
            /* Join the workers already started before tearing down. */
            for (--t; t >= 0; t--) pthread_join(threads[t], NULL);
            close_extraction();
            return EXIT_FAILURE;
        }
    }
    for (t = 0; t < num_threads; t++) {
        pthread_join(threads[t], NULL);
        if (workers[t].rc != 0) failures++;
    }

    close_extraction();

    if (failures == 0) {
        printf("[handler-churn] PASS: no data race on the handler map mutex\n");
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "[handler-churn] FAIL: %d worker(s) failed to "
            "create/destroy handlers\n", failures);
    return EXIT_FAILURE;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage:\n"
            "  %s replay <file.pcap> [num_threads]\n"
            "  %s registry-stress [num_threads] [iterations]\n"
            "  %s handler-churn [num_threads] [iterations]\n"
            "  %s <file.pcap> [num_threads]   (shorthand for replay)\n",
            argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "registry-stress") == 0) {
        int num_threads = (argc > 2) ? atoi(argv[2]) : 4;
        int iterations  = (argc > 3) ? atoi(argv[3]) : 200;
        return run_registry_stress(num_threads, iterations);
    }

    if (strcmp(argv[1], "handler-churn") == 0) {
        int num_threads = (argc > 2) ? atoi(argv[2]) : 4;
        int iterations  = (argc > 3) ? atoi(argv[3]) : 200;
        return run_handler_churn(num_threads, iterations);
    }

    {
        const char *pcap_path;
        int         num_threads;
        if (strcmp(argv[1], "replay") == 0) {
            if (argc < 3) { usage(argv[0]); return EXIT_FAILURE; }
            pcap_path   = argv[2];
            num_threads = (argc > 3) ? atoi(argv[3]) : 4;
        } else {
            /* shorthand: first arg is the pcap path */
            pcap_path   = argv[1];
            num_threads = (argc > 2) ? atoi(argv[2]) : 4;
        }
        return run_replay(pcap_path, num_threads);
    }
}

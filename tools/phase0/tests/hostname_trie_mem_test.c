/*
 * hostname_trie_mem_test — issue #253 (F-PERF-007) acceptance harness for
 * the sparse, lazily-built reversed-hostname trie.
 *
 * The old node was a dense 256-way branch table plus a pointer (2,056 B) —
 * the ~9,091 nodes the 1,167 suffixes expand to (~17.9 MB) were built in the
 * library constructor whether hostname classification ever ran or not.
 *
 * What this asserts:
 *   LAZY      mmt_hostname_trie_resident_bytes() == 0 right after the
 *             library is loaded — the constructor no longer builds the trie
 *             (it materialises on the first get_proto_id_by_hostname call).
 *   SIZE      once built, accounted resident bytes < 4 MiB (the acceptance
 *             bound; the sparse node+edge layout lands near 0.4 MB).
 *   RSS       the VmRSS delta across the lazy build < 4 MiB, sampled through
 *             /proc/self/status — the corrected memory-harness mechanism of
 *             issue #251 (run_memory_ceiling_test.sh / phase0_throughput.c).
 *   BEHAVIOUR identical matches: google.com / www.google.com resolve to
 *             PROTO_GOOGLE, an unlisted host to PROTO_UNKNOWN — the same
 *             cases classifier_init_test.c pins end-to-end.
 *
 * Built + run by run_hostname_trie_mem_test.sh against the DEFAULT profile:
 * RSS numbers must come from a non-sanitized library (an ASan runtime plus
 * its shadow memory would measure the sanitizer, not the trie).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

#include "mmt_core.h"
#include "mmt_tcpip_protocols.h"   /* PROTO_GOOGLE, PROTO_GMAIL, PROTO_UNKNOWN */
#include "packet_processing.h"     /* struct mmt_session_struct (content_flags) */
#include "internal_decls.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, ...) do {                                        \
        g_checks++;                                                  \
        if (cond) {                                                  \
            printf("  PASS: " __VA_ARGS__);                          \
            printf("\n");                                            \
        } else {                                                     \
            printf("  FAIL: " __VA_ARGS__);                          \
            printf("\n");                                            \
            g_failures++;                                            \
        }                                                            \
    } while (0)

/* Live resident set in KiB from /proc (VmRSS) — the same sampler
 * phase0_throughput.c uses for its library_rss_kib column (issue #251). */
static long current_rss_kib(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char  line[256];
    long  kib = -1;
    if (f == NULL) return -1;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (sscanf(line, "VmRSS: %ld kB", &kib) == 1) break;
    }
    fclose(f);
    return kib;
}

#define TRIE_CEILING_BYTES (4UL * 1024 * 1024) /* issue #253 bound */
#define TRIE_CEILING_KIB   (4UL * 1024)

int main(void)
{
    printf("== hostname_trie_mem_test (issue #253, F-PERF-007) ==\n");

    mmt_session_t sess;
    ipacket_t pkt;
    memset(&sess, 0, sizeof(sess));
    memset(&pkt, 0, sizeof(pkt));
    pkt.session = &sess;

    /* LAZY — the library is already loaded (linked at exec, so its
     * constructor has run): the trie must not exist yet. */
    uint64_t bytes0 = mmt_hostname_trie_resident_bytes();
    CHECK(bytes0 == 0,
          "trie is lazily unbuilt before the first hostname lookup "
          "(resident_bytes=%llu)", (unsigned long long) bytes0);

    long rss0 = current_rss_kib();

    /* First hostname classification: the lazy build happens here. */
    uint32_t p_bare = get_proto_id_by_hostname(&pkt, (char *) "google.com", 10);
    uint64_t bytes1 = mmt_hostname_trie_resident_bytes();
    printf("  info: resident_bytes at load = %llu, after first lookup = %llu\n",
           (unsigned long long) bytes0, (unsigned long long) bytes1);

    /* BEHAVIOUR — identical match semantics to the dense trie. */
    CHECK(p_bare == PROTO_GOOGLE,
          "google.com resolves to PROTO_GOOGLE via the '.google.com' entry");
    CHECK(get_proto_id_by_hostname(&pkt, (char *) "www.google.com", 14)
          == PROTO_GOOGLE,
          "www.google.com resolves to PROTO_GOOGLE (longest suffix)");
    CHECK(get_proto_id_by_hostname(&pkt, (char *) "mail.google.com", 15)
          == PROTO_GMAIL,
          "mail.google.com resolves to PROTO_GMAIL (longest suffix wins)");
    CHECK(get_proto_id_by_hostname(&pkt, (char *) "no-such-host.invalid", 20)
          == PROTO_UNKNOWN,
          "unlisted hostname resolves to PROTO_UNKNOWN");
    CHECK(get_proto_id_by_hostname(&pkt, (char *) "", 0) == PROTO_UNKNOWN,
          "empty hostname resolves to PROTO_UNKNOWN (no fallback)");

    long rss1 = current_rss_kib();

    /* SIZE — accounted node+edge bytes under the 4 MiB bound. */
    CHECK(bytes1 > 0,
          "trie materialised on first hostname lookup (lazy build ran)");
    CHECK(bytes1 < TRIE_CEILING_BYTES,
          "sparse trie resident bytes under the 4 MiB bound "
          "(resident_bytes=%llu)", (unsigned long long) bytes1);

    /* RSS — the wall measurement of the same attribution. */
    if (rss0 >= 0 && rss1 >= 0) {
        long delta = rss1 - rss0;
        printf("  info: VmRSS across lazy build: %ld -> %ld KiB (delta %ld KiB)\n",
               rss0, rss1, delta);
        CHECK(delta < (long) TRIE_CEILING_KIB,
              "VmRSS delta attributable to the trie under 4 MiB");
    } else {
        printf("  info: VmRSS unavailable — accounted-bytes assert stands\n");
    }

    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    return g_failures ? 1 : 0;
}

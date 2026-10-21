/*
 * test_fi_http.c — Nth-allocation sweep over the HTTP stream-parser
 * constructor (issue #505, F-BUG-015).
 *
 * init_http_parser() (src/mmt_tcpip/lib/http_parser_integration.h) makes
 * three mmt_malloc() calls: the two-direction parser and one stream
 * processor per direction. It used the first result unchecked — a NULL
 * parser was written through by llhttp_init(). The contract asserted here is
 * memory.c's post-B5 one: whichever allocation fails, the constructor
 * returns NULL without crashing and leaves nothing allocated; with no
 * failure it returns a parser whose close releases everything.
 *
 * The header's static inline constructor/destructor are compiled into this
 * unit; memory.c is the fiu-remapped object of the fi-core layer, so every
 * mmt_malloc()/mmt_free() is counted. get_settings() (http_parser_integration.c,
 * which drags in the whole tcpip plugin) is replaced by a local table.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "http_parser_integration.h"
#include "fi_alloc.h"

static int failures;
#define CHECK(cond, ...) do {                                   \
        if (!(cond)) {                                          \
            failures++;                                         \
            printf("  FAIL %s:%d: ", __func__, __LINE__);       \
            printf(__VA_ARGS__);                                \
            printf("\n");                                       \
        }                                                       \
    } while (0)

static llhttp_settings_t g_settings;
const llhttp_settings_t *get_settings(void) { return &g_settings; }

static void t_init_http_parser_sweep(void)
{
    /* Unarmed run: count the constructor's allocations. */
    int64_t before = fi_window_leaked();
    fi_begin(0);
    stream_parser_t *p = init_http_parser();
    uint64_t allocs = fi_end();
    CHECK(p != NULL, "init_http_parser failed without injection");
    CHECK(allocs == 3, "expected 3 allocations, saw %llu", (unsigned long long) allocs);
    if (p) {
        CHECK(p->parser[0].data != NULL && p->parser[1].data != NULL,
              "stream processors not attached");
        (void) close_http_parser(p);
    }
    CHECK(fi_window_leaked() - before == 0, "init+close not balanced");

    for (uint64_t n = 1; n <= allocs; n++) {
        before = fi_window_leaked();
        fi_begin(n);
        p = init_http_parser();
        fi_end();
        CHECK(p == NULL, "fail@%llu: init_http_parser returned a parser",
              (unsigned long long) n);
        if (p) (void) close_http_parser(p);
        CHECK(fi_window_leaked() - before == 0, "fail@%llu: %lld block(s) leaked",
              (unsigned long long) n, (long long) (fi_window_leaked() - before));
    }
}

int main(void)
{
    t_init_http_parser_sweep();
    CHECK(fi_double_free_count() == 0, "%d double free(s) observed",
          fi_double_free_count());
    if (failures == 0) {
        printf("fi-http: init_http_parser allocation-failure sweep passed\n");
        return 0;
    }
    printf("fi-http: %d check(s) FAILED\n", failures);
    return 1;
}

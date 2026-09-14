/*
 * test_double_init.c — regression test for issue #200 (F-BUG-005).
 *
 * A second init_extraction() in one process used to hit a use-after-free:
 * close_extraction() -> clear_protocol_stack_map() deleted the global
 * protocol-stack map without NULLing the pointer and nothing recreated it,
 * so the next init_extraction() -> plugin load -> register_protocol_stack()
 * dereferenced the freed map. The same shape affected the global handlers
 * map (delete without NULL) and each handler's timeout-milestones map.
 *
 * Under ASan the second init_extraction() trips heap-use-after-free on the
 * unfixed code; on the fixed code the whole sequence is clean.
 *
 * The test needs the protocol plugins (libmmt_tcpip registers the link-layer
 * stacks through the global map), so run_tests.sh executes it from a working
 * directory whose ./plugins symlink points at the freshly built plugins —
 * the same arrangement tests/http_header_case uses.
 */
#include <stdio.h>

#include "mmt_core.h"

int main(void) {
    if (!init_extraction()) {
        fprintf(stderr, "FAIL: first init_extraction() returned 0\n");
        return 1;
    }
    close_extraction();

    if (!init_extraction()) {
        fprintf(stderr, "FAIL: second init_extraction() returned 0\n");
        return 1;
    }
    close_extraction();

    /* A third cycle exercises the lazy re-creation once more and double
     * close_extraction() must be a no-op rather than a double delete. */
    if (!init_extraction()) {
        fprintf(stderr, "FAIL: third init_extraction() returned 0\n");
        return 1;
    }
    close_extraction();
    close_extraction();

    printf("double/triple init_extraction + close_extraction: OK\n");
    return 0;
}

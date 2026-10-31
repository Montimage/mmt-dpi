/*
 * test_fi_plugin_init.c — plugin load/init failures reach init_extraction()
 * (issue #503, F-BUG-006).
 *
 * Usage: test_fi_plugin_init ok|fail
 *
 * Calls init_extraction() once and exits 0 when its verdict is the expected
 * one. run_tests.sh drives it with MMT_DPI_PLUGINS_DIR pointing at plugin
 * directories that hold a failing stub (fi_plugin.c), so each case runs in
 * its own process: the registry is process-global. On an expected success
 * the HTTP protocol of libmmt_tcpip must have registered — proof the
 * selected directory's plugins are the ones that loaded.
 */
#include <stdio.h>
#include <string.h>

#include "mmt_core.h"

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "ok") != 0 && strcmp(argv[1], "fail") != 0)) {
        fprintf(stderr, "usage: %s ok|fail\n", argv[0]);
        return 2;
    }
    const int want_ok = strcmp(argv[1], "ok") == 0;
    const int got_ok = init_extraction() ? 1 : 0;

    if (got_ok != want_ok) {
        printf("fi-plugin-init: init_extraction() %s, expected %s\n",
               got_ok ? "succeeded" : "failed", want_ok ? "success" : "failure");
        return 1;
    }
    if (got_ok) {
        const uint32_t http = get_protocol_id_by_name("http");
        close_extraction();
        if (http == 0) {
            printf("fi-plugin-init: init_extraction() succeeded but 'http' is not registered\n");
            return 1;
        }
    }
    printf("fi-plugin-init: init_extraction() %s as expected\n", got_ok ? "succeeded" : "failed");
    return 0;
}

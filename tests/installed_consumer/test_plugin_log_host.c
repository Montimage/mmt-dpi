/*
 * test_plugin_log_host.c — loads the plugins of MMT_DPI_PLUGINS_DIR, among
 * them test_plugin_log.so (issue #66), and checks that mmt_core.h alone
 * does not pull in the logger: mmt_log.h is opt-in.
 */
#include "mmt_core.h"

#include <stdio.h>

#if defined(mmt_log_error) || defined(mmt_log_debug) || defined(MMT_LOG_H_)
#error "mmt_core.h pulls in mmt_log.h; the logger header must be opt-in"
#endif

int main(void) {
    if (!init_extraction()) {
        fprintf(stderr, "init_extraction() failed\n");
        return 1;
    }
    close_extraction();
    return 0;
}

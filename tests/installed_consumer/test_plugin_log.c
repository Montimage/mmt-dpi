/*
 * test_plugin_log.c — an out-of-tree protocol plugin that logs and uses
 * branch hints through the installed headers only (issue #66).
 *
 * Since 1.10.0 (issue #537) the installed headers define no debug(),
 * log_err(), log_warn(), log_info(), likely() or unlikely(). A plugin uses
 * the opt-in logger header mmt_log.h (mmt_log_error/warn/info/debug) and the
 * prefixed MMT_LIKELY()/MMT_UNLIKELY() of mmt_utils.h instead, as
 * docs/Add-New-Protocol.md describes. Legacy code that keeps the old names
 * maps them in the plugin itself, as the two defines below do.
 *
 * tests/installed_consumer/run_tests.sh compiles it with -fPIC -shared
 * -Wall -Wextra -Werror against $(MMT_INC), with and without -DDEBUG, loads
 * it through init_extraction() (test_plugin_log_host.c) and checks the
 * lines it writes to stderr.
 */
#include "mmt_core.h"
#include "plugin_defs.h"
#include "mmt_log.h"

/* The migration shim of docs/Add-New-Protocol.md: the plugin's own names. */
#define debug(...)   mmt_log_debug(__VA_ARGS__)
#define log_err(...) mmt_log_error(__VA_ARGS__)

int init_proto(void);
int cleanup_proto(void);

/* Called only from debug(): without DEBUG mmt_log_debug() drops its
 * arguments, so the helper is unused in a release build. */
__attribute__((unused)) static int debug_argument(void) {
    return 4;
}

int init_proto(void) {
    int hits = 0;
    for (int i = 0; i < 3; i++)
        if (MMT_LIKELY(i >= 0))
            hits++;
    if (MMT_UNLIKELY(hits != 3) || MMT_LIKELY(0) != 0 || MMT_UNLIKELY(5) != 1) {
        mmt_log_error("test plugin: branch hints changed a result");
        return 0;
    }
    log_err("test plugin error line %d", 1);
    mmt_log_warn("test plugin warn line %d", 2);
    mmt_log_info("test plugin info line %d", 3);
    debug("test plugin debug line %d", debug_argument());
    return 1;
}

int cleanup_proto(void) {
    return 1;
}

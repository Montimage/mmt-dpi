
#include <stdio.h>
#include <stdlib.h>
#include "packet_processing.h"
#include "mmt_utils.h"
#include "mmt_log.h"

/*
 * Issue #675: the core functions the protocol plugins import although no
 * core object calls them — the mmt_utils.h helpers libmmt_tcpip uses and the
 * logger entry points of libmmt_tmobile. All are MMTAPI. A consumer that
 * links libmmt_core.a (the STATIC_LINK mode of 5Greplay and NetworkFuzzer)
 * holds only the archive members its references pull, and the plugins bind
 * to the executable's copy, so without this table mmt_utils.o and mmt_log.o
 * stay out: libmmt_tcpip.so does not link and libmmt_tmobile.so does not
 * load. init_extraction() calls package_dependent_init(), so every static
 * consumer pulls this object and, through the table, those members.
 * tools/ci/check-static-link.sh fails when a plugin imports a core symbol a
 * static consumer lacks; add it here. Only the SDK build (_MMT_BUILD_SDK)
 * carries it: the unit suites that compile this file beside a subset of the
 * core sources (core_engine, dpi_profiles, resource_bounds) link no plugin.
 */
#ifdef _MMT_BUILD_SDK
static const struct {
    __typeof__(hex2int) *hex2int;
    __typeof__(str_combine) *str_combine;
    __typeof__(str_copy) *str_copy;
    __typeof__(str_get_indexes_n) *str_get_indexes_n;
    __typeof__(str_hex2str) *str_hex2str;
    __typeof__(str_sub_n) *str_sub_n;
    __typeof__(mmt_log_event) *mmt_log_event;
    __typeof__(mmt_log_write) *mmt_log_write;
} mmt_plugin_core_imports __attribute__((used)) = {
    hex2int, str_combine, str_copy, str_get_indexes_n, str_hex2str, str_sub_n,
    mmt_log_event, mmt_log_write,
};
#endif

int package_dependent_init() {
   return 1;
}

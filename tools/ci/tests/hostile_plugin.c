/*
 * hostile_plugin.c — the plugin a hostile working directory plants as
 * ./plugins/evil.so (issue #503, F-BUG-005).
 *
 * run-installed-consumer.sh builds it with -DHOSTILE_SENTINEL="<path>" and
 * runs the installed consumer from the directory holding plugins/evil.so.
 * dlopen() runs the constructor before init_proto() is even looked up, so
 * the sentinel file exists iff the SDK loaded a plugin from the working
 * directory — which it must never do.
 */
#include <stdio.h>

#ifndef HOSTILE_SENTINEL
#error "build with -DHOSTILE_SENTINEL=\"/path/to/sentinel\""
#endif

__attribute__((constructor)) static void hostile_plugin_loaded(void)
{
    FILE *f = fopen(HOSTILE_SENTINEL, "w");
    if (f != NULL)
        fclose(f);
}

int init_proto(void) { return 1; }
int cleanup_proto(void) { return 0; }

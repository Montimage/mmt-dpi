/*
 * File:   plugin_engine.h
 * Author: montimage
 *
 * Created on 31 mai 2011, 10:54
 */

#ifndef PLUGIN_ENGINE_H
#define PLUGIN_ENGINE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <dlfcn.h>

/*
 * The plugin directory is fixed at build time: rules/common.mk passes
 * -DPLUGINS_REPOSITORY_OPT="$(MMT_PLUGINS)", i.e. $(MMT_BASE)/plugins.
 * Issue #503: it is the only directory scanned, unless the environment
 * variable PLUGINS_DIR_ENV names another absolute directory. The working
 * directory is never scanned.
 */
#ifndef PLUGINS_REPOSITORY_OPT
	#define PLUGINS_REPOSITORY_OPT "/opt/mmt/plugins"
#endif
#define PLUGINS_DIR_ENV "MMT_DPI_PLUGINS_DIR"

#define PLUGIN_INIT_FUNCTION_NAME "init_proto"
#define PLUGIN_CLEANUP_FUNCTION_NAME "cleanup_proto"

    struct plugin_handler_struct {
        void * handler;
        struct plugin_handler_struct * next;
    };
    /**
     * Loads every *.so of the plugin directory (MMT_DPI_PLUGINS_DIR, else
     * PLUGINS_REPOSITORY_OPT), in alphabetical order.
     * @return positive value on success, 0 when the override is relative or
     * unreadable, or when a plugin fails to load or its init_proto() fails.
     */
    int load_plugins();

    /**
     * Loads the plugin with the given path and name
     * @param plugin_path_name the full path including the name to the plugin to load
     * @return 1 on success, 0 when dlopen()/dlsym() fails or init_proto()
     * returns 0 or a negative value.
     */
    int load_plugin(char * plugin_path_name);

    /**
     * Closes all loaded plugins. This function MUST only be used when the protocols corresponding
     * to the loaded plugins have been retrieved. Normally this function is used when closing the
     * library.
     */
    void close_plugins();

#ifdef __cplusplus
}
#endif

#endif /* PLUGIN_ENGINE_H */


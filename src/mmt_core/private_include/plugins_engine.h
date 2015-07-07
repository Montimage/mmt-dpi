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

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#define PLUGINS_REPOSITORY "plugins"
#define PLUGINS_REPOSITORY_OPT "/opt/mmt/plugins"
#define PLUGIN_INIT_FUNCTION_NAME "init_proto"

    struct plugin_handler_struct {
#ifdef _WIN32
        HMODULE handler;
#else
        void * handler;
#endif
        struct plugin_handler_struct * next;
    };
    /**
     * Loads all the plugins.
     * @return positive value on success, 0 on failure.
     */
    int load_plugins();

    /**
     * Loads the plugin with the given path and name
     * @param plugin_path_name the full path including the name to the plugin to load
     * @return positive value on success, 0 on failure.
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


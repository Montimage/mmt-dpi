#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "plugin_defs.h"
#include "plugins_engine.h"
#include "packet_processing.h"

#ifndef _WIN32
#include <dirent.h>

static int load_filter( const struct dirent *entry )
{
    char *ext = strrchr( entry->d_name, '.' );
    return( ext && !strcmp( ext, ".so" ));
}
#endif

static struct plugin_handler_struct * plugin_handlers_list = NULL;


int load_plugins() {
    int retval = 1;
#ifdef _WIN32
    HANDLE hFind;
    WIN32_FIND_DATA FindFileData;
    char folder_name[256] = "";

    strcat(folder_name, PLUGINS_REPOSITORY);
    strcat(folder_name, "/*.dll");

    if ((hFind = FindFirstFile(folder_name, &FindFileData)) != INVALID_HANDLE_VALUE) {
        do {
            char plugin_name[256] = "";
            strcat(plugin_name, PLUGINS_REPOSITORY);
            strcat(plugin_name, "/");
            strcat(plugin_name, FindFileData.cFileName);
            //printf("%s\n", FindFileData.cFileName);
            if (!load_plugin(plugin_name)) {
                retval = 0;
                break;
            }
        } while (FindNextFile(hFind, &FindFileData));
        FindClose(hFind);
    }
#else
    char path[ 256 ];

    struct dirent **entries;
    struct dirent *entry;
    int plugins_path=0;
    int n = scandir( PLUGINS_REPOSITORY, &entries, load_filter, alphasort );
    if( n < 0 ) {
        /* can't read PLUGINS_REPOSITORY -> just ignore and return success
         * (the directory may not exist or may be inaccessible, that's ok)
         * note: no entries were allocated at this point, no need for free().
         */
	plugins_path=1;
        n = scandir( PLUGINS_REPOSITORY_OPT, &entries, load_filter, alphasort );
	if (n<0){
		printf("You don't have any plugin");
	        return 1;
	}
    }

    int i;
    for( i = 0 ; i < n ; ++i ) {
        entry = entries[i];
        (void)snprintf( path, 256, "%s/%s",plugins_path==0?PLUGINS_REPOSITORY:PLUGINS_REPOSITORY_OPT,entry->d_name );
        printf("Loading plugins from: %s",path);
	(void)load_plugin( path );
        free( entry );
    }

    free( entries );
#endif
    return retval;
}

int load_plugin(char * plugin_path_name) {
    int retval = 0;
    struct plugin_handler_struct * plugin_handler;
    generic_init_proto init_proto_fct;

    plugin_handler = mmt_malloc(sizeof (struct plugin_handler_struct));
    if (plugin_handler == NULL) {
        fprintf(stderr, "Memory allocation error while initializing plugin %s\n", plugin_path_name);
        return 0;
    }
#ifdef _WIN32
    plugin_handler->handler = LoadLibrary(plugin_path_name);
    if (plugin_handler->handler == NULL) {
        fprintf(stderr, "Error when loading plugin %s\n", plugin_path_name);
        mmt_free(plugin_handler);
        return 0;
    }

    FARPROC initializer = GetProcAddress(plugin_handler->handler, PLUGIN_INIT_FUNCTION_NAME);
    if (initializer == NULL) {
        fprintf(stderr, "Error when extracting plugin content. Function %s was not found\n", PLUGIN_INIT_FUNCTION_NAME);
        FreeLibrary(plugin_handler->handler);
        mmt_free(plugin_handler);
        return 0;
    }

    init_proto_fct = (generic_init_proto) initializer;
#else
    char *error;
//    plugin_handler->handler = dlopen(plugin_path_name, RTLD_LAZY);
    plugin_handler->handler = dlopen(plugin_path_name, RTLD_NOW | RTLD_GLOBAL);

    if (!plugin_handler->handler) {
        fprintf(stderr, "%s\n", dlerror());
        mmt_free(plugin_handler);
        return 0;
    }
    dlerror(); /* Clear any existing error */
    init_proto_fct = dlsym(plugin_handler->handler, PLUGIN_INIT_FUNCTION_NAME);
    
    if ((error = dlerror()) != NULL) {
        fprintf(stderr, "%s\n", error);
        dlclose(plugin_handler->handler);
        mmt_free(plugin_handler);
        return 0;
    }
#endif
    retval = init_proto_fct();
    plugin_handler->next = plugin_handlers_list;
    plugin_handlers_list = plugin_handler;
    return retval;
}

void close_plugins() {
    struct plugin_handler_struct * temp_plugin = plugin_handlers_list;
    while (temp_plugin != NULL) {
        struct plugin_handler_struct * temp_plugin_to_free = temp_plugin;
        generic_cleanup_proto cleanup_proto_fct;
#ifdef _WIN32
        FARPROC cleaner = GetProcAddress(temp_plugin->handler,PLUGIN_CLEANUP_FUNCTION_NAME);
        if (cleaner == NULL) {
            debug("Cannot load function clean up when extracting plugin content. Function %s was not found\n", PLUGIN_CLEANUP_FUNCTION_NAME);
        }else{
            cleanup_proto_fct = (generic_cleanup_proto)cleaner;
        }
        cleanup_proto_fct();
        FreeLibrary(temp_plugin->handler);
#else
        char *error;
        cleanup_proto_fct = dlsym(temp_plugin->handler,PLUGIN_CLEANUP_FUNCTION_NAME);
        if((error=dlerror())==NULL){
            cleanup_proto_fct();
        }else{
            debug("Cannot load function clean up when extracting plugin content. Function %s was not found\n", PLUGIN_CLEANUP_FUNCTION_NAME);
        }
        dlclose(temp_plugin->handler);
#endif
        temp_plugin = temp_plugin->next;
        //Now it's safe to free the plugin struct
        mmt_free(temp_plugin_to_free);
    }
    //Finally set the plugins list pointer to NULL
    plugin_handlers_list = NULL;
}

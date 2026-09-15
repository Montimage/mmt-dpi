#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "plugin_defs.h"
#include "plugins_engine.h"
#include "packet_processing.h"

#include <dirent.h>

static int load_filter( const struct dirent *entry )
{
    char *ext = strrchr( entry->d_name, '.' );
    return( ext && !strcmp( ext, ".so" ));
}

/*
 * Issue #22 (thread safety) - global plugin registry.
 *
 * `plugin_handlers_list` is a process-wide singly linked list of loaded plugin
 * handles. It is mutated only at plugin-load time (load_plugin) and at teardown
 * (close_plugins); the per-packet processing hot path never touches it.
 *
 * Threading contract (see docs/THREADING.md): plugin loading and teardown must
 * complete on a single thread before any worker thread starts processing
 * packets. The mutex below guards the list mutations so that a defensive caller
 * that loads plugins concurrently (or races load against teardown) does not
 * corrupt the list head; it is NOT taken on any read/hot path.
 */
static pthread_mutex_t plugin_handlers_list_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct plugin_handler_struct * plugin_handlers_list = NULL;


int load_plugins() {
    int retval = 1;
    char path[ 256 ];

    struct dirent **entries;
    struct dirent *entry;
    int plugins_path=0;
    int ret;
    int n = scandir( PLUGINS_REPOSITORY, &entries, load_filter, alphasort );
    if( n < 0 ) {
        /* can't read PLUGINS_REPOSITORY -> just ignore and return success
         * (the directory may not exist or may be inaccessible, that's ok)
         * note: no entries were allocated at this point, no need for free().
         */
	plugins_path=1;
        n = scandir( PLUGINS_REPOSITORY_OPT, &entries, load_filter, alphasort );
	if (n<0){
		printf("You don't have any plugin\n");
	        return 1;
	}
    }

    int i;
    for( i = 0 ; i < n ; ++i ) {
        entry = entries[i];
        ret = snprintf( path, 256, "%s/%s",plugins_path==0?PLUGINS_REPOSITORY:PLUGINS_REPOSITORY_OPT,entry->d_name );

        if( ret <= 0 ) //must not occurs, but we need to check anyway to avoid warning when compiling using gcc7
        	return 0;

        // printf("Loading plugins from: %s \n",path);
	(void)load_plugin( path );
        free( entry );
    }

    free( entries );
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
    retval = init_proto_fct();
    /* Issue #22: guard the registry mutation only (not init_proto_fct, which
     * takes the configured_protocols lock separately - keeping the two locks
     * un-nested avoids any lock-ordering hazard). */
    pthread_mutex_lock(&plugin_handlers_list_mutex);
    plugin_handler->next = plugin_handlers_list;
    plugin_handlers_list = plugin_handler;
    pthread_mutex_unlock(&plugin_handlers_list_mutex);
    return retval;
}

void close_plugins() {
    /* Issue #22: guard the whole teardown so it cannot race a concurrent
     * load_plugin appending to the list head. */
    pthread_mutex_lock(&plugin_handlers_list_mutex);
    struct plugin_handler_struct * temp_plugin = plugin_handlers_list;
    while (temp_plugin != NULL) {
        struct plugin_handler_struct * temp_plugin_to_free = temp_plugin;
        generic_cleanup_proto cleanup_proto_fct;
        char *error;
        cleanup_proto_fct = dlsym(temp_plugin->handler,PLUGIN_CLEANUP_FUNCTION_NAME);
        if((error=dlerror())==NULL){
            cleanup_proto_fct();
        }else{
            debug("Cannot load function clean up when extracting plugin content. Function %s was not found\n", PLUGIN_CLEANUP_FUNCTION_NAME);
        }
        dlclose(temp_plugin->handler);
        temp_plugin = temp_plugin->next;
        //Now it's safe to free the plugin struct
        mmt_free(temp_plugin_to_free);
    }
    //Finally set the plugins list pointer to NULL
    plugin_handlers_list = NULL;
    pthread_mutex_unlock(&plugin_handlers_list_mutex);
}

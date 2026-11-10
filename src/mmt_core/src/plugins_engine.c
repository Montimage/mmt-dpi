#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* secure_getenv() */
#endif
#include <limits.h>
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


/*
 * Issue #503 (F-BUG-005): the plugin directory is the one compiled into the
 * library (PLUGINS_REPOSITORY_OPT, i.e. $(MMT_BASE)/plugins) unless the
 * MMT_DPI_PLUGINS_DIR environment variable names another absolute directory.
 * The working directory is never scanned: a CWD-relative "plugins/" used to
 * run the constructor and init_proto() of any .so planted wherever the host
 * process was started. secure_getenv() ignores the override in setuid/setgid
 * processes. Returns NULL (after logging why) for a relative override.
 */
static const char *plugins_directory(int *from_env)
{
    const char *dir = secure_getenv(PLUGINS_DIR_ENV);
    *from_env = 0;
    if (dir == NULL || dir[0] == '\0')
        return PLUGINS_REPOSITORY_OPT;
    *from_env = 1;
    if (dir[0] != '/') {
        mmt_stderr_log("%s must be an absolute directory, got \"%s\"\n", PLUGINS_DIR_ENV, dir);
        return NULL;
    }
    return dir;
}

int load_plugins() {
    int retval = 1;
    int from_env;
    char path[ PATH_MAX ];
    struct dirent **entries;
    const char *dir = plugins_directory(&from_env);
    if (dir == NULL)
        return 0;

    int n = scandir( dir, &entries, load_filter, alphasort );
    if( n < 0 ) {
        /* An explicitly requested directory must exist. The compiled-in one
         * may not (a core-only install): run without protocol plugins.
         * No entries were allocated, no need for free(). */
        if (from_env) {
            mmt_stderr_log("Cannot read plugin directory %s (%s)\n", dir, PLUGINS_DIR_ENV);
            return 0;
        }
        mmt_debug_log("You don't have any plugin\n");
        return 1;
    }

    /* Issue #503 (F-BUG-006): the first plugin that fails to load or to
     * initialize fails the whole load (and init_extraction()); the remaining
     * entries are only freed. */
    int i;
    for( i = 0 ; i < n ; ++i ) {
        if (retval) {
            int ret = snprintf( path, sizeof( path ), "%s/%s", dir, entries[i]->d_name );
            if( ret < 0 || (size_t) ret >= sizeof( path )) {
                mmt_stderr_log( "Plugin path too long: %s/%s\n", dir, entries[i]->d_name );
                retval = 0;
            } else if( !load_plugin( path )) {
                mmt_stderr_log( "Error loading plugin %s\n", path );
                retval = 0;
            }
        }
        free( entries[i] );
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
        mmt_stderr_log( "Memory allocation error while initializing plugin %s\n", plugin_path_name);
        return 0;
    }
    char *error;
//    plugin_handler->handler = dlopen(plugin_path_name, RTLD_LAZY);
    /* plugin_path_name is a file of plugins_directory(): the compiled-in
     * directory or an absolute MMT_DPI_PLUGINS_DIR read with secure_getenv()
     * (CodeQL cpp/uncontrolled-process-operation, dismissed with its reason
     * in docs/DECISIONS.md, issue #749). */
    plugin_handler->handler = dlopen(plugin_path_name, RTLD_NOW | RTLD_GLOBAL);

    if (!plugin_handler->handler) {
        mmt_stderr_log( "%s\n", dlerror());
        mmt_free(plugin_handler);
        return 0;
    }
    dlerror(); /* Clear any existing error */
    init_proto_fct = dlsym(plugin_handler->handler, PLUGIN_INIT_FUNCTION_NAME);
    
    if ((error = dlerror()) != NULL) {
        mmt_stderr_log( "%s\n", error);
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
    /* Issue #503: init_proto() reports failure as 0 or a negative value
     * (init_dicom_proto_struct() returns -1). The handle stays on the list
     * above so close_plugins() still runs cleanup_proto() and dlclose(). */
    if (retval <= 0) {
        mmt_stderr_log( "%s: %s() failed (%d)\n", plugin_path_name, PLUGIN_INIT_FUNCTION_NAME, retval );
        return 0;
    }
    return 1;
}

/*
 * Application/content class lookups (Montimage/mmt-probe#18): the tables stay
 * in the plugins, and a consumer reaches them through the core, so it never
 * links a plugin. Written at plugin load and teardown under
 * plugin_handlers_list_mutex, read without it: the threading contract above
 * has loading finish before any worker starts.
 */
#define MMT_CLASS_PROVIDERS_MAX 8
static const mmt_class_provider_t *class_providers[MMT_CLASS_PROVIDERS_MAX];
static size_t class_providers_count;

void close_plugins() {
    /* Issue #22: guard the whole teardown so it cannot race a concurrent
     * load_plugin appending to the list head. */
    pthread_mutex_lock(&plugin_handlers_list_mutex);
    /* The providers live in the plugins about to be unloaded. */
    class_providers_count = 0;
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

bool mmt_register_class_provider(const mmt_class_provider_t *provider) {
    bool done = false;
    size_t i;
    if (provider == NULL)
        return false;
    pthread_mutex_lock(&plugin_handlers_list_mutex);
    for (i = 0; i < class_providers_count && class_providers[i] != provider; i++)
        ;
    if (i < class_providers_count) {
        done = true;
    } else if (class_providers_count < MMT_CLASS_PROVIDERS_MAX) {
        class_providers[class_providers_count++] = provider;
        done = true;
    }
    pthread_mutex_unlock(&plugin_handlers_list_mutex);
    return done;
}

/* Defines the static class and label lookups of one kind of key. */
#define MMT_DEFINE_CLASS_LOOKUPS(kind, key_type, class_field, name_field, key_is_valid)      \
    static int find_##kind##_class(key_type key) {                                   \
        size_t i;                                                                    \
        for (i = 0; (key_is_valid) && i < class_providers_count; i++) {              \
            const mmt_class_provider_t *p = class_providers[i];                      \
            int found = p->class_field ? p->class_field(key) : MMT_CLASS_UNKNOWN;    \
            if (found != MMT_CLASS_UNKNOWN)                                          \
                return found;                                                        \
        }                                                                            \
        return MMT_CLASS_UNKNOWN;                                                    \
    }                                                                                \
    static char *find_##kind##_name(key_type key) {                                  \
        size_t i;                                                                    \
        for (i = 0; (key_is_valid) && i < class_providers_count; i++) {              \
            const mmt_class_provider_t *p = class_providers[i];                      \
            if (p->class_field && p->name_field                                      \
                    && p->class_field(key) != MMT_CLASS_UNKNOWN)                     \
                return p->name_field(key);                                           \
        }                                                                            \
        return NULL;                                                                 \
    }

MMT_DEFINE_CLASS_LOOKUPS(application, mmt_proto_id_t, application_class, application_class_name, true)
MMT_DEFINE_CLASS_LOOKUPS(content_type, char *, content_class_by_type, content_class_name_by_type, key != NULL)
MMT_DEFINE_CLASS_LOOKUPS(content_flags, uint32_t, content_class_by_flags, content_class_name_by_flags, true)

int mmt_application_class(mmt_proto_id_t proto_id) {
    return find_application_class(proto_id);
}

char *mmt_application_class_name(mmt_proto_id_t proto_id) {
    return find_application_name(proto_id);
}

int mmt_content_class_by_type(char *content_type) {
    return find_content_type_class(content_type);
}

char *mmt_content_class_name_by_type(char *content_type) {
    return find_content_type_name(content_type);
}

int mmt_content_class_by_flags(uint32_t content_flags) {
    return find_content_flags_class(content_flags);
}

char *mmt_content_class_name_by_flags(uint32_t content_flags) {
    return find_content_flags_name(content_flags);
}

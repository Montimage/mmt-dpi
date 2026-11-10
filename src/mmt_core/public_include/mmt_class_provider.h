/**
 * @file mmt_class_provider.h
 * Application and content class lookups, answered by the loaded plugins.
 *
 * The core knows no protocol, so it holds no class table. A plugin that can
 * class its protocols registers an mmt_class_provider_t from its init_proto();
 * a consumer asks the core and links libmmt_core alone. With no provider that
 * knows the key (no such plugin loaded, or init_extraction() not called yet)
 * a lookup reports MMT_CLASS_UNKNOWN, or NULL for a label.
 */
#ifndef MMT_CLASS_PROVIDER_H
#define MMT_CLASS_PROVIDER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include "data_defs.h"
#include "mmt_exports.h"

/** The class of a key no provider knows; a provider returns it to pass. */
#define MMT_CLASS_UNKNOWN 0

/**
 * The lookups one plugin offers. A plugin leaves NULL what it does not class.
 * A label callback is only called for a key its class callback knows.
 */
typedef struct mmt_class_provider_struct {
    int (*application_class)(mmt_proto_id_t proto_id);           /**< Application class of a protocol id. */
    char *(*application_class_name)(mmt_proto_id_t proto_id);    /**< Label of that application class. */
    int (*content_class_by_type)(char *content_type);            /**< Content class of a MIME type such as "video/mp4". */
    char *(*content_class_name_by_type)(char *content_type);     /**< Label of that content class. */
    int (*content_class_by_flags)(uint32_t content_flags);       /**< Content class of a session's content flags. */
    char *(*content_class_name_by_flags)(uint32_t content_flags);/**< Label of that content class. */
} mmt_class_provider_t;

/**
 * Registers a plugin's class lookups, from its init_proto(). Providers are
 * asked in registration order and the first that knows a key answers.
 * close_extraction() forgets them all before it unloads the plugins, so a
 * plugin has nothing to unregister.
 * @param provider the lookups; must stay valid until close_extraction().
 * @return true on success, or if this provider is already registered; false
 * if provider is NULL or the registry is full.
 */
MMTAPI bool MMTCALL mmt_register_class_provider(const mmt_class_provider_t *provider);

/**
 * @param proto_id a protocol identifier.
 * @return its application class, MMT_CLASS_UNKNOWN if no provider knows it.
 */
MMTAPI int MMTCALL mmt_application_class(mmt_proto_id_t proto_id);

/**
 * @param proto_id a protocol identifier.
 * @return the label of its application class, NULL if no provider knows it.
 */
MMTAPI char * MMTCALL mmt_application_class_name(mmt_proto_id_t proto_id);

/**
 * @param content_type a MIME type such as "video/mp4".
 * @return its content class, MMT_CLASS_UNKNOWN if content_type is NULL or no
 * provider knows it.
 */
MMTAPI int MMTCALL mmt_content_class_by_type(char *content_type);

/**
 * @param content_type a MIME type such as "video/mp4".
 * @return the label of its content class, NULL if content_type is NULL or no
 * provider knows it.
 */
MMTAPI char * MMTCALL mmt_content_class_name_by_type(char *content_type);

/**
 * @param content_flags the content flags of a session.
 * @return their content class, MMT_CLASS_UNKNOWN if no provider knows them.
 */
MMTAPI int MMTCALL mmt_content_class_by_flags(uint32_t content_flags);

/**
 * @param content_flags the content flags of a session.
 * @return the label of their content class, NULL if no provider knows them.
 */
MMTAPI char * MMTCALL mmt_content_class_name_by_flags(uint32_t content_flags);

#ifdef __cplusplus
}
#endif

#endif /* MMT_CLASS_PROVIDER_H */

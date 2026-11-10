/*
 * File:   mmt_tcpip_utils.h
 * Author: montimage
 *
 * Created on 28 mai 2015, 17:21
 */

#ifndef MMT_TCPIP_H
#define MMT_TCPIP_H

#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <stdlib.h>
#include "mmt_exports.h"
#include "mmt_class_provider.h"
#include "mmt_tcpip_protocols.h"
#include "mmt_tcpip_attributes.h"

/*
 * Content-family and application-class lookups. The tables live in this
 * plugin, but a consumer must not have to link it: the plugin is optional
 * (a log-only deployment does not load it) and is loaded at run time
 * (Montimage/mmt-probe#18). So these names forward to libmmt_core, which asks
 * the plugin it has loaded; without it they report the unknown class. The
 * plugin still exports the functions, for binaries built against v1.10.0.
 */
#ifdef MMT_TCPIP_CLASSES_DEFINITIONS

MMTAPI int MMTCALL get_content_class_by_content_type(char * str);
MMTAPI char * MMTCALL get_content_class_name_by_content_type(char * str);
MMTAPI int MMTCALL get_content_class_by_content_flags(uint32_t content_flags);
MMTAPI char * MMTCALL get_content_class_name_by_content_flags(uint32_t content_flags);
MMTAPI int MMTCALL get_application_class_by_protocol_id(int id);
MMTAPI char * MMTCALL get_application_class_name_by_protocol_id(int id);

#else

/** @return the MMT_CONTENT_FAMILY_* of a MIME content type such as "video/mp4" */
static inline int get_content_class_by_content_type(char * str) {
    return mmt_content_class_by_type(str);
}

/** @return the MMT_CONTENT_LONG_LABELS label of get_content_class_by_content_type(str) */
static inline char * get_content_class_name_by_content_type(char * str) {
    char * name = mmt_content_class_name_by_type(str);
    return name != NULL ? name : (char *) "";
}

/** @return the MMT_CONTENT_FAMILY_* of a session's MMT_CONTENT_* flags */
static inline int get_content_class_by_content_flags(uint32_t content_flags) {
    return mmt_content_class_by_flags(content_flags);
}

/** @return the MMT_CONTENT_LONG_LABELS label of get_content_class_by_content_flags(content_flags) */
static inline char * get_content_class_name_by_content_flags(uint32_t content_flags) {
    char * name = mmt_content_class_name_by_flags(content_flags);
    return name != NULL ? name : (char *) "";
}

/** @return the PROTO_CLASS_* application class of a protocol identifier */
static inline int get_application_class_by_protocol_id(int id) {
    return mmt_application_class(id);
}

/** @return the PROTO_CLASS_LABELS label of get_application_class_by_protocol_id(id) */
static inline char * get_application_class_name_by_protocol_id(int id) {
    char * name = mmt_application_class_name(id);
    return name != NULL ? name : (char *) "Unkown";
}

#endif /* MMT_TCPIP_CLASSES_DEFINITIONS */

#ifdef __cplusplus
}
#endif

#endif /* MMT_TCPIP_H */

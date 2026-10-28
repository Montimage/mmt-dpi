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
#include "mmt_tcpip_protocols.h"
#include "mmt_tcpip_attributes.h"

/*
 * Content-family and application-class lookups (issue #537). Their bodies used
 * to be inlined here; they are now defined in libmmt_tcpip, so a consumer
 * calling them links with -lmmt_tcpip and picks up table updates without
 * being rebuilt.
 */

/** @return the MMT_CONTENT_FAMILY_* of a MIME content type such as "video/mp4" */
MMTAPI int MMTCALL get_content_class_by_content_type(char * str);

/** @return the MMT_CONTENT_LONG_LABELS label of get_content_class_by_content_type(str) */
MMTAPI char * MMTCALL get_content_class_name_by_content_type(char * str);

/** @return the MMT_CONTENT_FAMILY_* of a session's MMT_CONTENT_* flags */
MMTAPI int MMTCALL get_content_class_by_content_flags(uint32_t content_flags);

/** @return the MMT_CONTENT_LONG_LABELS label of get_content_class_by_content_flags(content_flags) */
MMTAPI char * MMTCALL get_content_class_name_by_content_flags(uint32_t content_flags);

/** @return the PROTO_CLASS_* application class of a protocol identifier */
MMTAPI int MMTCALL get_application_class_by_protocol_id(int id);

/** @return the PROTO_CLASS_LABELS label of get_application_class_by_protocol_id(id) */
MMTAPI char * MMTCALL get_application_class_name_by_protocol_id(int id);

#ifdef __cplusplus
}
#endif

#endif /* MMT_TCPIP_H */

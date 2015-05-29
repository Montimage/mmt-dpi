/*
 * File:   mmt_tcpip.h
 * Author: montimage
 *
 * Created on 23 mai 2011, 17:21
 */

#ifndef MMT_TCPIP_H
#define MMT_TCPIP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mmt_core.h"
// #include "mmt_tcpip_utils.h"
#include "mmt_tcpip_protocols.h"

    /**
     * Returns the Content class id corresponding to the given content flags.
     * @param content_flags content flags
     * @return content class id corresponding to the given content flags.
     */
    int get_content_class_by_content_flags(uint32_t content_flags);

    /**
     * Returns the Content class name corresponding to the given content flags.
     * @param content_flags content flags
     * @return content class name corresponding to the given content flags.
     */

    char * get_content_class_name_by_content_flags(uint32_t content_flags);

    /**
     * Returns the Content class id corresponding to the given content type (HTTP like Content type).
     * @param str content type string
     * @return content class id corresponding to the given content type.
     */

    int get_content_class_by_content_type(char * str);

    /**
     * Returns the Content class name corresponding to the given content type (HTTP like Content type).
     * @param str content type string
     * @return content class name corresponding to the given content type.
     */
    char * get_content_class_name_by_content_type(char * str);

    /**
     * Returns the Application Class of the protocol/application given by its id.
     * @param id identifier of the protocol or application.
     * @return the Application Class of the protocol/application given by its id.
     */

    int get_application_class_by_protocol_id(int id);

    /**
     * Returns the Application Class name of the protocol/application given by its id.
     * @param id identifier of the protocol or application.
     * @return the Application Class name of the protocol/application given by its id.
     */
    char * get_application_class_name_by_protocol_id(int id);

#ifdef __cplusplus
}
#endif

#endif /* MMT_TCPIP_H */

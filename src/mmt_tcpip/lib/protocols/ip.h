/*
 * File:   ip.h
 * Author: montimage
 *
 * Created on 26 mai 2011, 16:47
 */

#ifndef IP_H
#define	IP_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"

#include <netinet/in.h>

#define IP_CE           0x8000          /* Flag: "Congestion"           */
#define IP_DF           0x4000          /* Flag: "Don't Fragment"       */
#define IP_MF           0x2000          /* Flag: "More Fragments"       */
#define IP_OFFSET       0x1FFF          /* "Fragment Offset" part       */

    //#define IP_ATTRIBUTES_NB    7

    int init_ip_proto_struct();

    //void * get_classification_internal_context(const ipacket_t * packet);


#ifdef	__cplusplus
}
#endif

#endif	/* IP_H */


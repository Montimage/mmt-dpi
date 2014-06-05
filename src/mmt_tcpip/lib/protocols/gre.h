/* 
 * File:   gre.h
 * Author: montimage
 *
 * Created on 26 avril 2012, 15:33
 */

#ifndef GRE_H
#define	GRE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"

    struct gre_hdr {
#if BYTE_ORDER == LITTLE_ENDIAN
        uint16_t rec : 3,
                srr : 1,
                seq : 1,
                key : 1,
                routing : 1,
                csum : 1,
                version : 3,
                reserved : 4,
                ack : 1;
#elif BYTE_ORDER == BIG_ENDIAN
        uint16_t csum : 1,
                routing : 1,
                key : 1,
                seq : 1,
                srr : 1,
                rec : 3,
                ack : 1,
                reserved : 4,
                version : 3;
#else
#error "BYTE_ORDER must be defined"
#endif
        uint16_t protocol;
        uint8_t data;
    };

    int init_gre_proto_struct();
    
#ifdef	__cplusplus
}
#endif

#endif	/* GRE_H */


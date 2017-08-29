/* 
 * File:   loopback.h
 * Author: montimage
 *
 * Created on 29 august 2017, 14h39
 */

#ifndef LOOPBACK_H
#define	LOOPBACK_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"


#ifndef LOOPBACK_P_IP
#define LOOPBACK_P_IP        2         /* Internet Protocol packet     */
#endif
    struct loopback_hdr_struct {
        uint16_t h_proto;
    };

    int init_loopback_proto_struct();

#ifdef	__cplusplus
}
#endif

#endif	/* LOOPBACK_H */


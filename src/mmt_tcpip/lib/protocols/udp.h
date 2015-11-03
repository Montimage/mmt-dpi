/* 
 * File:   udp.h
 * Author: Gerardo
 *
 * Created on 8 juin 2011, 12:02
 */

#ifndef UDP_H
#define	UDP_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"

#if defined(_WIN32) || defined(_OSX)
    struct udphdr {
        uint16_t source;
        uint16_t dest;
        uint16_t len;
        uint16_t check;
    };
#endif //WIN32

    int init_udp_proto_struct();

#ifdef	__cplusplus
}
#endif

#endif	/* UDP_H */


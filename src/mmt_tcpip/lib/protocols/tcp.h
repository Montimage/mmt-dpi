/* 
 * File:   tcp.h
 * Author: Gerardo
 *
 * Created on 14 juin 2011, 13:54
 */

#ifndef TCP_H
#define	TCP_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"

   
#ifdef _WIN32
    struct tcphdr {
        uint16_t source;
        uint16_t dest;
        uint32_t seq;
        uint32_t ack_seq;
#if BYTE_ORDER == LITTLE_ENDIAN
        uint16_t res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
#elif BYTE_ORDER == BIG_ENDIAN
        uint16_t doff : 4, res1 : 4, cwr : 1, ece : 1, urg : 1, ack : 1, psh : 1, rst : 1, syn : 1, fin : 1;
#else
#error "BYTE_ORDER must be defined"
#endif
        uint16_t window;
        uint16_t check;
        uint16_t urg_ptr;
    };
#endif //WIN32

    int init_tcp_proto_struct();


#ifdef	__cplusplus
}
#endif

#endif	/* TCP_H */


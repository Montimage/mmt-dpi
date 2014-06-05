/* Generated with MMT Plugin Generator */

#ifndef SLL_H
#define SLL_H
#ifdef    __cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"
#include "ethernet.h"

#ifndef SLL_HDR_LEN
#define SLL_HDR_LEN 16
#endif

#ifndef SLL_ADDRLEN
#define SLL_ADDRLEN 8
#endif

    struct sll_header {
        uint16_t pkttype ;
        uint16_t hatype ;
        uint16_t halen ;
        uint8_t addr[SLL_ADDRLEN] ;
        uint16_t protocol ;
    };

    int init_proto_sll_struct();

#ifdef    __cplusplus
}
#endif
#endif    /* SLL_H */




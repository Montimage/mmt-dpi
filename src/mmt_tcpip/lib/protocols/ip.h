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

#ifdef _WIN32
 #if 0
    struct in6_addr {
        unsigned char s6_addr[16]; /* IPv6 address */
    };
 #endif
#else
#include <netinet/in.h>
#endif //WIN32

#define IP_CE           0x8000          /* Flag: "Congestion"           */
#define IP_DF           0x4000          /* Flag: "Don't Fragment"       */
#define IP_MF           0x2000          /* Flag: "More Fragments"       */
#define IP_OFFSET       0x1FFF          /* "Fragment Offset" part       */

    //#define IP_ATTRIBUTES_NB    7

#ifdef _WIN32

    struct iphdr {
#if BYTE_ORDER == LITTLE_ENDIAN
        uint8_t ihl : 4, version : 4;
#elif BYTE_ORDER == BIG_ENDIAN
        uint8_t version : 4, ihl : 4;
#else
#error "BYTE_ORDER must be defined"
#endif
        uint8_t tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t check;
        uint32_t saddr;
        uint32_t daddr;
    };

    struct ip6_hdr {

        union {

            struct ip6_hdrctl {
                uint32_t ip6_un1_flow;
                uint16_t ip6_un1_plen;
                uint8_t ip6_un1_nxt;
                uint8_t ip6_un1_hlim;
            } ip6_un1;
            uint8_t ip6_un2_vfc;
        } ip6_ctlun;
        struct in6_addr ip6_src;
        struct in6_addr ip6_dst;
    };
#endif //WIN32
    int init_ip_proto_struct();

    //void * get_classification_internal_context(const ipacket_t * packet);


#ifdef	__cplusplus
}
#endif

#endif	/* IP_H */


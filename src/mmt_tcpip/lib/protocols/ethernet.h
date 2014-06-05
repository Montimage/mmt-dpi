/* 
 * File:   ethernet.h
 * Author: montimage
 *
 * Created on 23 mai 2011, 10:24
 */

#ifndef ETHERNET_H
#define	ETHERNET_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"


#ifndef ETH_P_IP
#define ETH_P_IP        0x0800          /* Internet Protocol packet     */
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP       0x0806          /* Address Resolution packet    */
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6      0x86DD          /* IPv6 over bluebook           */
#endif

#ifndef ETH_P_RARP
#define ETH_P_RARP      0x8035          /* Reverse Addr Res packet      */
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q      0x8100          /* 802.1 Q      */
#endif
#ifndef ETH_P_PPPoED
#define ETH_P_PPPoED      0x8863          /* PPPoE Discovery protocol     */
#endif
#ifndef ETH_P_PPPoES
#define ETH_P_PPPoES      0x8864          /* PPPoE Session protocol      */
#endif

    struct ethhdr {
        unsigned char h_dest[ETH_ALEN];
        unsigned char h_source[ETH_ALEN];
        uint16_t h_proto;
    };

    int init_ethernet_proto_struct();

#ifdef	__cplusplus
}
#endif

#endif	/* ETHERNET_H */


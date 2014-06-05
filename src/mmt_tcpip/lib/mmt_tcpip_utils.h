/*
 * File:   mmt_tcpip_utils.h
 * Author: montimage
 *
 * Created on December 17, 2012, 2:18 PM
 */

#ifndef MMT_TCPIP_UTILS_H
#define	MMT_TCPIP_UTILS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "mmt_core.h"
#include "mmt_tcpip_internal_defs_macros.h"
#include "mmt_tcpip_plugin_structs.h"

uint32_t mmt_bytestream_to_number(const uint8_t * str, uint16_t max_chars_to_read, uint16_t * bytes_read);

uint64_t mmt_bytestream_to_number64(const uint8_t * str, uint16_t max_chars_to_read, uint16_t * bytes_read);

uint32_t mmt_bytestream_dec_or_hex_to_number(const uint8_t * str, uint16_t max_chars_to_read, uint16_t * bytes_read);
uint64_t mmt_bytestream_dec_or_hex_to_number64(const uint8_t * str, uint16_t max_chars_to_read, uint16_t * bytes_read);

uint32_t mmt_bytestream_to_ipv4(const uint8_t * str, uint16_t max_chars_to_read, uint16_t * bytes_read);

/* function to parse a packet which has line based information into a line based structure
 * this function will also set some well known line pointers like:
 *  - host, user agent, empty line,....
 */
void mmt_parse_packet_line_info(ipacket_t * ipacket);

void mmt_parse_packet_line_info_unix(ipacket_t * ipacket);

uint16_t mmt_check_for_email_address(ipacket_t * ipacket, uint16_t counter);

static inline uint16_t
ntohs_mmt_bytestream_to_number(const uint8_t * str, uint16_t max_chars_to_read, uint16_t * bytes_read) {
    uint16_t val = mmt_bytestream_to_number(str, max_chars_to_read, bytes_read);
    return ntohs(val);
}

/* reset ip to zero */
static inline void
 mmt_set_ip_to_zeros(mmt_ip_addr_t * ip) {
    memset(ip, 0, sizeof (mmt_ip_addr_t));
}

static inline int
mmt_is_ip_set(const mmt_ip_addr_t * ip) {
    return memcmp(ip, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", sizeof (mmt_ip_addr_t)) != 0;
}

/* check if the source ip address in packet and ip are equal */
static inline int
mmt_compare_packet_source_ip_to_given_ip(const struct mmt_tcpip_internal_packet_struct *packet, const mmt_ip_addr_t * ip) {
#ifdef MMT_SUPPORT_IPV6
    if (packet->iphv6 != NULL) {
        if (packet->iphv6->saddr.mmt_v6_u.u6_addr64[0] == ip->ipv6.mmt_v6_u.u6_addr64[0] &&
                packet->iphv6->saddr.mmt_v6_u.u6_addr64[1] == ip->ipv6.mmt_v6_u.u6_addr64[1]) {

            return 1;
        } else {
            return 0;
        }
    }
#endif
    if (packet->iph->saddr == ip->ipv4) {
        return 1;
    }
    return 0;
}

/* check if the destination ip address in packet and ip are equal */
static inline int
mmt_compare_packet_destination_ip_to_given_ip(const struct mmt_tcpip_internal_packet_struct *packet, const mmt_ip_addr_t * ip) {
#ifdef MMT_SUPPORT_IPV6
    if (packet->iphv6 != NULL) {
        if (packet->iphv6->daddr.mmt_v6_u.u6_addr64[0] == ip->ipv6.mmt_v6_u.u6_addr64[0] &&
                packet->iphv6->daddr.mmt_v6_u.u6_addr64[1] == ip->ipv6.mmt_v6_u.u6_addr64[1]) {
            return 1;
        } else {
            return 0;
        }
    }
#endif
    if (packet->iph->daddr == ip->ipv4) {
        return 1;
    }
    return 0;
}

/* get the source ip address from packet and put it into ip */
static inline void
mmt_get_source_ip_from_packet(const struct mmt_tcpip_internal_packet_struct *packet, mmt_ip_addr_t * ip) {
    mmt_set_ip_to_zeros(ip);
#ifdef MMT_SUPPORT_IPV6
    if (packet->iphv6 != NULL) {
        ip->ipv6.mmt_v6_u.u6_addr64[0] = packet->iphv6->saddr.mmt_v6_u.u6_addr64[0];
        ip->ipv6.mmt_v6_u.u6_addr64[1] = packet->iphv6->saddr.mmt_v6_u.u6_addr64[1];
    } else
#endif
        ip->ipv4 = packet->iph->saddr;
}

/* get the destination ip address from packet and put it into ip */
static inline void
mmt_get_destination_ip_from_packet(const struct mmt_tcpip_internal_packet_struct *packet, mmt_ip_addr_t * ip) {
    mmt_set_ip_to_zeros(ip);
#ifdef MMT_SUPPORT_IPV6
    if (packet->iphv6 != NULL) {
        ip->ipv6.mmt_v6_u.u6_addr64[0] = packet->iphv6->daddr.mmt_v6_u.u6_addr64[0];
        ip->ipv6.mmt_v6_u.u6_addr64[1] = packet->iphv6->daddr.mmt_v6_u.u6_addr64[1];
    } else
#endif
        ip->ipv4 = packet->iph->daddr;
}

#ifdef	__cplusplus
}
#endif

#endif	/* MMT_TCPIP_UTILS_H */


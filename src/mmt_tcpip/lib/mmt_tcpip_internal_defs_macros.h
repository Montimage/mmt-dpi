/*
 * File:   mmt_tcpip_internal_defs_macros.h
 * Author: montimage
 *
 * Created on December 20, 2012, 5:24 PM
 */

#ifndef MMT_TCPIP_INTERNAL_DEFS_MACROS_H
#define	MMT_TCPIP_INTERNAL_DEFS_MACROS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "../include/mmt_tcpip_protocols.h"

#ifndef OPENDPI_NETFILTER_MODULE
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#endif

//#define __forceinline __attribute__((always_inline))
#if !(defined(_WIN32))
 #if 1 && !defined __APPLE__ && !defined __FreeBSD__
  #ifndef OPENDPI_NETFILTER_MODULE
   #include <endian.h>
   #include <byteswap.h>
  #else
   #include <asm/byteorder.h>
  #endif
 #endif							/* not _WIN32 && not APPLE) */
#endif /* ntop */

    /* default includes */

#if defined(__APPLE__) || defined(_WIN32) || defined(__FreeBSD__)

#ifndef _WIN32
#include <sys/param.h>
#endif

#if defined(__FreeBSD__)
#include <netinet/in.h>
#endif
#else							/* APPLE */
#ifndef OPENDPI_NETFILTER_MODULE
#include <netinet/in.h>
#endif
#include <netinet/ip.h>
//#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#endif

/* generic timestamp counter type */
#define MMT_INTERNAL_TIMESTAMP_TYPE		uint32_t

    /* misc definitions */
#define MMT_DEFAULT_MAX_TCP_RETRANSMISSION_WINDOW_SIZE 0x10000

    typedef enum {
        MMT_REAL_PROTOCOL = 0,
        MMT_CORRELATED_PROTOCOL = 1
    } mmt_protocol_type_t;

    typedef enum {
        MMT_LOG_ERROR,
        MMT_LOG_TRACE,
        MMT_LOG_DEBUG
    } mmt_log_level_t;

    typedef void (*mmt_debug_function_ptr) (uint32_t protocol,
            void *module_struct, mmt_log_level_t log_level, const char *format, ...);


    ////////////////////////////////////////////////////////////////////////////////
    ///////////// INTERNAL MACROS - MUST BE UPDATED WITH EVERY VERSION /////////////
    ////////////////////////////////////////////////////////////////////////////////

    /* The current number of protocols is 432! bitmask is 7 * 64bits*/

    typedef struct mmt_protocol_bitmask_struct {
        uint64_t bitmask[10];
    } mmt_protocol_bitmask_t;
#define MMT_PROTOCOL_BITMASK struct mmt_protocol_bitmask_struct



#define MMT_SAVE_AS_BITMASK(bmask,value)           \
  {                   \
  (bmask).bitmask[0] = 0;               \
  (bmask).bitmask[1] = 0;               \
  (bmask).bitmask[2] = 0;               \
  (bmask).bitmask[3] = 0;               \
  (bmask).bitmask[4] = 0;               \
  (bmask).bitmask[5] = 0;               \
  (bmask).bitmask[6] = 0;               \
  (bmask).bitmask[(value) >> 6] = (((uint64_t)1)<<((value) & 0x3F));     \
}

#define MMT_BITMASK_COMPARE(a,b) (((a).bitmask[0]) & ((b).bitmask[0]) || ((a).bitmask[1]) & ((b).bitmask[1]) || ((a).bitmask[2]) & ((b).bitmask[2]) || ((a).bitmask[3]) & ((b).bitmask[3]) || ((a).bitmask[4]) & ((b).bitmask[4]) || ((a).bitmask[5]) & ((b).bitmask[5]) || ((a).bitmask[6]) & ((b).bitmask[6]))
#define MMT_COMPARE_IPV6_ADDRESSES(x,y) ((((uint64_t *)(x))[0]) < (((uint64_t *)(y))[0]) || ( (((uint64_t *)(x))[0]) == (((uint64_t *)(y))[0]) && (((uint64_t *)(x))[1]) < (((uint64_t *)(y))[1])) )
#define MMT_BITMASK_MATCH(a,b) (((a).bitmask[0]) == ((b).bitmask[0]) && ((a).bitmask[1]) == ((b).bitmask[1]) && ((a).bitmask[2]) == ((b).bitmask[2]) && ((a).bitmask[3]) == ((b).bitmask[3]) && ((a).bitmask[4]) == ((b).bitmask[4]) && ((a).bitmask[5]) == ((b).bitmask[5]) && ((a).bitmask[6]) == ((b).bitmask[6]))

    // all protocols in b are also in a
#define MMT_BITMASK_CONTAINS_BITMASK(a,b)  ((((a).bitmask[0] & (b).bitmask[0]) == (b).bitmask[0]) && (((a).bitmask[1] & (b).bitmask[1]) == (b).bitmask[1]) && (((a).bitmask[2] & (b).bitmask[2]) == (b).bitmask[2]) && (((a).bitmask[3] & (b).bitmask[3]) == (b).bitmask[3]) && (((a).bitmask[4] & (b).bitmask[4]) == (b).bitmask[4]) && (((a).bitmask[5] & (b).bitmask[5]) == (b).bitmask[5]) && (((a).bitmask[6] & (b).bitmask[6]) == (b).bitmask[6]))


#define MMT_BITMASK_ADD(a,b)   {(a).bitmask[0] |= (b).bitmask[0]; (a).bitmask[1] |= (b).bitmask[1]; (a).bitmask[2] |= (b).bitmask[2]; (a).bitmask[3] |= (b).bitmask[3]; (a).bitmask[4] |= (b).bitmask[4]; (a).bitmask[5] |= (b).bitmask[5]; (a).bitmask[6] |= (b).bitmask[6];}
#define MMT_BITMASK_AND(a,b)   {(a).bitmask[0] &= (b).bitmask[0]; (a).bitmask[1] &= (b).bitmask[1]; (a).bitmask[2] &= (b).bitmask[2]; (a).bitmask[3] &= (b).bitmask[3]; (a).bitmask[4] &= (b).bitmask[4]; (a).bitmask[5] &= (b).bitmask[5]; (a).bitmask[6] &= (b).bitmask[6];}
#define MMT_BITMASK_DEL(a,b)   {(a).bitmask[0] = (a).bitmask[0] & (~((b).bitmask[0])); (a).bitmask[1] = (a).bitmask[1] & ( ~((b).bitmask[1])); (a).bitmask[2] = (a).bitmask[2] & (~((b).bitmask[2])); (a).bitmask[3] = (a).bitmask[3] & (~((b).bitmask[3])); (a).bitmask[4] = (a).bitmask[4] & (~((b).bitmask[4])); (a).bitmask[5] = (a).bitmask[5] & (~((b).bitmask[5])); (a).bitmask[6] = (a).bitmask[6] & (~((b).bitmask[6]));}

#define MMT_BITMASK_SET(a,b)   {(a).bitmask[0] = ((b).bitmask[0]); (a).bitmask[1] = (b).bitmask[1]; (a).bitmask[2] = (b).bitmask[2]; (a).bitmask[3] = (b).bitmask[3]; (a).bitmask[4] = (b).bitmask[4]; (a).bitmask[5] = (b).bitmask[5]; (a).bitmask[6] = (b).bitmask[6];}

#define MMT_BITMASK_RESET(a)   {((a).bitmask[0]) = 0; ((a).bitmask[1]) = 0; ((a).bitmask[2]) = 0; ((a).bitmask[3]) = 0; ((a).bitmask[4]) = 0; ((a).bitmask[5]) = 0; ((a).bitmask[6]) = 0;}
#define MMT_BITMASK_SET_ALL(a)   {((a).bitmask[0]) = 0xFFFFFFFFFFFFFFFFULL; ((a).bitmask[1]) = 0xFFFFFFFFFFFFFFFFULL; ((a).bitmask[2]) = 0xFFFFFFFFFFFFFFFFULL; ((a).bitmask[3]) = 0xFFFFFFFFFFFFFFFFULL; ((a).bitmask[4]) = 0xFFFFFFFFFFFFFFFFULL; ((a).bitmask[5]) = 0xFFFFFFFFFFFFFFFFULL; ((a).bitmask[6]) = 0xFFFFFFFFFFFFFFFFULL;}

    /* this is a very very tricky macro *g*,
     * the compiler will remove all shifts here if the protocol is static...
     */
#define MMT_ADD_PROTOCOL_TO_BITMASK(bmask,value)         \
  {(bmask).bitmask[(value) >> 6] |= (((uint64_t)1)<<((value) & 0x3F));}    \

#define MMT_DEL_PROTOCOL_FROM_BITMASK(bmask,value)               \
  {(bmask).bitmask[(value) >> 6] = (bmask).bitmask[(value) >> 6] & (~(((uint64_t)1)<<((value) & 0x3F)));}  \

#define MMT_COMPARE_PROTOCOL_TO_BITMASK(bmask,value)         \
  ((bmask).bitmask[(value) >> 6] & (((uint64_t)1)<<((value) & 0x3F)))      \


#define MMT_BITMASK_DEBUG_OUTPUT_BITMASK_STRING  "%llu , %llu , %llu, %llu, %llu, %llu, %llu"
#define MMT_BITMASK_DEBUG_OUTPUT_BITMASK_VALUE(bm) (bm).bitmask[0] , (bm).bitmask[1] , (bm).bitmask[2], (bm).bitmask[3], (bm).bitmask[4], (bm).bitmask[5], (bm).bitmask[6]

#define MMT_BITMASK_IS_ZERO(a) ( (a).bitmask[0] == 0 && (a).bitmask[1] == 0 && (a).bitmask[2] == 0 && (a).bitmask[3] == 0 && (a).bitmask[4] == 0 && (a).bitmask[5] == 0 && (a).bitmask[6] == 0)

#define MMT_BITMASK_CONTAINS_NEGATED_BITMASK(a,b) ((((a).bitmask[0] & ~(b).bitmask[0]) == ~(b).bitmask[0]) && (((a).bitmask[1] & ~(b).bitmask[1]) == ~(b).bitmask[1]) && (((a).bitmask[2] & ~(b).bitmask[2]) == ~(b).bitmask[2]) && (((a).bitmask[3] & ~(b).bitmask[3]) == ~(b).bitmask[3]) && (((a).bitmask[4] & ~(b).bitmask[4]) == ~(b).bitmask[4]) && (((a).bitmask[5] & ~(b).bitmask[5]) == ~(b).bitmask[5]) && (((a).bitmask[6] & ~(b).bitmask[6]) == ~(b).bitmask[6]))

#define MMT_PARSE_PACKET_LINE_INFO(ipacket, packet)                        \
                        if (packet->packet_lines_parsed_complete != 1) {        \
                                mmt_parse_packet_line_info(ipacket);      \
                        }                                                       \
////////////////////////////////////////////////////////////////////////////////
    //////////////////////////// END OF INTERNAL MACROS ////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////

#define mmt_mem_cmp memcmp

#define MMT_MICRO_IN_SEC        1000000 /**< Number of microseconds in a second */

#define MMT_USE_ASYMMETRIC_DETECTION             0
#define MMT_SELECTION_BITMASK_PROTOCOL_SIZE			uint32_t

#define MMT_SELECTION_BITMASK_PROTOCOL_IP			(1<<0)
#define MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP			(1<<1)
#define MMT_SELECTION_BITMASK_PROTOCOL_INT_UDP			(1<<2)
#define MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP		(1<<3)
#define MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD		(1<<4)
#define MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION	(1<<5)
#define MMT_SELECTION_BITMASK_PROTOCOL_IPV6			(1<<6)
#define MMT_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6		(1<<7)
#define MMT_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC		(1<<8)
    /* now combined detections */

    /* v4 */
#define MMT_SELECTION_BITMASK_PROTOCOL_TCP (MMT_SELECTION_BITMASK_PROTOCOL_IP | MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP)
#define MMT_SELECTION_BITMASK_PROTOCOL_UDP (MMT_SELECTION_BITMASK_PROTOCOL_IP | MMT_SELECTION_BITMASK_PROTOCOL_INT_UDP)
#define MMT_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP (MMT_SELECTION_BITMASK_PROTOCOL_IP | MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP)

    /* v6 */
#define MMT_SELECTION_BITMASK_PROTOCOL_V6_TCP (MMT_SELECTION_BITMASK_PROTOCOL_IPV6 | MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP)
#define MMT_SELECTION_BITMASK_PROTOCOL_V6_UDP (MMT_SELECTION_BITMASK_PROTOCOL_IPV6 | MMT_SELECTION_BITMASK_PROTOCOL_INT_UDP)
#define MMT_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP (MMT_SELECTION_BITMASK_PROTOCOL_IPV6 | MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP)

    /* v4 or v6 */
#define MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP (MMT_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6 | MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP)
#define MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP (MMT_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6 | MMT_SELECTION_BITMASK_PROTOCOL_INT_UDP)
#define MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP (MMT_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6 | MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP)


#define MMT_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD		(MMT_SELECTION_BITMASK_PROTOCOL_TCP | MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define MMT_SELECTION_BITMASK_PROTOCOL_V6_TCP_WITH_PAYLOAD		(MMT_SELECTION_BITMASK_PROTOCOL_V6_TCP | MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD		(MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP | MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

    /* does it make sense to talk about udp with payload ??? have you ever seen empty udp packets ? */
#define MMT_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD		(MMT_SELECTION_BITMASK_PROTOCOL_UDP | MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define MMT_SELECTION_BITMASK_PROTOCOL_V6_UDP_WITH_PAYLOAD		(MMT_SELECTION_BITMASK_PROTOCOL_V6_UDP | MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD		(MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP | MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

#define MMT_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD		(MMT_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP | MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define MMT_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP_WITH_PAYLOAD		(MMT_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP | MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD		(MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP | MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

#define MMT_SELECTION_BITMASK_PROTOCOL_TCP_WITHOUT_RETRANSMISSION	(MMT_SELECTION_BITMASK_PROTOCOL_TCP | MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)
#define MMT_SELECTION_BITMASK_PROTOCOL_V6_TCP_WITHOUT_RETRANSMISSION	(MMT_SELECTION_BITMASK_PROTOCOL_V6_TCP | MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)
#define MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITHOUT_RETRANSMISSION	(MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP | MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)

#define MMT_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITHOUT_RETRANSMISSION	(MMT_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP | MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)
#define MMT_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION	(MMT_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP | MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)
#define MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION	(MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP | MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)

#define MMT_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(MMT_SELECTION_BITMASK_PROTOCOL_TCP | MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define MMT_SELECTION_BITMASK_PROTOCOL_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(MMT_SELECTION_BITMASK_PROTOCOL_V6_TCP | MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP | MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

#define MMT_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(MMT_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP | MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define MMT_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(MMT_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP | MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP | MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

    /* safe src/dst protocol check macros... */

#define MMT_SRC_HAS_PROTOCOL(src,protocol) ((src) != NULL && MMT_COMPARE_PROTOCOL_TO_BITMASK((src)->detected_protocol_bitmask,(protocol)) != 0)

#define MMT_DST_HAS_PROTOCOL(dst,protocol) ((dst) != NULL && MMT_COMPARE_PROTOCOL_TO_BITMASK((dst)->detected_protocol_bitmask,(protocol)) != 0)

#define MMT_SRC_OR_DST_HAS_PROTOCOL(src,dst,protocol) (MMT_SRC_HAS_PROTOCOL(src,protocol) || MMT_SRC_HAS_PROTOCOL(dst,protocol))

    /**
     * convenience macro to check for excluded protocol
     * a protocol is excluded if the flow is known and either the protocol is not detected at all
     * or the excluded bitmask contains the protocol
     */
#define MMT_FLOW_PROTOCOL_EXCLUDED(flow,protocol) ((flow) != NULL && (MMT_COMPARE_PROTOCOL_TO_BITMASK((flow)->excluded_protocol_bitmask, (protocol)) != 0 ) )

    /* TODO: rebuild all memory areas to have a more aligned memory block here */



    /* DEFINITION OF MAX LINE NUMBERS FOR line parse algorithm */
#define MMT_MAX_PARSE_LINES_PER_PACKET 200


    /**********************
     * detection features *
     **********************/
#define MMT_SELECT_DETECTION_WITH_REAL_PROTOCOL ( 1 << 0 )

#if defined(_WIN32)
#define MMT_LOG_BITTORRENT(...) {}
#define MMT_LOG_GNUTELLA(...) {}
#define MMT_LOG_EDONKEY(...) {}
#define MMT_LOG(...) {}

#else
#define MMT_LOG_BITTORRENT(proto, mod, log_level, args...) {}

#define MMT_LOG_GNUTELLA(proto, mod, log_level, args...) {}

#define MMT_LOG_EDONKEY(proto, mod, log_level, args...) {}
#define MMT_LOG(proto, mod, log_level, args...) {}
#endif

    /* the get_uXX will return raw network packet bytes !! */
#define get_u8(X,O)  (*(uint8_t *)(((uint8_t *)X) + O))
#define get_u16(X,O)  (*(uint16_t *)(((uint8_t *)X) + O))
#define get_u32(X,O)  (*(uint32_t *)(((uint8_t *)X) + O))
#define get_u64(X,O)  (*(uint64_t *)(((uint8_t *)X) + O))

    /* new definitions to get little endian from network bytes */
#define get_ul8(X,O) get_u8(X,O)

#ifndef OPENDPI_NETFILTER_MODULE
#ifndef __BYTE_ORDER
#define __BYTE_ORDER BYTE_ORDER
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#define __BIG_ENDIAN BIG_ENDIAN
#endif
#else
#ifdef __BIG_ENDIAN
#define __BYTE_ORDER __BIG_ENDIAN
#else
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif
#endif


#if defined( __LITTLE_ENDIAN) && __BYTE_ORDER == __LITTLE_ENDIAN

#define get_l16(X,O)  get_u16(X,O)
#define get_l32(X,O)  get_u32(X,O)

#elif defined( __BIG_ENDIAN) && __BYTE_ORDER == __BIG_ENDIAN

    /* convert the bytes from big to little endian */
#ifndef OPENDPI_NETFILTER_MODULE
#define get_l16(X,O) bswap_16(get_u16(X,O))
#define get_l32(X,O) bswap_32(get_u32(X,O))
#else
#define get_l16(X,O) __cpu_to_le16(get_u16(X,O))
#define get_l32(X,O) __cpu_to_le32(get_u32(X,O))
#endif

#else

#error "__BYTE_ORDER MUST BE DEFINED !"

#endif							/* __BYTE_ORDER */


#ifdef	__cplusplus
}
#endif

#endif	/* MMT_TCPIP_INTERNAL_DEFS_MACROS_H */


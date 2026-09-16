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

#ifndef MMT_NETFILTER_MODULE
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#endif

//#define __forceinline __attribute__((always_inline))
#ifndef MMT_NETFILTER_MODULE
 #include <endian.h>
 #include <byteswap.h>
#else
 #include <asm/byteorder.h>
#endif

    /* default includes */

#ifndef MMT_NETFILTER_MODULE
#include <netinet/in.h>
#endif
#include <netinet/ip.h>
//#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/*
 * Issue #57 — alignment-safe views over the (byte-aligned) packet buffer.
 *
 * Network header pointers are routinely formed by casting "&data[offset]" of a
 * char-aligned capture buffer to a multi-byte header struct. struct
 * iphdr/tcphdr/udphdr require 2-/4-byte alignment for their fields, so when the
 * offset is odd (or merely not 4-aligned) dereferencing a field through such a
 * pointer is a misaligned access: undefined behaviour that aborts under
 * -fsanitize=alignment (the BUILD=asan profile, no-recover) and is non-portable
 * in release builds.
 *
 * These typedefs alias the same structs with the alignment requirement lowered
 * to 1, so the compiler emits alignment-safe loads. On architectures with
 * native unaligned access (x86_64, aarch64) each field access still lowers to a
 * single load instruction — there is no hot-path cost. Only the cast target /
 * pointer-variable type changes; field-access expressions and classification
 * behaviour are unchanged.
 */
typedef struct iphdr  __attribute__((aligned(1))) mmt_una_iphdr_t;
typedef struct tcphdr __attribute__((aligned(1))) mmt_una_tcphdr_t;
typedef struct udphdr __attribute__((aligned(1))) mmt_una_udphdr_t;

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

    /*
     * Protocol bitmask: one bit per protocol id (bit p == protocol id p).
     *
     * The number of 64-bit words MUST cover the full protocol-id space, i.e.
     * every id in [0, PROTO_MAX_IDENTIFIER). PROTO_MAX_IDENTIFIER (mmt_core.h)
     * is currently 1000, which needs (1000 >> 6) + 1 = 16 words.
     *
     * The array was historically [10] (640 bits, valid ids 0..639), which
     * silently overflowed for any id >= 640 -- e.g. PROTO_MQTT (657),
     * PROTO_INT (658) and PROTO_QUIC_IETF (661) all index bitmask[10], a
     * global-buffer-overflow (issues #51 and #52). Keep this value derived from
     * PROTO_MAX_IDENTIFIER; the _Static_assert below guards it against drift in
     * any translation unit that also sees mmt_core.h.
     */
#define MMT_PROTOCOL_BITMASK_NUM_WORDS 16

    typedef struct mmt_protocol_bitmask_struct {
        uint64_t bitmask[MMT_PROTOCOL_BITMASK_NUM_WORDS];
    } mmt_protocol_bitmask_t;
#define MMT_PROTOCOL_BITMASK struct mmt_protocol_bitmask_struct

#if defined(PROTO_MAX_IDENTIFIER) && !defined(__cplusplus) \
    && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    _Static_assert(MMT_PROTOCOL_BITMASK_NUM_WORDS * 64 >= PROTO_MAX_IDENTIFIER,
        "mmt_protocol_bitmask is too small to hold all protocol ids up to "
        "PROTO_MAX_IDENTIFIER; bump MMT_PROTOCOL_BITMASK_NUM_WORDS");
#endif

    /* Per-word helpers covering EVERY word of the (resized) bitmask. Driven by
     * MMT_PROTOCOL_BITMASK_NUM_WORDS so full-width coverage cannot drift out of
     * sync with the array size. Implemented as inline functions because the
     * matching macros are used in expression context (e.g. MMT_BITMASK_COMPARE
     * inside an if). */
    static inline int mmt_bitmask_compare(const mmt_protocol_bitmask_t *a,
                                          const mmt_protocol_bitmask_t *b) {
        int _i;
        for (_i = 0; _i < MMT_PROTOCOL_BITMASK_NUM_WORDS; _i++)
            if (a->bitmask[_i] & b->bitmask[_i]) return 1;
        return 0;
    }
    static inline int mmt_bitmask_match(const mmt_protocol_bitmask_t *a,
                                        const mmt_protocol_bitmask_t *b) {
        int _i;
        for (_i = 0; _i < MMT_PROTOCOL_BITMASK_NUM_WORDS; _i++)
            if (a->bitmask[_i] != b->bitmask[_i]) return 0;
        return 1;
    }
    /* all protocols in b are also in a */
    static inline int mmt_bitmask_contains_bitmask(const mmt_protocol_bitmask_t *a,
                                                   const mmt_protocol_bitmask_t *b) {
        int _i;
        for (_i = 0; _i < MMT_PROTOCOL_BITMASK_NUM_WORDS; _i++)
            if ((a->bitmask[_i] & b->bitmask[_i]) != b->bitmask[_i]) return 0;
        return 1;
    }
    static inline int mmt_bitmask_contains_negated_bitmask(const mmt_protocol_bitmask_t *a,
                                                           const mmt_protocol_bitmask_t *b) {
        int _i;
        for (_i = 0; _i < MMT_PROTOCOL_BITMASK_NUM_WORDS; _i++)
            if ((a->bitmask[_i] & ~b->bitmask[_i]) != ~b->bitmask[_i]) return 0;
        return 1;
    }
    static inline int mmt_bitmask_is_zero(const mmt_protocol_bitmask_t *a) {
        int _i;
        for (_i = 0; _i < MMT_PROTOCOL_BITMASK_NUM_WORDS; _i++)
            if (a->bitmask[_i] != 0) return 0;
        return 1;
    }



#define MMT_SAVE_AS_BITMASK(bmask,value)                                        \
  do {                                                                          \
    int _mmt_bm_i;                                                              \
    for (_mmt_bm_i = 0; _mmt_bm_i < MMT_PROTOCOL_BITMASK_NUM_WORDS; _mmt_bm_i++)\
      (bmask).bitmask[_mmt_bm_i] = 0;                                           \
    (bmask).bitmask[(value) >> 6] = (((uint64_t)1) << ((value) & 0x3F));        \
  } while (0)

#define MMT_BITMASK_COMPARE(a,b) mmt_bitmask_compare(&(a),&(b))
#define MMT_COMPARE_IPV6_ADDRESSES(x,y) ((((uint64_t *)(x))[0]) < (((uint64_t *)(y))[0]) || ( (((uint64_t *)(x))[0]) == (((uint64_t *)(y))[0]) && (((uint64_t *)(x))[1]) < (((uint64_t *)(y))[1])) )
#define MMT_BITMASK_MATCH(a,b) mmt_bitmask_match(&(a),&(b))

    // all protocols in b are also in a
#define MMT_BITMASK_CONTAINS_BITMASK(a,b) mmt_bitmask_contains_bitmask(&(a),&(b))


#define MMT_BITMASK_ADD(a,b)   do { int _mmt_bm_i; for (_mmt_bm_i = 0; _mmt_bm_i < MMT_PROTOCOL_BITMASK_NUM_WORDS; _mmt_bm_i++) (a).bitmask[_mmt_bm_i] |= (b).bitmask[_mmt_bm_i]; } while (0)
#define MMT_BITMASK_AND(a,b)   do { int _mmt_bm_i; for (_mmt_bm_i = 0; _mmt_bm_i < MMT_PROTOCOL_BITMASK_NUM_WORDS; _mmt_bm_i++) (a).bitmask[_mmt_bm_i] &= (b).bitmask[_mmt_bm_i]; } while (0)
#define MMT_BITMASK_DEL(a,b)   do { int _mmt_bm_i; for (_mmt_bm_i = 0; _mmt_bm_i < MMT_PROTOCOL_BITMASK_NUM_WORDS; _mmt_bm_i++) (a).bitmask[_mmt_bm_i] &= ~((b).bitmask[_mmt_bm_i]); } while (0)

#define MMT_BITMASK_SET(a,b)   do { int _mmt_bm_i; for (_mmt_bm_i = 0; _mmt_bm_i < MMT_PROTOCOL_BITMASK_NUM_WORDS; _mmt_bm_i++) (a).bitmask[_mmt_bm_i] = (b).bitmask[_mmt_bm_i]; } while (0)

#define MMT_BITMASK_RESET(a)   do { int _mmt_bm_i; for (_mmt_bm_i = 0; _mmt_bm_i < MMT_PROTOCOL_BITMASK_NUM_WORDS; _mmt_bm_i++) (a).bitmask[_mmt_bm_i] = 0; } while (0)
#define MMT_BITMASK_SET_ALL(a) do { int _mmt_bm_i; for (_mmt_bm_i = 0; _mmt_bm_i < MMT_PROTOCOL_BITMASK_NUM_WORDS; _mmt_bm_i++) (a).bitmask[_mmt_bm_i] = 0xFFFFFFFFFFFFFFFFULL; } while (0)

    /* this is a very very tricky macro *g*,
     * the compiler will remove all shifts here if the protocol is static...
     */
#define MMT_ADD_PROTOCOL_TO_BITMASK(bmask,value)         \
  {(bmask).bitmask[(value) >> 6] |= (((uint64_t)1)<<((value) & 0x3F));}    \

#define MMT_DEL_PROTOCOL_FROM_BITMASK(bmask,value)               \
  {(bmask).bitmask[(value) >> 6] = (bmask).bitmask[(value) >> 6] & (~(((uint64_t)1)<<((value) & 0x3F)));}  \

#define MMT_COMPARE_PROTOCOL_TO_BITMASK(bmask,value)         \
  ((bmask).bitmask[(value) >> 6] & (((uint64_t)1)<<((value) & 0x3F)))      \


/* Debug helper: prints all MMT_PROTOCOL_BITMASK_NUM_WORDS (16) words. */
#define MMT_BITMASK_DEBUG_OUTPUT_BITMASK_STRING  "%llu , %llu , %llu, %llu, %llu, %llu, %llu, %llu, %llu, %llu, %llu, %llu, %llu, %llu, %llu, %llu"
#define MMT_BITMASK_DEBUG_OUTPUT_BITMASK_VALUE(bm) (bm).bitmask[0] , (bm).bitmask[1] , (bm).bitmask[2], (bm).bitmask[3], (bm).bitmask[4], (bm).bitmask[5], (bm).bitmask[6], (bm).bitmask[7], (bm).bitmask[8], (bm).bitmask[9], (bm).bitmask[10], (bm).bitmask[11], (bm).bitmask[12], (bm).bitmask[13], (bm).bitmask[14], (bm).bitmask[15]

#define MMT_BITMASK_IS_ZERO(a) mmt_bitmask_is_zero(&(a))

#define MMT_BITMASK_CONTAINS_NEGATED_BITMASK(a,b) mmt_bitmask_contains_negated_bitmask(&(a),&(b))

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

#define MMT_SELECTION_BITMASK_PROTOCOL_IP			(1<<0) // 1
#define MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP			(1<<1) //10
#define MMT_SELECTION_BITMASK_PROTOCOL_INT_UDP			(1<<2) // 100
#define MMT_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP		(1<<3) // 1000
#define MMT_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD		(1<<4) // 10000
#define MMT_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION	(1<<5) // 100000
#define MMT_SELECTION_BITMASK_PROTOCOL_IPV6			(1<<6) // 1000000
#define MMT_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6		(1<<7) // 10000000
#define MMT_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC		(1<<8)// 100000000
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

    /* Issue #226 (F-DEAD-011): every protocol used to carry a private
     * `void mmt_init_classify_me_<proto>(void)` wrapper that only filled its
     * translation unit's selection/detection/excluded bitmasks — 106 copies of
     * the same body differing only in the protocol id. They are folded into
     * this single generic helper, invoked by the registered
     * init_proto_*_struct functions that proto_init_table
     * (proto_init_list.def) drives. The bitmasks stay file-scope in each
     * protocol TU (the check functions read them directly), so callers pass
     * pointers to their own three globals.
     *
     * `detection_add` is an extra protocol OR'd into detection_bitmask on top
     * of PROTO_UNKNOWN — pass PROTO_UNKNOWN when the protocol marks nothing
     * extra (adding PROTO_UNKNOWN again would be a no-op anyway).
     *
     * static inline keeps the helper a single source definition with no
     * exported symbol, so deleting the 106 wrappers drops libmmt_tcpip.so's
     * exported `_init` symbols by exactly 106. */
    static inline void mmt_init_classify_bitmasks(
        MMT_SELECTION_BITMASK_PROTOCOL_SIZE *selection_bitmask,
        MMT_PROTOCOL_BITMASK *detection_bitmask,
        MMT_PROTOCOL_BITMASK *excluded_protocol_bitmask,
        MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_value,
        uint32_t detection_add, uint32_t excluded_proto) {
        *selection_bitmask = selection_value;
        MMT_SAVE_AS_BITMASK(*detection_bitmask, PROTO_UNKNOWN);
        if (detection_add != PROTO_UNKNOWN) {
            MMT_ADD_PROTOCOL_TO_BITMASK(*detection_bitmask, detection_add);
        }
        MMT_SAVE_AS_BITMASK(*excluded_protocol_bitmask, excluded_proto);
    }

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

#define MMT_LOG_BITTORRENT(proto, mod, log_level, args...) {}

#define MMT_LOG_GNUTELLA(proto, mod, log_level, args...) {}

#define MMT_LOG_EDONKEY(proto, mod, log_level, args...) {}
#define MMT_LOG(proto, mod, log_level, args...) {}

    /* the get_uXX will return raw network packet bytes !! */
/*
 * Issue #57: these accessors read multi-byte integers straight out of the
 * byte-aligned packet payload. The historical "*(uint16_t*)(p+o)" form is a
 * misaligned load whenever (p+o) is not naturally aligned — undefined
 * behaviour that aborts under -fsanitize=alignment (BUILD=asan, no-recover).
 * Read the bytes with memcpy instead: the compiler lowers a fixed-size memcpy
 * to a single (unaligned) load on targets with native unaligned access
 * (x86_64, aarch64), so there is no hot-path cost, and the returned value is
 * identical. get_u8 is a single byte and is already alignment-safe.
 */
static inline uint16_t mmt_una_read_u16(const void *p, unsigned long o) {
    uint16_t v; memcpy(&v, (const uint8_t *)p + o, sizeof(v)); return v;
}
static inline uint32_t mmt_una_read_u32(const void *p, unsigned long o) {
    uint32_t v; memcpy(&v, (const uint8_t *)p + o, sizeof(v)); return v;
}
static inline uint64_t mmt_una_read_u64(const void *p, unsigned long o) {
    uint64_t v; memcpy(&v, (const uint8_t *)p + o, sizeof(v)); return v;
}
#define get_u8(X,O)  (*(uint8_t *)(((uint8_t *)X) + O))
#define get_u16(X,O)  mmt_una_read_u16((X), (O))
#define get_u32(X,O)  mmt_una_read_u32((X), (O))
#define get_u64(X,O)  mmt_una_read_u64((X), (O))

    /* new definitions to get little endian from network bytes */
#define get_ul8(X,O) get_u8(X,O)

#ifndef MMT_NETFILTER_MODULE
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
#ifndef MMT_NETFILTER_MODULE
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


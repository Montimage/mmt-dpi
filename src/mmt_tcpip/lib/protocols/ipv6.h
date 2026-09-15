/*
 * File:   ipv6.h
 * Author: montimage
 *
 * Created on 23 avril 2012, 17:08
 */

#ifndef IPV6_H
#define	IPV6_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "plugin_defs.h"
#include "mmt_core.h"
#include "ip.h"

#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS         0       /* IPv6 hop-by-hop options      */
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING         43      /* IPv6 routing header          */
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT        44      /* IPv6 fragmentation header    */
#endif
#ifndef IPPROTO_AH
#define IPPROTO_AH              51      /* Authentication Header        */
#endif
#ifndef IPPROTO_NONE
#define IPPROTO_NONE            59      /* IPv6 no next header          */
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS         60      /* IPv6 destination options     */
#endif
#ifndef IPPROTO_MH
#define IPPROTO_MH              135     /* IPv6 mobility header         */
#endif

#ifndef IPPROTO_HIP
#define IPPROTO_HIP              139     /* Host Identity Protocol         */
#endif

#ifndef IPPROTO_SHIM6P
#define IPPROTO_SHIM6P              140     /* Shim6 Protocol         */
#endif

    struct ipv6hdr {

        union {

            struct {
#if BYTE_ORDER == LITTLE_ENDIAN
                uint8_t priority : 4,
                        version : 4;
#elif BYTE_ORDER == BIG_ENDIAN
                uint8_t version : 4,
                        priority : 4;
#else
#error  "BYTE_ORDER must be defined"
#endif
                uint8_t flow_lbl[3];
            }l1_1;
            struct {
                uint16_t short_word_1;
                uint16_t short_word_2;
            }l1_2;
            uint32_t flow_label;
        };

        uint16_t payload_len;
        uint8_t nexthdr;
        uint8_t hop_limit;

        struct in6_addr saddr;
        struct in6_addr daddr;
    };
    struct ext_hdr_generic {
        uint8_t nexthdr;
        uint8_t ext_len;
        uint16_t data;
    };
    struct ext_hdr_fragment {
        uint8_t nexthdr;
        uint8_t reserved;
        uint16_t flag;
        uint32_t ident;
    };

    /*
     * Issue #59: the IPv6 header and the fragment extension header are formed by
     * casting "&data[offset]" of the byte-aligned capture buffer to these
     * structs and dereferencing multi-byte fields (payload_len, flag, ident,
     * flow_label, ...). When offset is not naturally aligned that deref is a
     * misaligned access — UB that aborts under -fsanitize=alignment (BUILD=asan)
     * and is non-portable in release builds. These typedefs alias the same
     * structs with the alignment requirement lowered to 1, so the compiler emits
     * alignment-safe loads. On targets with native unaligned access (x86_64,
     * aarch64) each field access still lowers to a single load — no hot-path
     * cost; only the cast/pointer type changes, field expressions are unchanged.
     * Mirrors the mmt_una_{iphdr,tcphdr,udphdr}_t views added in PR #58 (#57).
     */
    typedef struct ipv6hdr          __attribute__((aligned(1))) mmt_una_ipv6hdr_t;
    typedef struct ext_hdr_fragment __attribute__((aligned(1))) mmt_una_ext_hdr_fragment_t;

    int init_ip6_proto_struct();

#ifdef	__cplusplus
}
#endif

#endif	/* IPV6_H */


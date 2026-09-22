#include <stddef.h> /* offsetof — issue #59 alignment-safe field reads */
#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "ipv6.h"
#include "ip_session_id_management.h"
#include "proto_ipv6_dgram.h"
#include "proto_ip_dgram.h" /* Issue #201: frag-map sweep/evict helpers */
/* Shared IPv4/IPv6 L4-protocol dispatch table — emits the file-local
 * `static const uint16_t mmt_ip_l4_proto_table[256]` (issue #238). */
#include "ip_l4_proto_table.inc"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
/** macro to compare 2 IPv6 addresses with each other to identify the "smaller" IPv6 address  */

bool ipv6_session_comp(void * key1, void * key2) {
    mmt_session_key_t * l_session = (mmt_session_key_t *) key1;
    mmt_session_key_t * r_session = (mmt_session_key_t *) key2;

    // both flows of the same type
    int comp_val = mmt_memcmp(&l_session->next_proto, &r_session->next_proto, 5);
    if (comp_val == 0) {
   	 comp_val = mmt_memcmp(l_session->lower_ip, r_session->lower_ip, IPv6_ALEN);
   	 if (comp_val == 0) {
   		 comp_val = mmt_memcmp(l_session->higher_ip, r_session->higher_ip, IPv6_ALEN);
   	 }
    }
    return comp_val < 0;
}

/**
 * Issue #253 (F-PERF-008): one-call equality predicate for IPv6 session keys.
 * True iff the same fields ipv6_session_comp distinguishes agree — next_proto,
 * both ports and the 16 bytes of each interned IPv6 address — equivalent to
 * the old `!comp(a,b) && !comp(b,a)` probe but evaluated in a single pass.
 */
bool ipv6_session_equal(void * key1, void * key2) {
    mmt_session_key_t * l_session = (mmt_session_key_t *) key1;
    mmt_session_key_t * r_session = (mmt_session_key_t *) key2;

    return l_session->next_proto == r_session->next_proto
        && l_session->lower_ip_port == r_session->lower_ip_port
        && l_session->higher_ip_port == r_session->higher_ip_port
        && mmt_memcmp(l_session->lower_ip, r_session->lower_ip, IPv6_ALEN) == 0
        && mmt_memcmp(l_session->higher_ip, r_session->higher_ip, IPv6_ALEN) == 0;
}

/**
 * Hash of an IPv6 session key, consistent with ipv6_session_equal/
 * ipv6_session_comp: it mixes exactly the fields equality distinguishes —
 * next_proto, both ports and the 16 bytes of each interned IPv6 address — so
 * that any two keys that compare equal hash to the same value.
 *
 * Dependent-multiply count (asserted by tools/phase0/tests/
 * session_lookup_perf_test.sh): FNV-1a over the 37 key bytes ran 37
 * serially-dependent multiplies; the five multiplies below are INDEPENDENT
 * and the finalizer adds one dependent step — a chain 2 multiplies deep
 * before the table's inlined fmix64, versus ~40 before.
 */
uint64_t ipv6_session_hash(void * key) {
    mmt_session_key_t * s = (mmt_session_key_t *) key;
    uint64_t lip[2], hip[2];
    memcpy(lip, s->lower_ip, sizeof(lip));
    memcpy(hip, s->higher_ip, sizeof(hip));
    /* tuple word: next_proto(8b) | lower_ip_port(16b) | higher_ip_port(16b) */
    uint64_t w = (uint64_t) s->next_proto
               | ((uint64_t) s->lower_ip_port << 8)
               | ((uint64_t) s->higher_ip_port << 24);
    uint64_t h = w      * 0x9E3779B97F4A7C15ULL
               ^ lip[0] * 0xC2B2AE3D27D4EB4FULL
               ^ lip[1] * 0x165667B19E3779F9ULL
               ^ hip[0] * 0x2545F4914F6CDD1DULL
               ^ hip[1] * 0x9FB21C651E98DF25ULL;
    h *= 0xD6E8FEB86659FD93ULL;
    h ^= h >> 29;
    return h;
}

static inline
int is_extention_header(uint8_t next_header) {
    switch (next_header) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_FRAGMENT:
        case IPPROTO_AH:
        case IPPROTO_DSTOPTS:
        case IPPROTO_MH:
        case IPPROTO_HIP:
        case IPPROTO_ESP:
        case IPPROTO_SHIM6P:
            return 1;
        default:
            return 0;
    }
}

static inline
uint32_t get_next_header_offset(uint8_t current_header, const uint8_t * packet, uint8_t * next_hdr) {
    struct ext_hdr_generic * exthdr;
    switch (current_header) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_AH:
        case IPPROTO_HIP:
        case IPPROTO_ESP:
        case IPPROTO_SHIM6P:
        case IPPROTO_MH:
        case IPPROTO_DSTOPTS:
            exthdr = (struct ext_hdr_generic *) packet;
            *next_hdr = exthdr->nexthdr;
            // printf("next offset: %u\n",exthdr->ext_len);
            return 8 + ((uint32_t) (exthdr->ext_len) * 8); // The length is provided as the number of 8 octet words not including the first 8 octets
        case IPPROTO_FRAGMENT:
            exthdr = (struct ext_hdr_generic *) packet;
            *next_hdr = exthdr->nexthdr;
            return 8; // The fragment extention header has a fixed length
        default:
            // *next_hdr = exthdr->nexthdr;
            return 0;
    }
}

int ip6_version_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    mmt_una_ipv6hdr_t * ip6_hdr = (mmt_una_ipv6hdr_t *) & packet->data[proto_offset];

    *((unsigned char *) extracted_data->data) = ip6_hdr->l1_1.version;
    return 1;
}

int ip6_traffic_class_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    mmt_una_ipv6hdr_t * ip6_hdr = (mmt_una_ipv6hdr_t *) & packet->data[proto_offset];
    uint8_t tc = (uint8_t) ((ip6_hdr->l1_2.short_word_1 & 0x0FF0) >> 4);
    *((unsigned char *) extracted_data->data) = tc;
    return 1;
}

int ip6_flow_label_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    mmt_una_ipv6hdr_t * ip6_hdr = (mmt_una_ipv6hdr_t *) & packet->data[proto_offset];

    *((unsigned int *) extracted_data->data) = (ip6_hdr->l1_2.short_word_1 & 0x000FFFFF);
    return 1;
}

int ip6_next_proto_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    mmt_una_ipv6hdr_t * ip6_hdr = (mmt_una_ipv6hdr_t *) & packet->data[proto_offset];

    uint8_t  next_hdr    = ip6_hdr->nexthdr;
    /* Issue #201 (F-BUG-040): the extension-header offset accumulator must be
     * 32-bit — a long chain pushes it past 65535 and uint16_t silently wraps
     * back into captured data. */
    uint32_t next_offset = sizeof (struct ipv6hdr);

    while (is_extention_header(next_hdr) && (packet->p_hdr->caplen >= (proto_offset + next_offset + 2))) {
        next_offset += get_next_header_offset(next_hdr, & packet->data[proto_offset + next_offset], & next_hdr);
    }

    // At this level we have either an extention header, NO header or a protocol id header
    if (!is_extention_header(next_hdr) && next_hdr != IPPROTO_NONE) {
        *((unsigned char *) extracted_data->data) = next_hdr;
        return 1;
    }

    return 0;
}

int ip6_client_port_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if(packet->session != NULL) {
        mmt_session_key_t * s_key = (mmt_session_key_t *) packet->session->session_key;
        *((unsigned short *) extracted_data->data) = (s_key->is_lower_client)?s_key->lower_ip_port:s_key->higher_ip_port;
        return 1;
    }
    return 0;
}

int ip6_server_port_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if(packet->session != NULL) {
        mmt_session_key_t * s_key = (mmt_session_key_t *) packet->session->session_key;
        *((unsigned short *) extracted_data->data) = (s_key->is_lower_client)?s_key->higher_ip_port:s_key->lower_ip_port;
        return 1;
    }
    return 0;
}

int ip6_client_addr_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if(packet->session != NULL) {
        mmt_session_key_t * s_key = (mmt_session_key_t *) packet->session->session_key;
        if(s_key->is_lower_client) {
            memcpy(extracted_data->data, &((mmt_ip6_id_t *) s_key->lower_ip)->ip, IPv6_ALEN);
        }else {
            memcpy(extracted_data->data, &((mmt_ip6_id_t *) s_key->higher_ip)->ip, IPv6_ALEN);
        }
        return 1;
    }
    return 0;
}

int ip6_server_addr_extraction(const ipacket_t * packet, unsigned proto_index,
        attribute_t * extracted_data) {

    if(packet->session != NULL) {
        mmt_session_key_t * s_key = (mmt_session_key_t *) packet->session->session_key;
        if(s_key->is_lower_client) {
            memcpy(extracted_data->data, &((mmt_ip6_id_t *) s_key->higher_ip)->ip, IPv6_ALEN);
        }else {
            memcpy(extracted_data->data, &((mmt_ip6_id_t *) s_key->lower_ip)->ip, IPv6_ALEN);
        }
        return 1;
    }
    return 0;
}

int build_ipv6_session_key(ipacket_t * ipacket, int offset, mmt_session_key_t * ipv6_session) {
    int retval;
    mmt_una_ipv6hdr_t * ip6h = (mmt_una_ipv6hdr_t *) & ipacket->data[offset];

    uint8_t next_hdr = ip6h->nexthdr;
    /* Issue #201 (F-BUG-040): 32-bit accumulator, see ip6_next_proto_extraction. */
    uint32_t next_offset = sizeof (struct ipv6hdr);

    while (is_extention_header(next_hdr) && (ipacket->p_hdr->caplen >= (offset + next_offset + 2))) {
        next_offset += get_next_header_offset(next_hdr, & ipacket->data[offset + next_offset], & next_hdr);
    }
    // ipv6_session->lower_ip = (void*)mmt_malloc(sizeof(ip6h->saddr));
    // ipv6_session->higher_ip = (void*)mmt_malloc(sizeof(ip6h->daddr));
    if (MMT_COMPARE_IPV6_ADDRESSES(&ip6h->saddr, &ip6h->daddr)) {
        // memcpy(ipv6_session->lower_ip,&ip6h->saddr,sizeof(ip6h->saddr));
        // memcpy(ipv6_session->higher_ip,&ip6h->daddr,sizeof(ip6h->daddr));
        ipv6_session->lower_ip = &ip6h->saddr;
        ipv6_session->higher_ip = &ip6h->daddr;
        ipv6_session->is_lower_initiator = L2H_DIRECTION;
        ipv6_session->is_lower_client = L2H_DIRECTION;
        retval = L2H_DIRECTION;
    } else {
        // memcpy(ipv6_session->lower_ip,&ip6h->daddr,sizeof(ip6h->daddr));
        // memcpy(ipv6_session->higher_ip,&ip6h->saddr,sizeof(ip6h->saddr));
        ipv6_session->lower_ip = &ip6h->daddr;
        ipv6_session->higher_ip = &ip6h->saddr;
        ipv6_session->is_lower_initiator = H2L_DIRECTION;
        ipv6_session->is_lower_client = H2L_DIRECTION;
        retval = H2L_DIRECTION;
    }

    ipv6_session->ip_type = 6;

    ipv6_session->next_proto = next_hdr;

    if (ipacket->p_hdr->caplen >= (offset + next_offset + 4)) { //The packet contains the 4 L4 octets (source + destination ports) that follow the IPv6 header chain — both 16-bit ports are read below, so all 4 must be captured
        // tcp / udp detection
        if (ipv6_session->next_proto == 6) {
            const struct tcphdr *tcph = (struct tcphdr *) & ipacket->data[offset + next_offset];
            if (ipv6_session->is_lower_initiator) {
                ipv6_session->lower_ip_port = ntohs(tcph->source);
                ipv6_session->higher_ip_port = ntohs(tcph->dest);
            } else {
                ipv6_session->lower_ip_port = ntohs(tcph->dest);
                ipv6_session->higher_ip_port = ntohs(tcph->source);
            }
        } else if (ipv6_session->next_proto == 17) {
            const struct udphdr *udph = (struct udphdr *) & ipacket->data[offset + next_offset];
            if (ipv6_session->is_lower_initiator) {
                ipv6_session->lower_ip_port = ntohs(udph->source);
                ipv6_session->higher_ip_port = ntohs(udph->dest);
            } else {
                ipv6_session->lower_ip_port = ntohs(udph->dest);
                ipv6_session->higher_ip_port = ntohs(udph->source);
            }
        } else {
            // non tcp/udp protocols, one connection between two ip addresses
            ipv6_session->lower_ip_port = 0;
            ipv6_session->higher_ip_port = 0;
        }
    } else {
        // Next header does not exist!
        ipv6_session->lower_ip_port = 0;
        ipv6_session->higher_ip_port = 0;
    }

    return retval;
}

int ip6_session_cleanup_on_timeout(void * protocol_context, mmt_session_t * timedout_session, void * args) {
    //Remove the session from the sessions hash
    /* Issue #327: a failed delete leaves a map entry pointing at memory that
     * free_session_data() is about to release — log it; the cleanup must
     * still proceed because the session's owned memory is freed here. */
    if (delete_session_from_protocol_context(protocol_context, timedout_session->session_key) == 0) {
        mmt_debug_log( "[error] ip6_session_cleanup_on_timeout - delete_session_from_protocol_context failed\n");
    }

    // free session allocated memory. be careful about multiple free of the same data.
    // In the closup some session data are freed. These should not be the same as here.
    free_session_data(timedout_session->session_key, timedout_session, ((protocol_instance_t *) protocol_context)->args);

    return 0;
}

/* Compute the IPv6 fragment-reassembly hash key from the low 32 bits of the
 * source and destination addresses and the fragment identification.
 *
 * The low 32-bit words are extracted with memcpy from the last four octets of
 * each 16-byte address (s6_addr[12..15]). The previous code derived them with
 * `*(uint64_t *)(&ip6h->saddr + 12)`: because `&ip6h->saddr` has type
 * `struct in6_addr *`, the `+ 12` scaled by sizeof(struct in6_addr) (16) and
 * read 192 bytes past the address — an out-of-bounds, also-unaligned 64-bit
 * load. All three components are folded into the 64-bit key without discarding
 * any bits (the old double `<<= 32` dropped the first address word).
 *
 * Issue #59: ip6h / frag_header may point into the byte-aligned packet buffer,
 * so the multi-byte fields are read with memcpy rather than dereferenced
 * directly (a misaligned load is UB and aborts under -fsanitize=alignment).
 * memcpy of a fixed small size lowers to a single load on targets with native
 * unaligned access — no hot-path cost. The signature keeps the plain struct
 * types so the unit test's extern declaration stays stable, mirroring the
 * ip_fragment_key() treatment in PR #58 (#57). */
mmt_key_t ip6_fragment_key(const struct ipv6hdr *ip6h,
                           const struct ext_hdr_fragment *frag_header)
{
    uint32_t saddr_low, daddr_low, ident;
    /* Issue #201: callers pass a mmt_una_ipv6hdr_t view over the byte-aligned
     * capture buffer — even `&ip6h->saddr` is a member access on a misaligned
     * strict pointer (UB under -fsanitize=alignment). Reach the fields by
     * byte offset instead; no member access is formed. */
    memcpy(&saddr_low, (const uint8_t *) ip6h
                       + offsetof(struct ipv6hdr, saddr) + 12, sizeof(saddr_low));
    memcpy(&daddr_low, (const uint8_t *) ip6h
                       + offsetof(struct ipv6hdr, daddr) + 12, sizeof(daddr_low));
    memcpy(&ident, (const uint8_t *) frag_header
                   + offsetof(struct ext_hdr_fragment, ident), sizeof(ident));
    mmt_key_t key = ((mmt_key_t) saddr_low << 32) | (mmt_key_t) daddr_low;
    key ^= (mmt_key_t) ident;
    return key;
}

static inline int ip6_process_fragment(ipacket_t *ipacket, unsigned index)
{
    if (ipacket == NULL || ipacket->p_hdr == NULL || ipacket->data == NULL) return 0;
    mmt_handler_t *mmt = ipacket->mmt_handler;
    mmt_hashmap_t *map = mmt->ip6_streams;
    mmt_key_t key;
    ipv6_dgram_t *dg;

    if (map == NULL) return 0;

    /* Issue #201 (F-BUG-020): arm the fragment-map maintenance hooks the first
     * time a fragment is seen (shared with the IPv4 path). */
    if (mmt->frag_map_sweep_fct == NULL) {
        mmt->frag_map_sweep_fct = mmt_ip_frag_map_sweep;
    }

    int offset = get_packet_offset_at_index(ipacket, index);
    if (offset < 0) return 0;
    if (ipacket->p_hdr->caplen < (unsigned)(offset + (int)sizeof(struct ipv6hdr))) return 0;
    mmt_una_ipv6hdr_t *ip6h = (mmt_una_ipv6hdr_t *)&ipacket->data[offset];
    uint8_t next_hdr = ip6h->nexthdr;
    /* Issue #201 (F-BUG-040): 32-bit accumulator — a long extension-header
     * chain pushes it past 65535 and uint16_t silently wraps. The loop
     * condition bounds every read against caplen before it happens. */
    uint32_t next_offset = sizeof(struct ipv6hdr);
    // Get offset of Fragment header
    while (is_extention_header(next_hdr) && ((uint64_t) offset + next_offset + 2) <= ipacket->p_hdr->caplen && next_hdr != IPPROTO_FRAGMENT)
    {
        next_offset += get_next_header_offset(next_hdr, &ipacket->data[offset + next_offset], &next_hdr);
    }
    if (next_hdr != IPPROTO_FRAGMENT) return 0;
    if ((uint64_t) offset + next_offset + sizeof(struct ext_hdr_fragment) > ipacket->p_hdr->caplen) return 0;
    uint32_t ext_header_len = next_offset + sizeof(struct ext_hdr_fragment) - sizeof(struct ipv6hdr);
    mmt_una_ext_hdr_fragment_t *frag_header = (mmt_una_ext_hdr_fragment_t *)&ipacket->data[offset + next_offset];
    uint8_t more_fragment = ntohs(frag_header->flag) & 0x0001;
    uint16_t frag_offset = ntohs(frag_header->flag) >> 3;

    key = ip6_fragment_key((const struct ipv6hdr *) ip6h,
                           (const struct ext_hdr_fragment *) frag_header);
    if (!hashmap_get(map, key, (void **)&dg))
    {
        /* Issue #201 (F-BUG-020): bound the map BEFORE allocating — at the
         * ceiling, evict the stalest entry instead of growing without bound. */
        while (map->nkeys >= MMT_IP_FRAG_MAP_MAX_ENTRIES) {
            unsigned before = map->nkeys;
            mmt_ip_frag_map_evict_oldest(map);
            if (map->nkeys >= before)
                break; /* nothing evictable left — refuse to grow */
        }
        if (map->nkeys >= MMT_IP_FRAG_MAP_MAX_ENTRIES)
            return 0;
        dg = ipv6_dgram_alloc();
        if (dg == NULL)
            return 0; /* OOM: treat like an incomplete datagram — drop the fragment */
        hashmap_insert_kv(map, key, dg);
        /* hashmap_insert_kv() is void and drops silently on OOM — verify the
         * datagram actually landed, else it would be orphaned (issue #216). */
        void *check = NULL;
        hashmap_get(map, key, &check);
        if (check != dg) {
            ipv6_dgram_free(dg);
            return 0;
        }
        /* The handler owns the map, we own the value type: hand over the
         * destructor once so mmt_close_handler() can drain datagrams that
         * never completed (issue #216). */
        mmt->ip6_streams_value_free = (void (*)(void *)) ipv6_dgram_free;
    }

    /* Captured bytes available from the IPv6 header onward. */
    uint32_t avail = ipacket->p_hdr->caplen - (unsigned) offset;
    int dgram_update_result = ipv6_dgram_update(dg, ip6h, avail, frag_offset, next_offset + 8, more_fragment, ext_header_len);
    if (dgram_update_result == 1)
    {
        /* Issue #201 (F-BUG-037): malformed fragment — never park it in the
         * map. Fresh datagrams go straight back to the heap; an existing one
         * is evicted too — a failed update may have left its hole list
         * partially mutated. */
        hashmap_remove(map, key);
        ipv6_dgram_free(dg);
        return 0;
    }
    dg->last_activity = (uint32_t) ipacket->p_hdr->ts.tv_sec;

    if (dgram_update_result > 0)
    {
        // Overlapping
        ipacket->ipv6_overlapping[index] = 1;
    }
    /* Issue #201 (F-BUG-037): the subtraction below used to underflow when
     * declared payload_len < ext_header_len; that is now rejected inside
     * ipv6_dgram_update, so this is only reached with a sane extent. */
    uint32_t frag_payload_len = (uint32_t) ntohs(ip6h->payload_len) - ext_header_len;
    if (dg->current_packet_size != (unsigned) frag_offset * 8 + frag_payload_len) {
        ipacket->ipv6_outoforder[index] = 1;
    }
    // Check timed-out for all data gram

    // Detect too many fragment in one packet
    if (ipacket->mmt_handler->fragment_in_packet > 0 && (dg->nb_packets % ipacket->mmt_handler->fragment_in_packet) == 0)
    {
        fire_evasion_event(ipacket, PROTO_IPV6, index, EVA_IP_FRAGMENT_PACKET, (void *)&(dg->nb_packets));
    }
    if (!ipv6_dgram_is_complete(dg))
    {
        // debug("Fragmented packet is incompleted: %lu\n", ipacket->packet_id);
        // printf("Fragmented packet is incompleted: %lu\n", ipacket->packet_id);
        // fire_evasion_event(ipacket,PROTO_IPV6,index,1,(void*)NULL);
        return 0;
    }
    // At this point, dg is a fully reassembled datagram.
    // -> reconstruct ipacket from dg, and pass it along
    // printf("Going to combine packet: %d, %d\n",offset, ext_header_len);
    // printf("Datagram: %d\n", dg->len);
    uint64_t ioff = (uint64_t) offset + ext_header_len + sizeof(struct ipv6hdr);
    /* ioff is the end of the extension-header chain — bounded by caplen since
     * the fragment header itself was validated captured above. */
    if (ioff > ipacket->p_hdr->caplen)
    {
        hashmap_remove(map, key);
        ipv6_dgram_free(dg);
        return 0;
    }
    /* Issue #201: unchecked mmt_malloc — on failure the datagram must leave
     * the map with its buffer, not stay half-assembled. */
    uint8_t *x = (uint8_t*)mmt_malloc( ioff + dg->len );
    /* Issue #216: on OOM the datagram stays in the map — still consistent —
     * and drains at close via ip6_streams_value_free. */
    if (x == NULL)
        return 0;
    // copy the original ipacket data + IP header
    (void)memcpy( x,        ipacket->data, ioff );
    // copy the IP payload
    (void)memcpy( x + ioff, dg->x,         dg->len );
    ipacket->data = x;
    ipacket->p_hdr->len    = ioff + dg->len;
    ipacket->p_hdr->caplen = ioff + dg->len;
    ipacket->total_caplen  = dg->caplen;
    ipacket->nb_reassembled_packets[index] = dg->nb_packets;
    // debug("Total captured packet: %d\n", dg->nb_packets);
    // hexdump( dg->x, dg->len );
    // hexdump( x, ioff + dg->len );
    hashmap_remove(map, key);
    ipv6_dgram_free(dg);
    return 1;
}

void ipv6_parse_extension_headers(ipacket_t *ipacket, unsigned index)
{
    if (ipacket == NULL || ipacket->p_hdr == NULL || ipacket->data == NULL) return;
    int offset = get_packet_offset_at_index(ipacket, index);
    if (offset < 0) return;
    if (ipacket->p_hdr->caplen < (unsigned)(offset + (int)sizeof(struct ipv6hdr))) return;
    mmt_una_ipv6hdr_t *ip6h = (mmt_una_ipv6hdr_t *)&ipacket->data[offset];
    uint8_t next_hdr = ip6h->nexthdr;
    /* Issue #201 (F-BUG-040): 32-bit accumulator. */
    uint32_t next_offset = sizeof(struct ipv6hdr);
    while (is_extention_header(next_hdr) && ((uint64_t) offset + next_offset + 2) <= ipacket->p_hdr->caplen
           && ipacket->ipv6_ext_headers_len < PROTO_PATH_SIZE)
    {
        ipacket->ipv6_ext_headers_path[ipacket->ipv6_ext_headers_len] = next_hdr;
        ipacket->ipv6_ext_headers_offset[ipacket->ipv6_ext_headers_len] = next_offset;
        ipacket->ipv6_ext_headers_len++;
        uint32_t hdr_len = get_next_header_offset(next_hdr, &ipacket->data[offset + next_offset], &next_hdr);
        if (hdr_len == 0) break;
        if (next_offset + hdr_len < next_offset) break; // overflow
        if ((uint64_t) offset + next_offset + hdr_len > ipacket->p_hdr->caplen && is_extention_header(next_hdr)) {
            // next extension would be truncated; stop walking but keep already recorded headers
            // still advance to avoid infinite loop, then loop condition will exit
        }
        next_offset += hdr_len;
    }
}

void *ip6_sessionizer(void *protocol_context, ipacket_t *ipacket, unsigned index, int *is_new_session)
{
    if (ipacket == NULL || ipacket->p_hdr == NULL || ipacket->data == NULL) return NULL;
    int offset = get_packet_offset_at_index(ipacket, index);
    if (offset < 0) return NULL;
    if (ipacket->p_hdr->caplen < (unsigned)(offset + (int)sizeof(struct ipv6hdr))) return NULL;
    mmt_session_key_t ipv6_session_key;
    int packet_direction;
    // LN: Defragmentation
    mmt_una_ipv6hdr_t *ip6h = (mmt_una_ipv6hdr_t *)&ipacket->data[offset];
    uint8_t next_hdr = ip6h->nexthdr;
    /* Issue #201 (F-BUG-040): 32-bit accumulator. */
    uint32_t next_offset = sizeof(struct ipv6hdr);

    // Get offset of Fragment header
    while (is_extention_header(next_hdr) && ((uint64_t) offset + next_offset + 2) <= ipacket->p_hdr->caplen && next_hdr != IPPROTO_FRAGMENT)
    {
        next_offset += get_next_header_offset(next_hdr, &ipacket->data[offset + next_offset], &next_hdr);
    }

    if (next_hdr == IPPROTO_FRAGMENT)
    {
        ipacket->is_completed[index] = 0;
        ipacket->is_fragment[index] = 1;
        if (ipacket->session)
        {
            ipacket->session->is_fragmenting = 1;
        }
        // Going to defragment the packet
        if (!ip6_process_fragment(ipacket, index))
        {
            return NULL;
        }
    }
    // End of defragmentation
    ipacket->is_completed[index] = 1;
    if (ipacket->session)
    {
        ipacket->session->is_fragmenting = 0;
    }
    // Get the session of this packet and set it to the packet's session
    packet_direction = build_ipv6_session_key(ipacket, offset, &ipv6_session_key);

    mmt_session_t * session = get_session(protocol_context, &ipv6_session_key, ipacket, is_new_session);
    if(session) {
        if(session->last_packet_direction != packet_direction && session->packet_count>0){
            ip_rtt_t ip_rtt;
            ip_rtt.direction = session->last_packet_direction;
            ip_rtt.session = session;
            ip_rtt.rtt.tv_sec = ipacket->p_hdr->ts.tv_sec - session->s_last_activity_time.tv_sec;
            ip_rtt.rtt.tv_usec = ipacket->p_hdr->ts.tv_usec - session->s_last_activity_time.tv_usec;
            if((int) ip_rtt.rtt.tv_usec < 0) {
                ip_rtt.rtt.tv_usec += 1000000;
                ip_rtt.rtt.tv_sec -= 1;
            }
            fire_attribute_event(ipacket, PROTO_IPV6, IP6_RTT, index, (void *) &(ip_rtt));
        }

        // Fix proto_path , only fix til IP
        if (session->proto_path.proto_path[index] != PROTO_IPV6) {
            // debug("[IP6] Fixing proto_path of session: %lu", session->session_id);
            // Get PROTO_IPV6 index in current proto_path
            int j, ip_index = 0;
            for (j = 0; j < session->proto_path.len; j++) {
                if (session->proto_path.proto_path[j] == PROTO_IPV6) {
                    ip_index = j;
                    break;
                }
            }

            // debug("[IP6] Current index of PROTO_IPV6: %d / (packet)%d", ip_index, index);
            if (ip_index != 0) {
                if (ip_index > index) {
                    // debug("[IP6] Current protocol_path need to remove some protocol");
                    int pre_path = 0, post_path = ip_index + 1;

                    for (pre_path = 0; pre_path <= index; pre_path++)
                    {
                        session->proto_path.proto_path[pre_path] = ipacket->proto_hierarchy->proto_path[pre_path];
                        session->proto_headers_offset.proto_path[pre_path] = ipacket->proto_headers_offset->proto_path[pre_path];
                        session->proto_classif_status.proto_path[pre_path] = ipacket->proto_classif_status->proto_path[pre_path];
                    }
                    for (post_path = ip_index + 1; post_path < session->proto_path.len; post_path++, pre_path++) {
                        session->proto_path.proto_path[pre_path] = session->proto_path.proto_path[post_path];
                        session->proto_headers_offset.proto_path[pre_path] = session->proto_headers_offset.proto_path[post_path];
                        session->proto_classif_status.proto_path[pre_path] = session->proto_classif_status.proto_path[post_path];
                    }
                    session->proto_path.len = pre_path;
                    session->proto_headers_offset.len = pre_path;
                    session->proto_classif_status.len = pre_path;
                    // debug("[IP6] New protocol_path len %d", pre_path);
                } else {
                    // debug("[IP6] Current protocol_path need to add some protocol from packet hierarchy");
                    int delta = index - ip_index;
                    int new_len = session->proto_path.len + delta;
                    int pre_path = 0, post_path = new_len - 1;

                    for (post_path = new_len - 1; post_path > ip_index; post_path--) {
                        session->proto_path.proto_path[post_path] = session->proto_path.proto_path[post_path - delta];
                        session->proto_headers_offset.proto_path[post_path] = session->proto_headers_offset.proto_path[post_path - delta];
                        session->proto_classif_status.proto_path[post_path] = session->proto_classif_status.proto_path[post_path - delta];
                    }

                    for (pre_path = 0; pre_path <= index; pre_path++)
                    {
                        session->proto_path.proto_path[pre_path] = ipacket->proto_hierarchy->proto_path[pre_path];
                        session->proto_headers_offset.proto_path[pre_path] = ipacket->proto_headers_offset->proto_path[pre_path];
                        session->proto_classif_status.proto_path[pre_path] = ipacket->proto_classif_status->proto_path[pre_path];
                    }

                    session->proto_path.len = new_len;
                    session->proto_headers_offset.len = new_len;
                    session->proto_classif_status.len = new_len;
                    // debug("[IP6] New protocol_path len %d", new_len);
                }
                // Issue #19: the session offset path was rewritten in place; if
                // the packet shares this buffer the memoized cache is now stale.
                invalidate_packet_offset_cache(ipacket);
                /* Issue #252 (F-PERF-002): the splice moved path entries
                 * between indices, so the recorded per-layer winning checkers
                 * no longer line up with proto_path — drop them all. Affected
                 * layers re-walk the full chain (and re-record) instead of
                 * dispatching a stale engine. */
                memset(session->proto_checkers, 0, sizeof(session->proto_checkers));
            }

        }
        session->last_packet_direction = packet_direction;
    }

    // Parse extension headers
    ipv6_parse_extension_headers(ipacket, index);

    return (void *) session;
}

int ip6_classify_next_proto(ipacket_t * ipacket, unsigned index) {

    int offset = get_packet_offset_at_index(ipacket, index);
    mmt_una_ipv6hdr_t * ip6_hdr = (mmt_una_ipv6hdr_t *) & ipacket->data[offset];

    uint8_t next_hdr = ip6_hdr->nexthdr;
    /* Issue #201 (F-BUG-040): 32-bit accumulator. */
    uint32_t next_offset = sizeof (struct ipv6hdr);

    while (is_extention_header(next_hdr) && ((uint64_t) offset + next_offset + 2) <= ipacket->p_hdr->caplen) {
        // printf("[ip6_classify_next_proto] %d, %d\n", next_offset, next_hdr);
        next_offset += get_next_header_offset(next_hdr, & ipacket->data[offset + next_offset], & next_hdr);
    }

    classified_proto_t retval;
    retval.offset = -1;
    retval.proto_id = -1;
    retval.status = NonClassified;

    /* L4 protocol number -> PROTO_* dispatch (issue #238, F-CLEAN-005):
     * shared with the IPv4 classifier via ip_l4_proto_table.inc. Numbers 2
     * (IGMP) and 94 (IPIP) are IPv4-only entries in that table — the original
     * IPv6 switch had no case for them, so mask them back to PROTO_UNKNOWN. */
    retval.proto_id = mmt_ip_l4_proto_table[next_hdr];
    if (next_hdr == 2 || next_hdr == 94) {
        retval.proto_id = PROTO_UNKNOWN;
    }
    retval.offset = next_offset;
    retval.status = Classified;
    return set_classified_proto(ipacket, index + 1, retval);
    //return retval;
}

void ipv6_context_cleanup(void * proto_context, void * args) {
    close_session_lists(proto_context);
    cleanup_ipv6_internal_context(((protocol_instance_t *) proto_context)->args);
    close_ipv6_internal_context(proto_context);
}

void * setup_ipv6_context(void * proto_context, void * args) {
    return (void *) setup_ipv6_internal_context();
}

int proto_ext_headers_count_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                  attribute_t * extracted_data) {
    if (ipacket->ipv6_ext_headers_len > 0) {
        *((uint16_t *) extracted_data->data) = ipacket->ipv6_ext_headers_len;
        return 1;
    }
    return 0;
}

int proto_redundent_ext_header_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                  attribute_t * extracted_data) {

    if (ipacket->ipv6_ext_headers_len == 1) return 0;
    if (ipacket->ipv6_ext_headers_len > PROTO_PATH_SIZE) return 0;
    int i = 0, j = 0;
    uint16_t ext_headers[PROTO_PATH_SIZE];
    for (i = 0; i < ipacket->ipv6_ext_headers_len; i++) {
        uint16_t current_hdr = ipacket->ipv6_ext_headers_path[i];
        uint16_t nb_found = 0;
        ext_headers[i] = current_hdr;
        for (j = 0; j < i; j++) {
            if (ext_headers[j] == current_hdr) {
                nb_found++;
                if (current_hdr == IPPROTO_HOPOPTS && nb_found == 1) {
                    continue;
                }
                *((uint16_t *) extracted_data->data) = ext_headers[j];
                return 1;
            }
        }
    }
    return 0;
}

int proto_fragment_overlapping_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                  attribute_t * extracted_data) {
    if (ipacket->ipv6_overlapping[proto_index]) {
        *((uint16_t *) extracted_data->data) = 1;
        return 1;
    }
    return 0;
}

int proto_out_of_order_extraction(const ipacket_t * ipacket, unsigned proto_index,
                                  attribute_t * extracted_data) {
    if (ipacket->ipv6_outoforder[proto_index]) {
        *((uint16_t *) extracted_data->data) = 1;
        return 1;
    }
    return 0;
}

static attribute_metadata_t ip6_attributes_metadata[IP6_ATTRIBUTES_NB] = {
    {IP6_VERSION, IP6_VERSION_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, ip6_version_extraction},
    {IP6_TRAFFIC_CLASS, IP6_TRAFFIC_CLASS_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, ip6_traffic_class_extraction},
    {IP6_FLOW_LABEL, IP6_FLOW_LABEL_ALIAS, MMT_U32_DATA, sizeof (int), 0, SCOPE_PACKET, ip6_flow_label_extraction},
    {IP6_PAYLOAD_LEN, IP6_PAYLOAD_LEN_ALIAS, MMT_U16_DATA, sizeof (short), 4, SCOPE_PACKET, general_short_extraction_with_ordering_change},
    {IP6_NEXT_HEADER, IP6_NEXT_HEADER_ALIAS, MMT_U8_DATA, sizeof (char), 6, SCOPE_PACKET, general_char_extraction},
    {IP6_NEXT_PROTO, IP6_NEXT_PROTO_ALIAS, MMT_U8_DATA, sizeof (char), POSITION_NOT_KNOWN, SCOPE_PACKET, ip6_next_proto_extraction},
    {IP6_HOP_LIMIT, IP6_HOP_LIMIT_ALIAS, MMT_U8_DATA, sizeof (char), 7, SCOPE_PACKET, general_char_extraction},
    {IP6_SRC, IP6_SRC_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, 8, SCOPE_PACKET, general_byte_to_byte_extraction},
    {IP6_DST, IP6_DST_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, 24, SCOPE_PACKET, general_byte_to_byte_extraction},
    {IP6_CLIENT_ADDR, IP6_CLIENT_ADDR_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, POSITION_NOT_KNOWN, SCOPE_PACKET, ip6_client_addr_extraction},
    {IP6_SERVER_ADDR, IP6_SERVER_ADDR_ALIAS, MMT_DATA_IP6_ADDR, IPv6_ALEN, POSITION_NOT_KNOWN, SCOPE_PACKET, ip6_server_addr_extraction},
    {IP6_CLIENT_PORT, IP6_CLIENT_PORT_ALIAS, MMT_U16_DATA, sizeof (short), POSITION_NOT_KNOWN, SCOPE_PACKET, ip6_client_port_extraction},
    {IP6_SERVER_PORT, IP6_SERVER_PORT_ALIAS, MMT_U16_DATA, sizeof (short), POSITION_NOT_KNOWN, SCOPE_PACKET, ip6_server_port_extraction},
    {IP6_FRAG_PACKET_COUNT, IP6_FRAG_PACKET_COUNT_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_ip_frag_packet_count_extraction},
    {IP6_EXT_HEADERS_COUNT, IP6_EXT_HEADERS_COUNT_LABEL, MMT_U16_DATA, sizeof (uint16_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_ext_headers_count_extraction},
    {IP6_REDUNDANT_EXT_HEADERS, IP6_REDUNDANT_EXT_HEADERS_LABEL, MMT_U16_DATA, sizeof (uint16_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_redundent_ext_header_extraction},
    // {IP6_UNKNOWN_EXT_HEADERS, IP6_UNKNOWN_EXT_HEADERS_LABEL, MMT_U16_DATA, sizeof (uint16_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_unknown_ext_header_extraction},
    {IP6_FRAGMENT_OVERLAPPING, IP6_FRAGMENT_OVERLAPPING_LABEL, MMT_U8_DATA, sizeof (char), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_fragment_overlapping_extraction},
    {IP6_OUT_OF_ORDER, IP6_OUT_OF_ORDER_LABEL, MMT_U8_DATA, sizeof (char), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_out_of_order_extraction},
    {IP6_FRAG_DATA_VOLUME, IP_FRAG_DATA_VOLUME_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_ip_frag_data_volume_extraction},
    {IP6_DF_PACKET_COUNT, IP6_DF_PACKET_COUNT_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_ip_df_packet_count_extraction},
    {IP6_DF_DATA_VOLUME, IP_DF_DATA_VOLUME_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_ip_df_data_volume_extraction},
    {IP6_SESSIONS_COUNT, IP6_SESSIONS_COUNT_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_sessions_count_extraction},
    {IP6_ACTIVE_SESSIONS_COUNT, IP6_ACTIVE_SESSIONS_COUNT_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_active_sessions_count_extraction},
    {IP6_TIMEDOUT_SESSIONS_COUNT, IP6_TIMEDOUT_SESSIONS_COUNT_LABEL, MMT_U64_DATA, sizeof (uint64_t), POSITION_NOT_KNOWN, SCOPE_PACKET, proto_timedout_sessions_count_extraction},
};

int ipv6_pre_classification_function(ipacket_t * ipacket, unsigned index) {
    /* IP is a flow based protocol. If at this level the flow associated to this packet is null
     * stop the classification procedure by returning zero. For IPv6 this should never happen
     * (fragmentation in IPv6 is different than IPv4).
     */
    if (ipacket->session == NULL) {
        return MMT_CLASSIFY_SKIP;
    }
    return MMT_CLASSIFY_CONTINUE;
}

int ipv6_post_classification_function(ipacket_t * ipacket, unsigned index) {
    mmt_session_t * session = ipacket->session;
    /* Issue #201 (F-BUG-036): validate the captured length before the IPv6
     * header view is taken and before l3 lengths are subtracted below. */
    int ip_offset = get_packet_offset_at_index(ipacket, index);
    if (ip_offset < 0 || (uint64_t) ip_offset + sizeof(struct ipv6hdr) > ipacket->p_hdr->caplen)
        return MMT_CLASSIFY_CONTINUE;
    /* Issue #245 (F-PERF-003): reuse the shared per-protocol context packet
     * in reassembly mode too — see ip_post_classification_function(). */
    ipacket->internal_packet = &((internal_ip_proto_context_t *) ((protocol_instance_t *) session->protocol_container_context)->args)->packet;
    mmt_reset_internal_packet_scalars(ipacket->internal_packet);
    ipacket->internal_packet->packet_id = ipacket->packet_id;
    mmt_tcpip_internal_packet_t * packet = ipacket->internal_packet;

    struct mmt_ipv6hdr *ip6h = (struct mmt_ipv6hdr *) & ipacket->data[ip_offset];

    uint32_t time = ((uint64_t) ipacket->p_hdr->ts.tv_sec) * MMT_MICRO_IN_SEC + ipacket->p_hdr->ts.tv_usec;
    packet->tick_timestamp = time;

    struct mmt_internal_tcpip_id_struct * src = NULL;
    struct mmt_internal_tcpip_id_struct * dst = NULL;

    packet->iph = NULL;
    packet->iphv6 = (struct mmt_ipv6hdr *) ip6h;
    packet->l3_packet_len = (ipacket->p_hdr->len - ip_offset);
    /* BW: add the length of the truncated packet as well */
    packet->l3_captured_packet_len = (ipacket->p_hdr->caplen - ip_offset);

    if (mmt_memcmp(&((mmt_ip6_id_t *) ((mmt_session_key_t *) session->session_key)->higher_ip)->ip.s6_addr,
            &ip6h->saddr, IPv6_ALEN) == 0) {
        src = &((mmt_ip6_id_t *) ((mmt_session_key_t *) session->session_key)->higher_ip)->id_internal_context;
        dst = &((mmt_ip6_id_t *) ((mmt_session_key_t *) session->session_key)->lower_ip)->id_internal_context;
    } else {
        dst = &((mmt_ip6_id_t *) ((mmt_session_key_t *) session->session_key)->higher_ip)->id_internal_context;
        src = &((mmt_ip6_id_t *) ((mmt_session_key_t *) session->session_key)->lower_ip)->id_internal_context;
    }

    packet->flow = session->internal_data;
    packet->src = src;
    packet->dst = dst;

    /* build selction packet bitmask */
    packet->mmt_selection_packet = MMT_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC;
    packet->mmt_selection_packet |= MMT_SELECTION_BITMASK_PROTOCOL_IPV6 | MMT_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;
    // Update session statistics
    session->packet_count_direction[session->last_packet_direction]++;
    session->packet_cap_count_direction[session->last_packet_direction] += ipacket->nb_reassembled_packets[index];
    session->data_volume_direction[session->last_packet_direction] += ipacket->p_hdr->len;
    session->data_cap_volume_direction[session->last_packet_direction] += ipacket->total_caplen;
    mmt_session_t *p_session = session->parent_session;
    while (p_session)
    {
        /* Issue #255: children counters live in the lazily-allocated
         * tunnel-parent extension (NULL under OOM -> update skipped). */
        mmt_session_children_stats_t *cs = mmt_session_get_children_stats(p_session);
        if (cs != NULL) {
            uint8_t direction = p_session->last_packet_direction ;
            cs->sub_packet_count_direction[direction]++;
            cs->sub_packet_cap_count_direction[direction] += ipacket->nb_reassembled_packets[index];
            cs->sub_data_volume_direction[direction] += ipacket->p_hdr->len;
            cs->sub_data_cap_volume_direction[direction] += ipacket->total_caplen;
        }
        p_session = p_session->parent_session;
    }
    return 1;
}

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ipv6_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_IPV6, PROTO_IPV6_ALIAS);

    if (protocol_struct != NULL) {
        int i = 0;
        for (; i < IP6_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &ip6_attributes_metadata[i]);
        }

        register_classification_function(protocol_struct, ip6_classify_next_proto);
        register_pre_post_classification_functions(protocol_struct, ipv6_pre_classification_function, ipv6_post_classification_function);

        register_sessionizer_function(protocol_struct, ip6_sessionizer, ip6_session_cleanup_on_timeout, ipv6_session_comp);
        register_session_hash_function(protocol_struct, ipv6_session_hash);
        register_session_equal_function(protocol_struct, ipv6_session_equal);

        register_proto_context_init_cleanup_function(protocol_struct, setup_ipv6_context, ipv6_context_cleanup, NULL);

        return register_protocol(protocol_struct, PROTO_IPV6);
    } else {
        return 0;
    }
}



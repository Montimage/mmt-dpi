
#ifndef _MMT_IPV6_DGRAM_H
#define _MMT_IPV6_DGRAM_H

#include "mmt_core.h"
#include "mmt_common_internal_include.h"
#include "proto_ip_frag.h"
#include "hashmap.h"  /* issue #383: mmt_hlru_t eviction-order link */
#include "ipv6.h" /* issue #59: mmt_una_ipv6hdr_t alignment-safe view */
#define MMT_MAX_NUMBER_FRAGMENT 64 // Maximum number of fragments packet in an IP packets

/*
          G E N E R A L   I P   D A T A G R A M   L A Y O U T

   +----------------------------------------------------------------+
   |                               dgram                            |
   +----------------------------------------------------------------+
   |                                                                |
   +--------+  +---------------------+---------------+--------------+
   | frag#1 |  |       frag #4       |    frag #3    |   frag #5    | <- unordered
   +--------+  +---------------------+---------------+--------------+    fragments
   |    +------------+                                              |
   |    |   frag#2   | <- overlaps #1 & #4                          |
   |    +------------+                                              |
   +----------------------------------------------------------------+
   ^    ^  ^   ^    ^               ^^              ^^             ^
   |    |  |   |    |               ||              ||             +--- frag#5.roff
   |    |  |   |    |               ||              |+----------------- frag#5.loff
   |    |  |   |    |               ||              +------------------ frag#3.roff
   |    |  |   |    |               |+--------------------------------- frag#3.loff
   |    |  |   |    |               +---------------------------------- frag#4.roff
   |    |  |   |    +-------------------------------------------------- frag#2.roff
   |    |  |   +------------------------------------------------------- frag#4.loff
   |    |  +----------------------------------------------------------- frag#1.roff
   |    +-------------------------------------------------------------- frag#2.loff
   +------------------------------------------------------------------- frag#1.loff
 */

/* IP datagram */

struct ipv6_dgram
{
   /* Issue #201 (F-BUG-020): leading metadata identical to struct ip_dgram so
    * the shared ip_streams map can sweep/drain either type — ip_version (4 or
    * 6) selects the deallocator, last_activity drives the age-based expiry. */
   uint8_t ip_version;    // 6 for ipv6_dgram_t
   uint32_t last_activity; // tv_sec of the last fragment update
   mmt_hlru_t  lru;           // issue #383: eviction-order link (shared prefix)
   uint8_t *x;   // reassembly buffer
   unsigned len; // buffer length
   unsigned nb_packets;
   unsigned caplen;
   unsigned max_packet_size;
   unsigned current_packet_size;
   uint32_t last_offset; /* Issue #201: widened from uint16_t (F-BUG-040) */
   int packet_offsets[MMT_MAX_NUMBER_FRAGMENT];
   ip_frags_t holes; // list of holes
};

typedef struct ipv6_dgram ipv6_dgram_t;

//  - - - - - - - - - - - - - - - -  //
//  P U B L I C   I N T E R F A C E  //
//  - - - - - - - - - - - - - - - -  //

extern ipv6_dgram_t *ipv6_dgram_alloc(void);
extern void ipv6_dgram_free(ipv6_dgram_t *);
extern int ipv6_dgram_init(ipv6_dgram_t *);
extern void ipv6_dgram_cleanup(ipv6_dgram_t *);
extern void ipv6_dgram_dump(ipv6_dgram_t *);
extern void ipv6_dgram_dump_holes(ipv6_dgram_t *);

/* Issue #201 (F-BUG-037/040): payload_offset and ext_header_len are widened to
 * uint32_t — a long extension-header chain can push them past 65535.
 * @param avail captured bytes available starting at the IPv6 header
 *        (ipacket->p_hdr->caplen - ip_offset), NOT the raw pcap caplen. */
extern int ipv6_dgram_update(ipv6_dgram_t *dg, const mmt_una_ipv6hdr_t *ip, unsigned avail, uint16_t fragment_offset, uint32_t payload_offset, uint8_t more_fragment, uint32_t ext_header_len);
extern int ipv6_dgram_update_holes(ipv6_dgram_t *, const uint8_t *, unsigned, unsigned, int);
extern int ipv6_dgram_is_complete(ipv6_dgram_t *);

#endif /*_MMT_IPV6_DGRAM_H*/

/*EoF*/

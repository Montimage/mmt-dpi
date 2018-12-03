
#ifndef _MMT_IPV6_DGRAM_H
#define _MMT_IPV6_DGRAM_H

#include "mmt_core.h"
#include "mmt_common_internal_include.h"
#include "proto_ip_frag.h"
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
   uint8_t *x;   // reassembly buffer
   unsigned len; // buffer length
   unsigned nb_packets;
   unsigned caplen;
   unsigned max_packet_size;
   unsigned current_packet_size;
   uint16_t last_offset;
   int packet_offsets[MMT_MAX_NUMBER_FRAGMENT];
   ip_frags_t holes; // list of holes
};

typedef struct ipv6_dgram ipv6_dgram_t;

//  - - - - - - - - - - - - - - - -  //
//  P U B L I C   I N T E R F A C E  //
//  - - - - - - - - - - - - - - - -  //

extern ipv6_dgram_t *ipv6_dgram_alloc(void);
extern void ipv6_dgram_free(ipv6_dgram_t *);
extern void ipv6_dgram_init(ipv6_dgram_t *);
extern void ipv6_dgram_cleanup(ipv6_dgram_t *);
extern void ipv6_dgram_dump(ipv6_dgram_t *);
extern void ipv6_dgram_dump_holes(ipv6_dgram_t *);

extern int ipv6_dgram_update(ipv6_dgram_t *dg, const struct ipv6hdr *ip, unsigned caplen, uint16_t fragment_offset, uint16_t payload_offset, uint8_t more_fragment, uint16_t next_header_length);
extern int ipv6_dgram_update_holes(ipv6_dgram_t *, const uint8_t *, unsigned, unsigned, int);
extern int ipv6_dgram_is_complete(ipv6_dgram_t *);

#endif /*_MMT_IPV6_DGRAM_H*/

/*EoF*/

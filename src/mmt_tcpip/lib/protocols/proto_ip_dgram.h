
#ifndef _MMT_IP_DGRAM_H
#define _MMT_IP_DGRAM_H

#include "mmt_core.h"
#include "mmt_common_internal_include.h"
#include "proto_ip_frag.h"
#define MMT_MAX_NUMBER_FRAGMENT  20 // Maximum number of fragments packet in an IP packets

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

struct ip_dgram {
   uint8_t    *x;      // reassembly buffer
   unsigned    len;    // buffer length
   unsigned    nb_packets;
   unsigned    caplen;
   unsigned    max_packet_size;
   unsigned    current_packet_size;
   unsigned    packet_offsets[MMT_MAX_NUMBER_FRAGMENT];
   ip_frags_t  holes;  // list of holes
};

typedef struct ip_dgram ip_dgram_t;


//  - - - - - - - - - - - - - - - -  //
//  P U B L I C   I N T E R F A C E  //
//  - - - - - - - - - - - - - - - -  //

extern ip_dgram_t *ip_dgram_alloc        ( void );
extern void        ip_dgram_free         ( ip_dgram_t * );
extern void        ip_dgram_init         ( ip_dgram_t * );
extern void        ip_dgram_cleanup      ( ip_dgram_t * );
extern void        ip_dgram_dump         ( ip_dgram_t * );
extern void        ip_dgram_dump_holes   ( ip_dgram_t * );

extern void        ip_dgram_update       ( ip_dgram_t *, const struct iphdr *, unsigned ,unsigned);
extern void        ip_dgram_update_holes ( ip_dgram_t *, const uint8_t *, unsigned, unsigned, int );
extern int         ip_dgram_is_complete  ( ip_dgram_t * );


#endif /*_MMT_IP_DGRAM_H*/

/*EoF*/


#ifndef _MMT_IP_DGRAM_H
#define _MMT_IP_DGRAM_H

#include "mmt_core.h"
#include "mmt_common_internal_include.h"
#include "hashmap.h"             /* mmt_hashmap_t — frag-map helpers below */
#include "proto_ip_frag.h"
#define MMT_MAX_NUMBER_FRAGMENT  64 // Maximum number of fragments packet in an IP packets

/* Issue #201 (F-BUG-020): bounds for the shared ip_streams fragment map.
 *
 *  - MMT_IP_FRAG_MAP_MAX_ENTRIES caps the number of in-flight datagrams a
 *    handler will track; inserting past the ceiling evicts the least
 *    recently updated entry (mmt_ip_frag_map_make_room). Issue #383
 *    (F-PERF-004): the victim is the head of an intrusive recency list
 *    (mmt_hlru_t, sentinel on the handler), so eviction is O(1) instead of a
 *    walk of every in-flight datagram. Recency is update ORDER: with
 *    non-decreasing packet timestamps it is exactly the smallest
 *    last_activity (ties: the earliest updated), and a timestamp that runs
 *    backwards neither promotes nor demotes a datagram.
 *  - MMT_IP_FRAG_TIMEOUT_SEC is the age, in seconds of packet timestamp, after
 *    which an unfinished datagram is swept by the session-expiry timer pass.
 *  - MMT_IP_FRAG_MAX_DGRAM bounds a single reassembled payload: an IPv4
 *    datagram can carry at most 65535 - 20 = 65515 bytes of data, so any
 *    fragment claiming off+len beyond this is malformed on its face. This also
 *    bounds every reassembly buffer (and thus the resident memory of a flooded
 *    map: MAX_ENTRIES * MAX_DGRAM).
 */
#define MMT_IP_FRAG_MAP_MAX_ENTRIES  1024u
#define MMT_IP_FRAG_TIMEOUT_SEC      30u
#define MMT_IP_FRAG_MAX_DGRAM        65535u

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
   /* Issue #201 (F-BUG-020): leading metadata shared with ipv6_dgram so the
    * shared ip_streams map can sweep/drain either type — ip_version (4 or 6)
    * selects the right deallocator, last_activity (packet tv_sec) drives the
    * age-based expiry. Keep this prefix identical to struct ipv6_dgram. */
   uint8_t     ip_version;    // 4 for ip_dgram_t
   uint32_t    last_activity; // tv_sec of the last fragment update
   mmt_hlru_t  lru;           // issue #383: eviction-order link (shared prefix)
   uint8_t    *x;      // reassembly buffer
   unsigned    len;    // buffer length
   unsigned    nb_packets;
   unsigned    caplen;
   unsigned    max_packet_size;
   unsigned    current_packet_size;
   int    packet_offsets[MMT_MAX_NUMBER_FRAGMENT];
   ip_frags_t  holes;  // list of holes
};

typedef struct ip_dgram ip_dgram_t;


//  - - - - - - - - - - - - - - - -  //
//  P U B L I C   I N T E R F A C E  //
//  - - - - - - - - - - - - - - - -  //

extern ip_dgram_t *ip_dgram_alloc        ( void );
extern void        ip_dgram_free         ( ip_dgram_t * );
extern int         ip_dgram_init         ( ip_dgram_t * );
extern void        ip_dgram_cleanup      ( ip_dgram_t * );
extern void        ip_dgram_dump         ( ip_dgram_t * );
extern void        ip_dgram_dump_holes   ( ip_dgram_t * );

extern int        ip_dgram_update       ( ip_dgram_t *, const mmt_una_iphdr_t *, unsigned ,unsigned);
extern int        ip_dgram_update_holes ( ip_dgram_t *, const uint8_t *, unsigned, unsigned, int);
extern int         ip_dgram_is_complete  ( ip_dgram_t * );

/* Issue #201 (F-BUG-020): shared ip_streams fragment-map maintenance. Armed
 * into mmt_handler->frag_map_sweep_fct/frag_map_drain_fct by the TCP/IP plugin
 * on the first fragment seen; invoked by mmt_core from the session-expiry
 * timer pass and from mmt_close_handler(). */
extern void        mmt_ip_frag_map_sweep        ( mmt_hashmap_t *, uint32_t now );
extern void        mmt_ip_frag_map_drain        ( mmt_hashmap_t * );
extern void        mmt_ip_frag_map_evict_oldest ( mmt_hashmap_t *, mmt_hlru_t *lru );
/* Issue #383 (F-PERF-004): recency-list maintenance. make_room evicts from
 * the list head until the map is below MMT_IP_FRAG_MAP_MAX_ENTRIES and
 * returns 1 when a new datagram may be inserted, 0 otherwise. touch moves a
 * datagram's node to the tail (most recent) and records its map key; the
 * dgram deallocators unlink it, so every removal path keeps the list exact. */
extern int         mmt_ip_frag_map_make_room    ( mmt_hashmap_t *, mmt_hlru_t *lru );
extern void        mmt_ip_frag_lru_touch        ( mmt_hlru_t *lru, mmt_hlru_t *node, mmt_key_t key );
extern void        mmt_ip_frag_lru_unlink       ( mmt_hlru_t *node );

#ifdef MMT_IP_FRAG_INDEX_STATS
/* Test-only work counters (tests/resource_bounds fragment-eviction). */
struct mmt_ip_frag_index_stats {
   uint64_t victim_visits;  /* list nodes examined to pick eviction victims */
   uint64_t links;          /* node insertions at the list tail */
   uint64_t unlinks;        /* node removals from the list */
};
extern struct mmt_ip_frag_index_stats mmt_ip_frag_index_stats;
#endif


#endif /*_MMT_IP_DGRAM_H*/

/*EoF*/

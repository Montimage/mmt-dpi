
#include <string.h> // memcpy()

#include "proto_ip_dgram.h"
#include "proto_ipv6_dgram.h" /* Issue #201: sweep/drain dispatch on ip_version */


//  - - - - - - - - - - - - - -  //
//  P U B L I C   M E T H O D S  //
//  - - - - - - - - - - - - - -  //

/**
 * Create a new datagram (allocator)
 *
 * @return a new, initialized datagram
 */

ip_dgram_t *ip_dgram_alloc()
{
   /* Issue #201: both allocations below were unchecked — a NULL dg would be
    * written through by ip_dgram_init(), and a failed hole allocation left a
    * datagram whose hole list made it look instantly "complete". */
   ip_dgram_t *dg = (ip_dgram_t *)mmt_malloc( sizeof( ip_dgram_t ));
   if( dg == NULL )
      return NULL;
   if( !ip_dgram_init( dg )) {
      mmt_free( dg );
      return NULL;
   }

   return dg;
}

/**
 * Destroy a datagram (deallocator)
 *
 * @param dg a pointer to a ip_dgram_t previously allocated with dgram_alloc()
 */

void ip_dgram_free( ip_dgram_t *dg )
{
   ip_dgram_cleanup( dg );
   mmt_free( dg );
}

/**
 * Initialize a datagram (constructor)
 *
 * @param dg a pointer to an uninitialized ip_dgram_t
 * @return 1 on success, 0 if the initial hole could not be allocated
 */

int ip_dgram_init( ip_dgram_t *dg )
{
   /* Issue #201 (F-BUG-020): metadata used by the ip_streams sweep/drain
    * hooks — must stay the leading layout shared with struct ipv6_dgram. */
   dg->ip_version    = 4;
   dg->last_activity = 0;
   dg->x   = 0;
   dg->len = 0;
   dg->nb_packets = 0;
   dg->caplen = 0;
   dg->max_packet_size = 0;
   dg->current_packet_size = 0;
   int i = 0;
   for(i =0 ;i<MMT_MAX_NUMBER_FRAGMENT;i++){
      dg->packet_offsets[i] = -1;
   }
   LIST_INIT( &dg->holes );

   ip_frag_t *hole = ip_frag_alloc( 0, MMT_IP_FRAG_MAX_DGRAM );
   if( hole == NULL )
      return 0;
   LIST_INSERT_HEAD( &dg->holes, hole, frags );
   return 1;
}

/**
 * Cleanup a datagram (destructor)
 *
 * @param dg a pointer to a ip_dgram_t previously initialized with dgram_init()
 */

void ip_dgram_cleanup( ip_dgram_t *dg )
{
   if(dg==NULL) return;

   int i = 0;
   for(i =0 ;i<MMT_MAX_NUMBER_FRAGMENT;i++){
      dg->packet_offsets[i] = -1;
   }

   ip_frags_t *holes = &dg->holes;
   ip_frag_t  *hole  = holes->lh_first;
   ip_frag_t  *safe_to_delete;
   while( hole ) {
      safe_to_delete = hole;
      hole = hole->frags.le_next;
      ip_frag_free(safe_to_delete);
   }

   if( dg->x )
      mmt_free( dg->x );

   dg->x   = 0;
   dg->len = 0;
   dg->nb_packets = 0;
   dg->caplen = 0;
}

/**
 * Update a datagram
 *
 * @param dg  a pointer to a ip_dgram_t previously initialized with dgram_init()
 * @param x   payload address
 * @param len payload length
 * @return
 *      1 - malformed packet (header length mismatch or length mismatch)
 *      2 - duplicated fragment
 *      3 - overlapped data on the left of the hole
 *      4 - overlapped data on the right of the hole
 *      5 - overlapped data on both sides of the hole
 *      6 - duplicated fragment data
 *      0 - No problem
 */

/* Issue #57: ip is an alignment-safe view (mmt_una_iphdr_t) over the byte-
 * aligned packet buffer, so the tot_len/frag_off/id field reads below are
 * alignment-safe (single loads on targets with native unaligned access). */
int ip_dgram_update( ip_dgram_t *dg, const mmt_una_iphdr_t *ip, unsigned len ,unsigned caplen)
{
   unsigned ip_len =  ntohs( ip->tot_len  );
   unsigned ip_off = (ntohs( ip->frag_off ) & IP_OFFSET) << 3;
   unsigned ip_mf  =  ntohs( ip->frag_off ) & IP_MF;
   unsigned ip_hl  =  ip->ihl << 2;

   /* Issue #201 (F-BUG-017/037): every field is attacker-controlled — validate
    * all of them against the CAPTURED length `len` before deriving the payload
    * pointer or doing any subtraction:
    *   - ip_hl must be a full header (>= 20) and captured (<= len),
    *   - ip_len must cover the header (otherwise ip_len - ip_hl underflows to
    *     ~4 GiB and the hole update memcpy's gigabytes past the buffer),
    *   - the captured datagram must actually contain ip_len bytes. */
   if(( ip_hl < sizeof( struct iphdr )) || ( ip_hl > len )) {
      MMT_LOG( PROTO_IP, MMT_LOG_DEBUG, "*** Warning: malformed packet (header length mismatch)\n" );
      return 1;
   }

   if(( ip_len < ip_hl ) || ( ip_len > len )) {
      MMT_LOG( PROTO_IP, MMT_LOG_DEBUG, "*** Warning: malformed packet (length mismatch)\n" );
      return 1;
   }

   /* Issue #201 (F-BUG-037): bound the reassembled extent — a fragment can
    * legally address at most a 65535-byte datagram, so off+len beyond that is
    * malformed and also keeps every reassembly buffer <= 64 KiB. */
   if( (uint64_t) ip_off + ( ip_len - ip_hl ) > MMT_IP_FRAG_MAX_DGRAM ) {
      MMT_LOG( PROTO_IP, MMT_LOG_DEBUG, "*** Warning: malformed packet (fragment extent out of range)\n" );
      return 1;
   }

   const uint8_t *payload = (const uint8_t *)ip + ip_hl;

   dg->nb_packets ++;
   dg->caplen += caplen;
   dg->max_packet_size = dg->max_packet_size > (ip_off + ip_len - ip_hl)?dg->max_packet_size:(ip_off + ip_len - ip_hl);
   
   int i=0;
   for(i=0;i < MMT_MAX_NUMBER_FRAGMENT - 1;i++){
      if(dg->packet_offsets[i] == -1) break;
      if(dg->packet_offsets[i] == ip_off){
         debug("[IP -]> Duplicated fragment: offset - %d|%d, id - %d",i,ip_off, ip->id);
         // printf("[IP -]> Duplicated fragment: offset - %d|%d, id - %d\n",i,ip_off, ip->id);
         break;
      }
   }

   if(dg->packet_offsets[i]==-1) {
      dg->packet_offsets[i] = ip_off;
      dg->current_packet_size += ip_len - ip_hl;
   }else{
      // TODO: Can return here to not overwrite the later fragment
      return 2;
   }
   // ip_dgram_update_holes( dg, payload, ip_off, len - ip_hl, ip_mf);
   // LN: Using ip_len to remove the padding from IP payload
   return ip_dgram_update_holes( dg, payload, ip_off, ip_len - ip_hl, ip_mf);
}

/**
 * Check whether a datagram is complete (fully reassembled)
 *
 * @param dg a pointer to a ip_dgram_t previously initialized with dgram_init()
 * @return 1 if dg is a complete datagram, 0 otherwise
 */

int ip_dgram_is_complete( ip_dgram_t *dg )
{
   if(dg->current_packet_size < dg->max_packet_size) return 0;
   ip_frags_t *holes = &dg->holes;
   return( holes->lh_first == 0 );
}

/**
 * Dump a datagram
 *
 * @param dg a pointer to a ip_dgram_t previously initialized with dgram_init()
 */

void ip_dgram_dump( ip_dgram_t *dg )
{
   (void)mmt_stream_printf(stdout, "--- IP DATAGRAM ---\n" );
   (void)mmt_stream_printf(stdout, "   id: %p\n", dg );
   (void)mmt_stream_printf(stdout, "  len: %d\n", dg->len );

   ip_dgram_dump_holes( dg );
}

/**
 * Dump a datagram as a list of holes
 *
 * @param dg a pointer to a ip_dgram_t previously initialized with dgram_init()
 */

void ip_dgram_dump_holes( ip_dgram_t *dg )
{
   ip_frags_t *holes = &dg->holes;
   ip_frag_t  *hole  = holes->lh_first;

   (void)mmt_stream_printf(stdout, "holes:" );

   if( hole == 0 ) {
      (void)mmt_stream_printf(stdout, " none - datagram is complete\n" );
      return;
   }

   while( hole ) {
      ip_frag_dump( hole );
      hole = hole->frags.le_next;
   }

   (void)mmt_stream_printf(stdout, "\n" );
}

/**
 * Update holes in a datagram
 *
 * This method implements the reference IP fragment reassembly algorithm,
 * as described in rfc815 - http://tools.ietf.org/html/rfc815
 *
 * Hole list management:
 *
 * Missing parts in datagrams are materialized as "holes".
 * Holes are arranged as an ordered linked list within each datagram.
 *
 * Initially, freshly allocated datagrams are empty: their hole list
 * holds only one entry (one single hole covering the whole datagram).
 *
 * As datagrams get populated with incoming bits of data (IP fragments),
 * their respective hole list gets updated: areas covered with data are
 * removed from the list, possibly resizing, splitting or removing holes.
 * Successful IP reassembly is achieved when no hole remains in the list.
 *
 * Reassembly policies:
 *
 * The lack of a proper standard regarding how overlapping fragments are
 * supposed to be processed has been largely exploited by attackers since
 * the mid 90's.
 *
 * For instance, consider two overlapping fragments:
 *
 * +----+----+----+----+
 * |AAAA AAAA AAAA AAAA|  fragment #1
 * +----+----+----+----+
 *                +----+----+----+----+
 *                |ZZZZ ZZZZ ZZZZ ZZZZ|  fragment #2
 *                +----+----+----+----+
 *
 * Should they be reassembled as:
 *
 * <---- frag #1 -----><-- frag #2 -->
 * +----+----+----+----+----+----+----+
 * |AAAA AAAA AAAA AAAA ZZZZ ZZZZ ZZZZ|  (fragment #1 has precedence)
 * +----+----+----+----+----+----+----+
 *
 * or as:
 *
 * <-- frag #1 --><---- frag #2 ----->
 * +----+----+----+----+----+----+----+
 * |AAAA AAAA AAAA ZZZZ ZZZZ ZZZZ ZZZZ|  (fragment #2 has precedence)
 * +----+----+----+----+----+----+----+
 *
 * Depending on the destination OS, either strategy #1 or #2 may be used,
 * and this is only a very basic case (reality is even more complicated).
 * For a nice introduction to overlapping IP fragments issues, see:
 *
 * http://www.sans.org/reading_room/whitepapers/detection/ip-fragment-reassembly-scapy_33969
 *
 * Also, see the following references
 *
 * . http://tools.ietf.org/html/rfc1858
 * . http://en.wikipedia.org/wiki/IP_fragmentation_attacks
 *
 * For now, just let new fragments overwrite existing data in the
 * reassembly buffer.  This is the policy used by Cisco/IOS BTW.
 *
 * We should probably implement several possible reassembly policies,
 * and let the user decide which is the most appropriate.
 *
 * @param dg  a pointer to a ip_dgram_t previously initialized with dgram_init()
 * @param x   payload (fresh data)
 * @param off payload offset in the datagram (bytes)
 * @param len payload length in the datagram (bytes)
 * @param mf  true if more fragments are expected
 * @return 
 *          3 - overlapped data on the left side of the hole
 *          4 - overlapped data on the right side of the hole
 *          5 - overlapped data on both left and right side of the hole
 *          6 - fragment has not been used - duplicated data fragments
 *          0 - No overlapped data
 */

int ip_dgram_update_holes( ip_dgram_t *dg, const uint8_t *x, unsigned off, unsigned len, int mf)
{
   ip_frags_t *holes = &dg->holes;
   ip_frag_t  *hole  = holes->lh_first;

   /* Issue #201 (F-BUG-037): reject extents beyond the max datagram size up
    * front — callers should have validated this already, but the check keeps
    * the hole math and the buffer growth below bounded no matter who calls. */
   if( (uint64_t) off + len > MMT_IP_FRAG_MAX_DGRAM ) {
      MMT_LOG( PROTO_IP, MMT_LOG_DEBUG, "*** Warning: malformed packet (fragment extent out of range)\n" );
      return 1;
   }

   unsigned loff = off;
   unsigned roff = off+len;
   int is_overlapped = 0;
   int unused_fragment = 1;
   while( hole ) {
      int do_delete = 0;
      //if(( hole->roff < loff ) || ( hole->loff > roff )) {
      if( hole->roff < loff ) {
         // payload doesn't interact with this hole, skip it
         hole = hole->frags.le_next;
         continue;
      }

      if( hole->loff > roff ) {
         // current hole is past the payload.
         // don't bother considering the rest of the list since
         // any subsequent hole would be even further right.
         // LN: There is one case missing here: the current fragment is overlap some data which were already in the datagram. For example this case
         // frag    offset      len
         // 1       0           36
         // 2       24          4
         // -> so should we ignore fragment 2 or we will overwrite fragment 2 into fragment 1???
         // IGNORE FOR NOW -> BUT WITH NOTIFY!
         break;
      }
        // printf("[ip_dgram_update_holes] hole->loff: %d, hole->roff: %d, loff: %d, roff: %d \n",hole->loff, hole->roff, loff, roff);
      if( hole->loff < loff ) {
         // hole is trimmed from the right
         if( mf && ( hole->roff > roff )) {
            // hole is also trimmed from the left - the new segment split the current hole into 2 holes: before and after current sgements
            // -> resize current (left) hole
            // -> allocate a new (right) hole
            ip_frag_t *new = ip_frag_alloc( roff, hole->roff );
            /* Issue #201: unchecked allocation — a NULL hole must not be
             * inserted (LIST_INSERT_AFTER writes through it). */
            if( new == NULL )
               return 1;
            hole->roff = loff - 1;
            LIST_INSERT_AFTER( hole, new, frags );
            hole = new;
            unused_fragment = 0;
         } else {
            // hole is trimmed only from the right
            if (roff > hole->roff){
                // Overlap data on the right side of the hole
                is_overlapped = 4;
            }
            // -> resize it
            hole->roff = loff - 1;
            unused_fragment = 0;            
         }
      } else if( mf && ( hole->roff > roff )) {
         // hole is trimmed only from the left
         if(loff < hole->loff){
            // Overlap data on the left side of the hole
            is_overlapped = 3;
         }
         // -> resize it
         hole->loff = roff;
         unused_fragment = 0;
      } else {
         // payload is overlapping the entire hole
         // -> remove it from the list
         //BW: at this point we should delete the fragment, first need to step into the next frag
         LIST_REMOVE( hole, frags );
         do_delete = 1;
         if(hole->loff > loff && hole->roff < roff){
            is_overlapped = 5;
         }
         unused_fragment = 0;
      }

      // copy the payload, possibly growing the reassembly buffer
      if( roff > dg->len ) {
         /* Issue #201: unchecked realloc — on failure dg->x used to be
          * overwritten with NULL while dg->len still grew, so the memcpy below
          * wrote through NULL + off. Keep the old buffer on failure. */
         uint8_t *x0 = (uint8_t*)mmt_realloc( dg->x, roff );
         if( x0 == NULL )
            return 1;
         dg->x   = x0;
         dg->len = roff;
      }
      (void)memcpy( dg->x + off, x, len );

      //BW: delete the fragment if necessary
      if( do_delete ) {
         ip_frag_t  * to_delete = hole;
         hole = hole->frags.le_next;
         ip_frag_free( to_delete );
      } else {
         hole = hole->frags.le_next;
      }
   }
   if (unused_fragment) return 6;
   return is_overlapped;
}


/* Issue #201 (F-BUG-020): shared ip_streams fragment-map maintenance.
 *
 * The map holds both ip_dgram_t and ipv6_dgram_t values; both structs share
 * the same leading {ip_version, last_activity, x, len} layout, so the walkers
 * below can read the metadata and pick the right deallocator through an
 * ip_dgram_t view. Removal inside hashmap_walk() is safe: the walk caches the
 * successor before invoking the callback (hashmap.c). */

static void _frag_dgram_free( void *val )
{
   ip_dgram_t *dg = (ip_dgram_t *) val;
   if( dg == NULL )
      return;
   if( dg->ip_version == 6 )
      ipv6_dgram_free( (ipv6_dgram_t *) val );
   else
      ip_dgram_free( dg );
}

static void _frag_sweep_walker( mmt_hashmap_t *map, mmt_hent_t *he, void *arg )
{
   uint32_t    now = *(const uint32_t *) arg;
   ip_dgram_t *dg  = (ip_dgram_t *) he->val;

   /* Drop map corruption (NULL values) and datagrams idle for at least
    * MMT_IP_FRAG_TIMEOUT_SEC. The `now >= last_activity` clause keeps entries
    * alive if packet timestamps ever run backwards. */
   if( dg == NULL
   || ( now >= dg->last_activity
        && now - dg->last_activity >= MMT_IP_FRAG_TIMEOUT_SEC )) {
      void *val = he->val;
      hashmap_remove( map, he->key );
      _frag_dgram_free( val );
   }
}

void mmt_ip_frag_map_sweep( mmt_hashmap_t *map, uint32_t now )
{
   if( map == NULL || map->slots == NULL )
      return;
   hashmap_walk( map, _frag_sweep_walker, &now );
}

static void _frag_drain_walker( mmt_hashmap_t *map, mmt_hent_t *he, void *arg )
{
   (void) arg;
   void *val = he->val;
   hashmap_remove( map, he->key );
   _frag_dgram_free( val );
}

void mmt_ip_frag_map_drain( mmt_hashmap_t *map )
{
   if( map == NULL || map->slots == NULL )
      return;
   hashmap_walk( map, _frag_drain_walker, NULL );
}

struct _frag_oldest_ctx {
   int        found;
   uint32_t   last_activity;
   mmt_key_t  key;
};

static void _frag_oldest_walker( mmt_hashmap_t *map, mmt_hent_t *he, void *arg )
{
   (void) map;
   struct _frag_oldest_ctx *ctx = (struct _frag_oldest_ctx *) arg;
   ip_dgram_t *dg = (ip_dgram_t *) he->val;
   uint32_t    act = (dg != NULL) ? dg->last_activity : 0;
   if( !ctx->found || act < ctx->last_activity ) {
      ctx->found         = 1;
      ctx->last_activity = act;
      ctx->key           = he->key;
   }
}

void mmt_ip_frag_map_evict_oldest( mmt_hashmap_t *map )
{
   if( map == NULL || map->slots == NULL )
      return;
   struct _frag_oldest_ctx ctx = { 0, 0, 0 };
   hashmap_walk( map, _frag_oldest_walker, &ctx );
   if( !ctx.found )
      return;
   void *val = NULL;
   if( hashmap_get( map, ctx.key, &val ) ) {
      hashmap_remove( map, ctx.key );
      _frag_dgram_free( val );
   }
}


//  - - - - - - - - - - - - - - -  //
//  P R I V A T E   M E T H O D S  //
//  - - - - - - - - - - - - - - -  //

// ip_dgram_update_holes() should be private.
// (it was left public because of unit tests)

/*EoF*/


#include <string.h> // memcpy()

#include "proto_ip_dgram.h"


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
   ip_dgram_t *dg = (ip_dgram_t *)mmt_malloc( sizeof( ip_dgram_t ));
   ip_dgram_init( dg );

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
 */

void ip_dgram_init( ip_dgram_t *dg )
{
   dg->x   = 0;
   dg->len = 0;
   dg->nb_packets = 0;
   dg->caplen = 0;
   LIST_INIT( &dg->holes );

   ip_frag_t *hole = ip_frag_alloc( 0, (uint16_t)-1 );
   LIST_INSERT_HEAD( &dg->holes, hole, frags );
}

/**
 * Cleanup a datagram (destructor)
 *
 * @param dg a pointer to a ip_dgram_t previously initialized with dgram_init()
 */

void ip_dgram_cleanup( ip_dgram_t *dg )
{
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
 */

void ip_dgram_update( ip_dgram_t *dg, const struct iphdr *ip, unsigned len ,unsigned caplen)
{
   unsigned ip_len =  ntohs( ip->tot_len  );
   unsigned ip_off = (ntohs( ip->frag_off ) & IP_OFFSET) << 3;
   unsigned ip_mf  =  ntohs( ip->frag_off ) & IP_MF;
   unsigned ip_hl  =  ip->ihl << 2;

   const uint8_t *payload = (const uint8_t *)ip + ip_hl;

   if(( ip_hl < sizeof( struct iphdr )) || ( ip_hl > len )) {
      MMT_LOG( PROTO_IP, MMT_LOG_DEBUG, "*** Warning: malformed packet (header length mismatch)\n" );
      return;
   }

   if( len < ip_len ) {
      MMT_LOG( PROTO_IP, MMT_LOG_DEBUG, "*** Warning: malformed packet (length mismatch)\n" );
      return;
   }
   dg->nb_packets ++;
   dg->caplen += caplen;
   ip_dgram_update_holes( dg, payload, ip_off, len - ip_hl, ip_mf );
}

/**
 * Check whether a datagram is complete (fully reassembled)
 *
 * @param dg a pointer to a ip_dgram_t previously initialized with dgram_init()
 * @return 1 if dg is a complete datagram, 0 otherwise
 */

int ip_dgram_is_complete( ip_dgram_t *dg )
{
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
   (void)printf( "--- IP DATAGRAM ---\n" );
   (void)printf( "   id: %p\n", dg );
   (void)printf( "  len: %d\n", dg->len );

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

   (void)printf( "holes:" );

   if( hole == 0 ) {
      (void)printf( " none - datagram is complete\n" );
      return;
   }

   while( hole ) {
      ip_frag_dump( hole );
      hole = hole->frags.le_next;
   }

   (void)printf( "\n" );
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
 */

void ip_dgram_update_holes( ip_dgram_t *dg, const uint8_t *x, unsigned off, unsigned len, int mf )
{
   ip_frags_t *holes = &dg->holes;
   ip_frag_t  *hole  = holes->lh_first;

   unsigned loff = off;
   unsigned roff = off+len;
   int do_delete = 0;

   while( hole ) {
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
         break;
      }

      if( hole->loff < loff ) {
         // hole is trimmed from the right
         if( mf && ( hole->roff > roff )) {
            // hole is also trimmed from the left
            // -> resize current (left) hole
            // -> allocate a new (right) hole
            ip_frag_t *new = ip_frag_alloc( roff, hole->roff );
            hole->roff = loff - 1;
            LIST_INSERT_AFTER( hole, new, frags );
            hole = new;
         } else {
            // hole is trimmed only from the right
            // -> resize it
            hole->roff = loff - 1;
         }
      } else if( mf && ( hole->roff > roff )) {
         // hole is trimmed only from the left
         // -> resize it
         hole->loff = roff;
      } else {
         // payload is overlapping the entire hole
         // -> remove it from the list
         //BW: at this point we should delete the fragment, first need to step into the next frag
         LIST_REMOVE( hole, frags );
         do_delete = 1;
      }

      // copy the payload, possibly growing the reassembly buffer
      if( roff > dg->len ) {
         uint8_t *x0 = (uint8_t*)mmt_realloc( dg->x, roff );
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
}


//  - - - - - - - - - - - - - - -  //
//  P R I V A T E   M E T H O D S  //
//  - - - - - - - - - - - - - - -  //

// ip_dgram_update_holes() should be private.
// (it was left public because of unit tests)

/*EoF*/

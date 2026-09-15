
#include <string.h> // memcpy()

#include "proto_ipv6_dgram.h"
#include "proto_ip_dgram.h" /* Issue #201: MMT_IP_FRAG_MAX_DGRAM bound */

//  - - - - - - - - - - - - - -  //
//  P U B L I C   M E T H O D S  //
//  - - - - - - - - - - - - - -  //

/**
 * Create a new datagram (allocator)
 *
 * @return a new, initialized datagram
 */

ipv6_dgram_t *ipv6_dgram_alloc()
{
   /* Issue #201: unchecked mmt_malloc / ip_frag_alloc — a NULL dg would be
    * written through by ipv6_dgram_init(), and a missing initial hole made a
    * datagram look instantly "complete". */
   ipv6_dgram_t *dg = (ipv6_dgram_t *)mmt_malloc(sizeof(ipv6_dgram_t));
   if (dg == NULL)
      return NULL;
   if (!ipv6_dgram_init(dg))
   {
      mmt_free(dg);
      return NULL;
   }

   return dg;
}

/**
 * Destroy a datagram (deallocator)
 *
 * @param dg a pointer to a ipv6_dgram_t previously allocated with dgram_alloc()
 */

void ipv6_dgram_free(ipv6_dgram_t *dg)
{
   ipv6_dgram_cleanup(dg);
   mmt_free(dg);
}

/**
 * Initialize a datagram (constructor)
 *
 * @param dg a pointer to an uninitialized ipv6_dgram_t
 * @return 1 on success, 0 if the initial hole could not be allocated
 */

int ipv6_dgram_init(ipv6_dgram_t *dg)
{
   /* Issue #201 (F-BUG-020): metadata used by the ip_streams sweep/drain
    * hooks — must stay the leading layout shared with struct ip_dgram. */
   dg->ip_version = 6;
   dg->last_activity = 0;
   dg->x = 0;
   dg->len = 0;
   dg->nb_packets = 0;
   dg->caplen = 0;
   dg->max_packet_size = 0;
   dg->current_packet_size = 0;
   dg->last_offset = 0;
   int i = 0;
   for (i = 0; i < MMT_MAX_NUMBER_FRAGMENT; i++)
   {
      dg->packet_offsets[i] = -1;
   }
   LIST_INIT(&dg->holes);

   ip_frag_t *hole = ip_frag_alloc(0, MMT_IP_FRAG_MAX_DGRAM);
   if (hole == NULL)
      return 0;
   LIST_INSERT_HEAD(&dg->holes, hole, frags);
   return 1;
}

/**
 * Cleanup a datagram (destructor)
 *
 * @param dg a pointer to a ipv6_dgram_t previously initialized with dgram_init()
 */

void ipv6_dgram_cleanup(ipv6_dgram_t *dg)
{
   if (dg == NULL)
      return;

   int i = 0;
   for (i = 0; i < MMT_MAX_NUMBER_FRAGMENT; i++)
   {
      dg->packet_offsets[i] = -1;
   }

   ip_frags_t *holes = &dg->holes;
   ip_frag_t *hole = holes->lh_first;
   ip_frag_t *safe_to_delete;
   while (hole)
   {
      safe_to_delete = hole;
      hole = hole->frags.le_next;
      ip_frag_free(safe_to_delete);
   }

   if (dg->x)
      mmt_free(dg->x);

   dg->x = 0;
   dg->len = 0;
   dg->nb_packets = 0;
   dg->caplen = 0;
   dg->last_offset = 0;
}

/**
 * Update a datagram
 *
 * @param dg  a pointer to a ipv6_dgram_t previously initialized with dgram_init()
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

/* Issue #59: ip is an alignment-safe view (mmt_una_ipv6hdr_t) over the byte-
 * aligned capture buffer, mirroring ip_dgram_update() from PR #58 (#57), so the
 * ntohs(ip->payload_len) read below is a single alignment-safe load. */
/* Issue #201 (F-BUG-037/040): `avail` is the number of captured bytes starting
 * at the IPv6 header (caplen - ip_offset); payload_offset and ext_header_len
 * are uint32_t because a long extension chain pushes them past 65535. Every
 * subtraction below is guarded before it happens:
 *   - payload_len = declared - ext_header_len would wrap to ~64 KiB when the
 *     declared IPv6 payload is smaller than the walked extension chain,
 *   - payload must lie entirely inside the captured window. */
int ipv6_dgram_update(ipv6_dgram_t *dg, const mmt_una_ipv6hdr_t *ip, unsigned avail, uint16_t fragment_offset, uint32_t payload_offset, uint8_t more_fragment, uint32_t ext_header_len)
{
   uint32_t declared = ntohs(ip->payload_len);
   if (ext_header_len >= declared || payload_offset > avail)
   {
      MMT_LOG( PROTO_IPV6, MMT_LOG_DEBUG, "*** Warning: malformed packet (ipv6 fragment length mismatch)\n" );
      return 1;
   }
   uint32_t payload_len = declared - ext_header_len;
   if ((uint64_t) payload_offset + payload_len > avail)
   {
      MMT_LOG( PROTO_IPV6, MMT_LOG_DEBUG, "*** Warning: malformed packet (ipv6 fragment beyond captured data)\n" );
      return 1;
   }
   /* Bound the reassembled extent exactly like the IPv4 path. */
   if ((uint64_t) fragment_offset * 8 + payload_len > MMT_IP_FRAG_MAX_DGRAM)
   {
      MMT_LOG( PROTO_IPV6, MMT_LOG_DEBUG, "*** Warning: malformed packet (ipv6 fragment extent out of range)\n" );
      return 1;
   }
   const uint8_t *payload = (const uint8_t *)ip + payload_offset;
   dg->nb_packets++;
   dg->caplen += avail;
   if (fragment_offset == 0)
   {
      dg->max_packet_size = payload_len;
   }
   if (more_fragment == 0)
   {
      dg->max_packet_size = fragment_offset * 8 + payload_len;
      dg->last_offset = fragment_offset;
   }

   int i = 0;
   for (i = 0; i < MMT_MAX_NUMBER_FRAGMENT - 1; i++)
   {
      if (dg->packet_offsets[i] == -1)
         break;
      if (dg->packet_offsets[i] == fragment_offset)
      {
         // debug("[IP -]> Duplicated fragment: offset - %d",fragment_offset);
         // printf("[IP -]> Duplicated fragment: offset - %d|%d, id - %d\n",i,ip_off, ip->id);
         break;
      }
   }

   if (dg->packet_offsets[i] == -1)
   {
      dg->packet_offsets[i] = fragment_offset;
      dg->current_packet_size += payload_len;
      // printf("new fragment: %d", dg->current_packet_size);
   }
   else
   {
      // TODO: Can return here to not overwrite the later fragment
      return 2;
   }
   // ipv6_dgram_update_holes( dg, payload, ip_off, len - ip_hl, ip_mf);
   // LN: Using ip_len to remove the padding from IP payload
   // printf("Going to update holes: %d, %d, %d, %s\n",fragment_offset, payload_len, more_fragment, payload);
   return ipv6_dgram_update_holes(dg, payload, (unsigned) fragment_offset * 8, payload_len, more_fragment);
   // return 1;
}

/**
 * Check whether a datagram is complete (fully reassembled)
 *
 * @param dg a pointer to a ipv6_dgram_t previously initialized with dgram_init()
 * @return 1 if dg is a complete datagram, 0 otherwise
 */

int ipv6_dgram_is_complete(ipv6_dgram_t *dg)
{
   if (dg->last_offset == 0)
      return 0;
   if (dg->current_packet_size < dg->max_packet_size)
      return 0;
   ip_frags_t *holes = &dg->holes;
   return (holes->lh_first == 0);
}

/**
 * Dump a datagram
 *
 * @param dg a pointer to a ipv6_dgram_t previously initialized with dgram_init()
 */

void ipv6_dgram_dump(ipv6_dgram_t *dg)
{
   (void)printf("--- IP DATAGRAM ---\n");
   (void)printf("   id: %p\n", dg);
   (void)printf("  len: %d\n", dg->len);

   ipv6_dgram_dump_holes(dg);
}

/**
 * Dump a datagram as a list of holes
 *
 * @param dg a pointer to a ipv6_dgram_t previously initialized with dgram_init()
 */

void ipv6_dgram_dump_holes(ipv6_dgram_t *dg)
{
   ip_frags_t *holes = &dg->holes;
   ip_frag_t *hole = holes->lh_first;

   (void)printf("holes:");

   if (hole == 0)
   {
      (void)printf(" none - datagram is complete\n");
      return;
   }

   while (hole)
   {
      ip_frag_dump(hole);
      hole = hole->frags.le_next;
   }

   (void)printf("\n");
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
 * @param dg  a pointer to a ipv6_dgram_t previously initialized with dgram_init()
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

int ipv6_dgram_update_holes(ipv6_dgram_t *dg, const uint8_t *x, unsigned off, unsigned len, int mf)
{
   ip_frags_t *holes = &dg->holes;
   ip_frag_t *hole = holes->lh_first;

   /* Issue #201 (F-BUG-037): reject extents beyond the max datagram size —
    * mirrors the IPv4 path. */
   if ((uint64_t) off + len > MMT_IP_FRAG_MAX_DGRAM)
   {
      MMT_LOG( PROTO_IPV6, MMT_LOG_DEBUG, "*** Warning: malformed packet (ipv6 fragment extent out of range)\n" );
      return 1;
   }

   unsigned loff = off;
   unsigned roff = off + len;
   // printf("loff %d - roff %d\n", loff, roff );
   int is_overlapped = 0;
   int unused_fragment = 1;
   while (hole)
   {
      int do_delete = 0;
      //if(( hole->roff < loff ) || ( hole->loff > roff )) {
      if (hole->roff < loff)
      {
         // payload doesn't interact with this hole, skip it
         hole = hole->frags.le_next;
         continue;
      }

      if (hole->loff > roff)
      {
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
      // printf("[ipv6_dgram_update_holes] hole->loff: %d, hole->roff: %d, loff: %d, roff: %d \n",hole->loff, hole->roff, loff, roff);
      if (hole->loff < loff)
      {
         // hole is trimmed from the right
         if (mf && (hole->roff > roff))
         {
            // hole is also trimmed from the left - the new segment split the current hole into 2 holes: before and after current sgements
            // -> resize current (left) hole
            // -> allocate a new (right) hole
            ip_frag_t *new = ip_frag_alloc(roff, hole->roff);
            /* Issue #201: unchecked allocation — a NULL hole must not be
             * inserted (LIST_INSERT_AFTER writes through it). */
            if (new == NULL)
               return 1;
            hole->roff = loff - 1;
            LIST_INSERT_AFTER(hole, new, frags);
            hole = new;
            unused_fragment = 0;
         }
         else
         {
            // hole is trimmed only from the right
            if (roff > hole->roff)
            {
               // Overlap data on the right side of the hole
               // printf("roff %d - hole->roff %d\n", roff, hole->roff );
               is_overlapped = 4;
            }
            // -> resize it
            hole->roff = loff - 1;
            unused_fragment = 0;
         }
      }
      else if (mf && (hole->roff > roff))
      {
         // hole is trimmed only from the left
         if (loff < hole->loff)
         {
            // Overlap data on the left side of the hole
            // printf("loff %d - hole->loff %d\n", loff, hole->loff );
            is_overlapped = 3;
         }
         // -> resize it
         hole->loff = roff;
         unused_fragment = 0;
      }
      else
      {
         // payload is overlapping the entire hole
         // -> remove it from the list
         //BW: at this point we should delete the fragment, first need to step into the next frag
         LIST_REMOVE(hole, frags);
         do_delete = 1;
         if (hole->loff > loff && hole->roff < roff)
         {
            is_overlapped = 5;
         }
         unused_fragment = 0;
      }

      // copy the payload, possibly growing the reassembly buffer
      if (roff > dg->len)
      {
         /* Issue #201: unchecked realloc — keep the old buffer on failure
          * instead of overwriting dg->x with NULL before the memcpy. */
         uint8_t *x0 = (uint8_t *)mmt_realloc(dg->x, roff);
         if (x0 == NULL)
            return 1;
         dg->x = x0;
         dg->len = roff;
      }
      (void)memcpy(dg->x + off, x, len);

      //BW: delete the fragment if necessary
      if (do_delete)
      {
         ip_frag_t *to_delete = hole;
         hole = hole->frags.le_next;
         ip_frag_free(to_delete);
      }
      else
      {
         hole = hole->frags.le_next;
      }
   }
   if (unused_fragment)
      return 6;
   return is_overlapped;
}

//  - - - - - - - - - - - - - - -  //
//  P R I V A T E   M E T H O D S  //
//  - - - - - - - - - - - - - - -  //

// ipv6_dgram_update_holes() should be private.
// (it was left public because of unit tests)

/*EoF*/

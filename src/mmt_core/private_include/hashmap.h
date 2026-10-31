
#ifndef _MMT_HASHMAP_H
#define _MMT_HASHMAP_H

#include <stdlib.h>

#include <sys/queue.h>
#include "data_defs.h"


#define MMT_HASHMAP_NSLOTS  0x100

/*
   +--------------------+
   |   mmt_hashmap_t    |
   +--------------------+
   |  nslots            |
   |  slots (array):    |
   |  +--------------+  |
   |  | mmt_hslot_t  |  |
   |  +--------------+  |    +--------------+     +--------------+     +--------------+
   |  | mmt_hslot_t -+--+--->|  mmt_hent_t  |     |  mmt_hent_t  |     |  mmt_hent_t  |
   |  +--------------+  |    +--------------+     +--------------+     +--------------+
   |  | mmt_hslot_t  |  |    |  prev        |<----+- prev        |<----+- prev        |
   |  +--------------+  |    |  next -------+---->|  next -------+---->|  next        |
   |  | mmt_hslot_t  |  |    |  key         |     |  key         |     |  key         |
   |  +--------------+  |    |  val         |     |  val         |     |  val         |
   |  | mmt_hslot_t  |  |    +--------------+     +--------------+     +--------------+
   |  +--------------+  |
   +--------------------+

   USAGE:

      mmt_hashmap_t *map;
      mmt_key_t     key;
      mmt_vec_t     val;

      map = hashmap_alloc();

      hashmap_insert_kv( map, key, val );
      hashmap_get( map, key, &val );

      hashmap_free( map );
*/


//  - - - - - - - - - - - - - - - -  //
//  T Y P E   D E F I N I T I O N S  //
//  - - - - - - - - - - - - - - - -  //

/* vector of bytes in memory */

struct mmt_vec {
   void *x;
   unsigned len;
};

typedef struct mmt_vec mmt_vec_t;


/* hash entry */

struct mmt_hent {
   LIST_ENTRY(mmt_hent) entries;
   mmt_key_t  key;
   void      *val;
};

typedef struct mmt_hent mmt_hent_t;


/* Issue #383 (F-PERF-004): intrusive recency link for map values that need
 * an eviction order (the ip_streams / ip6_streams fragment maps). Values
 * embed one node; the map's owner keeps a sentinel node whose `key` is
 * unused. An empty list is a self-linked sentinel, and an all-zero sentinel
 * (a memset handler) is treated as empty. `key` lets the victim be removed
 * from the map without scanning it. */

struct mmt_hlru {
   struct mmt_hlru *prev;
   struct mmt_hlru *next;
   mmt_key_t        key;
};

typedef struct mmt_hlru mmt_hlru_t;


/* hash slot (linked list of entries) */

LIST_HEAD( mmt_hslot, mmt_hent );

typedef struct mmt_hslot  mmt_hslot_t;


/* hash map */

struct mmt_hashmap {
   mmt_hslot_t *slots; // array of slots
   unsigned    nslots; // number of slots
   unsigned    nkeys;  // number of keys
};

typedef struct mmt_hashmap mmt_hashmap_t;

typedef void (*mmt_hashmap_walker_t)( mmt_hashmap_t *, mmt_hent_t *, void * );


//  - - - - - - - - - - - - - - - -  //
//  P U B L I C   I N T E R F A C E  //
//  - - - - - - - - - - - - - - - -  //

extern mmt_hashmap_t *hashmap_alloc     ( void );
extern void           hashmap_free      ( mmt_hashmap_t * );
extern void           hashmap_init      ( mmt_hashmap_t * );
extern void           hashmap_cleanup   ( mmt_hashmap_t * );

/* Issue #533: MMTAPI = exported for libmmt_tcpip until #534 (the core is
 * built -fvisibility=hidden); the other hashmap_* entry points are hidden. */
MMTAPI void           hashmap_insert_kv ( mmt_hashmap_t *, mmt_key_t, void * );
MMTAPI int            hashmap_get       ( mmt_hashmap_t *, mmt_key_t, void ** );
MMTAPI void           hashmap_walk      ( mmt_hashmap_t *, mmt_hashmap_walker_t, void * );
MMTAPI int            hashmap_remove    ( mmt_hashmap_t *, mmt_key_t );

extern void           hashmap_dump      ( mmt_hashmap_t * );

/* Issue #558: the slot of a key. The fragment-map keys (ip_fragment_key(),
 * ip6_fragment_key()) pack addresses and the datagram id, and `key % 256`
 * kept only their low byte, so related datagrams shared a few chains. The
 * key goes through the fmix64 finalizer (MurmurHash3, as mmt_mix64() in
 * hash_utils.c) first, so every key bit reaches the slot index. */
static inline unsigned hashmap_slot_index( mmt_key_t key )
{
   uint64_t h = (uint64_t) key;
   h ^= h >> 33;
   h *= 0xff51afd7ed558ccdULL;
   h ^= h >> 33;
   h *= 0xc4ceb9fe1a85ec53ULL;
   h ^= h >> 33;
   return (unsigned) (h & (MMT_HASHMAP_NSLOTS - 1));
}


#endif /*_MMT_HASHMAP_H*/

/*EoF*/

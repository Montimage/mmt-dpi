
#ifndef _MMT_HASHMAP_H
#define _MMT_HASHMAP_H

#include <stdlib.h>

#include "queue.h"
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

extern void           hashmap_insert_kv ( mmt_hashmap_t *, mmt_key_t, void * );
extern int            hashmap_get       ( mmt_hashmap_t *, mmt_key_t, void ** );
extern void           hashmap_walk      ( mmt_hashmap_t *, mmt_hashmap_walker_t, void * );
extern int            hashmap_remove    ( mmt_hashmap_t *, mmt_key_t );

extern void           hashmap_dump      ( mmt_hashmap_t * );


#endif /*_MMT_HASHMAP_H*/

/*EoF*/

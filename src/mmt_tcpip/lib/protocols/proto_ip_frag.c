
#include <stdio.h>  // fprintf()

#include "packet_processing.h"
#include "proto_ip_frag.h"


//  - - - - - - - - - - - - - -  //
//  P U B L I C   M E T H O D S  //
//  - - - - - - - - - - - - - -  //

/**
 * Create a new IP fragment (allocator)
 *
 * @return a new, initialized fragment
 */

ip_frag_t *ip_frag_alloc( unsigned loff, unsigned roff )
{
   ip_frag_t *frag = (ip_frag_t *)mmt_malloc( sizeof( ip_frag_t ));

   if( !ip_frag_init( frag, loff, roff )) {
      (void)fprintf( stderr, "*** Warning: ip_frag_init() failed\n" );
      mmt_free( frag );
      return (ip_frag_t*)0;
   }

   return frag;
}

/**
 * Destroy an IP fragment (deallocator)
 *
 * @param frag a pointer to a ip_frag_t previously allocated with ip_frag_alloc()
 */

void ip_frag_free( ip_frag_t *frag )
{
   ip_frag_cleanup( frag );
   mmt_free( frag );
}

/**
 * Initialize a fragment (constructor)
 *
 * @param frag a pointer to an uninitialized ip_frag_t
 */

int ip_frag_init( ip_frag_t *frag, unsigned loff, unsigned roff )
{
   if( roff < loff ) {
      (void)fprintf( stderr, "*** Warning: inconsistent offsets in ip_frag_init()\n" );
      return 0;
   }

   frag->loff = loff;
   frag->roff = roff;

   return 1;
}

/**
 * Cleanup a fragment (destructor)
 *
 * @param frag a pointer to a ip_frag_t previously initialized with ip_frag_init()
 */

void ip_frag_cleanup( ip_frag_t *frag )
{
   frag->loff = 0;
   frag->roff = 0;
}

/**
 * Dump a fragment
 *
 * @param frag a pointer to a ip_frag_t previously initialized with ip_frag_init()
 */

void ip_frag_dump( ip_frag_t *frag )
{
   if( frag == (ip_frag_t*)0 )
      (void)printf( " [nil]" );
   else {
      (void)printf( " [%u;%u]", frag->loff, frag->roff );
   }
}

/*EoF*/

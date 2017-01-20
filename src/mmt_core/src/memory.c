
#include <stdio.h>  // fprintf()
#include <stdlib.h> // abort()

#include "memory.h"
#include "mmt_core.h"


// static uint64_t allocated = 0;
// static uint64_t freed     = 0;


//  - - - - - - - - - - - - - -  //
//  P U B L I C   M E T H O D S  //
//  - - - - - - - - - - - - - -  //

void *mmt_malloc( size_t size )
{
   uint8_t *x0 = (uint8_t*)malloc( size + sizeof( size_t ));

   if( unlikely( x0 == NULL )) {
      // log and abort
      (void)fprintf( stderr, "not enough memory\n" );
      abort();
   }

   *((size_t*)x0) = size;
   // allocated     += size;

   return (void*)( x0 + sizeof( size_t ));
}


void *mmt_realloc( void *x, size_t size )
{
   if( x == NULL ) {
      if( size == 0 ) return NULL; // nothig to do
      return mmt_malloc( size );
   }

   // x != NULL

   if( size == 0 ) {
      mmt_free( x );
      return NULL;
   }

   // ( x != NULL ) && ( size != 0 )

   uint8_t *x0 = (uint8_t*)x - sizeof( size_t );
   size_t  psz = *((size_t*)x0);

   if( size <= psz ) return NULL; // nothing to do

   // ( x != NULL ) && ( size > psz )

   uint8_t *x1 = (uint8_t*)realloc( x0, size + sizeof( size_t ));

   if( x1 == NULL ) {
      // log and abort
      (void)fprintf( stderr, "not enough memory\n" );
      abort();
   }

   *((size_t*)x1) = size;
   // allocated     += ( size - psz );

   return (void*)( x1 + sizeof( size_t ));
}


void mmt_free( void *x )
{
   if( unlikely( x == NULL )) return; // nothing to do

   uint8_t *x0 = (uint8_t*)x - sizeof( size_t );
   // freed += *((size_t*)x0);
   free( x0 );
}


// void mmt_meminfo( mmt_meminfo_t *m )
// {
//    m->allocated = allocated;
//    m->freed     = freed;
// }

/*EoF*/


#include <stdio.h>
#include <string.h>

#include "hexdump.h"


void
fhexdump( FILE *out, const uint8_t *x, uint32_t len )
{
   uint32_t i,j;
   char buf[8];
   char buffer[128];
   char strbuf[32];

   (void)sprintf( buffer,"\t00000000   " );

   for( i=0 ; i<len ; i++ ) {
      if( i && !( i%16 )) {
         (void)strcat( buffer,"\t" );
         (void)strcat( buffer, strbuf );
         (void)strcat( buffer,"\n" );
         (void)fprintf( out, "%s", buffer );
         (void)sprintf( buffer, "\t%08x   ", i );
      }

      if( i == ( len - 1 )) {
         if(( *(x+i) >= 0x20 ) && ( *(x+i) <= 0x7e ))
            strbuf[i%16] = *(x+i);
         else
            strbuf[i%16] = '.';
         strbuf[i%16+1] = 0;
         (void)sprintf( buf, " %02x", *(x+i) );
         (void)strcat( buffer, buf );
         for( j=0 ; j<16 - i%16 ; j++ )
            strcat( buffer, "   " );
         (void)strcat( buffer, "\t" );
         (void)strcat( buffer, strbuf );
         (void)strcat( buffer, "\n" );
         (void)fprintf( out, "%s", buffer );
      }
      if(( *(x+i) >= 0x20 ) && (( *(x+i) <= 0x7e ) && ( *(x+i) != 0x25 )))
         strbuf[i%16] = *(x+i);
      else
         strbuf[i%16] = '.';

      strbuf[i%16+1] = 0;
      (void)sprintf( buf, " %02x", *(x+i) );
      (void)strcat( buffer, buf );
   }
}


void
hexdump( const uint8_t *x, uint32_t len )
{ fhexdump( stderr, x, len ); }

/*EoF*/

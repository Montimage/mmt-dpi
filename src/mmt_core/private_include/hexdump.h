
#ifndef _MMT_HEXDUMP_H
#define _MMT_HEXDUMP_H

#include <stdio.h>
#include <stdint.h>


extern void fhexdump(FILE *out, const uint8_t *x, uint32_t len);
extern void hexdump(const uint8_t *x, uint32_t len);


#endif /*_MMT_HEXDUMP_H*/

/*EoF*/

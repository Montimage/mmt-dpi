
#ifndef _MMT_MEMORY_H
#define _MMT_MEMORY_H

#include <stdlib.h> // size_t
#include <stdint.h> // uint64_t


//  - - - - - - - - - - - - - - - -  //
//  T Y P E   D E F I N I T I O N S  //
//  - - - - - - - - - - - - - - - -  //

struct mmt_meminfo {
   uint64_t allocated;
   uint64_t freed;
};

typedef struct mmt_meminfo mmt_meminfo_t;


//  - - - - - - - - - - - - - - - -  //
//  P U B L I C   I N T E R F A C E  //
//  - - - - - - - - - - - - - - - -  //

extern void mmt_meminfo( mmt_meminfo_t * );


#endif /*_MMT_MEMORY_H*/

/*EoF*/

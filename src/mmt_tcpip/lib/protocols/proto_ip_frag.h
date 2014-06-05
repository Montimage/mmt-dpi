
#ifndef _MMT_IP_FRAG_H
#define _MMT_IP_FRAG_H

#include "queue.h"
#include "mmt_core.h"


/* IP fragment */

struct ip_frag {
   LIST_ENTRY(ip_frag) frags;  // sibling fragments
   uint16_t loff;              // leftmost offset in reassembly buffer
   uint16_t roff;              // rightmost offset in reassembly buffer
};


/* list of IP fragments */

LIST_HEAD( ip_frags, ip_frag );

typedef struct ip_frag  ip_frag_t;
typedef struct ip_frags ip_frags_t;


//  - - - - - - - - - - - - - - - -  //
//  P U B L I C   I N T E R F A C E  //
//  - - - - - - - - - - - - - - - -  //

extern ip_frag_t *ip_frag_alloc   ( unsigned, unsigned );
extern int        ip_frag_init    ( ip_frag_t *, unsigned, unsigned );
extern void       ip_frag_free    ( ip_frag_t * );
extern void       ip_frag_cleanup ( ip_frag_t * );
extern void       ip_frag_dump    ( ip_frag_t * );


#endif /* _MMT_IP_FRAG_H*/

/*EoF*/

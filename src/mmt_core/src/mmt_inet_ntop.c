/*
 * mmt_inet_ntop — exported address-to-text conversion (data_defs.h).
 *
 * A thin wrapper over the C library's inet_ntop(3) (issue #496, F-DEP-305):
 * the SDK supports Linux/glibc only, so it no longer carries its own copy of
 * the BSD/Apple implementation. IPv6 text is the canonical RFC 5952 form
 * glibc produces. The wrapper keeps the exported symbol and its contract:
 * NULL for a NULL address or buffer, an unsupported family, or a buffer too
 * small for the text.
 */
#include <sys/socket.h>
#include <arpa/inet.h>

#include "data_defs.h"

const char *
mmt_inet_ntop( int af, const void *addr, char *buf, socklen_t len )
{
   if( addr == NULL || buf == NULL )
      return NULL;
   if( af != AF_INET && af != AF_INET6 )
      return NULL;

   return inet_ntop( af, addr, buf, len );
}

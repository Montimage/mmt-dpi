/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/*
 * Copyright 1994, 1995 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <string.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#endif

#include "data_defs.h"

static const char *hexchars = "0123456789abcdef";

static const char *
mmt_inet_ntop4( const struct in_addr *addr, char *buf, socklen_t len )
{
   const uint8_t *ap = (const uint8_t *)&addr->s_addr;
   char tmp[INET_ADDRSTRLEN]; /* max length of ipv4 addr string */
   int fulllen;

   /*
    * snprintf returns number of bytes printed (not including NULL) or
    * number of bytes that would have been printed if more than would
    * fit
    */
   fulllen = snprintf(tmp, sizeof(tmp), "%d.%d.%d.%d",
                  ap[0], ap[1], ap[2], ap[3]);
   if (fulllen >= (int)len) {
      return NULL;
   }

   (void)memcpy( buf, tmp, fulllen + 1 );

   return buf;
}

static const char *
mmt_inet_ntop6( const struct in6_addr *addr, char *dst, socklen_t size )
{
   char hexa[8][5], tmp[INET6_ADDRSTRLEN];
   int zr[8];
   size_t len;
   int32_t i, j, k, skip;
   uint8_t x8, hx8;
   uint16_t x16;
   struct in_addr a4;

   if (addr == NULL) return NULL;

   (void)memset( tmp, 0, sizeof( tmp ));

   /*  check for mapped or compat addresses */
   i = IN6_IS_ADDR_V4MAPPED(addr);
   j = IN6_IS_ADDR_V4COMPAT(addr);
   if ((i != 0) || (j != 0))
   {
      char tmp2[16]; /* max length of ipv4 addr string */
#ifdef _WIN32
      a4.s_addr = addr->u.Word[3];
#elif _OSX
      a4.s_addr = 0;	//TODO need to fix in OSX
#else
      a4.s_addr = addr->__in6_u.__u6_addr32[3];
#endif
      len = snprintf(tmp, sizeof(tmp), "::%s%s", (i != 0) ? "ffff:" : "",
                  mmt_inet_ntop4(&a4, tmp2, sizeof(tmp2)));
      if (len >= size) return NULL;
      (void)memcpy( dst, tmp, len + 1 );
      return dst;
   }

   k = 0;
   for (i = 0; i < 16; i += 2)
   {
      j = 0;
      skip = 1;

      (void)memset( hexa[k], 0, 5 );

#ifdef _WIN32
      x8 = addr->u.Byte[i];
#elif _OSX

#else
      x8 = addr->__in6_u.__u6_addr8[i];
#endif

      hx8 = x8 >> 4;
      if (hx8 != 0)
      {
         skip = 0;
         hexa[k][j++] = hexchars[hx8];
      }

      hx8 = x8 & 0x0f;
      if ((skip == 0) || ((skip == 1) && (hx8 != 0)))
      {
         skip = 0;
         hexa[k][j++] = hexchars[hx8];
      }

#ifdef _WIN32
      x8 = addr->u.Byte[i + 1];
#elif _OSX

#else
      x8 = addr->__in6_u.__u6_addr8[i + 1];
#endif

      hx8 = x8 >> 4;
      if ((skip == 0) || ((skip == 1) && (hx8 != 0)))
      {
         hexa[k][j++] = hexchars[hx8];
      }

      hx8 = x8 & 0x0f;
      hexa[k][j++] = hexchars[hx8];

      k++;
   }

   /* find runs of zeros for :: convention */
   j = 0;
   for (i = 7; i >= 0; i--)
   {
      zr[i] = j;
#ifdef _WIN32
      x16 = addr->u.Word[i];
#elif _OSX

#else
      x16 = addr->__in6_u.__u6_addr16[i];
#endif
      if (x16 == 0) j++;
      else j = 0;
      zr[i] = j;
   }

   /* find longest run of zeros */
   k = -1;
   j = 0;
   for(i = 0; i < 8; i++)
   {
      if (zr[i] > j)
      {
         k = i;
         j = zr[i];
      }
   }

   for(i = 0; i < 8; i++)
   {
      if (i != k) zr[i] = 0;
   }

   len = 0;
   for (i = 0; i < 8; i++)
   {
      if (zr[i] != 0)
      {
         /* check for leading zero */
         if (i == 0) tmp[len++] = ':';
         tmp[len++] = ':';
         i += (zr[i] - 1);
         continue;
      }
      for (j = 0; hexa[i][j] != '\0'; j++) tmp[len++] = hexa[i][j];
      if (i != 7) tmp[len++] = ':';
   }

   /* trailing NULL */
   len++;

   if (len > size) return NULL;
   (void)memcpy( dst, tmp, len );
   return dst;
}

const char *
mmt_inet_ntop( int af, const void *addr, char *buf, socklen_t len )
{
   if( af == AF_INET6 )
      return mmt_inet_ntop6( addr, buf, len );
   if( af == AF_INET )
      return mmt_inet_ntop4( addr, buf, len );

   return NULL;
}

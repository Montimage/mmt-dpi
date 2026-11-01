/**
 * @file
 * Export markers of libmmt_core: MMTAPI and MMTCALL.
 */

#ifndef _MMT_EXPORTS_H
#define _MMT_EXPORTS_H

/* MMTAPI is the export marker of libmmt_core (issue #533): the core objects
 * are compiled with -fvisibility=hidden (rules/common.mk), so a core symbol
 * is in libmmt_core.so's dynamic symbol table only when its translation unit
 * sees an MMTAPI declaration. Inside the SDK build MMTAPI therefore carries
 * default visibility; for consumers it stays a plain `extern`, since
 * visibility only matters where the symbol is defined. It is `extern` in
 * both modes so data declarations (`MMTAPI const T name;`) never become
 * tentative definitions. */
 #ifdef _MMT_BUILD_SDK
   #if defined(__GNUC__)
     #define MMTAPI extern __attribute__((visibility("default")))
   #else
     #define MMTAPI extern
   #endif
 #else
   #define MMTAPI extern ///< Export marker of a public libmmt_core declaration: a plain `extern` for consumers.
 #endif
 #define MMTCALL ///< Calling-convention marker of a public function; empty on every supported toolchain.


#endif /*_MMT_EXPORTS_H*/

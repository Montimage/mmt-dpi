
#ifndef _MMT_EXPORTS_H
#define _MMT_EXPORTS_H


#ifdef _WIN32

 #ifdef _MMT_BUILD_SDK
   #define MMTAPI __declspec(dllexport)
 #else
   #define MMTAPI __declspec(dllimport)
 #endif
 #define MMTCALL __cdecl

#else

 #ifdef _MMT_BUILD_SDK
   #define MMTAPI
 #else
   #define MMTAPI extern
 #endif
 #define MMTCALL

#endif


#endif /*_MMT_EXPORTS_H*/


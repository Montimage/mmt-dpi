/*
 * common.h
 *
 *  Created on: Dec 10, 2018
 *          by: Huu-Nghia
 */

#ifndef SRC_MMT_5G_NAS_UTIL_COMMON_H_
#define SRC_MMT_5G_NAS_UTIL_COMMON_H_

#include <stdlib.h>
#include <stdint.h>


#ifdef __LITTLE_ENDIAN__
#error Macro __LITTLE_ENDIAN__ has been defined.
#endif

#if BYTE_ORDER == LITTLE_ENDIAN
#define __LITTLE_ENDIAN__
#else
#endif

//avoid memory padding
#define __package__  __attribute__((__packed__))


#endif /* SRC_MMT_5G_NAS_UTIL_COMMON_H_ */

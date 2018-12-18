/*
 * branch_optimization.h
 *
 *  Created on: Dec 10, 2018
 *          by: Huu-Nghia
 */

#ifndef SRC_MMT_5G_NAS_UTIL_BRANCH_OPTIMIZATION_H_
#define SRC_MMT_5G_NAS_UTIL_BRANCH_OPTIMIZATION_H_

#include <stdlib.h>
#include <stdint.h>

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif


#endif /* SRC_MMT_5G_NAS_UTIL_BRANCH_OPTIMIZATION_H_ */

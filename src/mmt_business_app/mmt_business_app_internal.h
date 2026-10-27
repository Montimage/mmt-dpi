/*
 * mmt_business_app_internal.h
 *
 *  Created on: Jun 3, 2021
 *      Author: nhnghia
 */

#ifndef SRC_MMT_BUSINESS_APP_MMT_BUSINESS_APP_INTERNAL_H_
#define SRC_MMT_BUSINESS_APP_MMT_BUSINESS_APP_INTERNAL_H_

#include "../mmt_core/public_include/mmt_core.h"
#include "../mmt_core/public_include/plugin_defs.h"
#include "../mmt_core/public_include/extraction_lib.h"
#include "include/mmt_business_app.h"

int init_proto_ips_data();

/* Plugin entry points, dlsym()ed by plugins_engine.c. libmmt_business_app is
 * built -fvisibility=hidden (issue #534): these are all it exports. */
MMTAPI int init_proto();
MMTAPI int cleanup_proto();

#endif /* SRC_MMT_BUSINESS_APP_MMT_BUSINESS_APP_INTERNAL_H_ */

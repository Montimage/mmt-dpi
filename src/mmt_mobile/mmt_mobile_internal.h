/*
 * mmt_mobile_internal.h
 *
 *  Created on: Dec 10, 2020
 *      Author: nhnghia
 */

#ifndef SRC_MMT_MOBILE_MMT_MOBILE_INTERNAL_H_
#define SRC_MMT_MOBILE_MMT_MOBILE_INTERNAL_H_

#include "mmt_mobile.h"
#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "mmt_tcpip.h"

//init protocols
int init_proto_diameter_struct();
int init_proto_s1ap();

#define __PACKED __attribute__((packed))

struct sctp_datahdr {
	uint8_t type;
	uint8_t flags;
	uint16_t length;
	uint32_t tsn;
	uint16_t stream;
	uint16_t ssn;
	uint32_t ppid;
} __PACKED;

struct sctphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t vtag;
    uint32_t checksum;
    uint8_t type;
    uint8_t flags;
    uint16_t length;
} __PACKED;

#endif /* SRC_MMT_MOBILE_MMT_MOBILE_INTERNAL_H_ */

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

/*
 https://tools.ietf.org/html/draft-ietf-aaa-diameter-05

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |      Ver      |                 Message Length                |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |R r r r r r r r|                  Command-Code                 |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                           Vendor-ID                           |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                      Hop-by-Hop Identifier                    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                      End-to-End Identifier                    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  AVPs ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-
 */
struct diameter_header {
	uint8_t version        :  8; //0-7
	uint32_t length        : 24; //9-31 ;//length of the Diameter message in bytes, including the header, always a multiple of 4 bytes
	uint8_t flag_r         :  1; //32
	uint8_t flag_p         :  1; //33
	uint8_t flag_e         :  1; //34
	uint8_t flag_t         :  1; //35
	uint8_t padding        :  4; //  4 bit padding
	uint32_t command_code  : 24;
	uint32_t application_id: 32;
	uint32_t hop_to_hop_id : 32;
	uint32_t end_to_end_id : 32;
} __PACKED;
#endif /* SRC_MMT_MOBILE_MMT_MOBILE_INTERNAL_H_ */

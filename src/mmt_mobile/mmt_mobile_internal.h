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
#include "mmt_common_internal_include.h"
#include "mmt_tcpip.h"

//init protocols
int init_proto_diameter_struct();
int init_proto_gtpv2_struct();

int init_proto_s1ap();


#define __PACKED __attribute__((packed))

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

//https://www.etsi.org/deliver/etsi_ts/129200_129299/129274/12.06.00_60/ts_129274v120600p.pdf
//page 20
struct gtpv2_header {
	uint8_t padding     : 3;
	uint8_t flag_t      : 1;
	uint8_t flag_p      : 1;
	uint8_t version     : 3; //should be always = 2
	uint8_t type        : 8;
	uint16_t length     : 16;
	/**
	 * If T flag is set to 1, then TEID shall be placed into octets 5-8.
	 * Otherwise, TEID field is not present at all.
	 */
	uint32_t teid : 32; //4 bytes;
	uint32_t sequence_number: 24; //3bytes
}__PACKED;


//The fields are transmitted in network byte order.
//For example: https://www.ietf.org/proceedings/52/I-D/draft-ietf-aaa-diameter-08.txt:
static inline uint32_t copy_4bytes_order( uint32_t data, int length ){
	uint32_t value = 0;
	char *dst = (char *)(&value);
	const char *src = (char *) &data;
	switch( length ){
	case 4:
		dst[3] = src[0];
		dst[2] = src[1];
		dst[1] = src[2];
		dst[0] = src[3];
		break;
	case 3:
		dst[2] = src[0];
		dst[1] = src[1];
		dst[0] = src[2];
		break;
	case 2:
		dst[1] = src[0];
		dst[0] = src[1];
		break;
	}
	return value;
}

#endif /* SRC_MMT_MOBILE_MMT_MOBILE_INTERNAL_H_ */

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
int init_proto_ngap_struct();
int init_proto_s1ap();
int init_proto_nas_5g_struct();


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
	/* Command flags byte (bits 32-39): R P E T r r r r, most significant
	 * bit first. Kept whole and decoded with DIAMETER_HDR_FLAG() — C
	 * bitfields are allocated LSB-first on little-endian GCC, so per-flag
	 * bitfields in wire order read the reserved bits (issue #504, F-BUG-202). */
	uint8_t flags;
	uint32_t command_code  : 24;
	uint32_t application_id: 32;
	uint32_t hop_to_hop_id : 32;
	uint32_t end_to_end_id : 32;
} __PACKED;

/* Diameter command flag masks within diameter_header.flags (RFC 6733 §3) */
#define DIAMETER_HDR_FLAG_R_MASK 0x80 /* Request */
#define DIAMETER_HDR_FLAG_P_MASK 0x40 /* Proxiable */
#define DIAMETER_HDR_FLAG_E_MASK 0x20 /* Error */
#define DIAMETER_HDR_FLAG_T_MASK 0x10 /* Potentially re-transmitted */
/* 1 when the flag selected by mask is set in hdr->flags, else 0 */
#define DIAMETER_HDR_FLAG(hdr, mask) ((uint8_t)(((hdr)->flags & (mask)) != 0))

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

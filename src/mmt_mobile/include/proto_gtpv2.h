/*
 * proto_gtpv2.h
 *
 *  Created on: Dec 11, 2020
 *      Author: nhnghia
 */

#ifndef SRC_MMT_MOBILE_INCLUDE_PROTO_GTPV2_H_
#define SRC_MMT_MOBILE_INCLUDE_PROTO_GTPV2_H_

enum {
	GTPV2_VERSION = 1,
	GTPV2_FLAG_T,
	GTPV2_FLAG_P,
	GTPV2_MESSAGE_TYPE,
	GTPV2_MESSAGE_LENGTH,
	GTPV2_TEID,
	GTPV2_SEQUENCE_NUMBER
};

#define GTPV2_VERSION_ALIAS               "version"
#define GTPV2_FLAG_T_ALIAS                "flag_type"
#define GTPV2_FLAG_P_ALIAS                "flag_p"
#define GTPV2_MESSAGE_TYPE_ALIAS          "message_type"
#define GTPV2_MESSAGE_LENGTH_ALIAS        "message_length"
#define GTPV2_TEID_ALIAS                  "teid"
#define GTPV2_SEQUENCE_NUMBER_ALIAS       "sequence_number"

#endif /* SRC_MMT_MOBILE_INCLUDE_PROTO_GTPV2_H_ */

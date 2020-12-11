/*
 * proto_diameter.h
 *
 *  Created on: Dec 9, 2020
 *      Author: nhnghia
 */

#ifndef SRC_MMT_LTE_INCLUDE_PROTO_DIAMETER_H_
#define SRC_MMT_LTE_INCLUDE_PROTO_DIAMETER_H_

enum {
	DIAMETER_VERSION = 1,
	DIAMETER_MESSAGE_LENGTH,
	DIAMETER_FLAG_R,
	DIAMETER_FLAG_P,
	DIAMETER_FLAG_E,
	DIAMETER_FLAG_T,
	DIAMETER_COMMAND_CODE,
	DIAMETER_APPLICATION_ID,
	DIAMETER_HOP_TO_HOP_ID,
	DIAMETER_END_TO_END_ID
};

#define DIAMETER_VERSION_ALIAS        "version"
#define DIAMETER_MESSAGE_LENGTH_ALIAS "message_length"
#define DIAMETER_FLAG_R_ALIAS         "flag_r"
#define DIAMETER_FLAG_P_ALIAS         "flag_p"
#define DIAMETER_FLAG_E_ALIAS         "flag_e"
#define DIAMETER_FLAG_T_ALIAS         "flag_t"
#define DIAMETER_COMMAND_CODE_ALIAS   "command_code"
#define DIAMETER_APPLICATION_ID_ALIAS "application_id"
#define DIAMETER_HOP_TO_HOP_ID_ALIAS  "hop_to_hop_id"
#define DIAMETER_END_TO_END_ID_ALIAS  "end_to_end_id"

#endif /* SRC_MMT_LTE_INCLUDE_PROTO_DIAMETER_H_ */

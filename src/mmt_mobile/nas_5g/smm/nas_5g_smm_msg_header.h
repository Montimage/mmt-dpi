/*
 * nas_5g_mmm_msg_header.h
 *
 *  Created on: Dec 18, 2020
 *      Author: nhnghia
 */

#include <stdlib.h>
#include <stdint.h>
#ifndef SRC_MMT_MOBILE_NAS_5G_SMM_NAS_5G_SMM_MSG_HEADER_H_
#define SRC_MMT_MOBILE_NAS_5G_SMM_NAS_5G_SMM_MSG_HEADER_H_

/* 3GPP TS 24.501 version 15.0.0 Release 15
 * ETSI TS 124 501 V15.0.0 (2018-07)
 * 8.3 5GS session management messages
 * General message organization example for a normal SMM NAS message:
 *
 *  --------------------------------------------------
 *   8     7      6      5     4      3      2      1
 *  +-----------------------+------------------------+
 *  +-----------------------+------------------------+
 *  |       Extended protocol discriminator          | octet 1
 *  +-----------------------+------------------------+
 *  |                 Session ID                     | octet 2
 *  +-----------------------+------------------------+
 *  |      Procedure transaction identity            | octet 3
 *  +-----------------------+------------------------+
 *  |                 Message type                   | octet 4
 *  +-----------------------+------------------------+
 *  |                                                | octet 5
 *  |     Other information elements as required     |
 *  ...                                            ...
 *  |                                                | octet n
 *  +-----------------------+------------------------+
 */

typedef struct nas_5g_smm_msg_header{
	uint8_t protocol_discriminator;
	uint8_t pdu_session_id;
	uint8_t procedure_transaction_identity;
	uint8_t message_type;
} nas_5g_smm_msg_header_t;

#endif /* SRC_MMT_MOBILE_NAS_5G_SMM_NAS_5G_SMM_MSG_HEADER_H_ */

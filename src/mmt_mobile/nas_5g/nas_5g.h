/*
 * nas_5g_msg.h
 *
 *  Created on: Dec 18, 2020
 *      Author: nhnghia
 */

#ifndef SRC_MMT_MOBILE_NAS_5G_NAS_5G_MSG_H_
#define SRC_MMT_MOBILE_NAS_5G_NAS_5G_MSG_H_
#include <stdbool.h>
#include "mmm/mmm_msg.h"
#include "smm/smm_msg.h"

#define NAS5G_MOBILITY_MANAGEMENT_MESSAGE 0x7E
#define NAS5G_SESSION_MANAGEMENT_MESSAGE  0x2E

typedef union{
	uint8_t protocol_discriminator;
	nas_5g_mmm_msg_header_t mmm;
	nas_5g_smm_msg_header_t smm;
}nas_5g_msg_t;

bool nas_5g_decode( nas_5g_msg_t *msg, const uint8_t *buffer, uint32_t length );

#endif /* SRC_MMT_MOBILE_NAS_5G_NAS_5G_MSG_H_ */

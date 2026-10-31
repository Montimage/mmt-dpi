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

/* security header types of a 5GMM message (TS 24.501 §9.3.1) */
#define NAS5G_SECURITY_HEADER_PLAIN                             0
#define NAS5G_SECURITY_HEADER_INTEGRITY_PROTECTED               1
#define NAS5G_SECURITY_HEADER_INTEGRITY_PROTECTED_NEW_CONTEXT   3
/* EPD, security header type, MAC (4 octets), sequence number */
#define NAS5G_SECURITY_PROTECTED_HEADER_LENGTH                  7

typedef union{
	uint8_t protocol_discriminator;
	nas_5g_mmm_msg_header_t mmm;
	nas_5g_smm_msg_header_t smm;
}nas_5g_msg_t;

bool nas_5g_decode( nas_5g_msg_t *msg, const uint8_t *buffer, uint32_t length );

/* Store in *message_type the message type of the NAS-5G PDU in buffer: the
 * 5GSM or plain 5GMM message type, the inner one for a 5GMM message that is
 * integrity protected but not ciphered (security header type 1 or 3), 0 for
 * a ciphered one. Returns false when the PDU (or the inner message) is too
 * short to carry it. */
bool nas_5g_message_type( const uint8_t *buffer, uint32_t length, uint8_t *message_type );

#endif /* SRC_MMT_MOBILE_NAS_5G_NAS_5G_MSG_H_ */

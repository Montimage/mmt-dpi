/*
 * ngap.h
 *
 *  Created on: Dec 14, 2020
 *      Author: nhnghia
 */

#ifndef SRC_MMT_MOBILE_NGAP_NGAP_H_
#define SRC_MMT_MOBILE_NGAP_NGAP_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "NGAP_NGAP-PDU.h"
#include "NGAP_InitiatingMessage.h"
#include "NGAP_SuccessfulOutcome.h"
#include "NGAP_UnsuccessfulOutcome.h"

typedef struct ngap_message{
	uint16_t procedure_code;
	NGAP_NGAP_PDU_PR pdu_present;
	struct{
		const uint8_t *data;
		size_t size;
	}nas_pdu; //pdu of NAS-5G
}ngap_message_t;

/**
 * Try decoding NGAP protocol
 * @param buffer
 * @param length
 * @return true if decode successfully, otherwise false
 */
bool try_decode_ngap( const uint8_t * buffer, const uint32_t length );

/**
 * Decode buffer to get attributes and store them into `message`
 * @param message
 * @param buffer
 * @param length
 * @return true if decode successfully, otherwise false
 */
bool decode_ngap( ngap_message_t *message, const uint8_t * buffer, const uint32_t length );
#endif /* SRC_MMT_MOBILE_NGAP_NGAP_H_ */

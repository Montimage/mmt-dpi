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
	uint16_t ran_ue_id;
	uint64_t amf_ue_id;
	struct{
		const uint8_t *data;
		size_t size;
	}nas_pdu; //pdu of NAS-5G
}ngap_message_t;

/**
 * Try decoding NGAP protocol
 * @param payload
 * @param length
 * @return true if decode successfully, otherwise false
 */
bool try_decode_ngap( const uint8_t * payload, const uint32_t length );

/**
 * Decode payload to get attributes and store them into `message`
 * @param message
 * @param payload
 * @param length
 * @return true if decode successfully, otherwise false
 */
bool decode_ngap( ngap_message_t *message, const uint8_t * payload, const uint32_t length );


/**
 * Decode NGAP stored in `payload`, then update some attributes' values of NGAP by the one in `message`,
 * then encode NGAP into buffer
 * @param buffer
 * @param buffer_size
 * @param message
 * @param payload
 * @param length
 * @return number of bytes being stored in `buffer`
 */
uint32_t encode_ngap( void *buffer, uint32_t buffer_size, const ngap_message_t *message, const uint8_t *payload, const uint32_t length);

/**
 * Store NAS-5G PDU into data
 * @param buffer
 * @param buffer_size: capacity of `buffer`
 * @param payload
 * @param length
 * @return number of bytes being stored in `buffer`
 */
uint32_t get_nas_pdu( void *buffer, uint32_t buffer_size, const uint8_t *payload, uint32_t length );
#endif /* SRC_MMT_MOBILE_NGAP_NGAP_H_ */

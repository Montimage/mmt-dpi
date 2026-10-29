/*
 * attach_request.c
 *
 *  Created on: Nov 7, 2018
 *          by: Huu-Nghia
 */



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "nas_emm_attach_request.h"
#include "../util/decoder.h"

int nas_emm_decode_attach_request(nas_emm_attach_request_t *msg, const uint8_t *buffer, uint32_t len){

	int decoded = 0;
	int ret = 0;
	int rc;

	rc = nas_check_pdu(buffer, 2, len);
	if (unlikely(rc < 0)) {
		NAS_LOG_PDU_CHECK(rc, 2, len);
		return rc;
	}

	DECODE_U8(buffer+decoded, msg->eps_attach_type, decoded );

	// F-BUG-215: capture negative decoder errors in signed and early-return before uint32 wrap
	ret = nas_decode_eps_mobile_identity(&msg->old_guti_or_imsi, 0, buffer+decoded, len-decoded);
	if (ret < 0)
		return ret;
	decoded += ret;


	return decoded;
}

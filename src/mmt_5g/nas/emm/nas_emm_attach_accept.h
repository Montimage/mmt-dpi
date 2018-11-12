/*
 * nas_emm_attach_accept.h
 *
 *  Created on: Nov 12, 2018
 *          by: Huu-Nghia
 */

#ifndef SRC_MMT_5G_NAS_EMM_NAS_EMM_ATTACH_ACCEPT_H_
#define SRC_MMT_5G_NAS_EMM_NAS_EMM_ATTACH_ACCEPT_H_

#include <stdlib.h>
#include <stdint.h>

#include "../nas_msg_header.h"
#include "../esp_mobile_identity.h"
#include "nas_emm_msg_type_t.h"

typedef struct {
	/* Mandatory fields */
	nas_msg_header_t    header;
	nas_emm_msg_type_t  message_type;
	uint8_t             eps_attach_type;
	uint8_t             tac;

	//FURTHER: Need to examine other fields
} nas_emm_attach_accept_msg_t;

int nas_decode_emm_attach_accept(nas_emm_attach_accept_msg_t *attach_accept, const uint8_t *buffer, uint32_t len);



#endif /* SRC_MMT_5G_NAS_EMM_NAS_EMM_ATTACH_ACCEPT_H_ */

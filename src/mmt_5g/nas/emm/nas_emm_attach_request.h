/*
 * attach_request.h
 *
 *  Created on: Nov 7, 2018
 *          by: Huu-Nghia
 */
#ifndef SRC_MMT_5G_NAS_EMM_ATTACH_REQUEST_H_
#define SRC_MMT_5G_NAS_EMM_ATTACH_REQUEST_H_

#include "../nas_msg_header.h"
#include "../esp_mobile_identity.h"
#include "nas_emm_msg_type_t.h"

#define EPS_ATTACH_TYPE_EPS   0b0001
#define EPS_ATTACH_TYPE_IMSI  0b0010
/*
 * Message name: Attach request
 * Description: This message is sent by the UE to the network in order to perform an attach procedure. See table 8.2.4.1.
 * Significance: dual
 * Direction: UE to network
 */

typedef struct {
	/* Mandatory fields */
	nas_msg_header_t    header;
	nas_emm_msg_type_t  message_type;
	uint8_t             eps_attach_type;
	EpsMobileIdentity   old_guti_or_imsi;

	//FURTHER: Need to examine other fields
} nas_emm_attach_request_msg_t;

int nas_decode_emm_attach_request(nas_emm_attach_request_msg_t *attachrequest, const uint8_t *buffer, uint32_t len);



#endif /* SRC_MMT_5G_NAS_EMM_ATTACH_REQUEST_H_ */

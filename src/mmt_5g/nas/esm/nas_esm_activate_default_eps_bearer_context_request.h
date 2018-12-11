/*
 * nas_esm_activate_default_eps_bearer_context_request.h
 *
 *  Created on: Dec 11, 2018
 *          by: Huu-Nghia
 */
#ifndef NAS_ESM_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_H_
#define NAS_ESM_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_H_

#include "../ies/pdn_address.h"
#include "../ies/eps_quality_of_service.h"
#include "../util/octet_string.h"
#include "nas_esm_msg_header.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_MINIMUM_LENGTH ( \
		EPS_QUALITY_OF_SERVICE_MINIMUM_LENGTH + \
		NAS_OCTET_STRING_MINIMUM_LENGTH + \
		PDN_ADDRESS_MINIMUM_LENGTH )

/* Maximum length macro. Formed by maximum length of each field */
#define ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_MAXIMUM_LENGTH ( \
		EPS_QUALITY_OF_SERVICE_MAXIMUM_LENGTH + \
		NAS_OCTET_STRING_MAXIMUM_LENGTH + \
		PDN_ADDRESS_MAXIMUM_LENGTH )

/*
 * Message name: Activate default EPS bearer context request
 * Description: This message is sent by the network to the UE to request activation of a default EPS bearer context.
 * See table 8.3.6.1.
 * Significance: dual
 * Direction: network to UE
 */

typedef struct {
	/* Mandatory fields */
	nas_esm_msg_header_t              header;
	nas_eps_quality_of_service_t      eps_qos;
	nas_octet_string_t                access_point_name;
	nas_pdn_address_t                 pdn_address;
	/* Optional fields */
} nas_esm_activate_default_eps_bearer_context_request_t;

int nas_esm_decode_activate_default_eps_bearer_context_request(nas_esm_activate_default_eps_bearer_context_request_t *msg, const uint8_t *buffer, uint32_t len);

#endif


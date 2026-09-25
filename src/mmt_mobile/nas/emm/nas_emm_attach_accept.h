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

#include "nas_emm_msg_header.h"
#include "../util/octet_string.h"
#include "../ies/tracking_area_identity_list.h"
#include "../ies/esp_mobile_identity.h"

#define NAS_EMM_ATTACH_ACCEPT_MIN_LEN 10
#define NAS_EMM_ATTACH_ACCEPT_MAX_LEN 100
typedef struct {
	/* Mandatory fields */
	nas_emm_msg_header_t               header;
	uint8_t                            eps_attach_result;
	uint8_t                            t3412value;
	nas_tracking_area_identity_list_t  tailist;
	nas_octet_string_t                 esm_message_container;
	/* Optional fields (TS 24.301 §8.2.1). Each one that was seen sets its
	 * NAS_EMM_ATTACH_ACCEPT_HAS_* bit in `present`; only the first
	 * occurrence of a repeated IE is kept (TS 24.301 §7.6.3); for the
	 * GUTI, the first well-formed one. Octet
	 * strings are views of the IE value inside the decoded buffer. */
	uint32_t                           present;
	nas_eps_mobile_identity_t          guti;
	nas_octet_string_t                 lai;                  /* 5-octet LAI value */
	nas_octet_string_t                 ms_identity;
	uint8_t                            emm_cause;
	uint8_t                            t3402value;
	uint8_t                            t3423value;
	uint8_t                            additional_update_result; /* low 4 bits */
	nas_octet_string_t                 equivalent_plmns;
	nas_octet_string_t                 emergency_number_list;
	nas_octet_string_t                 eps_network_feature_support;
	nas_octet_string_t                 t3412_extended_value;
	uint8_t                            unknown_ies;          /* skipped, not decoded (saturates at 255) */
} nas_emm_attach_accept_t;

#define NAS_EMM_ATTACH_ACCEPT_HAS_GUTI                        (1u << 0)
#define NAS_EMM_ATTACH_ACCEPT_HAS_LAI                         (1u << 1)
#define NAS_EMM_ATTACH_ACCEPT_HAS_MS_IDENTITY                 (1u << 2)
#define NAS_EMM_ATTACH_ACCEPT_HAS_EMM_CAUSE                   (1u << 3)
#define NAS_EMM_ATTACH_ACCEPT_HAS_T3402_VALUE                 (1u << 4)
#define NAS_EMM_ATTACH_ACCEPT_HAS_T3423_VALUE                 (1u << 5)
#define NAS_EMM_ATTACH_ACCEPT_HAS_EQUIVALENT_PLMNS            (1u << 6)
#define NAS_EMM_ATTACH_ACCEPT_HAS_EMERGENCY_NUMBER_LIST       (1u << 7)
#define NAS_EMM_ATTACH_ACCEPT_HAS_EPS_NETWORK_FEATURE_SUPPORT (1u << 8)
#define NAS_EMM_ATTACH_ACCEPT_HAS_ADDITIONAL_UPDATE_RESULT    (1u << 9)
#define NAS_EMM_ATTACH_ACCEPT_HAS_T3412_EXTENDED_VALUE        (1u << 10)
/* An optional IE overran the message: parsing stopped before it */
#define NAS_EMM_ATTACH_ACCEPT_TRUNCATED                       (1u << 31)

int nas_emm_decode_attach_accept(nas_emm_attach_accept_t *attach_accept, const uint8_t *buffer, uint32_t len);



#endif /* SRC_MMT_5G_NAS_EMM_NAS_EMM_ATTACH_ACCEPT_H_ */

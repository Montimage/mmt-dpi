/*
 * emm_msg.h
 *
 *  Created on: Nov 7, 2018
 *          by: Huu-Nghia
 */

#ifndef SRC_MMT_5G_NAS_EMM_EMM_MSG_H_
#define SRC_MMT_5G_NAS_EMM_EMM_MSG_H_

#include <stdlib.h>
#include <stdint.h>

#include "nas_emm_attach_request.h"
#include "nas_emm_attach_accept.h"

typedef union{
	nas_emm_msg_header_t         header;
	nas_emm_attach_request_t     attach_request;
	nas_emm_attach_accept_t      attach_accept;
}nas_emm_msg_t;


int nas_emm_decode_msg(nas_emm_msg_t *msg, const uint8_t *buffer, uint32_t len);

#endif /* SRC_MMT_5G_NAS_EMM_EMM_MSG_H_ */

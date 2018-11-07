/*
 * nas_msg.h
 *
 *  Created on: Nov 7, 2018
 *          by: Huu-Nghia
 */

#ifndef SRC_MMT_5G_NAS_NAS_MSG_H_
#define SRC_MMT_5G_NAS_NAS_MSG_H_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "msg_header.h"
#include "emm/emm_msg.h"

typedef union {
	msg_header_t header;
	emm_msg emm_msg;
} nas_msg_t;

int nas_msg_decode( nas_msg_t *msg, const uint8_t *buffer, int length, void *security);

#endif /* SRC_MMT_5G_NAS_NAS_MSG_H_ */

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


/* Message identifiers for EPS Mobility Management     */
# define ATTACH_REQUEST                0b01000001 /* 65 = 0x41 */
# define ATTACH_ACCEPT                 0b01000010 /* 66 = 0x42 */
# define ATTACH_COMPLETE               0b01000011 /* 67 = 0x43 */
# define ATTACH_REJECT                 0b01000100 /* 68 = 0x44 */
# define DETACH_REQUEST                0b01000101 /* 69 = 0x45 */
# define DETACH_ACCEPT                 0b01000110 /* 70 = 0x46 */
# define TRACKING_AREA_UPDATE_REQUEST  0b01001000 /* 72 = 0x48 */
# define TRACKING_AREA_UPDATE_ACCEPT   0b01001001 /* 73 = 0x49 */
# define TRACKING_AREA_UPDATE_COMPLETE 0b01001010 /* 74 = 0x4a */
# define TRACKING_AREA_UPDATE_REJECT   0b01001011 /* 75 = 0x4b */
# define EXTENDED_SERVICE_REQUEST      0b01001100 /* 76 = 0x4c */
# define SERVICE_REJECT                0b01001110 /* 78 = 0x4e */
# define GUTI_REALLOCATION_COMMAND     0b01010000 /* 80 = 0x50 */
# define GUTI_REALLOCATION_COMPLETE    0b01010001 /* 81 = 0x51 */
# define AUTHENTICATION_REQUEST        0b01010010 /* 82 = 0x52 */
# define AUTHENTICATION_RESPONSE       0b01010011 /* 83 = 0x53 */
# define AUTHENTICATION_REJECT         0b01010100 /* 84 = 0x54 */
# define AUTHENTICATION_FAILURE        0b01011100 /* 92 = 0x5c */
# define IDENTITY_REQUEST              0b01010101 /* 85 = 0x55 */
# define IDENTITY_RESPONSE             0b01010110 /* 86 = 0x56 */
# define SECURITY_MODE_COMMAND         0b01011101 /* 93 = 0x5d */
# define SECURITY_MODE_COMPLETE        0b01011110 /* 94 = 0x5e */
# define SECURITY_MODE_REJECT          0b01011111 /* 95 = 0x5f */
# define EMM_STATUS                    0b01100000 /* 96 = 0x60 */
# define EMM_INFORMATION               0b01100001 /* 97 = 0x61 */
# define DOWNLINK_NAS_TRANSPORT        0b01100010 /* 98 = 0x62 */
# define UPLINK_NAS_TRANSPORT          0b01100011 /* 99 = 0x63 */
# define CS_SERVICE_NOTIFICATION       0b01100100 /* 100 = 0x64 */

typedef uint8_t nas_emm_msg_type_t;


int nas_decode_emm_msg_type(nas_emm_msg_type_t *msg, const uint8_t *buffer, uint32_t len);

#endif /* SRC_MMT_5G_NAS_EMM_EMM_MSG_H_ */

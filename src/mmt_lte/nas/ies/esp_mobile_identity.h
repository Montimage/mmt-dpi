/*
 * esp_mobile_identity.h
 *
 *  Created on: Nov 7, 2018
 *          by: Huu-Nghia
 */

#ifndef SRC_MMT_5G_NAS_ESP_MOBILE_IDENTITY_H_
#define SRC_MMT_5G_NAS_ESP_MOBILE_IDENTITY_H_
#include <stdlib.h>
#include <stdint.h>

#define EPS_MOBILE_IDENTITY_MINIMUM_LENGTH  3
#define EPS_MOBILE_IDENTITY_MAXIMUM_LENGTH 13

typedef struct {
	uint8_t  spare:4;
#define EPS_MOBILE_IDENTITY_EVEN  0
#define EPS_MOBILE_IDENTITY_ODD   1
	uint8_t  oddeven:1;
	uint8_t  typeofidentity:3;
	uint8_t  mccdigit2:4;
	uint8_t  mccdigit1:4;
	uint8_t  mncdigit3:4;
	uint8_t  mccdigit3:4;
	uint8_t  mncdigit2:4;
	uint8_t  mncdigit1:4;
	uint16_t mmegroupid;
	uint8_t  mmecode;
	uint32_t mtmsi;
} nas_guti_eps_mobile_identity_t;

typedef struct {
	uint8_t  digit1:4;
	uint8_t  oddeven:1;
	uint8_t  typeofidentity:3;
	uint8_t  digit2:4;
	uint8_t  digit3:4;
	uint8_t  digit4:4;
	uint8_t  digit5:4;
	uint8_t  digit6:4;
	uint8_t  digit7:4;
	uint8_t  digit8:4;
	uint8_t  digit9:4;
	uint8_t  digit10:4;
	uint8_t  digit11:4;
	uint8_t  digit12:4;
	uint8_t  digit13:4;
	uint8_t  digit14:4;
	uint8_t  digit15:4;
} nas_imsi_eps_mobile_identity_t;

typedef nas_imsi_eps_mobile_identity_t nas_imei_eps_mobile_identity_t;

#define EPS_MOBILE_IDENTITY_IMSI  0b001
#define EPS_MOBILE_IDENTITY_GUTI  0b110
#define EPS_MOBILE_IDENTITY_IMEI  0b011

typedef union {
	nas_imsi_eps_mobile_identity_t imsi;
	nas_guti_eps_mobile_identity_t guti;
	nas_imei_eps_mobile_identity_t imei;
} nas_eps_mobile_identity_t;

int nas_decode_eps_mobile_identity(nas_eps_mobile_identity_t *epsmobileidentity, uint8_t iei, const uint8_t *buffer, uint32_t len);
#endif /* SRC_MMT_5G_NAS_ESP_MOBILE_IDENTITY_H_ */

#include "esp_mobile_identity.h"
#include "../util/decoder.h"



static int _decode_guti_eps_mobile_identity(guti_eps_mobile_identity_t *guti, const uint8_t *buffer)
{
	int decoded = 0;
	guti->spare = (*(buffer + decoded) >> 4) & 0xf;

	/*
	 * For the GUTI, bits 5 to 8 of octet 3 are coded as "1111"
	 */
	if (guti->spare != 0xf) {
		return (DECODE_VALUE_DOESNT_MATCH);
	}

	guti->oddeven = (*(buffer + decoded) >> 3) & 0x1;
	guti->typeofidentity = *(buffer + decoded) & 0x7;

	if (guti->typeofidentity != EPS_MOBILE_IDENTITY_GUTI) {
		return (DECODE_VALUE_DOESNT_MATCH);
	}

	decoded++;
	guti->mccdigit2 = (*(buffer + decoded) >> 4) & 0xf;
	guti->mccdigit1 = *(buffer + decoded) & 0xf;
	decoded++;
	guti->mncdigit3 = (*(buffer + decoded) >> 4) & 0xf;
	guti->mccdigit3 = *(buffer + decoded) & 0xf;
	decoded++;
	guti->mncdigit2 = (*(buffer + decoded) >> 4) & 0xf;
	guti->mncdigit1 = *(buffer + decoded) & 0xf;
	decoded++;
	//IES_DECODE_U16(guti->mmegroupid, *(buffer + decoded));
	IES_DECODE_U16(buffer, decoded, guti->mmegroupid);
	guti->mmecode = *(buffer + decoded);
	decoded++;
	//IES_DECODE_U32(guti->mtmsi, *(buffer + decoded));
	IES_DECODE_U32(buffer, decoded, guti->mtmsi);
	return decoded;
}

static int _decode_imsi_eps_mobile_identity(imsi_eps_mobile_identity_t *imsi, const uint8_t *buffer)
{
	int decoded = 0;
	imsi->typeofidentity = *(buffer + decoded) & 0x7;

	if (imsi->typeofidentity != EPS_MOBILE_IDENTITY_IMSI) {
		return (DECODE_VALUE_DOESNT_MATCH);
	}

	imsi->oddeven = (*(buffer + decoded) >> 3) & 0x1;
	imsi->digit1 = (*(buffer + decoded) >> 4) & 0xf;
	decoded++;
	imsi->digit2 = *(buffer + decoded) & 0xf;
	imsi->digit3 = (*(buffer + decoded) >> 4) & 0xf;
	decoded++;
	imsi->digit4 = *(buffer + decoded) & 0xf;
	imsi->digit5 = (*(buffer + decoded) >> 4) & 0xf;
	decoded++;
	imsi->digit6 = *(buffer + decoded) & 0xf;
	imsi->digit7 = (*(buffer + decoded) >> 4) & 0xf;
	decoded++;
	imsi->digit8 = *(buffer + decoded) & 0xf;
	imsi->digit9 = (*(buffer + decoded) >> 4) & 0xf;
	decoded++;
	imsi->digit10 = *(buffer + decoded) & 0xf;
	imsi->digit11 = (*(buffer + decoded) >> 4) & 0xf;
	decoded++;
	imsi->digit12 = *(buffer + decoded) & 0xf;
	imsi->digit13 = (*(buffer + decoded) >> 4) & 0xf;
	decoded++;
	imsi->digit14 = *(buffer + decoded) & 0xf;
	imsi->digit15 = (*(buffer + decoded) >> 4) & 0xf;

	/*
	 * IMSI is coded using BCD coding. If the number of identity digits is
	 * even then bits 5 to 8 of the last octet shall be filled with an end
	 * mark coded as "1111".
	 */
	if ((imsi->oddeven == EPS_MOBILE_IDENTITY_EVEN) && (imsi->digit15 != 0x0f)) {
		return (DECODE_VALUE_DOESNT_MATCH);
	}

	decoded++;
	return decoded;
}

static int _decode_imei_eps_mobile_identity(imei_eps_mobile_identity_t *imei, const uint8_t *buffer)
{
	int decoded = 0;
	imei->typeofidentity = *(buffer + decoded) & 0x7;

	if (imei->typeofidentity != EPS_MOBILE_IDENTITY_IMEI) {
		return (DECODE_VALUE_DOESNT_MATCH);
	}

	imei->oddeven = (*(buffer + decoded) >> 3) & 0x1;
	imei->digit1 = (*(buffer + decoded) >> 4) & 0xf;
	decoded++;
	imei->digit2 = *(buffer + decoded) & 0xf;
	imei->digit3 = (*(buffer + decoded) >> 4) & 0xf;
	decoded++;
	imei->digit4 = *(buffer + decoded) & 0xf;
	imei->digit5 = (*(buffer + decoded) >> 4) & 0xf;
	decoded++;
	imei->digit6 = *(buffer + decoded) & 0xf;
	imei->digit7 = (*(buffer + decoded) >> 4) & 0xf;
	decoded++;
	imei->digit8 = *(buffer + decoded) & 0xf;
	imei->digit9 = (*(buffer + decoded) >> 4) & 0xf;
	decoded++;
	imei->digit10 = *(buffer + decoded) & 0xf;
	imei->digit11 = (*(buffer + decoded) >> 4) & 0xf;
	decoded++;
	imei->digit12 = *(buffer + decoded) & 0xf;
	imei->digit13 = (*(buffer + decoded) >> 4) & 0xf;
	decoded++;
	imei->digit14 = *(buffer + decoded) & 0xf;
	imei->digit15 = (*(buffer + decoded) >> 4) & 0xf;
	decoded++;
	return decoded;
}


int nas_decode_eps_mobile_identity(eps_mobile_identity_t *ident, uint8_t iei, const uint8_t *buffer, uint32_t len)
{
	int decoded_rc = DECODE_VALUE_DOESNT_MATCH;
	int decoded = 0;
	uint8_t ielen = 0;

	if (iei > 0) {
		CHECK_IEI_DECODER(iei, *buffer);
		decoded++;
	}
	ielen = *(buffer + decoded);
	decoded++;
	CHECK_LENGTH_DECODER(len - decoded, ielen);

	uint8_t typeofidentity = *(buffer + decoded) & 0x7;

	switch( typeofidentity){
	case EPS_MOBILE_IDENTITY_IMSI:
		decoded_rc = _decode_imsi_eps_mobile_identity(&ident->imsi,
				buffer + decoded);
		break;
	case EPS_MOBILE_IDENTITY_GUTI:
		decoded_rc = _decode_guti_eps_mobile_identity(&ident->guti,
				buffer + decoded);
		break;
	case EPS_MOBILE_IDENTITY_IMEI:
		decoded_rc = _decode_imei_eps_mobile_identity(&ident->imei,
				buffer + decoded);
		break;
	}

	if (decoded_rc < 0)
		return decoded_rc;

	return (decoded + decoded_rc);
}

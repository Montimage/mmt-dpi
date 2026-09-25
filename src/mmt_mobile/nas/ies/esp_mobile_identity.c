#include "esp_mobile_identity.h"
#include "../util/decoder.h"



static int _decode_guti_eps_mobile_identity(nas_guti_eps_mobile_identity_t *guti, const uint8_t *buffer)
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

/*
 * IMSI (TS 24.301 §9.9.3.12, coded as TS 24.008 §10.5.1.4): octet 1 holds
 * digit 1, the odd/even indicator and the identity type; every further
 * octet holds two BCD digits, low nibble first. An IMSI has at most 15
 * digits (TS 23.003 §2.2), so the value is 1 + ceil((n - 1) / 2) octets:
 * 8 for 14..15 digits, 7 for 12..13, and so on. With an even digit count
 * the high nibble of the last octet is the "1111" filler.
 *
 * Issue #443: the value used to be read as exactly 8 octets, so IMSIs of
 * 13 digits or fewer (ielen <= 7) were rejected. Only ielen octets are
 * read now; every digit past the IMSI's end is set to 0xF, the same value
 * as the filler, so consumers find the end at the first 0xF digit.
 */
#define IMSI_MAX_OCTETS 8

static int _decode_imsi_eps_mobile_identity(nas_imsi_eps_mobile_identity_t *imsi,
		const uint8_t *buffer, uint8_t ielen)
{
	uint8_t digits[15];
	int ndigits, i, octets;

	imsi->typeofidentity = *buffer & 0x7;

	if (imsi->typeofidentity != EPS_MOBILE_IDENTITY_IMSI) {
		return (DECODE_VALUE_DOESNT_MATCH);
	}

	/* more than 15 digits is not an IMSI; reading only 8 of the ielen
	 * octets would also desync the caller's offset */
	if (ielen > IMSI_MAX_OCTETS)
		return (DECODE_VALUE_DOESNT_MATCH);
	octets = ielen;
	imsi->oddeven = (*buffer >> 3) & 0x1;

	memset(digits, 0x0f, sizeof(digits));
	digits[0] = (*buffer >> 4) & 0xf;
	for (i = 1; i < octets; i++) {
		digits[2 * i - 1] = buffer[i] & 0xf;
		digits[2 * i]     = (buffer[i] >> 4) & 0xf;
	}

	/*
	 * IMSI is coded using BCD coding. If the number of identity digits is
	 * even then bits 5 to 8 of the last octet shall be filled with an end
	 * mark coded as "1111".
	 */
	ndigits = 2 * octets - 1;
	if (imsi->oddeven == EPS_MOBILE_IDENTITY_EVEN) {
		if (digits[ndigits - 1] != 0x0f)
			return (DECODE_VALUE_DOESNT_MATCH);
		ndigits--;
	}
	/* no end mark inside the digit string */
	for (i = 0; i < ndigits; i++)
		if (digits[i] == 0x0f)
			return (DECODE_VALUE_DOESNT_MATCH);

	imsi->digit1  = digits[0];
	imsi->digit2  = digits[1];
	imsi->digit3  = digits[2];
	imsi->digit4  = digits[3];
	imsi->digit5  = digits[4];
	imsi->digit6  = digits[5];
	imsi->digit7  = digits[6];
	imsi->digit8  = digits[7];
	imsi->digit9  = digits[8];
	imsi->digit10 = digits[9];
	imsi->digit11 = digits[10];
	imsi->digit12 = digits[11];
	imsi->digit13 = digits[12];
	imsi->digit14 = digits[13];
	imsi->digit15 = digits[14];

	return octets;
}

static int _decode_imei_eps_mobile_identity(nas_imei_eps_mobile_identity_t *imei, const uint8_t *buffer)
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


int nas_decode_eps_mobile_identity(nas_eps_mobile_identity_t *ident, uint8_t iei, const uint8_t *buffer, uint32_t len)
{
	int decoded_rc = DECODE_VALUE_DOESNT_MATCH;
	int decoded = 0;
	uint8_t ielen = 0;

	/* F-BUG-083: validate pointer and length before the first read, and
	 * compute the remainder in a checked signed form (len - decoded must
	 * never wrap). */
	if (iei > 0) {
		CHECK_PDU_POINTER_AND_LENGTH_DECODER(buffer, 1, len);
		CHECK_IEI_DECODER(iei, *buffer);
		decoded++;
	}
	CHECK_PDU_POINTER_AND_LENGTH_DECODER(buffer, decoded + 1, len);
	ielen = *(buffer + decoded);
	decoded++;
	CHECK_LENGTH_DECODER((int32_t)len - decoded, ielen);

	// F-BUG-203: bound fixed-size decodes by remaining length
	if (ielen == 0) {
		errorCodeDecoder = DECODE_BUFFER_TOO_SHORT;
		return DECODE_BUFFER_TOO_SHORT;
	}
	CHECK_LENGTH_DECODER(ielen, 1);
	CHECK_LENGTH_DECODER((int32_t)len - decoded, 1);

	uint8_t typeofidentity = *(buffer + decoded) & 0x7;

	switch( typeofidentity){
	case EPS_MOBILE_IDENTITY_IMSI:
		// F-BUG-203: the IMSI decoder reads exactly ielen octets, which
		// CHECK_LENGTH_DECODER above bounded by the buffer, and rejects
		// more than 8 (identity octet + 7 BCD octets, 15 digits).
		// Issue #427: 15 digits are 8 octets, not 9. Issue #443: shorter
		// IMSIs are fewer octets (TS 24.301 §9.9.3.12) — at least 4, the
		// 6 digits of MCC + MNC.
		CHECK_LENGTH_DECODER(ielen, 4);
		decoded_rc = _decode_imsi_eps_mobile_identity(&ident->imsi,
				buffer + decoded, ielen);
		break;
	case EPS_MOBILE_IDENTITY_GUTI:
		// GUTI requires 11 bytes
		CHECK_LENGTH_DECODER(ielen, 11);
		CHECK_LENGTH_DECODER((int32_t)len - decoded, 11);
		decoded_rc = _decode_guti_eps_mobile_identity(&ident->guti,
				buffer + decoded);
		break;
	case EPS_MOBILE_IDENTITY_IMEI:
		// IMEI (15 digits) is read as 8 octets, like the IMSI (issue #427)
		CHECK_LENGTH_DECODER(ielen, 8);
		CHECK_LENGTH_DECODER((int32_t)len - decoded, 8);
		decoded_rc = _decode_imei_eps_mobile_identity(&ident->imei,
				buffer + decoded);
		break;
	}

	if (decoded_rc < 0)
		return decoded_rc;

	// Ensure we do not return more than ielen allows
	if ((uint32_t)decoded_rc > ielen) {
		errorCodeDecoder = DECODE_BUFFER_TOO_SHORT;
		return DECODE_BUFFER_TOO_SHORT;
	}

	return (decoded + decoded_rc);
}

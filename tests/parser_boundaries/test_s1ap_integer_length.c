/*
 * test_s1ap_integer_length.c — crafted-fixture test for issue #513:
 * the asn1c APER runtime under src/mmt_mobile/asn1c/common/ came from a
 * 2020 generator snapshot carrying two upstream advisories, fixed first by
 * recipe-applied patches and, since issue #522, by the pinned asn1c v1.5.3
 * runtime itself (the patches were dropped); this test pins both fixes.
 *
 *  - GHSA-x882-jvjm-xxh9: INTEGER_decode_aper() read the length determinant
 *    of a constrained INTEGER wider than 16 bits without bounding it by the
 *    octets the constraint permits. S1AP BitRate is INTEGER
 *    (0..10000000000): 34 bits, at most 5 octets, but its 3-bit determinant
 *    can declare 8. Eight octets led with 0xFF shifted a signed long by 56
 *    places (undefined behaviour: SANITIZE=asan aborts, the profile builds
 *    with -fno-sanitize-recover), and an over-long encoding of an in-range
 *    value was accepted, displacing every field after it. Both must now be
 *    rejected while every conformant length still decodes.
 *
 *  - GHSA-rcj5-gcvg-x796: OPEN_TYPE_aper_get() formed the inner value
 *    pointer before checking what the type selector returned. A selector
 *    result without a type descriptor, or with an alternative index past
 *    the open type's elements, must fail the decode instead of
 *    dereferencing NULL or reading past elements[].
 *
 * The PDU case goes through s1ap_decode() (the dissector's entry point) on
 * an InitialContextSetupRequest whose eNB-UE-S1AP-ID (24-bit range, at most
 * 3 octets, 2-bit determinant) declares 4 octets; the BitRate and NGAP
 * open-type cases call the asn1c runtime directly. The test links libmmt_tmobile.a whole-archive (same as
 * tests/s1ap_ngap_decode), because the shared library hides asn1c symbols.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "s1ap_common.h"
#include "S1ap-BitRate.h"
#include "NGAP_BitRate.h"
#include "NGAP_ProtocolIE-Field.h"
#include "OPEN_TYPE.h"

static int failures = 0;
static int checks   = 0;

#define CHECK(desc, cond) do { \
	checks++; \
	if (cond) { printf("  ok   %s\n", desc); } \
	else      { printf("  FAIL %s\n", desc); failures++; } \
} while (0)

/* ------------------------------------------------------------------ */
/* BitRate decoded on its own (aligned PER, complete encoding).        */
/* ------------------------------------------------------------------ */

/* Returns 1 when the encoding decodes to a value (stored in *value). */
static int decode_bitrate(const asn_TYPE_descriptor_t *td,
		const uint8_t *buf, size_t len, long *value) {
	INTEGER_t *st = NULL;
	asn_dec_rval_t rv = aper_decode_complete(NULL, td, (void **)&st, buf, len);
	int ok = rv.code == RC_OK && st != NULL
			&& asn_INTEGER2long(st, value) == 0;
	ASN_STRUCT_FREE(*td, st);
	return ok;
}

static void test_s1ap_bitrate(void) {
	/* determinant 0b000 (1 octet), value 5 */
	static const uint8_t ONE_OCTET[]  = { 0x00, 0x05 };
	/* determinant 0b100 (5 octets), the upper bound 10000000000 */
	static const uint8_t UPPER[]      = { 0x80, 0x02, 0x54, 0x0B, 0xE4, 0x00 };
	/* determinant 0b101 (6 octets): one more than the range permits */
	static const uint8_t SIX[]        = { 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };
	/* determinant 0b111 (8 octets), in-range value 5: the advisory's
	 * over-long encoding */
	static const uint8_t OVERLONG[]   = { 0xE0, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x05 };
	/* determinant 0b111 (8 octets) led with 0xFF: the signed shift by 56 */
	static const uint8_t OVERSHIFT[]  = { 0xE0, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF };
	long v = -1;

	printf("S1AP BitRate APER length determinant (GHSA-x882-jvjm-xxh9):\n");
	CHECK("1-octet BitRate 5 decodes",
			decode_bitrate(&asn_DEF_S1ap_BitRate, ONE_OCTET, sizeof(ONE_OCTET), &v)
			&& v == 5);
	v = -1;
	CHECK("5-octet BitRate 10000000000 (upper bound) decodes",
			decode_bitrate(&asn_DEF_S1ap_BitRate, UPPER, sizeof(UPPER), &v)
			&& v == 10000000000L);
	CHECK("6-octet determinant (range permits 5) rejected",
			!decode_bitrate(&asn_DEF_S1ap_BitRate, SIX, sizeof(SIX), &v));
	CHECK("8-octet over-long encoding of 5 rejected",
			!decode_bitrate(&asn_DEF_S1ap_BitRate, OVERLONG, sizeof(OVERLONG), &v));
	CHECK("8-octet 0xFF.. determinant rejected without a signed overshift",
			!decode_bitrate(&asn_DEF_S1ap_BitRate, OVERSHIFT, sizeof(OVERSHIFT), &v));
}

static void test_ngap_bitrate(void) {
	/* NGAP BitRate ::= INTEGER (0..4000000000000, ...): extension bit 0,
	 * 42-bit root range, at most 6 octets. Extension bit + determinant
	 * 0b101 (6 octets), value 5. */
	static const uint8_t SIX[]   = { 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };
	/* determinant 0b110 (7 octets) */
	static const uint8_t SEVEN[] = { 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };
	/* determinant 0b111 (8 octets) led with 0xFF */
	static const uint8_t EIGHT[] = { 0x70, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF };
	long v = -1;

	printf("NGAP BitRate APER length determinant (GHSA-x882-jvjm-xxh9):\n");
	CHECK("6-octet NGAP BitRate 5 decodes",
			decode_bitrate(&asn_DEF_NGAP_BitRate, SIX, sizeof(SIX), &v) && v == 5);
	CHECK("7-octet determinant (range permits 6) rejected",
			!decode_bitrate(&asn_DEF_NGAP_BitRate, SEVEN, sizeof(SEVEN), &v));
	CHECK("8-octet 0xFF.. determinant rejected",
			!decode_bitrate(&asn_DEF_NGAP_BitRate, EIGHT, sizeof(EIGHT), &v));
}

/* ------------------------------------------------------------------ */
/* A whole S1AP PDU through s1ap_decode().                             */
/* ------------------------------------------------------------------ */

/* The dissector decodes the UE id IEs of every handled message (the
 * BitRates above sit in IEs it skips). eNB-UE-S1AP-ID is INTEGER
 * (0..16777215): 24 bits, at most 3 octets, but its 2-bit determinant can
 * declare 4 — the same missing bound on a field s1ap_decode() reads. */

/* InitialContextSetupRequest (encoded with pycrate, the same vector as
 * tests/s1ap_ngap_decode VECTOR_ICS_REQUEST): MME-UE-S1AP-ID 7,
 * eNB-UE-S1AP-ID 1, UE-AMBR, one E-RAB (QCI 9, TEID 1),
 * UESecurityCapabilities, SecurityKey. */
static const uint8_t VECTOR_ICS_REQUEST[] = {
		0x00, 0x09, 0x00, 0x80, 0x85, 0x00, 0x00, 0x06, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x07, 0x00, 0x08, 0x00, 0x02, 0x00, 0x01,
		0x00, 0x42, 0x00, 0x0a, 0x18, 0x3b, 0x9a, 0xca, 0x00, 0x60,
		0x1d, 0xcd, 0x65, 0x00, 0x00, 0x18, 0x00, 0x37, 0x00, 0x00,
		0x34, 0x00, 0x32, 0x45, 0x00, 0x09, 0x04, 0x0f, 0x80, 0xc0,
		0xa8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x23, 0x17, 0x11,
		0x22, 0x33, 0x44, 0x01, 0x07, 0x42, 0x01, 0x21, 0x06, 0x00,
		0x00, 0xf1, 0x10, 0x00, 0x01, 0x00, 0x10, 0x52, 0x01, 0xc1,
		0x01, 0x09, 0x04, 0x03, 0x61, 0x70, 0x6e, 0x05, 0x01, 0x0a,
		0x2d, 0x00, 0x02, 0x00, 0x6b, 0x00, 0x05, 0x1c, 0x00, 0x0e,
		0x00, 0x00, 0x00, 0x49, 0x00, 0x20, 0x11, 0x11, 0x11, 0x11,
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
};
/* Layout of the vector: octets 3-4 = the 2-octet open-type length of the
 * IE container (0x80 | len >> 8, len & 0xFF), octet 17 = the
 * eNB-UE-S1AP-ID IE's 1-octet open-type length, octets 18-19 = its value
 * (determinant 0b00 = 1 octet, padding, 0x01). */
#define ICS_ENB_ID_LEN_AT    17
#define ICS_ENB_ID_VALUE_AT  18
#define ICS_ENB_ID_VALUE_LEN 2

/* Rebuild VECTOR_ICS_REQUEST with value as the eNB-UE-S1AP-ID value. */
static size_t build_ics_with_enb_id(uint8_t *out, size_t cap,
		const uint8_t *value, size_t value_len) {
	const size_t tail_at = ICS_ENB_ID_VALUE_AT + ICS_ENB_ID_VALUE_LEN;
	const size_t tail_len = sizeof(VECTOR_ICS_REQUEST) - tail_at;
	size_t n = ICS_ENB_ID_VALUE_AT + value_len + tail_len;
	size_t container_len = n - 5;

	if (n > cap || value_len > 127 || container_len >= 16384)
		return 0;
	memcpy(out, VECTOR_ICS_REQUEST, ICS_ENB_ID_VALUE_AT);
	memcpy(out + ICS_ENB_ID_VALUE_AT, value, value_len);
	memcpy(out + ICS_ENB_ID_VALUE_AT + value_len,
			VECTOR_ICS_REQUEST + tail_at, tail_len);
	out[3] = (uint8_t)(0x80 | (container_len >> 8));
	out[4] = (uint8_t)(container_len & 0xFF);
	out[ICS_ENB_ID_LEN_AT] = (uint8_t)value_len;
	return n;
}

static int decode_ics(const uint8_t *value, size_t value_len,
		s1ap_message_t *msg) {
	uint8_t pdu[256];
	size_t n = build_ics_with_enb_id(pdu, sizeof(pdu), value, value_len);

	memset(msg, 0, sizeof(*msg));
	if (n == 0)
		return -100;
	return s1ap_decode(msg, pdu, (uint32_t)n);
}

static void test_s1ap_pdu(void) {
	/* determinant 0b00 (1 octet), id 1: the vector as encoded */
	static const uint8_t ENB_ID_ONE[]   = { 0x00, 0x01 };
	/* determinant 0b10 (3 octets), the upper bound 16777215 */
	static const uint8_t ENB_ID_UPPER[] = { 0x80, 0xff, 0xff, 0xff };
	/* determinant 0b11 (4 octets) for the in-range id 1 */
	static const uint8_t ENB_ID_OVER[]  = { 0xc0, 0x00, 0x00, 0x00, 0x01 };
	s1ap_message_t msg;
	int ret;

	printf("S1AP InitialContextSetupRequest eNB-UE-S1AP-ID (GHSA-x882-jvjm-xxh9):\n");
	ret = decode_ics(ENB_ID_ONE, sizeof(ENB_ID_ONE), &msg);
	CHECK("ICS request with a 1-octet eNB-UE-S1AP-ID decodes, id 1",
			ret == 0 && msg.enb_ue_id == 1 && msg.mme_ue_id == 7);
	ret = decode_ics(ENB_ID_UPPER, sizeof(ENB_ID_UPPER), &msg);
	CHECK("ICS request with a 3-octet eNB-UE-S1AP-ID 16777215 decodes",
			ret == 0 && msg.enb_ue_id == 16777215);
	ret = decode_ics(ENB_ID_OVER, sizeof(ENB_ID_OVER), &msg);
	printf("       (over-long: s1ap_decode() = %d, enb_ue_id = %u)\n",
			ret, (unsigned)msg.enb_ue_id);
	CHECK("ICS request with a 4-octet eNB-UE-S1AP-ID rejected",
			ret != 0 && msg.enb_ue_id == 0);
}

/* ------------------------------------------------------------------ */
/* OPEN_TYPE_aper_get() with a selector result it cannot use.          */
/* ------------------------------------------------------------------ */

static asn_type_selector_result_t select_no_type(
		const asn_TYPE_descriptor_t *td, const void *sptr) {
	asn_type_selector_result_t r = { NULL, 1 };
	(void)td; (void)sptr;
	return r;
}

static asn_type_selector_result_t select_past_elements(
		const asn_TYPE_descriptor_t *td, const void *sptr) {
	/* A real type, but an alternative index one past the open type's
	 * alternatives (the value member's CHOICE). */
	asn_type_selector_result_t r = { &asn_DEF_NGAP_Cause,
			asn_DEF_NGAP_UEContextReleaseCommand_IEs.elements[2].type->elements_count + 1 };
	(void)td; (void)sptr;
	return r;
}

static int open_type_get(asn_type_selector_f *selector) {
	/* A 1-octet open type holding 0x00 */
	static const uint8_t WIRE[] = { 0x01, 0x00 };
	asn_TYPE_member_t elm = asn_DEF_NGAP_UEContextReleaseCommand_IEs.elements[2];
	NGAP_UEContextReleaseCommand_IEs_t *ie = calloc(1, sizeof(*ie));
	asn_per_data_t pd;
	asn_dec_rval_t rv;

	if (ie == NULL)
		return -1;
	memset(&pd, 0, sizeof(pd));
	pd.buffer = WIRE;
	pd.nbits = 8 * sizeof(WIRE);
	elm.type_selector = selector;
	rv = OPEN_TYPE_aper_get(NULL, &asn_DEF_NGAP_UEContextReleaseCommand_IEs,
			ie, &elm, &pd);
	free(ie);
	return rv.code;
}

static void test_open_type_selector(void) {
	printf("NGAP OPEN_TYPE_aper_get selector result (GHSA-rcj5-gcvg-x796):\n");
	CHECK("selector without a type descriptor fails the decode",
			open_type_get(select_no_type) == RC_FAIL);
	CHECK("selector index past the open type's alternatives fails the decode",
			open_type_get(select_past_elements) == RC_FAIL);
}

int main(void) {
	/* unbuffered: a crash on unfixed code still shows the checks before it */
	setvbuf(stdout, NULL, _IONBF, 0);
	test_s1ap_bitrate();
	test_ngap_bitrate();
	test_s1ap_pdu();
	test_open_type_selector();

	printf("\n%d/%d checks passed\n", checks - failures, checks);
	return failures == 0 ? 0 : 1;
}

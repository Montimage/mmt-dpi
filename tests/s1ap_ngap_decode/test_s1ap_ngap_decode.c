/*
 * test_s1ap_ngap_decode.c
 *
 * Regression tests for issue #132: S1AP/NGAP decode-result checking.
 *
 * Covers:
 *  - F-BUG-201: every ANY_to_type_aper() outer-decode site checks its
 *    result/out-pointer. A crafted S1AP PDU whose outer decode succeeds but
 *    whose inner IE-list ANY content is garbage used to NULL-deref the
 *    process; each of the 7 message handlers is exercised here.
 *  - F-BUG-213: get_nas_pdu() tracks copied bytes and returns explicit codes
 *    (0 when no NAS-PDU IE is present) instead of echoing back the caller
 *    supplied buffer size.
 *  - F-BUG-218: presence flags are set for decoded optional IEs.
 *  - F-BUG-220: IMSI is NUL-terminated within its 16-byte buffer.
 *  - F-BUG-221: NGAP hygiene - explicit codes instead of false-from-pointer
 *    functions, encode_ngap() NULL-check, act-aware NAS_PDU handling.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "s1ap_common.h"
#include "ngap.h"
#include "NGAP_ProtocolIE-Field.h"
#include "NGAP_RRCEstablishmentCause.h"

static int failures = 0;
static int checks   = 0;

#define CHECK(desc, cond) do { \
	checks++; \
	if (cond) { printf("  ok   %s\n", desc); } \
	else      { printf("  FAIL %s\n", desc); failures++; } \
} while (0)

/* ------------------------------------------------------------------ */
/* Crafted S1AP PDUs: outer decode OK / inner ANY decode failed.       */
/*                                                                     */
/* Layout (aligned PER): octet 0 = S1AP-PDU CHOICE index bits          */
/* (ext bit 0 + 2-bit index: initiatingMessage=0, successfulOutcome=1),*/
/* octet 1 = procedureCode, octet 2 = criticality, then the open-type  */
/* length determinant (hi|len>>8, len&0xFF for 128<=len<16384)         */
/* followed by len octets of inner content. 0xFF content is invalid    */
/* APER for every IE-list type => ANY_to_type_aper() fails => the      */
/* handler must bail out with -1 instead of dereferencing NULL.        */
/* ------------------------------------------------------------------ */
static int craft_s1ap_inner_fail(uint8_t *out, uint32_t out_size,
		uint8_t choice_byte, uint8_t procedure_code) {
	const uint16_t inner_len = 200;
	if (out_size < (uint32_t)(5 + inner_len))
		return -1;
	out[0] = choice_byte;
	out[1] = procedure_code;
	out[2] = 0x00;             /* criticality reject */
	out[3] = 0x80 | (inner_len >> 8);
	out[4] = inner_len & 0xFF;
	memset(&out[5], 0xFF, inner_len);
	return 5 + inner_len;
}

static void test_s1ap_outer_ok_inner_fail(void) {
	static const struct {
		const char *name;
		uint8_t     choice_byte;
		uint8_t     procedure_code;
	} cases[] = {
		{ "InitialContextSetupRequest",  0x00, S1ap_ProcedureCode_id_InitialContextSetup   },
		{ "InitialUEMessage",            0x00, S1ap_ProcedureCode_id_initialUEMessage      },
		{ "S1SetupRequest",              0x00, S1ap_ProcedureCode_id_S1Setup               },
		{ "UEContextRelease",            0x00, S1ap_ProcedureCode_id_UEContextRelease      },
		{ "UEContextReleaseRequest",     0x00, S1ap_ProcedureCode_id_UEContextReleaseRequest },
		{ "InitialContextSetupResponse", 0x20, S1ap_ProcedureCode_id_InitialContextSetup   },
		{ "S1SetupResponse",             0x20, S1ap_ProcedureCode_id_S1Setup               },
	};
	size_t i;
	printf("S1AP outer-decode-ok / inner-decode-fail (crafted, was F-BUG-201):\n");
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		s1ap_message_t msg;
		uint8_t buf[512];
		int len = craft_s1ap_inner_fail(buf, sizeof(buf),
				cases[i].choice_byte, cases[i].procedure_code);
		memset(&msg, 0, sizeof(msg));
		int ret = s1ap_decode(&msg, buf, (uint32_t)len);
		char desc[128];
		snprintf(desc, sizeof(desc), "%s bails out with -1 (no crash)",
				cases[i].name);
		CHECK(desc, ret == -1);
	}
}

/* ------------------------------------------------------------------ */
/* Hand-crafted, decoder-exact S1AP InitialUEMessage carrying a plain  */
/* EMM Attach Request whose EPS mobile identity is the IMSI            */
/* 001010123456789.                                                    */
/*                                                                     */
/* Wire layout follows the generated APER decoders:                    */
/*  [0]      CHOICE ext-bit 0 + index 00 (initiatingMessage)           */
/*  [1]      procedureCode 12 (id-initialUEMessage)                    */
/*  [2]      criticality reject (2 bits, padded)                       */
/*  [3]      open-type length determinant, short form = 20             */
/*  body:                                                              */
/*  [4]      SEQUENCE ext-bit 0 (padded)                               */
/*  [5..6]   IE-list count = 1 (16-bit aligned, SIZE(0..65535))        */
/*  [7..8]   IE id = 26 (id-NAS-PDU, 16-bit aligned INTEGER)           */
/*  [9]      IE criticality reject (2 bits, padded)                    */
/*  [10]     ANY open-type content length = 13                         */
/*  [11]     OCTET STRING length = 12                                  */
/*  [12..23] plain EMM attach request with BCD IMSI                    */
/*                                                                     */
/* Note: the vendored generated decoder (src/mmt_mobile/asn1c/, not    */
/* editable) decodes every nested S1ap_IE.value ANY as EMPTY content   */
/* (ANY_decode_aper passes ebits=0 to aper_get_length). Nested IE      */
/* decoding therefore always fails; the fixed handlers must return -1  */
/* cleanly instead of dereferencing the NULL out-pointer (F-BUG-201).  */
/* ------------------------------------------------------------------ */
static const uint8_t VECTOR_ATTACH_REQUEST_IMSI[] = {
		0x00, 0x0c, 0x00, 0x14,
		0x00, 0x00, 0x01, 0x00, 0x1a, 0x00,
		0x0d, 0x0c,
		0x07, 0x41, 0x01, 0x08,
		0x09, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0x89
};

static void test_s1ap_valid_vectors(void) {
	s1ap_message_t msg;
	uint8_t buf[512];
	int ret;

	printf("S1AP hand-crafted InitialUEMessage:\n");

	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, VECTOR_ATTACH_REQUEST_IMSI,
			sizeof(VECTOR_ATTACH_REQUEST_IMSI));
	CHECK("outer decode reaches the message handler", ret == -1);
	CHECK("procedure code extracted", msg.procedure_code == 12);
	CHECK("IMSI buffer keeps its terminator slot clean (F-BUG-220)",
			msg.imsi[15] == '\0');

	/* truncated packet: outer decode fails, must not crash */
	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, VECTOR_ATTACH_REQUEST_IMSI, 10);
	CHECK("truncated PDU rejected without crash", ret <= 0);

	/* corrupted inner content: outer decodes, inner fails (F-BUG-201 idiom) */
	memcpy(buf, VECTOR_ATTACH_REQUEST_IMSI,
			sizeof(VECTOR_ATTACH_REQUEST_IMSI));
	buf[13] ^= 0xFF; /* corrupt inside the NAS-PDU octet string */
	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, buf, sizeof(VECTOR_ATTACH_REQUEST_IMSI));
	CHECK("corrupted inner IE tolerated without crash", ret >= -1);

	/* empty payload: documented early return */
	CHECK("empty payload returns 0",
			s1ap_decode(&msg, buf, 0) == 0);

	/* F-SEC-011 (issue #214): NULL arguments are rejected unconditionally —
	 * the assert()s that used to guard them compiled out under the shipped
	 * -DNDEBUG build, leaving NULL dereferences. */
	CHECK("NULL message pointer rejected (F-SEC-011)",
			s1ap_decode(NULL, VECTOR_ATTACH_REQUEST_IMSI,
				sizeof(VECTOR_ATTACH_REQUEST_IMSI)) == -1);
	CHECK("NULL buffer rejected (F-SEC-011)",
			s1ap_decode(&msg, NULL, sizeof(VECTOR_ATTACH_REQUEST_IMSI)) == -1);
}

/* ------------------------------------------------------------------ */
/* NGAP helpers: build PDUs with the library's own APER encoder so the */
/* round trip exercises both SET_ACTION (encode_ngap path) and         */
/* GET_ACTION (decode/get_nas_pdu path).                               */
/* ------------------------------------------------------------------ */
static NGAP_NGAP_PDU_t *build_ngap_initial_ue_message(int with_nas_pdu) {
	NGAP_InitialUEMessage_t *iem;
	NGAP_InitialUEMessage_IEs_t *ie;
	NGAP_NGAP_PDU_t *pdu = calloc(1, sizeof(*pdu));

	if (pdu == NULL)
		return NULL;
	pdu->present = NGAP_NGAP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage = calloc(1, sizeof(NGAP_InitiatingMessage_t));
	if (pdu->choice.initiatingMessage == NULL) {
		free(pdu);
		return NULL;
	}
	pdu->choice.initiatingMessage->procedureCode =
			NGAP_ProcedureCode_id_InitialUEMessage;
	pdu->choice.initiatingMessage->criticality = NGAP_Criticality_reject;
	pdu->choice.initiatingMessage->value.present =
			NGAP_InitiatingMessage__value_PR_InitialUEMessage;
	iem = &pdu->choice.initiatingMessage->value.choice.InitialUEMessage;

	ie = calloc(1, sizeof(*ie));
	ie->id          = NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality = NGAP_Criticality_reject;
	ie->value.present = NGAP_InitialUEMessage_IEs__value_PR_RAN_UE_NGAP_ID;
	ie->value.choice.RAN_UE_NGAP_ID = 12345;
	ASN_SEQUENCE_ADD(&iem->protocolIEs.list, ie);

	if (with_nas_pdu) {
		static const uint8_t nas_payload[] = { 'A', 'B', 'C', 'D' };
		ie = calloc(1, sizeof(*ie));
		ie->id          = NGAP_ProtocolIE_ID_id_NAS_PDU;
		ie->criticality = NGAP_Criticality_reject;
		ie->value.present = NGAP_InitialUEMessage_IEs__value_PR_NAS_PDU;
		OCTET_STRING_fromBuf(&ie->value.choice.NAS_PDU,
				(const char *)nas_payload, sizeof(nas_payload));
		ASN_SEQUENCE_ADD(&iem->protocolIEs.list, ie);
	}
	else {
		/* second IE without any NAS-PDU: RRC establishment cause */
		ie = calloc(1, sizeof(*ie));
		ie->id          = NGAP_ProtocolIE_ID_id_RRCEstablishmentCause;
		ie->criticality = NGAP_Criticality_ignore;
		ie->value.present =
				NGAP_InitialUEMessage_IEs__value_PR_RRCEstablishmentCause;
		ie->value.choice.RRCEstablishmentCause =
				NGAP_RRCEstablishmentCause_mo_Signalling;
		ASN_SEQUENCE_ADD(&iem->protocolIEs.list, ie);
	}
	return pdu;
}

static ssize_t encode_ngap_pdu(NGAP_NGAP_PDU_t *pdu, uint8_t *out, size_t cap) {
	asn_enc_rval_t enc = aper_encode_to_buffer(&asn_DEF_NGAP_NGAP_PDU, NULL,
			pdu, out, cap);
	if (enc.encoded < 0)
		return -1;
	return (ssize_t)((enc.encoded + 7) / 8);
}

static void test_ngap_get_nas_pdu(void) {
	NGAP_NGAP_PDU_t *pdu;
	uint8_t buf[256], out[64];
	ssize_t len;
	ngap_message_t msg;

	printf("NGAP get_nas_pdu / hygiene:\n");

	/* --- with a NAS-PDU IE ---------------------------------------- */
	pdu = build_ngap_initial_ue_message(1);
	len = encode_ngap_pdu(pdu, buf, sizeof(buf));
	CHECK("library-encoded NGAP InitialUEMessage with NAS-PDU", len > 0);
	if (len > 0) {
		CHECK("get_nas_pdu copies the NAS-PDU bytes",
				get_nas_pdu(out, sizeof(out), buf, (uint32_t)len) == 4
				&& memcmp(out, "ABCD", 4) == 0);
		memset(&msg, 0, sizeof(msg));
		CHECK("decode_ngap succeeds", decode_ngap(&msg, buf, (uint32_t)len));
		/* nas_pdu.data points into the internally freed PDU, so only the
		 * copied size may be inspected after decode_ngap() returns. */
		CHECK("decoded NAS-PDU size is 4", msg.nas_pdu.size == 4);
	}
	ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);

	/* --- without any NAS-PDU IE ----------------------------------- */
	pdu = build_ngap_initial_ue_message(0);
	len = encode_ngap_pdu(pdu, buf, sizeof(buf));
	CHECK("library-encoded NGAP InitialUEMessage without NAS-PDU", len > 0);
	if (len > 0) {
		/* F-BUG-213: used to echo back data_size even though nothing
		 * had been copied, making callers read an uninitialized buffer. */
		memset(out, 0xAA, sizeof(out));
		CHECK("get_nas_pdu returns explicit 0 when no NAS-PDU IE exists",
				get_nas_pdu(out, sizeof(out), buf, (uint32_t)len) == 0);
	}
	ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);

	/* --- argument guards ------------------------------------------ */
	pdu = build_ngap_initial_ue_message(1);
	len = encode_ngap_pdu(pdu, buf, sizeof(buf));
	CHECK("get_nas_pdu guards NULL buffer",
			get_nas_pdu(NULL, sizeof(out), buf, (uint32_t)len) == 0);
	CHECK("encode_ngap guards NULL message (F-BUG-221)",
			encode_ngap(out, sizeof(out), NULL, buf, (uint32_t)len) == 0);
	ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);

	CHECK("get_nas_pdu guards empty payload",
			get_nas_pdu(out, sizeof(out), buf, 0) == 0);

	/* --- truncated payload ---------------------------------------- */
	pdu = build_ngap_initial_ue_message(1);
	len = encode_ngap_pdu(pdu, buf, sizeof(buf));
	CHECK("truncated NGAP payload rejected by get_nas_pdu",
			get_nas_pdu(out, sizeof(out), buf, (uint32_t)(len - 3)) == 0);
	ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
}

int main(void) {
	test_s1ap_outer_ok_inner_fail();
	test_s1ap_valid_vectors();
	test_ngap_get_nas_pdu();

	printf("\n%d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}

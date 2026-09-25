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
 *  - Issue #443: spec-valid S1Setup, InitialContextSetup, UEContextRelease
 *    vectors, unknown later-release IEs skipped, open types >= 16K.
 *  - F-BUG-221: NGAP hygiene - explicit codes instead of false-from-pointer
 *    functions, encode_ngap() NULL-check, act-aware NAS_PDU handling.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "s1ap_common.h"
#include "mobile/proto_s1ap.h"
#include "ngap.h"
#include "NGAP_ProtocolIE-Field.h"
#include "NGAP_RRCEstablishmentCause.h"
#include "S1ap-E-RABToBeSetupItemCtxtSUReq.h"

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
/* editable) decoded every S1ap open-type ANY as EMPTY content         */
/* (ANY_decode_aper passes ebits=0 to aper_get_length), so nested IE   */
/* decoding always failed. Issue #427 installs a corrected ANY APER    */
/* decoder from s1ap_common.c; this vector now decodes end to end.     */
/* ------------------------------------------------------------------ */
static const uint8_t VECTOR_ATTACH_REQUEST_IMSI[] = {
		0x00, 0x0c, 0x00, 0x14,
		0x00, 0x00, 0x01, 0x00, 0x1a, 0x00,
		0x0d, 0x0c,
		0x07, 0x41, 0x01, 0x08,
		0x09, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0x89
};

/* ------------------------------------------------------------------ */
/* Issue #427: the S1AP payload of                                     */
/* tools/phase0/ci/accuracy/acc_s1ap_positive.pcap — a TS 36.413       */
/* InitialUEMessage with all mandatory IEs (eNB-UE-S1AP-ID 1, NAS-PDU  */
/* EMM Attach Request with IMSI 001010123456789, TAI, EUTRAN-CGI,      */
/* RRC-Establishment-Cause), cross-checked against pycrate. It used to */
/* fail with "Decoding of S1ap_InitialUEMessage failed".               */
/* ------------------------------------------------------------------ */
static const uint8_t VECTOR_CORPUS_INITIAL_UE_MESSAGE[] = {
		0x00, 0x0c, 0x40, 0x3e, 0x00, 0x00, 0x05, 0x00, 0x08, 0x00,
		0x02, 0x00, 0x01, 0x00, 0x1a, 0x00, 0x16, 0x15, 0x07, 0x41,
		0x71, 0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98,
		0x02, 0xe0, 0xe0, 0x00, 0x04, 0x02, 0x01, 0xd0, 0x11, 0x00,
		0x43, 0x00, 0x06, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x01, 0x00,
		0x64, 0x40, 0x08, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x86, 0x40, 0x01, 0x30
};

static void test_s1ap_corpus_initial_ue_message(void) {
	s1ap_message_t msg;
	int ret;

	printf("S1AP accuracy-corpus InitialUEMessage (issue #427):\n");
	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, VECTOR_CORPUS_INITIAL_UE_MESSAGE,
			sizeof(VECTOR_CORPUS_INITIAL_UE_MESSAGE));
	CHECK("spec-valid InitialUEMessage decodes", ret == 0);
	CHECK("initiatingMessage present", msg.pdu_present == S1AP_PDU_PR_initiatingMessage);
	CHECK("procedure code 12", msg.procedure_code == 12);
	CHECK("eNB-UE-S1AP-ID 1", msg.enb_ue_id == 1);
	CHECK("IMSI 001010123456789",
			msg.has_imsi && strcmp(msg.imsi, "001010123456789") == 0);

	/* an open-type length running past the buffer must still fail cleanly:
	 * cut the PDU inside the NAS-PDU IE value */
	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, VECTOR_CORPUS_INITIAL_UE_MESSAGE, 24);
	CHECK("truncated inside an IE value rejected", ret < 0);
}

static void test_s1ap_valid_vectors(void) {
	s1ap_message_t msg;
	uint8_t buf[512];
	int ret;

	printf("S1AP hand-crafted InitialUEMessage:\n");

	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, VECTOR_ATTACH_REQUEST_IMSI,
			sizeof(VECTOR_ATTACH_REQUEST_IMSI));
	CHECK("InitialUEMessage IEs decode (#427)", ret == 0);
	CHECK("procedure code extracted", msg.procedure_code == 12);
	CHECK("IMSI extracted from the NAS-PDU IE (#427)",
			msg.has_imsi && strcmp(msg.imsi, "001012345678998") == 0);
	CHECK("IMSI buffer keeps its terminator slot clean (F-BUG-220)",
			msg.imsi[15] == '\0');

	/* even digit count: the last octet carries the 0xF filler, so the
	 * IMSI is 14 digits with no trailing '?' (issue #427 review) */
	memcpy(buf, VECTOR_ATTACH_REQUEST_IMSI,
			sizeof(VECTOR_ATTACH_REQUEST_IMSI));
	buf[16] = 0x01; /* digit1 0, even, type IMSI */
	buf[23] = 0xF9; /* digit14 9, filler */
	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, buf, sizeof(VECTOR_ATTACH_REQUEST_IMSI));
	CHECK("even-length IMSI has 14 digits",
			ret == 0 && strcmp(msg.imsi, "00101234567899") == 0);

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
/* Issue #427 review: UE IPv4 from the ESM message container of an     */
/* InitialContextSetupRequest. For an ESM PDU the upper nibble of      */
/* octet 1 is the EPS bearer identity (5..15 for a default bearer),    */
/* not a security header type, so a "plain message" guard on the       */
/* decoded container rejected every spec-valid bearer request.         */
/*                                                                     */
/* The E-RABToBeSetupItemCtxtSUReq leaf (no open types) is encoded     */
/* with the library's APER encoder; the ProtocolIE / S1AP-PDU open-type*/
/* wrappers are assembled by hand (octet-aligned length determinant,   */
/* X.691 §11.2), as in the InitialUEMessage vectors above.             */
/* ------------------------------------------------------------------ */
static const uint8_t UE_IPV4[4] = { 10, 45, 0, 2 };

/* integrity-protected EMM Attach Accept whose ESM message container is
 * an Activate Default EPS Bearer Context Request for EBI 5, PDN IPv4 */
static const uint8_t NAS_ATTACH_ACCEPT_EBI5[] = {
		0x17, 0x11, 0x22, 0x33, 0x44, 0x01, /* sec hdr 1, MAC, SQN     */
		0x07, 0x42,                         /* EMM, Attach Accept      */
		0x01,                               /* EPS attach result       */
		0x21,                               /* T3412                   */
		0x06, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x01, /* TAI list LV       */
		0x00, 0x10,                         /* ESM container length 16 */
		0x52, 0x01, 0xc1,                   /* EBI 5 + ESM PD, PTI, ADEBCR */
		0x01, 0x09,                         /* EPS QoS: QCI 9          */
		0x04, 0x03, 'a', 'p', 'n',          /* APN                     */
		0x05, 0x01, 10, 45, 0, 2            /* PDN address: IPv4       */
};

/* Unconstrained, octet-aligned length determinant + content (X.691
 * §11.9.3.6-8). From 16K octets on the content is split into fragments of
 * m * 16K octets (m = 1..4, header 0xC0 | m); the remainder, possibly 0,
 * then gets an ordinary determinant (issue #443: the split-length path). */
static size_t put_open_type(uint8_t *out, const uint8_t *content, size_t len) {
	size_t n = 0;
	while (len >= 16384) {
		size_t m = len / 16384 > 4 ? 4 : len / 16384;
		out[n++] = 0xC0 | (uint8_t)m;
		memcpy(out + n, content, m * 16384);
		n += m * 16384;
		content += m * 16384;
		len -= m * 16384;
	}
	if (len < 128)
		out[n++] = (uint8_t)len;
	else {
		out[n++] = 0x80 | (uint8_t)(len >> 8);
		out[n++] = (uint8_t)(len & 0xFF);
	}
	memcpy(out + n, content, len);
	return n + len;
}

/* ProtocolIE-Field: id (16-bit aligned), criticality reject, open value */
static size_t put_ie(uint8_t *out, uint16_t id, const uint8_t *content, size_t len) {
	out[0] = (uint8_t)(id >> 8);
	out[1] = (uint8_t)(id & 0xFF);
	out[2] = 0x00;
	return 3 + put_open_type(out + 3, content, len);
}

static ssize_t build_s1ap_ics_request(uint8_t *out, size_t cap) {
	S1ap_E_RABToBeSetupItemCtxtSUReq_t *item = calloc(1, sizeof(*item));
	static const uint8_t teid[4] = { 0x00, 0x00, 0x00, 0x01 };
	static const uint8_t gw[4]   = { 192, 168, 0, 1 };
	uint8_t item_enc[256], tmp[512], tmp2[512];
	asn_enc_rval_t enc;
	size_t item_len, n, m;

	if (item == NULL || cap < 512)
		return -1;
	item->e_RAB_ID = 5;
	item->e_RABlevelQoSParameters.qCI = 9;
	item->e_RABlevelQoSParameters.allocationRetentionPriority.priorityLevel = 1;
	item->transportLayerAddress.buf = malloc(sizeof(gw));
	if (item->transportLayerAddress.buf)
		memcpy(item->transportLayerAddress.buf, gw, sizeof(gw));
	item->transportLayerAddress.size = sizeof(gw);
	OCTET_STRING_fromBuf(&item->gTP_TEID, (const char *)teid, sizeof(teid));
	item->nAS_PDU = OCTET_STRING_new_fromBuf(&asn_DEF_S1ap_NAS_PDU,
			(const char *)NAS_ATTACH_ACCEPT_EBI5, sizeof(NAS_ATTACH_ACCEPT_EBI5));
	enc = aper_encode_to_buffer(&asn_DEF_S1ap_E_RABToBeSetupItemCtxtSUReq,
			NULL, item, item_enc, sizeof(item_enc));
	ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABToBeSetupItemCtxtSUReq, item);
	if (enc.encoded <= 0)
		return -1;
	item_len = (size_t)((enc.encoded + 7) / 8);

	/* E-RABToBeSetupListCtxtSUReq: SIZE(1..256) count - 1 = 0, one IE */
	tmp[0] = 0x00;
	n = 1 + put_ie(tmp + 1, S1ap_ProtocolIE_ID_id_E_RABToBeSetupItemCtxtSUReq,
			item_enc, item_len);
	/* InitialContextSetupRequest: ext bit, IE count 1, the list IE */
	tmp2[0] = 0x00;
	tmp2[1] = 0x00;
	tmp2[2] = 0x01;
	m = 3 + put_ie(tmp2 + 3, S1ap_ProtocolIE_ID_id_E_RABToBeSetupListCtxtSUReq,
			tmp, n);
	/* S1AP-PDU: initiatingMessage, id-InitialContextSetup, reject */
	out[0] = 0x00;
	out[1] = S1ap_ProcedureCode_id_InitialContextSetup;
	out[2] = 0x00;
	return (ssize_t)(3 + put_open_type(out + 3, tmp2, m));
}

static void test_s1ap_ics_request_ue_ipv4(void) {
	s1ap_message_t msg;
	uint8_t buf[512];
	ssize_t len;
	int ret;

	printf("S1AP InitialContextSetupRequest UE IPv4 (issue #427 review):\n");
	len = build_s1ap_ics_request(buf, sizeof(buf));
	CHECK("InitialContextSetupRequest vector built", len > 0);
	if (len <= 0)
		return;
	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, buf, (uint32_t)len);
	CHECK("InitialContextSetupRequest decodes", ret == 0);
	CHECK("QCI 9 extracted", msg.qos_qci == 9);
	CHECK("GTP TEID 1 extracted", msg.gtp_teid == 1);
	CHECK("UE IPv4 10.45.0.2 extracted from ESM container with EBI 5",
			memcmp(&msg.ue_ipv4, UE_IPV4, sizeof(UE_IPV4)) == 0);
}

/* ------------------------------------------------------------------ */
/* Issue #443: spec-valid vectors for the other handled procedures.    */
/* Each one was encoded with pycrate from the TS 36.413 Rel-16 ASN.1   */
/* (an encoder independent of the vendored asn1c tree), so the later-  */
/* release IEs are real ones the Rel-10 decoder has never heard of.    */
/* ------------------------------------------------------------------ */

/* S1SetupRequest: Global-ENB-ID (PLMN 001/01, macro eNB 1), eNBname
 * "enb01", SupportedTAs (TAC 1), DefaultPagingDRX v128 */
static const uint8_t VECTOR_S1SETUP_REQUEST[] = {
		0x00, 0x11, 0x00, 0x2a, 0x00, 0x00, 0x04, 0x00, 0x3b, 0x00,
		0x08, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00,
		0x3c, 0x40, 0x07, 0x02, 0x00, 0x65, 0x6e, 0x62, 0x30, 0x31,
		0x00, 0x40, 0x00, 0x07, 0x00, 0x00, 0x00, 0x40, 0x00, 0xf1,
		0x10, 0x00, 0x89, 0x40, 0x01, 0x40
};

/* S1SetupResponse: MMEname "mme01", ServedGUMMEIs (PLMN 001/01, group 1,
 * MMEC 1), RelativeMMECapacity 10 */
static const uint8_t VECTOR_S1SETUP_RESPONSE[] = {
		0x20, 0x11, 0x00, 0x22, 0x00, 0x00, 0x03, 0x00, 0x3d, 0x40,
		0x07, 0x02, 0x00, 0x6d, 0x6d, 0x65, 0x30, 0x31, 0x00, 0x69,
		0x00, 0x0b, 0x00, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x01, 0x00, 0x57, 0x40, 0x01, 0x0a
};

/* InitialContextSetupRequest with every mandatory IE: MME-UE-S1AP-ID 7,
 * eNB-UE-S1AP-ID 1, UE-AMBR, one E-RAB (id 5, QCI 9, SGW 192.168.0.1,
 * TEID 1, NAS-PDU = NAS_ATTACH_ACCEPT_EBI5), UESecurityCapabilities,
 * SecurityKey */
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

/* InitialContextSetupResponse: MME-UE-S1AP-ID 7, eNB-UE-S1AP-ID 1,
 * E-RABSetupListCtxtSURes (E-RAB 5, eNB 192.168.0.2, TEID 2) */
static const uint8_t VECTOR_ICS_RESPONSE[] = {
		0x20, 0x09, 0x00, 0x22, 0x00, 0x00, 0x03, 0x00, 0x00, 0x40,
		0x02, 0x00, 0x07, 0x00, 0x08, 0x40, 0x02, 0x00, 0x01, 0x00,
		0x33, 0x40, 0x0f, 0x00, 0x00, 0x32, 0x40, 0x0a, 0x0a, 0x1f,
		0xc0, 0xa8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02
};

/* UEContextReleaseCommand: UE-S1AP-ID pair (MME 7, eNB 1), Cause nas
 * detach */
static const uint8_t VECTOR_UE_CONTEXT_RELEASE_COMMAND[] = {
		0x00, 0x17, 0x00, 0x10, 0x00, 0x00, 0x02, 0x00, 0x63, 0x00,
		0x04, 0x00, 0x07, 0x00, 0x01, 0x00, 0x02, 0x40, 0x01, 0x24
};

/* UEContextReleaseRequest: MME-UE-S1AP-ID 7, eNB-UE-S1AP-ID 1, Cause
 * radio-connection-with-ue-lost, GWContextReleaseIndication true, and the
 * Rel-15 SecondaryRATDataUsageReportList (id 264, criticality ignore) */
static const uint8_t VECTOR_UE_CONTEXT_RELEASE_REQUEST[] = {
		0x00, 0x12, 0x40, 0x38, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x07, 0x00, 0x08, 0x00, 0x02, 0x00, 0x01, 0x00,
		0x02, 0x40, 0x02, 0x02, 0xa0, 0x00, 0xa4, 0x00, 0x01, 0x00,
		0x01, 0x08, 0x40, 0x1a, 0x00, 0x01, 0x09, 0x40, 0x15, 0x0a,
		0x00, 0x01, 0x0b, 0x40, 0x0f, 0x00, 0xe3, 0x00, 0x00, 0x00,
		0xe3, 0x00, 0x00, 0x3c, 0x20, 0x03, 0xe8, 0x20, 0x07, 0xd0
};

/* S1AP-PDU around a ProtocolIE-Container: CHOICE octet (0x00 initiating,
 * 0x20 successful), procedureCode, criticality (0x00 reject, 0x40 ignore),
 * then the open-type value: extension bit + padding, 16-bit IE count, the
 * IEs. */
static size_t put_s1ap_pdu(uint8_t *out, uint8_t choice, uint8_t procedure,
		uint8_t criticality, uint16_t ie_count, const uint8_t *ies,
		size_t ies_len, uint8_t *scratch) {
	scratch[0] = 0x00;
	scratch[1] = (uint8_t)(ie_count >> 8);
	scratch[2] = (uint8_t)(ie_count & 0xFF);
	memcpy(scratch + 3, ies, ies_len);
	out[0] = choice;
	out[1] = procedure;
	out[2] = criticality;
	return 3 + put_open_type(out + 3, scratch, ies_len + 3);
}

static void test_s1ap_spec_vectors(void) {
	static const uint8_t SGW_IPV4[4] = { 192, 168, 0, 1 };
	static const uint8_t ENB_IPV4[4] = { 192, 168, 0, 2 };
	/* id 264, criticality ignore, 3 opaque value octets */
	static const uint8_t UNKNOWN_IE[] = { 0x01, 0x08, 0x40, 0x03, 0xAA, 0xBB, 0xCC };
	uint8_t ies[64], scratch[128], buf[128];
	s1ap_message_t msg;
	size_t n;
	int ret;

	printf("S1AP spec-valid procedure vectors (issue #443):\n");

	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, VECTOR_S1SETUP_REQUEST, sizeof(VECTOR_S1SETUP_REQUEST));
	CHECK("S1SetupRequest decodes", ret == 0);
	CHECK("S1SetupRequest: procedure 17, initiatingMessage",
			msg.procedure_code == 17 && msg.pdu_present == S1AP_PDU_PR_initiatingMessage);
	CHECK("S1SetupRequest: eNB name enb01",
			msg.has_enb_name && strcmp(msg.enb_name, "enb01") == 0);
	CHECK("S1SetupRequest: eNB/MME attaching",
			msg.enb_status == S1AP_ENTITY_STATUS_ATTACHING
			&& msg.mme_status == S1AP_ENTITY_STATUS_ATTACHING);

	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, VECTOR_S1SETUP_RESPONSE, sizeof(VECTOR_S1SETUP_RESPONSE));
	CHECK("S1SetupResponse decodes", ret == 0);
	CHECK("S1SetupResponse: successfulOutcome",
			msg.pdu_present == S1AP_PDU_PR_successfulOutcome);
	CHECK("S1SetupResponse: MME name mme01",
			msg.has_mme_name && strcmp(msg.mme_name, "mme01") == 0);
	CHECK("S1SetupResponse: eNB/MME attached",
			msg.enb_status == S1AP_ENTITY_STATUS_ATTACHED
			&& msg.mme_status == S1AP_ENTITY_STATUS_ATTACHED);

	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, VECTOR_ICS_REQUEST, sizeof(VECTOR_ICS_REQUEST));
	CHECK("InitialContextSetupRequest (all mandatory IEs) decodes", ret == 0);
	CHECK("InitialContextSetupRequest: MME/eNB UE ids 7/1",
			msg.mme_ue_id == 7 && msg.enb_ue_id == 1);
	CHECK("InitialContextSetupRequest: QCI 9, TEID 1",
			msg.qos_qci == 9 && msg.gtp_teid == 1);
	CHECK("InitialContextSetupRequest: SGW 192.168.0.1",
			memcmp(&msg.gw_ipv4, SGW_IPV4, 4) == 0);
	CHECK("InitialContextSetupRequest: UE IPv4 10.45.0.2",
			memcmp(&msg.ue_ipv4, UE_IPV4, sizeof(UE_IPV4)) == 0);

	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, VECTOR_ICS_RESPONSE, sizeof(VECTOR_ICS_RESPONSE));
	CHECK("InitialContextSetupResponse decodes", ret == 0);
	CHECK("InitialContextSetupResponse: MME/eNB UE ids 7/1",
			msg.mme_ue_id == 7 && msg.enb_ue_id == 1);
	CHECK("InitialContextSetupResponse: TEID 2, eNB 192.168.0.2",
			msg.gtp_teid == 2 && memcmp(&msg.enb_ipv4, ENB_IPV4, 4) == 0);
	CHECK("InitialContextSetupResponse: UE attached",
			msg.ue_status == S1AP_ENTITY_STATUS_ATTACHED);

	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, VECTOR_UE_CONTEXT_RELEASE_COMMAND,
			sizeof(VECTOR_UE_CONTEXT_RELEASE_COMMAND));
	CHECK("UEContextReleaseCommand decodes", ret == 0);
	CHECK("UEContextReleaseCommand: UE id pair 7/1",
			msg.mme_ue_id == 7 && msg.enb_ue_id == 1);
	CHECK("UEContextReleaseCommand: cause detach => UE detached",
			msg.ue_status == S1AP_ENTITY_STATUS_DETACHED);

	/* the same command with an IE the Rel-10 decoder does not know
	 * appended: it used to reject the whole message */
	memcpy(ies, VECTOR_UE_CONTEXT_RELEASE_COMMAND + 7,
			sizeof(VECTOR_UE_CONTEXT_RELEASE_COMMAND) - 7);
	memcpy(ies + sizeof(VECTOR_UE_CONTEXT_RELEASE_COMMAND) - 7,
			UNKNOWN_IE, sizeof(UNKNOWN_IE));
	n = put_s1ap_pdu(buf, 0x00, S1ap_ProcedureCode_id_UEContextRelease, 0x00, 3, ies,
			sizeof(VECTOR_UE_CONTEXT_RELEASE_COMMAND) - 7 + sizeof(UNKNOWN_IE),
			scratch);
	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, buf, (uint32_t)n);
	CHECK("UEContextReleaseCommand + unknown IE 264 still decodes", ret == 0);
	CHECK("UEContextReleaseCommand + unknown IE: ids and cause kept",
			msg.mme_ue_id == 7 && msg.enb_ue_id == 1
			&& msg.ue_status == S1AP_ENTITY_STATUS_DETACHED);

	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, VECTOR_UE_CONTEXT_RELEASE_REQUEST,
			sizeof(VECTOR_UE_CONTEXT_RELEASE_REQUEST));
	CHECK("UEContextReleaseRequest with Rel-15 IE 264 decodes (was -1)", ret == 0);
	CHECK("UEContextReleaseRequest: MME/eNB UE ids 7/1",
			msg.mme_ue_id == 7 && msg.enb_ue_id == 1);
	CHECK("UEContextReleaseRequest: cause radio link lost",
			msg.ue_status == S1AP_ENTITY_STATUS_LOST_SIGNAL);
}

/* ------------------------------------------------------------------ */
/* Issue #443: the open-type decoder's split-length path. An open type */
/* of 16K octets or more is sent as fragments of m * 16K (X.691        */
/* §11.9.3.8) followed by a final length determinant, possibly 0.      */
/* ------------------------------------------------------------------ */
static void test_open_type_split_length(void) {
	static const size_t sizes[] = { 16383, 16384, 2 * 16384 + 5, 65536 + 4464, 65536 + 16384 };
	const size_t cap = 90000;
	asn_codec_ctx_t ctx; /* max_stack_size 0: no ASan-hostile stack guard */
	uint8_t *content = malloc(cap), *wire = malloc(cap + 16);
	size_t i, j, n;

	printf("S1AP open type, split-length (>= 16K) path (issue #443):\n");
	if (content == NULL || wire == NULL) {
		CHECK("allocation", 0);
		free(content);
		free(wire);
		return;
	}
	memset(&ctx, 0, sizeof(ctx));
	for (j = 0; j < cap; j++)
		content[j] = (uint8_t)(j * 7 + 3);

	for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		ANY_t *any = NULL;
		asn_dec_rval_t rv;
		char desc[96];

		n = put_open_type(wire, content, sizes[i]);
		rv = aper_decode(&ctx, &asn_DEF_ANY, (void **)&any, wire, n, 0, 0);
		snprintf(desc, sizeof(desc), "%zu-octet open type decodes whole (%zu wire octets)",
				sizes[i], n);
		CHECK(desc, rv.code == RC_OK && any != NULL && any->size == (int)sizes[i]
				&& memcmp(any->buf, content, sizes[i]) == 0
				&& rv.consumed == n * 8);
		ASN_STRUCT_FREE(asn_DEF_ANY, any);
	}

	/* a fragment cut short is an error, not a partial value */
	{
		ANY_t *any = NULL;
		asn_dec_rval_t rv;
		n = put_open_type(wire, content, 2 * 16384 + 5);
		rv = aper_decode(&ctx, &asn_DEF_ANY, (void **)&any, wire, 16384, 0, 0);
		CHECK("truncated fragment rejected", rv.code != RC_OK);
		ASN_STRUCT_FREE(asn_DEF_ANY, any);
	}
	/* m = 5 is not a valid fragment multiplier (X.691 §11.9.3.8.1) */
	{
		ANY_t *any = NULL;
		asn_dec_rval_t rv;
		wire[0] = 0xC5;
		rv = aper_decode(&ctx, &asn_DEF_ANY, (void **)&any, wire, cap, 0, 0);
		CHECK("fragment multiplier 5 rejected", rv.code != RC_OK);
		ASN_STRUCT_FREE(asn_DEF_ANY, any);
	}
	free(content);
	free(wire);
}

/* InitialUEMessage carrying the given NAS-PDU; the other IEs are those
 * of the corpus vector: eNB-UE-S1AP-ID 1 (octets 7..12), then TAI,
 * EUTRAN-CGI and RRC-Establishment-Cause (octets 39..end). Returns the
 * PDU length; the buffers must hold nas_len + 192 octets. */
static size_t build_initial_ue_message(uint8_t *pdu, const uint8_t *nas,
		size_t nas_len, uint8_t *octs, uint8_t *ies, uint8_t *scratch) {
	const size_t tail_len = sizeof(VECTOR_CORPUS_INITIAL_UE_MESSAGE) - 39;
	size_t n, k;

	/* NAS-PDU ::= OCTET STRING: its own length determinant, inside the
	 * ProtocolIE value open type */
	k = put_open_type(octs, nas, nas_len);
	memcpy(ies, VECTOR_CORPUS_INITIAL_UE_MESSAGE + 7, 6);
	n = 6 + put_ie(ies + 6, S1ap_ProtocolIE_ID_id_NAS_PDU, octs, k);
	memcpy(ies + n, VECTOR_CORPUS_INITIAL_UE_MESSAGE + 39, tail_len);
	n += tail_len;
	return put_s1ap_pdu(pdu, 0x00, S1ap_ProcedureCode_id_initialUEMessage,
			0x40, 5, ies, n, scratch);
}

/* TS 24.301 Attach Request with IMSI 001010123456789 */
static const uint8_t NAS_ATTACH_REQUEST_IMSI15[] = {
	0x07, 0x41, 0x71, 0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54,
	0x76, 0x98, 0x02, 0xe0, 0xe0, 0x00, 0x04, 0x02, 0x01, 0xd0, 0x11
};

/* End to end: an InitialUEMessage whose NAS-PDU is 20000 octets, so the
 * NAS-PDU OCTET STRING, its ProtocolIE value and the S1AP-PDU value are
 * all fragmented. The encoding is byte-identical to pycrate's. */
static void test_s1ap_split_length_message(void) {
	const size_t nas_len = 20000;
	uint8_t *nas = calloc(1, nas_len), *octs = malloc(nas_len + 192);
	uint8_t *ies = malloc(nas_len + 192), *scratch = malloc(nas_len + 192);
	uint8_t *pdu = malloc(nas_len + 192);
	s1ap_message_t msg;
	size_t n;
	int ret;

	printf("S1AP InitialUEMessage with a 20000-octet NAS-PDU (issue #443):\n");
	if (!nas || !octs || !ies || !scratch || !pdu) {
		CHECK("allocation", 0);
		goto out;
	}
	/* the attach request, then zero padding */
	memcpy(nas, NAS_ATTACH_REQUEST_IMSI15, sizeof(NAS_ATTACH_REQUEST_IMSI15));
	n = build_initial_ue_message(pdu, nas, nas_len, octs, ies, scratch);
	CHECK("outer value is fragmented", pdu[3] == 0xC1);

	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, pdu, (uint32_t)n);
	CHECK("fragmented InitialUEMessage decodes", ret == 0);
	CHECK("eNB-UE-S1AP-ID 1", msg.enb_ue_id == 1);
	CHECK("IMSI read from the reassembled NAS-PDU",
			msg.has_imsi && strcmp(msg.imsi, "001010123456789") == 0);

	memset(&msg, 0, sizeof(msg));
	ret = s1ap_decode(&msg, pdu, (uint32_t)(n - 100));
	CHECK("fragmented InitialUEMessage cut short rejected", ret < 0);
out:
	free(nas);
	free(octs);
	free(ies);
	free(scratch);
	free(pdu);
}

/* Issue #443: IMSIs of 13 digits or fewer (IE length <= 7) reach the
 * s1ap.imsi attribute (TS 24.301 §9.9.3.12). */
static void test_s1ap_short_imsi(void) {
	uint8_t nas[sizeof(NAS_ATTACH_REQUEST_IMSI15)];
	uint8_t octs[256], ies[256], scratch[256], pdu[256];
	s1ap_message_t msg;
	size_t n;

	printf("S1AP InitialUEMessage with short IMSIs (issue #443):\n");

	/* 13 digits 0010101234567: odd, IE length 7 — the last digit octet of
	 * the 15-digit IMSI is dropped and the rest shifts down */
	memcpy(nas, NAS_ATTACH_REQUEST_IMSI15, 3);
	nas[3] = 0x07;
	memcpy(nas + 4, NAS_ATTACH_REQUEST_IMSI15 + 4, 7);
	memcpy(nas + 11, NAS_ATTACH_REQUEST_IMSI15 + 12, sizeof(nas) - 12);
	n = build_initial_ue_message(pdu, nas, sizeof(nas) - 1, octs, ies, scratch);
	memset(&msg, 0, sizeof(msg));
	CHECK("13-digit IMSI message decodes", s1ap_decode(&msg, pdu, (uint32_t)n) == 0);
	CHECK("13-digit IMSI 0010101234567",
			msg.has_imsi && strcmp(msg.imsi, "0010101234567") == 0);

	/* 12 digits 001010123456: even, IE length 7, filler in the last octet */
	nas[4] = 0x01;
	nas[10] = 0xF6;
	memset(&msg, 0, sizeof(msg));
	n = build_initial_ue_message(pdu, nas, sizeof(nas) - 1, octs, ies, scratch);
	CHECK("12-digit IMSI message decodes", s1ap_decode(&msg, pdu, (uint32_t)n) == 0);
	CHECK("12-digit IMSI 001010123456",
			msg.has_imsi && strcmp(msg.imsi, "001010123456") == 0);
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

/* ------------------------------------------------------------------ */
/* Issue #207: SCTP-carried mobile protocols — decode-failure leaks,   */
/* bounded entity store, CHOICE discriminant integrity.                */
/* ------------------------------------------------------------------ */

/* F-BUG-078/087: every aper_decode() failure path must free the
 * partially-decoded S1AP_PDU. The loop is the regression; LSAN
 * (detect_leaks=1, forced by run_tests.sh under SANITIZE=asan) is the
 * oracle — pre-fix, each failing call leaked the 112-byte CHOICE root
 * allocated by CHOICE_decode_aper. stderr is muted during the loop:
 * each failure path fprintf()s a diagnostic. */
static void test_s1ap_decode_failure_no_leak(void) {
	/* 0xFF first octet: CHOICE extension bit set + out-of-range index —
	 * CHOICE_decode_aper allocates the S1AP_PDU then fails. */
	static const uint8_t bad_choice[] = { 0xFF, 0xFF, 0xFF, 0xFF };
	uint8_t inner_fail[5 + 200];
	s1ap_message_t msg;
	int i, rc1 = 0, rc2 = 0, rc3 = 0;
	int saved_stdout = -1, saved_stderr = -1;

	/* outer decode ok / inner IE-list ANY fails — walks the nested
	 * cleanup path (F-BUG-087). Same construction as
	 * craft_s1ap_inner_fail() for successfulOutcome/InitialContextSetup. */
	inner_fail[0] = 0x20;                 /* successfulOutcome */
	inner_fail[1] = 0x09;                 /* id-InitialContextSetup */
	inner_fail[2] = 0x00;                 /* criticality reject */
	inner_fail[3] = 0x80 | (200 >> 8);
	inner_fail[4] = 200 & 0xFF;
	memset(inner_fail + 5, 0xFF, sizeof(inner_fail) - 5);

	printf("S1AP decode-failure cleanup, 10k iterations "
			"(F-BUG-078/087 — leak oracle is LSAN):\n");

	/* the decoder logs failures on both stderr ([S1AP] Failed...) and
	 * stdout (S1AP_ERROR) — mute both for the 10k-iteration loop */
	fflush(stdout);
	fflush(stderr);
	saved_stdout = dup(STDOUT_FILENO);
	saved_stderr = dup(STDERR_FILENO);
	if (saved_stdout >= 0) {
		FILE *dn = freopen("/dev/null", "w", stdout);
		(void)dn;
	}
	if (saved_stderr >= 0) {
		FILE *dn = freopen("/dev/null", "w", stderr);
		(void)dn;
	}

	for (i = 0; i < 10000; i++) {
		memset(&msg, 0, sizeof(msg));
		rc1 = s1ap_decode(&msg, bad_choice, sizeof(bad_choice));
		memset(&msg, 0, sizeof(msg));
		rc2 = s1ap_decode(&msg, VECTOR_ATTACH_REQUEST_IMSI, 10);
		memset(&msg, 0, sizeof(msg));
		rc3 = s1ap_decode(&msg, inner_fail, sizeof(inner_fail));
	}

	fflush(stdout);
	fflush(stderr);
	if (saved_stdout >= 0) {
		dup2(saved_stdout, STDOUT_FILENO);
		close(saved_stdout);
		clearerr(stdout);
	}
	if (saved_stderr >= 0) {
		dup2(saved_stderr, STDERR_FILENO);
		close(saved_stderr);
		clearerr(stderr);
	}

	CHECK("bad CHOICE index rejected", rc1 == -1);
	CHECK("truncated PDU rejected", rc2 <= 0);
	CHECK("inner-fail PDU rejected", rc3 == -1);
}

/* F-BUG-086: the process-global entity store is capped at
 * S1AP_MAX_ENTITIES and indexed by entity type. */
static void test_s1ap_entity_store_cap(void) {
	s1ap_message_t msg;
	uint32_t i, id, first = 0, second = 0, inserted = 0;

	printf("S1AP entity store ceiling/index (F-BUG-086):\n");
	s1ap_entities_reset();
	CHECK("store empty after reset", s1ap_entities_count() == 0);

	/* the same entity seen twice updates in place, no second node */
	memset(&msg, 0, sizeof(msg));
	msg.enb_ipv4 = 0x0a000001;
	first  = s1ap_entities_update(S1AP_ENTITY_TYPE_ENODEB, &msg);
	second = s1ap_entities_update(S1AP_ENTITY_TYPE_ENODEB, &msg);
	CHECK("new entity got an id", first > 0);
	CHECK("same eNB updates in place (same id)", second == first);
	CHECK("in-place update did not grow the store",
			s1ap_entities_count() == 1);
	inserted = s1ap_entities_count();

	/* fill past the ceiling with distinct attacker-controlled ipv4s */
	for (i = 0; i < S1AP_MAX_ENTITIES + 500; i++) {
		memset(&msg, 0, sizeof(msg));
		msg.enb_ipv4 = 0x0b000000u + i;
		id = s1ap_entities_update(S1AP_ENTITY_TYPE_ENODEB, &msg);
		if (id != 0)
			inserted++;
	}
	CHECK("store never exceeds the ceiling",
			s1ap_entities_count() == S1AP_MAX_ENTITIES);
	CHECK("inserts past the ceiling are refused",
			inserted == S1AP_MAX_ENTITIES);

	memset(&msg, 0, sizeof(msg));
	msg.enb_ipv4 = 0x7f000001u;
	CHECK("update past ceiling returns 0",
			s1ap_entities_update(S1AP_ENTITY_TYPE_ENODEB, &msg) == 0);

	/* but a known entity still refreshes in place at the ceiling */
	memset(&msg, 0, sizeof(msg));
	msg.enb_ipv4 = 0x0a000001;
	CHECK("existing entity still updates at the ceiling",
			s1ap_entities_update(S1AP_ENTITY_TYPE_ENODEB, &msg) == first);

	/* a message carrying nothing for the type inserts nothing */
	memset(&msg, 0, sizeof(msg));
	CHECK("empty message inserts nothing",
			s1ap_entities_update(S1AP_ENTITY_TYPE_UE, &msg) == 0);

	s1ap_entities_reset();
	CHECK("store drains on reset", s1ap_entities_count() == 0);
}

/* F-BUG-089: encode must not let msg->pdu_present overwrite the decoded
 * CHOICE discriminant — only the union arm the wire actually carried may
 * be re-encoded and freed. */
static void test_ngap_choice_discriminant(void) {
	NGAP_NGAP_PDU_t *pdu;
	uint8_t buf[256], out[512];
	ssize_t len;
	ngap_message_t msg, msg2;
	long enc;

	printf("NGAP CHOICE discriminant (F-BUG-089):\n");
	pdu = build_ngap_initial_ue_message(0);
	len = encode_ngap_pdu(pdu, buf, sizeof(buf));
	CHECK("library-encoded initiatingMessage", len > 0);
	ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
	if (len <= 0)
		return;

	memset(&msg, 0, sizeof(msg));
	CHECK("decode_ngap sees initiatingMessage",
			decode_ngap(&msg, buf, (uint32_t)len)
			&& msg.pdu_present == NGAP_NGAP_PDU_PR_initiatingMessage);

	/* a different discriminant in the message view must not morph the
	 * decoded union arm on encode */
	msg.pdu_present = NGAP_NGAP_PDU_PR_successfulOutcome;
	enc = (long)encode_ngap(out, sizeof(out), &msg, buf, (uint32_t)len);
	CHECK("encode_ngap re-encodes the decoded arm, not the overwritten "
			"discriminant", enc > 0);
	if (enc > 0) {
		memset(&msg2, 0, sizeof(msg2));
		CHECK("round-trip keeps the real union arm",
				decode_ngap(&msg2, out, (uint32_t)((enc + 7) / 8))
				&& msg2.pdu_present == NGAP_NGAP_PDU_PR_initiatingMessage);
	}
}

int main(void) {
	test_s1ap_outer_ok_inner_fail();
	test_s1ap_valid_vectors();
	test_s1ap_corpus_initial_ue_message();
	test_s1ap_ics_request_ue_ipv4();
	test_s1ap_spec_vectors();
	test_open_type_split_length();
	test_s1ap_split_length_message();
	test_s1ap_short_imsi();
	test_ngap_get_nas_pdu();
	test_s1ap_decode_failure_no_leak();
	test_s1ap_entity_store_cap();
	test_ngap_choice_discriminant();

	printf("\n%d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}

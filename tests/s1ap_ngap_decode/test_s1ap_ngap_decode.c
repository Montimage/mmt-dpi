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
 *  - Issue #452: the NAS ciphering algorithm a Security Mode Command
 *    (DownlinkNASTransport) selects is kept per S1 connection in a bounded
 *    table; a ciphered Attach Accept is not parsed for EEA1-3, is parsed for
 *    EEA0, and is parsed best-effort when the algorithm is unknown.
 *  - F-BUG-221: NGAP hygiene - explicit codes instead of false-from-pointer
 *    functions, encode_ngap() NULL-check, act-aware NAS_PDU handling.
 *  - Issue #532: every per-message NGAP decoder reads the UE ids of its
 *    message and encode_ngap() patches new ones into it.
 *  - Issue #545: malformed S1AP PDUs write nothing to stdout or stderr by
 *    default (each failure counted by the SDK logger), and with logging on
 *    their diagnostics go to stderr, rate-limited per call site.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "s1ap_common.h"
#include "nas/nas_msg.h"
#include "mobile/proto_s1ap.h"
#include "ngap.h"
#include "NGAP_ProtocolIE-Field.h"
#include "NGAP_RRCEstablishmentCause.h"
#include "S1ap-E-RABToBeSetupItemCtxtSUReq.h"
#include "S1ap-E-RABLevelQoSParameters.h"
#include "S1ap-AllocationAndRetentionPriority.h"
#include "NGAP_InitialUEMessage.h"
#include "NGAP_ProtocolIE-Container.h"
#include "NGAP_SecondaryRATDataUsageReport.h"
#include "NGAP_HandoverFlag.h"
#include "NGAP_AMF-UE-NGAP-ID.h"
#include "NGAP_RAN-UE-NGAP-ID.h"
#include "NGAP_NAS-PDU.h"
#include "NGAP_UE-NGAP-IDs.h"
#include "NGAP_UE-NGAP-ID-pair.h"
#include "S1ap-IE.h"
#include "S1ap-NRUESecurityCapabilities.h"
#include "S1ap-InitialContextSetupRequest.h"
#include "S1ap-UEAggregateMaximumBitrate.h"
#include "S1ap-UESecurityCapabilities.h"
#include "S1ap-SecurityKey.h"
#include "S1ap-BearerType.h"
#include "S1ap-Packet-LossRate.h"

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
/* Issue #545: malformed PDUs write nothing — S1AP_ERROR/S1AP_WARN     */
/* used to print one stdout line per malformed PDU. They go through    */
/* the SDK logger now: off by default, stderr only, rate-limited per   */
/* call site, every event counted (src/mmt_core/private_include/       */
/* mmt_log.h).                                                         */
/* ------------------------------------------------------------------ */
static char *read_and_unlink(const char *path) {
	FILE *f = fopen(path, "r");
	char *buf = calloc(1, 65537);
	if (f != NULL && buf != NULL)
		buf[fread(buf, 1, 65536, f)] = '\0';
	if (f != NULL)
		fclose(f);
	unlink(path);
	return buf;
}

/* Decodes n malformed PDUs (outer decode fails, then inner IE-list decode
 * fails) with fds 1 and 2 captured; returns both captures (caller frees). */
static void decode_malformed_captured(int n, char **out, char **err) {
	char out_path[] = "/tmp/s1ap_log_out.XXXXXX";
	char err_path[] = "/tmp/s1ap_log_err.XXXXXX";
	int fo = mkstemp(out_path), fe = mkstemp(err_path);
	fflush(stdout);
	fflush(stderr);
	int saved_out = dup(1), saved_err = dup(2);
	dup2(fo, 1);
	dup2(fe, 2);
	for (int i = 0; i < n; i++) {
		s1ap_message_t msg;
		uint8_t buf[512];
		memset(&msg, 0, sizeof(msg));
		memset(buf, 0xFF, 16);
		(void) s1ap_decode(&msg, buf, 16);           /* outer decode fails */
		int len = craft_s1ap_inner_fail(buf, sizeof(buf), 0x00,
				S1ap_ProcedureCode_id_InitialContextSetup);
		memset(&msg, 0, sizeof(msg));
		(void) s1ap_decode(&msg, buf, (uint32_t)len); /* inner IE fails */
	}
	fflush(stdout);
	fflush(stderr);
	dup2(saved_out, 1);
	dup2(saved_err, 2);
	close(saved_out);
	close(saved_err);
	close(fo);
	close(fe);
	*out = read_and_unlink(out_path);
	*err = read_and_unlink(err_path);
}

static void test_s1ap_malformed_pdus_silent(void) {
	const int n = 50;
	mmt_log_stats_t before, after;
	char *out, *err;
	printf("S1AP malformed PDUs through the logger (issue #545):\n");

	mmt_log_get_stats(&before);
	decode_malformed_captured(n, &out, &err);
	mmt_log_get_stats(&after);
	CHECK("logging is off by default", mmt_log_get_level() == MMT_LOG_LEVEL_OFF);
	CHECK("malformed PDUs write nothing to stdout", out[0] == '\0');
	CHECK("malformed PDUs write nothing to stderr (logger off)", err[0] == '\0');
	CHECK("each failure is still counted",
			(after.events[MMT_LOG_LEVEL_WARN] - before.events[MMT_LOG_LEVEL_WARN])
			+ (after.events[MMT_LOG_LEVEL_ERROR] - before.events[MMT_LOG_LEVEL_ERROR])
			>= (uint64_t)(2 * n));
	CHECK("no line written while off", after.written == before.written);
	free(out);
	free(err);

	mmt_log_set_level(MMT_LOG_LEVEL_WARN);
	mmt_log_get_stats(&before);
	decode_malformed_captured(n, &out, &err);
	mmt_log_get_stats(&after);
	mmt_log_set_level(MMT_LOG_LEVEL_OFF);
	CHECK("enabled: still nothing on stdout", out[0] == '\0');
	CHECK("enabled: S1AP diagnostics reach stderr",
			strstr(err, "[mmt-dpi][W] s1ap_common.c:") != NULL
			&& strstr(err, "[S1AP] Failed to decode S1AP") != NULL);
	CHECK("enabled: the flood is rate-limited per call site",
			after.rate_limited > before.rate_limited
			&& after.written - before.written < (uint64_t) n);
	free(out);
	free(err);
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

/* ProtocolIE-Field: id (16-bit aligned), criticality reject, open value */
static size_t put_ie(uint8_t *out, uint16_t id, const uint8_t *content, size_t len);

/* InitialContextSetupRequest carrying nas in its one E-RAB; with_ids adds
 * MME-UE-S1AP-ID mme_ue_id and eNB-UE-S1AP-ID enb_ue_id (both < 256) */
static ssize_t build_s1ap_ics_request_nas(uint8_t *out, size_t cap,
		const uint8_t *nas, size_t nas_len, int with_ids,
		uint8_t mme_ue_id, uint8_t enb_ue_id) {
	S1ap_E_RABToBeSetupItemCtxtSUReq_t *item = calloc(1, sizeof(*item));
	static const uint8_t teid[4] = { 0x00, 0x00, 0x00, 0x01 };
	static const uint8_t gw[4]   = { 192, 168, 0, 1 };
	uint8_t item_enc[256], tmp[512], tmp2[512];
	asn_enc_rval_t enc;
	size_t item_len, n, m;

	if (item == NULL || cap < 512)
		return -1;
	/* asn1c v1.5.3 holds both QoS structures by pointer (issue #522) */
	item->e_RABlevelQoSParameters = calloc(1, sizeof(*item->e_RABlevelQoSParameters));
	if (item->e_RABlevelQoSParameters == NULL) {
		free(item);
		return -1;
	}
	item->e_RABlevelQoSParameters->allocationRetentionPriority =
			calloc(1, sizeof(*item->e_RABlevelQoSParameters->allocationRetentionPriority));
	if (item->e_RABlevelQoSParameters->allocationRetentionPriority == NULL) {
		ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABToBeSetupItemCtxtSUReq, item);
		return -1;
	}
	item->e_RAB_ID = 5;
	item->e_RABlevelQoSParameters->qCI = 9;
	item->e_RABlevelQoSParameters->allocationRetentionPriority->priorityLevel = 1;
	item->transportLayerAddress.buf = malloc(sizeof(gw));
	if (item->transportLayerAddress.buf)
		memcpy(item->transportLayerAddress.buf, gw, sizeof(gw));
	item->transportLayerAddress.size = sizeof(gw);
	OCTET_STRING_fromBuf(&item->gTP_TEID, (const char *)teid, sizeof(teid));
	item->nAS_PDU = OCTET_STRING_new_fromBuf(&asn_DEF_S1ap_NAS_PDU,
			(const char *)nas, (int)nas_len);
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
	/* InitialContextSetupRequest: ext bit, IE count, [the UE IDs,] the
	 * list IE */
	tmp2[0] = 0x00;
	tmp2[1] = 0x00;
	tmp2[2] = with_ids ? 0x03 : 0x01;
	m = 3;
	if (with_ids) {
		const uint8_t mme[2] = { 0x00, mme_ue_id };
		const uint8_t enb[2] = { 0x00, enb_ue_id };
		m += put_ie(tmp2 + m, S1ap_ProtocolIE_ID_id_MME_UE_S1AP_ID, mme, sizeof(mme));
		m += put_ie(tmp2 + m, S1ap_ProtocolIE_ID_id_eNB_UE_S1AP_ID, enb, sizeof(enb));
	}
	m += put_ie(tmp2 + m, S1ap_ProtocolIE_ID_id_E_RABToBeSetupListCtxtSUReq,
			tmp, n);
	/* S1AP-PDU: initiatingMessage, id-InitialContextSetup, reject */
	out[0] = 0x00;
	out[1] = S1ap_ProcedureCode_id_InitialContextSetup;
	out[2] = 0x00;
	return (ssize_t)(3 + put_open_type(out + 3, tmp2, m));
}

static ssize_t build_s1ap_ics_request(uint8_t *out, size_t cap) {
	return build_s1ap_ics_request_nas(out, cap, NAS_ATTACH_ACCEPT_EBI5,
			sizeof(NAS_ATTACH_ACCEPT_EBI5), 0, 0, 0);
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
	/* issue #522: QoS parameters and ARP are held by pointer since v1.5.3 */
	CHECK("ARP priority level 1 extracted", msg.qos_priority_level == 1);
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

/* ------------------------------------------------------------------ */
/* Issue #452: NAS ciphering algorithm learned from the Security Mode   */
/* Command of a DownlinkNASTransport, per S1 connection                 */
/* ------------------------------------------------------------------ */

/* DownlinkNASTransport: MME-UE-S1AP-ID, eNB-UE-S1AP-ID (< 256) and a
 * NAS-PDU holding an EMM Security Mode Command (security header type 3)
 * whose Selected NAS security algorithms octet is algorithms */
static size_t build_s1ap_dl_nas_smc(uint8_t *out, uint16_t mme_ue_id,
		uint8_t enb_ue_id, uint8_t algorithms) {
	/* INTEGER (0..2^32-1), APER: 2-bit octet count - 1, then the octets */
	const uint8_t mme[3] = { mme_ue_id < 256 ? 0x00 : 0x40,
			(uint8_t)(mme_ue_id < 256 ? mme_ue_id : mme_ue_id >> 8),
			(uint8_t)(mme_ue_id & 0xFF) };
	const uint8_t enb[2] = { 0x00, enb_ue_id };
	/* NAS-PDU OCTET STRING: length determinant + SMC (TS 24.301 §8.2.20:
	 * algorithms, NAS key set identifier, replayed UE security caps) */
	const uint8_t nas[] = { 13,
		0x37, 0x5a, 0x6b, 0x7c, 0x8d, 0x00,  /* sec hdr 3, MAC, SQN 0 */
		0x07, 0x5D, algorithms, 0x00,          /* EMM, SMC, algs, KSI */
		0x02, 0xE0, 0xE0 };                    /* UE security caps   */
	uint8_t ies[64], scratch[96];
	size_t n = 0;
	n += put_ie(ies + n, S1ap_ProtocolIE_ID_id_MME_UE_S1AP_ID, mme,
			mme_ue_id < 256 ? 2 : 3);
	n += put_ie(ies + n, S1ap_ProtocolIE_ID_id_eNB_UE_S1AP_ID, enb, sizeof(enb));
	n += put_ie(ies + n, S1ap_ProtocolIE_ID_id_NAS_PDU, nas, sizeof(nas));
	return put_s1ap_pdu(out, 0x00, S1ap_ProcedureCode_id_downlinkNASTransport,
			0x40, 3, ies, n, scratch);
}

/* decode an ICS request carrying nas for (mme_ue_id, enb_ue_id); 1 when
 * the UE IPv4 was extracted from its Attach Accept */
static int ics_extracts_ue_ipv4(const uint8_t *nas, size_t nas_len,
		uint8_t mme_ue_id, uint8_t enb_ue_id) {
	s1ap_message_t msg;
	uint8_t buf[512];
	ssize_t len = build_s1ap_ics_request_nas(buf, sizeof(buf), nas, nas_len,
			1, mme_ue_id, enb_ue_id);
	if (len <= 0)
		return -1;
	memset(&msg, 0, sizeof(msg));
	if (s1ap_decode(&msg, buf, (uint32_t)len) != 0
			|| msg.mme_ue_id != mme_ue_id || msg.enb_ue_id != enb_ue_id
			|| msg.qos_qci != 9 || msg.gtp_teid != 1)
		return -1;
	return memcmp(&msg.ue_ipv4, UE_IPV4, sizeof(UE_IPV4)) == 0;
}

static int decode_smc_id(uint16_t mme_ue_id, uint8_t enb_ue_id, uint8_t algorithms) {
	s1ap_message_t msg;
	uint8_t buf[128];
	size_t len = build_s1ap_dl_nas_smc(buf, mme_ue_id, enb_ue_id, algorithms);
	memset(&msg, 0, sizeof(msg));
	int ret = s1ap_decode(&msg, buf, (uint32_t)len);
	/* the DownlinkNASTransport only feeds the ciphering table */
	if (ret == 0 && (msg.procedure_code != S1ap_ProcedureCode_id_downlinkNASTransport
			|| msg.mme_ue_id != 0 || msg.enb_ue_id != 0))
		return -1;
	return ret;
}

static int decode_smc(uint8_t mme_ue_id, uint8_t enb_ue_id, uint8_t algorithms) {
	return decode_smc_id(mme_ue_id, enb_ue_id, algorithms);
}

static void test_s1ap_nas_ciphering(void) {
	uint8_t ciphered[sizeof(NAS_ATTACH_ACCEPT_EBI5)];
	s1ap_message_t msg;
	uint32_t id;

	printf("S1AP NAS ciphering algorithm per S1 connection (issue #452):\n");
	/* the same Attach Accept, security header type 2 (ciphered) */
	memcpy(ciphered, NAS_ATTACH_ACCEPT_EBI5, sizeof(ciphered));
	ciphered[0] = 0x27;
	s1ap_nas_ciphering_reset();

	CHECK("no SMC seen: algorithm unknown",
			s1ap_nas_ciphering_algorithm(7, 1) == NAS_CIPHERING_ALGORITHM_UNKNOWN);
	CHECK("unknown: plausible ciphered Attach Accept parsed (best effort)",
			ics_extracts_ue_ipv4(ciphered, sizeof(ciphered), 7, 1) == 1);

	CHECK("SMC selecting EEA2/EIA2 decodes", decode_smc(7, 1, 0x22) == 0);
	CHECK("EEA2 learned for (7, 1)", s1ap_nas_ciphering_algorithm(7, 1) == 2);
	CHECK("another eNB-UE-S1AP-ID is another connection",
			s1ap_nas_ciphering_algorithm(7, 2) == NAS_CIPHERING_ALGORITHM_UNKNOWN);
	CHECK("EEA2: ciphered Attach Accept not parsed, other IEs still are",
			ics_extracts_ue_ipv4(ciphered, sizeof(ciphered), 7, 1) == 0);
	CHECK("EEA2: integrity-only Attach Accept still parsed",
			ics_extracts_ue_ipv4(NAS_ATTACH_ACCEPT_EBI5, sizeof(NAS_ATTACH_ACCEPT_EBI5), 7, 1) == 1);
	CHECK("EEA2 of (7, 1) does not affect (8, 2)",
			ics_extracts_ue_ipv4(ciphered, sizeof(ciphered), 8, 2) == 1);

	CHECK("SMC selecting EEA0/EIA2 decodes", decode_smc(7, 1, 0x02) == 0);
	CHECK("EEA0 learned for (7, 1)", s1ap_nas_ciphering_algorithm(7, 1) == NAS_CIPHERING_ALGORITHM_EEA0);
	CHECK("EEA0: ciphered Attach Accept parsed",
			ics_extracts_ue_ipv4(ciphered, sizeof(ciphered), 7, 1) == 1);

	CHECK("SMC selecting EEA3/EIA3 decodes", decode_smc(7, 1, 0x33) == 0);
	CHECK("EEA3: ciphered Attach Accept not parsed",
			ics_extracts_ue_ipv4(ciphered, sizeof(ciphered), 7, 1) == 0);

	/* UEContextReleaseCommand names the pair (MME 7, eNB 1): slot freed */
	memset(&msg, 0, sizeof(msg));
	CHECK("UEContextReleaseCommand decodes",
			s1ap_decode(&msg, VECTOR_UE_CONTEXT_RELEASE_COMMAND,
					sizeof(VECTOR_UE_CONTEXT_RELEASE_COMMAND)) == 0);
	CHECK("release forgets the algorithm",
			s1ap_nas_ciphering_algorithm(7, 1) == NAS_CIPHERING_ALGORITHM_UNKNOWN);

	/* the entity-store reset (handler cleanup) also clears the table */
	CHECK("SMC selecting EEA1 decodes", decode_smc(7, 1, 0x11) == 0);
	CHECK("EEA1 learned", s1ap_nas_ciphering_algorithm(7, 1) == 1);
	s1ap_entities_reset();
	CHECK("s1ap_entities_reset forgets the algorithm",
			s1ap_nas_ciphering_algorithm(7, 1) == NAS_CIPHERING_ALGORITHM_UNKNOWN);

	/* a DownlinkNASTransport without an SMC learns nothing */
	{
		uint8_t buf[128];
		size_t len = build_s1ap_dl_nas_smc(buf, 7, 1, 0x22);
		/* turn the NAS message type 0x5D into 0x62 (EMM Information) */
		uint8_t *p = memchr(buf, 0x5D, len);
		CHECK("SMC octet found in the vector", p != NULL);
		if (p != NULL) {
			*p = 0x62;
			memset(&msg, 0, sizeof(msg));
			CHECK("non-SMC DownlinkNASTransport decodes",
					s1ap_decode(&msg, buf, (uint32_t)len) == 0);
			CHECK("non-SMC DownlinkNASTransport learns nothing",
					s1ap_nas_ciphering_algorithm(7, 1) == NAS_CIPHERING_ALGORITHM_UNKNOWN);
		}
	}

	/* bounded: a later connection mapping to the same slot evicts (7, 1),
	 * which then falls back to unknown, never to another UE's algorithm */
	CHECK("SMC selecting EEA2 decodes again", decode_smc(7, 1, 0x22) == 0);
	int smc_failures = 0;
	for (id = 8; id < 65536; id++) {
		smc_failures += decode_smc_id((uint16_t)id, 1, 0x11) != 0;
		if (s1ap_nas_ciphering_algorithm(7, 1) != 2)
			break;
	}
	CHECK("SMCs of other connections decode", smc_failures == 0);
	CHECK("a colliding connection evicts (7, 1) to unknown",
			id < 65536 && s1ap_nas_ciphering_algorithm(7, 1) == NAS_CIPHERING_ALGORITHM_UNKNOWN);
	CHECK("the colliding connection holds its own algorithm",
			id < 65536 && s1ap_nas_ciphering_algorithm(id, 1) == 1);
	s1ap_nas_ciphering_reset();
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
	NGAP_ProtocolIE_Container_6976P34_t *ies;
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
	/* asn1c v1.5.3 (issue #522): the message, its IE container (the
	 * NGAP_ProtocolIE_Container_6976P34 instance asn_DEF_NGAP_InitialUEMessage
	 * names) and every IE value are held by pointer; ASN_STRUCT_FREE of the
	 * PDU releases them all */
	iem = calloc(1, sizeof(*iem));
	pdu->choice.initiatingMessage->value.choice.InitialUEMessage = iem;
	if (iem == NULL)
		return pdu;
	ies = calloc(1, sizeof(*ies));
	iem->protocolIEs = (struct NGAP_ProtocolIE_Container *)ies;
	if (ies == NULL)
		return pdu;

	ie = calloc(1, sizeof(*ie));
	ie->id          = NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
	ie->criticality = NGAP_Criticality_reject;
	ie->value.present = NGAP_InitialUEMessage_IEs__value_PR_RAN_UE_NGAP_ID;
	ie->value.choice.RAN_UE_NGAP_ID = calloc(1, sizeof(*ie->value.choice.RAN_UE_NGAP_ID));
	*ie->value.choice.RAN_UE_NGAP_ID = 12345;
	ASN_SEQUENCE_ADD(&ies->list, ie);

	if (with_nas_pdu) {
		static const uint8_t nas_payload[] = { 'A', 'B', 'C', 'D' };
		ie = calloc(1, sizeof(*ie));
		ie->id          = NGAP_ProtocolIE_ID_id_NAS_PDU;
		ie->criticality = NGAP_Criticality_reject;
		ie->value.present = NGAP_InitialUEMessage_IEs__value_PR_NAS_PDU;
		ie->value.choice.NAS_PDU = OCTET_STRING_new_fromBuf(&asn_DEF_NGAP_NAS_PDU,
				(const char *)nas_payload, sizeof(nas_payload));
		ASN_SEQUENCE_ADD(&ies->list, ie);
	}
	else {
		/* second IE without any NAS-PDU: RRC establishment cause */
		ie = calloc(1, sizeof(*ie));
		ie->id          = NGAP_ProtocolIE_ID_id_RRCEstablishmentCause;
		ie->criticality = NGAP_Criticality_ignore;
		ie->value.present =
				NGAP_InitialUEMessage_IEs__value_PR_RRCEstablishmentCause;
		ie->value.choice.RRCEstablishmentCause =
				calloc(1, sizeof(*ie->value.choice.RRCEstablishmentCause));
		*ie->value.choice.RRCEstablishmentCause =
				NGAP_RRCEstablishmentCause_mo_Signalling;
		ASN_SEQUENCE_ADD(&ies->list, ie);
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
		/* issue #522: every IE value is held by pointer since v1.5.3 —
		 * read it (GET_ACTION) and patch it on re-encode (SET_ACTION) */
		CHECK("decoded RAN-UE-NGAP-ID is 12345", msg.ran_ue_id == 12345);
		{
			uint8_t enc_buf[256];
			ngap_message_t back;
			uint32_t enc_len;
			msg.ran_ue_id = 777;
			enc_len = encode_ngap(enc_buf, sizeof(enc_buf), &msg, buf, (uint32_t)len);
			memset(&back, 0, sizeof(back));
			CHECK("encode_ngap rewrites RAN-UE-NGAP-ID 777 into the PDU",
					enc_len > 0
					&& decode_ngap(&back, enc_buf, (enc_len + 7) / 8)
					&& back.ran_ue_id == 777);
		}
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

/* ------------------------------------------------------------------ */
/* Issue #532: every per-message NGAP decoder. NGAP-PDU shares the     */
/* S1AP outer layout, so put_s1ap_pdu()/put_ie() lay out the PDU (CHOICE */
/* octet 0x00 initiating, 0x20 successful, 0x40 unsuccessful); the IE   */
/* values come from the library's own APER encoder.                    */
/* ------------------------------------------------------------------ */

/* APER-encode one IE value: its length in octets, 0 on failure */
static size_t ngap_ie_value(const asn_TYPE_descriptor_t *td, const void *sptr,
		uint8_t *out, size_t cap) {
	asn_enc_rval_t enc = aper_encode_to_buffer(td, NULL, sptr, out, cap);
	return enc.encoded > 0 ? (size_t)((enc.encoded + 7) / 8) : 0;
}

/* AMF-UE-NGAP-ID (INTEGER 0..2^40-1) under IE id ie_id */
static size_t put_ngap_amf_ie(uint8_t *out, uint16_t ie_id, uint64_t amf) {
	INTEGER_t v;
	uint8_t val[16];
	size_t n = 0;

	memset(&v, 0, sizeof(v));
	if (asn_int642INTEGER(&v, (int64_t)amf) == 0)
		n = ngap_ie_value(&asn_DEF_NGAP_AMF_UE_NGAP_ID, &v, val, sizeof(val));
	ASN_STRUCT_RESET(asn_DEF_NGAP_AMF_UE_NGAP_ID, &v);
	return n ? put_ie(out, ie_id, val, n) : 0;
}

static size_t put_ngap_ran_ie(uint8_t *out, unsigned long ran) {
	NGAP_RAN_UE_NGAP_ID_t v = ran;
	uint8_t val[16];
	size_t n = ngap_ie_value(&asn_DEF_NGAP_RAN_UE_NGAP_ID, &v, val, sizeof(val));
	return n ? put_ie(out, NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID, val, n) : 0;
}

static size_t put_ngap_nas_ie(uint8_t *out, const uint8_t *nas, size_t len) {
	uint8_t copy[32], val[40];
	OCTET_STRING_t v;
	size_t n;

	memcpy(copy, nas, len);
	memset(&v, 0, sizeof(v));
	v.buf  = copy;
	v.size = len;
	n = ngap_ie_value(&asn_DEF_NGAP_NAS_PDU, &v, val, sizeof(val));
	return n ? put_ie(out, NGAP_ProtocolIE_ID_id_NAS_PDU, val, n) : 0;
}

/* UE-NGAP-IDs CHOICE: the uE-NGAP-ID-pair arm when pair, else aMF-UE-NGAP-ID */
static size_t put_ngap_ue_ids_ie(uint8_t *out, int pair, uint64_t amf,
		unsigned long ran) {
	NGAP_UE_NGAP_IDs_t *ids = calloc(1, sizeof(*ids));
	INTEGER_t *amf_v;
	uint8_t val[32];
	size_t n = 0;

	if (ids == NULL)
		return 0;
	if (pair) {
		ids->present = NGAP_UE_NGAP_IDs_PR_uE_NGAP_ID_pair;
		ids->choice.uE_NGAP_ID_pair = calloc(1, sizeof(*ids->choice.uE_NGAP_ID_pair));
		if (ids->choice.uE_NGAP_ID_pair == NULL) {
			free(ids);
			return 0;
		}
		amf_v = &ids->choice.uE_NGAP_ID_pair->aMF_UE_NGAP_ID;
		ids->choice.uE_NGAP_ID_pair->rAN_UE_NGAP_ID = ran;
	} else {
		ids->present = NGAP_UE_NGAP_IDs_PR_aMF_UE_NGAP_ID;
		amf_v = &ids->choice.aMF_UE_NGAP_ID;
	}
	if (asn_int642INTEGER(amf_v, (int64_t)amf) == 0)
		n = ngap_ie_value(&asn_DEF_NGAP_UE_NGAP_IDs, ids, val, sizeof(val));
	ASN_STRUCT_FREE(asn_DEF_NGAP_UE_NGAP_IDs, ids);
	return n ? put_ie(out, NGAP_ProtocolIE_ID_id_UE_NGAP_IDs, val, n) : 0;
}

enum { NGAP_IDS_IES, NGAP_IDS_PAIR, NGAP_IDS_AMF_ONLY };

struct ngap_vector {
	const char      *name;
	uint8_t          choice;      /* NGAP-PDU CHOICE octet */
	uint8_t          procedure;
	NGAP_NGAP_PDU_PR present;
	uint16_t         amf_ie;      /* IE id carrying the AMF-UE-NGAP-ID */
	int              ids;         /* separate AMF/RAN IEs, or UE-NGAP-IDs arm */
	int              nas;         /* carries a NAS-PDU IE */
};

#define NGAP_INIT(name, proc, amf_ie, ids, nas) { name, 0x00, proc, \
	NGAP_NGAP_PDU_PR_initiatingMessage, amf_ie, ids, nas }
#define NGAP_SUCC(name, proc) { name, 0x20, proc, \
	NGAP_NGAP_PDU_PR_successfulOutcome, NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID, \
	NGAP_IDS_IES, 0 }
#define NGAP_AMF NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID

static const struct ngap_vector NGAP_VECTORS[] = {
	NGAP_INIT("DownlinkNASTransport", NGAP_ProcedureCode_id_DownlinkNASTransport,
			NGAP_AMF, NGAP_IDS_IES, 1),
	NGAP_INIT("UplinkNASTransport", NGAP_ProcedureCode_id_UplinkNASTransport,
			NGAP_AMF, NGAP_IDS_IES, 1),
	NGAP_INIT("UEContextReleaseCommand (UE-NGAP-ID-pair)",
			NGAP_ProcedureCode_id_UEContextRelease, 0, NGAP_IDS_PAIR, 0),
	NGAP_INIT("UEContextReleaseCommand (AMF-UE-NGAP-ID arm)",
			NGAP_ProcedureCode_id_UEContextRelease, 0, NGAP_IDS_AMF_ONLY, 0),
	NGAP_INIT("UEContextReleaseRequest", NGAP_ProcedureCode_id_UEContextReleaseRequest,
			NGAP_AMF, NGAP_IDS_IES, 0),
	NGAP_INIT("UERadioCapabilityInfoIndication",
			NGAP_ProcedureCode_id_UERadioCapabilityInfoIndication,
			NGAP_AMF, NGAP_IDS_IES, 0),
	NGAP_INIT("HandoverRequired", NGAP_ProcedureCode_id_HandoverPreparation,
			NGAP_AMF, NGAP_IDS_IES, 0),
	/* PathSwitchRequest names its AMF id SourceAMF-UE-NGAP-ID (id 100) */
	NGAP_INIT("PathSwitchRequest", NGAP_ProcedureCode_id_PathSwitchRequest,
			NGAP_ProtocolIE_ID_id_SourceAMF_UE_NGAP_ID, NGAP_IDS_IES, 0),
	NGAP_INIT("PDUSessionResourceSetupRequest",
			NGAP_ProcedureCode_id_PDUSessionResourceSetup, NGAP_AMF, NGAP_IDS_IES, 0),
	NGAP_INIT("HandoverNotify", NGAP_ProcedureCode_id_HandoverNotification,
			NGAP_AMF, NGAP_IDS_IES, 0),
	NGAP_SUCC("UEContextReleaseComplete", NGAP_ProcedureCode_id_UEContextRelease),
	NGAP_SUCC("InitialContextSetupResponse", NGAP_ProcedureCode_id_InitialContextSetup),
	NGAP_SUCC("HandoverRequestAcknowledge",
			NGAP_ProcedureCode_id_HandoverResourceAllocation),
	NGAP_SUCC("HandoverCommand", NGAP_ProcedureCode_id_HandoverPreparation),
	NGAP_SUCC("PDUSessionResourceSetupResponse",
			NGAP_ProcedureCode_id_PDUSessionResourceSetup),
	NGAP_SUCC("PathSwitchRequestAcknowledge", NGAP_ProcedureCode_id_PathSwitchRequest),
	{ "UEContextModificationFailure", 0x40, NGAP_ProcedureCode_id_UEContextModification,
	  NGAP_NGAP_PDU_PR_unsuccessfulOutcome, NGAP_AMF, NGAP_IDS_IES, 0 },
};

/* The PDU of v carrying amf/ran (and a NAS-PDU when v->nas); 0 on failure */
static size_t build_ngap_vector(uint8_t *pdu, const struct ngap_vector *v,
		uint64_t amf, unsigned long ran, const uint8_t *nas, size_t nas_len) {
	uint8_t ies[128], scratch[160];
	size_t n = 0, ie;
	uint16_t count = 0;

	if (v->ids == NGAP_IDS_IES) {
		if ((ie = put_ngap_amf_ie(ies + n, v->amf_ie, amf)) == 0)
			return 0;
		n += ie;
		if ((ie = put_ngap_ran_ie(ies + n, ran)) == 0)
			return 0;
		n += ie;
		count = 2;
	} else {
		if ((ie = put_ngap_ue_ids_ie(ies + n, v->ids == NGAP_IDS_PAIR, amf, ran)) == 0)
			return 0;
		n += ie;
		count = 1;
	}
	if (v->nas) {
		if ((ie = put_ngap_nas_ie(ies + n, nas, nas_len)) == 0)
			return 0;
		n += ie;
		count++;
	}
	return put_s1ap_pdu(pdu, v->choice, v->procedure, 0x00, count, ies, n, scratch);
}

static void test_ngap_message_decoders(void) {
	static const uint8_t nas[] = { 0x7E, 0x00, 0x56, 0x01 };
	char desc[160];
	size_t i;

	printf("NGAP per-message decoders (issue #532):\n");
	for (i = 0; i < sizeof(NGAP_VECTORS) / sizeof(NGAP_VECTORS[0]); i++) {
		const struct ngap_vector *v = &NGAP_VECTORS[i];
		/* 5-octet AMF ids and 4-octet RAN ids, distinct per vector */
		const uint64_t amf = 0x0123456789ULL + i, amf2 = 0xFEDCBA9876ULL - i;
		const unsigned long ran = 0x80000000UL + i, ran2 = 1000 + i;
		const int has_ran = v->ids != NGAP_IDS_AMF_ONLY;
		uint8_t pdu[192], out[256], nas_out[16];
		ngap_message_t msg, back;
		uint32_t enc;
		size_t n = build_ngap_vector(pdu, v, amf, ran, nas, sizeof(nas));

		snprintf(desc, sizeof(desc), "%s: vector builds", v->name);
		CHECK(desc, n > 0);
		if (n == 0)
			continue;

		memset(&msg, 0, sizeof(msg));
		snprintf(desc, sizeof(desc), "%s: decodes with procedure %u and its UE ids",
				v->name, v->procedure);
		CHECK(desc, try_decode_ngap(pdu, (uint32_t)n)
				&& decode_ngap(&msg, pdu, (uint32_t)n)
				&& msg.pdu_present == v->present
				&& msg.procedure_code == v->procedure
				&& msg.amf_ue_id == amf
				&& msg.ran_ue_id == (has_ran ? ran : 0));

		if (v->nas) {
			snprintf(desc, sizeof(desc), "%s: NAS-PDU extracted", v->name);
			CHECK(desc, msg.nas_pdu.size == sizeof(nas)
					&& get_nas_pdu(nas_out, sizeof(nas_out), pdu, (uint32_t)n) == sizeof(nas)
					&& memcmp(nas_out, nas, sizeof(nas)) == 0);
		}

		/* SET_ACTION: the same decoder writes the new ids into the PDU */
		msg.amf_ue_id = amf2;
		msg.ran_ue_id = ran2;
		enc = encode_ngap(out, sizeof(out), &msg, pdu, (uint32_t)n);
		memset(&back, 0, sizeof(back));
		snprintf(desc, sizeof(desc), "%s: encode_ngap rewrites the UE ids", v->name);
		CHECK(desc, enc > 0
				&& decode_ngap(&back, out, (enc + 7) / 8)
				&& back.pdu_present == v->present
				&& back.procedure_code == v->procedure
				&& back.amf_ue_id == amf2
				&& back.ran_ue_id == (has_ran ? ran2 : 0));
	}
}

/* Issue #523: both decoders are generated from the r16.1.0 modules. The
 * constants are the r16.1.0 ones, an IE r10.5.0 lacks round-trips through
 * the S1AP dissector's IE-by-IE ANY path, and decode_ngap() reads a
 * message procedure r15.2.0 lacks. */
static void test_rel16_generation(void) {
	static const uint8_t enc_alg[2] = { 0xE0, 0x00 };
	static const uint8_t int_alg[2] = { 0xC0, 0x00 };
	S1ap_NRUESecurityCapabilities_t *caps, *back = NULL;
	S1ap_IE_t ie, *ie_back = NULL;
	NGAP_NGAP_PDU_t *pdu;
	NGAP_SecondaryRATDataUsageReport_t *report;
	NGAP_ProtocolIE_Container_6976P77_t *ies;
	NGAP_SecondaryRATDataUsageReportIEs_t *nie;
	ngap_message_t msg;
	asn_enc_rval_t enc;
	asn_dec_rval_t rv;
	uint8_t buf[128];
	ssize_t len;

	printf("Rel-16 generation (issue #523):\n");
	CHECK("S1AP procedure codes are the r16.1.0 ones",
			S1ap_ProcedureCode_id_UEContextResume == 56
			&& S1ap_ProcedureCode_id_SecondaryRATDataUsageReport == 62);
	CHECK("S1AP protocol IE ids are the r16.1.0 ones",
			S1ap_ProtocolIE_ID_id_NRUESecurityCapabilities == 269);
	CHECK("NGAP procedure codes are the r16.1.0 ones",
			NGAP_ProcedureCode_id_SecondaryRATDataUsageReport == 52
			&& NGAP_ProtocolIE_ID_id_HandoverFlag == 143);

	/* S1AP: NRUESecurityCapabilities (id 269, r15+) as an S1ap-IE value */
	caps = calloc(1, sizeof(*caps));
	if (caps == NULL)
		return;
	OCTET_STRING_fromBuf((OCTET_STRING_t *)&caps->nRencryptionAlgorithms,
			(const char *)enc_alg, sizeof(enc_alg));
	OCTET_STRING_fromBuf((OCTET_STRING_t *)&caps->nRintegrityProtectionAlgorithms,
			(const char *)int_alg, sizeof(int_alg));
	memset(&ie, 0, sizeof(ie));
	ie.id = S1ap_ProtocolIE_ID_id_NRUESecurityCapabilities;
	ie.criticality = S1ap_Criticality_ignore;
	CHECK("r16-only S1AP IE value encodes into an S1ap-IE",
			ANY_fromType_aper(&ie.value, &asn_DEF_S1ap_NRUESecurityCapabilities, caps) == 0);
	ASN_STRUCT_FREE(asn_DEF_S1ap_NRUESecurityCapabilities, caps);
	enc = aper_encode_to_buffer(&asn_DEF_S1ap_IE, NULL, &ie, buf, sizeof(buf));
	ASN_STRUCT_RESET(asn_DEF_S1ap_IE, &ie);
	CHECK("S1ap-IE carrying it encodes", enc.encoded > 0);
	if (enc.encoded <= 0)
		return;
	rv = aper_decode(NULL, &asn_DEF_S1ap_IE, (void **)&ie_back, buf,
			(size_t)((enc.encoded + 7) / 8), 0, 0);
	CHECK("S1ap-IE decodes with its r16 id",
			rv.code == RC_OK && ie_back != NULL
			&& ie_back->id == S1ap_ProtocolIE_ID_id_NRUESecurityCapabilities);
	if (rv.code == RC_OK && ie_back != NULL
			&& ANY_to_type_aper(&ie_back->value,
					&asn_DEF_S1ap_NRUESecurityCapabilities, (void **)&back) == 0) {
		CHECK("its ANY value decodes as NRUESecurityCapabilities",
				back->nRencryptionAlgorithms.size == 2
				&& back->nRencryptionAlgorithms.buf[0] == 0xE0
				&& back->nRintegrityProtectionAlgorithms.size == 2
				&& back->nRintegrityProtectionAlgorithms.buf[0] == 0xC0);
	} else {
		CHECK("its ANY value decodes as NRUESecurityCapabilities", 0);
	}
	ASN_STRUCT_FREE(asn_DEF_S1ap_NRUESecurityCapabilities, back);
	ASN_STRUCT_FREE(asn_DEF_S1ap_IE, ie_back);

	/* NGAP: SecondaryRATDataUsageReport (procedure 52) carrying HandoverFlag
	 * (IE 143); the IE container is the asn1c instance the message's
	 * descriptor names (asn_DEF_NGAP_ProtocolIE_Container_6976P77) */
	pdu = calloc(1, sizeof(*pdu));
	if (pdu == NULL)
		return;
	pdu->present = NGAP_NGAP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage = calloc(1, sizeof(*pdu->choice.initiatingMessage));
	report = calloc(1, sizeof(*report));
	ies = calloc(1, sizeof(*ies));
	nie = calloc(1, sizeof(*nie));
	if (pdu->choice.initiatingMessage == NULL || report == NULL || ies == NULL || nie == NULL) {
		free(nie);
		free(ies);
		free(report);
		ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
		return;
	}
	pdu->choice.initiatingMessage->procedureCode =
			NGAP_ProcedureCode_id_SecondaryRATDataUsageReport;
	pdu->choice.initiatingMessage->criticality = NGAP_Criticality_ignore;
	pdu->choice.initiatingMessage->value.present =
			NGAP_InitiatingMessage__value_PR_SecondaryRATDataUsageReport;
	pdu->choice.initiatingMessage->value.choice.SecondaryRATDataUsageReport = report;
	report->protocolIEs = (struct NGAP_ProtocolIE_Container *)ies;
	nie->id = NGAP_ProtocolIE_ID_id_HandoverFlag;
	nie->criticality = NGAP_Criticality_ignore;
	nie->value.present = NGAP_SecondaryRATDataUsageReportIEs__value_PR_HandoverFlag;
	nie->value.choice.HandoverFlag = calloc(1, sizeof(*nie->value.choice.HandoverFlag));
	if (nie->value.choice.HandoverFlag != NULL)
		*nie->value.choice.HandoverFlag = NGAP_HandoverFlag_handover_preparation;
	ASN_SEQUENCE_ADD(&ies->list, nie);
	len = encode_ngap_pdu(pdu, buf, sizeof(buf));
	ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
	CHECK("r16-only NGAP message encodes", len > 0);
	if (len <= 0)
		return;
	memset(&msg, 0, sizeof(msg));
	CHECK("decode_ngap reads the r16-only procedure",
			decode_ngap(&msg, buf, (uint32_t)len)
			&& msg.pdu_present == NGAP_NGAP_PDU_PR_initiatingMessage
			&& msg.procedure_code == NGAP_ProcedureCode_id_SecondaryRATDataUsageReport);
}

/* Issue #523: an InitialContextSetupRequest encoded by a codec independent
 * of the derived S1AP schema -- asn1c v1.5.3 run on the unmodified,
 * class-based 36413-g10.asn (ASN1C_PREFIX=S1AP_ -findirect-choice, the
 * recipe's codec flags). It carries Rel-16 content inside the containers
 * s1ap-simplify.py rewrites: the E-RAB list item has an iE-Extensions
 * (BearerType, id 233) and its QoS parameters one too (Packet-LossRate,
 * id 273), and the message carries NRUESecurityCapabilities (id 269). The
 * derived schema must decode every level of it. */
static const uint8_t REL16_ICS_REQUEST[] = {
	0x00, 0x09, 0x00, 0x7d, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x02, 0x00,
	0x07, 0x00, 0x08, 0x00, 0x02, 0x00, 0x09, 0x00, 0x42, 0x00, 0x0a, 0x18,
	0x05, 0xf5, 0xe1, 0x00, 0x60, 0x02, 0xfa, 0xf0, 0x80, 0x00, 0x18, 0x00,
	0x26, 0x00, 0x00, 0x34, 0x00, 0x21, 0x65, 0x20, 0x09, 0x04, 0x00, 0x00,
	0x01, 0x11, 0x40, 0x02, 0x00, 0x0a, 0x0f, 0x80, 0xc0, 0xa8, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x01, 0x03, 0x07, 0x42, 0x01, 0x00, 0x00, 0x00, 0xe9,
	0x00, 0x01, 0x00, 0x00, 0x6b, 0x00, 0x05, 0x1c, 0x00, 0x0e, 0x00, 0x00,
	0x00, 0x49, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x0d, 0x40, 0x05, 0x1c, 0x00, 0x0e, 0x00, 0x00,
};

/* Decode one ANY into `td`; 1 when it decodes. */
static int any_decodes(ANY_t *any, asn_TYPE_descriptor_t *td, void **out) {
	*out = NULL;
	return ANY_to_type_aper(any, td, out) == 0 && *out != NULL;
}

static void test_s1ap_rel16_independent_vector(void) {
	static const struct { long id; asn_TYPE_descriptor_t *td; } ies[] = {
		{ S1ap_ProtocolIE_ID_id_MME_UE_S1AP_ID, &asn_DEF_S1ap_MME_UE_S1AP_ID },
		{ S1ap_ProtocolIE_ID_id_eNB_UE_S1AP_ID, &asn_DEF_S1ap_ENB_UE_S1AP_ID },
		{ S1ap_ProtocolIE_ID_id_uEaggregateMaximumBitrate, &asn_DEF_S1ap_UEAggregateMaximumBitrate },
		{ S1ap_ProtocolIE_ID_id_E_RABToBeSetupListCtxtSUReq, &asn_DEF_S1ap_E_RABToBeSetupListCtxtSUReq },
		{ S1ap_ProtocolIE_ID_id_UESecurityCapabilities, &asn_DEF_S1ap_UESecurityCapabilities },
		{ S1ap_ProtocolIE_ID_id_SecurityKey, &asn_DEF_S1ap_SecurityKey },
		{ S1ap_ProtocolIE_ID_id_NRUESecurityCapabilities, &asn_DEF_S1ap_NRUESecurityCapabilities },
	};
	static const uint8_t SGW[4] = { 192, 168, 0, 1 };
	s1ap_message_t msg;
	S1AP_PDU_t *pdu = NULL;
	S1ap_InitialContextSetupRequest_t *req = NULL;
	S1ap_E_RABToBeSetupListCtxtSUReq_t *list = NULL;
	S1ap_E_RABToBeSetupItemCtxtSUReq_t *item = NULL;
	asn_dec_rval_t rv;
	void *value;
	int i, decoded = 0;

	printf("S1AP Rel-16 vector from the class-based codec (issue #523):\n");
	memset(&msg, 0, sizeof(msg));
	CHECK("s1ap_decode accepts it",
			s1ap_decode(&msg, REL16_ICS_REQUEST, sizeof(REL16_ICS_REQUEST)) == 0);
	CHECK("procedure, QCI, ARP, TEID and gateway extracted",
			msg.procedure_code == S1ap_ProcedureCode_id_InitialContextSetup
			&& msg.qos_qci == 9 && msg.qos_priority_level == 1
			&& msg.gtp_teid == 1 && memcmp(&msg.gw_ipv4, SGW, 4) == 0);

	rv = aper_decode(NULL, &asn_DEF_S1AP_PDU, (void **)&pdu,
			REL16_ICS_REQUEST, sizeof(REL16_ICS_REQUEST), 0, 0);
	/* aper_decode() reports the bits it consumed */
	CHECK("the whole PDU is consumed",
			rv.code == RC_OK && rv.consumed == 8 * sizeof(REL16_ICS_REQUEST)
			&& pdu->present == S1AP_PDU_PR_initiatingMessage
			&& pdu->choice.initiatingMessage != NULL);
	if (rv.code != RC_OK || pdu->choice.initiatingMessage == NULL
			|| !any_decodes(&pdu->choice.initiatingMessage->value,
					&asn_DEF_S1ap_InitialContextSetupRequest, (void **)&req)) {
		CHECK("message body decodes", 0);
		ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
		return;
	}
	CHECK("message body holds the 7 IEs",
			req->s1ap_InitialContextSetupRequest_ies.list.count == 7);
	for (i = 0; i < req->s1ap_InitialContextSetupRequest_ies.list.count && i < 7; i++) {
		S1ap_IE_t *ie = req->s1ap_InitialContextSetupRequest_ies.list.array[i];
		if (ie->id != ies[i].id || !any_decodes(&ie->value, ies[i].td, &value))
			continue;
		decoded++;
		if (ies[i].td == &asn_DEF_S1ap_E_RABToBeSetupListCtxtSUReq)
			list = value;
		else
			ASN_STRUCT_FREE(*ies[i].td, value);
	}
	CHECK("every IE value decodes into its derived type", decoded == 7);
	if (list != NULL && list->list.count == 1
			&& any_decodes(&list->list.array[0]->value,
					&asn_DEF_S1ap_E_RABToBeSetupItemCtxtSUReq, (void **)&item)) {
		const S1ap_IE_Extensions_t *ext = item->iE_Extensions;
		const S1ap_IE_Extensions_t *qext = item->e_RABlevelQoSParameters
				? item->e_RABlevelQoSParameters->iE_Extensions : NULL;
		S1ap_BearerType_t *bt = NULL;
		S1ap_Packet_LossRate_t *plr = NULL;
		CHECK("E-RAB item extension BearerType (id 233) decodes",
				ext && ext->list.count == 1 && ext->list.array[0]->id == 233
				&& any_decodes(&ext->list.array[0]->value, &asn_DEF_S1ap_BearerType, (void **)&bt)
				&& *bt == S1ap_BearerType_non_IP);
		CHECK("QoS extension Packet-LossRate (id 273) decodes",
				qext && qext->list.count == 1 && qext->list.array[0]->id == 273
				&& any_decodes(&qext->list.array[0]->value, &asn_DEF_S1ap_Packet_LossRate, (void **)&plr)
				&& *plr == 10);
		ASN_STRUCT_FREE(asn_DEF_S1ap_BearerType, bt);
		ASN_STRUCT_FREE(asn_DEF_S1ap_Packet_LossRate, plr);
	} else {
		CHECK("E-RAB item decodes", 0);
	}
	ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABToBeSetupItemCtxtSUReq, item);
	ASN_STRUCT_FREE(asn_DEF_S1ap_E_RABToBeSetupListCtxtSUReq, list);
	ASN_STRUCT_FREE(asn_DEF_S1ap_InitialContextSetupRequest, req);
	ASN_STRUCT_FREE(asn_DEF_S1AP_PDU, pdu);
}

int main(void) {
	/* The logger reads MMT_DPI_LOG_LEVEL once: run with its default (off). */
	unsetenv("MMT_DPI_LOG_LEVEL");
	test_s1ap_outer_ok_inner_fail();
	test_s1ap_valid_vectors();
	test_s1ap_corpus_initial_ue_message();
	test_s1ap_ics_request_ue_ipv4();
	test_s1ap_nas_ciphering();
	test_s1ap_spec_vectors();
	test_open_type_split_length();
	test_s1ap_split_length_message();
	test_s1ap_short_imsi();
	test_ngap_get_nas_pdu();
	test_s1ap_decode_failure_no_leak();
	test_s1ap_entity_store_cap();
	test_ngap_choice_discriminant();
	test_ngap_message_decoders();
	test_rel16_generation();
	test_s1ap_rel16_independent_vector();
	test_s1ap_malformed_pdus_silent();

	printf("\n%d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}

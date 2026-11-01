/*
 * test_s1ap_ngap_packets.c
 *
 * Packet-level regression tests for issue #207 — SCTP-carried mobile
 * protocols (NGAP, S1AP, Diameter). Unlike test_s1ap_ngap_decode.c, which
 * calls the decoders directly, this binary crafts whole
 * Ethernet/IPv4/SCTP frames and drives them through packet_process() with
 * the installed plugins loaded via init_extraction() — the shipped
 * classifier configuration.
 *
 * Oracles:
 *  - Under SANITIZE=asan any out-of-bounds read aborts the process, so
 *    reaching the end is itself the memory-safety assertion.
 *  - The classified protocol path pins down the classification contract:
 *
 *    F-BUG-079: a DATA chunk whose declared length is smaller than the
 *      16-byte DATA header (length underflow) or larger than the capture
 *      must not make the NGAP classifier decode past the captured bytes.
 *    F-BUG-080: PPID 46 classifies Diameter only when the whole 20-byte
 *      Diameter header is captured; the port-based fallback must prove the
 *      header too.
 *
 * Issue #507 (F-BUG-201): S1AP attribute extraction caches the parsed packet
 * per thread. The cache used to be keyed by packet_id alone — a per-handler
 * counter — and held raw pointers into the process-global entity store, so
 * a second handler on the same thread was served the first handler's packet
 * and, once a handler close had freed the store, read freed entities. The
 * two-handler scenario below asserts each handler sees its own packet, and
 * under SANITIZE=asan that no freed entity is read.
 *
 * Issue #574 (F-BUG-203): the S1AP ids of a UE are unique per node, so two
 * eNodeBs reusing an eNB-UE-S1AP-ID keep two UEs, and a
 * UEContextReleaseComplete removes the UE it names; the Rel-16 IEs mapped
 * into s1ap.nr_encryption_algorithms and ngap.srvcc_operation_possible are
 * extracted from whole frames, and from the accuracy-corpus captures
 * acc_s1ap_rel16_positive.pcap / acc_ngap_rel16_positive.pcap
 * (tools/phase0/ci/accuracy/, the directory given as argv[1]).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "mobile/mmt_mobile.h"
#include "mobile/proto_s1ap.h"
#include "mobile/proto_ngap.h"

static int failures = 0;
static int checks   = 0;

#define CHECK(desc, cond) do { \
	checks++; \
	if (cond) { printf("  ok   %s\n", desc); } \
	else      { printf("  FAIL %s\n", desc); failures++; } \
} while (0)

/* Wire-valid NGAP initiatingMessage (id-InitialUEMessage, RAN-UE-NGAP-ID
 * 12345) produced by the library's own APER encoder — the positive control
 * for the PPID-0 port-fallback decode path. */
static const uint8_t NGAP_WIRE[] = {
	0x00, 0x0f, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x00,
	0x55, 0x00, 0x03, 0x40, 0x30, 0x39
};

/* S1SetupRequest: Global-ENB-ID (PLMN 001/01, macro eNB 1), eNBname
 * "enb01", SupportedTAs (TAC 1), DefaultPagingDRX v128 — the pycrate vector
 * of test_s1ap_ngap_decode.c. S1SETUP_NAME_DIGIT indexes the name's last
 * character, so the same PDU names another eNodeB ("enb02"). */
static const uint8_t S1SETUP_REQUEST[] = {
	0x00, 0x11, 0x00, 0x2a, 0x00, 0x00, 0x04, 0x00, 0x3b, 0x00,
	0x08, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00,
	0x3c, 0x40, 0x07, 0x02, 0x00, 0x65, 0x6e, 0x62, 0x30, 0x31,
	0x00, 0x40, 0x00, 0x07, 0x00, 0x00, 0x00, 0x40, 0x00, 0xf1,
	0x10, 0x00, 0x89, 0x40, 0x01, 0x40
};
#define S1SETUP_NAME_DIGIT 29

/* Issue #574: InitialUEMessage naming its UE by eNB-UE-S1AP-ID 5 only,
 * and the UEContextReleaseComplete (MME-UE-S1AP-ID 7, eNB-UE-S1AP-ID 5)
 * test_s1ap_ngap_decode.c decodes */
static const uint8_t S1AP_INITIAL_UE_ENB5[] = {
	0x00, 0x0c, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00,
	0x02, 0x00, 0x05
};
static const uint8_t S1AP_RELEASE_COMPLETE[] = {
	0x20, 0x17, 0x00, 0x0f, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x07, 0x00, 0x08, 0x00, 0x02, 0x00, 0x05
};

/* The InitialContextSetupRequest of test_s1ap_ngap_decode.c encoded by the
 * class-based codec (issue #523); its Rel-16 NRUESecurityCapabilities
 * (IE 269) lists NEA1-NEA3 and NIA1-NIA3. */
static const uint8_t S1AP_REL16_ICS_REQUEST[] = {
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

/* The NGAP DownlinkNASTransport of test_s1ap_ngap_decode.c carrying the
 * Rel-16 SRVCCOperationPossible (IE 177) notPossible */
static const uint8_t NGAP_DL_NAS_SRVCC[] = {
	0x00, 0x04, 0x40, 0x1d, 0x00, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x02, 0x00,
	0x01, 0x00, 0x55, 0x00, 0x02, 0x00, 0x02, 0x00, 0x26, 0x00, 0x05, 0x04,
	0x7e, 0x00, 0x56, 0x01, 0x00, 0xb1, 0x00, 0x01, 0x40
};

/* ------------------------------------------------------------------ */

static char g_path[512];

/* IPv4 addresses of the frames build_sctp_data_frame() builds */
static uint8_t g_ip_src[4] = { 10, 0, 0, 0 };
static uint8_t g_ip_dst[4] = { 192, 168, 0, 0 };

/* what the S1AP packet handler extracted from the last packet */
static char g_enb_name[64];
static char g_enb_entity_name[S1AP_ENTITY_NAME_LENGTH];

static int packet_handler(const ipacket_t *ipacket, void *user_args) {
	(void)user_args;
	int len = 0, i;
	const proto_hierarchy_t *ph = ipacket->proto_hierarchy;
	g_path[0] = '\0';
	if (ph == NULL || ph->len <= 0)
		return 0;
	for (i = 0; i < ph->len && i < PROTO_PATH_SIZE; i++) {
		const char *name = get_protocol_name_by_id(ph->proto_path[i]);
		int n = snprintf(g_path + len, sizeof(g_path) - len, i ? ".%s" : "%s",
				name ? name : "?");
		if (n < 0 || n >= (int)(sizeof(g_path) - len))
			break;
		len += n;
	}
	return 0;
}

static int s1ap_packet_handler(const ipacket_t *ipacket, void *user_args) {
	const mmt_binary_data_t *name;
	const mmt_binary_var_data_t *ent;
	(void)user_args;
	g_enb_name[0] = '\0';
	g_enb_entity_name[0] = '\0';
	name = get_attribute_extracted_data(ipacket, PROTO_S1AP, S1AP_ATT_ENB_NAME);
	if (name != NULL && name->len < sizeof(g_enb_name)) {
		memcpy(g_enb_name, name->data, name->len);
		g_enb_name[name->len] = '\0';
	}
	/* the entity is copied out of the extraction cache: under ASan this
	 * read is the use-after-free oracle */
	ent = get_attribute_extracted_data(ipacket, PROTO_S1AP, S1AP_ATT_ENTITY_ENODEB);
	if (ent != NULL && ent->len == sizeof(s1ap_entity_t)) {
		s1ap_entity_t e;
		memcpy(&e, ent->data, sizeof(e));
		memcpy(g_enb_entity_name, e.data.enb.name, sizeof(g_enb_entity_name));
		g_enb_entity_name[sizeof(g_enb_entity_name) - 1] = '\0';
	}
	return 0;
}

static mmt_handler_t *s1ap_handler(void) {
	char errbuf[1024];
	mmt_handler_t *h = mmt_init_handler(1 /*DLT_EN10MB*/, 0, errbuf);
	if (h == NULL) {
		fprintf(stderr, "mmt_init_handler: %s\n", errbuf);
		exit(1);
	}
	register_extraction_attribute(h, PROTO_S1AP, S1AP_ATT_ENB_NAME);
	register_extraction_attribute(h, PROTO_S1AP, S1AP_ATT_ENTITY_ENODEB);
	register_packet_handler(h, 1, s1ap_packet_handler, NULL);
	return h;
}

/*
 * One Ethernet/IPv4/SCTP+DATA frame. The DATA chunk's declared length is
 * attacker-controlled and may disagree with the bytes actually captured;
 * the frame is malloc'd tight so any read past it aborts under ASan.
 */
static uint8_t *build_sctp_data_frame(size_t *out_len,
		uint16_t sport, uint16_t dport, uint32_t ppid,
		uint16_t declared_chunk_len,
		const uint8_t *payload, size_t payload_len) {
	const size_t eth = 14, ip = 20, sctp = 12, dhdr = 16;
	size_t total = eth + ip + sctp + dhdr + payload_len;
	uint8_t *f = calloc(1, total);
	uint8_t *p = f;
	uint16_t tot;

	/* ethernet */
	memset(p, 0x02, 6); memset(p + 6, 0x03, 6);
	p[12] = 0x08; p[13] = 0x00;
	p += eth;
	/* ipv4: ihl=5, proto=132 (SCTP) */
	p[0] = 0x45;
	p[8] = 64; p[9] = 132;
	tot = (uint16_t)(ip + sctp + dhdr + payload_len);
	p[2] = (uint8_t)(tot >> 8); p[3] = (uint8_t)(tot & 0xFF);
	memcpy(p + 12, g_ip_src, 4);
	memcpy(p + 16, g_ip_dst, 4);
	p += ip;
	/* sctp common header */
	p[0] = (uint8_t)(sport >> 8); p[1] = (uint8_t)(sport & 0xFF);
	p[2] = (uint8_t)(dport >> 8); p[3] = (uint8_t)(dport & 0xFF);
	p[4] = 0x12; p[5] = 0x34; p[6] = 0x56; p[7] = 0x78;
	p += sctp;
	/* DATA chunk: type=0, flags=3, length=declared, tsn, stream, ssn, ppid */
	p[0] = 0x00; p[1] = 0x03;
	p[2] = (uint8_t)(declared_chunk_len >> 8);
	p[3] = (uint8_t)(declared_chunk_len & 0xFF);
	p[4] = 0; p[5] = 0; p[6] = 0x03; p[7] = 0xE8;   /* tsn=1000 */
	p[10] = 0; p[11] = 1;                          /* ssn=1 */
	p[12] = (uint8_t)(ppid >> 24); p[13] = (uint8_t)(ppid >> 16);
	p[14] = (uint8_t)(ppid >> 8);  p[15] = (uint8_t)ppid;
	p += dhdr;
	memcpy(p, payload, payload_len);
	*out_len = total;
	return f;
}

/*
 * A frame whose capture ends inside the 16-byte DATA chunk header —
 * exercises the "is the whole datahdr captured" bounds added for the
 * mobile classifiers.
 */
static uint8_t *build_sctp_short_chunk_frame(size_t *out_len,
		uint16_t sport, uint16_t dport, size_t chunk_bytes) {
	const size_t eth = 14, ip = 20, sctp = 12;
	size_t total;
	uint8_t *f, *p;
	uint16_t tot;
	uint8_t chunk[16] = {0};

	if (chunk_bytes > 16)
		chunk_bytes = 16;
	total = eth + ip + sctp + chunk_bytes;
	f = calloc(1, total);
	p = f;

	memset(p, 0x02, 6); memset(p + 6, 0x03, 6);
	p[12] = 0x08; p[13] = 0x00;
	p += eth;
	p[0] = 0x45;
	p[8] = 64; p[9] = 132;
	tot = (uint16_t)(ip + sctp + chunk_bytes);
	p[2] = (uint8_t)(tot >> 8); p[3] = (uint8_t)(tot & 0xFF);
	p[12] = 10; p[16] = 192; p[17] = 168;
	p += ip;
	p[0] = (uint8_t)(sport >> 8); p[1] = (uint8_t)(sport & 0xFF);
	p[2] = (uint8_t)(dport >> 8); p[3] = (uint8_t)(dport & 0xFF);
	p[4] = 0x12; p[5] = 0x34; p[6] = 0x56; p[7] = 0x78;
	p += sctp;
	chunk[0] = 0x00; chunk[1] = 0x03;   /* DATA, declared length 16 */
	chunk[2] = 0x00; chunk[3] = 0x10;
	memcpy(p, chunk, chunk_bytes);
	*out_len = total;
	return f;
}

static void drive(mmt_handler_t *h, const uint8_t *frame, size_t len) {
	struct pkthdr hdr;
	memset(&hdr, 0, sizeof(hdr));
	hdr.caplen = len;
	hdr.len    = len;
	g_path[0] = '\0';
	packet_process(h, &hdr, frame);
}

/* feed an S1SetupRequest naming eNodeB "enb0<digit>" to h, then assert the
 * extracted eNB name and eNodeB entity are that packet's */
static void expect_s1ap_enb(mmt_handler_t *h, const char *label, char digit) {
	uint8_t pdu[sizeof(S1SETUP_REQUEST)];
	char want[8], desc[512];
	size_t flen;
	uint8_t *f;

	memcpy(pdu, S1SETUP_REQUEST, sizeof(pdu));
	pdu[S1SETUP_NAME_DIGIT] = (uint8_t)digit;
	snprintf(want, sizeof(want), "enb0%c", digit);
	f = build_sctp_data_frame(&flen, 36412, 36412, 18, 16 + sizeof(pdu),
			pdu, sizeof(pdu));
	drive(h, f, flen);
	free(f);
	snprintf(desc, sizeof(desc), "%s: enb_name %s (got \"%s\"), enb_entity %s (got \"%s\")",
			label, want, g_enb_name, want, g_enb_entity_name);
	CHECK(desc, strcmp(g_enb_name, want) == 0 &&
			strcmp(g_enb_entity_name, want) == 0);
}

/*
 * Issue #507 (F-BUG-201): two handlers on one thread with identical packet
 * ids. Each must be served its own packet, never the other handler's cached
 * one; and after a handler close frees the shared entity store, a handler
 * reaching the same packet id must not read the freed entities.
 */
static void test_s1ap_two_handlers(void) {
	mmt_handler_t *a = s1ap_handler();
	mmt_handler_t *b = s1ap_handler();
	mmt_handler_t *c;
	size_t flen;
	uint8_t *f;

	expect_s1ap_enb(a, "S1AP handler A packet 1", '1');
	expect_s1ap_enb(b, "S1AP handler B packet 1 (same id as A's)", '2');
	expect_s1ap_enb(a, "S1AP handler A packet 2", '2');
	expect_s1ap_enb(b, "S1AP handler B packet 2 (same id as A's)", '1');

	/* closing B runs the S1AP cleanup, which frees the entity store the
	 * cached packet 2 points into. C differs from B here, so the handler
	 * part of the cache key causes the miss; the store generation is the
	 * guard when the allocator hands C B's address (never under ASan's
	 * quarantine), so this sequence does not single it out. */
	mmt_close_handler(b);
	c = s1ap_handler();
	/* C's packet 1 carries no S1AP, so its packet 2 is the first one that
	 * reaches the extraction — with the cached packet's id */
	f = build_sctp_short_chunk_frame(&flen, 36412, 36412, 8);
	drive(c, f, flen);
	free(f);
	expect_s1ap_enb(c, "S1AP handler C packet 2 after B closed", '3');
	expect_s1ap_enb(a, "S1AP handler A packet 3 after B closed", '4');

	mmt_close_handler(c);
	mmt_close_handler(a);
}

/* ------------------------------------------------------------------ */
/* Issue #574: UE keying per node, release, Rel-16 IE attributes        */
/* ------------------------------------------------------------------ */

static uint32_t g_ue_id;      /* s1ap.ue_id, 0 when not extracted */
static int      g_nr_enc;     /* s1ap.nr_encryption_algorithms, -1 when not */
static int      g_nr_int;     /* s1ap.nr_integrity_algorithms, -1 when not */
static int      g_srvcc;      /* ngap.srvcc_operation_possible, -1 when not */
static int      g_proc;       /* s1ap/ngap.procedure_code, -1 when not */

static int mobile_attr_handler(const ipacket_t *ipacket, void *user_args) {
	const uint32_t *ue  = get_attribute_extracted_data(ipacket, PROTO_S1AP, S1AP_ATT_UE_ID);
	const uint16_t *enc = get_attribute_extracted_data(ipacket, PROTO_S1AP, S1AP_ATT_NR_ENCRYPTION_ALGORITHMS);
	const uint16_t *itg = get_attribute_extracted_data(ipacket, PROTO_S1AP, S1AP_ATT_NR_INTEGRITY_ALGORITHMS);
	const uint8_t *srvcc = get_attribute_extracted_data(ipacket, PROTO_NGAP, NGAP_ATT_SRVCC_OPERATION_POSSIBLE);
	const uint16_t *s1proc = get_attribute_extracted_data(ipacket, PROTO_S1AP, S1AP_ATT_PROCEDURE_CODE);
	const uint16_t *ngproc = get_attribute_extracted_data(ipacket, PROTO_NGAP, NGAP_ATT_PROCEDURE_CODE);
	(void)user_args;
	g_proc   = s1proc ? *s1proc : ngproc ? *ngproc : -1;
	g_ue_id  = ue  ? *ue  : 0;
	g_nr_enc = enc ? *enc : -1;
	g_nr_int = itg ? *itg : -1;
	g_srvcc  = srvcc ? *srvcc : -1;
	return 0;
}

/* drive one S1AP (PPID 18) or NGAP (PPID 60) PDU from src to dst */
static void drive_mobile(mmt_handler_t *h, const uint8_t src[4], const uint8_t dst[4],
		uint16_t port, uint32_t ppid, const uint8_t *pdu, size_t len) {
	size_t flen;
	uint8_t *f;

	memcpy(g_ip_src, src, 4);
	memcpy(g_ip_dst, dst, 4);
	f = build_sctp_data_frame(&flen, port, port, ppid, (uint16_t)(16 + len), pdu, len);
	g_ue_id = 0;
	g_nr_enc = g_nr_int = g_srvcc = -1;
	drive(h, f, flen);
	free(f);
}

static uint32_t drive_s1ap_ue(mmt_handler_t *h, const uint8_t enb[4],
		const uint8_t mme[4], const uint8_t *pdu, size_t len) {
	drive_mobile(h, enb, mme, 36412, 18, pdu, len);
	return g_ue_id;
}

static void test_mobile_ue_keying_and_rel16(void) {
	static const uint8_t ENB_A[4] = { 10, 0, 0, 1 }, ENB_B[4] = { 10, 0, 0, 2 };
	static const uint8_t MME[4] = { 10, 0, 0, 100 }, AMF[4] = { 10, 0, 0, 200 };
	static const uint8_t GNB[4] = { 10, 0, 0, 3 };
	static const uint8_t SRC0[4] = { 10, 0, 0, 0 }, DST0[4] = { 192, 168, 0, 0 };
	char errbuf[1024];
	uint32_t a, b, a2;
	mmt_handler_t *h = mmt_init_handler(1 /*DLT_EN10MB*/, 0, errbuf);

	if (h == NULL) {
		fprintf(stderr, "mmt_init_handler: %s\n", errbuf);
		exit(1);
	}
	register_extraction_attribute(h, PROTO_S1AP, S1AP_ATT_UE_ID);
	register_extraction_attribute(h, PROTO_S1AP, S1AP_ATT_NR_ENCRYPTION_ALGORITHMS);
	register_extraction_attribute(h, PROTO_S1AP, S1AP_ATT_NR_INTEGRITY_ALGORITHMS);
	register_extraction_attribute(h, PROTO_NGAP, NGAP_ATT_SRVCC_OPERATION_POSSIBLE);
	register_packet_handler(h, 1, mobile_attr_handler, NULL);

	a = drive_s1ap_ue(h, ENB_A, MME, S1AP_INITIAL_UE_ENB5, sizeof(S1AP_INITIAL_UE_ENB5));
	b = drive_s1ap_ue(h, ENB_B, MME, S1AP_INITIAL_UE_ENB5, sizeof(S1AP_INITIAL_UE_ENB5));
	CHECK("S1AP: two eNodeBs reusing eNB-UE-S1AP-ID 5 keep two UEs",
			a > 0 && b > 0 && a != b);
	CHECK("S1AP: eNodeB A's id 5 again names its UE",
			drive_s1ap_ue(h, ENB_A, MME, S1AP_INITIAL_UE_ENB5, sizeof(S1AP_INITIAL_UE_ENB5)) == a);
	CHECK("S1AP: UEContextReleaseComplete reports the UE it releases",
			drive_s1ap_ue(h, ENB_A, MME, S1AP_RELEASE_COMPLETE, sizeof(S1AP_RELEASE_COMPLETE)) == a);
	a2 = drive_s1ap_ue(h, ENB_A, MME, S1AP_INITIAL_UE_ENB5, sizeof(S1AP_INITIAL_UE_ENB5));
	CHECK("S1AP: after the release eNodeB A's id 5 is a new UE",
			a2 > 0 && a2 != a && a2 != b);
	CHECK("S1AP: eNodeB B's UE is untouched by A's release",
			drive_s1ap_ue(h, ENB_B, MME, S1AP_INITIAL_UE_ENB5, sizeof(S1AP_INITIAL_UE_ENB5)) == b);

	drive_mobile(h, MME, ENB_A, 36412, 18, S1AP_REL16_ICS_REQUEST, sizeof(S1AP_REL16_ICS_REQUEST));
	CHECK("S1AP: Rel-16 NRUESecurityCapabilities extracted (NEA1-3, NIA1-3)",
			g_nr_enc == 0xE000 && g_nr_int == 0xE000);
	drive_mobile(h, ENB_A, MME, 36412, 18, S1AP_INITIAL_UE_ENB5, sizeof(S1AP_INITIAL_UE_ENB5));
	CHECK("S1AP: a message without it extracts none", g_nr_enc == -1 && g_nr_int == -1);

	drive_mobile(h, AMF, GNB, 38412, 60, NGAP_DL_NAS_SRVCC, sizeof(NGAP_DL_NAS_SRVCC));
	CHECK("NGAP: Rel-16 SRVCCOperationPossible extracted (notPossible)", g_srvcc == 1);

	memcpy(g_ip_src, SRC0, 4);
	memcpy(g_ip_dst, DST0, 4);
	mmt_close_handler(h);
}

/* Issue #574: replay an accuracy-corpus capture (classic little-endian
 * pcap, LINKTYPE_ETHERNET, as the corpus generator writes it)
 * through h; the attributes of its last packet stay in g_*. Returns the
 * packet count, -1 when the file cannot be read. */
static int replay_corpus_pcap(mmt_handler_t *h, const char *dir, const char *name,
		uint16_t *proc) {
	static const uint8_t PCAP_MAGIC_LE[4] = { 0xd4, 0xc3, 0xb2, 0xa1 };
	static uint8_t frame[65535];
	char path[1024];
	uint8_t ghdr[24], rhdr[16];
	uint32_t caplen;
	int n = 0;
	FILE *fp;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fp = fopen(path, "rb");
	if (fp == NULL)
		return -1;
	if (fread(ghdr, 1, sizeof(ghdr), fp) != sizeof(ghdr)
			|| memcmp(ghdr, PCAP_MAGIC_LE, 4) != 0
			|| ghdr[20] != 1 || ghdr[21] || ghdr[22] || ghdr[23]) {
		fclose(fp);
		return -1;
	}
	while (fread(rhdr, 1, sizeof(rhdr), fp) == sizeof(rhdr)) {
		caplen = (uint32_t)rhdr[8] | (uint32_t)rhdr[9] << 8
			| (uint32_t)rhdr[10] << 16 | (uint32_t)rhdr[11] << 24;
		if (caplen > sizeof(frame) || fread(frame, 1, caplen, fp) != caplen) {
			fclose(fp);
			return -1;
		}
		g_ue_id = 0;
		g_nr_enc = g_nr_int = g_srvcc = -1;
		g_proc = -1;
		drive(h, frame, caplen);
		n++;
	}
	fclose(fp);
	*proc = (uint16_t)g_proc;
	return n;
}

static void test_mobile_rel16_corpus(const char *dir) {
	char errbuf[1024];
	uint16_t proc = 0;
	int n;
	mmt_handler_t *h = mmt_init_handler(1 /*DLT_EN10MB*/, 0, errbuf);

	if (h == NULL) {
		fprintf(stderr, "mmt_init_handler: %s\n", errbuf);
		exit(1);
	}
	register_extraction_attribute(h, PROTO_S1AP, S1AP_ATT_PROCEDURE_CODE);
	register_extraction_attribute(h, PROTO_S1AP, S1AP_ATT_NR_ENCRYPTION_ALGORITHMS);
	register_extraction_attribute(h, PROTO_S1AP, S1AP_ATT_NR_INTEGRITY_ALGORITHMS);
	register_extraction_attribute(h, PROTO_NGAP, NGAP_ATT_PROCEDURE_CODE);
	register_extraction_attribute(h, PROTO_NGAP, NGAP_ATT_SRVCC_OPERATION_POSSIBLE);
	register_packet_handler(h, 1, mobile_attr_handler, NULL);
	register_packet_handler(h, 2, packet_handler, NULL);

	n = replay_corpus_pcap(h, dir, "acc_s1ap_rel16_positive.pcap", &proc);
	CHECK("corpus acc_s1ap_rel16_positive.pcap: one S1AP packet read", n == 1);
	CHECK("corpus acc_s1ap_rel16_positive.pcap: S1AP InitialContextSetupRequest (procedure 9)",
			n == 1 && strstr(g_path, ".s1ap") != NULL && proc == 9);
	CHECK("corpus acc_s1ap_rel16_positive.pcap: Rel-16 NRUESecurityCapabilities extracted (NEA1-3, NIA1-3)",
			n == 1 && g_nr_enc == 0xE000 && g_nr_int == 0xE000);

	n = replay_corpus_pcap(h, dir, "acc_ngap_rel16_positive.pcap", &proc);
	CHECK("corpus acc_ngap_rel16_positive.pcap: one NGAP packet read", n == 1);
	CHECK("corpus acc_ngap_rel16_positive.pcap: NGAP DownlinkNASTransport (procedure 4)",
			n == 1 && strstr(g_path, ".ngap") != NULL && proc == 4);
	CHECK("corpus acc_ngap_rel16_positive.pcap: Rel-16 SRVCCOperationPossible extracted (notPossible)",
			n == 1 && g_srvcc == 1);

	mmt_close_handler(h);
}

/* feed a frame, then assert the classified path does/doesn't contain a
 * protocol name */
static void expect_path(mmt_handler_t *h, const char *label,
		const uint8_t *frame, size_t len,
		const char *want, const char *notwant) {
	char desc[512];
	drive(h, frame, len);
	snprintf(desc, sizeof(desc), "%s (path: %s)", label,
			g_path[0] ? g_path : "<none>");
	CHECK(desc,
			(want    == NULL || strstr(g_path, want)    != NULL) &&
			(notwant == NULL || strstr(g_path, notwant) == NULL));
}

int main(int argc, char **argv) {
	mmt_handler_t *h;
	char errbuf[1024];
	size_t flen;
	uint8_t *f;
	uint8_t pl[64];

	init_extraction();
	h = mmt_init_handler(1 /*DLT_EN10MB*/, 0, errbuf);
	if (h == NULL) {
		fprintf(stderr, "mmt_init_handler: %s\n", errbuf);
		return 1;
	}
	register_packet_handler(h, 1, packet_handler, NULL);

	/* ---------------- F-BUG-079: NGAP SCTP DATA length -------------- */

	/* declared chunk length smaller than the 16-byte DATA header — the
	 * subtraction used to wrap to ~64KiB. The payload is a valid NGAP PDU,
	 * so the pre-fix classifier would have decoded (and read past the
	 * capture) instead of rejecting up-front. declared_len=1 is the
	 * acceptance-criterion case; 8 covers the general <header range. */
	f = build_sctp_data_frame(&flen, 50000, 38412, 0,
			1, NGAP_WIRE, sizeof(NGAP_WIRE));
	expect_path(h, "NGAP ppid=0 dport=38412 declared_len=1 < header",
			f, flen, ".sctp_data", ".ngap");
	free(f);

	f = build_sctp_data_frame(&flen, 50000, 38412, 0,
			8, NGAP_WIRE, sizeof(NGAP_WIRE));
	expect_path(h, "NGAP ppid=0 dport=38412 declared_len=8 < header",
			f, flen, ".sctp_data", ".ngap");
	free(f);

	/* declared chunk length far beyond the captured bytes — clamped to
	 * caplen, decode of the truncated prefix then fails cleanly */
	f = build_sctp_data_frame(&flen, 50000, 38412, 0,
			4000, NGAP_WIRE, 8);
	expect_path(h, "NGAP ppid=0 declared_len=4000 captured=8",
			f, flen, ".sctp_data", ".ngap");
	free(f);

	/* control: the same port fallback with a complete valid PDU still
	 * classifies NGAP */
	f = build_sctp_data_frame(&flen, 50000, 38412, 0,
			16 + sizeof(NGAP_WIRE), NGAP_WIRE, sizeof(NGAP_WIRE));
	expect_path(h, "NGAP ppid=0 dport=38412 valid wire (control)",
			f, flen, ".ngap", NULL);
	free(f);

	/* control: PPID 60 classifies unconditionally */
	f = build_sctp_data_frame(&flen, 50000, 38412, 60, 16 + 4, pl, 4);
	expect_path(h, "NGAP ppid=60 (control)", f, flen, ".ngap", NULL);
	free(f);

	/* ---------------- F-BUG-080: Diameter header proof -------------- */

	/* PPID 46 with 1 byte of payload — the pre-fix classifier accessed a
	 * 20-byte Diameter header after proving only this byte */
	f = build_sctp_data_frame(&flen, 3868, 3868, 46, 16 + 1, pl, 1);
	expect_path(h, "Diameter ppid=46 payload=1B",
			f, flen, NULL, ".diameter");
	free(f);

	/* PPID 46 with 3 bytes — still short of the header */
	f = build_sctp_data_frame(&flen, 3868, 3868, 46, 16 + 3, pl, 3);
	expect_path(h, "Diameter ppid=46 payload=3B",
			f, flen, NULL, ".diameter");
	free(f);

	/* control: PPID 46 with a full 20-byte Diameter header */
	pl[0] = 1; pl[1] = 0; pl[2] = 0; pl[3] = 20;   /* version=1, len=20 */
	f = build_sctp_data_frame(&flen, 3868, 3868, 46, 16 + 20, pl, 20);
	expect_path(h, "Diameter ppid=46 full header (control)",
			f, flen, ".diameter", NULL);
	free(f);

	/* control: port-based fallback (3868/3868, ppid=0) with a valid
	 * header still classifies */
	f = build_sctp_data_frame(&flen, 3868, 3868, 0, 16 + 20, pl, 20);
	expect_path(h, "Diameter ports 3868 ppid=0 valid hdr (control)",
			f, flen, ".diameter", NULL);
	free(f);

	/* control: the fallback still rejects a wrong version */
	pl[0] = 7;
	f = build_sctp_data_frame(&flen, 3868, 3868, 0, 16 + 20, pl, 20);
	expect_path(h, "Diameter ports 3868 ppid=0 version=7 (control)",
			f, flen, NULL, ".diameter");
	free(f);

	/* ---------------- controls and truncated chunk ------------------ */

	/* control: PPID 18 classifies S1AP */
	f = build_sctp_data_frame(&flen, 36412, 36412, 18, 16 + 4, pl, 4);
	expect_path(h, "S1AP ppid=18 (control)", f, flen, ".s1ap", NULL);
	free(f);

	/* capture ends inside the DATA chunk header — no mobile classifier
	 * may touch the bytes */
	f = build_sctp_short_chunk_frame(&flen, 38412, 38412, 8);
	drive(h, f, flen);
	{
		char desc[512];
		snprintf(desc, sizeof(desc),
				"DATA chunk truncated mid-header (path: %s)",
				g_path[0] ? g_path : "<none>");
		CHECK(desc, strstr(g_path, ".ngap") == NULL &&
				strstr(g_path, ".diameter") == NULL &&
				strstr(g_path, ".s1ap") == NULL);
	}
	free(f);

	mmt_close_handler(h);

	/* ---------------- #507: S1AP extraction cache ------------------- */
	test_s1ap_two_handlers();

	/* ---------------- #574: UE keying, release, Rel-16 IEs ---------- */
	test_mobile_ue_keying_and_rel16();
	if (argc > 1)
		test_mobile_rel16_corpus(argv[1]);
	else
		CHECK("accuracy-corpus directory given (argv[1])", 0);

	close_extraction();

	printf("\n%d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}

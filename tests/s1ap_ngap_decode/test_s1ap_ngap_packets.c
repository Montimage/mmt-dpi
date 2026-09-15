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
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

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

/* ------------------------------------------------------------------ */

static char g_path[512];

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
	p[12] = 10; p[16] = 192; p[17] = 168;
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

int main(void) {
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
	close_extraction();

	printf("\n%d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}

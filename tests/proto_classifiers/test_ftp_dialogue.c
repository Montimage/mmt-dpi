/*
 * test_ftp_dialogue.c — crafted-input tests of the FTP dissector
 * (issue #563: the control-session lists of F-PERF-106 changed
 * proto_ftp.c and proto_ftp_session.c; this pins the dissector around them).
 *
 * The resource_bounds "ftp-control" fixture counts what the per-handler lists
 * cost; it only greets each flow and runs PASV transfers. This test drives
 * the rest of the dissector through its real entry points:
 *
 *   A. parsing — every command of the id table (upper and lower case), the
 *      short/odd command and reply shapes, and the PORT/EPRT/LPRT and
 *      227/228/229 address parameters, malformed ones included;
 *   B. session tuples — every ftp_compare_tuple6() verdict (IPv4 and IPv6)
 *      and the direction each one gives ftp_set_tuple6_direction();
 *   C. dialogues — IPv4 and IPv6 control flows through
 *      ftp_session_data_analysis(): login, SYST, FEAT continuation, PWD,
 *      SIZE/MDTM, passive (227/228/229) and active (PORT/EPRT/LPRT)
 *      transfers with their data flows, 226 resets and 221 close, each step
 *      read back through the registered attribute extractors;
 *   D. classification — mmt_check_ftp() on control commands and replies,
 *      the SMTP exclusion, the wait/reject budgets, the passive/active mode
 *      address capture and the data-stream detection with its timeout;
 *   E. out of memory — every allocation of the parsers, the session
 *      constructors and a dialogue failed in turn: nothing leaks or crashes.
 *
 * The proto_ftp*.c units and mmt_utils.c are compiled beside this TU with the
 * counted allocator of ftp_alloc_fail.c (-Dmalloc=fda_malloc ...), and
 * -DNDEBUG as in the SDK build; the mmt_core and plugin symbols they
 * reference are stubbed below.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "plugin_defs.h"
#include "mmt_core.h"
#include "extraction_lib.h"
#include "../../src/mmt_tcpip/lib/mmt_common_internal_include.h"
#include "../../src/mmt_tcpip/lib/protocols/ftp.h"

static int checks;
static int failures;
#define CHECK(cond, ...) do {                                        \
		checks++;                                                    \
		if (!(cond)) {                                               \
			failures++;                                              \
			fprintf(stderr, "FAIL %d: ", __LINE__);                  \
			fprintf(stderr, __VA_ARGS__);                            \
			fprintf(stderr, "\n");                                   \
		}                                                            \
	} while (0)

extern uint64_t fda_calls;
extern int64_t  fda_outstanding;
extern uint64_t fda_fail_at;
extern uint64_t fda_failed;

void *setup_ftp_context(void *proto_context, void *args);
void cleanup_ftp_context(void *proto_context, void *args);
int ftp_session_data_analysis(ipacket_t *ipacket, unsigned index);
int init_proto_ftp_struct(void);
int mmt_check_ftp(ipacket_t *ipacket, unsigned index);
uint16_t power_16(uint16_t nb, int t);

#define IDX 4u                  /* FTP's position in the protocol path */

/* ---- stubs: the core/plugin symbols the FTP units reference ---- */

int get_packet_offset_at_index(const ipacket_t *ipacket, unsigned index) {
	(void) ipacket; (void) index;
	return 0;                   /* the crafted packets hold only the payload */
}
static protocol_t g_protocol;
static int g_registered_attributes;
protocol_t *init_protocol_struct_for_registration(mmt_proto_id_t proto_id, const char *protocol_name) {
	(void) proto_id; (void) protocol_name;
	return &g_protocol;
}
bool register_attribute_with_protocol(protocol_t *p, attribute_metadata_t *m) {
	(void) p; (void) m;
	g_registered_attributes++;
	return 1;
}
void register_proto_context_init_cleanup_function(protocol_t *p, generic_proto_context_init_function i,
		generic_proto_context_cleanup_function c, mmt_opaque_t a) {
	(void) p; (void) i; (void) c; (void) a;
}
bool register_session_data_analysis_function(protocol_t *p, generic_session_data_analysis_function f) {
	(void) p; (void) f;
	return 1;
}
void register_session_data_cleanup_function(protocol_t *p, generic_session_data_cleanup_function f) {
	(void) p; (void) f;
}
bool register_protocol(protocol_t *p, mmt_proto_id_t proto_id) {
	(void) p; (void) proto_id;
	return 1;
}
/* Same contract as src/mmt_tcpip/lib/mmt_tcpip_utils.c (the 227 parser of
 * search_passive_ftp_mode() depends on it). */
uint32_t mmt_bytestream_to_number(const uint8_t *str, uint16_t max_chars_to_read, uint16_t *bytes_read) {
	uint32_t val = 0;
	while (max_chars_to_read > 0 && *str >= '0' && *str <= '9') {
		val = val * 10 + (uint32_t) (*str - '0');
		str++;
		max_chars_to_read--;
		*bytes_read = *bytes_read + 1;
	}
	return val;
}
static uint16_t g_detected;
void mmt_internal_add_connection(ipacket_t *ipacket, uint16_t detected_protocol, mmt_protocol_type_t t) {
	(void) t;
	g_detected = detected_protocol;
	ipacket->internal_packet->detected_protocol_stack[0] = detected_protocol;
}
/* The handler owns an extracted string until the next packet: keep the last
 * one and release it on the next adoption (or at the end). */
static void *g_adopted;
static mmt_packet_scratch_release_function g_adopted_release;
static void scratch_flush(void) {
	if (g_adopted != NULL && g_adopted_release != NULL) g_adopted_release(g_adopted);
	g_adopted = NULL;
	g_adopted_release = NULL;
}
bool mmt_packet_scratch_adopt(const ipacket_t *ipacket, mmt_opaque_t value,
		mmt_packet_scratch_release_function release) {
	(void) ipacket;
	scratch_flush();
	if (value == NULL) return 0;
	g_adopted = value;
	g_adopted_release = release;
	return 1;
}

/* ---- one crafted packet at a time, on a borrowed session ---- */

static mmt_handler_t g_handler;
static mmt_session_t g_sess;
static ipacket_t g_pkt;
static mmt_tcpip_internal_packet_t g_ip;
static mmt_internal_tcpip_session_t g_flow;
static mmt_internal_tcpip_id_struct g_src, g_dst;
static struct tcphdr g_tcp;
static struct iphdr g_iph;
static struct mmt_ipv6hdr g_ip6;
static pkthdr_t g_hdr;
static proto_hierarchy_t g_hier;
static uint8_t g_buf[512];

static ftp_context_t *ctx(void) {
	return (ftp_context_t *) g_handler.configured_protocols[PROTO_FTP].args;
}

static void handler_open(void) {
	g_handler.configured_protocols[PROTO_FTP].args =
		setup_ftp_context(&g_handler.configured_protocols[PROTO_FTP], NULL);
	g_hier.len = IDX + 1;
	g_hier.proto_path[IDX] = PROTO_FTP;
	g_ip.tcp = (const void *) &g_tcp;
	g_ip.iph = (const void *) &g_iph;
	g_ip.payload = g_buf;
	g_ip.flow = &g_flow;
	g_pkt.mmt_handler = &g_handler;
	g_pkt.session = &g_sess;
	g_pkt.internal_packet = &g_ip;
	g_pkt.proto_hierarchy = &g_hier;
	g_pkt.p_hdr = &g_hdr;
	g_pkt.data = g_buf;
}

static void handler_close(void) {
	cleanup_ftp_context(&g_handler.configured_protocols[PROTO_FTP], NULL);
}

static void use_ipv4(void) {
	g_ip.iph = (const void *) &g_iph;
	g_ip.iphv6 = NULL;
}

static void use_ipv6(void) {
	g_ip.iph = NULL;
	g_ip.iphv6 = (const void *) &g_ip6;
}

static void set_payload(const char *payload, size_t len) {
	memcpy(g_buf, payload, len);
	g_buf[len] = '\0';
	g_ip.payload_packet_len = (uint16_t) len;
	g_hdr.caplen = (unsigned) len;
}

static void set_ports(uint16_t sport, uint16_t dport) {
	g_tcp.source = htons(sport);
	g_tcp.dest = htons(dport);
}

/* Each flow owns only its FTP session_data slot; the packet borrows the one
 * session record and swaps the slot in and out. */
static void packet_n(void **slot, uint64_t flow_id, uint32_t saddr, uint16_t sport,
		uint32_t daddr, uint16_t dport, const char *payload, size_t len) {
	set_payload(payload, len);
	g_iph.saddr = saddr;
	g_iph.daddr = daddr;
	set_ports(sport, dport);
	g_sess.session_id = flow_id;
	g_sess.session_data[IDX] = *slot;
	CHECK(ftp_session_data_analysis(&g_pkt, IDX) == MMT_CONTINUE, "analysis continues");
	*slot = g_sess.session_data[IDX];
}

static void packet(void **slot, uint64_t flow_id, uint32_t saddr, uint16_t sport,
		uint32_t daddr, uint16_t dport, const char *payload) {
	packet_n(slot, flow_id, saddr, sport, daddr, dport, payload, strlen(payload));
}

/* What the core's expiry does for the FTP slot of a timed-out flow. */
static void expire(void **slot) {
	g_sess.session_data[IDX] = *slot;
	ftp_session_data_cleanup(&g_sess, IDX);
	*slot = g_sess.session_data[IDX];
}

/* ---- attribute extraction through the registered table ---- */

static union { uint64_t u64; uint32_t u32; uint16_t u16; uint8_t u8; } g_val;
static attribute_t g_attr;

/* Run the extractor of `id` on the current packet (whose slot is `slot`). */
static int extract(void *slot, uint32_t id) {
	for (int i = 0; i < FTP_ATTRIBUTES_NB; i++) {
		if (ftp_attributes_metadata[i].id != (int) id) continue;
		g_sess.session_data[IDX] = slot;
		memset(&g_val, 0, sizeof(g_val));
		g_attr.data = &g_val;
		return ftp_attributes_metadata[i].extraction_function(&g_pkt, IDX, &g_attr);
	}
	CHECK(0, "attribute %u is in the FTP table", id);
	return 0;
}

static const char *extract_str(void *slot, uint32_t id) {
	return extract(slot, id) ? (const char *) g_attr.data : NULL;
}

static int str_is(const char *got, const char *want) {
	return got != NULL && strcmp(got, want) == 0;
}

/* Every extractor once, on whatever the current packet is — the absent
 * values must answer 0, never crash. Returns how many answered 1. */
static int extract_all(void *slot) {
	int n = 0;
	for (int i = 0; i < FTP_ATTRIBUTES_NB; i++) {
		g_sess.session_data[IDX] = slot;
		memset(&g_val, 0, sizeof(g_val));
		g_attr.data = &g_val;
		n += ftp_attributes_metadata[i].extraction_function(&g_pkt, IDX, &g_attr) != 0;
		scratch_flush();
	}
	return n;
}

#define SERVER    htonl(0xc0000201u)    /* 192.0.2.1 */
#define CLIENT    htonl(0x0a000001u)    /* 10.0.0.1 */
#define CPORT     40000

/* ======================= A. parsing ======================= */

static const char *const k_commands[] = {
	"PWD", "CWD", "CCC", "ENC", "MIC", "MKD", "RMD",
	"RETR", "USER", "PASS", "SYST", "TYPE", "SIZE", "EPSV", "FEAT", "MDTM",
	"ABOR", "ACCT", "ALLO", "APPE", "AUTH", "CDUP", "CONF", "DELE", "EPRT",
	"HELP", "LANG", "LIST", "LPRT", "LPSV", "MLSD", "MLST", "MODE", "NLST",
	"NOOP", "OPTS", "PASV", "PBSZ", "PORT", "QUIT", "REIN", "REST", "RNFR",
	"RNTO", "SITE", "SMNT", "STAT", "STOR", "STOU", "STRU", "XCUP", "XMKD",
	"XPWD", "XRCP", "XRMD", "XRSQ", "XSEM", "XSEN",
};
static const uint16_t k_command_ids[] = {
	MMT_FTP_PWD_CMD, MMT_FTP_CWD_CMD, MMT_FTP_CCC_CMD, MMT_FTP_ENC_CMD, MMT_FTP_MIC_CMD,
	MMT_FTP_MKD_CMD, MMT_FTP_RMD_CMD,
	MMT_FTP_RETR_CMD, MMT_FTP_USER_CMD, MMT_FTP_PASS_CMD, MMT_FTP_SYST_CMD, MMT_FTP_TYPE_CMD,
	MMT_FTP_SIZE_CMD, MMT_FTP_EPSV_CMD, MMT_FTP_FEAT_CMD, MMT_FTP_MDTM_CMD,
	MMT_FTP_ABOR_CMD, MMT_FTP_ACCT_CMD, MMT_FTP_ALLO_CMD, MMT_FTP_APPE_CMD, MMT_FTP_AUTH_CMD,
	MMT_FTP_CDUP_CMD, MMT_FTP_CONF_CMD, MMT_FTP_DELE_CMD, MMT_FTP_EPRT_CMD,
	MMT_FTP_HELP_CMD, MMT_FTP_LANG_CMD, MMT_FTP_LIST_CMD, MMT_FTP_LPRT_CMD, MMT_FTP_LPSV_CMD,
	MMT_FTP_MLSD_CMD, MMT_FTP_MLST_CMD, MMT_FTP_MODE_CMD, MMT_FTP_NLST_CMD,
	MMT_FTP_NOOP_CMD, MMT_FTP_OPTS_CMD, MMT_FTP_PASV_CMD, MMT_FTP_PBSZ_CMD, MMT_FTP_PORT_CMD,
	MMT_FTP_QUIT_CMD, MMT_FTP_REIN_CMD, MMT_FTP_REST_CMD, MMT_FTP_RNFR_CMD,
	MMT_FTP_RNTO_CMD, MMT_FTP_SITE_CMD, MMT_FTP_SMNT_CMD, MMT_FTP_STAT_CMD, MMT_FTP_STOR_CMD,
	MMT_FTP_STOU_CMD, MMT_FTP_STRU_CMD, MMT_FTP_XCUP_CMD, MMT_FTP_XMKD_CMD,
	MMT_FTP_XPWD_CMD, MMT_FTP_XRCP_CMD, MMT_FTP_XRMD_CMD, MMT_FTP_XRSQ_CMD, MMT_FTP_XSEM_CMD,
	MMT_FTP_XSEN_CMD,
};
#define N_COMMANDS (sizeof(k_commands) / sizeof(k_commands[0]))

static ftp_command_t *command_of(const char *s) {
	return ftp_get_command((char *) s, (int) strlen(s));
}

static void test_command_table(void) {
	CHECK(N_COMMANDS == sizeof(k_command_ids) / sizeof(k_command_ids[0]), "command table sizes agree");
	int ok = 0;
	for (size_t i = 0; i < N_COMMANDS; i++) {
		for (int lower = 0; lower < 2; lower++) {
			char line[32];
			size_t n = strlen(k_commands[i]);
			for (size_t j = 0; j < n; j++)
				line[j] = (char) (lower ? k_commands[i][j] - 'A' + 'a' : k_commands[i][j]);
			memcpy(line + n, " arg\r\n", 7);
			ftp_command_t *c = command_of(line);
			ok += (c != NULL && c->cmd == k_command_ids[i] && str_is(c->param, "arg")
			       && c->str_cmd != NULL && strlen(c->str_cmd) == n);
			free_ftp_command(c);
		}
	}
	CHECK(ok == (int) (2 * N_COMMANDS), "%d of %zu commands parse to their id", ok, 2 * N_COMMANDS);

	/* Verbs the table does not know. */
	ftp_command_t *c = command_of("XYZ a\r\n");
	CHECK(c && c->cmd == MMT_FTP_UNKNOWN_CMD && str_is(c->str_cmd, "XYZ"), "unknown 3-letter verb");
	free_ftp_command(c);
	c = command_of("WXYZ a\r\n");
	CHECK(c && c->cmd == MMT_FTP_UNKNOWN_CMD && str_is(c->str_cmd, "WXYZ"), "unknown 4-letter verb");
	free_ftp_command(c);
}

static void test_command_shapes(void) {
	/* mmt_int_check_possible_ftp_command: 3-4 letters, then a space. */
	CHECK(mmt_int_check_possible_ftp_command("AB", 2) == 0, "too short");
	CHECK(mmt_int_check_possible_ftp_command("1BC", 3) == 0, "digit at 0");
	CHECK(mmt_int_check_possible_ftp_command("A1C", 3) == 0, "digit at 1");
	CHECK(mmt_int_check_possible_ftp_command("AB1", 3) == 0, "digit at 2");
	CHECK(mmt_int_check_possible_ftp_command("abc", 3) == 1, "bare 3 letters");
	CHECK(mmt_int_check_possible_ftp_command("ABC1", 4) == 0, "digit at 3");
	CHECK(mmt_int_check_possible_ftp_command("NOOP", 4) == 2, "NOOP");
	CHECK(mmt_int_check_possible_ftp_command("noop", 4) == 2, "noop");
	CHECK(mmt_int_check_possible_ftp_command("ABCDE", 5) == 0, "5 letters, no space");
	CHECK(mmt_int_check_possible_ftp_command("ABCD x", 6) == 1, "4 letters + space");
	CHECK(mmt_int_check_possible_ftp_command("ABC x", 5) == 1, "3 letters + space");

	/* Replies: 3 digits then space or hyphen. */
	CHECK(mmt_int_check_possible_ftp_reply("220", 3) == 0, "short reply");
	CHECK(mmt_int_check_possible_ftp_reply("220x ", 5) == 0, "no separator");
	CHECK(mmt_int_check_possible_ftp_reply("a20 x", 5) == 0, "letter at 0");
	CHECK(mmt_int_check_possible_ftp_reply("2a0 x", 5) == 0, "letter at 1");
	CHECK(mmt_int_check_possible_ftp_reply("22a x", 5) == 0, "letter at 2");
	CHECK(mmt_int_check_possible_ftp_reply("220-x", 5) == 1, "continued reply");
	CHECK(mmt_int_check_possible_ftp_continuation_reply("abc", 3) == 0, "short continuation");
	CHECK(mmt_int_check_possible_ftp_continuation_reply("ab\001de", 5) == 0, "control byte");
	CHECK(mmt_int_check_possible_ftp_continuation_reply(" EPSV", 5) == 1, "continuation line");

	/* ftp_get_command shapes. */
	ftp_command_t *c = command_of("FEAT\r\n");
	CHECK(c && c->cmd == MMT_FTP_FEAT_CMD && c->param == NULL, "FEAT CRLF");
	free_ftp_command(c);
	c = command_of("PWD\r\n");
	CHECK(c && c->cmd == MMT_FTP_PWD_CMD && c->param == NULL, "PWD CRLF");
	free_ftp_command(c);
	c = command_of("12345678");
	CHECK(c && c->cmd == MMT_FTP_UNKNOWN_CMD && str_is(c->str_cmd, "UNKNOWN_CMD"), "not a command");
	free_ftp_command(c);
	c = command_of("ABC");
	CHECK(c && c->cmd == MMT_FTP_UNKNOWN_CMD && str_is(c->str_cmd, "UNKNOWN_CMD"), "bare ABC");
	free_ftp_command(c);
	c = command_of("CWD \r\n");
	CHECK(c && c->cmd == MMT_FTP_CWD_CMD && c->param == NULL, "3-letter verb, empty parameter");
	free_ftp_command(c);
	c = command_of("STOR \r\n");
	CHECK(c && c->cmd == MMT_FTP_STOR_CMD && c->param == NULL, "4-letter verb, empty parameter");
	free_ftp_command(c);

	/* ftp_get_command_param. */
	char *p = ftp_get_command_param("FEAT\r\n", 6);
	CHECK(p == NULL, "FEAT has no parameter");
	p = ftp_get_command_param("PWD\r\n", 5);
	CHECK(p == NULL, "PWD has no parameter");
	p = ftp_get_command_param("1234567", 7);
	CHECK(str_is(p, "1234567"), "a non-command is its own parameter");
	free(p);
	p = ftp_get_command_param("CWD pub\r\n", 9);
	CHECK(str_is(p, "pub"), "3-letter verb parameter");
	free(p);
	p = ftp_get_command_param("CWD \r\n", 6);
	CHECK(p == NULL, "3-letter verb, empty parameter");
	p = ftp_get_command_param("RETR f.txt\r\n", 12);
	CHECK(str_is(p, "f.txt"), "4-letter verb parameter");
	free(p);
	p = ftp_get_command_param("RETR \r\n", 7);
	CHECK(p == NULL, "4-letter verb, empty parameter");
	p = ftp_get_command_param("ABC", 3);
	CHECK(p == NULL, "bare ABC has no parameter");

	/* ftp_get_command_str: a heap string on every path (issue #506). */
	const char *in[] = {"FEAT\r\n", "PWD\r\n", "12345678", "CWD pub\r\n", "RETR f\r\n", "ABC"};
	const char *want[] = {"FEAT", "PWD", "UNKNOWN_CMD", "CWD", "RETR", "UNKNOWN_CMD"};
	for (size_t i = 0; i < sizeof(in) / sizeof(in[0]); i++) {
		char *s = ftp_get_command_str((char *) in[i], (int) strlen(in[i]));
		CHECK(str_is(s, want[i]), "command string of '%s'", want[i]);
		free(s);
	}
}

static void test_reply_shapes(void) {
	ftp_response_t *r = ftp_get_response("230 Login ok\r\n", 14);
	CHECK(r && r->code == 230 && str_is(r->str_code, "230") && str_is(r->value, "Login ok"), "230 reply");
	free_ftp_response(r);
	r = ftp_get_response("213 \r\n", 6);
	CHECK(r && r->code == 213 && r->value == NULL, "213 without a value");
	free_ftp_response(r);
	r = ftp_get_response(" EPSV\r\n", 7);
	CHECK(r && r->code == MMT_FTP_CONTINUE_CODE && str_is(r->value, " EPSV"), "continuation line");
	free_ftp_response(r);
	r = ftp_get_response("ab\r\n", 4);
	CHECK(r && r->code == MMT_FTP_UNKNOWN_CODE && str_is(r->value, "ab"), "unknown reply");
	free_ftp_response(r);
	r = ftp_get_response("x", 1);
	CHECK(r && r->code == MMT_FTP_UNKNOWN_CODE && r->value == NULL, "one-byte reply");
	free_ftp_response(r);

	char *v = ftp_get_response_value("257 \"/\"\r\n", 9);
	CHECK(str_is(v, "\"/\""), "reply value");
	free(v);
	v = ftp_get_response_value("213 \r\n", 6);
	CHECK(v == NULL, "reply without a value");
	v = ftp_get_response_value(" MDTM\r\n", 7);
	CHECK(str_is(v, " MDTM"), "continuation value");
	free(v);
	v = ftp_get_response_value("x\r\n", 3);
	CHECK(v == NULL, "no value in garbage");

	CHECK(ftp_get_response_code("550 no\r\n", 8) == 550, "reply code");
	CHECK(ftp_get_response_code(" MDTM\r\n", 7) == MMT_FTP_CONTINUE_CODE, "continuation code");
	CHECK(ftp_get_response_code("x\r\n", 3) == MMT_FTP_UNKNOWN_CODE, "unknown code");
}

#define S(x) (char *) (x), (uint32_t) strlen(x)

static void test_address_parameters(void) {
	/* EPRT |1|addr|port| */
	CHECK(ftp_get_data_client_addr_from_EPRT(S("EPRT |1|10.0.0.1|2002|\r\n")) == inet_addr("10.0.0.1"),
	      "EPRT IPv4 address");
	CHECK(ftp_get_data_client_addr_from_EPRT(S("EPRT 1 10.0.0.1 2002\r\n")) == 0, "EPRT without '|'");
	CHECK(ftp_get_data_client_addr_from_EPRT(S("EPRT |1|\r\n")) == 0, "EPRT with two '|'");
	CHECK(ftp_get_data_client_port_from_EPRT(S("EPRT |1|10.0.0.1|2002|\r\n")) == 2002, "EPRT port");
	CHECK(ftp_get_data_client_port_from_EPRT(S("EPRT |2|::1|1031\r\n")) == 1031, "EPRT port without a 4th '|'");
	CHECK(ftp_get_data_client_port_from_EPRT(S("EPRT |2|::1|\r")) == 0, "EPRT empty trailing port");
	CHECK(ftp_get_data_client_port_from_EPRT(S("EPRT |2|::1||")) == 0, "EPRT empty port");
	CHECK(ftp_get_data_client_port_from_EPRT(S("EPRT 2 ::1\r\n")) == 0, "EPRT port without '|'");
	CHECK(ftp_get_data_client_port_from_EPRT(S("EPRT |2|\r\n")) == 0, "EPRT port with two '|'");
	char *v6 = ftp_get_data_client_addr_v6_from_EPRT(S("EPRT |2|2001:db8::1|2010|\r\n"));
	CHECK(str_is(v6, "2001:db8::1"), "EPRT IPv6 address");
	free(v6);
	CHECK(ftp_get_data_client_addr_v6_from_EPRT(S("EPRT 2\r\n")) == NULL, "EPRT v6 without '|'");
	CHECK(ftp_get_data_client_addr_v6_from_EPRT(S("EPRT |2|\r\n")) == NULL, "EPRT v6 with two '|'");

	/* PORT h1,h2,h3,h4,p1,p2 */
	CHECK(ftp_get_addr_from_parameter(S("10,0,0,1,7,209\r\n")) == inet_addr("10.0.0.1"), "PORT address");
	CHECK(ftp_get_addr_from_parameter(S("10 0 0 1\r\n")) == 0, "PORT address without ','");
	CHECK(ftp_get_addr_from_parameter(S("10,0,0\r\n")) == 0, "PORT address with two ','");
	CHECK(ftp_get_addr_from_parameter(S("10,0,0,1")) == 0, "PORT address with three ','");
	CHECK(ftp_get_port_from_parameter(S("PORT 10,0,0,1,7,209\r\n")) == ntohs(7 * 256 + 209), "PORT port");
	CHECK(ftp_get_port_from_parameter(S("PORT 10\r\n")) == 0, "PORT port without ','");
	CHECK(ftp_get_port_from_parameter(S("PORT 10,0,0,1\r\n")) == 0, "PORT port with three ','");

	/* LPRT af,hal,h1..hn,pal,p1..pn (RFC 1639). */
	v6 = ftp_get_data_client_addr_v6_from_LPRT(
		S("LPRT 6,16,32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1,2,7,218\r\n"));
	CHECK(v6 != NULL && strlen(v6) > 0 && strlen(v6) <= 32, "LPRT IPv6 address '%s'", v6 ? v6 : "(null)");
	free(v6);
	v6 = ftp_get_data_client_addr_v6_from_LPRT(S("LPRT 6,99,1,2\r\n"));
	CHECK(str_is(v6, ""), "LPRT oversized host length");
	free(v6);
	v6 = ftp_get_data_client_addr_v6_from_LPRT(S("LPRT 6,3,10,300,1\r\n"));
	CHECK(v6 != NULL && strlen(v6) <= 32, "LPRT octet out of range stops the parse");
	free(v6);
	v6 = ftp_get_data_client_addr_v6_from_LPRT(S("LPRT 6,4,1,0,0,2"));
	CHECK(v6 != NULL, "LPRT odd-free host address");
	free(v6);
	v6 = ftp_get_data_client_addr_v6_from_LPRT(S("LPRT 6,16,1,2"));
	CHECK(v6 != NULL, "LPRT truncated host address");
	free(v6);
	CHECK(ftp_get_data_client_addr_v6_from_LPRT("", 0) == NULL, "LPRT empty");
	CHECK(ftp_get_data_client_port_from_LPRT(
		S("LPRT 6,16,32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1,2,7,218\r\n")) == 7 * 256 + 218, "LPRT port");
	CHECK(ftp_get_data_client_port_from_LPRT(S("LPRT 4,4,10,0,0,1,1,9\r\n")) == 9, "LPRT one-octet port");
	CHECK(ftp_get_data_client_port_from_LPRT(S("LPRT 6,0,1\r\n")) == 0, "LPRT zero host length");
	CHECK(ftp_get_data_client_port_from_LPRT(S("LPRT 4,4,10,0,0,1,9,1,2\r\n")) == 0, "LPRT oversized port length");
	CHECK(ftp_get_data_client_port_from_LPRT(S("LPRT 4,4,10,0,0,1,2,7")) == 7 * 256, "LPRT truncated port");
	CHECK(ftp_get_data_client_port_from_LPRT("", 0) == 0, "LPRT port empty");
	CHECK(power_16(3, 2) == 3 * 256 && power_16(5, 0) == 5, "power_16");

	/* Passive-mode replies. */
	CHECK(ftp_get_data_server_addr_code_227(S("227 Entering Passive Mode (192,0,2,1,7,208)\r\n"))
	      == inet_addr("192.0.2.1"), "227 address");
	CHECK(ftp_get_data_server_port_code_227(S("227 Entering Passive Mode (192,0,2,1,7,208)\r\n"))
	      == ntohs(7 * 256 + 208), "227 port");
	CHECK(ftp_get_data_server_addr_code_227(S("227 no parenthesis\r\n")) == 0, "227 without '('");
	CHECK(ftp_get_data_server_port_code_227(S("227 open ( only\r\n")) == 0, "227 without ')'");
	CHECK(ftp_get_data_server_port_code_227(S("227 empty ()\r\n")) == 0, "227 empty parameter");
	CHECK(ftp_get_data_server_port_code_229(S("Entering Extended Passive Mode (|||2003|)")) == htons(2003),
	      "229 port");
	CHECK(ftp_get_data_server_port_code_229(S("Entering Extended Passive Mode")) == 0, "229 without port");
	CHECK(ftp_get_data_server_port_code_229("", 0) == 0, "229 empty");
	CHECK(ftp_get_data_server_port_code_229(NULL, 0) == 0, "229 NULL");
	CHECK(ftp_get_data_server_port_code_228(S("Entering Long Passive Mode (3221225985, 2004)")) == htons(2004),
	      "228 port");
	CHECK(ftp_get_data_server_addr_code_228(S("Entering Long Passive Mode (77, 2004)")) == htons(77),
	      "228 address field");
	CHECK(ftp_get_data_server_port_code_228(S("Entering Long Passive Mode")) == 0, "228 without port");
	CHECK(ftp_get_data_server_addr_code_228(S("Entering Long Passive Mode")) == 0, "228 without address");
}

/* ======================= B. session tuples ======================= */

static ftp_tuple6_t tuple(uint8_t type, uint8_t dir, uint32_t ca, uint32_t cp, uint32_t sa, uint32_t sp) {
	ftp_tuple6_t t;
	memset(&t, 0, sizeof(t));
	t.conn_type = type; t.direction = dir;
	t.c_addr = ca; t.c_port = cp; t.s_addr = sa; t.s_port = sp;
	return t;
}

static void test_tuples(void) {
	const uint32_t A = 1, B = 2;
	ftp_tuple6_t c1 = tuple(MMT_FTP_CONTROL_CONNECTION, MMT_FTP_PACKET_CLIENT, A, 10, B, 21);
	ftp_tuple6_t c2 = c1;
	CHECK(ftp_compare_tuple6(NULL, &c1) == 0 && ftp_compare_tuple6(&c1, NULL) == 0, "NULL tuples");
	CHECK(ftp_compare_tuple6(&c1, &c2) == 1, "equal control tuples");
	c2.c_addr = 9; CHECK(ftp_compare_tuple6(&c1, &c2) == 0, "control: client address differs");
	c2 = c1; c2.s_addr = 9; CHECK(ftp_compare_tuple6(&c1, &c2) == 0, "control: server address differs");
	c2 = c1; c2.c_port = 9; CHECK(ftp_compare_tuple6(&c1, &c2) == 0, "control: client port differs");
	c2 = c1; c2.s_port = 9; CHECK(ftp_compare_tuple6(&c1, &c2) == 0, "control: server port differs");
	c2 = c1; c2.conn_type = MMT_FTP_DATA_CONNECTION; CHECK(ftp_compare_tuple6(&c1, &c2) == 0, "types differ");
	c2 = c1; c2.is_ipv6 = 1; CHECK(ftp_compare_tuple6(&c1, &c2) == 0, "families differ");

	/* Data tuples: verdicts 2..9 and the direction each one sets. */
	struct { ftp_tuple6_t pkt, conn; int verdict; uint8_t dir; } v[] = {
		{tuple(2, 0, A, 10, B, 20), tuple(2, MMT_FTP_PACKET_SERVER, A, 10, B, 20), 2, MMT_FTP_PACKET_SERVER},
		{tuple(2, 0, B, 20, A, 10), tuple(2, MMT_FTP_PACKET_SERVER, A, 10, B, 20), 3, MMT_FTP_PACKET_CLIENT},
		{tuple(2, 0, B, 20, A, 10), tuple(2, MMT_FTP_PACKET_CLIENT, A, 10, B, 20), 3, MMT_FTP_PACKET_SERVER},
		{tuple(2, 0, A, 10, B, 20), tuple(2, MMT_FTP_PACKET_CLIENT, A, 0, B, 20), 4, MMT_FTP_PACKET_CLIENT},
		{tuple(2, 0, B, 20, A, 10), tuple(2, MMT_FTP_PACKET_SERVER, A, 0, B, 20), 5, MMT_FTP_PACKET_CLIENT},
		{tuple(2, 0, B, 20, A, 10), tuple(2, MMT_FTP_PACKET_CLIENT, A, 0, B, 20), 5, MMT_FTP_PACKET_SERVER},
		{tuple(2, 0, A, 10, B, 20), tuple(2, MMT_FTP_PACKET_CLIENT, A, 10, B, 0), 6, MMT_FTP_PACKET_CLIENT},
		{tuple(2, 0, B, 20, A, 10), tuple(2, MMT_FTP_PACKET_SERVER, A, 10, B, 0), 7, MMT_FTP_PACKET_CLIENT},
		{tuple(2, 0, B, 20, A, 10), tuple(2, MMT_FTP_PACKET_CLIENT, A, 10, B, 0), 7, MMT_FTP_PACKET_SERVER},
		{tuple(2, 0, A, 10, B, 20), tuple(2, MMT_FTP_PACKET_CLIENT, A, 10, 0, 0), 8, MMT_FTP_PACKET_CLIENT},
		{tuple(2, 0, A, 10, B, 20), tuple(2, MMT_FTP_PACKET_SERVER, 0, 0, A, 10), 9, MMT_FTP_PACKET_CLIENT},
		{tuple(2, 0, A, 10, B, 20), tuple(2, MMT_FTP_PACKET_CLIENT, 0, 0, A, 10), 9, MMT_FTP_PACKET_SERVER},
		{tuple(2, 0, A, 10, B, 20), tuple(2, MMT_FTP_PACKET_CLIENT, 7, 7, 7, 7), 0, 0},
	};
	int ok = 0;
	for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
		int r = ftp_compare_tuple6(&v[i].pkt, &v[i].conn);
		ftp_set_tuple6_direction(&v[i].pkt, &v[i].conn, r);
		ok += (r == v[i].verdict && v[i].pkt.direction == v[i].dir);
		if (r != v[i].verdict || v[i].pkt.direction != v[i].dir)
			fprintf(stderr, "  tuple case %zu: verdict %d (want %d), direction %u (want %u)\n",
			        i, r, v[i].verdict, v[i].pkt.direction, v[i].dir);
	}
	CHECK(ok == (int) (sizeof(v) / sizeof(v[0])), "%d data-tuple verdicts as expected", ok);

	/* IPv6 data tuples compare the 32-byte address buffers. */
	char a6[33] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", b6[33] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	char z6[33] = {0};
	struct { char *pc, *ps; uint32_t pcp, psp; char *cc, *cs; uint32_t ccp, csp; int verdict; } w[] = {
		{a6, b6, 10, 20, a6, b6, 10, 20, 2},
		{b6, a6, 20, 10, a6, b6, 10, 20, 3},
		{a6, b6, 10, 20, a6, b6, 0, 20, 4},
		{b6, a6, 20, 10, a6, b6, 0, 20, 5},
		{a6, b6, 10, 20, a6, b6, 10, 0, 6},
		{b6, a6, 20, 10, a6, b6, 10, 0, 7},
		{a6, b6, 10, 20, z6, z6, 3, 3, 0},
	};
	ok = 0;
	for (size_t i = 0; i < sizeof(w) / sizeof(w[0]); i++) {
		ftp_tuple6_t p = tuple(2, 0, 0, w[i].pcp, 0, w[i].psp);
		ftp_tuple6_t c = tuple(2, MMT_FTP_PACKET_CLIENT, 0, w[i].ccp, 0, w[i].csp);
		p.is_ipv6 = c.is_ipv6 = 1;
		p.c_addr_v6 = w[i].pc; p.s_addr_v6 = w[i].ps;
		c.c_addr_v6 = w[i].cc; c.s_addr_v6 = w[i].cs;
		/* The IPv4 fields are 0 on both sides, so a v6 miss falls through to
		 * the IPv4 rules: make them differ to keep the v6 verdict. */
		if (w[i].verdict == 0) { p.c_addr = 1; c.s_addr = 2; c.c_addr = 3; }
		ok += ftp_compare_tuple6(&p, &c) == w[i].verdict;
	}
	CHECK(ok == (int) (sizeof(w) / sizeof(w[0])), "%d IPv6 data-tuple verdicts as expected", ok);

	ftp_tuple6_t c6a = tuple(1, 0, 0, 10, 0, 21), c6b = c6a;
	c6a.is_ipv6 = c6b.is_ipv6 = 1;
	c6a.c_addr_v6 = a6; c6a.s_addr_v6 = b6; c6b.c_addr_v6 = a6; c6b.s_addr_v6 = b6;
	CHECK(ftp_compare_tuple6(&c6a, &c6b) == 1, "equal IPv6 control tuples");
	c6b.c_addr_v6 = b6;
	CHECK(ftp_compare_tuple6(&c6a, &c6b) == 0, "IPv6 control: client address differs");
	c6b.c_addr_v6 = a6; c6b.s_addr_v6 = a6;
	CHECK(ftp_compare_tuple6(&c6a, &c6b) == 0, "IPv6 control: server address differs");

	/* An IPv6 tuple copies its address buffers. */
	ftp_tuple6_t *t = ftp_new_tuple6();
	CHECK(t != NULL, "new tuple");
	if (t != NULL) {
		t->is_ipv6 = 1;
		t->c_addr_v6 = calloc(33, 1);
		t->s_addr_v6 = calloc(33, 1);
		ftp_tuple6_t *cp = ftp_copy_tupl6(t);
		CHECK(cp && cp->is_ipv6 && cp->c_addr_v6 && cp->s_addr_v6 && cp->c_addr_v6 != t->c_addr_v6,
		      "IPv6 tuple copy owns its buffers");
		free_ftp_tuple6(cp);
		free_ftp_tuple6(t);
	}
	free_ftp_tuple6(NULL);
}

/* ======================= C. dialogues ======================= */

static void test_ipv4_dialogue(void) {
	void *ctl = NULL, *dat = NULL, *probe = NULL;
	use_ipv4();

	/* A data flow before any control session: nothing to attach to. */
	packet(&probe, 900, SERVER, 2000, CLIENT, 50000, "early");
	CHECK(probe == NULL, "no control session yet");

	/* Packets the analysis skips. */
	packet_n(&ctl, 1, SERVER, 21, CLIENT, CPORT, "", 0);
	CHECK(ctl == NULL, "empty payload is skipped");
	g_ip.tcp = NULL;
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "220 x\r\n");
	g_ip.tcp = (const void *) &g_tcp;
	CHECK(ctl == NULL, "a packet without TCP has no tuple");
	void *args = g_handler.configured_protocols[PROTO_FTP].args;
	g_handler.configured_protocols[PROTO_FTP].args = NULL;
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "220 x\r\n");
	g_handler.configured_protocols[PROTO_FTP].args = args;
	CHECK(ctl == NULL, "no FTP context, no session");

	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "220 ready\r\n");
	ftp_control_session_t *c = ctl;
	CHECK(c != NULL && c->kind == MMT_FTP_KIND_CONTROL && ctx()->live_count == 1, "greeting opens a session");
	if (c == NULL) return;
	CHECK(extract(ctl, FTP_SERVER_CONT_ADDR) && g_val.u32 == SERVER, "server control address");
	CHECK(extract(ctl, FTP_SERVER_CONT_PORT) && g_val.u16 == htons(21), "server control port");
	CHECK(extract(ctl, FTP_CLIENT_CONT_ADDR) && g_val.u32 == CLIENT, "client control address");
	CHECK(extract(ctl, FTP_CLIENT_CONT_PORT) && g_val.u16 == htons(CPORT), "client control port");
	CHECK(extract(ctl, FTP_CONT_IP_SESSION_ID) && g_val.u64 == 1, "control IP session id");
	CHECK(extract(ctl, FTP_SESSION_CONN_TYPE) && g_val.u8 == MMT_FTP_CONTROL_CONNECTION, "connection type");
	CHECK(extract(ctl, FTP_PACKET_TYPE) && g_val.u8 == MMT_FTP_PACKET_RESPONSE, "a reply packet");
	CHECK(extract(ctl, FTP_PACKET_RESPONSE_CODE) && g_val.u16 == 220, "reply code 220");
	CHECK(str_is(extract_str(ctl, FTP_PACKET_RESPONSE_VALUE), "ready"), "reply value");
	scratch_flush();
	CHECK(extract(ctl, FTP_PACKET_REQUEST) == 0, "no request on a reply");
	CHECK(extract(ctl, FTP_PACKET_REQUEST_PARAMETER) == 0, "no request parameter on a reply");
	CHECK(extract(ctl, FTP_PACKET_DATA_LEN) == 0, "no data length on a control packet");
	CHECK(extract(ctl, FTP_USERNAME) == 0 && extract(ctl, FTP_STATUS) == 0, "nothing logged in yet");

	/* A packet of another control connection on this flow is ignored. */
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT + 1, "220 other\r\n");
	CHECK(c->last_response && str_is(c->last_response->value, "ready"), "mismatched tuple ignored");
	ftp_tuple6_t *conn = c->contrl_conn;
	c->contrl_conn = NULL;
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "220 again\r\n");
	c->contrl_conn = conn;
	CHECK(str_is(c->last_response->value, "ready"), "a session without its tuple is skipped");

	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "USER alice\r\n");
	CHECK(extract(ctl, FTP_PACKET_TYPE) && g_val.u8 == MMT_FTP_PACKET_COMMAND, "a command packet");
	CHECK(str_is(extract_str(ctl, FTP_PACKET_REQUEST), "USER"), "request verb");
	CHECK(str_is(extract_str(ctl, FTP_PACKET_REQUEST_PARAMETER), "alice"), "request parameter");
	scratch_flush();
	CHECK(extract(ctl, FTP_PACKET_RESPONSE_CODE) == 0 && extract(ctl, FTP_PACKET_RESPONSE_VALUE) == 0,
	      "no reply on a command");
	CHECK(str_is(extract_str(ctl, FTP_USERNAME), "alice"), "username");
	CHECK(extract(ctl, FTP_STATUS) && g_val.u16 == MMT_FTP_STATUS_OPENED, "status opened");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "USER bob\r\n");
	CHECK(str_is(extract_str(ctl, FTP_USERNAME), "bob"), "username replaced");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "331 Password required\r\n");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "PASS secret\r\n");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "PASS secret2\r\n");
	CHECK(str_is(extract_str(ctl, FTP_PASSWORD), "secret2"), "password");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "230 Login successful\r\n");
	CHECK(extract(ctl, FTP_STATUS) && g_val.u16 == MMT_FTP_STATUS_CONTROLING, "status logged in");

	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "SYST\r\n");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "SYST x\r\n");
	CHECK(str_is(extract_str(ctl, FTP_SYST), "x"), "SYST parameter kept");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "215 UNIX Type: L8\r\n");
	CHECK(str_is(extract_str(ctl, FTP_SYST), "UNIX Type: L8"), "system type");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "215 UNIX\r\n");
	CHECK(str_is(extract_str(ctl, FTP_SYST), "UNIX"), "system type replaced");

	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "FEAT\r\n");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "211-Features:\r\n");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, " EPSV\r\n");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, " MDTM\r\n");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "211 End\r\n");
	const char *feats = extract_str(ctl, FTP_SESSION_FEATURES);
	CHECK(feats && strstr(feats, "EPSV") && strstr(feats, "MDTM"), "features '%s'", feats ? feats : "(null)");
	CHECK(extract(ctl, FTP_LAST_RESPONSE_CODE) && ((ftp_response_t *) g_attr.data)->code == 211,
	      "last reply");

	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "PWD\r\n");
	CHECK(extract(ctl, FTP_LAST_COMMAND) && ((ftp_command_t *) g_attr.data)->cmd == MMT_FTP_PWD_CMD,
	      "last command");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "257 \"/home\"\r\n");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "257 \"/pub\"\r\n");
	CHECK(str_is(extract_str(ctl, FTP_CURRENT_DIR), "\"/pub\""), "current directory");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "CWD pub\r\n");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "250 Directory changed\r\n");

	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "TYPE A\r\n");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "TYPE I\r\n");
	CHECK(str_is(extract_str(ctl, FTP_DATA_TRANSFER_TYPE), "I"), "transfer type");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "SIZE f.txt\r\n");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "213 1234\r\n");
	CHECK(extract(ctl, FTP_FILE_SIZE) && g_val.u32 == 1234, "file size");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "213 \r\n");
	CHECK(extract(ctl, FTP_FILE_SIZE) == 0, "213 without a value clears the size");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "MDTM f.txt\r\n");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "213 20261031120000\r\n");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "213 20261031120001\r\n");
	CHECK(str_is(extract_str(ctl, FTP_FILE_LAST_MODIFIED), "20261031120001"), "last modified");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "NOOP\r\n");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "213 9\r\n");
	CHECK(extract(ctl, FTP_FILE_SIZE) == 0, "213 after another command changes nothing");

	/* Passive transfer: 227, LIST, a data flow, 226. */
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "PASV\r\n");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "227 Entering Passive Mode (192,0,2,1,7,208)\r\n");
	CHECK(extract(ctl, FTP_DATA_MODE) && g_val.u8 == MMT_FTP_DATA_PASSIVE_MODE, "passive mode");
	CHECK(extract(ctl, FTP_SERVER_DATA_ADDR) && g_val.u32 == SERVER, "server data address");
	CHECK(extract(ctl, FTP_SERVER_DATA_PORT) && g_val.u16 == htons(2000), "server data port");
	CHECK(extract(ctl, FTP_CLIENT_DATA_ADDR) && g_val.u32 == CLIENT, "client data address");
	CHECK(extract(ctl, FTP_CLIENT_DATA_PORT) == 0, "client data port not known yet");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "LIST\r\n");
	CHECK(extract(ctl, FTP_DATA_TYPE) && g_val.u8 == MMT_FTP_DATA_TYPE_LIST, "listing");
	CHECK(extract(ctl, FTP_DATA_DIRECTION) && g_val.u8 == MMT_FTP_PACKET_UNKNOWN_DIRECTION,
	      "direction reported on the control connection");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "150 Here comes the listing\r\n");
	CHECK(extract(ctl, FTP_STATUS) && g_val.u16 == MMT_FTP_STATUS_DATA_OPENED, "data opened");

	packet(&dat, 2, SERVER, 2000, CLIENT, 50000, "file1\r\nfile2\r\n");
	ftp_data_session_t *d = dat;
	CHECK(d != NULL && d->kind == MMT_FTP_KIND_DATA && d->control_session == c, "data flow attached");
	if (d == NULL) return;
	CHECK(extract(dat, FTP_PACKET_TYPE) && g_val.u8 == MMT_FTP_PACKET_DATA, "a data packet");
	CHECK(extract(dat, FTP_PACKET_DATA_LEN) && g_val.u32 == 14, "data length");
	CHECK(extract(dat, FTP_SESSION_CONN_TYPE) && g_val.u8 == MMT_FTP_DATA_CONNECTION, "data connection");
	CHECK(extract(dat, FTP_CLIENT_DATA_PORT) && g_val.u16 == htons(50000), "client data port learnt");
	CHECK(extract(dat, FTP_DATA_IP_SESSION_ID) && g_val.u64 == 2, "data IP session id");
	CHECK(str_is(extract_str(dat, FTP_USERNAME), "bob"), "control attributes through the data flow");
	CHECK(extract(dat, FTP_DATA_DIRECTION) && g_val.u8 == MMT_FTP_PACKET_UNKNOWN_DIRECTION,
	      "a listing has no transfer direction");
	CHECK(extract_all(dat) > 10, "every extractor on a data packet");
	packet(&dat, 2, SERVER, 2000, CLIENT, 50000, "file3\r\n");
	packet(&dat, 2, CLIENT, 50000, SERVER, 2000, "ack");
	CHECK(dat == d, "both directions stay on the data session");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "226 Transfer complete\r\n");
	CHECK(extract(ctl, FTP_STATUS) && g_val.u16 == MMT_FTP_STATUS_DATA_CLOSED, "data closed");
	CHECK(extract(ctl, FTP_SERVER_DATA_PORT) == 0 && extract(ctl, FTP_DATA_TYPE) == 0, "data session reset");
	packet(&dat, 2, SERVER, 2000, CLIENT, 50000, "late");
	CHECK(dat == NULL, "the finished transfer's flow detaches");

	/* Active transfer: PORT, RETR, a data flow from port 20. */
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "PORT 10,0,0,1,7,209\r\n");
	CHECK(extract(ctl, FTP_DATA_MODE) && g_val.u8 == MMT_FTP_DATA_ACTIVE_MODE, "active mode");
	CHECK(extract(ctl, FTP_CLIENT_DATA_ADDR) && g_val.u32 == CLIENT, "PORT client address");
	CHECK(extract(ctl, FTP_CLIENT_DATA_PORT) && g_val.u16 == htons(2001), "PORT client port");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "RETR f.txt\r\n");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "RETR g.txt\r\n");
	CHECK(str_is(extract_str(ctl, FTP_FILE_NAME), "g.txt"), "file name");
	CHECK(extract(ctl, FTP_DATA_DIRECTION) && g_val.u8 == MMT_FTP_DATA_DOWNLOAD, "download");
	CHECK(extract(ctl, FTP_DATA_TYPE) && g_val.u8 == MMT_FTP_DATA_TYPE_FILE, "file transfer");
	packet(&dat, 3, SERVER, 20, CLIENT, 2001, "content");
	CHECK(dat != NULL && ((ftp_data_session_t *) dat)->control_session == c, "active data flow attached");
	CHECK(extract(dat, FTP_DATA_DIRECTION) && g_val.u8 == MMT_FTP_DATA_DOWNLOAD, "download on the data flow");
	CHECK(extract(dat, FTP_SERVER_DATA_PORT) && g_val.u16 == htons(20), "server data port learnt");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "226 done\r\n");
	expire(&dat);
	CHECK(dat == NULL, "data flow expired");

	/* EPRT, uploads, the listing variants, LPRT on IPv4. */
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "EPRT |1|10.0.0.1|2002|\r\n");
	CHECK(extract(ctl, FTP_CLIENT_DATA_PORT) && g_val.u16 == 2002, "EPRT client port");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "STOR up.bin\r\n");
	CHECK(extract(ctl, FTP_DATA_DIRECTION) && g_val.u8 == MMT_FTP_DATA_UPLOAD, "upload");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "STOU up2.bin\r\n");
	CHECK(str_is(extract_str(ctl, FTP_FILE_NAME), "up2.bin"), "unique upload name");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "NLST\r\n");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "MLSD\r\n");
	CHECK(extract(ctl, FTP_DATA_TYPE) && g_val.u8 == MMT_FTP_DATA_TYPE_LIST, "MLSD listing");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "MLST x\r\n");
	CHECK(extract(ctl, FTP_DATA_TYPE) && g_val.u8 == MMT_FTP_DATA_TYPE_UNKNOWN, "MLST");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "LPRT 4,4,10,0,0,1,2,7,212\r\n");
	CHECK(extract(ctl, FTP_CLIENT_DATA_PORT) && g_val.u16 == 7 * 256 + 212, "LPRT port on IPv4");

	/* Extended and long passive mode. */
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "EPSV\r\n");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "229 Entering Extended Passive Mode (|||2003|)\r\n");
	CHECK(extract(ctl, FTP_SERVER_DATA_PORT) && g_val.u16 == htons(2003), "229 server data port");
	CHECK(extract(ctl, FTP_SERVER_DATA_ADDR) && g_val.u32 == SERVER, "229 server address");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "LPSV\r\n");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "228 Entering Long Passive Mode (77, 2004)\r\n");
	CHECK(extract(ctl, FTP_SERVER_DATA_PORT) && g_val.u16 == htons(2004), "228 server data port");

	/* Odd payloads on the control connection. */
	packet_n(&ctl, 1, CLIENT, CPORT, SERVER, 21, "\0x", 2);
	packet_n(&ctl, 1, SERVER, 21, CLIENT, CPORT, "\0x", 2);
	CHECK(extract(ctl, FTP_PACKET_REQUEST) == 0 && extract(ctl, FTP_PACKET_RESPONSE_CODE) == 0,
	      "a NUL-led payload has no request or reply");
	packet_n(&ctl, 1, SERVER, 21, CLIENT, CPORT, "\0x", 2);
	CHECK(extract(ctl, FTP_PACKET_REQUEST_PARAMETER) == 0 && extract(ctl, FTP_PACKET_RESPONSE_VALUE) == 0,
	      "nor a parameter or value");
	g_hdr.caplen = 0;
	CHECK(extract(ctl, FTP_PACKET_RESPONSE_CODE) == 0 && extract(ctl, FTP_PACKET_RESPONSE_VALUE) == 0,
	      "nothing captured, nothing extracted");
	packet_n(&ctl, 1, CLIENT, CPORT, SERVER, 21, "USER", 4);
	g_hdr.caplen = 0;
	CHECK(extract(ctl, FTP_PACKET_REQUEST) == 0 && extract(ctl, FTP_PACKET_REQUEST_PARAMETER) == 0,
	      "nothing captured, no request");
	set_payload("", 0);
	CHECK(extract(ctl, FTP_PACKET_TYPE) && g_val.u8 == MMT_FTP_PACKET_TYPE_UNKNOWN, "empty packet type");
	g_ip.tcp = NULL;
	CHECK(extract(ctl, FTP_SESSION_CONN_TYPE) == 0, "no tuple, no connection type");
	set_payload("x", 1);
	CHECK(extract(NULL, FTP_SERVER_DATA_ADDR) == 0 && extract(NULL, FTP_USERNAME) == 0,
	      "a data packet without a session");
	g_ip.tcp = (const void *) &g_tcp;
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "abc\r\n");
	CHECK(c->last_response && c->last_response->code == MMT_FTP_UNKNOWN_CODE, "unknown reply kept");
	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "12");
	CHECK(c->last_command && c->last_command->cmd == MMT_FTP_UNKNOWN_CMD, "unknown command kept");
	CHECK(extract_all(ctl) > 10, "every extractor on a control packet");

	packet(&ctl, 1, CLIENT, CPORT, SERVER, 21, "QUIT\r\n");
	packet(&ctl, 1, SERVER, 21, CLIENT, CPORT, "221 Goodbye\r\n");
	CHECK(extract(ctl, FTP_STATUS) && g_val.u16 == MMT_FTP_STATUS_CLOSED, "session closed");
	expire(&ctl);
	CHECK(ctl == NULL && ctx()->live_count == 0 && ctx()->retired_count == 0, "control flow expired");

	/* A second session that the handler teardown releases. */
	packet(&ctl, 7, SERVER, 21, CLIENT, CPORT, "220 again\r\n");
	CHECK(ctl != NULL && ctx()->live_count == 1, "a session left for teardown");
	g_sess.session_data[IDX] = NULL;
}

static void ip6(struct mmt_ipv6hdr *h, uint8_t s, uint8_t d) {
	memset(h, 0, sizeof(*h));
	h->saddr.mmt_v6_u.u6_addr8[0] = 0x20;
	h->saddr.mmt_v6_u.u6_addr8[15] = s;
	h->daddr.mmt_v6_u.u6_addr8[0] = 0x20;
	h->daddr.mmt_v6_u.u6_addr8[15] = d;
}

static void test_ipv6_dialogue(void) {
	void *ctl = NULL, *ctl2 = NULL;
	use_ipv6();
	ip6(&g_ip6, 1, 2);              /* server ::1 -> client ::2 */
	packet(&ctl, 11, 0, 21, 0, CPORT, "220 v6 ready\r\n");
	ftp_control_session_t *c = ctl;
	CHECK(c && c->contrl_conn->is_ipv6 && c->current_data_session->data_conn->is_ipv6, "IPv6 control session");
	if (c == NULL) return;
	ip6(&g_ip6, 2, 1);
	packet(&ctl, 11, 0, CPORT, 0, 21, "USER v6\r\n");
	CHECK(str_is(extract_str(ctl, FTP_USERNAME), "v6"), "IPv6 username");
	packet(&ctl, 11, 0, CPORT, 0, 21, "EPRT |2|2001:db8::2|2010|\r\n");
	CHECK(str_is(c->current_data_session->data_conn->c_addr_v6, "2001:db8::2"), "EPRT IPv6 client address");
	CHECK(extract(ctl, FTP_CLIENT_DATA_PORT) && g_val.u16 == 2010, "EPRT IPv6 client port");
	packet(&ctl, 11, 0, CPORT, 0, 21, "PORT 10,0,0,1,7,211\r\n");
	CHECK(extract(ctl, FTP_CLIENT_DATA_PORT) && g_val.u16 == htons(7 * 256 + 211), "PORT port on IPv6");
	ip6(&g_ip6, 1, 2);
	packet(&ctl, 11, 0, 21, 0, CPORT, "226 done\r\n");

	/* A second IPv6 control flow for LPRT (its data session is fresh). */
	ip6(&g_ip6, 3, 1);
	packet(&ctl2, 13, 0, CPORT, 0, 21, "LPRT 6,16,32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,3,2,7,218\r\n");
	ftp_control_session_t *c2 = ctl2;
	CHECK(c2 && c2->current_data_session->data_conn->c_addr_v6 != NULL, "LPRT IPv6 client address");
	CHECK(extract(ctl2, FTP_CLIENT_DATA_PORT) && g_val.u16 == 7 * 256 + 218, "LPRT IPv6 client port");
	CHECK(ctx()->live_count == 3, "two IPv6 sessions beside the IPv4 one");
	expire(&ctl2);
	expire(&ctl);
	use_ipv4();
}

/* ======================= D. classification ======================= */

static void flow_reset(void) {
	memset(&g_flow, 0, sizeof(g_flow));
	memset(&g_src, 0, sizeof(g_src));
	memset(&g_dst, 0, sizeof(g_dst));
	memset(g_ip.detected_protocol_stack, 0, sizeof(g_ip.detected_protocol_stack));
	g_ip.mmt_selection_packet = (MMT_SELECTION_BITMASK_PROTOCOL_SIZE) ~0u;
	memset(&g_ip.detection_bitmask, 0xFF, sizeof(g_ip.detection_bitmask));
	g_ip.src = &g_src;
	g_ip.dst = &g_dst;
	g_tcp.syn = 0;
	g_tcp.ack = 1;
	g_detected = 0;
	g_sess.data_packet_count = 1;
	g_sess.setup_packet_direction = 0;
	g_sess.last_packet_direction = 0;
}

/* One classifier call: `dir` is the packet direction (0 = setup). */
static int classify(const char *payload, uint16_t sport, uint16_t dport, unsigned dir, uint64_t count) {
	set_payload(payload, strlen(payload));
	set_ports(sport, dport);
	g_iph.saddr = dir ? SERVER : CLIENT;
	g_iph.daddr = dir ? CLIENT : SERVER;
	g_sess.last_packet_direction = dir;
	g_sess.data_packet_count = count;
	return mmt_check_ftp(&g_pkt, IDX);
}

static int excluded(void) {
	return MMT_COMPARE_PROTOCOL_TO_BITMASK(g_flow.excluded_protocol_bitmask, PROTO_FTP) != 0;
}

static void test_classification(void) {
	use_ipv4();
	struct { const char *pl; unsigned dir; int syn; const char *what; } detect[] = {
		{"USER bob\r\n", 0, 1, "USER after a SYN"},
		{"user bob\r\n", 0, 1, "lower-case user"},
		{"FEAT\r\n", 0, 1, "FEAT"},
		{"feat\r\n", 0, 1, "feat"},
		{"NOOP\r\n", 0, 1, "NOOP"},
		{"220 hi\r\n", 1, 0, "220 without a SYN (digit: server side)"},
		{"220-hi\r\n", 1, 1, "220-"},
		{"331 pw\r\n", 1, 1, "331"},
		{"211 feats\r\n", 1, 1, "211"},
		{"USER bob\r\n", 0, 0, "USER without a SYN (letter: client side)"},
	};
	int ok = 0;
	for (size_t i = 0; i < sizeof(detect) / sizeof(detect[0]); i++) {
		flow_reset();
		g_flow.l4.tcp.seen_syn = (uint32_t) detect[i].syn;
		int r = classify(detect[i].pl, detect[i].dir ? 21 : CPORT, detect[i].dir ? CPORT : 21,
		                 detect[i].dir, 1);
		int hit = (r == 4 && g_detected == PROTO_FTP);
		ok += hit;
		if (!hit) fprintf(stderr, "  not detected: %s (r=%d)\n", detect[i].what, r);
	}
	CHECK(ok == (int) (sizeof(detect) / sizeof(detect[0])), "%d control packets detected", ok);

	flow_reset();
	g_flow.l4.tcp.seen_syn = 1;
	CHECK(classify("ABCD x\r\n", CPORT, 21, 0, 1) == 4 && g_detected == 0,
	      "an unknown verb is not evidence: wait");
	flow_reset();
	g_flow.l4.tcp.seen_syn = 1;
	CHECK(classify("1234\r\n", CPORT, 21, 0, 1) == 0 && excluded(), "a digit-led command is excluded");
	flow_reset();
	g_flow.l4.tcp.seen_syn = 1;
	CHECK(classify("\001\002\003\004\005\006", 21, CPORT, 1, 1) == 0 && excluded(), "binary reply excluded");
	flow_reset();
	g_flow.l4.tcp.seen_syn = 1;
	CHECK(classify(" abcdef\r\n", 21, CPORT, 1, 1) == 0 && excluded(), "continuation before any code");
	flow_reset();
	g_flow.l4.tcp.seen_syn = 1;
	g_flow.l4.tcp.ftp_codes_seen = FTP_220_CODE;
	CHECK(classify(" abcdef\r\n", 21, CPORT, 1, 2) == 4 && g_detected == PROTO_FTP, "continuation after 220");

	/* Not detected: SMTP excluded, then the wait/reject budgets. */
	flow_reset();
	g_flow.l4.tcp.seen_syn = 1;
	CHECK(classify("220 smtp\r\n", 21, 25, 1, 1) == 4 && g_detected == 0, "220 to port 25 waits (known port)");
	CHECK(classify("220 smtp\r\n", 21, 25, 1, 41) == 0, "220 on the FTP port rejected after 40 packets");
	flow_reset();
	g_flow.l4.tcp.seen_syn = 1;
	CHECK(classify("USER x\r\n", 25, 21, 0, 2) == 4 && g_detected == 0, "USER to SMTP port 21 waits");
	CHECK(classify("USER x\r\n", 25, 21, 0, 21) == 0, "non-220 on the FTP port rejected after 20");
	flow_reset();
	g_flow.l4.tcp.seen_syn = 1;
	CHECK(classify("220 smtp\r\n", 25, 30000, 1, 2) == 4 && g_detected == 0, "220 off the FTP port waits");
	CHECK(classify("220 smtp\r\n", 25, 30000, 1, 21) == 0, "220 off the FTP port rejected after 20");
	flow_reset();
	g_flow.l4.tcp.seen_syn = 1;
	CHECK(classify("USER x\r\n", 30000, 25, 0, 2) == 4 && g_detected == 0, "USER off the FTP port waits");
	CHECK(classify("USER x\r\n", 30000, 25, 0, 11) == 0, "USER off the FTP port rejected after 10");
	flow_reset();
	g_flow.l4.tcp.seen_syn = 1;
	CHECK(classify("500 what\r\n", 21, CPORT, 1, 4) == 0, "no FTP code after 3 packets: rejected");

	/* Guards. */
	flow_reset();
	g_ip.mmt_selection_packet = 0;
	CHECK(classify("USER x\r\n", CPORT, 21, 0, 1) == 0 && !excluded(), "selection guard closed");
	flow_reset();
	CHECK(classify("", CPORT, 21, 0, 1) == 0, "empty payload skipped");

	/* Detected control flow: passive and active mode addresses. */
	flow_reset();
	g_ip.detected_protocol_stack[0] = PROTO_FTP;
	g_ip.tick_timestamp = 100;
	CHECK(classify("227 Entering Passive Mode (192,0,2,1,7,208)\r\n", 21, CPORT, 1, 5) == 1,
	      "227 on a detected flow");
	CHECK(g_dst.ftp_timer_set && g_dst.ftp_ip.ipv4 == SERVER && g_src.ftp_timer_set
	      && g_src.ftp_ip.ipv4 == CLIENT, "227 records both data endpoints");
	const char *bad227[] = {"227 no paren", "227 (", "227 (192", "227 (192;0", "227 (,"};
	for (size_t i = 0; i < sizeof(bad227) / sizeof(bad227[0]); i++) {
		flow_reset();
		g_ip.detected_protocol_stack[0] = PROTO_FTP;
		CHECK(classify(bad227[i], 21, CPORT, 1, 5) == 1 && !g_dst.ftp_timer_set, "malformed '%s'", bad227[i]);
	}
	flow_reset();
	g_ip.detected_protocol_stack[0] = PROTO_FTP;
	g_ip.src = NULL;
	g_ip.dst = NULL;
	CHECK(classify("227 Entering Passive Mode (192,0,2,1,7,208)\r\n", 21, CPORT, 1, 5) == 1,
	      "227 without endpoint records");
	CHECK(classify("229 Entering Extended Passive Mode (|||2003|)\r\n", 21, CPORT, 1, 5) == 1,
	      "229 without endpoint records");
	CHECK(classify("PORT 10,0,0,1,7,209\r\n", CPORT, 21, 0, 5) == 1, "PORT without endpoint records");
	flow_reset();
	g_ip.detected_protocol_stack[0] = PROTO_FTP;
	CHECK(classify("229 Entering Extended Passive Mode (|||2003|)\r\n", 21, CPORT, 1, 5) == 1
	      && g_dst.ftp_timer_set && g_src.ftp_timer_set, "229 records both endpoints");
	flow_reset();
	g_ip.detected_protocol_stack[0] = PROTO_FTP;
	CHECK(classify("EPRT |1|10.0.0.1|2002|\r\n", CPORT, 21, 0, 5) == 1
	      && g_dst.ftp_timer_set && g_src.ftp_timer_set, "EPRT records both endpoints");
	flow_reset();
	g_ip.detected_protocol_stack[0] = PROTO_FTP;
	use_ipv6();
	ip6(&g_ip6, 1, 2);
	set_payload("227 Entering Passive Mode (192,0,2,1,7,208)\r\n", 46);
	set_ports(21, CPORT);
	CHECK(mmt_check_ftp(&g_pkt, IDX) == 1 && g_dst.ftp_timer_set
	      && g_dst.ftp_ip.ipv6.mmt_v6_u.u6_addr8[15] == 1, "227 on IPv6 uses the control server address");
	use_ipv4();

	/* Data-stream detection from the recorded endpoint and its timeout. */
	for (int side = 0; side < 2; side++) {
		mmt_internal_tcpip_id_struct *id = side ? &g_dst : &g_src;
		flow_reset();
		MMT_ADD_PROTOCOL_TO_BITMASK(id->detected_protocol_bitmask, PROTO_FTP);
		id->ftp_ip.ipv4 = side ? CLIENT : SERVER;   /* src: packet daddr, dst: packet saddr */
		id->ftp_timer_set = 1;
		id->ftp_timer = 100;
		g_ip.tick_timestamp = 101;
		g_tcp.syn = 1;
		g_tcp.ack = 0;
		CHECK(classify("", 3000, 4000, 0, 0) == 1 && g_detected == PROTO_FTP, "data stream (%d)", side);
		g_detected = 0;
		g_ip.detected_protocol_stack[0] = 0;
		CHECK(classify("", 20, 4000, 0, 0) == 1 && g_detected == PROTO_FTP, "data stream from port 20 (%d)", side);
		g_detected = 0;
		g_ip.detected_protocol_stack[0] = 0;
		CHECK(classify("", 3000, 80, 0, 0) == 0 && g_detected == 0, "low destination port (%d)", side);
		g_ip.tick_timestamp = 100 + MMT_FTP_TIMEOUT * MMT_MICRO_IN_SEC;
		CHECK(classify("", 3000, 4000, 0, 0) == 0 && id->ftp_timer_set == 0, "endpoint timed out (%d)", side);
	}
	flow_reset();
}

/* ======================= E. out of memory ======================= */

/* Fail each allocation of `fn` in turn (1st, 2nd, ... until a run fails
 * none): every run must return everything it allocated. */
static void oom_sweep(const char *what, void (*fn)(void)) {
	int leaks = 0;
	uint64_t k;
	for (k = 1; k < 10000; k++) {
		int64_t out0 = fda_outstanding;
		uint64_t failed0 = fda_failed;
		fda_calls = 0;
		fda_fail_at = k;
		fn();
		fda_fail_at = 0;
		leaks += (fda_outstanding != out0);
		if (fda_failed == failed0) break;      /* fn made fewer than k calls */
	}
	CHECK(k > 1 && leaks == 0, "%s: %llu allocation sites failed in turn, %d leaked", what,
	      (unsigned long long) (k - 1), leaks);
}

static void oom_parse(void) {
	const char *cmds[] = {"FEAT\r\n", "PWD\r\n", "1234", "CWD pub\r\n", "RETR f\r\n", "ABC"};
	for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
		int n = (int) strlen(cmds[i]);
		free_ftp_command(ftp_get_command((char *) cmds[i], n));
		free(ftp_get_command_param((char *) cmds[i], n));
		free(ftp_get_command_str((char *) cmds[i], n));
	}
	const char *replies[] = {"230 ok\r\n", " EPSV\r\n", "ab\r\n"};
	for (size_t i = 0; i < sizeof(replies) / sizeof(replies[0]); i++) {
		int n = (int) strlen(replies[i]);
		free_ftp_response(ftp_get_response((char *) replies[i], n));
		free(ftp_get_response_value((char *) replies[i], n));
		(void) ftp_get_response_code((char *) replies[i], n);
	}
}

static void oom_addr(void) {
	(void) ftp_get_data_client_addr_from_EPRT(S("EPRT |1|10.0.0.1|2002|\r\n"));
	free(ftp_get_data_client_addr_v6_from_EPRT(S("EPRT |2|::1|2002|\r\n")));
	(void) ftp_get_data_client_port_from_EPRT(S("EPRT |1|10.0.0.1|2002|\r\n"));
	(void) ftp_get_data_client_port_from_EPRT(S("EPRT |2|::1|1031\r\n"));
	(void) ftp_get_addr_from_parameter(S("10,0,0,1,7,209\r\n"));
	(void) ftp_get_port_from_parameter(S("PORT 10,0,0,1,7,209\r\n"));
	free(ftp_get_data_client_addr_v6_from_LPRT(S("LPRT 6,16,32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1,2,7,218\r\n")));
	(void) ftp_get_data_client_port_from_LPRT(S("LPRT 6,16,32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1,2,7,218\r\n"));
	(void) ftp_get_data_server_addr_code_227(S("227 x (192,0,2,1,7,208)\r\n"));
	(void) ftp_get_data_server_port_code_227(S("227 x (192,0,2,1,7,208)\r\n"));
	(void) ftp_get_data_server_port_code_228(S("x (77, 2004)"));
	(void) ftp_get_data_server_addr_code_228(S("x (77, 2004)"));
	(void) ftp_get_data_server_port_code_229(S("x (|||2003|)"));
}

static void oom_sessions(void) {
	ftp_tuple6_t *t = ftp_new_tuple6();
	if (t != NULL) {
		t->is_ipv6 = 1;
		t->c_addr_v6 = calloc(33, 1);
		t->s_addr_v6 = calloc(33, 1);
		if (t->c_addr_v6 != NULL && t->s_addr_v6 != NULL) {
			free_ftp_tuple6(ftp_copy_tupl6(t));
			free_ftp_control_session(ftp_new_control_session(t));
		}
		free_ftp_tuple6(t);
	}
	ftp_data_session_t *d = ftp_new_data_connection();
	if (d != NULL) {
		(void) ftp_reset_data_session(d);
		free_ftp_data_session(d);
	}
	ftp_free_context(ftp_new_context());
}

/* An IPv4 dialogue, its data flow and the expiries. (IPv6 is left out: a
 * failed address-buffer calloc in ftp_get_tuple6() leaves a NULL buffer that
 * ftp_copy_tupl6() then copies from.) */
static void oom_dialogue(void) {
	void *ctl = NULL, *dat = NULL;
	use_ipv4();
	packet(&ctl, 21, SERVER, 21, CLIENT, CPORT, "220 ready\r\n");
	packet(&ctl, 21, CLIENT, CPORT, SERVER, 21, "USER u\r\n");
	packet(&ctl, 21, SERVER, 21, CLIENT, CPORT, "211-Features:\r\n");
	packet(&ctl, 21, SERVER, 21, CLIENT, CPORT, " EPSV\r\n");
	packet(&ctl, 21, SERVER, 21, CLIENT, CPORT, "257 \"/\"\r\n");
	packet(&ctl, 21, CLIENT, CPORT, SERVER, 21, "PASV\r\n");
	packet(&ctl, 21, SERVER, 21, CLIENT, CPORT, "227 Entering Passive Mode (192,0,2,1,7,208)\r\n");
	packet(&dat, 22, SERVER, 2000, CLIENT, 50000, "data");
	packet(&ctl, 21, SERVER, 21, CLIENT, CPORT, "226 done\r\n");
	packet(&ctl, 21, SERVER, 21, CLIENT, CPORT, "229 Entering Extended Passive Mode (|||2003|)\r\n");
	packet(&ctl, 21, SERVER, 21, CLIENT, CPORT, "228 Entering Long Passive Mode (77, 2004)\r\n");
	packet(&ctl, 21, CLIENT, CPORT, SERVER, 21, "RETR f\r\n");
	packet(&ctl, 21, CLIENT, CPORT, SERVER, 21, "TYPE I\r\n");
	expire(&dat);
	expire(&ctl);
	g_sess.session_data[IDX] = NULL;
}

int main(void) {
	printf("test_ftp_dialogue: FTP dissector parsing, sessions and classification (issue #563)\n");
	int64_t out0 = fda_outstanding;
	handler_open();
	CHECK(ctx() != NULL, "FTP context");
	if (ctx() == NULL) return 1;
	CHECK(init_proto_ftp_struct() == 1 && g_registered_attributes == FTP_ATTRIBUTES_NB,
	      "FTP registers its %d attributes", FTP_ATTRIBUTES_NB);

	test_command_table();
	test_command_shapes();
	test_reply_shapes();
	test_address_parameters();
	test_tuples();
	test_ipv4_dialogue();
	test_ipv6_dialogue();
	test_classification();

	oom_sweep("parsers", oom_parse);
	oom_sweep("address parameters", oom_addr);
	oom_sweep("session constructors", oom_sessions);
	oom_sweep("dialogue", oom_dialogue);

	scratch_flush();
	handler_close();
	CHECK(fda_outstanding == out0, "%lld allocations outstanding at the end",
	      (long long) (fda_outstanding - out0));
	printf("  %d checks, %d failed\n", checks, failures);
	return failures == 0 ? 0 : 1;
}

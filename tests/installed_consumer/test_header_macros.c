/*
 * test_header_macros.c — installed-header namespace consumer (issue #537,
 * F-BUG-010 / F-CLEAN-011).
 *
 * The installed mmt_core.h used to pull in dbg.h, which defined unprefixed
 * debug/check/log_err/sentinel/... macros for every consumer, and
 * mmt_utils.h defined likely/unlikely; mmt_tcpip.h shipped the content and
 * application class tables as `static inline` bodies. This file is compiled
 * against the INSTALLED headers only, with -Werror, by
 * tests/installed_consumer/run_tests.sh, which generates
 * MMT_ALL_HEADERS_FILE: one #include line per header under
 * $(MMT_INC), so every installed header is covered.
 *
 *   -DMMT_OWN_MACROS=1  the consumer defines its own debug, check, likely and
 *                       unlikely BEFORE the headers: a header redefining one
 *                       fails the build (-Werror) and a header that silently
 *                       kept a guarded copy fails the runtime checks below.
 *   -DMMT_OWN_MACROS=0  no consumer macro: after the headers, none of the
 *                       internal macro names may be defined at all.
 *
 * Both modes then call the six class lookups. The program links libmmt_core
 * alone: the TCP/IP plugin answers them through the core when it is loaded
 * (Montimage/mmt-probe#18). With MMT_TEST_TCPIP=absent the plugin directory
 * holds only libmmt_business_app: the lookups report the unknown class and a
 * log line still goes through its own, non-network, protocol stack.
 */
#ifndef MMT_OWN_MACROS
#error "compile with -DMMT_OWN_MACROS=0 or -DMMT_OWN_MACROS=1"
#endif

#if MMT_OWN_MACROS
static int consumer_check(int cond) { return cond ? 11 : 12; }
#define debug(msg)   31
#define check(cond)  consumer_check(cond)
#define likely(x)    ((x) ? 21 : 22)
#define unlikely(x)  ((x) ? 41 : 42)
#endif

#include MMT_ALL_HEADERS_FILE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* No installed header may leave one of dbg.h's internal macros behind. */
#if defined(log_err) || defined(log_warn) || defined(log_info) \
	|| defined(sentinel) || defined(check_mem) || defined(check_debug) \
	|| defined(clean_errno) || defined(mmt_debug_log) \
	|| defined(mmt_stderr_log) || defined(mmt_stream_printf) \
	|| defined(__dbg_h__)
#error "an installed header leaks a dbg.h macro"
#endif

#if !MMT_OWN_MACROS
#if defined(debug) || defined(check) || defined(likely) || defined(unlikely)
#error "an installed header defines debug, check, likely or unlikely"
#endif
#endif

static int checks;
static int failures;
#define EXPECT(cond, msg) do { \
		checks++; \
		if (!(cond)) { \
			failures++; \
			fprintf(stderr, "FAIL %d: %s\n", __LINE__, msg); \
		} \
	} while (0)

/* How many times the process has the TCP/IP plugin's code mapped. */
static int tcpip_mappings(void) {
	char line[1024];
	int n = 0;
	FILE *maps = fopen("/proc/self/maps", "r");
	if (maps == NULL)
		return -1;
	while (fgets(line, sizeof(line), maps) != NULL)
		if (strstr(line, "r-xp") != NULL && strstr(line, "libmmt_tcpip") != NULL)
			n++;
	fclose(maps);
	return n;
}

static int log_lines_seen;
static void on_log_attribute(const ipacket_t *packet, attribute_t *attribute, void *user) {
	(void) packet;
	(void) attribute;
	(void) user;
	log_lines_seen++;
}

/* Without the TCP/IP plugin: unknown classes, and logs are still dissected. */
static void expect_tcpip_absent(void) {
	static const char *content_labels[] = {MMT_CONTENT_LONG_LABELS};
	static const char *class_labels[] = {PROTO_CLASS_LABELS};
	static const char line[] = "TrolleyPos: 32.981, Hoistpos: 38.042, NoOfMarkers: 0";
	char error[1024];
	struct pkthdr header;
	mmt_handler_t *handler;

	EXPECT(tcpip_mappings() == 0, "the TCP/IP plugin is not in the process");
	EXPECT(get_application_class_by_protocol_id(PROTO_STACKPATH) == PROTO_CLASS_UNKOWN,
	       "without the plugin a protocol has the unknown class");
	EXPECT(strcmp(get_application_class_name_by_protocol_id(PROTO_STACKPATH),
	              class_labels[PROTO_CLASS_UNKOWN]) == 0,
	       "without the plugin the application label is the unknown one");
	EXPECT(get_content_class_by_content_type("video/mp4") == MMT_CONTENT_FAMILY_UNSPECIFIED,
	       "without the plugin a content type is unspecified");
	EXPECT(strcmp(get_content_class_name_by_content_type("video/mp4"),
	              content_labels[MMT_CONTENT_FAMILY_UNSPECIFIED]) == 0,
	       "without the plugin the content-type label is the unspecified one");
	EXPECT(get_content_class_by_content_flags(MMT_CONTENT_AUDIO) == MMT_CONTENT_FAMILY_UNSPECIFIED,
	       "without the plugin content flags are unspecified");
	EXPECT(strcmp(get_content_class_name_by_content_flags(MMT_CONTENT_AUDIO),
	              content_labels[MMT_CONTENT_FAMILY_UNSPECIFIED]) == 0,
	       "without the plugin the content-flags label is the unspecified one");

	handler = mmt_init_handler(PROTO_IPS_DATA, 0, error);
	EXPECT(handler != NULL, "the log protocol stack opens a handler");
	if (handler == NULL)
		return;
	EXPECT(register_attribute_handler(handler, PROTO_IPS_DATA, IPS_DATA_TROLLEY_POS,
	                                  on_log_attribute, NULL, NULL),
	       "the log attribute takes a handler");
	memset(&header, 0, sizeof(header));
	header.caplen = header.len = sizeof(line) - 1;
	EXPECT(packet_process(handler, &header, (const u_char *) line) != 0,
	       "the log line is processed");
	EXPECT(log_lines_seen > 0, "the log line is dissected without the TCP/IP plugin");
	mmt_close_handler(handler);
}

int main(void) {
	const char *tcpip = getenv("MMT_TEST_TCPIP");
	static const char *content_labels[] = {MMT_CONTENT_LONG_LABELS};
	static const char *class_labels[] = {PROTO_CLASS_LABELS};

#if MMT_OWN_MACROS
	EXPECT(debug("x") == 31, "consumer debug() survives the installed headers");
	EXPECT(check(1) == 11 && check(0) == 12, "consumer check() survives the installed headers");
	EXPECT(likely(1) == 21 && likely(0) == 22, "consumer likely() survives the installed headers");
	EXPECT(unlikely(1) == 41 && unlikely(0) == 42, "consumer unlikely() survives the installed headers");
#endif
	/* <stdbool.h> semantics, not a private macro copy. */
	EXPECT(true == 1 && false == 0, "true/false keep their <stdbool.h> values");

	EXPECT(init_extraction(), "the plugins load");
	if (tcpip != NULL && strcmp(tcpip, "absent") == 0) {
		expect_tcpip_absent();
		goto done;
	}

	/* The class tables answer from the loaded plugin, mapped exactly once:
	 * a consumer linked against it would hold a second copy. */
	EXPECT(tcpip_mappings() == 1, "the TCP/IP plugin is mapped once");
	EXPECT(get_content_class_by_content_type("video/mp4") == MMT_CONTENT_FAMILY_VIDEO,
	       "video/mp4 is a video content type");
	EXPECT(get_content_class_by_content_type("application/json") == MMT_CONTENT_FAMILY_TEXT,
	       "application/json is a text content type");
	EXPECT(get_content_class_by_content_type("application/zip") == MMT_CONTENT_FAMILY_APPLICATION,
	       "application/zip falls back to the application family");
	EXPECT(get_content_class_by_content_type("") == MMT_CONTENT_FAMILY_UNSPECIFIED,
	       "an empty content type is unspecified");
	EXPECT(strcmp(get_content_class_name_by_content_type("image/png"),
	              content_labels[MMT_CONTENT_FAMILY_IMAGE]) == 0,
	       "image/png is labelled as an image");
	EXPECT(get_content_class_by_content_flags(MMT_CONTENT_AUDIO) == MMT_CONTENT_FAMILY_AUDIO,
	       "the audio content flag maps to the audio family");
	EXPECT(get_content_class_by_content_flags(0) == MMT_CONTENT_FAMILY_UNSPECIFIED,
	       "no content flag is unspecified");
	EXPECT(strcmp(get_content_class_name_by_content_flags(MMT_CONTENT_VIDEO),
	              content_labels[MMT_CONTENT_FAMILY_VIDEO]) == 0,
	       "the video content flag is labelled as video");
	EXPECT(get_application_class_by_protocol_id(PROTO_STACKPATH) == PROTO_CLASS_CDN,
	       "StackPath is a CDN");
	/* Issue #566: the Microsoft 365 ids the hostname table labels. */
	EXPECT(get_application_class_by_protocol_id(PROTO_MS_TEAMS) == PROTO_CLASS_CONVERSATIONAL,
	       "Microsoft Teams is conversational");
	EXPECT(get_application_class_by_protocol_id(PROTO_SHAREPOINT) == PROTO_CLASS_CLOUD_STORAGE,
	       "SharePoint is cloud storage");
	EXPECT(get_application_class_by_protocol_id(PROTO_OFFICE365) == PROTO_CLASS_WEB,
	       "Office 365 is web");
	/* Issue #565: the Google Cloud tenancy id the IP-range table labels,
	 * classed like its AWS peer. */
	EXPECT(PROTO_GOOGLE_CLOUD == 667 && strcmp(PROTO_GOOGLE_CLOUD_ALIAS, "google_cloud") == 0,
	       "PROTO_GOOGLE_CLOUD is id 667, alias google_cloud");
	EXPECT(get_application_class_by_protocol_id(PROTO_GOOGLE_CLOUD)
	           == get_application_class_by_protocol_id(PROTO_AWS),
	       "Google Cloud has the AWS class");
	/* Issue #572: the encapsulations walked to the inner flow are tunnels. */
	EXPECT(PROTO_MPLS == 668 && strcmp(PROTO_MPLS_ALIAS, "mpls") == 0
	       && PROTO_VXLAN == 669 && strcmp(PROTO_VXLAN_ALIAS, "vxlan") == 0
	       && PROTO_GENEVE == 670 && strcmp(PROTO_GENEVE_ALIAS, "geneve") == 0,
	       "PROTO_MPLS/VXLAN/GENEVE are ids 668-670, aliases mpls/vxlan/geneve");
	EXPECT(get_application_class_by_protocol_id(PROTO_MPLS) == PROTO_CLASS_TUNNEL
	       && get_application_class_by_protocol_id(PROTO_VXLAN) == PROTO_CLASS_TUNNEL
	       && get_application_class_by_protocol_id(PROTO_GENEVE) == PROTO_CLASS_TUNNEL,
	       "MPLS, VXLAN and GENEVE are tunnels");
	EXPECT(get_application_class_by_protocol_id(PROTO_UNKNOWN) == PROTO_CLASS_UNKOWN,
	       "the unknown protocol has the unknown class");
	EXPECT(strcmp(get_application_class_name_by_protocol_id(PROTO_STACKPATH),
	              class_labels[PROTO_CLASS_CDN]) == 0,
	       "StackPath is labelled as a CDN");

done:
	close_extraction();
	if (failures) {
		fprintf(stderr, "header-macros consumer: %d/%d checks failed\n", failures, checks);
		return 1;
	}
	printf("header-macros consumer: all %d checks passed\n", checks);
	return 0;
}

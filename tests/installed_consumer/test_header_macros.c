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
 * Both modes then call the six class-table lookups, which link from
 * libmmt_tcpip (-lmmt_tcpip) instead of being compiled into the consumer.
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

int main(void) {
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

	/* The class tables now resolve from libmmt_tcpip. */
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
	EXPECT(get_application_class_by_protocol_id(PROTO_UNKNOWN) == PROTO_CLASS_UNKOWN,
	       "the unknown protocol has the unknown class");
	EXPECT(strcmp(get_application_class_name_by_protocol_id(PROTO_STACKPATH),
	              class_labels[PROTO_CLASS_CDN]) == 0,
	       "StackPath is labelled as a CDN");

	if (failures) {
		fprintf(stderr, "header-macros consumer: %d/%d checks failed\n", failures, checks);
		return 1;
	}
	printf("header-macros consumer: all %d checks passed\n", checks);
	return 0;
}

/*
 * test_byte_order.c — installed-header byte-order consumer (issue #504,
 * F-BUG-009).
 *
 * The public data_defs.h used to #undef ntohl/ntohs and redefine them as
 * unconditional byte swaps that evaluated their argument more than once:
 * every consumer including mmt_core.h got a wrong ntohl on big-endian hosts
 * and a double side effect for ntohl(x++). The header now takes them from
 * <arpa/inet.h>. This file is compiled against the INSTALLED headers only,
 * includes mmt_core.h first and <arpa/inet.h> second (the order that used to
 * leave the override in place), and checks:
 *   - ntohl(x++) / ntohs(*p++) / ntohll(y++) evaluate their argument once;
 *   - ntohl/ntohs/ntohll decode network-order bytes to the right host value
 *     on this host, whatever its byte order;
 *   - the swab16/swab32/swab64 helpers remain unconditional byte swaps.
 */
#include "mmt_core.h"
#include <arpa/inet.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int checks;
static int failures;
#define CHECK(cond, msg) do { \
		checks++; \
		if (!(cond)) { \
			failures++; \
			fprintf(stderr, "FAIL %d: %s\n", __LINE__, msg); \
		} \
	} while (0)

int main(void) {
	static const unsigned char wire[8] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	};
	uint16_t n16;
	uint32_t n32;
	uint64_t n64;
	memcpy(&n16, wire, sizeof(n16));
	memcpy(&n32, wire, sizeof(n32));
	memcpy(&n64, wire, sizeof(n64));

	/* Network-order bytes decode to the same host value on any host. */
	CHECK(ntohs(n16) == 0x0102, "ntohs decodes network order");
	CHECK(ntohl(n32) == 0x01020304UL, "ntohl decodes network order");
	CHECK(ntohll(n64) == 0x0102030405060708ULL, "ntohll decodes network order");
	CHECK(ntohl(htonl(0xa1b2c3d4UL)) == 0xa1b2c3d4UL, "ntohl(htonl(x)) == x");
	CHECK(ntohs(htons(0xa1b2)) == 0xa1b2, "ntohs(htons(x)) == x");

	/* Each macro evaluates its argument exactly once. */
	uint32_t x = 7;
	(void) ntohl(x++);
	CHECK(x == 8, "ntohl(x++) increments x once");
	uint16_t s = 7;
	(void) ntohs(s++);
	CHECK(s == 8, "ntohs(s++) increments s once");
	uint64_t y = 7;
	(void) ntohll(y++);
	CHECK(y == 8, "ntohll(y++) increments y once");
	uint32_t words[2] = { n32, 0 };
	const uint32_t *p = words;
	CHECK(ntohl(*p++) == 0x01020304UL && p == words + 1,
			"ntohl(*p++) reads one word and advances once");

	/* swab* stay unconditional byte swaps. */
	CHECK(swab16(0x0102) == 0x0201, "swab16 swaps bytes");
	CHECK(swab32(0x01020304UL) == 0x04030201UL, "swab32 swaps bytes");
	CHECK(swab64(0x0102030405060708ULL) == 0x0807060504030201ULL,
			"swab64 swaps bytes");

	printf("byte-order consumer: %d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}

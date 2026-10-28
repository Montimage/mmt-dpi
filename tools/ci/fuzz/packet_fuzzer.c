/*
 * packet_fuzzer.c — coverage-guided libFuzzer target for the packet path
 * (issue #530, F-TEST-013).
 *
 * The mutation gate in tools/ci/run-fuzz.sh feeds whole mutated pcaps to
 * phase0_classify without coverage feedback. This target puts libFuzzer in
 * front of packet_process() instead, so mutations that reach new dissector
 * code are kept and mutated further.
 *
 * Input format — a classic pcap file held in memory, so the committed seeds
 * (tools/ci/fuzz/seeds), the regression reproducers
 * (tools/ci/fuzz/regressions) and the golden captures replay unchanged:
 *   - 24-byte global header, either byte order, microsecond or nanosecond
 *     magic; the link type comes from the header;
 *   - then 16-byte record headers, each followed by incl_len frame bytes.
 *     A record longer than the bytes left is clamped to them; a record
 *     larger than 65535 bytes ends the walk.
 * Input without a pcap magic is fed as one Ethernet frame, so mutations
 * that break the header still exercise the dissectors.
 *
 * Each frame is copied into a heap buffer of exactly caplen bytes before
 * packet_process() sees it: AddressSanitizer then reports any read past the
 * captured length, which a pcap reader's larger buffer would hide.
 *
 * Every input gets a fresh handler (mmt_init_handler/mmt_close_handler), so
 * no session state leaks from one input into the next and every finding
 * reproduces from its own file. Library-wide initialisation runs once, in
 * LLVMFuzzerInitialize.
 *
 * Linking: run-fuzz.sh --libfuzzer links libmmt_core.a and libmmt_tcpip.a
 * statically and loads no plugin directory, so this target registers the
 * TCP/IP protocols itself with init_tcpip_plugin() — the core's own
 * package_dependent_init() registers none. Only those two archives can be
 * linked together: every plugin archive defines init_proto().
 *
 * MMT_FUZZ_PRINT_PATHS (set to anything) prints the protocol path of every
 * processed packet on stdout, e.g. "meta.ethernet.ip.tcp.smtp". run-fuzz.sh
 * uses it to check that each seed still reaches the dissector it targets.
 *
 * Build and run: bash tools/ci/run-fuzz.sh --libfuzzer (see its header).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip_plugin.h"

#define PCAP_GLOBAL_HDR_LEN 24
#define PCAP_RECORD_HDR_LEN 16
#define PCAP_MAX_FRAME      65535u   /* packet_process() rejects larger caplen */
#define LINKTYPE_ETHERNET   1u

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int print_paths;

static uint32_t read_u32(const uint8_t *p, int swap) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return swap ? __builtin_bswap32(v) : v;
}

static int print_path(const ipacket_t *ipacket, void *user_args) {
    const proto_hierarchy_t *ph = ipacket->proto_hierarchy;
    int i;

    (void) user_args;
    if (ph == NULL || ph->len <= 0) {
        puts("<none>");
        return 0;
    }
    for (i = 0; i < ph->len && i < PROTO_PATH_SIZE; i++) {
        const char *name = get_protocol_name_by_id(ph->proto_path[i]);
        printf(i == 0 ? "%s" : ".%s", name != NULL ? name : "?");
    }
    putchar('\n');
    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
    if (!init_extraction() || !init_tcpip_plugin()) {
        fprintf(stderr, "packet_fuzzer: SDK initialisation failed\n");
        abort();
    }
    print_paths = getenv("MMT_FUZZ_PRINT_PATHS") != NULL;
    return 0;
}

static void feed_frame(mmt_handler_t *handler, const uint8_t *data, size_t caplen,
                       size_t wire_len, uint32_t sec, uint32_t usec) {
    struct pkthdr header;
    uint8_t *frame;

    if (caplen == 0)
        return;
    frame = malloc(caplen);
    if (frame == NULL)
        return;
    memcpy(frame, data, caplen);
    memset(&header, 0, sizeof(header));
    header.ts.tv_sec = (time_t) sec;
    header.ts.tv_usec = (suseconds_t) usec;
    header.caplen = (unsigned int) caplen;
    /* packet_process() drops a packet whose len is below its caplen. */
    header.len = (unsigned int) (wire_len < caplen ? caplen : wire_len);
    packet_process(handler, &header, frame);
    free(frame);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char errbuf[1024];
    mmt_handler_t *handler;
    uint32_t magic, linktype = LINKTYPE_ETHERNET;
    int swap = -1;
    size_t off;

    if (size >= PCAP_GLOBAL_HDR_LEN) {
        memcpy(&magic, data, sizeof(magic));
        if (magic == 0xa1b2c3d4u || magic == 0xa1b23c4du)
            swap = 0;
        else if (magic == 0xd4c3b2a1u || magic == 0x4d3cb2a1u)
            swap = 1;
        if (swap >= 0)
            linktype = read_u32(data + 20, swap) & 0x0fffffffu;
    }

    handler = mmt_init_handler(linktype, 0, errbuf);
    if (handler == NULL)
        return 0;   /* a link type the SDK does not handle */
    if (print_paths)
        register_packet_handler(handler, 1, print_path, NULL);

    if (swap < 0) {
        feed_frame(handler, data, size > PCAP_MAX_FRAME ? PCAP_MAX_FRAME : size,
                   size, 0, 0);
    } else {
        off = PCAP_GLOBAL_HDR_LEN;
        while (size - off >= PCAP_RECORD_HDR_LEN) {
            const uint8_t *rec = data + off;
            uint32_t sec = read_u32(rec, swap);
            uint32_t usec = read_u32(rec + 4, swap);
            size_t incl = read_u32(rec + 8, swap);
            size_t wire = read_u32(rec + 12, swap);

            off += PCAP_RECORD_HDR_LEN;
            if (incl > size - off)
                incl = size - off;
            if (incl > PCAP_MAX_FRAME)
                break;
            feed_frame(handler, data + off, incl, wire, sec, usec);
            off += incl;
        }
    }
    mmt_close_handler(handler);
    return 0;
}

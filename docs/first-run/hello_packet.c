/* hello_packet.c - a first MMT-DPI program: print the size and the
 * classified protocol path of every packet in a capture.
 *
 * Build against an installed SDK (replace /opt/mmt with your MMT_BASE):
 *   gcc -o hello_packet hello_packet.c -I /opt/mmt/dpi/include \
 *       -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
 * Run on the sample capture published next to this file:
 *   ./hello_packet traffic.pcap
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include "mmt_core.h"

static int on_packet(const ipacket_t *ipacket, void *user_args) {
    uint32_t *len = (uint32_t *)get_attribute_extracted_data_by_name(
        ipacket, "META", "PACKET_LEN");
    char path[256] = "";
    (void)user_args;
    proto_hierarchy_to_str_with_size(ipacket->proto_hierarchy, path, sizeof(path));
    printf("packet %" PRIu64 ": %u bytes, %s\n", ipacket->packet_id,
           len ? *len : 0, path);
    return 0; // returning 1 skips the remaining handlers for this packet
}

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE > MMT_ERRBUF_SIZE ? PCAP_ERRBUF_SIZE : MMT_ERRBUF_SIZE];
    if (argc != 2) {
        fprintf(stderr, "usage: %s <capture.pcap>\n", argv[0]);
        return 1;
    }
    // Open the capture first: a missing file needs no MMT state to report.
    pcap_t *pcap = pcap_open_offline(argv[1], errbuf);
    if (!pcap) {
        fprintf(stderr, "hello_packet: cannot open capture '%s': %s\n", argv[1], errbuf);
        if (strcmp(argv[1], "traffic.pcap") == 0) // only the sample has a download
            fprintf(stderr, "  to fetch the sample capture into the current directory:\n"
                    "  curl -fsSLO https://montimage-projects.github.io/mmt-dpi/first-run/traffic.pcap\n");
        return 1;
    }
    if (pcap_datalink(pcap) != DLT_EN10MB) {
        fprintf(stderr, "hello_packet: '%s' is not an Ethernet capture\n", argv[1]);
        pcap_close(pcap);
        return 1;
    }

    // 1. global state, once, before any handler
    if (!init_extraction()) {
        fprintf(stderr, "hello_packet: init_extraction failed\n");
        pcap_close(pcap);
        return 1;
    }
    // 2. one handler for this packet stream
    mmt_handler_t *handler = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (!handler) {
        fprintf(stderr, "hello_packet: handler init failed: %s\n", errbuf);
        close_extraction();
        pcap_close(pcap);
        return 1;
    }
    // 3. register what to extract and the per-packet callback
    struct pcap_pkthdr *pkt_hdr;
    const u_char *data;
    unsigned long count = 0;
    int rc, status = 1;
    if (!register_extraction_attribute_by_name(handler, "META", "PACKET_LEN")
        || !register_packet_handler(handler, 1, on_packet, NULL)) {
        fprintf(stderr, "hello_packet: registration failed\n");
        goto out;
    }
    // 4. the processing loop: one packet_process() call per captured packet
    while ((rc = pcap_next_ex(pcap, &pkt_hdr, &data)) == 1) {
        struct pkthdr header;
        memset(&header, 0, sizeof(header));
        header.ts = pkt_hdr->ts;
        header.caplen = pkt_hdr->caplen;
        header.len = pkt_hdr->len;
        if (!packet_process(handler, &header, data))
            fprintf(stderr, "hello_packet: packet %lu not processed\n", count + 1);
        count++;
    }
    if (rc == -1) {
        fprintf(stderr, "hello_packet: read error: %s\n", pcap_geterr(pcap));
        goto out;
    }
    printf("%lu packets processed\n", count);
    status = 0;
out:
    // 5. every handler before the global teardown, which comes last
    mmt_close_handler(handler);
    close_extraction();
    pcap_close(pcap);
    return status;
}

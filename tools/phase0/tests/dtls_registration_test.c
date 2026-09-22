/*
 * dtls_registration_test — end-to-end regression test for the DTLS plugin
 * registration gap (issue #262).
 *
 * init_proto_dtls_struct() existed since the DTLS dissector landed but was
 * never listed in proto_init_list.def, so init_tcpip_plugin() never ran it:
 * PROTO_DTLS was absent from the protocol registry, none of the
 * dtls_attributes_metadata[] entries were registered, and
 * classify_dtls_from_udp() was never hooked onto PROTO_UDP — DTLS traffic
 * classified as plain UDP. The guard harness
 * (dtls_classify_guard_test.c) drives the classifier symbol directly, so the
 * gap was invisible to it.
 *
 * This test exercises the real registration path instead:
 *
 *   1. init_extraction() loads the installed plugin .so and runs
 *      init_tcpip_plugin(); PROTO_DTLS must then be present in the protocol
 *      registry (get_protocol_struct_by_id).
 *   2. The DTLS attribute metadata must be extractable —
 *      register_extraction_attribute() fails on an unregistered protocol,
 *      so a successful registration proves the metadata is wired up.
 *   3. A DTLS pcap is replayed through packet_process() — the fully
 *      registered classifier chain — and the recorded proto paths must show
 *      the flow classified as meta.ethernet.ip.udp.dtls, while a
 *      bogus-version (0x0100) datagram on a second flow stays
 *      meta.ethernet.ip.udp.unknown.
 *
 * The pcap (gen_tcpip_pcap.py --pcap dtls) carries 3 packets: a DTLS 1.2
 * ClientHello record and a DTLS application-data record on flow A, plus a
 * valid-content-type / bogus-version datagram on flow B — so the expected
 * path counts are exactly 2 x udp.dtls and 1 x udp.unknown.
 *
 * Build (see run_dtls_registration_test.sh):
 *   gcc -g -O1 -fsanitize=address,undefined -o dtls_registration_test \
 *       dtls_registration_test.c -I<prefix>/dpi/include \
 *       -L<prefix>/dpi/lib -lmmt_core -ldl -lpcap -lpthread -lm
 *
 * Usage: dtls_registration_test <dtls.pcap>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, msg) do {                                         \
        g_checks++;                                                   \
        if (cond) {                                                   \
            printf("  PASS: %s\n", (msg));                            \
        } else {                                                      \
            printf("  FAIL: %s\n", (msg));                            \
            g_failures++;                                             \
        }                                                             \
    } while (0)

#define MAX_PATH_STR 512
#define MAX_DISTINCT 64

typedef struct {
    char path[MAX_PATH_STR];
    unsigned long count;
} path_entry_t;

static path_entry_t g_paths[MAX_DISTINCT];
static int g_npaths = 0;

static void record_path(const char *path) {
    int i;
    for (i = 0; i < g_npaths; i++) {
        if (strcmp(g_paths[i].path, path) == 0) {
            g_paths[i].count++;
            return;
        }
    }
    if (g_npaths >= MAX_DISTINCT) return;
    snprintf(g_paths[g_npaths].path, MAX_PATH_STR, "%s", path);
    g_paths[g_npaths].count = 1;
    g_npaths++;
}

static unsigned long count_of(const char *path) {
    int i;
    for (i = 0; i < g_npaths; i++) {
        if (strcmp(g_paths[i].path, path) == 0) return g_paths[i].count;
    }
    return 0;
}

/* Same fingerprint logic as tcpip_pcap_harness.c / phase0_classify.c. */
static int packet_handler(const ipacket_t *ipacket, void *user_args) {
    (void)user_args;
    char path[MAX_PATH_STR];
    int len = 0;
    int i;
    const proto_hierarchy_t *ph = ipacket->proto_hierarchy;

    if (ph == NULL || ph->len <= 0) {
        record_path("<none>");
        return 0;
    }
    path[0] = '\0';
    for (i = 0; i < ph->len && i < PROTO_PATH_SIZE; i++) {
        const char *name = get_protocol_name_by_id(ph->proto_path[i]);
        int n;
        if (name == NULL) name = "?";
        n = snprintf(path + len, sizeof(path) - len,
                     (i == 0) ? "%s" : ".%s", name);
        if (n < 0 || n >= (int)(sizeof(path) - len)) {
            len = (int)sizeof(path) - 1;
            break;
        }
        len += n;
    }
    record_path(path);
    return 0;
}

int main(int argc, char **argv)
{
    char errbuf[1024];
    mmt_handler_t *mmt_handler;
    pcap_t *pcap;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    const u_char *data;
    struct pcap_pkthdr p_pkthdr;
    struct pkthdr header;
    int datalink;
    int i;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <dtls.pcap>\n", argv[0]);
        return 2;
    }

    printf("=== DTLS registration test (issue #262) ===\n");

    /* init_extraction() -> load_plugins() -> dlopen(plugin .so) ->
     * init_proto() -> init_tcpip_plugin(): the real registration path. */
    if (!init_extraction()) {
        fprintf(stderr, "init_extraction() failed\n");
        return 2;
    }

    /* (1) PROTO_DTLS is in the registry after plugin init. */
    {
        const char *name;
        CHECK(get_protocol_struct_by_id(PROTO_DTLS) != NULL,
              "PROTO_DTLS is registered after init_tcpip_plugin()");
        name = get_protocol_name_by_id(PROTO_DTLS);
        CHECK(name != NULL && strcmp(name, PROTO_DTLS_ALIAS) == 0,
              "registered protocol resolves to the name \"" PROTO_DTLS_ALIAS "\"");
    }

    pcap = pcap_open_offline(argv[1], pcap_errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_offline(%s) failed: %s\n", argv[1], pcap_errbuf);
        close_extraction();
        return 2;
    }
    datalink = pcap_datalink(pcap);

    mmt_handler = mmt_init_handler((uint32_t)datalink, 0, errbuf);
    if (mmt_handler == NULL) {
        fprintf(stderr, "mmt_init_handler failed: %s\n", errbuf);
        pcap_close(pcap);
        close_extraction();
        return 2;
    }

    /* (2) The DTLS attribute metadata is extractable — registration only
     * succeeds on a registered protocol with registered attributes. */
    CHECK(register_extraction_attribute(mmt_handler, PROTO_DTLS,
                                        DTLS_CONTENT_TYPE),
          "dtls.content_length attribute is extractable");
    CHECK(register_extraction_attribute(mmt_handler, PROTO_DTLS,
                                        DTLS_VERSION),
          "dtls.version attribute is extractable");

    register_packet_handler(mmt_handler, 1, packet_handler, NULL);

    /* (3) Replay the pcap through the registered classifier chain. */
    memset(&header, 0, sizeof(header));
    while ((data = pcap_next(pcap, &p_pkthdr)) != NULL) {
        header.ts = p_pkthdr.ts;
        header.caplen = p_pkthdr.caplen;
        header.len = p_pkthdr.len;
        if (p_pkthdr.caplen > 0) {
            u_char *copy = (u_char *) malloc(p_pkthdr.caplen);
            if (copy == NULL) {
                fprintf(stderr, "out of memory\n");
                mmt_close_handler(mmt_handler);
                pcap_close(pcap);
                close_extraction();
                return 2;
            }
            memcpy(copy, data, p_pkthdr.caplen);
            packet_process(mmt_handler, &header, copy);
            free(copy);
        } else {
            packet_process(mmt_handler, &header, data);
        }
    }

    for (i = 0; i < g_npaths; i++) {
        printf("  path: %lu\t%s\n", g_paths[i].count, g_paths[i].path);
    }

    CHECK(count_of("meta.ethernet.ip.udp.dtls") == 2,
          "2 DTLS packets classify end to end as udp.dtls");
    CHECK(count_of("meta.ethernet.ip.udp.unknown") == 1,
          "bogus-version (0x0100) datagram stays udp.unknown");

    mmt_close_handler(mmt_handler);
    pcap_close(pcap);
    close_extraction();

    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}

/*
 * test_fi_plugin_order.c — a plugin that loads before the plugin it depends
 * on (issue #115).
 *
 * Usage: test_fi_plugin_order CHAIN_DIR [ORPHAN_DIR]
 *
 * CHAIN_DIR holds the installed plugins plus mmt_fi_child.so and
 * mmt_fi_parent.so (fi_chain_plugin.c): the child registers its classifier
 * under fi_parent, which a plugin loaded after it registers. ORPHAN_DIR holds
 * the installed plugins plus a child whose parent no plugin registers.
 *
 * With ORPHAN_DIR, init_extraction() over it must fail (run_tests.sh checks
 * the message on stderr names both protocols), and close_extraction()
 * follow. Then init_extraction() over CHAIN_DIR must succeed, and a UDP
 * packet fi_parent claims must reach the child's classifier on that first
 * packet: the deferred registration was attached and fi_parent's opted-in
 * layer was processed. A second init/close cycle over CHAIN_DIR repeats it.
 */
#define _GNU_SOURCE /* RTLD_DEFAULT */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mmt_core.h"

static int chain_cycle(const char *dir, int cycle) {
    static const char payload[] = "FI115 first packet";
    unsigned char buf[128];
    char errbuf[1024];
    struct pkthdr hdr;
    mmt_handler_t *h;
    const int *calls;
    int o = 0, before, ok;
    const int plen = (int) sizeof(payload) - 1;
    const int ip_total = 20 + 8 + plen;
    const unsigned char frame[42] = {
        0,0,0,0,0,1, 0,0,0,0,0,2, 0x08,0x00,                        /* Ethernet */
        0x45,0x00,(unsigned char)(ip_total >> 8),(unsigned char) ip_total,
        0,0,0x40,0x00, 0x40,0x11,0,0, 10,0,0,1, 10,0,0,2,           /* IPv4, UDP */
        0x9c,0x40, 0x9c,0x41, (unsigned char)((8 + plen) >> 8),(unsigned char)(8 + plen), 0,0 };

    setenv("MMT_DPI_PLUGINS_DIR", dir, 1);
    if (!init_extraction()) {
        printf("fi-plugin-order: cycle %d: init_extraction() failed over the chained plugins\n", cycle);
        return 0;
    }
    calls = (const int *) dlsym(RTLD_DEFAULT, "fi_child_calls");
    h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (calls == NULL || h == NULL) {
        printf("fi-plugin-order: cycle %d: %s\n", cycle, calls == NULL ? "fi_child_calls not found" : errbuf);
        if (h != NULL) mmt_close_handler(h);
        close_extraction();
        return 0;
    }
    memcpy(buf, frame, sizeof(frame)); o = (int) sizeof(frame);
    memcpy(buf + o, payload, (size_t) plen); o += plen;
    memset(&hdr, 0, sizeof(hdr));
    hdr.len = hdr.caplen = (unsigned) o;
    before = *calls;
    packet_process(h, &hdr, buf);
    ok = *calls == before + 1;
    printf("fi-plugin-order: cycle %d: child classifier called %d time(s) on the first packet%s\n",
           cycle, *calls - before, ok ? "" : ", expected 1");
    mmt_close_handler(h);
    close_extraction();
    return ok;
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) {
        fprintf(stderr, "usage: %s CHAIN_DIR [ORPHAN_DIR]\n", argv[0]);
        return 2;
    }
    if (argc == 3) {
        setenv("MMT_DPI_PLUGINS_DIR", argv[2], 1);
        if (init_extraction()) {
            printf("fi-plugin-order: init_extraction() succeeded with an orphan registration\n");
            close_extraction();
            return 1;
        }
        close_extraction();
        printf("fi-plugin-order: an orphan registration failed init_extraction() as expected\n");
    }
    if (!chain_cycle(argv[1], 1) || !chain_cycle(argv[1], 2)) return 1;
    printf("fi-plugin-order: the child loaded before its parent was attached\n");
    return 0;
}

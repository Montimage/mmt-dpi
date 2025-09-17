/**
 * A benchmark variant of extract_all.c that logs timing and throughput summary to stderr,
 * while preserving stdout for output comparison.
 *
 * Build (from repo root):
 *   clang -O3 -DNDEBUG -o sdk/bin/extract_all_bench \
 *     src/examples/extract_all_bench.c -I sdk/include -L sdk/lib \
 *     -lmmt_core -ldl -lpcap -Wl,-rpath,sdk/lib
 *
 * Usage:
 *   ./extract_all_bench -t sample.pcap > out.txt 2> perf.txt
 *   ./extract_all_bench -i en0              # live capture (Ctrl-C to stop)
 *
 * macOS runtime environment (important):
 *   export MMT_PLUGINS_PATH=/path/to/mmt-dpi/sdk/lib
 *   export DYLD_LIBRARY_PATH=/path/to/mmt-dpi/sdk/lib:$DYLD_LIBRARY_PATH
 *
 * The SUMMARY line is printed to stderr as:
 *   SUMMARY pkts=... bytes=... secs=... pps=... Mbps=... user=... sys=...
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <pcap.h>
#include <time.h>
#include <inttypes.h>
#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

#define MAX_FILENAME_SIZE 256
#define TRACE_FILE 1
#define LIVE_INTERFACE 2

mmt_handler_t *mmt_handler;   // MMT handler
pcap_t *pcap;                  // Pcap handler
struct pcap_stat pcs;          /* packet capture filter stats */
int pcap_bs = 0;

// Benchmark globals
static struct timespec g_t0 = {0}, g_t1 = {0};
static volatile uint64_t g_pkts = 0;
static volatile uint64_t g_bytes = 0; // on-wire bytes (pcap hdr.len)

static inline double timespec_diff_s(const struct timespec *a, const struct timespec *b){
  return (double)(b->tv_sec - a->tv_sec) + (double)(b->tv_nsec - a->tv_nsec)/1e9;
}

static void print_summary_stderr(void){
  // stop timer if not stopped
  if(g_t1.tv_sec == 0 && g_t1.tv_nsec == 0){
    clock_gettime(CLOCK_MONOTONIC, &g_t1);
  }
  double secs = timespec_diff_s(&g_t0, &g_t1);
  struct rusage ru = {0};
  getrusage(RUSAGE_SELF, &ru);
  double user_s = ru.ru_utime.tv_sec + ru.ru_utime.tv_usec/1e6;
  double sys_s  = ru.ru_stime.tv_sec + ru.ru_stime.tv_usec/1e6;
  double pps  = secs > 0 ? (double)g_pkts / secs : 0.0;
  double mbps = secs > 0 ? (g_bytes * 8.0) / (1e6 * secs) : 0.0;
  fprintf(stderr,
    "SUMMARY pkts=%" PRIu64 " bytes=%" PRIu64 " secs=%.6f pps=%.0f Mbps=%.2f user=%.3f sys=%.3f\n",
    g_pkts, g_bytes, secs, pps, mbps, user_s, sys_s);
}

/**
 * Initialize a pcap handler
 */
pcap_t * init_pcap(char *iname, uint16_t buffer_size, uint16_t snaplen){
    pcap_t * my_pcap;
    char errbuf[1024];
    my_pcap = pcap_create(iname, errbuf);
    if (my_pcap == NULL) {
        fprintf(stderr, "[error] Couldn't open device %s\n", errbuf);
        exit(0);
    }
    pcap_set_snaplen(my_pcap, snaplen);
    pcap_set_promisc(my_pcap, 1);
#ifdef __APPLE__
    // macOS needs a non-zero timeout for proper operation
    pcap_set_timeout(my_pcap, 1000); // 1 second timeout
#else
    pcap_set_timeout(my_pcap, 0);
#endif
    if (buffer_size > 0) {
        pcap_set_buffer_size(my_pcap, buffer_size * 1000 * 1000);
    }
    pcap_activate(my_pcap);

    if (pcap_datalink(my_pcap) != DLT_EN10MB) {
        fprintf(stderr, "[error] %s is not an Ethernet (Make sure you run with administrator permission! )\n", iname);
        exit(0);
    }
    return my_pcap;
}

/** Show help message */
void usage(const char * prg_name) {
    fprintf(stderr, "%s [<option>]\n", prg_name);
    fprintf(stderr, "Option:\n");
    fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
    fprintf(stderr, "\t-i <interface> : Gives the interface name for live traffic analysis.\n");
    fprintf(stderr, "\t-b <MB>        : pcap buffer size in MB (live mode).\n");
    fprintf(stderr, "\t-h             : Prints this help.\n");
    exit(1);
}

/** Parse options */
void parseOptions(int argc, char ** argv, char * filename, int * type) {
    int opt, optcount = 0;
    while ((opt = getopt(argc, argv, "t:i:b:h")) != EOF) {
        switch (opt) {
            case 't':
            optcount++;
            if (optcount > 5) usage(argv[0]);
            strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
            *type = TRACE_FILE;
            break;
            case 'i':
            optcount++;
            if (optcount > 5) usage(argv[0]);
            strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
            *type = LIVE_INTERFACE;
            break;
            case 'b':
            optcount++;
            if (optcount > 5) usage(argv[0]);
            pcap_bs = atoi(optarg);
            break;
            case 'h':
            default: usage(argv[0]);
        }
    }

    if (filename == NULL || strcmp(filename, "") == 0) {
        if (*type == TRACE_FILE) fprintf(stderr, "Missing trace file name\n");
        if (*type == LIVE_INTERFACE) fprintf(stderr, "Missing network interface name\n");
        usage(argv[0]);
    }
}

/** Register extraction attributes */
void attributes_iterator(attribute_metadata_t * attribute, uint32_t proto_id, void * args) {
    register_extraction_attribute(args, proto_id, attribute->id);
}

/** Iterate through all protocol attributes */
void protocols_iterator(uint32_t proto_id, void * args) {
    iterate_through_protocol_attributes(proto_id, attributes_iterator, args);
}

/** Live capture callback */
void live_capture_callback( u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data )
{
    mmt_handler_t *mmt = (mmt_handler_t*)user;
    struct pkthdr header;
    header.ts = p_pkthdr->ts;
    header.caplen = p_pkthdr->caplen;
    header.len = p_pkthdr->len;
    // header.probe_id = 4;
    // header.source_id = 10;
    if (!packet_process(mmt, &header, data)) {
        fprintf(stderr, "Packet data extraction failure.\n");
    }
    // update counters
    g_pkts++;
    g_bytes += p_pkthdr->len;
}

/** Clean resources */
void clean() {
    printf("\n[info] Cleaning....\n");
    //Close the MMT handler
    mmt_close_handler(mmt_handler);
    printf("[info] Closed mmt_handler\n");
    //Close MMT
    close_extraction();
    printf("[info] Closed extraction \n");

    // Show pcap statistic if capture from an interface
    if (pcap && pcap_stats(pcap, &pcs) == 0) {
        (void) printf("[info] \n%12d packets received by filter\n", pcs.ps_recv);
        (void) printf("[info] %12d packets dropped by kernel (%3.2f%%)\n", pcs.ps_drop, pcs.ps_drop * 100.0 / pcs.ps_recv);
        (void) printf("[info] %12d packets dropped by driver (%3.2f%%)\n", pcs.ps_ifdrop, pcs.ps_ifdrop * 100.0 / pcs.ps_recv);
        fflush(stderr);
    }

    printf("[info] Closing pcaps...!\n");
    if (pcap != NULL) pcap_close(pcap);
    printf("[info] Finished cleaning....\n");
}

/** Signal handler */
void signal_handler(int type) {
    fprintf(stderr, "\n[info] reception of signal %d\n", type);
    // stop timer and print partial summary
    clock_gettime(CLOCK_MONOTONIC, &g_t1);
    print_summary_stderr();
    fflush(stderr);
    clean();
}

int main(int argc, char ** argv) {
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
    printf("|\t\t MONTIMAGE\n");
    printf("|\t MMT-SDK version: %s\n",mmt_version());
    printf("|\t %s: built %s %s\n", argv[0], __DATE__, __TIME__);
    printf("|\t http://montimage.com\n");
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");

    sigset_t signal_set;

    char mmt_errbuf[1024];
    char filename[MAX_FILENAME_SIZE + 1]; // interface name or path to pcap file
    int type; // Online or offline mode
    filename[0] = '\0';
    type = TRACE_FILE; // default

    // Parse option
    parseOptions(argc, argv, filename, &type);

    //Initialize MMT
    init_extraction();

    //Initialize MMT handler
    mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
    if (!mmt_handler) {
        fprintf(stderr, "[error] MMT handler init failed for the following reason: %s\n", mmt_errbuf );
        return EXIT_FAILURE;
    }

    // Interate through protocols to register extraction of all attributes
    iterate_through_protocols(protocols_iterator, mmt_handler);

    // Register packet handler function that prints extracted attributes to stdout
    register_packet_handler(mmt_handler, 1, debug_extracted_attributes_printout_handler, NULL);

    // Handle signals
    sigfillset(&signal_set);
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);

    // Start timing
    clock_gettime(CLOCK_MONOTONIC, &g_t0);

    if (type == TRACE_FILE) {
        // OFFLINE mode
        struct pkthdr header; // MMT packet header
        struct pcap_pkthdr p_pkthdr;
        pcap = pcap_open_offline(filename, mmt_errbuf);
        if (!pcap) {
            fprintf(stderr, "pcap_open failed for the following reason\n");
            return EXIT_FAILURE;
        }
        const u_char *data = NULL;
        while ((data = pcap_next(pcap, &p_pkthdr))) {
            header.ts = p_pkthdr.ts;
            header.caplen = p_pkthdr.caplen;
            header.len = p_pkthdr.len;
            if (!packet_process(mmt_handler, &header, data)) {
                fprintf(stderr, "Packet data extraction failure.\n");
            }
            // update counters
            g_pkts++;
            g_bytes += p_pkthdr.len;
        }
        clock_gettime(CLOCK_MONOTONIC, &g_t1);
        print_summary_stderr();
    } else {
        // ONLINE MODE
        if(pcap_bs == 0){
            printf("[info] Use default buffer size: 50 (MB)\n");
        }else{
            printf("[info] Use buffer size: %d (MB)\n",pcap_bs);
        }
        pcap = init_pcap(filename, pcap_bs, 65535);
        if (!pcap) {
            fprintf(stderr, "[error] creating pcap failed for the following reason: %s\n", mmt_errbuf);
            return EXIT_FAILURE;
        }
        // pcap_loop blocks; summary printed in signal handler or after loop returns
        int rc = pcap_loop( pcap, -1, &live_capture_callback, (u_char*)mmt_handler );
        (void)rc;
        clock_gettime(CLOCK_MONOTONIC, &g_t1);
        print_summary_stderr();
    }

    clean();
    return EXIT_SUCCESS;
}

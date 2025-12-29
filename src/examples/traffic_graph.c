/**
 * traffic_graph.c - Live Traffic ASCII Line Chart using MMT-DPI
 *
 * Captures live traffic from a network interface and displays an ASCII
 * time-series line chart with filled areas showing inbound (download)
 * and outbound (upload) traffic volumes.
 *
 * Features:
 * - Live packet capture using libpcap
 * - Direction detection using MMT-DPI session tracking
 * - Configurable update interval (default 5 seconds)
 * - Auto-scaling Y-axis
 * - 40 data points history
 * - ANSI colors for terminal display
 * - Average speed statistics
 *
 * Compile (from MMT-DPI root directory):
 *
 * Linux:
 * $ gcc -o traffic_graph src/examples/traffic_graph.c \
 *     -I sdk/include -I sdk/include/tcpip -L sdk/lib \
 *     -lmmt_core -lmmt_tcpip -lpcap -ldl -lm
 *
 * macOS:
 * $ clang -o traffic_graph src/examples/traffic_graph.c \
 *     -I sdk/include -I sdk/include/tcpip -L sdk/lib \
 *     -lmmt_core -lmmt_tcpip -lpcap -ldl -lm \
 *     -Wl,-rpath,$(pwd)/sdk/lib
 *
 * Run:
 * IMPORTANT for macOS - set environment first:
 * $ export MMT_PLUGINS_PATH=$(pwd)/sdk/lib
 * $ export DYLD_LIBRARY_PATH=$(pwd)/sdk/lib:$DYLD_LIBRARY_PATH
 *
 * $ sudo ./traffic_graph -i en0           # macOS (use en0, en1, etc.)
 * $ sudo ./traffic_graph -i eth0          # Linux
 * $ sudo ./traffic_graph -i eth0 -n 2     # 2-second intervals
 *
 * Press Ctrl+C to stop.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <sys/time.h>
#include <getopt.h>
#include <pcap.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>  /* For _NSGetExecutablePath */
#endif

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

/* ============================================================================
 * Constants and Configuration
 * ============================================================================ */

#define MAX_HISTORY      40      /* Number of data points to display */
#define GRAPH_HEIGHT     15      /* Height of graph in terminal rows */
#define GRAPH_WIDTH      60      /* Width of graph area */
#define DEFAULT_INTERVAL 5       /* Default update interval in seconds */

/* ANSI Color Codes */
#define COLOR_RESET      "\033[0m"
#define COLOR_BOLD       "\033[1m"
#define COLOR_DIM        "\033[2m"

/* Download (Inbound) - Cyan */
#define COLOR_DL_LINE    "\033[96m"      /* Bright cyan for line */
#define COLOR_DL_FILL    "\033[46m"      /* Cyan background for fill */
#define COLOR_DL_DARK    "\033[36m"      /* Dark cyan */

/* Upload (Outbound) - Green */
#define COLOR_UL_LINE    "\033[92m"      /* Bright green for line */
#define COLOR_UL_FILL    "\033[42m"      /* Green background for fill */
#define COLOR_UL_DARK    "\033[32m"      /* Dark green */

/* Background */
#define COLOR_BG         "\033[48;5;236m" /* Dark gray background */
#define COLOR_AXIS       "\033[90m"       /* Gray for axis */
#define COLOR_LABEL      "\033[97m"       /* White for labels */

/* Characters for drawing */
#define CHAR_DL_POINT    "\xe2\x97\x8f"  /* ● solid circle */
#define CHAR_UL_POINT    "\xe2\x97\x8b"  /* ○ hollow circle */
#define CHAR_FILL        " "             /* Space with background color */
#define CHAR_EMPTY       " "

/* ============================================================================
 * Data Structures
 * ============================================================================ */

typedef struct {
    uint64_t bytes_in;       /* Bytes downloaded (inbound) */
    uint64_t bytes_out;      /* Bytes uploaded (outbound) */
    uint64_t packets_in;     /* Packets inbound */
    uint64_t packets_out;    /* Packets outbound */
    struct timeval timestamp;
} traffic_interval_t;

typedef struct {
    /* Ring buffer for history */
    traffic_interval_t history[MAX_HISTORY];
    int head;                /* Next write position */
    int count;               /* Number of valid entries */

    /* Current interval accumulator */
    uint64_t current_bytes_in;
    uint64_t current_bytes_out;
    uint64_t current_packets_in;
    uint64_t current_packets_out;
    struct timeval interval_start;

    /* Running totals */
    uint64_t total_bytes_in;
    uint64_t total_bytes_out;
    uint64_t total_packets;
    struct timeval start_time;

    /* Configuration */
    int interval_seconds;
    char interface[64];
} traffic_state_t;

/* ============================================================================
 * Global State
 * ============================================================================ */

static traffic_state_t g_state;
static mmt_handler_t *g_mmt_handler = NULL;
static pcap_t *g_pcap = NULL;
static volatile int g_running = 1;

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Format bytes into human-readable string (e.g., "1.23 MB")
 */
static void format_bytes(uint64_t bytes, char *buf, size_t buflen) {
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double value = (double)bytes;

    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        unit++;
    }

    if (unit == 0) {
        snprintf(buf, buflen, "%lu %s", (unsigned long)bytes, units[unit]);
    } else {
        snprintf(buf, buflen, "%.1f %s", value, units[unit]);
    }
}

/**
 * Format bytes per second into human-readable rate
 */
static void format_rate(double bytes_per_sec, char *buf, size_t buflen) {
    const char *units[] = {"B/s", "KB/s", "MB/s", "GB/s"};
    int unit = 0;
    double value = bytes_per_sec;

    while (value >= 1024.0 && unit < 3) {
        value /= 1024.0;
        unit++;
    }

    snprintf(buf, buflen, "%.1f %s", value, units[unit]);
}

/**
 * Format duration into human-readable string
 */
static void format_duration(int seconds, char *buf, size_t buflen) {
    int hours = seconds / 3600;
    int mins = (seconds % 3600) / 60;
    int secs = seconds % 60;

    if (hours > 0) {
        snprintf(buf, buflen, "%dh %dm %ds", hours, mins, secs);
    } else if (mins > 0) {
        snprintf(buf, buflen, "%dm %ds", mins, secs);
    } else {
        snprintf(buf, buflen, "%ds", secs);
    }
}

/**
 * Get time difference in seconds
 */
static double timeval_diff(struct timeval *end, struct timeval *start) {
    return (end->tv_sec - start->tv_sec) +
           (end->tv_usec - start->tv_usec) / 1000000.0;
}

/* ============================================================================
 * Graph Rendering
 * ============================================================================ */

/**
 * Clear screen and move cursor to top
 */
static void clear_screen(void) {
    printf("\033[2J\033[H");
    fflush(stdout);
}

/**
 * Find maximum value in history for auto-scaling
 */
static uint64_t find_max_value(void) {
    uint64_t max_val = 1024;  /* Minimum 1 KB for scale */

    for (int i = 0; i < g_state.count; i++) {
        int idx = (g_state.head - g_state.count + i + MAX_HISTORY) % MAX_HISTORY;
        if (g_state.history[idx].bytes_in > max_val) {
            max_val = g_state.history[idx].bytes_in;
        }
        if (g_state.history[idx].bytes_out > max_val) {
            max_val = g_state.history[idx].bytes_out;
        }
    }

    /* Round up to nice number */
    uint64_t magnitude = 1;
    while (magnitude < max_val) {
        magnitude *= 10;
    }
    max_val = ((max_val / (magnitude / 10)) + 1) * (magnitude / 10);

    return max_val;
}

/**
 * Calculate Y position for a value (0 = bottom, GRAPH_HEIGHT-1 = top)
 */
static int value_to_y(uint64_t value, uint64_t max_val) {
    if (max_val == 0) return 0;
    int y = (int)((double)value / max_val * (GRAPH_HEIGHT - 1));
    if (y >= GRAPH_HEIGHT) y = GRAPH_HEIGHT - 1;
    return y;
}

/**
 * Render the ASCII line chart
 */
static void render_graph(void) {
    struct timeval now;
    gettimeofday(&now, NULL);

    clear_screen();

    /* Header */
    printf("%s%s╔════════════════════════════════════════════════════════════════════╗%s\n",
           COLOR_BOLD, COLOR_LABEL, COLOR_RESET);
    printf("%s%s║  MMT-DPI Traffic Monitor - %s (%ds intervals)%*s║%s\n",
           COLOR_BOLD, COLOR_LABEL, g_state.interface, g_state.interval_seconds,
           (int)(30 - strlen(g_state.interface)), "", COLOR_RESET);
    printf("%s%s╚════════════════════════════════════════════════════════════════════╝%s\n\n",
           COLOR_BOLD, COLOR_LABEL, COLOR_RESET);

    /* Find scale */
    uint64_t max_val = find_max_value();
    char max_label[32], mid_label[32];
    format_bytes(max_val, max_label, sizeof(max_label));
    format_bytes(max_val / 2, mid_label, sizeof(mid_label));

    /* Prepare data arrays for rendering */
    int dl_y[MAX_HISTORY];
    int ul_y[MAX_HISTORY];

    for (int i = 0; i < MAX_HISTORY; i++) {
        dl_y[i] = -1;
        ul_y[i] = -1;
    }

    /* Map history to Y positions */
    for (int i = 0; i < g_state.count; i++) {
        int hist_idx = (g_state.head - g_state.count + i + MAX_HISTORY) % MAX_HISTORY;
        int display_idx = MAX_HISTORY - g_state.count + i;
        if (display_idx >= 0 && display_idx < MAX_HISTORY) {
            dl_y[display_idx] = value_to_y(g_state.history[hist_idx].bytes_in, max_val);
            ul_y[display_idx] = value_to_y(g_state.history[hist_idx].bytes_out, max_val);
        }
    }

    /* Render graph rows (top to bottom) */
    for (int row = GRAPH_HEIGHT - 1; row >= 0; row--) {
        /* Y-axis label */
        if (row == GRAPH_HEIGHT - 1) {
            printf("%s%8s │%s", COLOR_AXIS, max_label, COLOR_RESET);
        } else if (row == GRAPH_HEIGHT / 2) {
            printf("%s%8s │%s", COLOR_AXIS, mid_label, COLOR_RESET);
        } else if (row == 0) {
            printf("%s%8s │%s", COLOR_AXIS, "0", COLOR_RESET);
        } else {
            printf("%s         │%s", COLOR_AXIS, COLOR_RESET);
        }

        /* Graph content */
        printf("%s", COLOR_BG);  /* Dark background */

        for (int col = 0; col < MAX_HISTORY; col++) {
            int dl = dl_y[col];
            int ul = ul_y[col];

            /* Determine what to draw at this position */
            int is_dl_line = (dl == row);
            int is_ul_line = (ul == row);
            int is_dl_fill = (dl >= 0 && row <= dl);
            int is_ul_fill = (ul >= 0 && row <= ul);

            if (is_dl_line && is_ul_line) {
                /* Both lines at same position - show combined */
                printf("%s%s%s", COLOR_DL_LINE, CHAR_DL_POINT, COLOR_RESET COLOR_BG);
            } else if (is_dl_line) {
                /* Download line point */
                if (is_ul_fill) {
                    printf("%s%s%s%s", COLOR_UL_FILL, COLOR_DL_LINE, CHAR_DL_POINT, COLOR_RESET COLOR_BG);
                } else {
                    printf("%s%s%s", COLOR_DL_LINE, CHAR_DL_POINT, COLOR_RESET COLOR_BG);
                }
            } else if (is_ul_line) {
                /* Upload line point */
                if (is_dl_fill) {
                    printf("%s%s%s%s", COLOR_DL_FILL, COLOR_UL_LINE, CHAR_UL_POINT, COLOR_RESET COLOR_BG);
                } else {
                    printf("%s%s%s", COLOR_UL_LINE, CHAR_UL_POINT, COLOR_RESET COLOR_BG);
                }
            } else if (is_dl_fill && is_ul_fill) {
                /* Both fills overlap - blend colors */
                printf("%s %s", COLOR_DL_FILL, COLOR_RESET COLOR_BG);
            } else if (is_dl_fill) {
                /* Download fill only */
                printf("%s %s", COLOR_DL_FILL, COLOR_RESET COLOR_BG);
            } else if (is_ul_fill) {
                /* Upload fill only */
                printf("%s %s", COLOR_UL_FILL, COLOR_RESET COLOR_BG);
            } else {
                /* Empty space */
                printf(" ");
            }
        }

        printf("%s\n", COLOR_RESET);
    }

    /* X-axis */
    printf("%s         └", COLOR_AXIS);
    for (int i = 0; i < MAX_HISTORY; i++) {
        printf("─");
    }
    printf("→%s\n", COLOR_RESET);

    /* Time labels */
    printf("%s          ", COLOR_DIM);
    int label_interval = MAX_HISTORY / 4;
    for (int i = 0; i < MAX_HISTORY; i++) {
        if (i == MAX_HISTORY - 1) {
            printf("Now");
        } else if (i % label_interval == 0) {
            int secs_ago = (MAX_HISTORY - 1 - i) * g_state.interval_seconds;
            printf("-%ds", secs_ago);
            i += 3;  /* Skip space for label */
        } else {
            printf(" ");
        }
    }
    printf("%s\n\n", COLOR_RESET);

    /* Legend */
    printf("  %s%s●%s Download (Inbound)    %s%s○%s Upload (Outbound)\n\n",
           COLOR_DL_LINE, COLOR_BOLD, COLOR_RESET,
           COLOR_UL_LINE, COLOR_BOLD, COLOR_RESET);

    /* Statistics */
    double duration = timeval_diff(&now, &g_state.start_time);
    if (duration < 1.0) duration = 1.0;

    double avg_in = g_state.total_bytes_in / duration;
    double avg_out = g_state.total_bytes_out / duration;

    char total_in_str[32], total_out_str[32];
    char avg_in_str[32], avg_out_str[32];
    char duration_str[32];

    format_bytes(g_state.total_bytes_in, total_in_str, sizeof(total_in_str));
    format_bytes(g_state.total_bytes_out, total_out_str, sizeof(total_out_str));
    format_rate(avg_in, avg_in_str, sizeof(avg_in_str));
    format_rate(avg_out, avg_out_str, sizeof(avg_out_str));
    format_duration((int)duration, duration_str, sizeof(duration_str));

    printf("%s╭─────────────────────────────────────────────────────────────────────╮%s\n",
           COLOR_DIM, COLOR_RESET);
    printf("%s│%s  %s▼ Download:%s  Avg: %s%-12s%s  Total: %s%-12s%s              %s│%s\n",
           COLOR_DIM, COLOR_RESET,
           COLOR_DL_LINE, COLOR_RESET,
           COLOR_BOLD, avg_in_str, COLOR_RESET,
           COLOR_BOLD, total_in_str, COLOR_RESET,
           COLOR_DIM, COLOR_RESET);
    printf("%s│%s  %s▲ Upload:  %s  Avg: %s%-12s%s  Total: %s%-12s%s              %s│%s\n",
           COLOR_DIM, COLOR_RESET,
           COLOR_UL_LINE, COLOR_RESET,
           COLOR_BOLD, avg_out_str, COLOR_RESET,
           COLOR_BOLD, total_out_str, COLOR_RESET,
           COLOR_DIM, COLOR_RESET);
    printf("%s│%s  Duration: %s%-10s%s  Packets: %s%-12lu%s                     %s│%s\n",
           COLOR_DIM, COLOR_RESET,
           COLOR_BOLD, duration_str, COLOR_RESET,
           COLOR_BOLD, (unsigned long)g_state.total_packets, COLOR_RESET,
           COLOR_DIM, COLOR_RESET);
    printf("%s╰─────────────────────────────────────────────────────────────────────╯%s\n",
           COLOR_DIM, COLOR_RESET);

    printf("\n%sPress Ctrl+C to stop%s\n", COLOR_DIM, COLOR_RESET);

    fflush(stdout);
}

/* ============================================================================
 * Traffic Tracking
 * ============================================================================ */

/**
 * Push current interval to history and reset
 */
static void push_interval(void) {
    struct timeval now;
    gettimeofday(&now, NULL);

    /* Store in ring buffer */
    g_state.history[g_state.head].bytes_in = g_state.current_bytes_in;
    g_state.history[g_state.head].bytes_out = g_state.current_bytes_out;
    g_state.history[g_state.head].packets_in = g_state.current_packets_in;
    g_state.history[g_state.head].packets_out = g_state.current_packets_out;
    g_state.history[g_state.head].timestamp = now;

    /* Advance head */
    g_state.head = (g_state.head + 1) % MAX_HISTORY;
    if (g_state.count < MAX_HISTORY) {
        g_state.count++;
    }

    /* Reset current interval */
    g_state.current_bytes_in = 0;
    g_state.current_bytes_out = 0;
    g_state.current_packets_in = 0;
    g_state.current_packets_out = 0;
    g_state.interval_start = now;

    /* Render updated graph */
    render_graph();
}

/**
 * MMT packet handler callback
 */
static int packet_handler_callback(const ipacket_t *ipacket, void *user_args) {
    (void)user_args;

    /* Get packet length */
    uint32_t *p_len = (uint32_t *)get_attribute_extracted_data(
        ipacket, PROTO_META, META_P_LEN);
    if (!p_len) {
        return 0;
    }

    /* Get packet direction */
    uint32_t *p_dir = (uint32_t *)get_attribute_extracted_data(
        ipacket, PROTO_META, META_PACKET_DIRECTION);

    uint32_t pkt_len = *p_len;

    /*
     * For network traffic monitoring, we want:
     * - Download = traffic coming TO us (responses from servers)
     * - Upload = traffic going FROM us (requests to servers)
     *
     * MMT-DPI direction values (from mmt_core.h):
     * - FROM_INITIATOR (1) = packet in same direction as session initiator
     * - TO_INITIATOR (2) = packet in opposite direction (response)
     * - H2L_DIRECTION (0) / L2H_DIRECTION (1) = based on IP comparison
     *
     * For a typical client (web browser, etc.), YOU initiate connections,
     * so FROM_INITIATOR (1) = your requests = UPLOAD
     * and TO_INITIATOR (0 or 2) = responses = DOWNLOAD
     */
    int is_inbound = 1;  /* Default to inbound (download) if no direction info */

    if (p_dir) {
        uint32_t dir = *p_dir;
        /* FROM_INITIATOR (1) = our outgoing requests = upload
         * Everything else (0, 2) = incoming responses = download */
        is_inbound = (dir != 1);
    }

    /* Accumulate bytes */
    if (is_inbound) {
        g_state.current_bytes_in += pkt_len;
        g_state.current_packets_in++;
        g_state.total_bytes_in += pkt_len;
    } else {
        g_state.current_bytes_out += pkt_len;
        g_state.current_packets_out++;
        g_state.total_bytes_out += pkt_len;
    }
    g_state.total_packets++;

    /* Check if interval has elapsed */
    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = timeval_diff(&now, &g_state.interval_start);

    if (elapsed >= g_state.interval_seconds) {
        push_interval();
    }

    return 0;
}

/* ============================================================================
 * PCAP Integration
 * ============================================================================ */

/**
 * Initialize pcap for live capture
 */
static pcap_t *init_pcap_live(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;

    pcap = pcap_create(interface, errbuf);
    if (!pcap) {
        fprintf(stderr, "[error] Could not open interface %s: %s\n",
                interface, errbuf);
        return NULL;
    }

    pcap_set_snaplen(pcap, 65535);
    pcap_set_promisc(pcap, 1);

    pcap_set_timeout(pcap, 100);  /* 100ms timeout for responsive updates */

    pcap_set_buffer_size(pcap, 16 * 1024 * 1024);  /* 16 MB buffer */

    int status = pcap_activate(pcap);
    if (status != 0) {
        fprintf(stderr, "[error] Could not activate pcap: %s\n",
                pcap_geterr(pcap));
        pcap_close(pcap);
        return NULL;
    }

    if (pcap_datalink(pcap) != DLT_EN10MB) {
        fprintf(stderr, "[error] %s is not an Ethernet interface\n", interface);
        pcap_close(pcap);
        return NULL;
    }

    return pcap;
}

/**
 * PCAP callback for live capture
 */
static void pcap_callback(u_char *user, const struct pcap_pkthdr *pkthdr,
                          const u_char *packet) {
    mmt_handler_t *mmt = (mmt_handler_t *)user;
    struct pkthdr header;

    header.ts = pkthdr->ts;
    header.caplen = pkthdr->caplen;
    header.len = pkthdr->len;

    packet_process(mmt, &header, packet);
}

/* ============================================================================
 * Signal Handling
 * ============================================================================ */

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;

    if (g_pcap) {
        pcap_breakloop(g_pcap);
    }
}

/* ============================================================================
 * Main Program
 * ============================================================================ */

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s -i <interface> [-n <interval>]\n", prog);
    fprintf(stderr, "       %s -t <pcap_file> [-n <interval>]\n\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i <interface>  Network interface to capture (e.g., en0, eth0)\n");
    fprintf(stderr, "  -t <pcap_file>  Read from pcap file (for testing)\n");
    fprintf(stderr, "  -n <interval>   Update interval in seconds (default: %d)\n",
            DEFAULT_INTERVAL);
    fprintf(stderr, "  -h              Show this help\n\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  sudo %s -i en0              # macOS live capture\n", prog);
    fprintf(stderr, "  sudo %s -i eth0             # Linux live capture\n", prog);
    fprintf(stderr, "  sudo %s -i eth0 -n 2        # 2-second intervals\n", prog);
    fprintf(stderr, "  %s -t capture.pcap          # Read from file\n", prog);
    fprintf(stderr, "\nNote: Live capture requires root/sudo.\n");
    fprintf(stderr, "\nmacOS: Set environment before running:\n");
    fprintf(stderr, "  export MMT_PLUGINS_PATH=$(pwd)/sdk/lib\n");
    fprintf(stderr, "  export DYLD_LIBRARY_PATH=$(pwd)/sdk/lib:$DYLD_LIBRARY_PATH\n");
}

static void cleanup(void) {
    printf("\n\n[info] Cleaning up...\n");

    if (g_mmt_handler) {
        mmt_close_handler(g_mmt_handler);
        g_mmt_handler = NULL;
        printf("[info] Closed MMT handler\n");
    }

    close_extraction();
    printf("[info] Closed extraction\n");

    if (g_pcap) {
        struct pcap_stat stats;
        if (pcap_stats(g_pcap, &stats) == 0) {
            printf("[info] Packets received: %u\n", stats.ps_recv);
            printf("[info] Packets dropped:  %u\n", stats.ps_drop);
        }
        pcap_close(g_pcap);
        g_pcap = NULL;
        printf("[info] Closed pcap\n");
    }

    printf("[info] Done.\n");
}

int main(int argc, char **argv) {
    char interface[64] = "";
    char pcap_file[256] = "";
    int interval = DEFAULT_INTERVAL;
    int opt;
    int is_live = 1;

    /* Print banner */
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
    printf("|\t\t MONTIMAGE\n");
    printf("|\t MMT-SDK version: %s\n", mmt_version());
    printf("|\t %s: built %s %s\n", argv[0], __DATE__, __TIME__);
    printf("|\t http://montimage.com\n");
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");

    /* Parse command line */
    while ((opt = getopt(argc, argv, "i:t:n:h")) != -1) {
        switch (opt) {
            case 'i':
                strncpy(interface, optarg, sizeof(interface) - 1);
                interface[sizeof(interface) - 1] = '\0';
                is_live = 1;
                break;
            case 't':
                strncpy(pcap_file, optarg, sizeof(pcap_file) - 1);
                pcap_file[sizeof(pcap_file) - 1] = '\0';
                strncpy(interface, "file", sizeof(interface) - 1);
                is_live = 0;
                break;
            case 'n':
                interval = atoi(optarg);
                if (interval < 1) interval = 1;
                if (interval > 60) interval = 60;
                break;
            case 'h':
            default:
                usage(argv[0]);
                return (opt == 'h') ? 0 : 1;
        }
    }

    if (strlen(interface) == 0) {
        fprintf(stderr, "[error] No interface or pcap file specified\n\n");
        usage(argv[0]);
        return 1;
    }

    /* Initialize state */
    memset(&g_state, 0, sizeof(g_state));
    g_state.interval_seconds = interval;
    strncpy(g_state.interface, interface, sizeof(g_state.interface) - 1);
    gettimeofday(&g_state.start_time, NULL);
    g_state.interval_start = g_state.start_time;

    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Set default MMT_PLUGINS_PATH if not set (for sudo compatibility) */
    if (getenv("MMT_PLUGINS_PATH") == NULL) {
        /* Try to find plugins relative to executable or use common paths */
        char exe_path[1024] = {0};
        char plugin_path[1024] = {0};

#ifdef __APPLE__
        uint32_t size = sizeof(exe_path);
        if (_NSGetExecutablePath(exe_path, &size) == 0) {
            /* Get directory of executable */
            char *last_slash = strrchr(exe_path, '/');
            if (last_slash) {
                *last_slash = '\0';
                snprintf(plugin_path, sizeof(plugin_path), "%s/sdk/lib", exe_path);
                if (access(plugin_path, F_OK) == 0) {
                    setenv("MMT_PLUGINS_PATH", plugin_path, 0);
                    printf("[info] Auto-set MMT_PLUGINS_PATH=%s\n", plugin_path);
                } else {
                    /* Try current directory */
                    if (access("./sdk/lib", F_OK) == 0) {
                        setenv("MMT_PLUGINS_PATH", "./sdk/lib", 0);
                        printf("[info] Auto-set MMT_PLUGINS_PATH=./sdk/lib\n");
                    }
                }
            }
        }
#else
        /* Linux: try common paths */
        if (access("./sdk/lib", F_OK) == 0) {
            setenv("MMT_PLUGINS_PATH", "./sdk/lib", 0);
            printf("[info] Auto-set MMT_PLUGINS_PATH=./sdk/lib\n");
        } else if (access("/opt/mmt/dpi/lib", F_OK) == 0) {
            setenv("MMT_PLUGINS_PATH", "/opt/mmt/dpi/lib", 0);
            printf("[info] Auto-set MMT_PLUGINS_PATH=/opt/mmt/dpi/lib\n");
        }
#endif
    }

    /* Initialize MMT */
    char mmt_errbuf[1024];

    if (!init_extraction()) {
        fprintf(stderr, "[error] MMT extraction init failed\n");
        fprintf(stderr, "[error] Hint: Set MMT_PLUGINS_PATH environment variable\n");
        fprintf(stderr, "[error] Example: sudo MMT_PLUGINS_PATH=$(pwd)/sdk/lib ./traffic_graph -i en0\n");
        return 1;
    }

    g_mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
    if (!g_mmt_handler) {
        fprintf(stderr, "[error] MMT handler init failed: %s\n", mmt_errbuf);
        close_extraction();
        return 1;
    }

    /* Register attributes for extraction */
    register_extraction_attribute(g_mmt_handler, PROTO_META, META_P_LEN);
    register_extraction_attribute(g_mmt_handler, PROTO_META, META_PACKET_DIRECTION);

    /* Register packet handler */
    register_packet_handler(g_mmt_handler, 1, packet_handler_callback, NULL);

    /* Initialize pcap */
    if (is_live) {
        g_pcap = init_pcap_live(interface);
        if (!g_pcap) {
            mmt_close_handler(g_mmt_handler);
            close_extraction();
            return 1;
        }
    } else {
        char errbuf[PCAP_ERRBUF_SIZE];
        g_pcap = pcap_open_offline(pcap_file, errbuf);
        if (!g_pcap) {
            fprintf(stderr, "[error] Could not open pcap file %s: %s\n",
                    pcap_file, errbuf);
            mmt_close_handler(g_mmt_handler);
            close_extraction();
            return 1;
        }
        /* Use filename in display */
        const char *basename = strrchr(pcap_file, '/');
        if (basename) {
            strncpy(g_state.interface, basename + 1, sizeof(g_state.interface) - 1);
        } else {
            strncpy(g_state.interface, pcap_file, sizeof(g_state.interface) - 1);
        }
    }

    /* Initial render */
    render_graph();

    /* Start capture loop */
    if (is_live) {
        /* Live capture mode */
        while (g_running) {
            int ret = pcap_dispatch(g_pcap, 100, pcap_callback, (u_char *)g_mmt_handler);
            if (ret < 0) {
                if (ret == PCAP_ERROR_BREAK) {
                    break;  /* pcap_breakloop was called */
                }
                fprintf(stderr, "[error] pcap_dispatch failed: %s\n",
                        pcap_geterr(g_pcap));
                break;
            }

            /* Check for interval timeout even with no packets */
            struct timeval now;
            gettimeofday(&now, NULL);
            double elapsed = timeval_diff(&now, &g_state.interval_start);
            if (elapsed >= g_state.interval_seconds) {
                push_interval();
            }
        }
    } else {
        /* Offline mode - process packets from pcap file */
        struct pcap_pkthdr *pkthdr;
        const u_char *packet;
        struct timeval first_pkt_time = {0, 0};
        int first_packet = 1;

        while (g_running && pcap_next_ex(g_pcap, &pkthdr, &packet) >= 0) {
            if (first_packet) {
                first_pkt_time = pkthdr->ts;
                g_state.interval_start = pkthdr->ts;
                first_packet = 0;
            }

            struct pkthdr header;
            header.ts = pkthdr->ts;
            header.caplen = pkthdr->caplen;
            header.len = pkthdr->len;

            packet_process(g_mmt_handler, &header, packet);

            /* Check interval based on packet timestamp */
            double elapsed = timeval_diff(&pkthdr->ts, &g_state.interval_start);
            if (elapsed >= g_state.interval_seconds) {
                push_interval();
                g_state.interval_start = pkthdr->ts;
                usleep(100000);  /* Brief pause to see graph update */
            }
        }
        /* Push final interval */
        if (g_state.current_bytes_in > 0 || g_state.current_bytes_out > 0) {
            push_interval();
        }
    }

    cleanup();
    return 0;
}

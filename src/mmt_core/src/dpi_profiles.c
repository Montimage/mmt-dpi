/*
 * dpi_profiles.c — named DPI profiles with per-level detection toggles
 * (issue #87).
 *
 * A profile bundles the four independent detection levers of the engine so a
 * deployment can trade detection depth for throughput with one call:
 *
 *   - classification_max_depth: deepest protocol-path index the classifier
 *     may write (enforced in packet_pipeline.c — proto_packet_classify_next
 *     skips the checker walk, set_classified_proto refuses deeper appends);
 *   - app_protocol_classify  -> mmt_handler_t.hostname_classify (TLS SNI /
 *     HTTP Host / hostname fingerprint detection);
 *   - port_classify          -> mmt_handler_t.port_classify (well-known port
 *     fallback of last resort);
 *   - ip_address_classify    -> mmt_handler_t.ip_address_classify (IP-range
 *     fallback).
 *
 * Selection paths, all optional:
 *   1. mmt_apply_dpi_profile() — apply a caller-built profile struct;
 *   2. mmt_apply_dpi_profile_by_name() — apply a predefined or file-defined
 *      name;
 *   3. MMT_DPI_PROFILE / MMT_DPI_PROFILES_FILE environment variables —
 *      applied once by mmt_init_handler() (mmt_dpi_profile_apply_env).
 *
 * Threading contract (same as the M9 external tables): the custom-profile
 * registry below is populated only at init time — via the env hook or an
 * explicit mmt_load_dpi_profiles_file() call before packets flow — and is
 * read-only afterwards, so no locking is needed on the lookup path.
 *
 * The built-in handler defaults are untouched: with no profile applied the
 * engine behaves exactly as before (byte-identical classification), which
 * keeps the phase0 golden-pcap fingerprint stable.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include "packet_processing.h"
#include "mmt_core.h"

#define MMT_DPI_PROFILE_NAME_LEN 32
#define MMT_DPI_CUSTOM_PROFILES_MAX 32

/* Predefined profiles. MMT_DPI_PROFILE_DEFAULT mirrors the initialiser in
 * packet_registry.c (mmt_init_handler): keep the two in sync — the test
 * suite pins the equivalence. */
const mmt_dpi_profile_t MMT_DPI_PROFILE_DEFAULT = {
    /* .classification_max_depth = */ PROTO_PATH_SIZE - 1,
    /* .app_protocol_classify    = */ 1,
    /* .port_classify            = */ 0,
    /* .ip_address_classify      = */ 1,
};

const mmt_dpi_profile_t MMT_DPI_PROFILE_FULL = {
    /* .classification_max_depth = */ PROTO_PATH_SIZE - 1,
    /* .app_protocol_classify    = */ 1,
    /* .port_classify            = */ 1,
    /* .ip_address_classify      = */ 1,
};

const mmt_dpi_profile_t MMT_DPI_PROFILE_BALANCED = {
    /* .classification_max_depth = */ 5,
    /* .app_protocol_classify    = */ 1,
    /* .port_classify            = */ 0,
    /* .ip_address_classify      = */ 1,
};

const mmt_dpi_profile_t MMT_DPI_PROFILE_MINIMAL = {
    /* .classification_max_depth = */ 3,
    /* .app_protocol_classify    = */ 0,
    /* .port_classify            = */ 0,
    /* .ip_address_classify      = */ 0,
};

static const struct {
    const char *name;
    const mmt_dpi_profile_t *profile;
} predefined_profiles[] = {
    { "default",  &MMT_DPI_PROFILE_DEFAULT  },
    { "full",     &MMT_DPI_PROFILE_FULL     },
    { "balanced", &MMT_DPI_PROFILE_BALANCED },
    { "minimal",  &MMT_DPI_PROFILE_MINIMAL  },
};

typedef struct {
    char name[MMT_DPI_PROFILE_NAME_LEN];
    mmt_dpi_profile_t profile;
} custom_profile_entry_t;

static custom_profile_entry_t custom_profiles[MMT_DPI_CUSTOM_PROFILES_MAX];
static size_t custom_profiles_n = 0;

static const mmt_dpi_profile_t *find_profile_by_name(const char *name) {
    if (name == NULL || name[0] == '\0') {
        return NULL;
    }
    for (size_t i = 0; i < sizeof(predefined_profiles) / sizeof(predefined_profiles[0]); i++) {
        if (strcasecmp(name, predefined_profiles[i].name) == 0) {
            return predefined_profiles[i].profile;
        }
    }
    for (size_t i = 0; i < custom_profiles_n; i++) {
        if (strcasecmp(name, custom_profiles[i].name) == 0) {
            return &custom_profiles[i].profile;
        }
    }
    return NULL;
}

static uint8_t clamp_depth(unsigned long depth) {
    if (depth > (unsigned long) (PROTO_PATH_SIZE - 1)) {
        return (uint8_t) (PROTO_PATH_SIZE - 1);
    }
    return (uint8_t) depth;
}

bool set_classification_max_depth(mmt_handler_t *mmt_handler, uint8_t max_depth) {
    if (likely(mmt_handler != NULL)) {
        mmt_handler->classification_max_depth = clamp_depth(max_depth);
        return 1;
    }
    return 0;
}

uint8_t get_classification_max_depth(const mmt_handler_t *mmt_handler) {
    if (mmt_handler == NULL) {
        return 0;
    }
    return mmt_handler->classification_max_depth;
}

bool mmt_apply_dpi_profile(mmt_handler_t *mmt_handler, const mmt_dpi_profile_t *profile) {
    if (mmt_handler == NULL || profile == NULL) {
        return 0;
    }
    mmt_handler->classification_max_depth = clamp_depth(profile->classification_max_depth);
    mmt_handler->hostname_classify     = (profile->app_protocol_classify != 0) ? 1 : 0;
    mmt_handler->port_classify         = (profile->port_classify != 0) ? 1 : 0;
    mmt_handler->ip_address_classify   = (profile->ip_address_classify != 0) ? 1 : 0;
    return 1;
}

bool mmt_apply_dpi_profile_by_name(mmt_handler_t *mmt_handler, const char *name) {
    if (mmt_handler == NULL) {
        return 0;
    }
    const mmt_dpi_profile_t *profile = find_profile_by_name(name);
    if (profile == NULL) {
        return 0;
    }
    return mmt_apply_dpi_profile(mmt_handler, profile);
}

int mmt_load_dpi_profiles_file(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        mmt_stderr_log("[mmt-dpi][profiles] could not open profiles file '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    char line[512];
    int loaded = 0, lineno = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        lineno++;
        char *hash = strchr(line, '#');
        if (hash != NULL) {
            *hash = '\0';
        }
        /* Format: "<name> <max_depth> <app> <port> <ip>" — same one-line-one-
         * rule style as the M9 port-map file. */
        char name_tok[MMT_DPI_PROFILE_NAME_LEN];
        int depth = -1, app = -1, port = -1, ip = -1;
        int nf = sscanf(line, "%31s %d %d %d %d",
                name_tok, &depth, &app, &port, &ip);
        if (nf < 5) {
            continue; // blank / malformed line -> skip silently
        }
        if (depth < 0 || (app != 0 && app != 1) || (port != 0 && port != 1)
                || (ip != 0 && ip != 1)) {
            mmt_stderr_log("[mmt-dpi][profiles] %s:%d invalid value(s) "
                    "(depth %d must be >= 0, toggles must be 0/1) - skipped\n",
                    path, lineno, depth);
            continue;
        }
        if (find_profile_by_name(name_tok) != NULL) {
            mmt_stderr_log("[mmt-dpi][profiles] %s:%d name '%s' already taken "
                    "(predefined or loaded) - skipped\n", path, lineno, name_tok);
            continue;
        }
        if (custom_profiles_n >= MMT_DPI_CUSTOM_PROFILES_MAX) {
            mmt_stderr_log("[mmt-dpi][profiles] %s:%d custom profile table full "
                    "(%d) - '%s' skipped\n", path, lineno,
                    MMT_DPI_CUSTOM_PROFILES_MAX, name_tok);
            continue;
        }
        custom_profile_entry_t *e = &custom_profiles[custom_profiles_n];
        strncpy(e->name, name_tok, sizeof(e->name) - 1);
        e->name[sizeof(e->name) - 1] = '\0';
        e->profile.classification_max_depth = clamp_depth((unsigned long) depth);
        e->profile.app_protocol_classify = (uint8_t) app;
        e->profile.port_classify = (uint8_t) port;
        e->profile.ip_address_classify = (uint8_t) ip;
        custom_profiles_n++;
        loaded++;
    }
    fclose(fp);
    return loaded;
}

void mmt_dpi_profile_apply_env(mmt_handler_t *mmt_handler) {
    if (mmt_handler == NULL) {
        return;
    }
    /* Custom names first so MMT_DPI_PROFILE can resolve them below. Unset
     * variables are no-ops — the default path stays byte-identical. */
    const char *profiles_path = getenv("MMT_DPI_PROFILES_FILE");
    if (profiles_path != NULL && profiles_path[0] != '\0') {
        /* The env var IS the feature — an operator-supplied config path,
         * the same deliberate contract as MMT_DPI_IP_RANGES_FILE /
         * MMT_DPI_PORT_MAP_FILE (open alerts #26/#27 on main). */
        int n = mmt_load_dpi_profiles_file(profiles_path); // codeql[cpp/path-injection]
        if (n > 0) {
            mmt_stderr_log("[mmt-dpi][profiles] loaded %d custom profile(s) from %s\n",
                    n, profiles_path);
        }
    }
    const char *name = getenv("MMT_DPI_PROFILE");
    if (name == NULL || name[0] == '\0') {
        return;
    }
    if (!mmt_apply_dpi_profile_by_name(mmt_handler, name)) {
        mmt_stderr_log("[mmt-dpi][profiles] unknown profile '%s' - keeping built-in defaults\n",
                name);
    }
}

# Common definitions for MMT-DPI ZIP install/uninstall.
# Sourced by install.sh and uninstall.sh — single source of truth for paths,
# version, and library inventory. Canonical install logic lives in sdk/Makefile;
# this file mirrors it for the offline ZIP distribution.
# shellcheck shell=bash
# shellcheck disable=SC2034  # vars are used by sourcing scripts

# VERSION is stamped at `make zip` time from rules/common.mk (single source).
# Fallback is kept for direct execution from the source tree without rebuilding.
VERSION="${VERSION:-1.8.0}"

# Install prefix — honour MMT_BASE if the caller exported it (consistent with
# sdk/Makefile and the root install.sh).
MMT_BASE="${MMT_BASE:-/opt/mmt}"
MMT_DPI="$MMT_BASE/dpi"
MMT_LIB="$MMT_DPI/lib"
MMT_INC="$MMT_DPI/include"
MMT_PLUGINS="$MMT_BASE/plugins"
MMT_EXAMS="$MMT_BASE/examples"

# ld.so config — canonical name is mmt-dpi.conf (sdk/Makefile); mmt.conf is
# the legacy name kept for cleanup on uninstall.
LD_CONF_CANONICAL="/etc/ld.so.conf.d/mmt-dpi.conf"
LD_CONF_LEGACY="/etc/ld.so.conf.d/mmt.conf"

# Libraries shipped in the ZIP (must stay in sync with sdk/Makefile LIB* vars).
MMT_LIBS=(
    libmmt_core
    libmmt_tcpip
    libmmt_tmobile
    libmmt_tdicom
    libmmt_business_app
    libmmt_security
    libmmt_fuzz
)
# Subset also installed as plugins (sdk/Makefile copies these to MMT_PLUGINS).
MMT_PLUGIN_LIBS=(
    libmmt_tcpip
    libmmt_tmobile
    libmmt_tdicom
    libmmt_business_app
)

# Validate install prefix — the single definition shared by the root
# install.sh (sourced at run time) and both ZIP scripts (issue #211,
# F-BUG-121: the blacklist used to miss several shell-significant
# characters — space, tab, ( ) { } [ ] # % = : ~ , ^ — so validation is now
# an allowlist instead of an enumeration of bad characters).
validate_mmt_base() {
    local p="$1"
    if [ -z "$p" ] || [ ${#p} -gt 256 ]; then
        echo "ERROR: MMT_BASE must be 1-256 characters" >&2; return 1
    fi
    if [[ "$p" != /* ]]; then
        echo "ERROR: MMT_BASE must be an absolute path: $p" >&2; return 1
    fi
    if [ "$p" = "/" ]; then
        echo "ERROR: MMT_BASE must not be /" >&2; return 1
    fi
    if [[ "$p" == *".."* ]]; then
        echo "ERROR: MMT_BASE must not contain .. : $p" >&2; return 1
    fi
    # Allowlist: path components may only contain [A-Za-z0-9._-] — every
    # metacharacter, whitespace and control character is rejected by
    # construction rather than by an incomplete blacklist.
    if [[ ! "$p" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
        echo "ERROR: MMT_BASE contains characters outside [A-Za-z0-9._/-]: $p" >&2; return 1
    fi
    if [[ "$p" == */ ]]; then
        echo "ERROR: MMT_BASE must not have trailing slash: $p" >&2; return 1
    fi
}

# True when the current user can create/write inside prefix "$1": walks up to
# the nearest existing ancestor and tests its writability. The installers use
# this to decide whether elevation is needed at all — a user-local prefix must
# not escalate (issue #211, F-BUG-116).
prefix_writable() {
    local p="$1"
    while [ ! -e "$p" ]; do
        p="$(dirname -- "$p")"
    done
    [ -w "$p" ]
}

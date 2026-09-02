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

# Validate install prefix — same hardening as root install.sh / issue #136.
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
    # shellcheck disable=SC1003  # single-quote pattern $'\'' is intentional
    if [[ "$p" == *';'* || "$p" == *'|'* || "$p" == *'&'* || "$p" == *'$'* || "$p" == *'`'* \
        || "$p" == *'!'* || "$p" == *'*'* || "$p" == *'?'* || "$p" == *'<'* || "$p" == *'>'* \
        || "$p" == *'"'* || "$p" == *$'\''* || "$p" == *'\\'* || "$p" == *$'\n'* ]]; then
        echo "ERROR: MMT_BASE contains shell metacharacters: $p" >&2; return 1
    fi
    if [[ "$p" == */ ]]; then
        echo "ERROR: MMT_BASE must not have trailing slash: $p" >&2; return 1
    fi
}

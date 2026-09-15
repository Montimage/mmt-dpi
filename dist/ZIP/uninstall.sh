#!/usr/bin/env bash
# MMT-DPI offline ZIP uninstaller — hardened, deduped via mmt-install-common.sh.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091  # dynamic path via SCRIPT_DIR
# shellcheck source=./mmt-install-common.sh
source "$SCRIPT_DIR/mmt-install-common.sh"

validate_mmt_base "$MMT_BASE" || exit 1

# Elevation mirrors install.sh (issue #211): a user-local prefix uninstalls
# without root; system paths (/etc/ld.so.conf.d, ldconfig) are touched only
# when we actually have the privileges to do so.
ELEVATED=0
if ! prefix_writable "$MMT_BASE" && [[ $(id -u) -ne 0 ]]; then
    echo "This script should be run using sudo or as the root user" >&2
    echo "(prefix $MMT_BASE is not writable by $(id -un))" >&2
    exit 1
elif [[ $(id -u) -eq 0 ]]; then
    ELEVATED=1
fi

echo "Start uninstalling mmt-sdk .... "
echo "MMT_BASE: $MMT_BASE"
echo "MMT_DPI: $MMT_DPI"
echo "Checking location ... "

if [ ! -d "$MMT_DPI" ]; then
    echo "Nothing to remove: $MMT_DPI does not exist" >&2
else
    echo "Removing mmt-sdk ... "
    rm -rf "$MMT_DPI"
fi

if [ -d "$MMT_PLUGINS" ]; then
    for lib in "${MMT_PLUGIN_LIBS[@]}"; do
        rm -f "$MMT_PLUGINS/$lib.so"
    done
    rmdir "$MMT_PLUGINS" 2>/dev/null || true
fi

# The installer creates $MMT_EXAMS (mkdir -p + full copy) — remove it too so
# an install/uninstall round trip leaves no residue (issue #211, F-BUG-121).
if [ -d "$MMT_EXAMS" ]; then
    rm -rf "$MMT_EXAMS"
fi
# Drop the prefix itself when nothing remains — rmdir fails harmlessly on a
# non-empty directory the installer did not create (e.g. /opt/mmt content).
rmdir "$MMT_BASE" 2>/dev/null || true

echo "Cleaning environment ... "
if [ "$ELEVATED" = "1" ]; then
    rm -f "$LD_CONF_CANONICAL" "$LD_CONF_LEGACY"
    ldconfig
fi

echo "[MMT-]> mmt-sdk has been removed from the system! "
echo "You can learn more about mmt-sdk at: http://www.montimage.eu"

#!/usr/bin/env bash
# MMT-DPI offline ZIP uninstaller — hardened, deduped via mmt-install-common.sh.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091  # dynamic path via SCRIPT_DIR
# shellcheck source=./mmt-install-common.sh
source "$SCRIPT_DIR/mmt-install-common.sh"

if [[ $(id -u) -ne 0 ]]; then
    echo "This script should be run using sudo or as the root user" >&2
    exit 1
fi

validate_mmt_base "$MMT_BASE"

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

echo "Cleaning environment ... "
rm -f "$LD_CONF_CANONICAL" "$LD_CONF_LEGACY"
ldconfig

echo "[MMT-]> mmt-sdk has been removed from the system! "
echo "You can learn more about mmt-sdk at: http://www.montimage.eu"

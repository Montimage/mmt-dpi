#!/usr/bin/env bash
# MMT-DPI offline ZIP installer — hardened, deduped via mmt-install-common.sh.
# Canonical install logic is in sdk/Makefile; this script mirrors it for the
# offline ZIP distribution. VERSION is stamped by `make zip` from rules/common.mk.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Source shared constants and helpers (single source of truth for paths/libs).
# shellcheck disable=SC1091  # dynamic path via SCRIPT_DIR
# shellcheck source=./mmt-install-common.sh
source "$SCRIPT_DIR/mmt-install-common.sh"

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
if [[ $(id -u) -ne 0 ]]; then
    echo "This script should be run using sudo or as the root user" >&2
    exit 1
fi

validate_mmt_base "$MMT_BASE"

# Resolve source directories relative to this script (not $PWD).
SDKINC="$SCRIPT_DIR/include"
SDKLIB="$SCRIPT_DIR/lib"
SDKXAM="$SCRIPT_DIR/examples"

for d in "$SDKINC" "$SDKLIB" "$SDKXAM"; do
    if [ ! -d "$d" ]; then
        echo "ERROR: required source directory not found: $d" >&2
        echo "  Run this script from the extracted ZIP root (where lib/, include/, examples/ live)." >&2
        exit 1
    fi
done

if ! compgen -G "$SDKLIB/libmmt_*.so.*" >/dev/null; then
    echo "ERROR: no versioned libraries found in $SDKLIB" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
echo "Start installing mmt-sdk .... "
echo "VERSION: $VERSION"
echo "MMT_BASE: $MMT_BASE"
echo "MMT_DPI: $MMT_DPI"
echo "MMT_LIB: $MMT_LIB"
echo "MMT_INC: $MMT_INC"
echo "MMT_PLUGINS: $MMT_PLUGINS"
echo "SDKINC: $SDKINC"
echo "SDKLIB: $SDKLIB"
echo "SDKXAM: $SDKXAM"

echo "Preparing location ... "
mkdir -p "$MMT_DPI"
mkdir -p "$MMT_LIB"
mkdir -p "$MMT_INC"
mkdir -p "$MMT_PLUGINS"
mkdir -p "$MMT_EXAMS"

echo "Copying resource ... "

shopt -s nullglob
for lib in "${MMT_LIBS[@]}"; do
    matches=("$SDKLIB/$lib.so."*)
    if [ ${#matches[@]} -eq 0 ]; then
        echo "[WARN] $lib not found in $SDKLIB -- skipping" >&2
        continue
    fi
    cp "${matches[@]}" "$MMT_LIB"/
    base="$(basename "${matches[0]}")"
    ln -snf "$MMT_LIB/$base" "$MMT_LIB/$lib.so"
done
shopt -u nullglob
echo "[MMT-]> Installed  $SDKLIB at $MMT_LIB"

cp -R "$SDKINC"/* "$MMT_INC"/
echo "[MMT-]> Installed  $SDKINC at $MMT_INC"

cp -R "$SDKXAM"/* "$MMT_EXAMS"/
echo "[MMT-]> Installed  $SDKXAM at $MMT_EXAMS"

for lib in "${MMT_PLUGIN_LIBS[@]}"; do
    shopt -s nullglob
    matches=("$SDKLIB/$lib.so."*)
    shopt -u nullglob
    if [ ${#matches[@]} -eq 0 ]; then
        echo "[WARN] plugin $lib not found -- skipping" >&2
        continue
    fi
    cp "${matches[0]}" "$MMT_PLUGINS/$lib.so"
    echo "[MMT-]> Installed $MMT_PLUGINS/$lib.so"
done

if [ -f "$LD_CONF_LEGACY" ] && [ ! -f "$LD_CONF_CANONICAL" ]; then
    mv "$LD_CONF_LEGACY" "$LD_CONF_CANONICAL"
fi
if [ ! -f "$LD_CONF_CANONICAL" ] || ! grep -qxF "$MMT_LIB" "$LD_CONF_CANONICAL" 2>/dev/null; then
    echo "$MMT_LIB" >> "$LD_CONF_CANONICAL"
fi
if [ -f "$LD_CONF_LEGACY" ] && [ -f "$LD_CONF_CANONICAL" ]; then
    rm -f "$LD_CONF_LEGACY"
fi

ldconfig

echo "[MMT-]> Done! "
echo "Thanks you for installing mmt-sdk, you can learn more about mmt-sdk at: http://www.montimage.eu"

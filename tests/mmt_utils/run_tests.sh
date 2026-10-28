#!/bin/bash
# Run mmt_utils tests
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source paths
CORE_SRC="$PROJECT_DIR/src/mmt_core/src"
CORE_PUBLIC_INC="$PROJECT_DIR/src/mmt_core/public_include"

# Compile test
echo "Compiling mmt_utils tests..."
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"
${CC:-gcc} "${extra_cflags[@]}" -Wall -Wextra -std=c11 \
    -D'u_char=unsigned char' \
    -I"$PROJECT_DIR/src/mmt_core/private_include" -I"$CORE_PUBLIC_INC" \
    -o "$SCRIPT_DIR/test_mmt_utils" \
    "$SCRIPT_DIR/test_mmt_utils.c" \
    "$CORE_SRC/mmt_utils.c" \
    -lm

# Issue #505: the public attribute formatters (packet_processing.c) — the
# header-line formatter wrote buff[-1] for len <= 0. packet_processing.c links
# on its own plus mmt_inet_ntop.c; the test file stubs the two registry
# lookups it references.
${CC:-gcc} "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 \
    -I"$PROJECT_DIR/src/mmt_core/private_include" -I"$CORE_PUBLIC_INC" \
    -I"$PROJECT_DIR/src/mmt_tcpip/lib" \
    -o "$SCRIPT_DIR/test_attr_snprintf" \
    "$SCRIPT_DIR/test_attr_snprintf.c" \
    "$CORE_SRC/packet_processing.c" \
    "$CORE_SRC/mmt_inet_ntop.c" \
    -lm -lpthread

# Run tests
echo "Running mmt_utils tests..."
if "$SCRIPT_DIR/test_mmt_utils" && "$SCRIPT_DIR/test_attr_snprintf"; then
    echo "mmt_utils tests: PASSED"
else
    echo "mmt_utils tests: FAILED"
    exit 1
fi

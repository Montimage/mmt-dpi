#!/bin/bash
# Run the DPI-profiles suite (issue #87): named profiles with per-level
# detection toggles — the mmt_apply_dpi_profile* API, the profiles-file
# loader, the MMT_DPI_PROFILE(S)_FILE env selection and the
# classification_max_depth bound enforced in the classification walk and in
# set_classified_proto().
#
# The suite source-compiles the mmt_core objects the engine needs
# (packet_registry, packet_pipeline, packet_session, packet_stats, memory,
# hashmap, mmt_data, mmt_inet_ntop, proto_meta, plugins_engine,
# extraction_lib, mmt_init) plus dpi_profiles.c and hash_utils.cpp — the
# same recipe as tests/core_engine — so gcov records them under --coverage
# and ASan/UBSan instrument them under SANITIZE=*.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

CORE_SRC="$PROJECT_DIR/src/mmt_core/src"
CORE_PRIVATE_INC="$PROJECT_DIR/src/mmt_core/private_include"
CORE_PUBLIC_INC="$PROJECT_DIR/src/mmt_core/public_include"

CC="${CC:-gcc}"
CXX="${CXX:-g++}"
read -r -a extra_cflags <<< "${EXTRA_CFLAGS:-}"

INCS=(-I"$CORE_PRIVATE_INC" -I"$CORE_PUBLIC_INC" -I"$PROJECT_DIR/src/mmt_tcpip/lib")

echo "Compiling dpi-profiles tests..."

C_SOURCES="packet_processing.c packet_registry.c packet_pipeline.c \
packet_session.c packet_stats.c memory.c \
hashmap.c mmt_data.c mmt_inet_ntop.c \
proto_meta.c plugins_engine.c extraction_lib.c mmt_init.c \
dpi_profiles.c"

objects=()
for src in $C_SOURCES; do
    obj="$SCRIPT_DIR/$(basename "$src" .c).o"
    "$CC" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 "${INCS[@]}" \
        -c "$CORE_SRC/$src" -o "$obj"
    objects+=("$obj")
done

"$CXX" "${extra_cflags[@]}" -Wall -Wextra -std=c++11 "${INCS[@]}" \
    -c "$CORE_SRC/hash_utils.cpp" -o "$SCRIPT_DIR/hash_utils.o"
objects+=("$SCRIPT_DIR/hash_utils.o")

"$CC" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 "${INCS[@]}" \
    -c "$SCRIPT_DIR/test_dpi_profiles.c" -o "$SCRIPT_DIR/test_dpi_profiles.o"
objects+=("$SCRIPT_DIR/test_dpi_profiles.o")

"$CXX" "${extra_cflags[@]}" \
    -o "$SCRIPT_DIR/test_dpi_profiles" "${objects[@]}" -lm -lpthread -ldl

# Run from a scratch directory: load_plugins() scans ./plugins first, and an
# empty/missing one deterministically takes the no-plugin early return. Keep
# the engine's verbose output in a log unless the suite fails.
echo "Running dpi-profiles tests..."
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
if ( cd "$WORK" && "$SCRIPT_DIR/test_dpi_profiles" > "$WORK/dpi_profiles.log" 2>&1 ); then
    echo "DPI-profiles tests: PASSED"
else
    cat "$WORK/dpi_profiles.log"
    echo "DPI-profiles tests: FAILED"
    exit 1
fi

#!/bin/bash
# Run core-engine tests (issue #241): session lifecycle through
# packet_session.c's session manager and the memory.c arena allocator.
# Part 2 (issue #242) adds the classification utilities: hostname matching
# (doted-name trie + linear suffix scan), the CIDR attribution trees and the
# memoized packet-offset cache.
#
# The suite source-compiles packet_processing.c and the objects it needs from
# src/mmt_core (packet_registry, packet_pipeline, packet_session,
# packet_stats, memory, hashmap, mmt_data, mmt_inet_ntop, proto_meta,
# plugins_engine, extraction_lib, mmt_init, dpi_profiles) plus
# hash_utils.cpp, so gcov records them under --coverage and ASan/UBSan
# instrument them under SANITIZE=*.
#
# -Wl,--wrap=malloc/--wrap=calloc route the library's libc allocations through
# the budget counters in test_core_engine.c; test_core_engine_new.cpp replaces
# operator new so the C++ allocation sites in hash_utils.cpp can be failed too.
#
# Issue #525: the same library objects (plus mmt_attr_sprintf_compat.c and,
# since #533, mmt_utils.c) also
# link test_api_contracts — the public-API contract table, one entry per
# MMTAPI function, linked without the allocator wraps. After it passes,
# tools/ci/check-api-contracts.sh fails the suite when a declared MMTAPI
# function has no entry (or an entry is stale, duplicated or an unlisted
# waiver).
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

echo "Compiling core-engine tests..."

C_SOURCES="packet_processing.c packet_registry.c packet_pipeline.c \
packet_session.c packet_stats.c memory.c \
hashmap.c mmt_data.c mmt_inet_ntop.c \
proto_meta.c plugins_engine.c extraction_lib.c mmt_init.c \
dpi_profiles.c"

# lib_objects: the library under test, shared by both binaries (one set of
# .o files, so --coverage counters from both runs merge).
lib_objects=()
for src in $C_SOURCES; do
    obj="$SCRIPT_DIR/$(basename "$src" .c).o"
    "$CC" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 "${INCS[@]}" \
        -c "$CORE_SRC/$src" -o "$obj"
    lib_objects+=("$obj")
done

"$CXX" "${extra_cflags[@]}" -Wall -Wextra -std=c++11 "${INCS[@]}" \
    -c "$CORE_SRC/hash_utils.cpp" -o "$SCRIPT_DIR/hash_utils.o"
lib_objects+=("$SCRIPT_DIR/hash_utils.o")

# Issue #242: the classification-utility unit under test lives in
# src/mmt_tcpip/lib. Compile it and its avltree dependency here; the unit's
# mmt_common_internal_include.h pulls protocols/rtp.h, which needs the
# fuzz-engine include dir for mmt_quality_estimation_utilities.h.
# -Wno-missing-field-initializers keeps the generated 3-field table entries
# quiet under -Wextra.
TCPIP_SRC="$PROJECT_DIR/src/mmt_tcpip/lib"
for src in avltree.c mmt_tcpip_classif_utils.c; do
    obj="$SCRIPT_DIR/$(basename "$src" .c).o"
    "$CC" "${extra_cflags[@]}" -Wall -Wextra -Wno-missing-field-initializers \
        -std=gnu11 "${INCS[@]}" -I"$PROJECT_DIR/src/mmt_fuzz_engine" \
        -c "$TCPIP_SRC/$src" -o "$obj"
    lib_objects+=("$obj")
done

objects=("${lib_objects[@]}")
"$CC" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 "${INCS[@]}" \
    -c "$SCRIPT_DIR/test_core_engine.c" -o "$SCRIPT_DIR/test_core_engine.o"
objects+=("$SCRIPT_DIR/test_core_engine.o")

"$CXX" "${extra_cflags[@]}" -Wall -Wextra -std=c++11 "${INCS[@]}" \
    -c "$SCRIPT_DIR/test_core_engine_new.cpp" -o "$SCRIPT_DIR/test_core_engine_new.o"
objects+=("$SCRIPT_DIR/test_core_engine_new.o")

"$CXX" "${extra_cflags[@]}" -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc \
    -o "$SCRIPT_DIR/test_core_engine" "${objects[@]}" -lm -lpthread -ldl

# Issue #525: the public-API contract binary — library objects only, no wraps.
# Issue #533 adds mmt_utils.c: its string/hex utilities are MMTAPI now.
"$CC" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 "${INCS[@]}" \
    -c "$CORE_SRC/mmt_attr_sprintf_compat.c" -o "$SCRIPT_DIR/mmt_attr_sprintf_compat.o"
"$CC" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 "${INCS[@]}" \
    -c "$CORE_SRC/mmt_utils.c" -o "$SCRIPT_DIR/mmt_utils.o"
"$CC" "${extra_cflags[@]}" -Wall -Wextra -std=gnu11 "${INCS[@]}" \
    -c "$SCRIPT_DIR/test_api_contracts.c" -o "$SCRIPT_DIR/test_api_contracts.o"
"$CXX" "${extra_cflags[@]}" -o "$SCRIPT_DIR/test_api_contracts" "${lib_objects[@]}" \
    "$SCRIPT_DIR/mmt_attr_sprintf_compat.o" "$SCRIPT_DIR/mmt_utils.o" \
    "$SCRIPT_DIR/test_api_contracts.o" -lm -lpthread -ldl

# Run from a scratch directory: load_plugins() scans ./plugins first, and an
# empty/missing one deterministically takes the no-plugin early return. The
# engine prints verbose DEBUG lines; keep them in a log and only surface it
# when the suite fails.
echo "Running core-engine tests..."
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
if ( cd "$WORK" && "$SCRIPT_DIR/test_core_engine" > "$WORK/core_engine.log" 2>&1 ); then
    echo "Core-engine tests: PASSED"
else
    cat "$WORK/core_engine.log"
    echo "Core-engine tests: FAILED"
    exit 1
fi

echo "Running public-API contract tests..."
if ( cd "$WORK" && "$SCRIPT_DIR/test_api_contracts" > "$WORK/api_contracts.log" 2>&1 ); then
    tail -n 1 "$WORK/api_contracts.log"
else
    cat "$WORK/api_contracts.log"
    echo "Public-API contract tests: FAILED"
    exit 1
fi
bash "$PROJECT_DIR/tools/ci/check-public-decls.sh" --list > "$WORK/api_decls.txt"
"$SCRIPT_DIR/test_api_contracts" --list > "$WORK/api_contracts.txt"
if bash "$PROJECT_DIR/tools/ci/check-api-contracts.sh" --decls "$WORK/api_decls.txt" \
        --contracts "$WORK/api_contracts.txt" \
        --waivers "$SCRIPT_DIR/api-contract-waivers.txt"; then
    echo "Public-API contract tests: PASSED"
else
    echo "Public-API contract tests: FAILED"
    exit 1
fi

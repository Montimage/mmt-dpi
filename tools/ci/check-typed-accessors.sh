#!/usr/bin/env bash
#
# check-typed-accessors.sh — assert that each typed accessor added by the
# typed-enum pass (#150) has at least one internal call site (issue #230,
# F-DEAD-009).
#
# The five static-inline accessors in src/mmt_core/public_include/mmt_core.h
# were published but never adopted, leaving the weakly typed originals as the
# only ones in use and the type discipline unenforceable. An accessor with
# zero callers is dead API surface; this gate fails the moment one regresses
# back to zero callers.
#
# What it counts: uses of each accessor name in src/**/*.c outside the
# defining header (the accessors live in a public header, so a caller is any
# .c occurrence — the definitions themselves are in mmt_core.h).
#
# It also asserts that generic_classification_function returns
# mmt_classify_verdict_t (issue #546).
#
# Exit codes: 0 = every accessor has >= 1 call site and the typedef holds,
#             1 = violation.
#
# Usage: bash tools/ci/check-typed-accessors.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

ACCESSORS="
mmt_attr_get_scope_typed
mmt_attr_get_data_type_typed
mmt_attribute_get_scope_typed
mmt_attribute_get_data_type_typed
mmt_attr_get_proto_id_typed
"

fail=0
for accessor in $ACCESSORS; do
    # `|| true`: grep exits 1 on zero matches; without it `set -e`/`pipefail`
    # would kill the script here before the diagnostic below can print (same
    # zero-match bug fixed in count-weak-types.sh).
    count="$(grep -rn --include='*.c' -e "\b${accessor}\b" src/ | wc -l || true)"
    if [ "$count" -eq 0 ]; then
        echo "✗ ${accessor}: zero internal call sites — adopt it or drop it (F-DEAD-009)" >&2
        fail=1
    else
        echo "    ${accessor}: ${count} call site(s)"
    fi
done

# Issue #546 (F-CLEAN-021): the classifier callback type returns the verdict
# enum, not a bare int, in C (C++ keeps an int view of the same ABI; see the
# comment in plugin_defs.h).
if grep -Eq '^typedef mmt_classify_verdict_t \(\*generic_classification_function\)' \
        src/mmt_core/public_include/plugin_defs.h; then
    echo "    generic_classification_function: returns mmt_classify_verdict_t"
else
    echo "✗ generic_classification_function does not return mmt_classify_verdict_t (issue #546)" >&2
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "✓ every typed accessor has at least one internal call site"
echo "✓ the classifier typedef returns mmt_classify_verdict_t"

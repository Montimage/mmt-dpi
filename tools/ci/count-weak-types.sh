#!/usr/bin/env bash
#
# count-weak-types.sh — ratchet on weakly typed public-API signatures
# (issues #230/#231, F-DEAD-010; helper committed under #190).
#
# src/mmt_core/public_include/ historically declared its API with weak types:
# raw-integer protocol-id parameters (#230, task 5.6), raw `void *`
# parameters and `int`-as-boolean returns (#231, task 5.7). This counter
# makes the migration ratchetable.
#
# What it counts, in src/mmt_core/public_include/*.h:
#
#   proto_id     parameter declarations whose name contains "proto" or
#                "protocol" and whose type is a raw integer type
#                (int/uintN_t/unsigned/short/long/char), excluding pointer
#                parameters and `*_name` strings.
#
#   void_star    `void *` occurrences inside parentheses — i.e. in parameter
#                position of a function declaration or function-pointer
#                typedef — after comments are stripped. Return types at
#                paren depth 0 (e.g. `MMTAPI void* MMTCALL get_...`) and
#                struct fields are not parameters and are not counted.
#                Use mmt_opaque_t / mmt_const_opaque_t instead.
#
#   int_bool     public function declarations returning `int` that are not
#                on the explicit allowlist below — every boolean-semantic
#                function must return `bool` (stdbool.h). The allowlist
#                covers the remaining legitimate `int` returns:
#                - value getters (attribute ids/lengths/positions, offsets,
#                  link type, hex/int parsers, string index)
#                - tri-state comparators (mmt_str*cmp, mmt_memcmp) and
#                  length writers (mmt_attr_*format, proto_hierarchy_to_str)
#                - enum-status returns (set_classified_proto)
#                - load-count/error returns (mmt_load_dpi_profiles_file —
#                  issue #87: number of profiles loaded, -1 on open failure)
#                - callback-conforming functions whose signature must stay
#                  assignment-compatible with an int-returning
#                  function-pointer typedef (general_*_extraction,
#                  silent_extraction, debug_extracted_attributes_printout_handler)
#
# Modes:
#   default      exit 1 when any count rises above its committed baseline
#                (tools/ci/weak-types-baseline.txt); a drop is reported so
#                the baseline can be tightened in the same change.
#   --strict     exit 1 when any count is anything but 0 — the Task 5.7 gate.
#
# Exit codes: 0 = pass, 1 = condition violated, 2 = helper broken.
#
# Usage: bash tools/ci/count-weak-types.sh [--strict]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

BASELINE_FILE="tools/ci/weak-types-baseline.txt"
STRICT=0
[ "${1:-}" = "--strict" ] && STRICT=1

# --- proto_id ---------------------------------------------------------------
proto_id_count="$(grep -hE '\b(int|uint32_t|uint16_t|uint8_t|unsigned|u_int32_t|short|long|char)[[:space:]]+[a-z_]*(proto|protocol)[a-z_]*[[:space:]]*[,)=]' \
    src/mmt_core/public_include/*.h \
    | grep -vcE '\*|_name[[:space:]]*[,)=]' || true)"

# --- void_star --------------------------------------------------------------
# Strip comments, then count `void *` tokens at paren depth >= 1.
void_star_count="$(awk '
{
  line = $0; out = ""; i = 1; n = length(line)
  while (i <= n) {
    c2 = substr(line, i, 2)
    if (inblock) { if (c2 == "*/") { inblock = 0; i += 2 } else i++; continue }
    if (c2 == "/*") { inblock = 1; i += 2; continue }
    if (c2 == "//") break
    out = out substr(line, i, 1); i++
  }
  m = length(out); j = 1
  while (j <= m) {
    ch = substr(out, j, 1)
    if (ch == "(") depth++
    else if (ch == ")") { if (depth > 0) depth-- }
    else if (ch == "v" && substr(out, j, 4) == "void") {
      k = j + 4
      while (substr(out, k, 1) == " " || substr(out, k, 1) == "\t") k++
      if (substr(out, k, 1) == "*") { if (depth >= 1) count++; j = k }
    }
    j++
  }
}
END { print count + 0 }
' src/mmt_core/public_include/*.h)"

# --- int_bool ---------------------------------------------------------------
# Names of public functions allowed to keep an `int` return (see header).
read -r -d '' INT_RETURN_ALLOWLIST <<'EOF' || true
get_packet_offset_at_index
get_attr_protocol_index
get_attr_status
get_attr_data_type
get_attr_data_len
get_attr_offset
get_attr_scope
get_data_size_by_proto_and_field_ids
get_field_position_by_protocol_and_field_ids
get_attribute_scope
get_proto_attribute_position
get_proto_attribute_length
get_proto_attribute_id
get_proto_attribute_type
get_proto_attribute_scope
get_data_link_type
mmt_strcasecmp
mmt_strncasecmp
mmt_strcmp
mmt_strncmp
mmt_memcmp
mmt_attr_format
mmt_attr_fprintf
mmt_attr_sprintf
proto_hierarchy_to_str
proto_hierarchy_to_str_with_size
set_classified_proto
mmt_load_dpi_profiles_file
hex2int
str_hex2int
str_hex2int_n
char2int
str_index
general_byte_to_byte_extraction
general_char_extraction
general_int_extraction
general_int_extraction_with_ordering_change
general_short_extraction
general_short_extraction_with_ordering_change
silent_extraction
debug_extracted_attributes_printout_handler
EOF

int_bool_count="$(
  {
    # MMTAPI-exported declarations: MMTAPI int MMTCALL name(
    grep -hoE 'MMTAPI[[:space:]]+int[[:space:]]+MMTCALL[[:space:]]+[a-zA-Z_][a-zA-Z_0-9]*' \
        src/mmt_core/public_include/*.h | awk '{print $4}'
    # Plain declarations: `int name(` / `static inline int name(` at line start.
    grep -hoE '^[[:space:]]*(static[[:space:]]+inline[[:space:]]+)?int[[:space:]]+[a-zA-Z_][a-zA-Z_0-9]*[[:space:]]*\(' \
        src/mmt_core/public_include/*.h | grep -oE '[a-zA-Z_][a-zA-Z_0-9]*[[:space:]]*\($' | tr -d ' \t('
  } | sort -u | { grep -vxF "$INT_RETURN_ALLOWLIST" || true; } | wc -l
)"

echo "    raw-integer protocol-id parameters: $proto_id_count"
echo "    raw void * parameters:              $void_star_count"
echo "    int-as-boolean returns:             $int_bool_count"

if [ "$STRICT" -eq 1 ]; then
    fails=0
    for pair in "raw-integer protocol-id parameter:$proto_id_count" "raw void * parameter:$void_star_count" "int-as-boolean return:$int_bool_count"; do
        label="${pair%%:*}"; n="${pair##*:}"
        if [ "$n" -ne 0 ]; then
            echo "✗ $n ${label}(s) remain — Task 5.7 requires 0" >&2
            fails=1
        fi
    done
    [ "$fails" -ne 0 ] && exit 1
    echo "✓ no weakly typed public-API signatures remain"
    exit 0
fi

if [ ! -f "$BASELINE_FILE" ]; then
    echo "✗ baseline not found: $BASELINE_FILE" >&2
    exit 2
fi

baseline_for() {
    awk -v k="$1" 'NF && $1 !~ /^#/ && $1 == k {print $2; exit}' "$BASELINE_FILE"
}

fails=0
for triple in "proto_id:$proto_id_count:raw-integer protocol-id parameters" \
              "void_star:$void_star_count:raw void * parameters" \
              "int_bool:$int_bool_count:int-as-boolean returns"; do
    key="${triple%%:*}"; rest="${triple#*:}"
    count="${rest%%:*}"; label="${rest#*:}"
    baseline="$(baseline_for "$key")"
    if ! [[ "$baseline" =~ ^[0-9]+$ ]]; then
        echo "✗ baseline for '$key' unreadable in $BASELINE_FILE" >&2
        exit 2
    fi
    if [ "$count" -gt "$baseline" ]; then
        echo "✗ $label rose above the baseline: $count > $baseline" >&2
        echo "  To fix: use the typed aliases (mmt_proto_id_t / mmt_opaque_t /" >&2
        echo "  bool) for new signatures, or update $BASELINE_FILE with justification" >&2
        fails=1
    elif [ "$count" -lt "$baseline" ]; then
        echo "  note: $label dropped below the baseline ($count < $baseline) —"
        echo "        tighten $BASELINE_FILE in this change"
    fi
done
[ "$fails" -ne 0 ] && exit 1
echo "✓ weak-type counts within the baselines"

#!/usr/bin/env bash
#
# run_throughput_attrs_test.sh — the issue #555 acceptance harness for the
# phase0_throughput attribute/handler modes and the instruction-count gate.
#
# Steps:
#   1. Build + install the default-profile SDK into an isolated prefix.
#   2. Compile tools/phase0/phase0_throughput.c against it.
#   3. Run every mode (PHASE0_MODE=bare|attrs8|all, plus a PHASE0_ATTRS
#      custom list) over three vendored CI pcaps and check: exit status, the
#      8-column output (ns_per_pkt last, consistent with pps), the
#      `mode<TAB><mode><TAB><attributes>` stderr line (0, 8, and every
#      protocol attribute for fetch-all), one rss line per iteration in the
#      attribute modes and no RSS growth across iterations; an unknown mode
#      and PHASE0_MODE together with PHASE0_ATTRS must be refused.
#   4. Run the instruction gate's comparator self-test
#      (tools/phase0/ci/check_instructions.sh --self-test), and — when valgrind
#      and <valgrind/callgrind.h> are installed — check that the callgrind
#      bracket counts a non-zero, repeatable replay and that fetch-all costs
#      more instructions than bare (skipped with a note otherwise).
#
# Usage:
#   tools/phase0/tests/run_throughput_attrs_test.sh
#   MMT_SDK_PREBUILT=1 MMT_THRUATTRS_PREFIX=<prefix> ... — reuse an existing build
set -euo pipefail
export LC_ALL=C
export MMT_DETERMINISTIC_SEED=1

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHASE0_DIR="$(cd "${TEST_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PHASE0_DIR}/../.." && pwd)"
PCAP_DIR="${PHASE0_DIR}/ci/pcaps"
PREFIX="${MMT_THRUATTRS_PREFIX:-$(mktemp -d "${TMPDIR:-/tmp}/thruattrs.XXXXXX")}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"; [ -n "${MMT_THRUATTRS_PREFIX:-}" ] || rm -rf "${PREFIX}"' EXIT

ITER=3
PCAPS=(ftp_multiple_session.pcap tcp_ecn_sample.pcap dns_query.pcap)
FAILS=0
fail() { echo "    ✗ $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "    ✓ $*"; }

if [ "${MMT_SDK_PREBUILT:-0}" = "1" ]; then
    echo "[1/4] reusing prebuilt SDK at ${PREFIX} (MMT_SDK_PREBUILT=1)"
    [ -f "${PREFIX}/dpi/include/mmt_core.h" ] || { echo "✗ no installed SDK under ${PREFIX}" >&2; exit 2; }
else
    echo "[1/4] building + installing the default SDK -> ${PREFIX}"
    make -C "${REPO_ROOT}/sdk" clean >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" -j"$(nproc)" >/dev/null
    make -C "${REPO_ROOT}/sdk" MMT_BASE="${PREFIX}" install >/dev/null
fi

echo "[2/4] compiling phase0_throughput"
BIN="${WORK}/phase0_throughput"
gcc -O2 -Wall -Wextra -Werror -o "${BIN}" "${PHASE0_DIR}/phase0_throughput.c" \
    -I "${PREFIX}/dpi/include" -L "${PREFIX}/dpi/lib" -lmmt_core -ldl -lpcap
export LD_LIBRARY_PATH="${PREFIX}/dpi/lib:${LD_LIBRARY_PATH:-}"

# run_driver <VAR=value...> <command...>: runs it under env from the
# neutral WORK dir, stdout -> WORK/out, stderr -> WORK/err; returns its rc.
run_driver() {
    local rc
    set +e
    ( cd "${WORK}" && env "$@" >"${WORK}/out" 2>"${WORK}/err" )
    rc=$?
    set -e
    return "${rc}"
}

# check_run <label> <mode> <expected attrs: number or ">=N"> <pcap> <want_rss>
check_run() {
    local label="$1" want_mode="$2" want_attrs="$3" rel="$4" want_rss="$5"
    local line nf mode_line got_mode got_attrs pps ns
    line="$(cat "${WORK}/out")"
    nf="$(awk -F'\t' '{ print NF }' "${WORK}/out")"
    if [ "$(wc -l < "${WORK}/out")" -ne 1 ] || [ "${nf}" != 8 ]; then
        fail "${label} ${rel}: expected one 8-column line, got '${line}'"; return
    fi
    if ! awk -F'\t' '{ for (i = 1; i <= 8; i++) if ($i !~ /^-?[0-9]+(\.[0-9]+)?$/) exit 1 }' "${WORK}/out"; then
        fail "${label} ${rel}: non-numeric column in '${line}'"; return
    fi
    pps="$(cut -f4 "${WORK}/out")"; ns="$(cut -f8 "${WORK}/out")"
    if ! awk -v p="${pps}" -v n="${ns}" 'BEGIN { if (p <= 0) exit 0; e = 1e9 / p; d = (n - e) / e; exit (d < -0.01 || d > 0.01) }'; then
        fail "${label} ${rel}: ns_per_pkt ${ns} is not 1e9/pps (pps ${pps})"; return
    fi
    mode_line="$(grep -m1 '^mode' "${WORK}/err" || true)"
    got_mode="$(printf '%s' "${mode_line}" | cut -f2)"
    got_attrs="$(printf '%s' "${mode_line}" | cut -f3)"
    if [ "${got_mode}" != "${want_mode}" ]; then
        fail "${label} ${rel}: stderr mode line '${mode_line}', expected mode ${want_mode}"; return
    fi
    case "${want_attrs}" in
        '>='*) [ "${got_attrs:-0}" -ge "${want_attrs#>=}" ] \
                 || { fail "${label} ${rel}: ${got_attrs} attributes registered, expected ${want_attrs}"; return; } ;;
        *)     [ "${got_attrs}" = "${want_attrs}" ] \
                 || { fail "${label} ${rel}: ${got_attrs} attributes registered, expected ${want_attrs}"; return; } ;;
    esac
    local nrss first last
    nrss="$(grep -c '^rss' "${WORK}/err" || true)"
    if [ "${want_rss}" = 1 ]; then
        [ "${nrss}" -eq "${ITER}" ] \
            || { fail "${label} ${rel}: ${nrss} rss lines for ${ITER} iterations"; return; }
        first="$(grep '^rss' "${WORK}/err" | head -n 1 | cut -f3)"
        last="$(grep '^rss' "${WORK}/err" | tail -n 1 | cut -f3)"
        # Flat: the extractors release what they allocate (issue #506);
        # 256 KiB absorbs allocator noise.
        if [ "${first}" -ge 0 ] && [ $((last - first)) -gt 256 ]; then
            fail "${label} ${rel}: library RSS grew ${first} -> ${last} KiB over ${ITER} iterations"; return
        fi
    else
        [ "${nrss}" -eq 0 ] || { fail "${label} ${rel}: unexpected rss lines in bare mode"; return; }
    fi
    ok "${label} ${rel}: ${got_attrs} attribute(s), $(cut -f8 "${WORK}/out") ns/pkt"
}

echo "[3/4] running the modes over ${PCAPS[*]}"
for rel in "${PCAPS[@]}"; do
    pcap="${PCAP_DIR}/${rel}"
    [ -f "${pcap}" ] || { fail "missing vendored pcap ${pcap}"; continue; }
    packets=""
    for spec in "bare|bare|0|0|PHASE0_MODE=bare" \
                "default|bare|0|0|PHASE0_MODE=" \
                "attrs8|attrs8|8|1|PHASE0_MODE=attrs8" \
                "all|all|>=1000|1|PHASE0_MODE=all" \
                "custom|custom|2|1|PHASE0_ATTRS=dns.queries,ftp.packet_request"; do
        IFS='|' read -r label want_mode want_attrs want_rss envset <<< "${spec}"
        if ! run_driver PHASE0_MODE= PHASE0_ATTRS= "${envset}" "${BIN}" "${pcap}" "${ITER}"; then
            fail "${label} ${rel}: driver exited non-zero: $(tail -n 2 "${WORK}/err" | tr '\n' ' ')"
            continue
        fi
        check_run "${label}" "${want_mode}" "${want_attrs}" "${rel}" "${want_rss}"
        pk="$(cut -f1 "${WORK}/out")"
        if [ -z "${packets}" ]; then packets="${pk}"
        elif [ "${pk}" != "${packets}" ]; then fail "${label} ${rel}: ${pk} packets, other modes ${packets}"; fi
    done
done

pcap="${PCAP_DIR}/${PCAPS[0]}"
if run_driver PHASE0_MODE=bogus "${BIN}" "${pcap}" 1; then
    fail "an unknown PHASE0_MODE was accepted"
else
    ok "an unknown PHASE0_MODE is refused: $(head -n 1 "${WORK}/err")"
fi
if run_driver PHASE0_MODE=all PHASE0_ATTRS=dns.queries "${BIN}" "${pcap}" 1; then
    fail "PHASE0_MODE together with PHASE0_ATTRS was accepted"
else
    ok "PHASE0_MODE with PHASE0_ATTRS is refused: $(head -n 1 "${WORK}/err")"
fi

echo "[4/4] instruction-count gate"
if bash "${PHASE0_DIR}/ci/check_instructions.sh" --self-test | sed 's/^/    /'; then
    ok "comparator self-test"
else
    fail "check_instructions.sh --self-test"
fi
if command -v valgrind >/dev/null 2>&1 \
   && echo '#include <valgrind/callgrind.h>' | gcc -E -x c - >/dev/null 2>&1; then
    # callgrind_ir <mode>: the replay's instruction count over PCAPS[0].
    callgrind_ir() {
        run_driver PHASE0_MODE="$1" valgrind --tool=callgrind --collect-atstart=no \
            --callgrind-out-file=/dev/null "${BIN}" "${pcap}" 1 || return 1
        sed -n 's/^==[0-9]*== Collected : \([0-9]*\)$/\1/p' "${WORK}/err" | tail -n 1
    }
    b1="$(callgrind_ir bare || true)"; b2="$(callgrind_ir bare || true)"; a1="$(callgrind_ir all || true)"
    case "${b1}:${b2}:${a1}" in
        *[!0-9:]*|:*|*::*|*:) fail "callgrind gave no count (bare '${b1}' '${b2}', all '${a1}')" ;;
        *)
            if [ "${b1}" -eq 0 ]; then fail "callgrind counted 0 instructions: the driver lacks the bracket"
            elif [ "${b1}" != "${b2}" ]; then fail "bare count not repeatable: ${b1} vs ${b2}"
            elif [ "${a1}" -le "${b1}" ]; then fail "fetch-all (${a1} Ir) is not dearer than bare (${b1} Ir)"
            else ok "callgrind bracket: bare ${b1} Ir (repeatable), fetch-all ${a1} Ir on ${PCAPS[0]}"
            fi ;;
    esac
else
    echo "    ○ callgrind bracket check skipped: valgrind or <valgrind/callgrind.h> not installed"
fi

if [ "${FAILS}" -eq 0 ]; then
    echo "✓ throughput attribute modes (issue #555) test: PASS"
    exit 0
fi
echo "✗ throughput attribute modes (issue #555) test: FAIL (${FAILS} check(s))"
exit 1

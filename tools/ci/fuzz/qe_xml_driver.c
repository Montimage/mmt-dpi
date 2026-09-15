/*
 * qe_xml_driver — fuzz driver for the shipped fuzz engine (libmmt_fuzz),
 * issue #224 (F-SEC-009).
 *
 * The engine is only built with ENABLESEC=1 and, before this driver, was
 * only ever compiled — never run — in CI. The driver feeds one input file
 * to the engine's public XML entry point,
 * application_quality_estimation_xml_parser(), the same function the
 * rule-engine suite (tests/rule_engine/test_fuzz_engine.c) regression-tests.
 *
 * Built and run under BUILD=asan instrumentation by tools/ci/run-fuzz.sh:
 * a NULL return is a clean refusal (exit 0); any memory-safety fault or UB
 * aborts the process and is what the fuzz gate treats as a finding.
 *
 * Usage:
 *   qe_xml_driver <model.xml>
 */
#include <stdio.h>
#include <stdlib.h>

#include "fuzz/mmt_quality_estimation_defs.h"
#include "fuzz/mmt_quality_estimation_utilities.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <model.xml>\n", argv[0]);
        return 2;
    }
    /* Mutated XML is the hostile input: a NULL refusal is the expected
     * healthy outcome for malformed models; a crash is the fuzz finding. */
    (void) application_quality_estimation_xml_parser(argv[1]);
    return 0;
}

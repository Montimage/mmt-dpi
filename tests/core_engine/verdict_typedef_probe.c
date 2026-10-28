/*
 * verdict_typedef_probe.c — compile-only probe of the classifier typedef
 * (issue #546). run_tests.sh compiles it with -Werror as C (gnu17) and as
 * C++ (-x c++), through the public headers alone.
 *
 * C:   generic_classification_function returns mmt_classify_verdict_t, and a
 *      classifier written before that — returning int — still converts
 *      without a cast or an -Wincompatible-pointer-types diagnostic
 *      (MMT_CLASSIFY_VERDICT_INT_ANCHOR_ makes the enum int-compatible).
 * C++: the typedef keeps its int view, so existing C++ plugins that register
 *      int-returning classifiers keep compiling.
 */
#include "mmt_core.h"

static int legacy_classifier(ipacket_t *ipacket, unsigned index) {
    (void) ipacket;
    return index ? 1 : 0;
}

#ifndef __cplusplus
static mmt_classify_verdict_t typed_classifier(ipacket_t *ipacket, unsigned index) {
    (void) ipacket;
    return index ? MMT_CLASSIFY_MATCHED : MMT_CLASSIFY_SKIP;
}

/* Converting to the typedef is what a C plugin does; the textual return
 * type itself is asserted by tools/ci/check-typed-accessors.sh, since an
 * int-compatible enum and int cannot be told apart by _Generic. */
_Static_assert(sizeof(mmt_classify_verdict_t) == sizeof(int), "verdict stays int-sized");
#endif

int verdict_typedef_probe(protocol_t *proto);
int verdict_typedef_probe(protocol_t *proto) {
    generic_classification_function fns[] = {
        legacy_classifier,
#ifndef __cplusplus
        typed_classifier,
#endif
    };
    (void) fns;
    return register_classification_function(proto, legacy_classifier)
        && register_pre_post_classification_functions(proto, legacy_classifier, legacy_classifier);
}

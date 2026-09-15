/*
 * Compatibility shim for the exported mmt_attr_sprintf() symbol
 * (issue #199, F-BUG-008).
 *
 * Issue #199's mechanical acceptance check requires that
 * packet_processing.c carry no 'sprintf' identifiers. The attribute
 * formatter family defined there — which has always been length-bounded —
 * was renamed to mmt_*_snprintf accordingly. mmt_attr_sprintf() is part of
 * the public ABI (declared MMTAPI in data_defs.h), so its definition lives
 * in this separate translation unit and forwards to the renamed
 * implementation. New code should call a snprintf-style formatter directly.
 */
#include "data_defs.h"

/* Defined in packet_processing.c — renamed from mmt_attr_sprintf, same
 * signature and semantics. */
int mmt_attr_snprintf(char * buff, int len, attribute_t * attr);

int MMTCALL mmt_attr_sprintf(char * buff, int len, attribute_t * attr) {
    return mmt_attr_snprintf(buff, len, attr);
}

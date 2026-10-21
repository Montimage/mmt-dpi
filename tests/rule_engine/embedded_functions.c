/*
 * embedded_functions.c — the libembedded_functions.so the rule engine
 * dlopens for #function(...) calls (LIB_NAME, src/mmt_security/
 * tips_internal.h), built by run_tests.sh into a scratch directory that is
 * put on LD_LIBRARY_PATH (issue #511).
 *
 * Contract (tips_xml.c / tips_extract.c): every function takes its
 * parameters as void * — an attribute's extracted data, a tuple reference
 * or a numeric constant as text — and returns a malloc'd result the engine
 * frees; get_data_type_of_funct_return_value() names the result's MMT type
 * and size.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "types_defs.h"

int *get_data_type_of_funct_return_value(char *funct_name, int *size)
{
    int *type = malloc(sizeof *type);
    if (type == NULL) return NULL;
    *type = MMT_U16_DATA;
    *size = (int) sizeof(uint16_t);
    (void) funct_name;
    return type;
}

/* #echo_port(UDP.dest_port): the destination port, unchanged */
void *echo_port(void *port)
{
    uint16_t *out = malloc(sizeof *out);
    if (out == NULL) return NULL;
    *out = (port != NULL) ? *(uint16_t *) port : 0;
    return out;
}

/* #sum_ports(UDP.dest_port, a, b, c): the port plus three numeric
 * constants — the largest arity the engine accepts (four) */
void *sum_ports(void *port, void *a, void *b, void *c)
{
    uint16_t *out = malloc(sizeof *out);
    if (out == NULL) return NULL;
    *out = (uint16_t) (*(uint16_t *) port + atoi((char *) a) + atoi((char *) b) + atoi((char *) c));
    return out;
}

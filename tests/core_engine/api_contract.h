/*
 * api_contract.h — the public-API contract table (issue #525, F-TEST-011).
 *
 * One entry per MMTAPI function declared in the public headers under
 * src/mmt_core/public_include. tools/ci/check-api-contracts.sh compares
 * the entry names
 * (test_api_contracts --list) with the declared names
 * (tools/ci/check-public-decls.sh --list): a new export without an entry
 * fails the core_engine suite.
 *
 *   CONTRACT(fn, behave, err)
 *       behave() asserts a result of fn on valid input, err() feeds fn a
 *       real invalid input and asserts its documented failure result.
 *   NO_ERROR_PATH(fn, behave, "reason")
 *       fn has no invalid input it reports on (a pure accessor, a function
 *       with no parameters, a total function); the reason must be a
 *       non-empty string literal and the name must be listed in
 *       api-contract-waivers.txt.
 *
 * Both macros take the address of fn, so a misspelled or undeclared name
 * is a compile error, not a silently untested entry. Casting to
 * void (*)(void) is the one function-pointer conversion -Wcast-function-type
 * (enabled by -Wextra) exempts.
 */
#ifndef API_CONTRACT_H
#define API_CONTRACT_H

#include <stddef.h> /* NULL */

typedef void (*api_contract_symbol_t)(void);

typedef struct api_contract {
    const char *name;              /* the MMTAPI function under contract */
    api_contract_symbol_t symbol;  /* its address: proves the name is declared */
    void (*behave)(void);          /* behaviour assertion */
    void (*error_path)(void);      /* error-path assertion, NULL when waived */
    const char *waiver;            /* why there is no error path, NULL otherwise */
} api_contract_t;

#define CONTRACT(fn, behave, err) \
    { #fn, (api_contract_symbol_t) &fn, (behave), (err), NULL }

/* "" reason: only a string literal concatenates, so the reason cannot be a
 * variable or NULL; the runner rejects an empty one. */
#define NO_ERROR_PATH(fn, behave, reason) \
    { #fn, (api_contract_symbol_t) &fn, (behave), NULL, "" reason }

#endif /* API_CONTRACT_H */

/*
 * rb_result.h — machine-readable result lines for the resource_bounds
 * fixtures (issue #394, F-PERF-001..004).
 *
 * Every fixture reports the deterministic counts its budgets are checked
 * against as one line per value on stdout:
 *
 *   @rb <fixture> metric <key> <unsigned integer>
 *   @rb <fixture> seed   <key> 0x<16 hex digits>
 *
 * run_tests.sh strips these lines from the human log, assembles them into
 * results.json (schema: results.schema.json) and evaluates the budgets in
 * budgets.json against them. Only counts are reported — never timings.
 * Keys are dot-separated [a-z0-9_.-] words; the fixture id is the name
 * run_tests.sh selects it by.
 */
#ifndef RB_RESULT_H
#define RB_RESULT_H

#include <stdint.h>
#include <stdio.h>

static inline void rb_metric(const char *fixture, const char *key, uint64_t value)
{
	printf("@rb %s metric %s %llu\n", fixture, key, (unsigned long long) value);
	fflush(stdout);   /* keep the line whole next to unbuffered stderr */
}

static inline void rb_seed(const char *fixture, const char *key, uint64_t seed)
{
	printf("@rb %s seed %s 0x%016llx\n", fixture, key, (unsigned long long) seed);
	fflush(stdout);
}

#endif /* RB_RESULT_H */

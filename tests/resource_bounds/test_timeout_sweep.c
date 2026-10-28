/*
 * test_timeout_sweep.c — issue #500 (F-BUG-003): the out-of-memory forced
 * sweep (process_outofmemory_force_sessions_timeout) expires at most
 * MMT_OOM_SWEEP_BUDGET sessions per call. It used to stop mid-list at that
 * budget and then delete the whole milestone, so every session left on the
 * list was unlinked from the timeout ring without expiring — it never timed
 * out and its memory was never released.
 *
 * Workload: SESSIONS sessions share one milestone (one list longer than the
 * budget) and TAIL more sit on the next milestone. One forced sweep must
 * expire exactly the budget and leave every other session linked; the
 * regular expiry pass (timeout_expire_milestones_range, the path
 * process_timedout_sessions takes) must then expire every remaining one —
 * each session exactly once.
 *
 * Sessions are inserted in a fixed-seed shuffled order (splitmix64 +
 * Fisher-Yates), so which ones the budget stop leaves behind is not simply
 * the tail of the id range.
 *
 * The real packet_session.c / hash_utils.c run unmodified (linked from the
 * core sources by run_tests.sh); the handler is a zeroed struct carrying
 * only the timeout ring, the sessions a static array (no protocol context,
 * so cleanup releases nothing).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "packet_processing.h"
#include "rb_result.h"

#define RB        "timeout-sweep"
#define SESSIONS  70000u            /* one list longer than the budget */
#define TAIL      10u               /* on the following milestone */
#define NOW       1000u
#define MILESTONE (NOW + 30u)
#define ORDER_SEED 0x5eed0500c0ffee00ULL /* insertion-order shuffle */

static int failed;
#define CHECK(cond, msg) do { if (!(cond)) { \
        fprintf(stderr, "  FAIL: %s\n", (msg)); failed++; } } while (0)

static mmt_session_t sessions[SESSIONS + TAIL];
static unsigned char expiries[SESSIONS + TAIL];

static void on_expiry(const mmt_session_t *expired, void *args)
{
	(void) args;
	expiries[expired->session_id]++;
}

static uint64_t splitmix64(uint64_t *state)
{
	uint64_t z = (*state += 0x9e3779b97f4a7c15ULL);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

static uint32_t order[SESSIONS + TAIL];

static uint64_t list_length(mmt_handler_t *h, uint32_t milestone)
{
	uint64_t n = 0;
	for (mmt_session_t *s = get_timed_out_session_list(h, milestone); s != NULL; s = s->next)
		n++;
	return n;
}

static uint64_t count_expired(unsigned times)
{
	uint64_t n = 0;
	for (uint32_t i = 0; i < SESSIONS + TAIL; i++)
		if (expiries[i] == times) n++;
	return n;
}

int main(void)
{
	mmt_handler_t *h = (mmt_handler_t *) calloc(1, sizeof(*h));
	if (h == NULL) return 2;
	h->timeout_milestones_map = init_timeout_milestones_index();
	if (h->timeout_milestones_map == NULL) return 2;
	h->session_expiry_handler.handler_fct = on_expiry;
	h->last_expiry_timeout = NOW;

	printf("issue #500: a forced sweep stopping at its budget keeps the rest of the list\n");
	uint64_t rng = ORDER_SEED;
	for (uint32_t i = 0; i < SESSIONS + TAIL; i++)
		order[i] = i;
	for (uint32_t i = SESSIONS + TAIL - 1; i > 0; i--) {
		uint32_t j = (uint32_t) (splitmix64(&rng) % (i + 1));
		uint32_t t = order[i]; order[i] = order[j]; order[j] = t;
	}
	for (uint32_t k = 0; k < SESSIONS + TAIL; k++) {
		uint32_t i = order[k];
		mmt_session_t *s = &sessions[i];
		s->session_id = i;
		s->mmt_handler = h;
		s->session_timeout_milestone = i < SESSIONS ? MILESTONE : MILESTONE + 1;
		if (insert_session_timeout_milestone(h, s->session_timeout_milestone, s) != MMT_TIMEOUT_INSERTED) {
			fprintf(stderr, "  insert %u failed\n", i);
			return 2;
		}
	}
	h->active_sessions_count = SESSIONS + TAIL;

	process_outofmemory_force_sessions_timeout(h, NULL);
	uint64_t swept = count_expired(1);
	uint64_t left = list_length(h, MILESTONE);
	uint64_t tail_left = list_length(h, MILESTONE + 1);
	printf("  forced sweep expired %llu, left %llu linked on the long list, %llu on the next\n",
	       (unsigned long long) swept, (unsigned long long) left, (unsigned long long) tail_left);
	CHECK(swept == MMT_OOM_SWEEP_BUDGET, "the sweep expired exactly its budget");
	CHECK(left == SESSIONS - MMT_OOM_SWEEP_BUDGET, "the rest of the long list stays linked");
	CHECK(tail_left == TAIL, "the next milestone was not touched");

	/* The regular expiry pass: everything still linked expires once. */
	timeout_expire_milestones_range(h, NOW, MILESTONE + 2, force_sessions_timeout);
	uint64_t once = count_expired(1), twice_or_more = 0, never = count_expired(0);
	for (uint32_t i = 0; i < SESSIONS + TAIL; i++)
		if (expiries[i] > 1) twice_or_more++;
	CHECK(never == 0, "every remaining session expired");
	CHECK(twice_or_more == 0, "no session expired twice");
	CHECK(get_timed_out_session_list(h, MILESTONE) == NULL &&
	      get_timed_out_session_list(h, MILESTONE + 1) == NULL, "both milestones drained");
	CHECK(h->active_sessions_count == 0, "active count back to zero");

	rb_seed(RB, "insert_order.splitmix64", ORDER_SEED);
	rb_metric(RB, "sessions", SESSIONS + TAIL);
	rb_metric(RB, "sweep_budget", MMT_OOM_SWEEP_BUDGET);
	rb_metric(RB, "sweep.expired", swept);
	rb_metric(RB, "sweep.left_linked", left + tail_left);
	rb_metric(RB, "later.expired", once - swept);
	rb_metric(RB, "expired_once", once);
	rb_metric(RB, "expired_twice", twice_or_more);
	rb_metric(RB, "never_expired", never);
	rb_metric(RB, "checks.failed", (uint64_t) failed);

	clear_timeout_milestones(h);
	free(h);
	if (failed) {
		fprintf(stderr, "%d check(s) failed\n", failed);
		return 1;
	}
	printf("  all checks passed\n");
	return 0;
}

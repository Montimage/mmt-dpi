#include "hash_utils.h"
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/auxv.h>
#include <sys/random.h>
#include <time.h>

//////////////// Stores
//
// Issue #539 (F-CLEAN-017): this file was the SDK's only C++ translation
// unit, and its C++ use came down to two snapshot vectors, one sort and the
// ordered parked-milestone index — yet it forced a $(CXX) link, and so a
// libstdc++ dependency, on every library. It is plain C now: the snapshots
// are exact-size malloc arrays, the sort is qsort over the same
// (milestone, pointer) order std::sort produced, and the parked index is a
// sorted array. The extern-C/try-catch(...) wrappers of issue #200
// (F-BUG-003) have nothing left to catch: every allocation failure returns
// the failure value of its function's return type (NULL / 0 / nothing),
// exactly what the catch(...) arms returned. The three insert-failure
// diagnostics go through debug() (dbg.h) like the rest of the packet path
// (issue #246): they compile out of release builds instead of printing an
// unconditional stdout line per failed insert. A NULL table pointer is still
// treated as a failure: callers that ignore an init_*_map_space() failure
// get a safe no-op instead of a NULL dereference.
//
// Issue #254 (F-PERF-011/012/013): the red-black-tree stores are gone. All
// key/value stores below are open-addressing tables or the timeout ring —
// same pattern as the per-flow session store (issue #17).

// finalizer (fmix64 from MurmurHash3) — decorrelates the supplied hash from the
// power-of-two slot index so a weak low-bit distribution does not cluster.
static inline uint64_t mmt_mix64(uint64_t h) {
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

//////////////// Open-addressing table (void * keys) ////////////////
//
// Linear-probing table keyed on void * — the store that replaced the previous
// O(log n) red-black-tree session store (issue #17) and now also backs
// the generic map API (issue #254): the interned-IP registry (ips_map) was
// the remaining hot-path ordered tree — a tree descent costs ~15
// pointer-chasing node visits plus ~48 bytes of node overhead per distinct
// IP, versus ~2 cache-friendly probes here.
//
// Correctness vs. the old ordered map: equality is derived from the
// protocol's strict-weak-ordering comparison function exactly as the tree
// computed equivalence — two keys are the same entry iff neither compares
// less than the other — so classification is byte-for-byte unchanged. The
// hash function must be consistent with that equality (equal keys hash
// equally); a NULL hash degrades to a correct but slow constant hash rather
// than crashing.
//
// Issue #379 (F-PERF-001) — bounded collision work: every probe sequence is
// capped at cap slot visits. find/update/remove loop `n < t->cap` outright;
// insert additionally fails (returns 0) when a full scan finds no EMPTY
// terminator, which used < cap makes unreachable in correct operation — the
// bound is defense-in-depth against invariant corruption, not a semantic
// change. Adversarial inputs can therefore buy at most O(cap) comparator
// work per operation, never an unbounded scan; the per-table seed mixed
// into mmt_oa_hash_of (see mmt_oa_create) is the mitigation that keeps
// engineered collision clusters from being computed per handler in the
// first place.
//
// Slots are 16 bytes (two pointers) so four pack into a 64-byte cache line.
// Empty/tombstone states are encoded in the key pointer rather than a
// separate field: real keys are heap-allocated structures, so NULL and the
// 0x1 sentinel can never collide with a live key.
//
// Issue #562 (F-PERF-007): each live slot also carries a 16-bit tag — the top
// 16 bits of its key's hash — in an array that follows the slots in the same
// allocation (mmt_oa_tags()). A probe compares the tag first and calls the
// equality predicate only when it matches, so a probe passing a slot of
// another key no longer dereferences that key (a heap object, usually a
// cache miss): a mismatch reaches equal() once per 65,536 on average. The
// tag of an EMPTY or TOMB slot is never read.

#define MMT_SLOT_EMPTY ((void *) NULL)
#define MMT_SLOT_TOMB  ((void *) (uintptr_t) 1)

/* Issue #253 (F-PERF-008): debug-build tripwires for the per-packet session
 * lookup — mmt_oa_equal_calls counts probes resolved through the one-call
 * equality predicate, mmt_oa_comp_calls counts probes that fell back to the
 * two-invocation ordering comparator. Same arming contract as the classify
 * counters in packet_pipeline.c: assert-enabled or sanitizer builds only,
 * relaxed atomics, always-exported accessors so test harnesses link
 * regardless of profile. */
#if !defined(NDEBUG) || defined(MMT_BUILD_ASAN) || defined(MMT_BUILD_TSAN)
#define MMT_SESSION_LOOKUP_STATS 1
static uint64_t mmt_oa_equal_calls = 0;
static uint64_t mmt_oa_comp_calls  = 0;
#else
#define MMT_SESSION_LOOKUP_STATS 0
#endif

typedef struct mmt_oa_slot {
    void * key;
    void * value;
} mmt_oa_slot;

typedef struct mmt_oa_table {
    mmt_oa_slot *          slots;
    size_t                 cap;        // power of two
    size_t                 size;       // live (occupied) slots
    size_t                 used;       // occupied + tombstones (drives resize)
    generic_comparison_fct comp;
    generic_hash_fct       hash;
    generic_equal_fct      equal;      // issue #253 (F-PERF-008)
    uint64_t               seed;       // issue #379 (F-PERF-001): per-table hash key
} mmt_oa_table;

static inline uint64_t mmt_oa_hash_of(const mmt_oa_table * t, void * k) {
    // The mixer is a static-inline fmix64 — it compiles into the call
    // site (no function call, ~3 serially-dependent multiply steps on
    // top of the key hash itself). The per-table seed keys the result:
    // two tables built on the same hash function still bucket keys
    // differently, so a collision cluster engineered for one handler's
    // map does not transfer to another's (issue #379).
    return mmt_mix64((t->hash ? t->hash(k) : 0) ^ t->seed);
}

// Issue #253 (F-PERF-008): a registered equality predicate resolves a
// probe in ONE call. The fallback keeps the old map equivalence under a
// strict weak ordering — two keys are the same entry iff neither orders
// before the other — which costs two comparator invocations.
static inline bool mmt_oa_key_equal(const mmt_oa_table * t, void * a, void * b) {
    if (t->equal != NULL) {
#if MMT_SESSION_LOOKUP_STATS
        __atomic_add_fetch(&mmt_oa_equal_calls, 1, __ATOMIC_RELAXED);
#endif
        return t->equal(a, b);
    }
#if MMT_SESSION_LOOKUP_STATS
    __atomic_add_fetch(&mmt_oa_comp_calls, 1, __ATOMIC_RELAXED);
#endif
    return !t->comp(a, b) && !t->comp(b, a);
}

#define MMT_OA_INITIAL_CAP ((size_t) 16) // power of two

// Issue #562: one slot array allocation holds cap slots, then cap tags.
#define MMT_OA_SLOT_BYTES (sizeof(mmt_oa_slot) + sizeof(uint16_t))

static inline uint16_t * mmt_oa_tags(const mmt_oa_table * t) {
    return (uint16_t *) (t->slots + t->cap);
}

static inline uint16_t mmt_oa_tag_of(uint64_t h) {
    return (uint16_t) (h >> 48); // the index uses the low bits
}

static void mmt_oa_alloc_slots(mmt_oa_table * t, size_t cap) {
    t->slots = (mmt_oa_slot *) calloc(cap, MMT_OA_SLOT_BYTES);
    if (t->slots == NULL) { t->cap = 0; return; }
    t->cap   = cap;
    // calloc zero-fills -> every slot's key is NULL (MMT_SLOT_EMPTY).
}

// Insert a known-unique key into a tombstone-free table (used during resize).
static void mmt_oa_put_raw(mmt_oa_table * t, void * key, void * value) {
    size_t mask = t->cap - 1;
    uint64_t h = mmt_oa_hash_of(t, key);
    size_t i = (size_t) h & mask;
    while (t->slots[i].key != MMT_SLOT_EMPTY) {
        i = (i + 1) & mask;
    }
    t->slots[i].key   = key;
    t->slots[i].value = value;
    mmt_oa_tags(t)[i] = mmt_oa_tag_of(h);
}

static void mmt_oa_resize(mmt_oa_table * t, size_t new_cap) {
    mmt_oa_slot * old = t->slots;
    size_t old_cap = t->cap;
    mmt_oa_alloc_slots(t, new_cap);
    if (t->slots == NULL) {
        // Issue #200: allocation failed — keep the old table so the store
        // stays usable instead of probing a NULL slot array.
        t->slots = old;
        t->cap   = old_cap;
        return;
    }
    t->used = t->size; // tombstones dropped on rehash
    for (size_t i = 0; i < old_cap; i++) {
        void * k = old[i].key;
        if (k != MMT_SLOT_EMPTY && k != MMT_SLOT_TOMB) {
            mmt_oa_put_raw(t, k, old[i].value);
        }
    }
    free(old);
}

// Issue #254 (F-PERF-011): the table previously grew but never shrank, so a
// burst to N entries pinned ~2*16*N bytes of slot memory forever (and the
// tombstones left behind lengthened every probe sequence). Removing an entry
// now shrinks once occupancy falls below 1/4 of capacity — halving keeps the
// post-shrink load <= 1/2, comfortably under the 0.7 grow watermark, and the
// rehash drops the tombstones for free.
static inline void mmt_oa_maybe_shrink(mmt_oa_table * t) {
    if (t->cap > MMT_OA_INITIAL_CAP && t->size * 4 <= t->cap) {
        mmt_oa_resize(t, t->cap >> 1);
    }
}

// Issue #254 (F-PERF-011): clear used to memset the slots while keeping peak
// capacity, so a burst stayed resident forever. Reset now drops the slot
// array back to the initial capacity — a large table is an mmap'd block, so
// freeing it returns the memory to the OS instead of the allocator's cache.
static void mmt_oa_reset(mmt_oa_table * t) {
    mmt_oa_slot * fresh = (mmt_oa_slot *) calloc(MMT_OA_INITIAL_CAP, MMT_OA_SLOT_BYTES);
    if (fresh == NULL) {
        // OOM: fall back to the old behaviour — wipe the slots in place; the
        // table stays usable, only the memory release is skipped.
        memset(t->slots, 0, t->cap * MMT_OA_SLOT_BYTES);
    } else {
        free(t->slots);
        t->slots = fresh;
        t->cap   = MMT_OA_INITIAL_CAP;
    }
    t->size = 0;
    t->used = 0;
}

/* Issue #379 (F-PERF-001): per-table seed supply. Every created table draws
 * the next step of a process-local counter decorrelated through fmix64, so
 * two maps are keyed independently — a forced-collision key set computed
 * for one handler's table does not transfer to another's. The bound that
 * actually caps adversarial work is the per-operation probe ceiling
 * documented at mmt_oa_insert — the seed is the mitigation, the bound is the
 * guarantee.
 *
 * Issue #551 (F-BUG-011): the counter used to start at a fixed constant, so
 * every process derived the same, predictable seeds. Its start is now drawn
 * once per process, on the first table creation, from getrandom(); a
 * process without entropy (GRND_NONBLOCK fails early at boot) falls back to
 * a clock/pid/address mix. MMT_DETERMINISTIC_SEED=1 (any non-empty value but
 * "0") keeps the legacy constant, so the per-table sequence is exactly the
 * pre-#551 one: the golden classification gate, the precision gate and the
 * fixed-seed resource budgets set it. A set-uid/set-gid process (AT_SECURE)
 * ignores the variable — the environment of such a process is untrusted. */
#define MMT_OA_SEED_LEGACY 0x243F6A8885A308D3ULL
#define MMT_OA_SEED_STEP   0x9E3779B97F4A7C15ULL
static uint64_t mmt_oa_seed_supply = MMT_OA_SEED_LEGACY;
static pthread_once_t mmt_oa_seed_once = PTHREAD_ONCE_INIT;

static bool mmt_oa_seed_deterministic(void) {
    const char * v = getenv("MMT_DETERMINISTIC_SEED");
    if (v == NULL || v[0] == '\0' || strcmp(v, "0") == 0) return false;
    return getauxval(AT_SECURE) == 0;
}

static void mmt_oa_seed_init(void) {
    uint64_t base = MMT_OA_SEED_LEGACY;
    if (!mmt_oa_seed_deterministic() &&
            getrandom(&base, sizeof base, GRND_NONBLOCK) != (ssize_t) sizeof base) {
        uintptr_t aslr = (uintptr_t) &base;
        base = mmt_mix64((uint64_t) time(NULL) ^ ((uint64_t) getpid() << 32)
                         ^ (uint64_t) aslr ^ (uint64_t) clock());
    }
    __atomic_store_n(&mmt_oa_seed_supply, base, __ATOMIC_RELAXED);
}

static uint64_t mmt_oa_next_seed(void) {
    (void) pthread_once(&mmt_oa_seed_once, mmt_oa_seed_init);
    return mmt_mix64(__atomic_add_fetch(&mmt_oa_seed_supply, MMT_OA_SEED_STEP,
                                        __ATOMIC_RELAXED));
}

/* Issue #551: a table's seed, for the hashmap suite (test_session_table.c
 * links this file directly). Not MMTAPI: the core is built
 * -fvisibility=hidden, so libmmt_core does not export it. */
uint64_t mmt_oa_table_seed(const void * map) {
    return map != NULL ? ((const mmt_oa_table *) map)->seed : 0;
}

static void * mmt_oa_create(generic_comparison_fct comp_fct, generic_hash_fct hash_fct, generic_equal_fct equal_fct) {
    mmt_oa_table * t = (mmt_oa_table *) malloc(sizeof(mmt_oa_table));
    if (t == NULL) return NULL;
    t->size = 0;
    t->used = 0;
    t->comp = comp_fct;
    t->hash = hash_fct;
    t->equal = equal_fct;
    t->seed = mmt_oa_next_seed();
    mmt_oa_alloc_slots(t, MMT_OA_INITIAL_CAP);
    if (t->slots == NULL) { free(t); return NULL; }
    return t;
}

static void mmt_oa_destroy(mmt_oa_table * t) {
    if (t == NULL) return;
    free(t->slots);
    free(t);
}

// Insert only when absent (the old map's insert contract): 1 on success,
// 0 on a duplicate key or a failed resize.
static int mmt_oa_insert(mmt_oa_table * t, void * key, void * value) {
    if (t == NULL || t->slots == NULL || t->cap == 0) return 0;

    // Keep the load factor <= 0.7. Grow only when the live population is dense.
    // If the slots are mostly tombstones (delete-heavy churn from session
    // timeouts) rehash in place at the same capacity to reclaim them.
    if ((t->used + 1) * 10 >= t->cap * 7) {
        size_t new_cap = (t->size * 2 >= t->cap) ? (t->cap << 1) : t->cap;
        mmt_oa_resize(t, new_cap);
        // Issue #200: the probe loop below only terminates on an EMPTY slot;
        // when the resize could not allocate (or was not enough) and no
        // EMPTY remains, fail instead of scanning the array forever.
        if (t->used >= t->cap) return 0;
    }

    size_t mask = t->cap - 1;
    uint64_t h = mmt_oa_hash_of(t, key);
    size_t i = (size_t) h & mask;
    uint16_t * tags = mmt_oa_tags(t);
    const uint16_t tag = mmt_oa_tag_of(h);
    size_t tomb = 0;
    bool have_tomb = false;
    bool found_empty = false;
    void * k = NULL;
    /* Issue #379 (F-PERF-001): the probe is now explicitly bounded by cap,
     * matching find/update/remove. used < cap normally guarantees an EMPTY
     * terminator exists; if that invariant is ever violated (a table with
     * no EMPTY slot at all) the scan stops after cap steps and the insert
     * fails instead of wrapping the ring forever — the finite per-operation
     * bound the collision-work budget is built on. */
    for (size_t n = 0; n < t->cap; n++) {
        k = t->slots[i].key;
        if (k == MMT_SLOT_EMPTY) { found_empty = true; break; }
        if (k == MMT_SLOT_TOMB) {
            if (!have_tomb) { tomb = i; have_tomb = true; }
        } else if (tags[i] == tag && mmt_oa_key_equal(t, k, key)) {
            return 0; // duplicate: mirror the old map (no overwrite)
        }
        i = (i + 1) & mask;
    }
    if (!found_empty) return 0;
    size_t dst = have_tomb ? tomb : i;
    if (t->slots[dst].key == MMT_SLOT_EMPTY) {
        t->used++; // reusing a tombstone does not change the load count
    }
    t->slots[dst].key   = key;
    t->slots[dst].value = value;
    tags[dst] = tag;
    t->size++;
    return 1;
}

static void * mmt_oa_find(mmt_oa_table * t, void * key) {
    if (t == NULL || t->slots == NULL || t->cap == 0) return NULL;
    size_t mask = t->cap - 1;
    uint64_t h = mmt_oa_hash_of(t, key);
    size_t i = (size_t) h & mask;
    const uint16_t * tags = mmt_oa_tags(t);
    const uint16_t tag = mmt_oa_tag_of(h);
    void * k;
    for (size_t n = 0; n < t->cap; n++) {
        k = t->slots[i].key;
        if (k == MMT_SLOT_EMPTY) break;
        if (k != MMT_SLOT_TOMB && tags[i] == tag && mmt_oa_key_equal(t, k, key)) {
            return t->slots[i].value;
        }
        i = (i + 1) & mask;
    }
    return NULL;
}

// Remove `key` if present, then apply the F-PERF-011 shrink. Mirrors the old
// erase-or-ignore contract: the call always "succeeds".
static void mmt_oa_remove(mmt_oa_table * t, void * key) {
    if (t == NULL || t->slots == NULL || t->cap == 0) return;
    size_t mask = t->cap - 1;
    uint64_t h = mmt_oa_hash_of(t, key);
    size_t i = (size_t) h & mask;
    const uint16_t * tags = mmt_oa_tags(t);
    const uint16_t tag = mmt_oa_tag_of(h);
    void * k;
    // Bounded probe: a table whose slots are all TOMB/non-empty must not
    // loop forever looking for an EMPTY terminator.
    for (size_t n = 0; n < t->cap; n++) {
        k = t->slots[i].key;
        if (k == MMT_SLOT_EMPTY) break;
        if (k != MMT_SLOT_TOMB && tags[i] == tag && mmt_oa_key_equal(t, k, key)) {
            // Tombstone the slot: a probe sequence may run through it, so it
            // cannot be reset to EMPTY (that would truncate later lookups).
            t->slots[i].key   = MMT_SLOT_TOMB;
            t->slots[i].value = NULL;
            t->size--;
            mmt_oa_maybe_shrink(t);
            return;
        }
        i = (i + 1) & mask;
    }
}

// Issue #200 (F-BUG-004) snapshot of the live entries of `t`, taken before a
// dispatch loop so the callbacks may mutate the table. Returns the entry
// count; *out is NULL when there is nothing to dispatch or the snapshot
// could not be allocated (the caller then dispatches nothing — the failure
// path of the old vector snapshot).
static size_t mmt_oa_snapshot(const mmt_oa_table * t, mmt_oa_slot ** out) {
    size_t n = 0, live = 0;
    *out = NULL;
    for (size_t i = 0; i < t->cap; i++) {
        void * k = t->slots[i].key;
        if (k != MMT_SLOT_EMPTY && k != MMT_SLOT_TOMB) live++;
    }
    if (live == 0) return 0;
    mmt_oa_slot * entries = (mmt_oa_slot *) malloc(live * sizeof(mmt_oa_slot));
    if (entries == NULL) return 0;
    for (size_t i = 0; i < t->cap; i++) {
        void * k = t->slots[i].key;
        if (k != MMT_SLOT_EMPTY && k != MMT_SLOT_TOMB) {
            entries[n++] = t->slots[i];
        }
    }
    *out = entries;
    return n;
}

//////////////// Open-addressing table (uint32_t keys) ////////////////
//
// Same layout policy for the int-keyed maps (per-protocol attribute
// registries, encapsulated-proto stats, the protocol-stack index). All the
// registered comparators are a plain `a < b`, so map-equivalence coincides
// with `==` and hashing the raw key through mmt_mix64 is consistent.
//
// The EMPTY/LIVE/TOMB states live in a per-slot byte rather than a key
// sentinel: uint32 keys span the whole 32-bit range, so no magic value is
// safe to reserve.

enum mmt_int_state { MMT_INT_EMPTY = 0, MMT_INT_LIVE = 1, MMT_INT_TOMB = 2 };

typedef struct mmt_int_slot {
    uint32_t key;
    void *   value;
    uint8_t  state; // mmt_int_state
} mmt_int_slot;

typedef struct mmt_int_map {
    mmt_int_slot *              slots;
    size_t                      cap;
    size_t                      size;
    size_t                      used;
    generic_int_comparison_fct  comp;
} mmt_int_map;

static inline bool mmt_int_key_equal(const mmt_int_map * m, uint32_t a, uint32_t b) {
    return !m->comp(a, b) && !m->comp(b, a);
}

static void mmt_int_alloc_slots(mmt_int_map * m, size_t cap) {
    m->slots = (mmt_int_slot *) calloc(cap, sizeof(mmt_int_slot));
    if (m->slots == NULL) { m->cap = 0; return; }
    m->cap = cap; // calloc -> every state is MMT_INT_EMPTY
}

static void mmt_int_put_raw(mmt_int_map * m, uint32_t key, void * value) {
    size_t mask = m->cap - 1;
    size_t i = (size_t) mmt_mix64(key) & mask;
    // rehash target is tombstone-free; only EMPTY terminates the probe
    while (m->slots[i].state != MMT_INT_EMPTY) {
        i = (i + 1) & mask;
    }
    m->slots[i].key   = key;
    m->slots[i].value = value;
    m->slots[i].state = MMT_INT_LIVE;
}

static void mmt_int_resize(mmt_int_map * m, size_t new_cap) {
    mmt_int_slot * old = m->slots;
    size_t old_cap = m->cap;
    mmt_int_alloc_slots(m, new_cap);
    if (m->slots == NULL) {
        m->slots = old;
        m->cap   = old_cap;
        return;
    }
    m->used = m->size;
    for (size_t i = 0; i < old_cap; i++) {
        if (old[i].state == MMT_INT_LIVE) {
            mmt_int_put_raw(m, old[i].key, old[i].value);
        }
    }
    free(old);
}

static inline void mmt_int_maybe_shrink(mmt_int_map * m) {
    if (m->cap > MMT_OA_INITIAL_CAP && m->size * 4 <= m->cap) {
        mmt_int_resize(m, m->cap >> 1);
    }
}

static void mmt_int_reset(mmt_int_map * m) {
    mmt_int_slot * fresh = (mmt_int_slot *) calloc(MMT_OA_INITIAL_CAP, sizeof(mmt_int_slot));
    if (fresh == NULL) {
        memset(m->slots, 0, m->cap * sizeof(mmt_int_slot));
    } else {
        free(m->slots);
        m->slots = fresh;
        m->cap   = MMT_OA_INITIAL_CAP;
    }
    m->size = 0;
    m->used = 0;
}

static int mmt_int_insert(mmt_int_map * m, uint32_t key, void * value) {
    if (m == NULL || m->slots == NULL || m->cap == 0) return 0;
    if ((m->used + 1) * 10 >= m->cap * 7) {
        size_t new_cap = (m->size * 2 >= m->cap) ? (m->cap << 1) : m->cap;
        mmt_int_resize(m, new_cap);
        if (m->used >= m->cap) return 0;
    }
    size_t mask = m->cap - 1;
    size_t i = (size_t) mmt_mix64(key) & mask;
    size_t tomb = 0;
    bool have_tomb = false;
    while (m->slots[i].state != MMT_INT_EMPTY) {
        if (m->slots[i].state == MMT_INT_TOMB) {
            if (!have_tomb) { tomb = i; have_tomb = true; }
        } else if (mmt_int_key_equal(m, m->slots[i].key, key)) {
            return 0; // duplicate: mirror the old map (no overwrite)
        }
        i = (i + 1) & mask;
    }
    size_t dst = have_tomb ? tomb : i;
    if (m->slots[dst].state == MMT_INT_EMPTY) {
        m->used++;
    }
    m->slots[dst].key   = key;
    m->slots[dst].value = value;
    m->slots[dst].state = MMT_INT_LIVE;
    m->size++;
    return 1;
}

static void * mmt_int_find(mmt_int_map * m, uint32_t key) {
    if (m == NULL || m->slots == NULL || m->cap == 0) return NULL;
    size_t mask = m->cap - 1;
    size_t i = (size_t) mmt_mix64(key) & mask;
    for (size_t n = 0; n < m->cap; n++) {
        if (m->slots[i].state == MMT_INT_EMPTY) break;
        if (m->slots[i].state == MMT_INT_LIVE && mmt_int_key_equal(m, m->slots[i].key, key)) {
            return m->slots[i].value;
        }
        i = (i + 1) & mask;
    }
    return NULL;
}

static void mmt_int_remove(mmt_int_map * m, uint32_t key) {
    if (m == NULL || m->slots == NULL || m->cap == 0) return;
    size_t mask = m->cap - 1;
    size_t i = (size_t) mmt_mix64(key) & mask;
    for (size_t n = 0; n < m->cap; n++) {
        if (m->slots[i].state == MMT_INT_EMPTY) break;
        if (m->slots[i].state == MMT_INT_LIVE && mmt_int_key_equal(m, m->slots[i].key, key)) {
            m->slots[i].state = MMT_INT_TOMB;
            m->slots[i].value = NULL;
            m->size--;
            mmt_int_maybe_shrink(m);
            return;
        }
        i = (i + 1) & mask;
    }
}

//////////////// Session-timeout ring (issue #254, F-PERF-013) ////////
//
// The timeout index used to be a red-black tree keyed on the absolute expiry
// second, so every session-timeout advance paid up to three tree descents
// plus a node allocation pair — ~300k tree operations and ~100k allocator
// round-trips per second at 100k sessions, for a key space bounded by the
// timeout delay. It is now a timing wheel: slot = milestone & (cap - 1).
//
// Invariant: a non-empty slot is owned by exactly one live milestone
// (slot->milestone) and its intrusive next/previous list holds only that
// milestone's sessions — so get_timed_out_session_list() keeps its exact
// "sessions expiring at this second" contract. Live milestones span at most
// the largest timeout delay in use; a slot collision (occupied by a
// different milestone) therefore means the span outgrew cap, and the ring
// doubles until cap exceeds the span — which provably separates every live
// milestone (two distinct milestones < cap apart cannot be congruent mod
// cap). Insert/update/delete on the hot path are O(1) and perform zero
// allocations; growth is the rare exception and its allocation failure
// degrades to the same 0 return the old map's bad_alloc path produced.
//
// Issue #500 (F-BUG-002): a span the ring cannot reach (> MMT_RING_MAX_CAP,
// e.g. a pcap timestamp stepping back or forward by more than ~48 days, or
// a timeout delay that large) is not an allocation failure. Such an outlier
// milestone is parked in an ordered side index instead — a sorted array
// searched in O(log n), allocating only on that cold path — and insert
// returns MMT_TIMEOUT_PARKED, so callers no longer mistake it for OOM and
// force-expire live sessions. A milestone lives either in a ring slot or in
// the parked index, never in both; every lookup, unlink, expiry and
// iteration below consults both.

typedef struct mmt_timeout_slot {
    mmt_session_t * head;      // session list of the owning milestone
    uint32_t        milestone; // owning milestone (valid while head != NULL)
} mmt_timeout_slot;

// Issue #500 parked index entry; the index is kept sorted by milestone
// (issue #539: a sorted array replaced the std::map it used to be).
typedef struct mmt_parked_entry {
    uint32_t        milestone;
    mmt_session_t * head;      // list head of that milestone
} mmt_parked_entry;

typedef struct mmt_timeout_ring {
    mmt_timeout_slot * slots;
    size_t             cap;        // power of two
    size_t             milestones; // live (owned) slots
    mmt_parked_entry * parked;     // issue #500: out-of-span milestones, sorted (NULL until first used)
    size_t             parked_n;   // live parked entries
    size_t             parked_cap; // allocated parked entries
} mmt_timeout_ring;

#define MMT_RING_INITIAL_CAP ((size_t) 1024)     // ~17 min of distinct seconds
#define MMT_RING_MAX_CAP     ((size_t) 1 << 22)  // ~48 days of spread — beyond that, park
#define MMT_PARKED_INITIAL_CAP ((size_t) 4)

// mmt_ring_grow() results (issue #500): the span overflow is distinct from OOM.
enum { MMT_RING_GROW_NOMEM = 0, MMT_RING_GROW_OK = 1, MMT_RING_GROW_SPAN = 2 };

// Grow the ring until no two live milestones share a slot. A collision-free
// capacity is the first power of two strictly greater than the live span
// (max - min milestone), so a single relink is always enough.
static int mmt_ring_grow(mmt_timeout_ring * r, uint32_t new_key) {
    uint32_t lo = new_key, hi = new_key;
    for (size_t i = 0; i < r->cap; i++) {
        if (r->slots[i].head != NULL) {
            if (r->slots[i].milestone < lo) lo = r->slots[i].milestone;
            if (r->slots[i].milestone > hi) hi = r->slots[i].milestone;
        }
    }
    uint64_t span = (uint64_t) hi - (uint64_t) lo;
    size_t new_cap = r->cap;
    while (new_cap <= span) {
        if (new_cap >= MMT_RING_MAX_CAP) return MMT_RING_GROW_SPAN; // the caller parks new_key
        new_cap <<= 1;
    }
    mmt_timeout_slot * fresh = (mmt_timeout_slot *) calloc(new_cap, sizeof(mmt_timeout_slot));
    if (fresh == NULL) return MMT_RING_GROW_NOMEM;
    for (size_t i = 0; i < r->cap; i++) {
        if (r->slots[i].head != NULL) {
            // distinct target slot guaranteed: |a - b| <= span < new_cap
            size_t j = (size_t) r->slots[i].milestone & (new_cap - 1);
            fresh[j] = r->slots[i];
        }
    }
    free(r->slots);
    r->slots = fresh;
    r->cap   = new_cap;
    return MMT_RING_GROW_OK;
}

// Issue #500: index of the first parked entry whose milestone is >= key
// (std::map::lower_bound) — parked_n when there is none.
static size_t mmt_parked_lower_bound(const mmt_timeout_ring * r, uint32_t key) {
    size_t lo = 0, hi = r->parked_n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (r->parked[mid].milestone < key) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

// Issue #500: the parked list head of `milestone`, or NULL when it is not
// parked. The pointer is valid until the next parked insert or erase.
static mmt_session_t ** mmt_parked_head(mmt_timeout_ring * r, uint32_t milestone) {
    if (r->parked_n == 0) return NULL;
    size_t i = mmt_parked_lower_bound(r, milestone);
    if (i == r->parked_n || r->parked[i].milestone != milestone) return NULL;
    return &r->parked[i].head;
}

// Remove the parked entries [first, last).
static void mmt_parked_erase_range(mmt_timeout_ring * r, size_t first, size_t last) {
    if (first >= last) return;
    memmove(&r->parked[first], &r->parked[last],
            (r->parked_n - last) * sizeof(mmt_parked_entry));
    r->parked_n -= last - first;
}

// Remove `milestone` from the parked index if present.
static void mmt_parked_erase(mmt_timeout_ring * r, uint32_t milestone) {
    if (r->parked_n == 0) return;
    size_t i = mmt_parked_lower_bound(r, milestone);
    if (i < r->parked_n && r->parked[i].milestone == milestone) {
        mmt_parked_erase_range(r, i, i + 1);
    }
}

// Make room for one more parked entry. Grows by malloc + copy (not realloc)
// so an allocation failure leaves the index untouched. 1 on success, 0 on OOM.
static int mmt_parked_reserve_one(mmt_timeout_ring * r) {
    if (r->parked_n < r->parked_cap) return 1;
    size_t new_cap = r->parked_cap ? r->parked_cap * 2 : MMT_PARKED_INITIAL_CAP;
    mmt_parked_entry * fresh = (mmt_parked_entry *) malloc(new_cap * sizeof(mmt_parked_entry));
    if (fresh == NULL) return 0;
    if (r->parked_n > 0) memcpy(fresh, r->parked, r->parked_n * sizeof(mmt_parked_entry));
    free(r->parked);
    r->parked     = fresh;
    r->parked_cap = new_cap;
    return 1;
}

// Insert a milestone known to be absent from the parked index, at its
// sorted position. Room must have been reserved (mmt_parked_reserve_one).
static void mmt_parked_insert(mmt_timeout_ring * r, uint32_t milestone, mmt_session_t * head) {
    size_t i = mmt_parked_lower_bound(r, milestone);
    memmove(&r->parked[i + 1], &r->parked[i],
            (r->parked_n - i) * sizeof(mmt_parked_entry));
    r->parked[i].milestone = milestone;
    r->parked[i].head      = head;
    r->parked_n++;
}

// Unlink `session` from the intrusive list at *head. Returns true when the
// list became empty (the milestone is gone).
static bool mmt_list_unlink(mmt_session_t ** head, mmt_session_t * session) {
    if (*head == session) {
        if (session->next == NULL) {
            // Only session on this milestone: the milestone is gone.
            *head = NULL;
            return true;
        }
        *head = session->next;
        session->next->previous = NULL;
    } else {
        // F-BUG-011 (issue #199): a session that is not the milestone head
        // should be mid-list, but a session that was never linked has
        // previous == NULL — never dereference it.
        if (session->previous != NULL) {
            session->previous->next = session->next;
        }
        if (session->next != NULL) {
            session->next->previous = session->previous;
        }
    }
    return false;
}

// Unlink `session` from the slot (or parked entry) owned by `milestone`.
// Returns 1 when the milestone exists (matching the old map version, which
// reported success on a found milestone even if the session was not linked
// into its list), 0 when no such milestone is live.
static int mmt_ring_unlink(mmt_timeout_ring * r, uint32_t milestone, mmt_session_t * session) {
    mmt_timeout_slot * s = &r->slots[(size_t) milestone & (r->cap - 1)];
    if (s->head != NULL && s->milestone == milestone) {
        if (mmt_list_unlink(&s->head, session)) r->milestones--;
        return 1;
    }
    mmt_session_t ** parked = mmt_parked_head(r, milestone);
    if (parked == NULL) return 0;
    if (mmt_list_unlink(parked, session)) mmt_parked_erase(r, milestone);
    return 1;
}

// A milestone detached for dispatch (the old pair<uint32_t, mmt_session_t *>).
typedef struct mmt_due_entry {
    uint32_t        milestone;
    mmt_session_t * head;
} mmt_due_entry;

// The std::sort order of the old pair<uint32_t, mmt_session_t *>: ascending
// milestone, then ascending list-head address. Milestones are distinct in
// every due set (a milestone lives in one place), so the address tie-break
// never decides anything; it is kept so the order is total.
static int mmt_due_cmp(const void * a, const void * b) {
    const mmt_due_entry * x = (const mmt_due_entry *) a;
    const mmt_due_entry * y = (const mmt_due_entry *) b;
    if (x->milestone != y->milestone) return x->milestone < y->milestone ? -1 : 1;
    uintptr_t px = (uintptr_t) x->head, py = (uintptr_t) y->head;
    return (px > py) - (px < py);
}

// Snapshot then dispatch the live milestone heads — the callbacks delete the
// milestone (or free the sessions) they are invoked on. A snapshot that
// cannot be allocated dispatches nothing.
static void mmt_ring_iterate(mmt_timeout_ring * r, generic_mapspace_iteration_callback fct, mmt_handler_t *mmt_handler) {
    size_t count = r->parked_n, n = 0;
    for (size_t i = 0; i < r->cap; i++) {
        if (r->slots[i].head != NULL) count++;
    }
    if (count == 0) return;
    mmt_session_t ** heads = (mmt_session_t **) malloc(count * sizeof(mmt_session_t *));
    if (heads == NULL) return;
    for (size_t i = 0; i < r->cap; i++) {
        if (r->slots[i].head != NULL) {
            heads[n++] = r->slots[i].head;
        }
    }
    for (size_t i = 0; i < r->parked_n; i++) {
        heads[n++] = r->parked[i].head;
    }
    for (size_t i = 0; i < n; i++) {
        fct(NULL, heads[i], mmt_handler);
    }
    free(heads);
}

// Sort the detached milestones into ascending order and dispatch them.
static void mmt_due_dispatch(mmt_due_entry * due, size_t n,
        generic_mapspace_iteration_callback fct, mmt_handler_t *mmt_handler) {
    if (n > 1) qsort(due, n, sizeof(mmt_due_entry), mmt_due_cmp);
    for (size_t i = 0; i < n; i++) {
        fct(NULL, due[i].head, mmt_handler);
    }
}

/* Issue #306: expire every live milestone in [lo, hi).
 *
 * The caller used to step one second at a time across the whole range —
 * get_timed_out_session_list() + delete_timeout_milestone() per second — so
 * a hostile pcap record timestamp jumping billions of seconds ahead made
 * process_timedout_sessions() burn CPU in an effectively unbounded loop.
 * Two bounded strategies keep the exact same expiry semantics:
 *
 *   - gap <= cap: per-second stepping (the old loop), already bounded by
 *     the ring capacity;
 *   - gap >  cap: a single O(cap) slot sweep — strictly cheaper than
 *     stepping — collecting every slot whose owner milestone lies in
 *     [lo, hi), then dispatching in ascending milestone order (the
 *     chronological order the stepping loop produced).
 *
 * Slots are detached during the collection pass, before dispatch, so a
 * callback that re-inserts a milestone never frees the fresh head — the
 * same snapshot convention as the iteration helpers above (F-BUG-004,
 * issue #200). */
static void mmt_ring_expire_range(mmt_timeout_ring * r, uint32_t lo, uint32_t hi,
        generic_mapspace_iteration_callback fct, mmt_handler_t *mmt_handler) {
    if ((uint64_t) hi - (uint64_t) lo <= (uint64_t) r->cap) {
        for (uint32_t s = lo; s < hi; s++) {
            mmt_timeout_slot * slot = &r->slots[(size_t) s & (r->cap - 1)];
            if (slot->head != NULL && slot->milestone == s) {
                mmt_session_t * head = slot->head;
                slot->head = NULL;
                r->milestones--;
                fct(NULL, head, mmt_handler);
                continue; // a milestone is never both in a slot and parked
            }
            // Issue #500: an out-of-span milestone is due at the same second.
            mmt_session_t ** parked = mmt_parked_head(r, s);
            if (parked != NULL) {
                mmt_session_t * head = *parked;
                mmt_parked_erase(r, s);
                fct(NULL, head, mmt_handler);
            }
        }
        return;
    }
    // Size the snapshot exactly and allocate it before detaching anything, so
    // an allocation failure leaves every milestone in place (the old
    // reserve()-before-detach convention).
    size_t p_first = mmt_parked_lower_bound(r, lo);
    size_t p_last  = mmt_parked_lower_bound(r, hi);
    size_t count = p_last - p_first, n = 0;
    for (size_t i = 0; i < r->cap; i++) {
        const mmt_timeout_slot * slot = &r->slots[i];
        if (slot->head != NULL && slot->milestone >= lo && slot->milestone < hi) count++;
    }
    if (count == 0) return;
    mmt_due_entry * due = (mmt_due_entry *) malloc(count * sizeof(mmt_due_entry));
    if (due == NULL) return;
    // Issue #500: detach every parked milestone in [lo, hi).
    for (size_t i = p_first; i < p_last; i++) {
        due[n].milestone = r->parked[i].milestone;
        due[n].head      = r->parked[i].head;
        n++;
    }
    mmt_parked_erase_range(r, p_first, p_last);
    for (size_t i = 0; i < r->cap; i++) {
        mmt_timeout_slot * slot = &r->slots[i];
        if (slot->head != NULL && slot->milestone >= lo && slot->milestone < hi) {
            due[n].milestone = slot->milestone;
            due[n].head      = slot->head;
            n++;
            slot->head = NULL;
            r->milestones--;
        }
    }
    mmt_due_dispatch(due, n, fct, mmt_handler);
    free(due);
}

/* Issue #499: detach every live milestone (ring and parked) and dispatch them
 * in ascending order. Unlike mmt_ring_iterate() the slots are emptied before
 * dispatch, so a callback may re-arm a session (a tunnel parent whose
 * children are still live) and a later drain picks it up. Returns the number
 * of milestones dispatched; 0, with nothing detached, when the snapshot
 * cannot be allocated. */
static size_t mmt_ring_drain(mmt_timeout_ring * r, generic_mapspace_iteration_callback fct,
        mmt_handler_t *mmt_handler) {
    size_t count = r->parked_n, n = 0;
    for (size_t i = 0; i < r->cap; i++) {
        if (r->slots[i].head != NULL) count++;
    }
    if (count == 0) {
        r->milestones = 0;
        return 0;
    }
    mmt_due_entry * due = (mmt_due_entry *) malloc(count * sizeof(mmt_due_entry));
    if (due == NULL) return 0;
    for (size_t i = 0; i < r->cap; i++) {
        mmt_timeout_slot * slot = &r->slots[i];
        if (slot->head != NULL) {
            due[n].milestone = slot->milestone;
            due[n].head      = slot->head;
            n++;
            slot->head = NULL;
        }
    }
    r->milestones = 0;
    for (size_t i = 0; i < r->parked_n; i++) {
        due[n].milestone = r->parked[i].milestone;
        due[n].head      = r->parked[i].head;
        n++;
    }
    r->parked_n = 0;
    mmt_due_dispatch(due, n, fct, mmt_handler);
    free(due);
    return n;
}

uint64_t mmt_oa_equal_call_count(void) {
#if MMT_SESSION_LOOKUP_STATS
    return __atomic_load_n(&mmt_oa_equal_calls, __ATOMIC_RELAXED);
#else
    return 0;
#endif
}

uint64_t mmt_oa_comp_call_count(void) {
#if MMT_SESSION_LOOKUP_STATS
    return __atomic_load_n(&mmt_oa_comp_calls, __ATOMIC_RELAXED);
#else
    return 0;
#endif
}

void * init_session_map_space(generic_comparison_fct comp_fct, generic_hash_fct hash_fct, generic_equal_fct equal_fct) {
    return mmt_oa_create(comp_fct, hash_fct, equal_fct);
}

void delete_session_map_space(void * sessionmap) {
    mmt_oa_destroy((mmt_oa_table *) sessionmap);
}

void * init_map_space(generic_comparison_fct comp_fct, generic_hash_fct hash_fct) {
    // Generic maps have no registered equality predicate — the two-call
    // comparator equivalence stays (issue #253 scoped the one-call path
    // to the session store).
    return mmt_oa_create(comp_fct, hash_fct, NULL);
}

void * init_int_map_space(generic_int_comparison_fct comp_fct) {
    mmt_int_map * m = (mmt_int_map *) malloc(sizeof(mmt_int_map));
    if (m == NULL) return NULL;
    m->size = 0;
    m->used = 0;
    m->comp = comp_fct;
    mmt_int_alloc_slots(m, MMT_OA_INITIAL_CAP);
    if (m->slots == NULL) { free(m); return NULL; }
    return m;
}

int insert_key_value(void * maplist, void * key, void * value) {
    mmt_oa_table * t = (mmt_oa_table *) maplist;
    if (mmt_oa_insert(t, key, value) == 0) {
        debug("FROM InsertSession got a problem: hash_utils.c - insert_key_value()");
        return 0;
    }
    return 1;
}

int insert_int_key_value(void * maplist, uint32_t key, void * value) {
    mmt_int_map * m = (mmt_int_map *) maplist;
    if (mmt_int_insert(m, key, value) == 0) {
        debug("FROM InsertSession got a problem: hash_utils.c - insert_int_key_value()");
        return 0;
    }
    return 1;
}

int insert_session_into_protocol_context(void * protocol_context, void * key, void * value) {
    if (protocol_context == NULL) return 0;
    mmt_oa_table * t = (mmt_oa_table *) ((protocol_instance_t *) protocol_context)->sessions_map;
    if (mmt_oa_insert(t, key, value) == 0) {
        debug("FROM InsertSession got a problem: hash_utils.c - insert_session_into_protocol_context()");
        return 0;
    }
    return 1;
}

void * find_key_value(void * maplist, void * key) {
    return mmt_oa_find((mmt_oa_table *) maplist, key);
}

void * find_int_key_value(void * maplist, uint32_t key) {
    return mmt_int_find((mmt_int_map *) maplist, key);
}

void * get_session_from_protocol_context_by_session_key(void * protocol_context, void * key) {
    if (protocol_context == NULL) return NULL;
    return mmt_oa_find((mmt_oa_table *) ((protocol_instance_t *) protocol_context)->sessions_map, key);
}

int delete_key_value(void * maplist, void * key) {
    mmt_oa_table * t = (mmt_oa_table *) maplist;
    if (t == NULL) return 0;
    // The old erase-or-ignore contract always reported success.
    mmt_oa_remove(t, key);
    return 1;
}

int delete_int_key_value(void * maplist, uint32_t key) {
    mmt_int_map * m = (mmt_int_map *) maplist;
    if (m == NULL) return 0;
    mmt_int_remove(m, key);
    return 1;
}

int delete_session_from_protocol_context(void * protocol_context, void * key) {
    // F-BUG-001 (issue #199): early-out on a missing or dead table,
    // mirroring the not-found return of the old delete_key_value.
    if (protocol_context == NULL) return 1;
    mmt_oa_remove((mmt_oa_table *) ((protocol_instance_t *) protocol_context)->sessions_map, key);
    return 1;
}

void clear_map_space(void * maplist) {
    mmt_oa_table * t = (mmt_oa_table *) maplist;
    if (t == NULL || t->slots == NULL) return;
    mmt_oa_reset(t);
}

void clear_int_map_space(void * maplist) {
    mmt_int_map * m = (mmt_int_map *) maplist;
    if (m == NULL || m->slots == NULL) return;
    mmt_int_reset(m);
}

void delete_map_space(void * maplist) {
    mmt_oa_destroy((mmt_oa_table *) maplist);
}

void delete_int_map_space(void * maplist) {
    mmt_int_map * m = (mmt_int_map *) maplist;
    if (m == NULL) return;
    free(m->slots);
    free(m);
}


void clear_sessions_from_protocol_context(void * protocol_context) {
    if (protocol_context == NULL) return;
    mmt_oa_table * t = (mmt_oa_table *) ((protocol_instance_t *) protocol_context)->sessions_map;
    if (t == NULL || t->slots == NULL) return;
    mmt_oa_reset(t);
}

/* Issue #200 (F-BUG-004): the dispatch callbacks may remove the table entry
 * they are invoked on — e.g. close_extraction() iterates
 * mmt_configured_handlers_map via iterate_through_mmt_handlers() and
 * mmt_close_handler() deletes its own node, after which `it++` advanced a
 * dangling iterator. Every iteration helper therefore snapshots the
 * key/value pairs first, then dispatches: mutations during a callback
 * affect the table, never the snapshot being walked. */
void mapspace_iteration_callback(void * maplist, generic_mapspace_iteration_callback fct, void * args) {
    mmt_oa_table * t = (mmt_oa_table *) maplist;
    if (t == NULL || t->slots == NULL || fct == NULL) return;
    mmt_oa_slot * entries;
    size_t n = mmt_oa_snapshot(t, &entries);
    for (size_t i = 0; i < n; i++) {
        fct(entries[i].key, entries[i].value, args);
    }
    free(entries);
}

void int_mapspace_iteration_callback(void * maplist, generic_mapspace_iteration_callback fct, void * args) {
    mmt_int_map * m = (mmt_int_map *) maplist;
    if (m == NULL || m->slots == NULL || fct == NULL) return;
    size_t count = 0, n = 0;
    for (size_t i = 0; i < m->cap; i++) {
        if (m->slots[i].state == MMT_INT_LIVE) count++;
    }
    if (count == 0) return;
    void ** values = (void **) malloc(count * sizeof(void *));
    if (values == NULL) return;
    for (size_t i = 0; i < m->cap; i++) {
        if (m->slots[i].state == MMT_INT_LIVE) {
            values[n++] = m->slots[i].value;
        }
    }
    for (size_t i = 0; i < n; i++) {
        fct(NULL, values[i], args);
    }
    free(values);
}

void protocol_sessions_iteration_callback(void * protocol_context, generic_mapspace_iteration_callback fct, void * args) {
    if (protocol_context == NULL || fct == NULL) return;
    mmt_oa_table * t = (mmt_oa_table *) ((protocol_instance_t *) protocol_context)->sessions_map;
    if (t == NULL || t->slots == NULL) return;
    // Snapshot: the callback may tombstone a slot or trigger a resize that
    // reallocates the slot array underneath a live cursor.
    mmt_oa_slot * entries;
    size_t n = mmt_oa_snapshot(t, &entries);
    for (size_t i = 0; i < n; i++) {
        fct(entries[i].key, entries[i].value, args);
    }
    free(entries);
}
//////////////// Stores End

//////////////// Session-timeout index — timing wheel ////////////////
//
// init_timeout_milestones_index() returns the per-handler timeout index the
// wrappers below operate on; see the "Session-timeout ring" block above for
// the design. All operations are O(1) with zero allocations on the hot path.

void * init_timeout_milestones_index(void) {
    mmt_timeout_ring * r = (mmt_timeout_ring *) malloc(sizeof(mmt_timeout_ring));
    if (r == NULL) return NULL;
    r->milestones = 0;
    r->parked     = NULL;
    r->parked_n   = 0;
    r->parked_cap = 0;
    r->slots = (mmt_timeout_slot *) calloc(MMT_RING_INITIAL_CAP, sizeof(mmt_timeout_slot));
    if (r->slots == NULL) { free(r); return NULL; }
    r->cap = MMT_RING_INITIAL_CAP;
    return r;
}

void timeout_iteration_callback(mmt_handler_t *mmt_handler, generic_mapspace_iteration_callback fct) {
    if (mmt_handler == NULL || fct == NULL) return;
    mmt_timeout_ring * r = (mmt_timeout_ring *) mmt_handler->timeout_milestones_map;
    if (r == NULL || r->slots == NULL) return;
    mmt_ring_iterate(r, fct, mmt_handler);
}

void session_timer_iteration_callback(mmt_handler_t *mmt_handler, generic_mapspace_iteration_callback fct) {
    if (mmt_handler == NULL || fct == NULL) return;
    mmt_timeout_ring * r = (mmt_timeout_ring *) mmt_handler->timeout_milestones_map;
    if (r == NULL || r->slots == NULL) return;
    mmt_ring_iterate(r, fct, mmt_handler);
}

/* Issue #306: range expiry used by process_timedout_sessions() — bounded
 * pass over [range_lo, range_hi), see mmt_ring_expire_range(). */
void timeout_expire_milestones_range(mmt_handler_t *mmt_handler, uint32_t range_lo, uint32_t range_hi, generic_mapspace_iteration_callback fct) {
    if (mmt_handler == NULL || fct == NULL || range_hi <= range_lo) return;
    mmt_timeout_ring * r = (mmt_timeout_ring *) mmt_handler->timeout_milestones_map;
    if (r == NULL || r->slots == NULL) return;
    mmt_ring_expire_range(r, range_lo, range_hi, fct, mmt_handler);
}

/* Issue #499: drain every live milestone, see mmt_ring_drain(). */
size_t timeout_drain_milestones(mmt_handler_t *mmt_handler, generic_mapspace_iteration_callback fct) {
    if (mmt_handler == NULL || fct == NULL) return 0;
    mmt_timeout_ring * r = (mmt_timeout_ring *) mmt_handler->timeout_milestones_map;
    if (r == NULL || r->slots == NULL) return 0;
    return mmt_ring_drain(r, fct, mmt_handler);
}


int update_session_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t new_timeout, uint32_t old_timeout, mmt_session_t * session) {
    if (mmt_handler == NULL || session == NULL) return 0;
    mmt_timeout_ring * r = (mmt_timeout_ring *) mmt_handler->timeout_milestones_map;
    if (r == NULL || r->slots == NULL) return 0;

    mmt_ring_unlink(r, old_timeout, session);
    //printf("From update session timeout milestone, trying to add session %i to milestone %u\n", session->session_id, new_timeout);
    return insert_session_timeout_milestone(mmt_handler, new_timeout, session);
}

int force_session_timeout(mmt_handler_t *mmt_handler, mmt_session_t * session) {
    if (mmt_handler == NULL || session == NULL) return 0;
    mmt_timeout_ring * r = (mmt_timeout_ring *) mmt_handler->timeout_milestones_map;
    if (r == NULL || r->slots == NULL) return 0;
    return mmt_ring_unlink(r, session->session_timeout_milestone, session);
}

int insert_session_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t timeout, mmt_session_t * session) {
    if (mmt_handler == NULL || session == NULL) return 0;
    mmt_timeout_ring * r = (mmt_timeout_ring *) mmt_handler->timeout_milestones_map;
    if (r == NULL || r->slots == NULL) return 0;

    for (;;) {
        // Issue #500: an already parked milestone keeps its sessions there.
        mmt_session_t ** parked = mmt_parked_head(r, timeout);
        if (parked != NULL) {
            session->previous   = NULL;
            session->next       = *parked;
            (*parked)->previous = session;
            *parked             = session;
            return MMT_TIMEOUT_PARKED;
        }
        mmt_timeout_slot * s = &r->slots[(size_t) timeout & (r->cap - 1)];
        if (s->head == NULL) {
            // Fresh milestone: claim the slot. No allocation — the session
            // itself carries the list links.
            s->milestone = timeout;
            s->head      = session;
            session->next     = NULL;
            session->previous = NULL;
            r->milestones++;
            return MMT_TIMEOUT_INSERTED;
        }
        if (s->milestone == timeout) {
            // Existing milestone: prepend on its intrusive list.
            session->previous = NULL;
            session->next     = s->head;
            s->head->previous = session;
            s->head           = session;
            return MMT_TIMEOUT_INSERTED;
        }
        // Slot owned by a different live milestone: the live milestone span
        // reached the ring capacity — grow until the span fits (bounded,
        // single-relink) or fail cleanly like the old map's OOM.
        int grown = mmt_ring_grow(r, timeout);
        if (grown == MMT_RING_GROW_OK) continue;
        if (grown == MMT_RING_GROW_NOMEM) return MMT_TIMEOUT_NOMEM;
        // Issue #500: the span cannot fit any ring — park the outlier
        // milestone. Growing the parked index is the only allocation here.
        if (!mmt_parked_reserve_one(r)) return MMT_TIMEOUT_NOMEM;
        session->previous = NULL;
        session->next     = NULL;
        mmt_parked_insert(r, timeout, session);
        return MMT_TIMEOUT_PARKED;
    }
}

mmt_session_t * get_timed_out_session_list(mmt_handler_t *mmt_handler, uint32_t timeout) {
    if (mmt_handler == NULL) return NULL;
    mmt_timeout_ring * r = (mmt_timeout_ring *) mmt_handler->timeout_milestones_map;
    if (r == NULL || r->slots == NULL) return NULL;
    mmt_timeout_slot * s = &r->slots[(size_t) timeout & (r->cap - 1)];
    if (s->head != NULL && s->milestone == timeout) {
        return s->head;
    }
    mmt_session_t ** parked = mmt_parked_head(r, timeout);
    return parked != NULL ? *parked : NULL;
}

int delete_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t timeout) {
    if (mmt_handler == NULL) return 0;
    mmt_timeout_ring * r = (mmt_timeout_ring *) mmt_handler->timeout_milestones_map;
    if (r == NULL || r->slots == NULL) return 0;
    mmt_timeout_slot * s = &r->slots[(size_t) timeout & (r->cap - 1)];
    if (s->head != NULL && s->milestone == timeout) {
        s->head = NULL;
        r->milestones--;
    } else {
        mmt_parked_erase(r, timeout);
    }
    return 1;
}

void clear_timeout_milestones(mmt_handler_t *mmt_handler) {
    if (mmt_handler == NULL) return;
    mmt_timeout_ring * r = (mmt_timeout_ring *) mmt_handler->timeout_milestones_map;
    if (r != NULL) {
        free(r->parked);
        free(r->slots);
        free(r);
        // Issue #200 (F-BUG-005): NULL the field after deleting so a second
        // teardown cannot dereference the dangling pointer.
        mmt_handler->timeout_milestones_map = NULL;
    }
}


/////// Protocol stack map

static bool protocol_stack_id_comp_fn_pt(uint32_t ps1, uint32_t ps2) {
    return (ps1 < ps2);
}

/* Issue #200 (F-BUG-005): this map used to be built by a load-time
 * initializer and clear_protocol_stack_map() deleted it without NULLing the
 * pointer — a second init_extraction() in one process then dereferenced the
 * dangling map (use-after-free). It is now created lazily by the write path
 * and recreated after a clear; read paths treat NULL as "no stack". */
static void * protocol_stack_map = NULL;

static mmt_int_map * get_protocol_stack_map(void) {
    if (protocol_stack_map == NULL) {
        protocol_stack_map = init_int_map_space(protocol_stack_id_comp_fn_pt);
    }
    return (mmt_int_map *) protocol_stack_map;
}

void iterate_through_protocol_stacks(generic_mapspace_iteration_callback fct, void * args) {
    // Snapshot before dispatching (see the F-BUG-004 note above);
    // int_mapspace_iteration_callback early-outs on a NULL map.
    int_mapspace_iteration_callback(protocol_stack_map, fct, args);
}

int insert_protocol_stack_into_map(uint32_t key, void * value) {
    return insert_int_key_value(get_protocol_stack_map(), key, value);
}

void * get_protocol_stack_from_map(uint32_t key) {
    // Read path: NULL map means "no stack registered" — never create one.
    return find_int_key_value(protocol_stack_map, key);
}

int delete_protocol_stack_from_map(uint32_t key) {
    return delete_int_key_value(protocol_stack_map, key);
}

void clear_protocol_stack_map(void) {
    mmt_int_map * m = (mmt_int_map *) protocol_stack_map;
    if (m != NULL) {
        free(m->slots);
        free(m);
        protocol_stack_map = NULL;
    }
}

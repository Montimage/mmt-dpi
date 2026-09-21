#include "hash_utils.h"
#include <new>
#include <vector>
#include <utility>
#include <cstdint>
#include <cstddef>

using namespace std;

//////////////// Wrapper
//
// Issue #200 (F-BUG-003): every function below is exported across an
// extern-C boundary into C callers whose frames have no C++ unwind
// tables. An escaping exception (the std::vector snapshots below can throw
// std::bad_alloc) cannot be caught there and reaches std::terminate, killing
// the host process — so every definition is explicitly marked with C linkage
// and wraps its body in try/catch(...) returning the failure value of its
// return type (NULL / 0 / nothing). A NULL table pointer is likewise treated
// as a failure: callers that ignore an init_*_map_space() failure get a safe
// no-op instead of a NULL dereference.
//
// Issue #254 (F-PERF-011/012/013): the red-black-tree stores are gone. All
// key/value stores below are open-addressing tables or the timeout ring —
// same pattern as the per-flow session store (issue #17).

namespace {

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
// Slots are 16 bytes (two pointers) so four pack into a 64-byte cache line.
// Empty/tombstone states are encoded in the key pointer rather than a
// separate field: real keys are heap-allocated structures, so NULL and the
// 0x1 sentinel can never collide with a live key.

static void * const MMT_SLOT_EMPTY = NULL;
static void * const MMT_SLOT_TOMB  = reinterpret_cast<void *>(static_cast<uintptr_t>(1));

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

struct mmt_oa_slot {
    void * key;
    void * value;
};

struct mmt_oa_table {
    mmt_oa_slot *          slots;
    size_t                 cap;        // power of two
    size_t                 size;       // live (occupied) slots
    size_t                 used;       // occupied + tombstones (drives resize)
    generic_comparison_fct comp;
    generic_hash_fct       hash;
    generic_equal_fct      equal;      // issue #253 (F-PERF-008)

    uint64_t hash_of(void * k) const {
        // The mixer is a static-inline fmix64 — it compiles into the call
        // site (no function call, ~3 serially-dependent multiply steps on
        // top of the key hash itself).
        return mmt_mix64(hash ? hash(k) : 0);
    }
    // Issue #253 (F-PERF-008): a registered equality predicate resolves a
    // probe in ONE call. The fallback keeps the old map equivalence under a
    // strict weak ordering — two keys are the same entry iff neither orders
    // before the other — which costs two comparator invocations.
    bool key_equal(void * a, void * b) const {
        if (equal != NULL) {
#if MMT_SESSION_LOOKUP_STATS
            __atomic_add_fetch(&mmt_oa_equal_calls, 1, __ATOMIC_RELAXED);
#endif
            return equal(a, b);
        }
#if MMT_SESSION_LOOKUP_STATS
        __atomic_add_fetch(&mmt_oa_comp_calls, 1, __ATOMIC_RELAXED);
#endif
        return !comp(a, b) && !comp(b, a);
    }
};

static const size_t MMT_OA_INITIAL_CAP = 16; // power of two

static void mmt_oa_alloc_slots(mmt_oa_table * t, size_t cap) {
    t->slots = (mmt_oa_slot *) calloc(cap, sizeof(mmt_oa_slot));
    if (t->slots == NULL) { t->cap = 0; return; }
    t->cap   = cap;
    // calloc zero-fills -> every slot's key is NULL (MMT_SLOT_EMPTY).
}

// Insert a known-unique key into a tombstone-free table (used during resize).
static void mmt_oa_put_raw(mmt_oa_table * t, void * key, void * value) {
    size_t mask = t->cap - 1;
    size_t i = (size_t) t->hash_of(key) & mask;
    while (t->slots[i].key != MMT_SLOT_EMPTY) {
        i = (i + 1) & mask;
    }
    t->slots[i].key   = key;
    t->slots[i].value = value;
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
    mmt_oa_slot * fresh = (mmt_oa_slot *) calloc(MMT_OA_INITIAL_CAP, sizeof(mmt_oa_slot));
    if (fresh == NULL) {
        // OOM: fall back to the old behaviour — wipe the slots in place; the
        // table stays usable, only the memory release is skipped.
        memset(t->slots, 0, t->cap * sizeof(mmt_oa_slot));
    } else {
        free(t->slots);
        t->slots = fresh;
        t->cap   = MMT_OA_INITIAL_CAP;
    }
    t->size = 0;
    t->used = 0;
}

static void * mmt_oa_create(generic_comparison_fct comp_fct, generic_hash_fct hash_fct, generic_equal_fct equal_fct) {
    mmt_oa_table * t = (mmt_oa_table *) malloc(sizeof(mmt_oa_table));
    if (t == NULL) return NULL;
    t->size = 0;
    t->used = 0;
    t->comp = comp_fct;
    t->hash = hash_fct;
    t->equal = equal_fct;
    mmt_oa_alloc_slots(t, MMT_OA_INITIAL_CAP);
    if (t->slots == NULL) { free(t); return NULL; }
    return reinterpret_cast<void *>(t);
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

    // Keep the load factor <= 0.7. Grow only when the live population is dense;
    // if the slots are mostly tombstones (delete-heavy churn from session
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
    size_t i = (size_t) t->hash_of(key) & mask;
    size_t tomb = 0;
    bool have_tomb = false;
    void * k;
    while ((k = t->slots[i].key) != MMT_SLOT_EMPTY) {
        if (k == MMT_SLOT_TOMB) {
            if (!have_tomb) { tomb = i; have_tomb = true; }
        } else if (t->key_equal(k, key)) {
            return 0; // duplicate: mirror the old map (no overwrite)
        }
        i = (i + 1) & mask;
    }
    size_t dst = have_tomb ? tomb : i;
    if (t->slots[dst].key == MMT_SLOT_EMPTY) {
        t->used++; // reusing a tombstone does not change the load count
    }
    t->slots[dst].key   = key;
    t->slots[dst].value = value;
    t->size++;
    return 1;
}

static void * mmt_oa_find(mmt_oa_table * t, void * key) {
    if (t == NULL || t->slots == NULL || t->cap == 0) return NULL;
    size_t mask = t->cap - 1;
    size_t i = (size_t) t->hash_of(key) & mask;
    void * k;
    for (size_t n = 0; n < t->cap; n++) {
        k = t->slots[i].key;
        if (k == MMT_SLOT_EMPTY) break;
        if (k != MMT_SLOT_TOMB && t->key_equal(k, key)) {
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
    size_t i = (size_t) t->hash_of(key) & mask;
    void * k;
    // Bounded probe: a table whose slots are all TOMB/non-empty must not
    // loop forever looking for an EMPTY terminator.
    for (size_t n = 0; n < t->cap; n++) {
        k = t->slots[i].key;
        if (k == MMT_SLOT_EMPTY) break;
        if (k != MMT_SLOT_TOMB && t->key_equal(k, key)) {
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

struct mmt_int_slot {
    uint32_t key;
    void *   value;
    uint8_t  state; // mmt_int_state
};

struct mmt_int_map {
    mmt_int_slot *              slots;
    size_t                      cap;
    size_t                      size;
    size_t                      used;
    generic_int_comparison_fct  comp;

    bool key_equal(uint32_t a, uint32_t b) const {
        return !comp(a, b) && !comp(b, a);
    }
};

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
        } else if (m->key_equal(m->slots[i].key, key)) {
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
        if (m->slots[i].state == MMT_INT_LIVE && m->key_equal(m->slots[i].key, key)) {
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
        if (m->slots[i].state == MMT_INT_LIVE && m->key_equal(m->slots[i].key, key)) {
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
// allocations; growth is the rare exception and its failure degrades to the
// same 0 return the old map's bad_alloc path produced.

struct mmt_timeout_slot {
    mmt_session_t * head;      // session list of the owning milestone
    uint32_t        milestone; // owning milestone (valid while head != NULL)
};

struct mmt_timeout_ring {
    mmt_timeout_slot * slots;
    size_t             cap;        // power of two
    size_t             milestones; // live (owned) slots
};

static const size_t MMT_RING_INITIAL_CAP = 1024;          // ~17 min of distinct seconds
static const size_t MMT_RING_MAX_CAP     = 1u << 22;      // ~48 days of spread — beyond that, fail

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
        if (new_cap >= MMT_RING_MAX_CAP) return 0; // pathological spread — fail like the old bad_alloc
        new_cap <<= 1;
    }
    mmt_timeout_slot * fresh = (mmt_timeout_slot *) calloc(new_cap, sizeof(mmt_timeout_slot));
    if (fresh == NULL) return 0;
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
    return 1;
}

// Unlink `session` from the slot owned by `milestone`. Returns 1 when the
// milestone exists (matching the old map version, which reported success on
// a found milestone even if the session was not linked into its list), 0 when
// no such milestone is live.
static int mmt_ring_unlink(mmt_timeout_ring * r, uint32_t milestone, mmt_session_t * session) {
    mmt_timeout_slot * s = &r->slots[(size_t) milestone & (r->cap - 1)];
    if (s->head == NULL || s->milestone != milestone) return 0;
    if (s->head == session) {
        if (session->next == NULL) {
            // Only session on this milestone: the milestone is gone.
            s->head = NULL;
            r->milestones--;
        } else {
            s->head = session->next;
            session->next->previous = NULL;
        }
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
    return 1;
}

// Snapshot then dispatch the live milestone heads — the callbacks delete the
// milestone (or free the sessions) they are invoked on.
static void mmt_ring_iterate(mmt_timeout_ring * r, generic_mapspace_iteration_callback fct, mmt_handler_t *mmt_handler) {
    vector<void *> heads;
    heads.reserve(r->milestones);
    for (size_t i = 0; i < r->cap; i++) {
        if (r->slots[i].head != NULL) {
            heads.push_back((void *) r->slots[i].head);
        }
    }
    for (size_t i = 0; i < heads.size(); i++) {
        fct(NULL, heads[i], mmt_handler);
    }
}

} // namespace

extern "C" uint64_t mmt_oa_equal_call_count(void) {
#if MMT_SESSION_LOOKUP_STATS
    return __atomic_load_n(&mmt_oa_equal_calls, __ATOMIC_RELAXED);
#else
    return 0;
#endif
}

extern "C" uint64_t mmt_oa_comp_call_count(void) {
#if MMT_SESSION_LOOKUP_STATS
    return __atomic_load_n(&mmt_oa_comp_calls, __ATOMIC_RELAXED);
#else
    return 0;
#endif
}

extern "C" void * init_session_map_space(generic_comparison_fct comp_fct, generic_hash_fct hash_fct, generic_equal_fct equal_fct) {
    try {
        return mmt_oa_create(comp_fct, hash_fct, equal_fct);
    } catch (...) {
        return NULL;
    }
}

extern "C" void delete_session_map_space(void * sessionmap) {
    try {
        mmt_oa_destroy(reinterpret_cast<mmt_oa_table *>(sessionmap));
    } catch (...) {
        return;
    }
}

extern "C" void * init_map_space(generic_comparison_fct comp_fct, generic_hash_fct hash_fct) {
    try {
        // Generic maps have no registered equality predicate — the two-call
        // comparator equivalence stays (issue #253 scoped the one-call path
        // to the session store).
        return mmt_oa_create(comp_fct, hash_fct, NULL);
    } catch (...) {
        return NULL;
    }
}

extern "C" void * init_int_map_space(generic_int_comparison_fct comp_fct) {
    try {
        mmt_int_map * m = (mmt_int_map *) malloc(sizeof(mmt_int_map));
        if (m == NULL) return NULL;
        m->size = 0;
        m->used = 0;
        m->comp = comp_fct;
        mmt_int_alloc_slots(m, MMT_OA_INITIAL_CAP);
        if (m->slots == NULL) { free(m); return NULL; }
        return reinterpret_cast<void *>(m);
    } catch (...) {
        return NULL;
    }
}

extern "C" int getmapsize(void * maplist) {
    try {
        mmt_oa_table * t = reinterpret_cast<mmt_oa_table *> (maplist);
        if (t == NULL) return 0;
        return (int) t->size;
    } catch (...) {
        return 0;
    }
}

extern "C" int insert_key_value(void * maplist, void * key, void * value) {
    try {
        mmt_oa_table * t = reinterpret_cast<mmt_oa_table *> (maplist);
        if (mmt_oa_insert(t, key, value) == 0) {
            printf("FROM InsertSession got a problem: hash_utils.cpp - insert_key_value() \n");
            return 0;
        }
        return 1;
    } catch (...) {
        return 0;
    }
}

extern "C" int insert_int_key_value(void * maplist, uint32_t key, void * value) {
    try {
        mmt_int_map * m = reinterpret_cast<mmt_int_map *> (maplist);
        if (mmt_int_insert(m, key, value) == 0) {
            printf("FROM InsertSession got a problem: hash_utils.cpp - insert_int_key_value() \n");
            return 0;
        }
        return 1;
    } catch (...) {
        return 0;
    }
}

extern "C" int insert_session_into_protocol_context(void * protocol_context, void * key, void * value) {
    try {
        if (protocol_context == NULL) return 0;
        mmt_oa_table * t = reinterpret_cast<mmt_oa_table *>(((protocol_instance_t *) protocol_context)->sessions_map);
        if (mmt_oa_insert(t, key, value) == 0) {
            printf("FROM InsertSession got a problem: hash_utils.cpp - insert_session_into_protocol_context() \n");
            return 0;
        }
        return 1;
    } catch (...) {
        return 0;
    }
}

extern "C" int update_key_value(void * maplist, void * key, void * new_value) {
    try {
        mmt_oa_table * t = reinterpret_cast<mmt_oa_table *> (maplist);
        if (t == NULL || t->slots == NULL || t->cap == 0) return 0;
        size_t mask = t->cap - 1;
        size_t i = (size_t) t->hash_of(key) & mask;
        void * k;
        for (size_t n = 0; n < t->cap; n++) {
            k = t->slots[i].key;
            if (k == MMT_SLOT_EMPTY) break;
            if (k != MMT_SLOT_TOMB && t->key_equal(k, key)) {
                t->slots[i].value = new_value;
                return 1;
            }
            i = (i + 1) & mask;
        }
        return 0;
    } catch (...) {
        return 0;
    }
}

extern "C" void * find_key_value(void * maplist, void * key) {
    try {
        return mmt_oa_find(reinterpret_cast<mmt_oa_table *> (maplist), key);
    } catch (...) {
        return NULL;
    }
}

extern "C" void * find_int_key_value(void * maplist, uint32_t key) {
    try {
        return mmt_int_find(reinterpret_cast<mmt_int_map *> (maplist), key);
    } catch (...) {
        return NULL;
    }
}

extern "C" void * get_session_from_protocol_context_by_session_key(void * protocol_context, void * key) {
    try {
        if (protocol_context == NULL) return NULL;
        return mmt_oa_find(reinterpret_cast<mmt_oa_table *>(((protocol_instance_t *) protocol_context)->sessions_map), key);
    } catch (...) {
        return NULL;
    }
}

extern "C" int delete_key_value(void * maplist, void * key) {
    try {
        mmt_oa_table * t = reinterpret_cast<mmt_oa_table *> (maplist);
        if (t == NULL) return 0;
        // The old erase-or-ignore contract always reported success.
        mmt_oa_remove(t, key);
        return 1;
    } catch (...) {
        return 0;
    }
}

extern "C" int delete_int_key_value(void * maplist, uint32_t key) {
    try {
        mmt_int_map * m = reinterpret_cast<mmt_int_map *> (maplist);
        if (m == NULL) return 0;
        mmt_int_remove(m, key);
        return 1;
    } catch (...) {
        return 0;
    }
}

extern "C" int delete_session_from_protocol_context(void * protocol_context, void * key) {
    try {
        // F-BUG-001 (issue #199): early-out on a missing or dead table,
        // mirroring the not-found return of the old delete_key_value.
        if (protocol_context == NULL) return 1;
        mmt_oa_remove(reinterpret_cast<mmt_oa_table *>(((protocol_instance_t *) protocol_context)->sessions_map), key);
        return 1;
    } catch (...) {
        return 0;
    }
}

extern "C" void clear_map_space(void * maplist) {
    try {
        mmt_oa_table * t = reinterpret_cast<mmt_oa_table *> (maplist);
        if (t == NULL || t->slots == NULL) return;
        mmt_oa_reset(t);
    } catch (...) {
        return;
    }
}

extern "C" void clear_int_map_space(void * maplist) {
    try {
        mmt_int_map * m = reinterpret_cast<mmt_int_map *> (maplist);
        if (m == NULL || m->slots == NULL) return;
        mmt_int_reset(m);
    } catch (...) {
        return;
    }
}

extern "C" void delete_map_space(void * maplist) {
    try {
        mmt_oa_destroy(reinterpret_cast<mmt_oa_table *> (maplist));
    } catch (...) {
        return;
    }
}

extern "C" void delete_int_map_space(void * maplist) {
    try {
        mmt_int_map * m = reinterpret_cast<mmt_int_map *> (maplist);
        if (m == NULL) return;
        free(m->slots);
        free(m);
    } catch (...) {
        return;
    }
}


extern "C" void clear_sessions_from_protocol_context(void * protocol_context) {
    try {
        if (protocol_context == NULL) return;
        mmt_oa_table * t = reinterpret_cast<mmt_oa_table *>(((protocol_instance_t *) protocol_context)->sessions_map);
        if (t == NULL || t->slots == NULL) return;
        mmt_oa_reset(t);
    } catch (...) {
        return;
    }
}

/* Issue #200 (F-BUG-004): the dispatch callbacks may remove the table entry
 * they are invoked on — e.g. close_extraction() iterates
 * mmt_configured_handlers_map via iterate_through_mmt_handlers() and
 * mmt_close_handler() deletes its own node, after which `it++` advanced a
 * dangling iterator. Every iteration helper therefore snapshots the
 * key/value pairs into a vector first, then dispatches: mutations during a
 * callback affect the table, never the snapshot being walked. */
extern "C" void mapspace_iteration_callback(void * maplist, generic_mapspace_iteration_callback fct, void * args) {
    try {
        mmt_oa_table * t = reinterpret_cast<mmt_oa_table *> (maplist);
        if (t == NULL || t->slots == NULL || fct == NULL) return;
        vector<pair<void *, void *> > entries;
        entries.reserve(t->size);
        for (size_t i = 0; i < t->cap; i++) {
            void * k = t->slots[i].key;
            if (k != MMT_SLOT_EMPTY && k != MMT_SLOT_TOMB) {
                entries.push_back(make_pair(k, t->slots[i].value));
            }
        }
        for (size_t i = 0; i < entries.size(); i++) {
            fct(entries[i].first, entries[i].second, args);
        }
    } catch (...) {
        return;
    }
}

extern "C" void int_mapspace_iteration_callback(void * maplist, generic_mapspace_iteration_callback fct, void * args) {
    try {
        mmt_int_map * m = reinterpret_cast<mmt_int_map *> (maplist);
        if (m == NULL || m->slots == NULL || fct == NULL) return;
        vector<void *> values;
        values.reserve(m->size);
        for (size_t i = 0; i < m->cap; i++) {
            if (m->slots[i].state == MMT_INT_LIVE) {
                values.push_back(m->slots[i].value);
            }
        }
        for (size_t i = 0; i < values.size(); i++) {
            fct(NULL, values[i], args);
        }
    } catch (...) {
        return;
    }
}

extern "C" void protocol_sessions_iteration_callback(void * protocol_context, generic_mapspace_iteration_callback fct, void * args) {
    try {
        if (protocol_context == NULL || fct == NULL) return;
        mmt_oa_table * t = reinterpret_cast<mmt_oa_table *>(((protocol_instance_t *) protocol_context)->sessions_map);
        if (t == NULL || t->slots == NULL) return;
        // Snapshot: the callback may tombstone a slot or trigger a resize that
        // reallocates the slot array underneath a live cursor.
        vector<pair<void *, void *> > entries;
        entries.reserve(t->size);
        for (size_t i = 0; i < t->cap; i++) {
            void * k = t->slots[i].key;
            if (k != MMT_SLOT_EMPTY && k != MMT_SLOT_TOMB) {
                entries.push_back(make_pair(k, t->slots[i].value));
            }
        }
        for (size_t i = 0; i < entries.size(); i++) {
            fct(entries[i].first, entries[i].second, args);
        }
    } catch (...) {
        return;
    }
}
//////////////// Wrapper End

//////////////// Session-timeout index — timing wheel ////////////////
//
// init_timeout_milestones_index() returns the per-handler timeout index the
// wrappers below operate on; see the "Session-timeout ring" block above for
// the design. All operations are O(1) with zero allocations on the hot path.

extern "C" void * init_timeout_milestones_index(void) {
    try {
        mmt_timeout_ring * r = (mmt_timeout_ring *) malloc(sizeof(mmt_timeout_ring));
        if (r == NULL) return NULL;
        r->milestones = 0;
        r->slots = (mmt_timeout_slot *) calloc(MMT_RING_INITIAL_CAP, sizeof(mmt_timeout_slot));
        if (r->slots == NULL) { free(r); return NULL; }
        r->cap = MMT_RING_INITIAL_CAP;
        return reinterpret_cast<void *>(r);
    } catch (...) {
        return NULL;
    }
}

extern "C" void timeout_iteration_callback(mmt_handler_t *mmt_handler, generic_mapspace_iteration_callback fct) {
    try {
        if (mmt_handler == NULL || fct == NULL) return;
        mmt_timeout_ring * r = reinterpret_cast<mmt_timeout_ring *> (mmt_handler->timeout_milestones_map);
        if (r == NULL || r->slots == NULL) return;
        mmt_ring_iterate(r, fct, mmt_handler);
    } catch (...) {
        return;
    }
}

extern "C" void session_timer_iteration_callback(mmt_handler_t *mmt_handler, generic_mapspace_iteration_callback fct) {
    try {
        if (mmt_handler == NULL || fct == NULL) return;
        mmt_timeout_ring * r = reinterpret_cast<mmt_timeout_ring *> (mmt_handler->timeout_milestones_map);
        if (r == NULL || r->slots == NULL) return;
        mmt_ring_iterate(r, fct, mmt_handler);
    } catch (...) {
        return;
    }
}


extern "C" int update_session_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t new_timeout, uint32_t old_timeout, mmt_session_t * session) {
    try {
        if (mmt_handler == NULL || session == NULL) return 0;
        mmt_timeout_ring * r = reinterpret_cast<mmt_timeout_ring *> (mmt_handler->timeout_milestones_map);
        if (r == NULL || r->slots == NULL) return 0;

        mmt_ring_unlink(r, old_timeout, session);
        //printf("From update session timeout milestone, trying to add session %i to milestone %u\n", session->session_id, new_timeout);
        return insert_session_timeout_milestone(mmt_handler, new_timeout, session);
    } catch (...) {
        return 0;
    }
}

extern "C" int force_session_timeout(mmt_handler_t *mmt_handler, mmt_session_t * session) {
    try {
        if (mmt_handler == NULL || session == NULL) return 0;
        mmt_timeout_ring * r = reinterpret_cast<mmt_timeout_ring *> (mmt_handler->timeout_milestones_map);
        if (r == NULL || r->slots == NULL) return 0;
        return mmt_ring_unlink(r, session->session_timeout_milestone, session);
    } catch (...) {
        return 0;
    }
}

extern "C" int insert_session_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t timeout, mmt_session_t * session) {
    try {
        if (mmt_handler == NULL || session == NULL) return 0;
        mmt_timeout_ring * r = reinterpret_cast<mmt_timeout_ring *> (mmt_handler->timeout_milestones_map);
        if (r == NULL || r->slots == NULL) return 0;

        for (;;) {
            mmt_timeout_slot * s = &r->slots[(size_t) timeout & (r->cap - 1)];
            if (s->head == NULL) {
                // Fresh milestone: claim the slot. No allocation — the session
                // itself carries the list links.
                s->milestone = timeout;
                s->head      = session;
                session->next     = NULL;
                session->previous = NULL;
                r->milestones++;
                return 1;
            }
            if (s->milestone == timeout) {
                // Existing milestone: prepend on its intrusive list.
                session->previous = NULL;
                session->next     = s->head;
                s->head->previous = session;
                s->head           = session;
                return 1;
            }
            // Slot owned by a different live milestone: the live milestone span
            // reached the ring capacity — grow until the span fits (bounded,
            // single-relink) or fail cleanly like the old map's OOM.
            if (mmt_ring_grow(r, timeout) == 0) return 0;
        }
    } catch (...) {
        return 0;
    }
}

extern "C" mmt_session_t * get_timed_out_session_list(mmt_handler_t *mmt_handler, uint32_t timeout) {
    try {
        if (mmt_handler == NULL) return NULL;
        mmt_timeout_ring * r = reinterpret_cast<mmt_timeout_ring *> (mmt_handler->timeout_milestones_map);
        if (r == NULL || r->slots == NULL) return NULL;
        mmt_timeout_slot * s = &r->slots[(size_t) timeout & (r->cap - 1)];
        if (s->head != NULL && s->milestone == timeout) {
            return s->head;
        }
        return NULL;
    } catch (...) {
        return NULL;
    }
}

extern "C" int delete_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t timeout) {
    try {
        if (mmt_handler == NULL) return 0;
        mmt_timeout_ring * r = reinterpret_cast<mmt_timeout_ring *> (mmt_handler->timeout_milestones_map);
        if (r == NULL || r->slots == NULL) return 0;
        mmt_timeout_slot * s = &r->slots[(size_t) timeout & (r->cap - 1)];
        if (s->head != NULL && s->milestone == timeout) {
            s->head = NULL;
            r->milestones--;
        }
        return 1;
    } catch (...) {
        return 0;
    }
}

extern "C" void clear_timeout_milestones(mmt_handler_t *mmt_handler) {
    try {
        if (mmt_handler == NULL) return;
        mmt_timeout_ring * r = reinterpret_cast<mmt_timeout_ring *> (mmt_handler->timeout_milestones_map);
        if (r != NULL) {
            free(r->slots);
            free(r);
            // Issue #200 (F-BUG-005): NULL the field after deleting so a second
            // teardown cannot dereference the dangling pointer.
            mmt_handler->timeout_milestones_map = NULL;
        }
    } catch (...) {
        return;
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

static mmt_int_map * get_protocol_stack_map() {
    if (protocol_stack_map == NULL) {
        protocol_stack_map = init_int_map_space(protocol_stack_id_comp_fn_pt);
    }
    return reinterpret_cast<mmt_int_map*>(protocol_stack_map);
}

extern "C" void iterate_through_protocol_stacks(generic_mapspace_iteration_callback fct, void * args) {
    try {
        // Snapshot before dispatching (see the F-BUG-004 note above);
        // int_mapspace_iteration_callback early-outs on a NULL map.
        int_mapspace_iteration_callback(protocol_stack_map, fct, args);
    } catch (...) {
        return;
    }
}

extern "C" int insert_protocol_stack_into_map(uint32_t key, void * value) {
    try {
        return insert_int_key_value(get_protocol_stack_map(), key, value);
    } catch (...) {
        return 0;
    }
}

extern "C" void * get_protocol_stack_from_map(uint32_t key) {
    try {
        // Read path: NULL map means "no stack registered" — never create one.
        return find_int_key_value(protocol_stack_map, key);
    } catch (...) {
        return NULL;
    }
}

extern "C" int delete_protocol_stack_from_map(uint32_t key) {
    try {
        return delete_int_key_value(protocol_stack_map, key);
    } catch (...) {
        return 0;
    }
}

extern "C" void clear_protocol_stack_map() {
    try {
        mmt_int_map * m = reinterpret_cast<mmt_int_map *> (protocol_stack_map);
        if (m != NULL) {
            free(m->slots);
            free(m);
            protocol_stack_map = NULL;
        }
    } catch (...) {
        return;
    }
}

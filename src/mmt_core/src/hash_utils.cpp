#include "hash_utils.h"
#include <map>
#include <new>
#include <cstdint>
#include <cstddef>

using namespace std;

//////////////// Wrapper

typedef std::map<void *, void *, bool(*)(void *, void *) > MMT_Map;
typedef std::map<uint32_t, void *, bool(*)(uint32_t, uint32_t)> MMT_IntMap;

//////////////// Per-flow session store ////////////////
//
// An open-addressing (linear-probing) hash table keyed on a packed 5-tuple,
// replacing the previous O(log n) std::map<void*,void*> session store
// (issue #17). Open addressing keeps the slots in one contiguous array, so a
// lookup is a cache-friendly linear scan rather than the pointer-chasing of a
// red-black tree or a chained hash map — the property that actually makes this
// the biggest hot-path win.
//
// Correctness vs. the old std::map: equality is derived from the protocol's
// strict-weak-ordering comparison function exactly as std::map computed
// equivalence — two keys are the same entry iff neither compares less than the
// other — so classification is byte-for-byte unchanged. The per-slot cached
// hash is compared first, so the (relatively expensive) comparison function is
// only invoked on a hash match. The hash function must be consistent with that
// equality (equal keys hash equally); a NULL hash degrades to a correct but
// slow constant hash rather than crashing.

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

// Slots are 16 bytes (two pointers) so four pack into a 64-byte cache line —
// the dense layout is what makes linear probing fast. Empty/tombstone states
// are encoded in the key pointer rather than a separate field: real session
// keys are heap-allocated mmt_session_t structures, so NULL and the 0x1
// sentinel can never collide with a live key.
static void * const MMT_SLOT_EMPTY = NULL;
static void * const MMT_SLOT_TOMB  = reinterpret_cast<void *>(static_cast<uintptr_t>(1));

struct mmt_session_slot {
    void * key;
    void * value;
};

struct mmt_session_table {
    mmt_session_slot *     slots;
    size_t                 cap;        // power of two
    size_t                 size;       // live (occupied) slots
    size_t                 used;       // occupied + tombstones (drives resize)
    generic_comparison_fct comp;
    generic_hash_fct       hash;

    uint64_t hash_of(void * k) const {
        return mmt_mix64(hash ? hash(k) : 0);
    }
    // Equivalence as std::map computed it from a strict weak ordering: two keys
    // are the same entry iff neither orders before the other.
    bool key_equal(void * a, void * b) const {
        return !comp(a, b) && !comp(b, a);
    }
};

static const size_t MMT_SESSION_INITIAL_CAP = 16; // power of two

static void mmt_session_alloc_slots(mmt_session_table * t, size_t cap) {
    t->slots = (mmt_session_slot *) calloc(cap, sizeof(mmt_session_slot));
    if (t->slots == NULL) { t->cap = 0; return; }
    t->cap   = cap;
    // calloc zero-fills -> every slot's key is NULL (MMT_SLOT_EMPTY).
}

// Insert a known-unique key into a tombstone-free table (used during resize).
static void mmt_session_put_raw(mmt_session_table * t, void * key, void * value) {
    size_t mask = t->cap - 1;
    size_t i = (size_t) t->hash_of(key) & mask;
    while (t->slots[i].key != MMT_SLOT_EMPTY) {
        i = (i + 1) & mask;
    }
    t->slots[i].key   = key;
    t->slots[i].value = value;
}

static void mmt_session_resize(mmt_session_table * t, size_t new_cap) {
    mmt_session_slot * old = t->slots;
    size_t old_cap = t->cap;
    mmt_session_alloc_slots(t, new_cap);
    // F-BUG-001 (issue #199): on allocation failure the table is left as it
    // was — mmt_session_alloc_slots signals failure with slots == NULL/cap == 0
    // and rehashing into it would index a NULL array at mask == SIZE_MAX.
    if (t->slots == NULL) {
        t->slots = old;
        t->cap   = old_cap;
        return;
    }
    t->used = t->size; // tombstones dropped on rehash
    for (size_t i = 0; i < old_cap; i++) {
        void * k = old[i].key;
        if (k != MMT_SLOT_EMPTY && k != MMT_SLOT_TOMB) {
            mmt_session_put_raw(t, k, old[i].value);
        }
    }
    free(old);
}

} // namespace

void * init_session_map_space(generic_comparison_fct comp_fct, generic_hash_fct hash_fct) {
    mmt_session_table * t = (mmt_session_table *) malloc(sizeof(mmt_session_table));
    if (t == NULL) return NULL;
    t->size = 0;
    t->used = 0;
    t->comp = comp_fct;
    t->hash = hash_fct;
    mmt_session_alloc_slots(t, MMT_SESSION_INITIAL_CAP);
    if (t->slots == NULL) { free(t); return NULL; }
    return reinterpret_cast<void *>(t);
}

void delete_session_map_space(void * sessionmap) {
    mmt_session_table * t = reinterpret_cast<mmt_session_table *>(sessionmap);
    if (t == NULL) return;
    free(t->slots);
    free(t);
}

void * init_map_space(generic_comparison_fct comp_fct) {
    return reinterpret_cast<void*> (new (std::nothrow) MMT_Map(comp_fct));
}

void * init_int_map_space(generic_int_comparison_fct comp_fct) {
    return reinterpret_cast<void*> (new (std::nothrow) MMT_IntMap(comp_fct));
}

int getmapsize(void * maplist) {
    MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);
    return m->size();
}

int insert_key_value(void * maplist, void * key, void * value) {
    pair < map<void *, void *>::iterator, bool> ret;
    MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);

    ret = m->insert(std::pair<void *, void *>(key, value));
    if (ret.second == false) {
        printf("FROM InsertSession got a problem: hash_utils.cpp - insert_key_value() \n");
        return 0;
    }
    return 1;
}

int insert_int_key_value(void * maplist, uint32_t key, void * value) {
    pair < map<uint32_t, void *>::iterator, bool> ret;
    MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (maplist);

    ret = m->insert(std::pair<uint32_t, void *>(key, value));
    if (ret.second == false) {
        printf("FROM InsertSession got a problem: hash_utils.cpp - insert_int_key_value() \n");
        return 0;
    }
    return 1;
}

int insert_session_into_protocol_context(void * protocol_context, void * key, void * value) {
    // F-BUG-001 (issue #199): early-out on a missing or dead table — cap == 0
    // means the slot allocation failed, and mask = cap - 1 would wrap to
    // SIZE_MAX on a NULL slots array.
    if (protocol_context == NULL) return 0;
    mmt_session_table * t = reinterpret_cast<mmt_session_table *>(((protocol_instance_t *) protocol_context)->sessions_map);
    if (t == NULL || t->cap == 0 || t->slots == NULL) return 0;

    // Keep the load factor <= 0.7. Grow only when the live population is dense;
    // if the slots are mostly tombstones (delete-heavy churn from session
    // timeouts) rehash in place at the same capacity to reclaim them.
    if ((t->used + 1) * 10 >= t->cap * 7) {
        size_t new_cap = (t->size * 2 >= t->cap) ? (t->cap << 1) : t->cap;
        mmt_session_resize(t, new_cap);
    }

    // A table with no EMPTY slot at all would loop forever below; this can only
    // happen while the allocator keeps failing (the grow above is refused).
    if (t->used >= t->cap) return 0;

    size_t mask = t->cap - 1;
    size_t i = (size_t) t->hash_of(key) & mask;
    size_t tomb = 0;
    bool have_tomb = false;
    void * k;
    while ((k = t->slots[i].key) != MMT_SLOT_EMPTY) {
        if (k == MMT_SLOT_TOMB) {
            if (!have_tomb) { tomb = i; have_tomb = true; }
        } else if (t->key_equal(k, key)) {
            // Duplicate key: mirror the old std::map behaviour (no overwrite).
            printf("FROM InsertSession got a problem: hash_utils.cpp - insert_session_into_protocol_context() \n");
            return 0;
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

int update_key_value(void * maplist, void * key, void * new_value) {
    map<void *, void *>::iterator it;
    MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);
    it = m->find(key);
    if (it != m->end()) {
        (*it).second = new_value;
        return 1;
    } else {
        return 0;
    }
}

void * find_key_value(void * maplist, void * key) {
    map<void *, void *>::iterator it;
    MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);
    it = m->find(key);
    if (it != m->end()) {
        return (*it).second;
    } else {
        return NULL;
    }
}

void * find_int_key_value(void * maplist, uint32_t key) {
    map<uint32_t, void *>::iterator it;
    MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (maplist);
    it = m->find(key);
    if (it != m->end()) {
        return (*it).second;
    } else {
        return NULL;
    }
}

void * get_session_from_protocol_context_by_session_key(void * protocol_context, void * key) {
    // F-BUG-001 (issue #199): early-out on a missing or dead table (cap == 0).
    if (protocol_context == NULL) return NULL;
    mmt_session_table * t = reinterpret_cast<mmt_session_table *>(((protocol_instance_t *) protocol_context)->sessions_map);
    if (t == NULL || t->cap == 0 || t->slots == NULL) return NULL;
    size_t mask = t->cap - 1;
    size_t i = (size_t) t->hash_of(key) & mask;
    void * k;
    // Bounded probe: a table with no EMPTY slot (full under sustained OOM)
    // must not spin forever.
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

int delete_key_value(void * maplist, void * key) {
    map<void *, void *>::iterator it;
    MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);
    it = m->find(key);
    if (likely( it != m->end())) {
        m->erase(it);
    }
    return 1;
}

int delete_int_key_value(void * maplist, uint32_t key) {
    map<uint32_t, void *>::iterator it;
    MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (maplist);
    it = m->find(key);
    if (it != m->end()) {
        m->erase(it);
    }
    return 1;
}

int delete_session_from_protocol_context(void * protocol_context, void * key) {
    // F-BUG-001 (issue #199): early-out on a missing or dead table (cap == 0).
    if (protocol_context == NULL) return 1; // mirrors the not-found return
    mmt_session_table * t = reinterpret_cast<mmt_session_table *>(((protocol_instance_t *) protocol_context)->sessions_map);
    if (t == NULL || t->cap == 0 || t->slots == NULL) return 1;
    size_t mask = t->cap - 1;
    size_t i = (size_t) t->hash_of(key) & mask;
    void * k;
    // Bounded probe, same full-table safeguard as the lookup above.
    for (size_t n = 0; n < t->cap; n++) {
        k = t->slots[i].key;
        if (k == MMT_SLOT_EMPTY) break;
        if (k != MMT_SLOT_TOMB && t->key_equal(k, key)) {
            // Tombstone the slot: a probe sequence may run through it, so it
            // cannot be reset to EMPTY (that would truncate later lookups).
            t->slots[i].key   = MMT_SLOT_TOMB;
            t->slots[i].value = NULL;
            t->size--;
            return 1;
        }
        i = (i + 1) & mask;
    }
    return 1; // not found: mirror the old delete_key_value (always returns 1)
}

void clear_map_space(void * maplist) {
    MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);
    m->clear();
}

void clear_int_map_space(void * maplist) {
    MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (maplist);
    m->clear();
}

void delete_map_space(void * maplist) {
    MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);
    clear_map_space(maplist);
    delete m;
}

void delete_int_map_space(void * maplist) {
    MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (maplist);
    clear_int_map_space(maplist);
    delete m;
}


void clear_sessions_from_protocol_context(void * protocol_context) {
    mmt_session_table * t = reinterpret_cast<mmt_session_table *>(((protocol_instance_t *) protocol_context)->sessions_map);
    if (t != NULL && t->slots != NULL) {
        memset(t->slots, 0, t->cap * sizeof(mmt_session_slot)); // every key -> NULL (empty)
        t->size = 0;
        t->used = 0;
    }
}

void mapspace_iteration_callback(void * maplist, generic_mapspace_iteration_callback fct, void * args) {
    map<void *, void *>::iterator it;
    MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);
    for (it = m->begin(); it != m->end(); it++) {
        fct((*it).first, (*it).second, args);
    }
}

void int_mapspace_iteration_callback(void * maplist, generic_mapspace_iteration_callback fct, void * args) {
    map<uint32_t, void *>::iterator it;
    MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (maplist);
    for (it = m->begin(); it != m->end(); it++) {
        fct(NULL, (*it).second, args); //TODO
    }
}

void protocol_sessions_iteration_callback(void * protocol_context, generic_mapspace_iteration_callback fct, void * args) {
    mmt_session_table * t = reinterpret_cast<mmt_session_table *>(((protocol_instance_t *) protocol_context)->sessions_map);
    if (t != NULL && t->slots != NULL) {
        for (size_t i = 0; i < t->cap; i++) {
            void * k = t->slots[i].key;
            if (k != MMT_SLOT_EMPTY && k != MMT_SLOT_TOMB) {
                fct(k, t->slots[i].value, args);
            }
        }
    }
}
//////////////// Wrapper End

bool session_timeout_comp_fn_pt(uint32_t l_timeout, uint32_t r_timeout) {
    return (l_timeout < r_timeout);
}

void timeout_iteration_callback(mmt_handler_t *mmt_handler, generic_mapspace_iteration_callback fct) {
    map<uint32_t, void *>::iterator it;
    MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (mmt_handler->timeout_milestones_map);
    for (it = m->begin(); it != m->end(); it++) {
        fct(NULL, (*it).second, mmt_handler);
    }
}

void session_timer_iteration_callback(mmt_handler_t *mmt_handler, generic_mapspace_iteration_callback fct) {
    map<uint32_t, void *>::iterator it;
    MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (mmt_handler->timeout_milestones_map);
    for (it = m->begin(); it != m->end(); it++) {
        fct(NULL, (*it).second, mmt_handler);
    }
}


int update_session_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t new_timeout, uint32_t old_timeout, mmt_session_t * session) {
    map<uint32_t, void *>::iterator it;
    MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (mmt_handler->timeout_milestones_map);

    it = m->find(old_timeout);
    if (it != m->end()) {
        //printf("From update session timeout milestone, removing session %i from milestone %u\n", session->session_id, old_timeout);
        //session already existed in the old
        if ((*it).second == session) {
            if (session->next == NULL) {
                // This is the only session with this timeout milestone! delete this milestone!
                (*it).second = NULL;
                delete_timeout_milestone(mmt_handler, old_timeout);
            } else {
                (*it).second = session->next;
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
    }
    //printf("From update session timeout milestone, trying to add session %i to milestone %u\n", session->session_id, new_timeout);
    return insert_session_timeout_milestone(mmt_handler, new_timeout, session);

}

int force_session_timeout(mmt_handler_t *mmt_handler, mmt_session_t * session) {
    map<uint32_t, void *>::iterator it;
    MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (mmt_handler->timeout_milestones_map);

    it = m->find(session->session_timeout_milestone);
    if (it != m->end()) {
        if ((*it).second == session) {
            if (session->next == NULL) {
                // This is the only session with this timeout milestone! delete this milestone!
                (*it).second = NULL;
                delete_timeout_milestone(mmt_handler, session->session_timeout_milestone);
            } else {
                (*it).second = session->next;
                session->next->previous = NULL;
            }
        } else {
            // F-BUG-011 (issue #199): same unlink guard — previous may be NULL
            // for a session that was never linked into this milestone's list.
            if (session->previous != NULL) {
                session->previous->next = session->next;
            }
            if (session->next != NULL) {
                session->next->previous = session->previous;
            }
        }
        return 1;
    }
    return 0;
}

int insert_session_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t timeout, mmt_session_t * session) {
    map<uint32_t, void *>::iterator it;
    mmt_session_t * session_list;
    MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (mmt_handler->timeout_milestones_map);
    it = m->find(timeout);
    if (it != m->end()) {
        // printf("\nInsert session %i in EXISTING timeout milestone %u \n", session->session_id, timeout);
        session_list = (mmt_session_t *) (*it).second;
        session->previous = NULL;
        session->next = session_list;
        // F-BUG-011 (issue #199): the milestone may exist with a NULL head.
        if (session_list != NULL) {
            session_list->previous = session;
        }
        (*it).second = (void *) session;
        return 1;
    } else {
        // printf("\nInsert session %i in timeout milestone %u \n", session->session_id, timeout);
        pair<map<uint32_t, void *>::iterator, bool> ret;
        session->next = NULL;
        session->previous = NULL;
        ret = m->insert(pair<uint32_t, void *>(timeout, (void *) session));
        if (ret.second == false) {
            // printf("\nError occurred in insert session timeout milesotne\n");
            return 0;
        }
        return 1;
    }
}

mmt_session_t * get_timed_out_session_list(mmt_handler_t *mmt_handler, uint32_t timeout) {
    map<uint32_t, void *>::iterator it;
    MMT_IntMap * m = reinterpret_cast<MMT_IntMap*> (mmt_handler->timeout_milestones_map);
    it = m->find(timeout);
    if (it != m->end()) {
        return (mmt_session_t *) (*it).second;
    } else {
        return NULL;
    }
}

int delete_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t timeout) {
    map<uint32_t, void *>::iterator it;
    MMT_IntMap * m = reinterpret_cast<MMT_IntMap*> (mmt_handler->timeout_milestones_map);
    it = m->find(timeout);
    if (it != m->end()) {
        m->erase(it);
    }
    return 1;
}

void clear_timeout_milestones(mmt_handler_t *mmt_handler) {
    MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (mmt_handler->timeout_milestones_map);
    m->clear();
    delete m;
}


/////// Protocol stack map

bool protocol_stack_id_comp_fn_pt(uint32_t ps1, uint32_t ps2) {
    return (ps1 < ps2);
}

static void * protocol_stack_map = init_int_map_space(protocol_stack_id_comp_fn_pt);

void iterate_through_protocol_stacks(generic_mapspace_iteration_callback fct, void * args) {
    map<uint32_t, void *>::iterator it;
    MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (protocol_stack_map);
    for (it = m->begin(); it != m->end(); it++) {
        fct(NULL, (*it).second, args); //TODO
    }
}

int insert_protocol_stack_into_map(uint32_t key, void * value) {
    return insert_int_key_value(protocol_stack_map, key, value);
}

void * get_protocol_stack_from_map(uint32_t key) {
    return find_int_key_value(protocol_stack_map, key);
}

int delete_protocol_stack_from_map(uint32_t key) {
    return delete_int_key_value(protocol_stack_map, key);
}

void clear_protocol_stack_map() {
    MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (protocol_stack_map);
    m->clear();
    delete m;
}

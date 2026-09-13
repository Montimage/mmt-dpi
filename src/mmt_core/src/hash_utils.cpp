#include "hash_utils.h"
#include <map>
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
// tables. An escaping exception (std::map inserts can throw std::bad_alloc)
// cannot be caught there and reaches std::terminate, killing the host
// process — so every definition is explicitly marked with C linkage and wraps
// its body in try/catch(...) returning the failure value of its return type
// (NULL / 0 / nothing). A NULL map pointer is likewise treated as a failure:
// callers that ignore an init_*_map_space() failure get a safe no-op instead
// of a NULL dereference.

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
            mmt_session_put_raw(t, k, old[i].value);
        }
    }
    free(old);
}

} // namespace

extern "C" void * init_session_map_space(generic_comparison_fct comp_fct, generic_hash_fct hash_fct) {
    try {
        mmt_session_table * t = (mmt_session_table *) malloc(sizeof(mmt_session_table));
        if (t == NULL) return NULL;
        t->size = 0;
        t->used = 0;
        t->comp = comp_fct;
        t->hash = hash_fct;
        mmt_session_alloc_slots(t, MMT_SESSION_INITIAL_CAP);
        if (t->slots == NULL) { free(t); return NULL; }
        return reinterpret_cast<void *>(t);
    } catch (...) {
        return NULL;
    }
}

extern "C" void delete_session_map_space(void * sessionmap) {
    try {
        mmt_session_table * t = reinterpret_cast<mmt_session_table *>(sessionmap);
        if (t == NULL) return;
        free(t->slots);
        free(t);
    } catch (...) {
        return;
    }
}

extern "C" void * init_map_space(generic_comparison_fct comp_fct) {
    try {
        return reinterpret_cast<void*> (new (std::nothrow) MMT_Map(comp_fct));
    } catch (...) {
        return NULL;
    }
}

extern "C" void * init_int_map_space(generic_int_comparison_fct comp_fct) {
    try {
        return reinterpret_cast<void*> (new (std::nothrow) MMT_IntMap(comp_fct));
    } catch (...) {
        return NULL;
    }
}

extern "C" int getmapsize(void * maplist) {
    try {
        MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);
        if (m == NULL) return 0;
        return m->size();
    } catch (...) {
        return 0;
    }
}

extern "C" int insert_key_value(void * maplist, void * key, void * value) {
    try {
        pair < map<void *, void *>::iterator, bool> ret;
        MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);
        if (m == NULL) return 0;

        ret = m->insert(std::pair<void *, void *>(key, value));
        if (ret.second == false) {
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
        pair < map<uint32_t, void *>::iterator, bool> ret;
        MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (maplist);
        if (m == NULL) return 0;

        ret = m->insert(std::pair<uint32_t, void *>(key, value));
        if (ret.second == false) {
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
        mmt_session_table * t = reinterpret_cast<mmt_session_table *>(((protocol_instance_t *) protocol_context)->sessions_map);
        if (t == NULL || t->slots == NULL || t->cap == 0) return 0;

        // Keep the load factor <= 0.7. Grow only when the live population is dense;
        // if the slots are mostly tombstones (delete-heavy churn from session
        // timeouts) rehash in place at the same capacity to reclaim them.
        if ((t->used + 1) * 10 >= t->cap * 7) {
            size_t new_cap = (t->size * 2 >= t->cap) ? (t->cap << 1) : t->cap;
            mmt_session_resize(t, new_cap);
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
    } catch (...) {
        return 0;
    }
}

extern "C" int update_key_value(void * maplist, void * key, void * new_value) {
    try {
        map<void *, void *>::iterator it;
        MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);
        if (m == NULL) return 0;
        it = m->find(key);
        if (it != m->end()) {
            (*it).second = new_value;
            return 1;
        } else {
            return 0;
        }
    } catch (...) {
        return 0;
    }
}

extern "C" void * find_key_value(void * maplist, void * key) {
    try {
        map<void *, void *>::iterator it;
        MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);
        if (m == NULL) return NULL;
        it = m->find(key);
        if (it != m->end()) {
            return (*it).second;
        } else {
            return NULL;
        }
    } catch (...) {
        return NULL;
    }
}

extern "C" void * find_int_key_value(void * maplist, uint32_t key) {
    try {
        map<uint32_t, void *>::iterator it;
        MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (maplist);
        if (m == NULL) return NULL;
        it = m->find(key);
        if (it != m->end()) {
            return (*it).second;
        } else {
            return NULL;
        }
    } catch (...) {
        return NULL;
    }
}

extern "C" void * get_session_from_protocol_context_by_session_key(void * protocol_context, void * key) {
    try {
        if (protocol_context == NULL) return NULL;
        mmt_session_table * t = reinterpret_cast<mmt_session_table *>(((protocol_instance_t *) protocol_context)->sessions_map);
        if (t == NULL || t->slots == NULL || t->cap == 0) return NULL;
        size_t mask = t->cap - 1;
        size_t i = (size_t) t->hash_of(key) & mask;
        void * k;
        while ((k = t->slots[i].key) != MMT_SLOT_EMPTY) {
            if (k != MMT_SLOT_TOMB && t->key_equal(k, key)) {
                return t->slots[i].value;
            }
            i = (i + 1) & mask;
        }
        return NULL;
    } catch (...) {
        return NULL;
    }
}

extern "C" int delete_key_value(void * maplist, void * key) {
    try {
        map<void *, void *>::iterator it;
        MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);
        if (m == NULL) return 0;
        it = m->find(key);
        if (likely( it != m->end())) {
            m->erase(it);
        }
        return 1;
    } catch (...) {
        return 0;
    }
}

extern "C" int delete_int_key_value(void * maplist, uint32_t key) {
    try {
        map<uint32_t, void *>::iterator it;
        MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (maplist);
        if (m == NULL) return 0;
        it = m->find(key);
        if (it != m->end()) {
            m->erase(it);
        }
        return 1;
    } catch (...) {
        return 0;
    }
}

extern "C" int delete_session_from_protocol_context(void * protocol_context, void * key) {
    try {
        if (protocol_context == NULL) return 0;
        mmt_session_table * t = reinterpret_cast<mmt_session_table *>(((protocol_instance_t *) protocol_context)->sessions_map);
        if (t == NULL || t->slots == NULL || t->cap == 0) return 0;
        size_t mask = t->cap - 1;
        size_t i = (size_t) t->hash_of(key) & mask;
        void * k;
        while ((k = t->slots[i].key) != MMT_SLOT_EMPTY) {
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
    } catch (...) {
        return 0;
    }
}

extern "C" void clear_map_space(void * maplist) {
    try {
        MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);
        if (m == NULL) return;
        m->clear();
    } catch (...) {
        return;
    }
}

extern "C" void clear_int_map_space(void * maplist) {
    try {
        MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (maplist);
        if (m == NULL) return;
        m->clear();
    } catch (...) {
        return;
    }
}

extern "C" void delete_map_space(void * maplist) {
    try {
        MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);
        if (m == NULL) return;
        m->clear();
        delete m;
    } catch (...) {
        return;
    }
}

extern "C" void delete_int_map_space(void * maplist) {
    try {
        MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (maplist);
        if (m == NULL) return;
        m->clear();
        delete m;
    } catch (...) {
        return;
    }
}


extern "C" void clear_sessions_from_protocol_context(void * protocol_context) {
    try {
        if (protocol_context == NULL) return;
        mmt_session_table * t = reinterpret_cast<mmt_session_table *>(((protocol_instance_t *) protocol_context)->sessions_map);
        if (t != NULL && t->slots != NULL) {
            memset(t->slots, 0, t->cap * sizeof(mmt_session_slot)); // every key -> NULL (empty)
            t->size = 0;
            t->used = 0;
        }
    } catch (...) {
        return;
    }
}

/* Issue #200 (F-BUG-004): the dispatch callbacks may erase the map entry (or
 * tombstone the table slot) they are invoked on — e.g. close_extraction()
 * iterates mmt_configured_handlers_map via iterate_through_mmt_handlers()
 * and mmt_close_handler() deletes its own node, after which `it++` advanced
 * a dangling iterator. Every iteration helper therefore snapshots the
 * key/value pairs into a vector first, then dispatches: mutations during a
 * callback affect the map, never the snapshot being walked. */
extern "C" void mapspace_iteration_callback(void * maplist, generic_mapspace_iteration_callback fct, void * args) {
    try {
        MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);
        if (m == NULL || fct == NULL) return;
        vector<pair<void *, void *> > entries;
        entries.reserve(m->size());
        for (map<void *, void *>::iterator it = m->begin(); it != m->end(); ++it) {
            entries.push_back(make_pair(it->first, it->second));
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
        MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (maplist);
        if (m == NULL || fct == NULL) return;
        vector<void *> values;
        values.reserve(m->size());
        for (map<uint32_t, void *>::iterator it = m->begin(); it != m->end(); ++it) {
            values.push_back(it->second);
        }
        for (size_t i = 0; i < values.size(); i++) {
            fct(NULL, values[i], args); //TODO
        }
    } catch (...) {
        return;
    }
}

extern "C" void protocol_sessions_iteration_callback(void * protocol_context, generic_mapspace_iteration_callback fct, void * args) {
    try {
        if (protocol_context == NULL || fct == NULL) return;
        mmt_session_table * t = reinterpret_cast<mmt_session_table *>(((protocol_instance_t *) protocol_context)->sessions_map);
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

// NOTE (issue #200): the C++ duplicate of session_timeout_comp_fn_pt() that
// used to live here was removed — the canonical definition is the C one in
// packet_processing.c; the dead duplicate would have collided with it once
// given C linkage.

extern "C" void timeout_iteration_callback(mmt_handler_t *mmt_handler, generic_mapspace_iteration_callback fct) {
    try {
        if (mmt_handler == NULL || fct == NULL) return;
        MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (mmt_handler->timeout_milestones_map);
        if (m == NULL) return;
        // Snapshot: the callback (force_sessions_timeout) deletes the milestone
        // it is invoked on, which used to leave `it` dangling before `it++`.
        vector<void *> values;
        values.reserve(m->size());
        for (map<uint32_t, void *>::iterator it = m->begin(); it != m->end(); ++it) {
            values.push_back(it->second);
        }
        for (size_t i = 0; i < values.size(); i++) {
            fct(NULL, values[i], mmt_handler);
        }
    } catch (...) {
        return;
    }
}

extern "C" void session_timer_iteration_callback(mmt_handler_t *mmt_handler, generic_mapspace_iteration_callback fct) {
    try {
        if (mmt_handler == NULL || fct == NULL) return;
        MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (mmt_handler->timeout_milestones_map);
        if (m == NULL) return;
        vector<void *> values;
        values.reserve(m->size());
        for (map<uint32_t, void *>::iterator it = m->begin(); it != m->end(); ++it) {
            values.push_back(it->second);
        }
        for (size_t i = 0; i < values.size(); i++) {
            fct(NULL, values[i], mmt_handler);
        }
    } catch (...) {
        return;
    }
}


extern "C" int update_session_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t new_timeout, uint32_t old_timeout, mmt_session_t * session) {
    try {
        map<uint32_t, void *>::iterator it;
        if (mmt_handler == NULL || session == NULL) return 0;
        MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (mmt_handler->timeout_milestones_map);
        if (m == NULL) return 0;

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
                session->previous->next = session->next;
                if (session->next != NULL) {
                    session->next->previous = session->previous;
                }
            }
        }
        //printf("From update session timeout milestone, trying to add session %i to milestone %u\n", session->session_id, new_timeout);
        return insert_session_timeout_milestone(mmt_handler, new_timeout, session);
    } catch (...) {
        return 0;
    }
}

extern "C" int force_session_timeout(mmt_handler_t *mmt_handler, mmt_session_t * session) {
    try {
        map<uint32_t, void *>::iterator it;
        if (mmt_handler == NULL || session == NULL) return 0;
        MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (mmt_handler->timeout_milestones_map);
        if (m == NULL) return 0;

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
                session->previous->next = session->next;
                if (session->next != NULL) {
                    session->next->previous = session->previous;
                }
            }
            return 1;
        }
        return 0;
    } catch (...) {
        return 0;
    }
}

extern "C" int insert_session_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t timeout, mmt_session_t * session) {
    try {
        map<uint32_t, void *>::iterator it;
        mmt_session_t * session_list;
        if (mmt_handler == NULL || session == NULL) return 0;
        MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (mmt_handler->timeout_milestones_map);
        if (m == NULL) return 0;
        it = m->find(timeout);
        if (it != m->end()) {
            // printf("\nInsert session %i in EXISTING timeout milestone %u \n", session->session_id, timeout);
            session_list = (mmt_session_t *) (*it).second;
            session->previous = NULL;
            session->next = session_list;
            session_list->previous = session;
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
    } catch (...) {
        return 0;
    }
}

extern "C" mmt_session_t * get_timed_out_session_list(mmt_handler_t *mmt_handler, uint32_t timeout) {
    try {
        map<uint32_t, void *>::iterator it;
        if (mmt_handler == NULL) return NULL;
        MMT_IntMap * m = reinterpret_cast<MMT_IntMap*> (mmt_handler->timeout_milestones_map);
        if (m == NULL) return NULL;
        it = m->find(timeout);
        if (it != m->end()) {
            return (mmt_session_t *) (*it).second;
        } else {
            return NULL;
        }
    } catch (...) {
        return NULL;
    }
}

extern "C" int delete_timeout_milestone(mmt_handler_t *mmt_handler, uint32_t timeout) {
    try {
        map<uint32_t, void *>::iterator it;
        if (mmt_handler == NULL) return 0;
        MMT_IntMap * m = reinterpret_cast<MMT_IntMap*> (mmt_handler->timeout_milestones_map);
        if (m == NULL) return 0;
        it = m->find(timeout);
        if (it != m->end()) {
            m->erase(it);
        }
        return 1;
    } catch (...) {
        return 0;
    }
}

extern "C" void clear_timeout_milestones(mmt_handler_t *mmt_handler) {
    try {
        if (mmt_handler == NULL) return;
        MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (mmt_handler->timeout_milestones_map);
        if (m != NULL) {
            m->clear();
            delete m;
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

static MMT_IntMap * get_protocol_stack_map() {
    if (protocol_stack_map == NULL) {
        protocol_stack_map = init_int_map_space(protocol_stack_id_comp_fn_pt);
    }
    return reinterpret_cast<MMT_IntMap*>(protocol_stack_map);
}

extern "C" void iterate_through_protocol_stacks(generic_mapspace_iteration_callback fct, void * args) {
    try {
        MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (protocol_stack_map);
        if (m == NULL || fct == NULL) return;
        // Snapshot before dispatching (see the F-BUG-004 note above).
        vector<void *> values;
        values.reserve(m->size());
        for (map<uint32_t, void *>::iterator it = m->begin(); it != m->end(); ++it) {
            values.push_back(it->second);
        }
        for (size_t i = 0; i < values.size(); i++) {
            fct(NULL, values[i], args); //TODO
        }
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
        MMT_IntMap* m = reinterpret_cast<MMT_IntMap*> (protocol_stack_map);
        if (m != NULL) {
            m->clear();
            delete m;
            protocol_stack_map = NULL;
        }
    } catch (...) {
        return;
    }
}

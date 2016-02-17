#include "hash_utils.h"
#include <map>

using namespace std;

//////////////// Wrapper

typedef std::map<void *, void *, bool(*)(void *, void *) > MMT_Map;
typedef std::map<uint32_t, void *, bool(*)(uint32_t, uint32_t)> MMT_IntMap;

void * init_map_space(generic_comparison_fct comp_fct) {
    return reinterpret_cast<void*> (new MMT_Map(comp_fct));
}

void * init_int_map_space(generic_int_comparison_fct comp_fct) {
    return reinterpret_cast<void*> (new MMT_IntMap(comp_fct));
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
    return insert_key_value(((protocol_instance_t *) protocol_context)->sessions_map, key, value);
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
    return find_key_value(((protocol_instance_t *) protocol_context)->sessions_map, key);
}

int delete_key_value(void * maplist, void * key) {
    map<void *, void *>::iterator it;
    MMT_Map* m = reinterpret_cast<MMT_Map*> (maplist);
    it = m->find(key);
    if (it != m->end()) {
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
    return delete_key_value(((protocol_instance_t *) protocol_context)->sessions_map, key);
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
    return clear_map_space(((protocol_instance_t *) protocol_context)->sessions_map);
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
    if(((protocol_instance_t *) protocol_context)->sessions_map != NULL)
        mapspace_iteration_callback(((protocol_instance_t *) protocol_context)->sessions_map, fct, args);
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
            session->previous->next = session->next;
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
            session->previous->next = session->next;
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

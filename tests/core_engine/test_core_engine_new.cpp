/*
 * test_core_engine_new.cpp — C++ allocation failure injection for the
 * core-engine suite (issue #241).
 *
 * hash_utils.cpp still allocates through operator new in one place: the
 * std::vector snapshots taken by the iteration callbacks (issue #200,
 * F-BUG-004). Those calls are not reachable via -Wl,--wrap=malloc, so this
 * TU keeps replacing the global new/delete with budgeted versions — the
 * budget also stays a tripwire for any C++ allocation that creeps back into
 * the store implementations (issue #254 removed the tree nodes entirely):
 *
 *   ce_set_new_budget(-1)  unlimited (default)
 *   ce_set_new_budget( 0)  every new fails — throwing new raises
 *                          std::bad_alloc (caught by the extern-C wrappers in
 *                          hash_utils.cpp, which return their failure value);
 *                          nothrow new returns nullptr.
 *   ce_set_new_budget( N)  the next N news succeed, the rest fail.
 *
 * Allocation is routed to __real_malloc directly (not malloc) so the C budget
 * in test_core_engine.c (--wrap=malloc) is not disturbed by C++ traffic.
 */
#include <cstddef>
#include <cstdlib>
#include <new>

extern "C" void *__real_malloc(std::size_t size);
extern "C" void free(void *ptr);

static long g_new_budget = -1;

extern "C" void ce_set_new_budget(long budget) { g_new_budget = budget; }

static inline bool new_allowed() {
    if (g_new_budget == 0) return false;
    if (g_new_budget > 0) g_new_budget--;
    return true;
}

void *operator new(std::size_t size) {
    if (!new_allowed()) throw std::bad_alloc();
    void *p = __real_malloc(size);
    if (p == NULL) throw std::bad_alloc();
    return p;
}
void *operator new[](std::size_t size) {
    if (!new_allowed()) throw std::bad_alloc();
    void *p = __real_malloc(size);
    if (p == NULL) throw std::bad_alloc();
    return p;
}
void *operator new(std::size_t size, const std::nothrow_t &) noexcept {
    if (!new_allowed()) return NULL;
    return __real_malloc(size);
}
void *operator new[](std::size_t size, const std::nothrow_t &) noexcept {
    if (!new_allowed()) return NULL;
    return __real_malloc(size);
}
void operator delete(void *p) noexcept { free(p); }
void operator delete[](void *p) noexcept { free(p); }
void operator delete(void *p, std::size_t) noexcept { free(p); }
void operator delete[](void *p, std::size_t) noexcept { free(p); }
void operator delete(void *p, const std::nothrow_t &) noexcept { free(p); }
void operator delete[](void *p, const std::nothrow_t &) noexcept { free(p); }

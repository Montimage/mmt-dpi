/*
 * fi_alloc.c — allocation-failure interposer + accounting core (issue #216).
 *
 * Built two ways from this single source:
 *   -DFI_INTERPOSE : shared library exporting malloc/calloc/realloc/free that
 *                    forward to the real libc symbols (RTLD_NEXT) and feed the
 *                    accounting core below. Loaded via LD_PRELOAD so the
 *                    installed SDK, its plugins and libstdc++ operator new are
 *                    all covered.
 *   (no define)    : emits fiu_malloc/fiu_calloc/fiu_realloc/fiu_free, meant to
 *                    be reached through -Dmalloc=fiu_malloc ... on a specific
 *                    source file under test.
 *
 * Accounting model: a fixed open-addressed table records every live pointer.
 * Pointers allocated while armed are tagged "window"; fi_window_leaked()
 * reports how many window-tagged blocks are still outstanding — i.e. net
 * leaked by the code under test, independent of global/runtime allocations.
 * A freed slot becomes a tombstone: freeing it again (or a pointer never
 * tracked) is reported through fi_double_free_count().
 *
 * The table never grows and never allocates, so the hooks are safe to call
 * recursively (e.g. from libc internals reached through our own malloc).
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef FI_INTERPOSE
#include <dlfcn.h>
#endif
#include "fi_alloc.h"

/* ------------------------------------------------------------------ *
 *  Accounting core                                                     *
 * ------------------------------------------------------------------ */

#define FI_TABLE_BITS 20 /* 1 M slots — far above any observed process usage */
#define FI_TABLE_SIZE ((size_t)1 << FI_TABLE_BITS)
#define FI_TABLE_MASK (FI_TABLE_SIZE - 1)

enum { FI_EMPTY = 0, FI_LIVE_BG = 1, FI_LIVE_WIN = 2, FI_TOMB = 3 };

typedef struct {
    void          *ptr;
    unsigned char  state;
} fi_slot_t;

static fi_slot_t fi_table[FI_TABLE_SIZE];

static int      fi_armed;
static uint64_t fi_fail_at;
static uint64_t fi_count;   /* allocation calls attempted while armed */
static uint64_t fi_failed;  /* forced failures */
static int64_t  fi_win_live;
static int      fi_dfrees;

static size_t fi_hash(void *p)
{
    uintptr_t x = (uintptr_t)p;
    x >>= 4; /* heap pointers are 16-aligned */
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 29;
    return (size_t)x & FI_TABLE_MASK;
}

static fi_slot_t *fi_find(void *p)
{
    size_t i = fi_hash(p);
    for (size_t k = 0; k < FI_TABLE_SIZE; k++) {
        fi_slot_t *s = &fi_table[(i + k) & FI_TABLE_MASK];
        if (s->state == FI_EMPTY || s->ptr == p)
            return s;
    }
    return NULL; /* table full — should not happen */
}

static void fi_track(void *p)
{
    fi_slot_t *s = fi_find(p);
    if (!s)
        return;
    if (s->state == FI_EMPTY || s->state == FI_TOMB) {
        s->ptr   = p;
        s->state = fi_armed ? FI_LIVE_WIN : FI_LIVE_BG;
        if (fi_armed)
            fi_win_live++;
    } else {
        /* allocator handed back a pointer still marked live: a real heap
         * corruption signature — count it as a bookkeeping double event. */
        fi_dfrees++;
    }
}

/* Returns 1 when the free should be forwarded to the real allocator. */
static int fi_track_free(void *p)
{
    fi_slot_t *s = fi_find(p);
    if (s && s->ptr == p && s->state != FI_EMPTY) {
        if (s->state == FI_TOMB) {
            fi_dfrees++;
            return 0; /* swallow the second free */
        }
        if (s->state == FI_LIVE_WIN)
            fi_win_live--;
        s->state = FI_TOMB;
        return 1;
    }
    /* Never tracked: allocated before our hooks ran (e.g. by the dynamic
     * loader) — pass through untouched, do not count it. */
    return 1;
}

static int fi_try_fail(void)
{
    if (!fi_armed)
        return 0;
    fi_count++;
    if (fi_fail_at != 0 && fi_count == fi_fail_at) {
        fi_failed++;
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ *
 *  Control API                                                         *
 * ------------------------------------------------------------------ */

void fi_begin(uint64_t fail_at)
{
    fi_count   = 0;
    fi_fail_at = fail_at;
    fi_armed   = 1;
}

uint64_t fi_end(void)
{
    fi_armed = 0;
    return fi_count;
}

int64_t fi_window_leaked(void)
{
    return fi_win_live;
}

int fi_double_free_count(void)
{
    return fi_dfrees;
}

uint64_t fi_failed_allocs(void)
{
    return fi_failed;
}

/* ------------------------------------------------------------------ *
 *  Front-ends                                                          *
 * ------------------------------------------------------------------ */

#ifdef FI_INTERPOSE

static void *(*real_malloc)(size_t);
static void *(*real_calloc)(size_t, size_t);
static void *(*real_realloc)(void *, size_t);
static void  (*real_free)(void *);

/* Allocations performed while dlsym itself resolves symbols (or before the
 * constructor ran) are served from a small never-freed bump arena. */
static char   fi_boot[1 << 20];
static size_t fi_boot_off;
static int    fi_resolving;

static void *fi_boot_alloc(size_t n)
{
    n = (n + 15) & ~(size_t)15;
    if (fi_boot_off + n > sizeof(fi_boot))
        return NULL;
    void *p = fi_boot + fi_boot_off;
    fi_boot_off += n;
    return p;
}

static int fi_is_boot(void *p)
{
    return p >= (void *)fi_boot && p < (void *)(fi_boot + sizeof(fi_boot));
}

static void fi_resolve(void)
{
    if (real_malloc || fi_resolving)
        return;
    fi_resolving = 1;
    real_malloc  = dlsym(RTLD_NEXT, "malloc");
    real_calloc  = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_free    = dlsym(RTLD_NEXT, "free");
    fi_resolving = 0;
}

__attribute__((constructor)) static void fi_ctor(void)
{
    fi_resolve();
}

void *malloc(size_t n)
{
    if (fi_resolving || !real_malloc) {
        if (!fi_resolving)
            fi_resolve();
        return fi_boot_alloc(n);
    }
    if (fi_try_fail())
        return NULL;
    void *p = real_malloc(n);
    if (p)
        fi_track(p);
    return p;
}

void *calloc(size_t nm, size_t sz)
{
    if (fi_resolving || !real_calloc) {
        if (!fi_resolving)
            fi_resolve();
        void *p = fi_boot_alloc(nm * sz);
        if (p)
            memset(p, 0, nm * sz);
        return p;
    }
    if (fi_try_fail())
        return NULL;
    void *p = real_calloc(nm, sz);
    if (p)
        fi_track(p);
    return p;
}

void *realloc(void *p, size_t n)
{
    if (fi_resolving || !real_realloc) {
        if (!fi_resolving)
            fi_resolve();
        return fi_boot_alloc(n); /* lose old contents — bootstrap only */
    }
    if (!p)
        return malloc(n);
    if (fi_is_boot(p))
        return fi_boot_alloc(n);
    if (fi_try_fail())
        return NULL; /* original block stays valid — still tracked */
    fi_slot_t *s = fi_find(p);
    unsigned char was = (s && s->ptr == p) ? s->state : FI_EMPTY;
    void *q = real_realloc(p, n);
    if (!q)
        return NULL; /* p still owned by caller, keep its state */
    /* real_realloc may return p unchanged or a fresh pointer. */
    if (q != p) {
        if (was == FI_LIVE_WIN)
            fi_win_live--;
        if (s && s->ptr == p)
            s->state = FI_TOMB;
        fi_track(q);
    }
    return q;
}

void free(void *p)
{
    if (!p)
        return;
    if (fi_is_boot(p))
        return;
    if (!real_free || fi_resolving)
        return;
    if (fi_track_free(p))
        real_free(p);
}

#else /* !FI_INTERPOSE — unit-mode front-ends */

void *fiu_malloc(size_t n)
{
    if (fi_try_fail())
        return NULL;
    void *p = malloc(n);
    if (p)
        fi_track(p);
    return p;
}

void *fiu_calloc(size_t nm, size_t sz)
{
    if (fi_try_fail())
        return NULL;
    void *p = calloc(nm, sz);
    if (p)
        fi_track(p);
    return p;
}

void *fiu_realloc(void *p, size_t n)
{
    if (!p)
        return fiu_malloc(n);
    if (fi_try_fail())
        return NULL;
    fi_slot_t *s = fi_find(p);
    unsigned char was = (s && s->ptr == p) ? s->state : FI_EMPTY;
    void *q = realloc(p, n);
    if (!q)
        return NULL;
    if (q != p) {
        if (was == FI_LIVE_WIN)
            fi_win_live--;
        if (s && s->ptr == p)
            s->state = FI_TOMB;
        fi_track(q);
    }
    return q;
}

void fiu_free(void *p)
{
    if (!p)
        return;
    if (fi_track_free(p))
        free(p);
}

#endif /* FI_INTERPOSE */

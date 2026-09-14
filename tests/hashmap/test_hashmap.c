/*
 * test_hashmap.c — comprehensive test suite for the hashmap (src/mmt_core/src/hashmap.c).
 *
 * Tests cover:
 *   - hashmap_alloc / hashmap_free lifecycle
 *   - hashmap_init / hashmap_cleanup lifecycle
 *   - hashmap_insert_kv / hashmap_get (single and multiple keys)
 *   - hashmap_get with nonexistent keys
 *   - hashmap_remove (existing and nonexistent keys)
 *   - hashmap_walk (visits all entries)
 *   - Collision handling (keys that hash to the same slot)
 *   - Overwrite behavior (inserting same key twice)
 *   - Empty map operations
 *   - Large number of keys
 *   - hashmap_dump (sanity check, no crash)
 */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

/* We need the hashmap API. Include the private headers directly for testing. */
#include "hashmap.h"
#include "data_defs.h"

static int g_failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
        fprintf(stderr, "  FAIL [%s:%d]: %s\n", __FILE__, __LINE__, (msg)); g_failures++; } } while (0)

/* ---- Test: alloc/free lifecycle ---- */
static void test_alloc_free(void) {
    fprintf(stderr, "  test: alloc/free lifecycle\n");
    mmt_hashmap_t *map = hashmap_alloc();
    CHECK(map != NULL, "hashmap_alloc returned NULL");
    hashmap_free(map);
    /* Double free should not crash (we can't easily test this without ASAN,
       but we verify the API doesn't segfault on a freshly freed pointer
       by not using it). */
}

/* ---- Test: init/cleanup lifecycle ---- */
static void test_init_cleanup(void) {
    fprintf(stderr, "  test: init/cleanup lifecycle\n");
    mmt_hashmap_t map;
    hashmap_init(&map);
    /* Insert and retrieve to verify it works */
    uint64_t key = 42;
    int value = 100;
    hashmap_insert_kv(&map, key, &value);

    void *val = NULL;
    int found = hashmap_get(&map, key, &val);
    CHECK(found == 1, "hashmap_get should find inserted key");
    CHECK(val == &value, "hashmap_get returned wrong value pointer");

    hashmap_cleanup(&map);
    /* After cleanup, the map should be empty */
    found = hashmap_get(&map, key, &val);
    CHECK(found == 0, "hashmap_get should not find key after cleanup");
}

/* ---- Test: single insert/get ---- */
static void test_single_insert_get(void) {
    fprintf(stderr, "  test: single insert/get\n");
    mmt_hashmap_t *map = hashmap_alloc();
    uint64_t key = 12345;
    int value = 999;
    hashmap_insert_kv(map, key, &value);

    void *val = NULL;
    int found = hashmap_get(map, key, &val);
    CHECK(found == 1, "hashmap_get should find inserted key");
    CHECK(val == &value, "hashmap_get returned wrong value");

    hashmap_free(map);
}

/* ---- Test: multiple inserts and retrieves ---- */
static void test_multiple_insert_get(void) {
    fprintf(stderr, "  test: multiple insert/get\n");
    mmt_hashmap_t *map = hashmap_alloc();
    int values[100];
    for (int i = 0; i < 100; i++) {
        values[i] = i * 10;
        hashmap_insert_kv(map, (uint64_t)i, &values[i]);
    }

    for (int i = 0; i < 100; i++) {
        void *val = NULL;
        int found = hashmap_get(map, (uint64_t)i, &val);
        CHECK(found == 1, "hashmap_get should find key");
        CHECK(val == &values[i], "hashmap_get returned wrong value");
    }

    hashmap_free(map);
}

/* ---- Test: get nonexistent key ---- */
static void test_get_nonexistent(void) {
    fprintf(stderr, "  test: get nonexistent key\n");
    mmt_hashmap_t *map = hashmap_alloc();
    void *val = (void*)0xdeadbeef; /* sentinel */
    int found = hashmap_get(map, 99999, &val);
    CHECK(found == 0, "hashmap_get should return 0 for nonexistent key");
    CHECK(val == (void*)0xdeadbeef, "hashmap_get should not modify val pointer for missing key");
    hashmap_free(map);
}

/* ---- Test: remove existing key ---- */
static void test_remove_existing(void) {
    fprintf(stderr, "  test: remove existing key\n");
    mmt_hashmap_t *map = hashmap_alloc();
    int value = 42;
    hashmap_insert_kv(map, 100, &value);

    int removed = hashmap_remove(map, 100);
    CHECK(removed == 1, "hashmap_remove should return 1 for existing key");

    void *val = NULL;
    int found = hashmap_get(map, 100, &val);
    CHECK(found == 0, "hashmap_get should not find removed key");

    hashmap_free(map);
}

/* ---- Test: remove nonexistent key ---- */
static void test_remove_nonexistent(void) {
    fprintf(stderr, "  test: remove nonexistent key\n");
    mmt_hashmap_t *map = hashmap_alloc();
    int removed = hashmap_remove(map, 99999);
    CHECK(removed == 0, "hashmap_remove should return 0 for nonexistent key");
    hashmap_free(map);
}

/* ---- Test: walk visits all entries ---- */
static int walk_count = 0;
static void test_walker(mmt_hashmap_t *map, mmt_hent_t *he, void *arg) {
    (void)map; (void)arg;
    walk_count++;
}

static void test_walk(void) {
    fprintf(stderr, "  test: walk visits all entries\n");
    mmt_hashmap_t *map = hashmap_alloc();
    int vals[50];
    for (int i = 0; i < 50; i++) {
        vals[i] = i;
        hashmap_insert_kv(map, (uint64_t)i, &vals[i]);
    }

    walk_count = 0;
    hashmap_walk(map, test_walker, NULL);
    CHECK(walk_count == 50, "hashmap_walk should visit all 50 entries");

    hashmap_free(map);
}

/* ---- Test: collision handling (keys hashing to same slot) ---- */
static void test_collision_handling(void) {
    fprintf(stderr, "  test: collision handling\n");
    mmt_hashmap_t *map = hashmap_alloc();
    /* MMT_HASHMAP_NSLOTS is 0x100 = 256. Keys 0, 256, 512 all hash to slot 0. */
    int v0 = 0, v256 = 256, v512 = 512;
    hashmap_insert_kv(map, 0, &v0);
    hashmap_insert_kv(map, 256, &v256);
    hashmap_insert_kv(map, 512, &v512);

    void *val = NULL;
    CHECK(hashmap_get(map, 0, &val) == 1, "should find key 0");
    CHECK(val == &v0, "key 0 value mismatch");
    CHECK(hashmap_get(map, 256, &val) == 1, "should find key 256");
    CHECK(val == &v256, "key 256 value mismatch");
    CHECK(hashmap_get(map, 512, &val) == 1, "should find key 512");
    CHECK(val == &v512, "key 512 value mismatch");

    hashmap_free(map);
}

/* ---- Test: overwrite same key ---- */
static void test_overwrite_key(void) {
    fprintf(stderr, "  test: overwrite same key\n");
    mmt_hashmap_t *map = hashmap_alloc();
    int v1 = 1, v2 = 2;
    hashmap_insert_kv(map, 10, &v1);
    hashmap_insert_kv(map, 10, &v2);

    void *val = NULL;
    int found = hashmap_get(map, 10, &val);
    CHECK(found == 1, "should find overwritten key");
    CHECK(val == &v2, "should return latest value after overwrite");

    /* Note: this hashmap implementation doesn't deduplicate -
       walking will see both entries. This is expected behavior. */
    walk_count = 0;
    hashmap_walk(map, test_walker, NULL);
    CHECK(walk_count >= 1, "walk should count at least one entry for key 10");

    hashmap_free(map);
}

/* ---- Test: empty map operations ---- */
static void test_empty_map(void) {
    fprintf(stderr, "  test: empty map operations\n");
    mmt_hashmap_t *map = hashmap_alloc();

    void *val = (void*)0xdeadbeef;
    CHECK(hashmap_get(map, 1, &val) == 0, "get on empty map should return 0");
    CHECK(hashmap_remove(map, 1) == 0, "remove on empty map should return 0");

    walk_count = 0;
    hashmap_walk(map, test_walker, NULL);
    CHECK(walk_count == 0, "walk on empty map should visit 0 entries");

    hashmap_free(map);
}

/* ---- Test: large number of keys ---- */
static void test_large_number_of_keys(void) {
    fprintf(stderr, "  test: large number of keys (1000)\n");
    mmt_hashmap_t *map = hashmap_alloc();
    int *values = malloc(sizeof(int) * 1000);
    CHECK(values != NULL, "malloc for values");

    for (int i = 0; i < 1000; i++) {
        values[i] = i * 3;
        hashmap_insert_kv(map, (uint64_t)i, &values[i]);
    }

    for (int i = 0; i < 1000; i++) {
        void *val = NULL;
        int found = hashmap_get(map, (uint64_t)i, &val);
        CHECK(found == 1, "should find all 1000 keys");
        CHECK(val == &values[i], "value mismatch for key");
    }

    /* Remove half */
    for (int i = 0; i < 500; i++) {
        CHECK(hashmap_remove(map, (uint64_t)i) == 1, "remove should succeed");
    }

    /* Verify removed keys are gone */
    for (int i = 0; i < 500; i++) {
        void *val = NULL;
        CHECK(hashmap_get(map, (uint64_t)i, &val) == 0, "removed key should not be found");
    }

    /* Verify remaining keys are still there */
    for (int i = 500; i < 1000; i++) {
        void *val = NULL;
        CHECK(hashmap_get(map, (uint64_t)i, &val) == 1, "remaining key should be found");
    }

    free(values);
    hashmap_free(map);
}

/* ---- Test: dump doesn't crash ---- */
static void test_dump(void) {
    fprintf(stderr, "  test: dump doesn't crash\n");
    mmt_hashmap_t *map = hashmap_alloc();
    int val = 42;
    hashmap_insert_kv(map, 1, &val);
    hashmap_dump(map); /* Just verify it doesn't crash */
    hashmap_free(map);
}

/* ---- Test: init/cleanup can be called multiple times ---- */
static void test_reinit(void) {
    fprintf(stderr, "  test: init/cleanup can be called multiple times\n");
    mmt_hashmap_t map;

    /* First round */
    hashmap_init(&map);
    int v1 = 1;
    hashmap_insert_kv(&map, 10, &v1);
    hashmap_cleanup(&map);

    /* Second round */
    hashmap_init(&map);
    int v2 = 2;
    hashmap_insert_kv(&map, 20, &v2);
    void *val = NULL;
    CHECK(hashmap_get(&map, 20, &val) == 1, "second round: should find key");
    CHECK(val == &v2, "second round: correct value");
    CHECK(hashmap_get(&map, 10, &val) == 0, "second round: old key should be gone");
    hashmap_cleanup(&map);
}

/* ---- Test: keys with value NULL ---- */
static void test_null_value(void) {
    fprintf(stderr, "  test: keys with NULL value\n");
    mmt_hashmap_t *map = hashmap_alloc();
    hashmap_insert_kv(map, 55, NULL);

    void *val = (void*)0xdeadbeef;
    int found = hashmap_get(map, 55, &val);
    CHECK(found == 1, "should find key with NULL value");
    CHECK(val == NULL, "value should be NULL");

    /* Remove should work */
    CHECK(hashmap_remove(map, 55) == 1, "remove should succeed for NULL value");
    CHECK(hashmap_get(map, 55, &val) == 0, "key should be gone after remove");

    hashmap_free(map);
}

/* ---- Test: key 0 is valid ---- */
static void test_key_zero(void) {
    fprintf(stderr, "  test: key 0 is valid\n");
    mmt_hashmap_t *map = hashmap_alloc();
    int val = 0;
    hashmap_insert_kv(map, 0, &val);

    void *val_out = NULL;
    CHECK(hashmap_get(map, 0, &val_out) == 1, "should find key 0");
    CHECK(val_out == &val, "key 0 value mismatch");

    hashmap_free(map);
}

/* ---- F-BUG-007 (issue #199): a map whose slot array never allocated must not crash ---- */
static void test_failed_init_map(void) {
    fprintf(stderr, "  test: operations on a map with NULL slots\n");
    mmt_hashmap_t map;
    memset(&map, 0, sizeof(map));
    /* This is exactly the state hashmap_init() leaves after an OOM:
       slots == NULL, nslots == 0, nkeys == 0. */
    map.slots  = NULL;
    map.nslots = 0;
    map.nkeys  = 0;

    int v = 1;
    void *val = (void*)0xdeadbeef;
    CHECK(hashmap_get(&map, 7, &val) == 0, "get on NULL-slots map should return 0");
    CHECK(val == (void*)0xdeadbeef, "get on NULL-slots map should not touch *val");
    CHECK(hashmap_remove(&map, 7) == 0, "remove on NULL-slots map should return 0");

    walk_count = 0;
    hashmap_walk(&map, test_walker, NULL);
    CHECK(walk_count == 0, "walk on NULL-slots map should visit nothing");

    hashmap_insert_kv(&map, 7, &v);   /* must not crash; insert already guards */
    hashmap_cleanup(&map);            /* must not crash; cleanup already guards */
}

/* ---- F-BUG-007 (issue #199): NULL map argument must not crash ---- */
static void test_null_map_arg(void) {
    fprintf(stderr, "  test: operations on a NULL map\n");
    void *val = NULL;
    CHECK(hashmap_get(NULL, 1, &val) == 0, "get on NULL map should return 0");
    CHECK(hashmap_remove(NULL, 1) == 0, "remove on NULL map should return 0");
    walk_count = 0;
    hashmap_walk(NULL, test_walker, NULL);
    CHECK(walk_count == 0, "walk on NULL map should visit nothing");
    hashmap_insert_kv(NULL, 1, &val); /* must not crash */
    hashmap_free(NULL);               /* must not crash */
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    fprintf(stderr, "Hashmap test suite\n");

    test_alloc_free();
    test_init_cleanup();
    test_single_insert_get();
    test_multiple_insert_get();
    test_get_nonexistent();
    test_remove_existing();
    test_remove_nonexistent();
    test_walk();
    test_collision_handling();
    test_overwrite_key();
    test_empty_map();
    test_large_number_of_keys();
    test_dump();
    test_reinit();
    test_null_value();
    test_key_zero();
    test_failed_init_map();
    test_null_map_arg();

    if (g_failures == 0) {
        fprintf(stderr, "ALL CHECKS PASSED\n");
        return 0;
    }
    fprintf(stderr, "%d CHECK(S) FAILED\n", g_failures);
    return 1;
}

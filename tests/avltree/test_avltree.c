/*
 * test_avltree.c — self-contained correctness + micro-benchmark harness for the
 * AVL tree (src/mmt_tcpip/lib/avltree.c). Written for issue #21
 * ("Cache AVL heights / bottom-up build").
 *
 * It is deliberately portable across BOTH the pre-fix and post-fix sources:
 * it only touches the public avltree API (avltree_create / avltree_insert /
 * avltree_find / avltree_valid / avltree_get_height / avltree_size), never the
 * struct's internal `height` field. This lets run_tests.sh compile the SAME
 * test against the old and new avltree.c and prove the tree SHAPE is identical.
 *
 * Modes:
 *   (default)        run the correctness suite, exit non-zero on any failure.
 *   --bench N [R]    build an N-node tree R times (default R=1), print the
 *                    elapsed milliseconds and a shape fingerprint to stdout.
 *   --fingerprint N  build an N-node tree with the fixed PRNG, print only the
 *                    preorder shape fingerprint (key/left/right) — used to diff
 *                    old-vs-new tree shape.
 *
 * Correctness checks (per random tree):
 *   1. avltree_get_height(node,1) == brute-force recomputed height, for EVERY
 *      node. In the post-fix build avltree_get_height returns the cached value,
 *      so this asserts the cache is exactly correct. In the pre-fix build it
 *      asserts the recomputation — trivially true — keeping the test portable.
 *   2. avltree_valid(root) == 1 (every subtree balance factor in [-1,1]).
 *   3. Every inserted key is found by avltree_find; a key never inserted is not.
 *   4. In-order traversal is strictly increasing (BST ordering preserved).
 *   5. avltree_size(root) == number of distinct keys inserted.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "avltree.h"

/* ---- a tiny deterministic PRNG so old and new builds see identical keys ---- */
static uint64_t rng_state;
static void rng_seed(uint64_t s) { rng_state = s ? s : 0x9E3779B97F4A7C15ULL; }
static uint32_t rng_next(void) {
    /* xorshift64* */
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return (uint32_t)((rng_state * 0x2545F4914F6CDD1DULL) >> 32);
}

/* ---- brute-force (uncached) height: 0 for empty, 1 for a leaf ---- */
static int brute_height(avltree_t *n) {
    if (n == NULL) return 0;
    int l = brute_height(n->left_child);
    int r = brute_height(n->right_child);
    return 1 + (l > r ? l : r);
}

static int g_failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
        fprintf(stderr, "  FAIL: %s\n", (msg)); g_failures++; } } while (0)

/* Verify cached height (via public getter) equals the brute-force height. */
static void check_heights(avltree_t *n) {
    if (n == NULL) return;
    int cached = avltree_get_height(n, 1);
    int actual = brute_height(n);
    if (cached != actual) {
        fprintf(stderr, "  FAIL: height mismatch at key %u: getter=%d brute=%d\n",
                n->key, cached, actual);
        g_failures++;
    }
    check_heights(n->left_child);
    check_heights(n->right_child);
}

/* In-order traversal must be strictly increasing. */
static int check_inorder(avltree_t *n, long *prev) {
    if (n == NULL) return 1;
    if (!check_inorder(n->left_child, prev)) return 0;
    if ((long)n->key <= *prev) {
        fprintf(stderr, "  FAIL: inorder not sorted at key %u (prev %ld)\n",
                n->key, *prev);
        return 0;
    }
    *prev = (long)n->key;
    return check_inorder(n->right_child, prev);
}

/* Preorder fingerprint of the tree shape: (key,Lkey,Rkey) per node. */
static void fingerprint(avltree_t *n, FILE *out) {
    if (n == NULL) return;
    fprintf(out, "%u,%u,%u\n", n->key,
            n->left_child  ? n->left_child->key  : 0,
            n->right_child ? n->right_child->key : 0);
    fingerprint(n->left_child, out);
    fingerprint(n->right_child, out);
}

/* Build a tree of `n` distinct keys with the deterministic PRNG (seed fixed). */
static avltree_t *build_tree(int n, uint32_t **out_keys, int *out_count) {
    rng_seed(0xC0FFEE123456789ULL);
    avltree_t *root = NULL;
    uint32_t *keys = malloc(sizeof(uint32_t) * (size_t)n);
    int count = 0;
    for (int i = 0; i < n; i++) {
        uint32_t k = rng_next();
        if (k == 0) k = 1; /* key 0 is the "empty" sentinel in callers */
        /* skip duplicates so size == count is exact */
        if (avltree_find(root, k) != NULL) continue;
        avltree_t *node = avltree_create(k, NULL);
        root = avltree_insert(root, node);
        keys[count++] = k;
    }
    if (out_keys) *out_keys = keys; else free(keys);
    if (out_count) *out_count = count;
    return root;
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static int run_correctness(void) {
    const int sizes[] = { 1, 2, 3, 8, 64, 1000, 10000 };
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        int n = sizes[s];
        uint32_t *keys = NULL;
        int count = 0;
        avltree_t *root = build_tree(n, &keys, &count);

        check_heights(root);
        CHECK(avltree_valid(root) == 1, "tree is not a valid AVL tree");
        CHECK(avltree_size(root) == count, "size != number of distinct keys");

        long prev = -1;
        CHECK(check_inorder(root, &prev) == 1, "inorder traversal not sorted");

        for (int i = 0; i < count; i++)
            CHECK(avltree_find(root, keys[i]) != NULL, "inserted key not found");

        /* a key the PRNG path won't have produced for this run */
        CHECK(avltree_find(root, 0) == NULL, "spurious find of sentinel key 0");

        free(keys);
        avltree_free_tree(root);
        fprintf(stderr, "  ok: n=%d distinct=%d\n", n, count);
    }
    return g_failures;
}

/* Issue #212 (F-BUG-027): inserting a node whose key already exists must not
 * lose the existing subtree. The duplicate branch used to return
 * avltree_get_root(node) — and an unlinked node is its own root — so the
 * `tree = avltree_insert(tree, node)` idiom silently replaced the whole tree
 * with the orphan node. This case pins both the tree preservation and the
 * explicit duplicate signal added by avltree_insert_ex(). */
static int run_duplicate_key_case(void) {
    fprintf(stderr, "== duplicate-key case (issue #212 / F-BUG-027) ==\n");

    uint32_t *keys = NULL;
    int count = 0;
    avltree_t *root = build_tree(256, &keys, &count);
    int size_before = avltree_size(root);

    /* 1. duplicate via the classic 2-arg API: must return the EXISTING root */
    avltree_t *dup1 = avltree_create(keys[0], NULL);
    avltree_t *ret1 = avltree_insert(root, dup1);
    CHECK(ret1 == root, "duplicate insert (2-arg) must keep the existing root");
    CHECK(avltree_size(root) == size_before, "duplicate insert must not change tree size");
    for (int i = 0; i < count; i++)
        CHECK(avltree_find(root, keys[i]) != NULL, "subtree lost after duplicate insert");
    CHECK(avltree_valid(root) == 1, "tree invalid after duplicate insert");
    CHECK(avltree_find(root, keys[0]) != dup1, "duplicate node must NOT be linked");
    avltree_free_node(dup1); /* unlinked duplicate stays caller-owned */

    /* 2. avltree_insert_ex signals the duplicate and still keeps the root */
    int is_dup = 0;
    avltree_t *dup2 = avltree_create(keys[count - 1], NULL);
    avltree_t *ret2 = avltree_insert_ex(root, dup2, &is_dup);
    CHECK(is_dup == 1, "avltree_insert_ex must flag the duplicate key");
    CHECK(ret2 == root, "duplicate insert (_ex) must keep the existing root");
    CHECK(avltree_size(root) == size_before, "duplicate insert (_ex) must not change tree size");
    for (int i = 0; i < count; i++)
        CHECK(avltree_find(root, keys[i]) != NULL, "subtree lost after duplicate _ex insert");
    avltree_free_node(dup2);

    /* 3. a non-duplicate _ex insert reports 0 and grows the tree */
    uint32_t fresh_key = 0xDEADBEEFu;
    while (avltree_find(root, fresh_key) != NULL) fresh_key++;
    is_dup = 1;
    avltree_t *fresh = avltree_create(fresh_key, NULL);
    root = avltree_insert_ex(root, fresh, &is_dup);
    CHECK(is_dup == 0, "avltree_insert_ex must not flag a fresh key");
    CHECK(avltree_size(root) == size_before + 1, "fresh insert (_ex) must grow the tree");
    CHECK(avltree_find(root, fresh_key) == fresh, "fresh key not found after _ex insert");
    CHECK(avltree_valid(root) == 1, "tree invalid after _ex insert");

    /* 4. duplicate at the ROOT key itself */
    avltree_t *dup_root = avltree_create(root->key, NULL);
    is_dup = 0;
    avltree_t *ret4 = avltree_insert_ex(root, dup_root, &is_dup);
    CHECK(is_dup == 1, "root-key duplicate must be flagged");
    CHECK(ret4 == root, "root-key duplicate must keep the existing root");
    avltree_free_node(dup_root);

    /* 5. duplicate insert into an EMPTY tree is a plain insert */
    is_dup = 1;
    avltree_t *lone = avltree_create(42, NULL);
    avltree_t *t5 = avltree_insert_ex(NULL, lone, &is_dup);
    CHECK(is_dup == 0 && t5 == lone, "insert into empty tree must link the node");
    avltree_free_tree(t5);

    free(keys);
    avltree_free_tree(root);
    fprintf(stderr, "  ok: duplicate-key case done\n");
    return g_failures;
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "--bench") == 0) {
        int n = atoi(argv[2]);
        int reps = (argc >= 4) ? atoi(argv[3]) : 1;
        if (reps < 1) reps = 1;
        double best = 1e18;
        avltree_t *root = NULL;
        for (int r = 0; r < reps; r++) {
            double t0 = now_ms();
            root = build_tree(n, NULL, NULL);
            double dt = now_ms() - t0;
            if (dt < best) best = dt;
            if (r + 1 < reps) avltree_free_tree(root);
        }
        printf("build n=%d best_of=%d time_ms=%.3f\n", n, reps, best);
        avltree_free_tree(root);
        return 0;
    }
    if (argc >= 3 && strcmp(argv[1], "--fingerprint") == 0) {
        int n = atoi(argv[2]);
        avltree_t *root = build_tree(n, NULL, NULL);
        fingerprint(root, stdout);
        avltree_free_tree(root);
        return 0;
    }

    fprintf(stderr, "AVL tree correctness suite\n");
    int fails = run_correctness();
    fails += run_duplicate_key_case();
    if (fails == 0) {
        fprintf(stderr, "ALL CHECKS PASSED\n");
        return 0;
    }
    fprintf(stderr, "%d CHECK(S) FAILED\n", fails);
    return 1;
}


#include <stdio.h>  // printf()

#include "packet_processing.h"
#include "hashmap.h"
#include "hexdump.h"


//  - - - - - - - - - - - -  //
//  D E C L A R A T I O N S  //
//  - - - - - - - - - - - -  //

static void hslot_init(mmt_hslot_t *slot);
static void hslot_free(mmt_hslot_t *slot);

static mmt_hent_t *hent_new(void);
static void hent_free(mmt_hent_t *he);

static mmt_hent_t *hmap_lookup(mmt_hashmap_t *map, mmt_key_t key);

static void hmap_dump_entry(mmt_hashmap_t *map, mmt_hent_t *he, void *arg);


//  - - - - - - - - - - - - - -  //
//  P U B L I C   M E T H O D S  //
//  - - - - - - - - - - - - - -  //

/**
 * Create a new hashmap (allocator)
 *
 * @return a newly created hashmap
 */

mmt_hashmap_t *hashmap_alloc()
{
	mmt_hashmap_t *map = (mmt_hashmap_t *)mmt_malloc(sizeof(mmt_hashmap_t));
	hashmap_init(map);

	return map;
}

/**
 * Destroy a hashmap (deallocator)
 *
 * @param map a pointer to a mmt_hashmap_t previously allocated with hashmap_alloc()
 */

void hashmap_free(mmt_hashmap_t *map)
{
	hashmap_cleanup(map);
	mmt_free(map->slots);
}

/**
 * Initialize a hashmap (constructor)
 *
 * @param map a pointer to an uninitialized mmt_hashmap_t
 */

void hashmap_init(mmt_hashmap_t *map)
{
	int i;

	mmt_hslot_t *slots = (mmt_hslot_t *)mmt_malloc(MMT_HASHMAP_NSLOTS * sizeof(mmt_hslot_t));

	for (i = 0; i < MMT_HASHMAP_NSLOTS; ++i)
		hslot_init(&slots[i]);

	map->slots = slots;
	map->nslots = MMT_HASHMAP_NSLOTS;
	map->nkeys = 0;
}

/**
 * Cleanup a hashmap (destructor)
 *
 * @param map a pointer to mmt_hashmap_t previously initialized with hashmap_init()
 */

void hashmap_cleanup(mmt_hashmap_t *map)
{
	int i;

	for (i = 0; i < MMT_HASHMAP_NSLOTS; ++i)
		hslot_free(&map->slots[i]);
}

/**
 * Map the specified key to the specified value in map
 *
 * @param map a pointer to a mmt_hashmap_t previously initialized with hashmap_init()
 * @param key the hashmap key, as a mmt_key_t
 * @param val the value (pointer)
 */

void hashmap_insert_kv(mmt_hashmap_t *map, mmt_key_t key, void *val)
{
	mmt_hslot_t *slot = &map->slots[key & MMT_HASHMAP_MASK]; /* Use bitmask instead of modulo */
	mmt_hent_t *he = hent_new();

	he->key = key;
	he->val = val;

	LIST_INSERT_HEAD(slot, he, entries);
	//++map->nkeys;
}

/**
 * Retrieve the value to which key is mapped in map
 *
 * @param map a pointer to a mmt_hashmap_t previously initialized with hashmap_init()
 * @param key the key whose associated value is to be returned
 * @param val a pointer to a pointer
 *
 * @return 1 if the key was succesfully maped, 0 otherwise
 */

int hashmap_get(mmt_hashmap_t *map, mmt_key_t key, void **val)
{
	mmt_hent_t *he = hmap_lookup(map, key);

	if (he == NULL)
		return 0; /* not found */

	*val = he->val;

	return 1;
}

/**
 * Walk the whole hashmap, applying walker to every entry
 *
 * @param map a pointer to a mmt_hashmap_t previously initialized with hashmap_init()
 * @param walker a function to be applied to every entry present in hashmap
 * @param arg user data
 */

void hashmap_walk(mmt_hashmap_t *map, mmt_hashmap_walker_t walker, void *arg)
{
	mmt_hslot_t *slot;
	mmt_hent_t *he;
	int i;

	for (i = 0; i < MMT_HASHMAP_NSLOTS; ++i) {
		slot = &map->slots[i];
		for (he = slot->lh_first; he != NULL; he = he->entries.le_next)
			walker(map, he, arg);
	}
}

/**
 * Dump the hashmap to stdout
 *
 * @param map a pointer to a mmt_hashmap_t previously initialized with hashmap_init()
 */

void hashmap_dump(mmt_hashmap_t *map)
{
	(void)printf("*** DUMPING HASHMAP %p\n", map);
	hashmap_walk(map, hmap_dump_entry, 0);
}

/**
 * Remove the mapping for the specified key from this map
 */

int hashmap_remove(mmt_hashmap_t *map, mmt_key_t key)
{
	mmt_hent_t *he = hmap_lookup(map, key);

	if (he == NULL)
		return 0; /* not found */

	LIST_REMOVE(he, entries);
	// BW: now free the hash entry (it was allocated in @method hashmap_insert_kv)
	hent_free(he);

	return 1;
}


//  - - - - - - - - - - - - - - -  //
//  P R I V A T E   M E T H O D S  //
//  - - - - - - - - - - - - - - -  //

mmt_hent_t *hmap_lookup(mmt_hashmap_t *map, mmt_key_t key)
{
	mmt_hslot_t *slot = &map->slots[key & MMT_HASHMAP_MASK]; /* Use bitmask instead of modulo */
	mmt_hent_t *he = slot->lh_first;

	while ((he != NULL) && (he->key != key))
		he = he->entries.le_next;

	return he;
}


void hmap_dump_entry(mmt_hashmap_t *map, mmt_hent_t *he, void *arg)
{
	(void)printf("KEY: 0x%p\n", (void *)he->key);
	(void)printf("VAL: *(%p)\n", he->val);
}


mmt_hent_t *hent_new()
{
	mmt_hent_t *he = (mmt_hent_t *)mmt_malloc(sizeof(mmt_hent_t));

	he->key = 0;
	he->val = (void *)0;

	return he;
}


void hent_free(mmt_hent_t *he)
{
	mmt_free(he);
}


void hslot_init(mmt_hslot_t *slot)
{
	LIST_INIT(slot);
}


void hslot_free(mmt_hslot_t *slot)
{
	mmt_hent_t *he = slot->lh_first;

	while (he != NULL) {
		LIST_REMOVE(he, entries);
		hent_free(he);
		he = slot->lh_first;
	}
}

/*EoF*/

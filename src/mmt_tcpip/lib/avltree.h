/**
 * AVL Tree - implementation of AVL Tree data structure
 * provide simple API to use AVL Tree
 */

#ifndef AVLTREE_H
#define AVLTREE_H
#include "stdint.h"
/**
 * Present an AVL Tree node
 */
typedef struct avltree_struct {
	uint32_t key; // Key of the node
	void * data; // data of the node - use void pointer to have flexible in implementation
	struct avltree_struct * parent; // Parent of current node
	struct avltree_struct * left_child; // left child of current node: which contains all the node with the key smaller than the key of current node
	struct avltree_struct * right_child; // right child of current node: which contains all the node with the key bigger than the key of current node
} avltree_t;

/**
 * Create a new AVL Tree node
 * @return NULL if cannot allocate memory for a new AVL Tree node
 *              a pointer points to new AVL Tree node. The new node has the key = 0, all other attributes are NULL
 */
avltree_t * avltree_new();

/**
 * Create a new avltree node from given key and data
 * @param  key  key of new AVL Tree node
 * @param  data the pointer points to the data
 * @return      NULL if cannot allocate memory for a new AVL Tree node
 *                   a pointer points to new AVL Tree node with given key and data
 */
avltree_t * avltree_create(uint32_t key, void * data);

/**
 * Free an AVL Tree node
 * @param node AVL Tree node to be free
 */
void avltree_free_node(avltree_t * node);

/**
 * Free an AVL Tree tree
 * @param node root of the AVL Tree
 */
void avltree_free_tree(avltree_t * node);

/**
 * Set the key for an AVL Tree node
 * @param  key given key to set
 * @return     1 - success
 *               0 - failed
 */
// int avltree_set_key(int key);

/**
 * Set data for an AVL Tree node
 * @param  data pointer points to the data
 * @return      1 - success
 *                0 - failed
 */
// int avltree_set_data(void * data);

/**
 * Get the key of an AVL Tree node
 * @param  node AVL Tree node
 * @return      the key of given AVL Tree node
 */
uint32_t avltree_get_key(avltree_t * node);

/**
 * Get the data of an AVL Tree node
 * @param  node AVL Tree node
 * @return      the pointer points to the data of given AVL Tree node
 */
void * avltree_get_data(avltree_t * node);

/**
 * Get the height of a node - the height of a node is the number of level from given node to the farthest leaf
 * @param  node given node to calculate the height
 * @return      the number of node on the path from current node to the farthest leaf
 */
// int avltree_get_height(avltree_t * node);

/**
 * Perform left rotation to keep the Tree balance
 * @param  node the node which is unbalanced
 * @return      the new root of the tree after rotating
 */
// avltree_t * avltree_rotate_left(avltree_t * node);

/**
 * Perform right rotation to keep the Tree balance
 * @param  node the node which is unbalanced
 * @return      the new root of the tree after rotating
 */
// avltree_t * avltree_rotate_right(avltree_t * node);


/**
 * Perform left_right rotation to keep the Tree balance
 * @param  node the node which is unbalanced
 * @return      the new root of the tree after rotating
 */
// avltree_t * avltree_rotate_left_right(avltree_t * node);

/**
 * Perform right_left rotation to keep the Tree balance
 * @param  node the node which is unbalanced
 * @return      the new root of the tree after rotating
 */
// avltree_t * avltree_rotate_right_left(avltree_t * node);

/**
 * Insert a new node into a AVL Tree
 * @param  root current root of AVL Tree
 * @param  node new node to be inserted
 * @return      new root of the AVL Tree
 */
avltree_t * avltree_insert(avltree_t * root, avltree_t * node);

/**
 * Search in the given AVL Tree a node which has the key equals with given key
 * @param  root root of AVL Tree
 * @param  key  key value to search the node
 * @return      NULL - if there isn't any node in given AVL Tree which has the given key value
 *                   a pointer points to the node which has given key value
 */
avltree_t * avltree_find(avltree_t * root, uint32_t key);

/**
 * Show current AVL Tree structure
 * @param node root of the AVL Tree
 */
void avltree_show_tree(avltree_t * node);

/**
 * Show current AVL Tree node
 * @param node given node
 */
void avltree_show_node(avltree_t * node);

/**
 * Validate a AVL Tree is a valid one
 * @param  node root of the tree
 * @return      0 - if the AVL Tree has balanced factor is more than 2
 *              0 - any its subtree is invalid
 *              1 - if the AVL Tree is valid
 */
int avltree_valid(avltree_t * node);

/**
 * Get the number of node in the tree
 * @param  node root of the tree
 * @return      number of node on the tree
 */
int avltree_size(avltree_t * node);

#endif // End of AVLTREE_H
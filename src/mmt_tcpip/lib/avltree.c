#include "stdio.h"
#include "stdlib.h"
#include "avltree.h"
#include "dbg.h"

/**
 * Create a new AVL Tree node
 * @return NULL if cannot allocate memory for a new AVL Tree node
 *              a pointer points to new AVL Tree node. The new node has the key = 0, all other attributes are NULL
 */
avltree_t * avltree_new() {
    avltree_t * node = (avltree_t *) malloc (sizeof(avltree_t));
    if (node == 0x0) {
        mmt_stderr_log("[error] Cannot allocate memory for a new AVLTree\n");
        return 0x0;
    }

    node->key = 0;
    node->parent = 0x0;
    node->left_child = 0x0;
    node->right_child = 0x0;
    node->data = 0x0;
    node->height = 1; // a fresh, child-less node is a leaf
    return node;
};

/**
 * Cached subtree height of a node.
 * @param  node a node, or NULL for an empty subtree
 * @return      node->height, or 0 if node is NULL
 *
 * This is the O(1) read used to maintain heights incrementally. It must agree
 * with the legacy recomputation: an empty subtree contributes 0, a leaf 1.
 */
static int avltree_node_height(avltree_t * node) {
    return (node == NULL) ? 0 : node->height;
};

/**
 * Recompute a single node's cached height from its children's cached heights.
 * O(1). Children heights are assumed already up to date.
 * @param node node whose height field is refreshed (no-op if NULL)
 */
static void avltree_update_height(avltree_t * node) {
    if (node == NULL) return;
    int left_height = avltree_node_height(node->left_child);
    int right_height = avltree_node_height(node->right_child);
    node->height = 1 + (left_height > right_height ? left_height : right_height);
};

/**
 * Create a new avltree node from given key and data
 * @param  key  key of new AVL Tree node
 * @param  data the pointer points to the data
 * @return      NULL if cannot allocate memory for a new AVL Tree node
 *                   a pointer points to new AVL Tree node with given key and data
 */
avltree_t * avltree_create(uint32_t key, void * data) {
    avltree_t * node = avltree_new();
    if (node != NULL) {
        node->key = key;
        node->data = data;
        return node;
    }
    return NULL;
};


/**
 * Free an AVL Tree node
 * @param node AVL Tree node to be free
 */
void avltree_free_node(avltree_t * node) {
    if (node != 0x0) {
        node->key = 0;
        node->parent = 0x0;
        node->left_child = 0x0;
        node->right_child = 0x0;
        // if(node->data!=NULL) free(node->data);
        node->data = 0x0;
        free(node);
    }
};


/**
 * Free an AVL Tree tree
 * @param node root of the AVL Tree
 */
void avltree_free_tree(avltree_t * node) {
    if (node == NULL) return;
    // Free left subtree
    if (node->left_child != NULL) avltree_free_tree(node->left_child);
    // Free right subtree
    if (node->right_child != NULL) avltree_free_tree(node->right_child);

    // Free root
    avltree_free_node(node);
};

/**
 * Get the key of an AVL Tree node
 * @param  node AVL Tree node
 * @return      the key of given AVL Tree node
 */
uint32_t avltree_get_key(avltree_t * node) {
    if (node == NULL) return 0;
    return node->key;
};

/**
 * Get the data of an AVL Tree node
 * @param  node AVL Tree node
 * @return      the pointer points to the data of given AVL Tree node
 */
void * avltree_get_data(avltree_t * node) {
    if (node == NULL) return NULL;
    return node->data;
};

/**
 * Get the height of a node - the height of a node is the number of level from given node to the farthest leaf
 * @param  node given node to calculate the height
 * @param current_level current level of given node
 * @return      the number of node on the path from current node to the farthest leaf
 *                  current_level - 1: if given node == NULL
 *                  1 if this is the root of the tree
 *                  maximum value between left tree and right tree
 */
int avltree_get_height(avltree_t * node, int current_level) {
    // O(1) read of the cached height. This is algebraically identical to the
    // former O(subtree) recursion: that version returned (current_level - 1)
    // for a NULL subtree and, for a non-NULL node, (current_level - 1) plus the
    // node-count distance to its farthest leaf. The cached node->height stores
    // exactly that distance (0 for empty, 1 for a leaf), so callers — including
    // avltree_get_balance_factor — observe the same values as before.
    return current_level - 1 + avltree_node_height(node);
};

/**
 * Perform left rotation to keep the Tree balance
 * @param  node the node which is unbalanced
 * @return      the new root of the tree after rotating
 */
avltree_t * avltree_rotate_left(avltree_t * node) {
#ifdef DEBUG
    mmt_debug_log("[debug] avltree_rotate_left for node: %d\n", node->key);
#endif
    avltree_t * new_root = node->right_child;
    new_root->parent = node->parent;
    if (node->parent != NULL) {
        if (node->parent->right_child != NULL) {
            if (node->parent->right_child->key == node->key) {
                node->parent->right_child = new_root;
            }
        }

        if (node->parent->left_child != NULL) {
            if (node->parent->left_child->key == node->key) {
                node->parent->left_child = new_root;
            }
        }

    }
    if (new_root->left_child != NULL) {
        node->right_child = new_root->left_child;
        new_root->left_child->parent = node;
    } else {
        node->right_child = 0x0;
    }

    new_root->left_child = node;
    node->parent = new_root;
    // Subtree composition of node and new_root changed; refresh cached heights
    // bottom-up (node first, since new_root's height depends on it).
    avltree_update_height(node);
    avltree_update_height(new_root);
#ifdef DEBUG
    avltree_show_tree(new_root);
#endif
    return new_root;
};

/**
 * Perform right rotation to keep the Tree balance
 * @param  node the node which is unbalanced
 * @return      the new root of the tree after rotating
 */
avltree_t * avltree_rotate_right(avltree_t * node) {
#ifdef DEBUG
    mmt_debug_log("[debug] avltree_rotate_right for node: %d\n", node->key);
#endif
    avltree_t * new_root = node->left_child;
    new_root->parent = node->parent;
    if (node->parent != NULL) {
        if (node->parent->right_child != NULL) {
            if (node->parent->right_child->key == node->key) {
                node->parent->right_child = new_root;
            }
        }

        if (node->parent->left_child != NULL) {
            if (node->parent->left_child->key == node->key) {
                node->parent->left_child = new_root;
            }
        }
    }
    if (new_root->right_child != NULL) {
        node->left_child = new_root->right_child;
        new_root->right_child->parent = node;
    } else {
        node->left_child = 0x0;
    }

    new_root->right_child = node;
    node->parent = new_root;
    // Subtree composition of node and new_root changed; refresh cached heights
    // bottom-up (node first, since new_root's height depends on it).
    avltree_update_height(node);
    avltree_update_height(new_root);
#ifdef DEBUG
    avltree_show_tree(new_root);
#endif
    return new_root;
};


/**
 * Perform left_right rotation to keep the Tree balance
 * @param  node the node which is unbalanced
 * @return      the new root of the tree after rotating
 */
avltree_t * avltree_rotate_left_right(avltree_t * node) {
#ifdef DEBUG
    mmt_debug_log("[debug] avltree_rotate_left_right for node: %u\n", node->key);
#endif
    avltree_t * temp_node = avltree_rotate_left(node->left_child);
#ifdef DEBUG
    mmt_debug_log("[debug] avltree_rotate_left_right temp_node: %u\n", temp_node->key);
#endif
    avltree_t * new_root = avltree_rotate_right(temp_node->parent);
#ifdef DEBUG
    avltree_show_tree(new_root);
#endif
    return new_root;
};

/**
 * Perform right_left rotation to keep the Tree balance
 * @param  node the node which is unbalanced
 * @return      the new root of the tree after rotating
 */
avltree_t * avltree_rotate_right_left(avltree_t * node) {
#ifdef DEBUG
    mmt_debug_log("[debug] avltree_rotate_right_left for node: %u\n", node->key);
#endif
    avltree_t * temp_node = avltree_rotate_right(node->right_child);
#ifdef DEBUG
    mmt_debug_log("[debug] avltree_rotate_right_left temp_node: %u\n", temp_node->key);
#endif
    avltree_t * new_root = avltree_rotate_left(temp_node->parent);
#ifdef DEBUG
    avltree_show_tree(new_root);
#endif
    return new_root;
};

/**
 * Get root of the AVL Tree which contains given node
 * @param  node the given node
 * @return      the pointer points to the root of the AVL Tree
 *                  NULL: if the given node is NULL
 *                  given node : if the given node does not have parent
 */
avltree_t * avltree_get_root(avltree_t * node) {
    if ( node == NULL) return NULL;
    if (node->parent == NULL) return node;
    avltree_t * current_node = node;
    while (current_node->parent != NULL) {
        current_node = current_node->parent;
    }
    return current_node;
}
/**
 * Calculate the balance factor of an AVL Tree
 * @param  node root of the tree
 * @return      0 if root is NULL
 *                the different height of left subtree and right subtree
 */
int avltree_get_balance_factor(avltree_t * node) {
    if (node == NULL) return 0;
    return (avltree_get_height(node->left_child, 1) - avltree_get_height(node->right_child, 1));
}

/**
 * Insert a new node into a AVL Tree, reporting a duplicate key
 * @param  root current root of AVL Tree
 * @param  node new node to be inserted
 * @param  is_duplicate optional out-param (may be NULL): set to 1 when
 *         node->key already exists in the tree — in that case node is NOT
 *         linked and the tree is unchanged — 0 otherwise
 * @return      root of the (possibly rebalanced) AVL Tree. On a duplicate key
 *              this is the EXISTING tree's root, never the unlinked node —
 *              issue #212 (F-BUG-027): this function used to end with
 *              `return avltree_get_root(node)`, and since a duplicate node is
 *              never linked it is its own root, so the
 *              `tree = avltree_insert(tree, node)` idiom silently replaced the
 *              entire existing subtree with the orphan node.
 */
avltree_t * avltree_insert_ex(avltree_t * root, avltree_t * node, int * is_duplicate) {
    if (is_duplicate != NULL) {
        *is_duplicate = 0;
    }
#ifdef DEBUG
    mmt_debug_log("[debug] Insert new node: %u\n", node->key);
#endif
    if (root == NULL) {
#ifdef DEBUG
        mmt_debug_log("[debug] First node of the tree\n");
#endif        
        return node;
    }
    if (root->key > node->key) {
        // Insert in the left subtree
#ifdef DEBUG
        mmt_debug_log("[debug] Insert in the left subtree of node: %u\n", root->key);
#endif
        if (root->left_child == NULL) {
            root->left_child = node;
            node->parent = root;
            // The new node (a leaf, height already 1) was attached under root;
            // refresh root's cached height before walking up the ancestor chain.
            avltree_update_height(root);
            avltree_t * parent = root->parent;
            while (parent != NULL) {
                // Refresh this ancestor's cached height from its (now current)
                // children before reading its balance factor, so the O(1)
                // cached lookups match the legacy full recomputation exactly.
                avltree_update_height(parent);
#ifdef DEBUG
                mmt_debug_log("[debug] Checking balance of tree: %u\n",parent->key);
#endif
                int balance_factor = avltree_get_balance_factor(parent);
#ifdef DEBUG
                mmt_debug_log("[debug] balance_factor of node %u: %d\n", parent->key, balance_factor);
#endif
                if (balance_factor > 1) {
#ifdef DEBUG
                    mmt_debug_log("[debug] Tree need to rebalanced on left side: %d\n", balance_factor);
#endif
                    int balance_factor_child = avltree_get_balance_factor(parent->left_child);
                    if (balance_factor_child > 0) {
                        // Left -left -> Need to rotate right
                        parent = avltree_rotate_right(parent);
                    } else if (balance_factor_child < 0) {
                        // left - right -> need to rotate right then left
                        parent = avltree_rotate_left_right(parent);
                    } else {
                        mmt_debug_log( "[error] Insert left_child and tree unbalanced: %d / %d \n", balance_factor, balance_factor_child);
                        avltree_show_tree(parent);
                    }
                } else if (balance_factor < -1) {
#ifdef DEBUG
                    mmt_debug_log("[debug] Tree need to rebalanced on right side: %d\n", balance_factor);
#endif
                    int balance_factor_child = avltree_get_balance_factor(parent->right_child);
                    if (balance_factor_child > 0) {
                        // right -left -> Need to rotate left then right
                        parent = avltree_rotate_right_left(parent);
                    } else if (balance_factor_child < 0) {
                        // right - right -> need to rotate left
                        parent = avltree_rotate_left(parent);
                    } else {
                        mmt_debug_log( "[error] Insert left_child and tree unbalanced: %d / %d \n", balance_factor, balance_factor_child);
                        avltree_show_tree(parent);
                    }
                }
                parent = parent->parent;
            }            
        } else {
            avltree_insert_ex(root->left_child, node, is_duplicate);
        }
    } else if(root->key < node->key){
        // Insert in the right subtree
#ifdef DEBUG
        mmt_debug_log("[debug] Insert in the right subtree of node: %u\n", root->key);
#endif
        if (root->right_child == NULL) {
            root->right_child = node;
            node->parent = root;
            // The new node (a leaf, height already 1) was attached under root;
            // refresh root's cached height before walking up the ancestor chain.
            avltree_update_height(root);
            avltree_t * parent = root->parent;
            while (parent != NULL) {
                // Refresh this ancestor's cached height from its (now current)
                // children before reading its balance factor, so the O(1)
                // cached lookups match the legacy full recomputation exactly.
                avltree_update_height(parent);
                int balance_factor = avltree_get_balance_factor(parent);
#ifdef DEBUG
                mmt_debug_log("[debug] balance_factor of node %u: %d\n", parent->key, balance_factor);
#endif
                if (balance_factor > 1) {
#ifdef DEBUG
                    mmt_debug_log("[debug] Tree need to rebalanced on left side: %d\n", balance_factor);
#endif
                    int balance_factor_child = avltree_get_balance_factor(parent->left_child);
                    if (balance_factor_child > 0) {
                        // Left -left -> Need to rotate right
                        parent = avltree_rotate_right(parent);
                    } else if (balance_factor_child < 0) {
                        // left - right -> need to rotate right then left
                        parent = avltree_rotate_left_right(parent);
                    } else {
                        mmt_debug_log( "[error] Insert left_child and tree unbalanced: %d / %d \n", balance_factor, balance_factor_child);
                        avltree_show_tree(parent);
                    }
                } else if (balance_factor < -1) {
#ifdef DEBUG
                    mmt_debug_log("[debug] Tree need to rebalanced on right side: %d\n", balance_factor);
#endif
                    int balance_factor_child = avltree_get_balance_factor(parent->right_child);
                    if (balance_factor_child > 0) {
                        // right -left -> Need to rotate left then right
                        parent = avltree_rotate_right_left(parent);
                    } else if (balance_factor_child < 0) {
                        // right - right -> need to rotate left
                        parent = avltree_rotate_left(parent);
                    } else {
                        mmt_debug_log( "[error] Insert left_child and tree unbalanced: %d / %d \n", balance_factor, balance_factor_child);
                        avltree_show_tree(parent);
                    }
                }
                parent = parent->parent;
            }
        } else {
            avltree_insert_ex(root->right_child, node, is_duplicate);
        }
    }else{
        if (is_duplicate != NULL) {
            *is_duplicate = 1;
        }
        mmt_debug_log("[info] Node is already exist: %u - %p | %u - %p\n",root->key,root->data ,node->key,node->data );
    }
    /* F-BUG-027: return the root of the EXISTING tree. On a duplicate, node was
     * never linked so avltree_get_root(node) would be node itself — returning
     * it would orphan the whole subtree for callers doing
     * `tree = avltree_insert(tree, node)`. Walking up from `root` is correct in
     * every case: node was either linked under it, or the tree is unchanged. */
    return avltree_get_root(root);
};

/**
 * Insert a new node into a AVL Tree
 * @param  root current root of AVL Tree
 * @param  node new node to be inserted
 * @return      root of the (possibly rebalanced) AVL Tree — on a duplicate key
 *              the existing root, and the unlinked node is left to the caller
 */
avltree_t * avltree_insert(avltree_t * root, avltree_t * node) {
    return avltree_insert_ex(root, node, NULL);
};

/**
 * Search in the given AVL Tree a node which has the key equals with given key
 * @param  root root of AVL Tree
 * @param  key  key value to search the node
 * @return      NULL - if there isn't any node in given AVL Tree which has the given key value
 *                   a pointer points to the node which has given key value
 */
avltree_t * avltree_find(avltree_t * root, uint32_t key) {
    if (root == NULL) return NULL;
    if (root->key == key ) return root;
    if ( root->key > key) {
        // Search on left subtree
        return avltree_find(root->left_child, key);
    } else {
        // Search on right subtree
        return avltree_find(root->right_child, key);
    }
};

/**
 * Show current AVL Tree structure
 * @param node root of the AVL Tree
 */
void avltree_show_tree(avltree_t * node) {
    avltree_show_node(node);
    if (node != NULL) {
        avltree_show_tree(node->left_child);
        avltree_show_tree(node->right_child);
    }
};

void avltree_show_node(avltree_t * node) {
    if (node == NULL) {
        mmt_debug_log("\"NULL\"");
    } else {
        mmt_debug_log("{Key: %u, Left: %u, Right: %u}\n", node->key, node->left_child == NULL ? 0 : node->left_child->key, node->right_child == NULL ? 0 : node->right_child->key);
    }
}

/**
 * Validate a AVL Tree is a valid one
 * @param  node root of the tree
 * @return      0 - if the AVL Tree has balanced factor is more than 2
 *              0 - any its subtree is invalid
 *              1 - if the AVL Tree is valid
 */
int avltree_valid(avltree_t * node){
    if(node == NULL) return 1;
    int balance_factor = avltree_get_balance_factor(node);
    if(balance_factor < -1 || balance_factor > 1){
        return 0;
    }

    if(avltree_valid(node->left_child) == 0) return 0;

    if(avltree_valid(node->right_child) == 0) return 0;

    return 1;
};

/**
 * Get the number of node in the tree
 * @param  node root of the tree
 * @return      number of node on the tree
 */
int avltree_size(avltree_t * node){
    int ret = 0;
    
    if (node == NULL) return 0;
    
    ret = 1;

    if (node->left_child != NULL){
        ret += avltree_size(node->left_child);
    }

    if (node->right_child != NULL){
        ret += avltree_size(node->right_child);
    }

    return ret;
};

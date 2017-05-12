#include "stdio.h"
#include "stdlib.h"
#include "avltree.h"

/**
 * Create a new AVL Tree node
 * @return NULL if cannot allocate memory for a new AVL Tree node
 *              a pointer points to new AVL Tree node. The new node has the key = 0, all other attributes are NULL
 */
avltree_t * avltree_new() {
    avltree_t * node = (avltree_t *) malloc (sizeof(avltree_t));
    if (node == 0x0) {
        fprintf(stderr, "[error] Cannot allocate memory for a new AVLTree\n");
        return 0x0;
    }

    node->key = 0;
    node->parent = 0x0;
    node->left_child = 0x0;
    node->right_child = 0x0;
    node->data = 0x0;
    return node;
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
    if (node == NULL) return current_level - 1;
    if (node->parent == NULL) return 1;
    int left_height = avltree_get_height(node->left_child, current_level + 1);
    int right_height = avltree_get_height(node->right_child, current_level + 1);
    return left_height > right_height ? left_height : right_height;
};

/**
 * Perform left rotation to keep the Tree balance
 * @param  node the node which is unbalanced
 * @return      the new root of the tree after rotating
 */
avltree_t * avltree_rotate_left(avltree_t * node) {
#ifdef DEBUG
    printf("[debug] avltree_rotate_left for node: %d\n", node->key);
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
    printf("[debug] avltree_rotate_right for node: %d\n", node->key);
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
    printf("[debug] avltree_rotate_left_right for node: %u\n", node->key);
#endif
    avltree_t * temp_node = avltree_rotate_left(node->left_child);
#ifdef DEBUG
    printf("[debug] avltree_rotate_left_right temp_node: %u\n", temp_node->key);
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
    printf("[debug] avltree_rotate_right_left for node: %u\n", node->key);
#endif
    avltree_t * temp_node = avltree_rotate_right(node->right_child);
#ifdef DEBUG
    printf("[debug] avltree_rotate_right_left temp_node: %u\n", temp_node->key);
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
 * Insert a new node into a AVL Tree
 * @param  root current root of AVL Tree
 * @param  node new node to be inserted
 * @return      new root of the AVL Tree
 */
avltree_t * avltree_insert(avltree_t * root, avltree_t * node) {
#ifdef DEBUG
    printf("[debug] Insert new node: %u\n", node->key);
#endif
    if (root == NULL) {
#ifdef DEBUG
        printf("[debug] First node of the tree\n");
#endif        
        return node;
    }
    if (root->key > node->key) {
        // Insert in the left subtree
#ifdef DEBUG
        printf("[debug] Insert in the left subtree of node: %u\n", root->key);
#endif
        if (root->left_child == NULL) {
            root->left_child = node;
            node->parent = root;
            avltree_t * parent = root->parent;
            while (parent != NULL) {
#ifdef DEBUG
                printf("[debug] Checking balance of tree: %u\n",parent->key);
#endif        
                int balance_factor = avltree_get_balance_factor(parent);
#ifdef DEBUG
                printf("[debug] balance_factor of node %u: %d\n", parent->key, balance_factor);
#endif
                if (balance_factor > 1) {
#ifdef DEBUG
                    printf("[debug] Tree need to rebalanced on left side: %d\n", balance_factor);
#endif
                    int balance_factor_child = avltree_get_balance_factor(parent->left_child);
                    if (balance_factor_child > 0) {
                        // Left -left -> Need to rotate right
                        parent = avltree_rotate_right(parent);
                    } else if (balance_factor_child < 0) {
                        // left - right -> need to rotate right then left
                        parent = avltree_rotate_left_right(parent);
                    } else {
                        fprintf(stderr, "[error] Insert left_child and tree unbalanced: %d / %d \n", balance_factor, balance_factor_child);
                        avltree_show_tree(parent);
                    }
                } else if (balance_factor < -1) {
#ifdef DEBUG
                    printf("[debug] Tree need to rebalanced on right side: %d\n", balance_factor);
#endif
                    int balance_factor_child = avltree_get_balance_factor(parent->right_child);
                    if (balance_factor_child > 0) {
                        // right -left -> Need to rotate left then right
                        parent = avltree_rotate_right_left(parent);
                    } else if (balance_factor_child < 0) {
                        // right - right -> need to rotate left
                        parent = avltree_rotate_left(parent);
                    } else {
                        fprintf(stderr, "[error] Insert left_child and tree unbalanced: %d / %d \n", balance_factor, balance_factor_child);
                        avltree_show_tree(parent);
                    }
                }
                parent = parent->parent;
            }            
        } else {
            avltree_insert(root->left_child, node);
        }
    } else if(root->key < node->key){
        // Insert in the right subtree
#ifdef DEBUG
        printf("[debug] Insert in the right subtree of node: %u\n", root->key);
#endif
        if (root->right_child == NULL) {
            root->right_child = node;
            node->parent = root;
            avltree_t * parent = root->parent;
            while (parent != NULL) {
                int balance_factor = avltree_get_balance_factor(parent);
#ifdef DEBUG
                printf("[debug] balance_factor of node %u: %d\n", parent->key, balance_factor);
#endif
                if (balance_factor > 1) {
#ifdef DEBUG
                    printf("[debug] Tree need to rebalanced on left side: %d\n", balance_factor);
#endif
                    int balance_factor_child = avltree_get_balance_factor(parent->left_child);
                    if (balance_factor_child > 0) {
                        // Left -left -> Need to rotate right
                        parent = avltree_rotate_right(parent);
                    } else if (balance_factor_child < 0) {
                        // left - right -> need to rotate right then left
                        parent = avltree_rotate_left_right(parent);
                    } else {
                        fprintf(stderr, "[error] Insert left_child and tree unbalanced: %d / %d \n", balance_factor, balance_factor_child);
                        avltree_show_tree(parent);
                    }
                } else if (balance_factor < -1) {
#ifdef DEBUG
                    printf("[debug] Tree need to rebalanced on right side: %d\n", balance_factor);
#endif
                    int balance_factor_child = avltree_get_balance_factor(parent->right_child);
                    if (balance_factor_child > 0) {
                        // right -left -> Need to rotate left then right
                        parent = avltree_rotate_right_left(parent);
                    } else if (balance_factor_child < 0) {
                        // right - right -> need to rotate left
                        parent = avltree_rotate_left(parent);
                    } else {
                        fprintf(stderr, "[error] Insert left_child and tree unbalanced: %d / %d \n", balance_factor, balance_factor_child);
                        avltree_show_tree(parent);
                    }
                }
                parent = parent->parent;
            }
        } else {
            avltree_insert(root->right_child, node);
        }
    }else{
        printf("[info] Node is already exist: %u - %p | %u - %p\n",root->key,root->data ,node->key,node->data );
    }
    return avltree_get_root(node);
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
        printf("\"NULL\"");
    } else {
        printf("{Key: %u, Left: %u, Right: %u}\n", node->key, node->left_child == NULL ? 0 : node->left_child->key, node->right_child == NULL ? 0 : node->right_child->key);
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

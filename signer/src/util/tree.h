/*
 * $Id: tree.h 7057 2013-02-26 09:30:10Z matthijs $
 *
 * Copyright (c) 2013 NLNet Labs. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * Tree storage.
 *
 */

#ifndef UTIL_TREE_H
#define UTIL_TREE_H

#include "util/region.h"

#include <ldns/ldns.h>

#define TREE_NULL LDNS_RBTREE_NULL

/**
 * Tree storage structure.
 *
 */
typedef struct tree_struct tree_type;
struct tree_struct {
    ldns_rbtree_t* storage;
};

/**
 * Tree node.
 *
 */
typedef ldns_rbnode_t tree_node;

/**
 * Create tree storage.
 * @param region:  memory region.
 * @param cmpfunc: compare function.
 * @return:        (tree_type*) tree storage.
 *
 */
tree_type* tree_create(region_type* region,
    int (*cmpfunc)(const void *, const void *));

/**
 * Get number of nodes in tree.
 * @param tree: tree.
 * @return:     (size_t) number of nodes in tree.
 *
 */
size_t tree_count(tree_type* tree);

/**
 * Insert node into tree.
 * @param tree: tree.
 * @param node: node.
 * @return:     (tree_node*) inserted node, NULL on error.
 *
 */
tree_node* tree_insert(tree_type* tree, tree_node* node);

/**
 * Search tree.
 * @param tree: tree.
 * @param key:  search key.
 * @return:     (tree_node*) searched node, NULL if not found.
 *
 */
tree_node* tree_search(tree_type* tree, const void* key);

/**
 * Delete node from tree.
 * @param tree: tree.
 * @param key:  search key.
 * @return:     (tree_node*) deleted node, NULL if not found.
 *
 */
tree_node* tree_delete(tree_type* tree, const void* key);

/**
 * Get first node from tree.
 * @param tree: tree.
 * @return:     (tree_node*) first node, NULL if tree is empty.
 *
 */
tree_node* tree_first(tree_type* tree);


/**
 * Get last node from tree.
 * @param tree: tree.
 * @return:     (tree_node*) last node, NULL if tree is empty.
 *
 */
tree_node* tree_last(tree_type* tree);

/**
 * Get next node from tree.
 * @param node: node in tree.
 * @return:     (tree_node*) next node, NULL if there is no next node.
 *
 */
tree_node* tree_next(tree_node* node);

/**
 * Get previous node from tree.
 * @param node: node in tree.
 * @return:     (tree_node*) previous node, NULL if there is no previous node.
 *
 */
tree_node* tree_prev(tree_node* node);

/**
 * Clean up tree storage.
 * @param tree: tree storage.
 *
 */
void tree_cleanup(tree_type* tree);

#endif /* UTIL_TREE_H */

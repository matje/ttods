/*
 * $Id: tree.c 7057 2013-02-26 09:30:10Z matthijs $
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

#include "util/log.h"
#include "util/tree.h"

#include <stdlib.h>

static const char* logstr = "tree";


/**
 * Create tree.
 *
 */
tree_type*
tree_create(region_type* region, int (*cmpfunc)(const void *, const void *))
{
    tree_type* tree;
    ods_log_assert(region);
    tree = region_alloc(region, sizeof(tree_type));
    tree->storage = ldns_rbtree_create(cmpfunc);
    if (!tree->storage) {
        ods_log_crit("[%s] ldns_rbtree_create() failed", logstr);
        exit(1);
    }
    return tree;
}


/**
 * Get number of nodes in tree.
 *
 */
size_t
tree_count(tree_type* tree)
{
    if (tree && tree->storage) {
        return tree->storage->count;
    }
    return 0;
}


/**
 * Insert node into tree.
 *
 */
tree_node*
tree_insert(tree_type* tree, tree_node* node)
{
    ods_log_assert(tree);
    ods_log_assert(node);
    return ldns_rbtree_insert(tree->storage, (ldns_rbnode_t*) node);
}


/**
 * Search tree.
 *
 */
tree_node*
tree_search(tree_type* tree, const void* key)
{
    ods_log_assert(tree);
    ods_log_assert(key);
    return ldns_rbtree_search(tree->storage, key);
}


/**
 * Delete node from tree.
 *
 */
tree_node*
tree_delete(tree_type* tree, const void* key)
{
    ods_log_assert(tree);
    ods_log_assert(key);
    return ldns_rbtree_delete(tree->storage, key);
}


/**
 * Get first node from tree.
 *
 */
tree_node* tree_first(tree_type* tree)
{
    ods_log_assert(tree);
    return ldns_rbtree_first(tree->storage);
}


/**
 * Get last node from tree.
 *
 */
tree_node* tree_last(tree_type* tree)
{
    ods_log_assert(tree);
    return ldns_rbtree_last(tree->storage);
}


/**
 * Get next node from tree.
 *
 */
tree_node* tree_next(tree_node* node)
{
    ods_log_assert(node);
    return ldns_rbtree_next((ldns_rbnode_t*) node);
}


/**
 * Get previous node from tree.
 *
 */
tree_node* tree_prev(tree_node* node)
{
    ods_log_assert(node);
    return ldns_rbtree_previous((ldns_rbnode_t*) node);
}


/**
 * Clean up tree.
 *
 */
void
tree_cleanup(tree_type* tree)
{
    if (tree) {
        ldns_rbtree_free(tree->storage);
    }
    return;
}


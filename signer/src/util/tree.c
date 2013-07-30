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
 * Insert node into tree.
 *
 */

/**
 * Search tree.
 *
 */

/**
 * Delete node from tree.
 *
 */

/**
 * Get first node from tree.
 *
 */

/**
 * Get last node from tree.
 *
 */

/**
 * Get next node from tree.
 *
 */

/**
 * Get previous node from tree.
 *
 */

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


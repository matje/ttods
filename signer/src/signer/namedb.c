/*
 * $Id: namedb.c 5467 2011-08-24 06:51:16Z matthijs $
 *
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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
 * Domain name database.
 *
 */

#include "config.h"
#include "dns/dname.h"
#include "util/log.h"
#include "util/util.h"
#include "signer/namedb.h"
#include "signer/zone.h"

const char* logstr = "namedb";


/**
 * Compare domains.
 *
 */
static int
domain_compare(const void* a, const void* b)
{
    dname_type* x = (dname_type*)a;
    dname_type* y = (dname_type*)b;
    return dname_compare(x, y);
}


/**
 * Create a new namedb.
 *
 */
namedb_type*
namedb_create(struct zone_struct* zone)
{
    namedb_type* db = NULL;
    tree_type* domains = NULL;
    ods_log_assert(zone);
    ods_log_assert(zone->region);

    db = (namedb_type*) region_alloc(zone->region, sizeof(namedb_type));
    db->zone = zone;
    db->domains = tree_create(zone->region, domain_compare);
    return db;
}


/**
 * Convert a domain to a tree node.
 *
 */
static tree_node*
domain2node(domain_type* domain)
{
    tree_node* node = (tree_node*) region_alloc(domain->zone->region,
        sizeof(tree_node));
    node->key = domain->dname;
    node->data = domain;
    return node;
}


/**
 * Create new domain and add it to namedb.
 *
 */
domain_type*
namedb_add_domain(namedb_type* db, dname_type* dname)
{
    domain_type* domain;
    tree_node* node;
    ods_log_assert(db);
    ods_log_assert(dname);
    domain = domain_create(db->zone, dname);
    node = domain2node(domain);
    if (!tree_insert(db->domains, node)) {
        ods_log_error("[%s] add domain failed: already present", logstr);
/*        dname_log(domain->dname, "ERR +DOMAIN", LOG_ERR); */
        domain_cleanup(domain);
        return NULL;
    }
    domain = (domain_type*) node->data;
    domain->node = node;
    domain->is_new = 1;
/*    log_dname(domain->dname, "+DOMAIN", LOG_DEEEBUG); */
    return domain;
}


/**
 * Clean up namedb.
 *
 */
void
namedb_cleanup(namedb_type* db)
{
    if (db) {
        tree_cleanup(db);
    }
    return;
}

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
    ods_log_assert(zone);
    ods_log_assert(zone->region);

    db = (namedb_type*) region_alloc(zone->region, sizeof(namedb_type));
    db->zone = zone;
    db->domains = tree_create(zone->region, domain_compare);
    return db;
}


/**
 * Add empty non-terminals for domain to the apex.
 *
 */
ods_status
namedb_entize(namedb_type* db, domain_type* domain, dname_type* apex)
{
    region_type* tmp_region = NULL;
    dname_type* parent_dname = NULL;
    domain_type* parent_domain = NULL;
    ods_log_assert(db);
    ods_log_assert(db->zone);
    ods_log_assert(db->zone->region);
    ods_log_assert(domain);
    ods_log_assert(apex);
    ods_log_assert(apex->label_count > 0);
    if (domain->parent) {
        /* already entized */
        return ODS_STATUS_OK;
    }
    tmp_region = region_create();
    if (!tmp_region) {
        ods_log_crit("[%s] create region failed", logstr);
        exit(1);
    }
    while (domain && dname_is_subdomain(domain->dname, apex) &&
        dname_compare(domain->dname, apex) != 0) {
        /**
         * RFC5155:
         * 4. If the difference in number of labels between the apex and
         *    the original owner name is greater than 1, additional NSEC3
         *    RRs need to be added for every empty non-terminal between
         *     the apex and the original owner name.
         */
        ods_log_assert(domain->dname->label_count > apex->label_count);
        parent_dname = dname_leftchop(tmp_region, domain->dname);
        parent_domain = namedb_lookup_domain(db, parent_dname);
        if (!parent_domain) {
            dname_log(parent_dname, "[namedb] add empty non-terminal",
                LOG_DEBUG);
            parent_domain = namedb_add_domain(db, parent_dname);
            ods_log_assert(parent_domain);
            domain->parent = parent_domain;
            domain = parent_domain;
        } else {
            domain->parent = parent_domain;
            domain = NULL;
        }
    }
    region_cleanup(tmp_region);
    return ODS_STATUS_OK;
}


/**
 * Lookup domain.
 *
 */
domain_type*
namedb_lookup_domain(namedb_type* db, dname_type* dname)
{
    tree_node* node;
    if (!db || !dname) {
        return NULL;
    }
    node = tree_search(db->domains, dname);
    if (node && node != TREE_NULL) {
        return (void*) node->data;
    }
    return NULL;
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
        dname_log(domain->dname, "[namedb] add domain failed: already present",
            LOG_WARNING);
        domain_cleanup(domain);
        return NULL;
    }
    domain = (domain_type*) node->data;
    domain->node = node;
    domain->is_new = 1;
    dname_log(domain->dname, "[namedb] +DOMAIN", LOG_DEEEBUG);
    return domain;
}


/**
 * Apply differences in namedb.
 *
 */
void
namedb_diff(namedb_type* db, unsigned incremental, unsigned more_coming)
{
    tree_node* node;
    domain_type* domain;
    ods_log_assert(db);
    if (!db->domains) {
        return;
    }
    node = tree_first(db->domains);
    if (!node || node == TREE_NULL) {
        return;
    }
    while (node && node != TREE_NULL) {
        domain = (domain_type*) node->data;
        node = tree_next(node);
        domain_diff(domain, incremental, more_coming);
    }
    if (!node || node == TREE_NULL) {
        return;
    }
    while (node && node != TREE_NULL) {
        domain = (domain_type*) node->data;
        node = tree_next(node);
        /* TODO: del_denial_trigger, add_denial_trigger */
    }
    return;
}


/**
 * Nsecify namedb.
 *
 */
uint32_t namedb_nsecify(namedb_type* db)
{
    return 0;
}


/**
 * Print namedb.
 *
 */
void
namedb_print(FILE* fd, namedb_type* db, ods_status* status)
{
    tree_node* node;
    domain_type* domain;
    ods_log_assert(fd);
    ods_log_assert(db);
    ods_log_assert(status);
    node = tree_first(db->domains);
    while (node && node != TREE_NULL) {
        domain = (domain_type*) node->data;
        domain_print(fd, domain, status);
        node = tree_next(node);
    }
    return;
}


/**
 * Clean up namedb.
 *
 */
void
namedb_cleanup(namedb_type* db)
{
    if (db) {
        tree_cleanup(db->domains);
    }
    return;
}

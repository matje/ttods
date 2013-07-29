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
 * Initialize domains.
 *
 */
static void
namedb_init_domains(namedb_type* db)
{
    if (db) {
        db->domains = ldns_rbtree_create(domain_compare);
    }
    return;
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
    ods_log_assert(zone->name);
    ods_log_assert(zone->region);
    db = (namedb_type*) region_alloc(zone->region, sizeof(namedb_type));
    db->zone = zone;

    namedb_init_domains(db);
    if (!db->domains) {
        ods_log_error("[%s] unable to create namedb for zone %s: "
            "init domains failed", logstr, zone->name);
        namedb_cleanup(db);
        return NULL;
    }
    return db;
}


/**
 * Clean up domains.
 *
 */
static void
namedb_cleanup_domains(namedb_type* db)
{
    if (db && db->domains) {
        ldns_rbtree_free(db->domains);
        db->domains = NULL;
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
    zone_type* zone = NULL;
    if (!db) {
        return;
    }
    zone = (zone_type*) db->zone;
    if (!zone || !zone->region) {
        return;
    }
    namedb_cleanup_domains(db);
    return;
}

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
 * Name database.
 *
 */

#include "config.h"
#include "signer/namedb.h"
#include "signer/zone.h"

static const char* logstr = "namedb";


/**
 * Create a new name databse.
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
    if (!db) {
        ods_log_crit("[%s] region alloc failed", logstr);
        return NULL;
    }
    db->zone = zone;
    db->serial_in = 0;
    db->serial_mem = 0;
    db->serial_out = 0;
    db->is_initialized = 0;
    db->is_processed = 0;
    db->serial_updated = 0;
    return db;
}


/**
 * Clean up namedb.
 *
 */
void
namedb_cleanup(namedb_type* ATTR_UNUSED(db))
{
    return;
}

/*
 * $Id: zlist.h 5948 2011-11-30 11:56:02Z matthijs $
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
 * The zonelist.
 *
 */

#ifndef SIGNER_ZLIST_H
#define SIGNER_ZLIST_H

#include "signer/zone.h"
#include "util/locks.h"
#include "util/region.h"
#include "util/status.h"
#include "util/tree.h"

#include <ldns/ldns.h>
#include <stdio.h>
#include <time.h>

/**
 * Zonelist structure.
 *
 */
typedef struct zlist_struct zlist_type;
struct zlist_struct {
    tree_type* zones;
    time_t last_modified;
    int just_added;
    int just_updated;
    int just_removed;
    lock_basic_type zl_lock;

    /* 1x ptr, 5x int */
    /* est.mem: ZL = 28 + N*Z bytes */
};

/**
 * Create zone list.
 * @return: (zlist_type*) created zone list.
 *
 */
zlist_type* zlist_create(region_type* r);

/**
 * Add zone.
 * @param zl:   zone list.
 * @param zone: zone.
 * @return:     (zone_type*) added zone, NULL if failed to add the zone.
 *
 */
zone_type* zlist_add_zone(zlist_type* zl, zone_type* zone);

/**
 * Delete zone.
 * @param zl:   zone list.
 * @param zone: zone.
 * @return:     (zone_type*) deleted zone, caller should free zone.
 *
 */
zone_type* zlist_del_zone(zlist_type* zlist, zone_type* zone);

/**
 * Update zonelist.
 * @param zl:     zone list.
 * @param zlfile: zone list filename.
 * @return:       (ods_status) status.
 *
 */
ods_status zlist_update(zlist_type* zl, const char* zlfile);

/**
 * Free zone list.
 * @param zl: zone list.
 *
 */
void zlist_free(zlist_type* zl);

/**
 * Clean up zone list.
 * @param zl: zone list.
 *
 */
void zlist_cleanup(zlist_type* zl);

#endif /* SIGNER_ZLIST_H */

/*
 * $Id: zone.h 6577 2012-08-29 07:41:11Z jerry $
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
 * Zone.
 *
 */

#ifndef SIGNER_ZONE_H
#define SIGNER_ZONE_H

#include "adapter/adapter.h"
#include "dns/dname.h"
#include "dns/rr.h"
#include "schedule/schedule.h"
#include "schedule/task.h"
#include "signer/namedb.h"
#include "signer/signconf.h"
#include "util/locks.h"
#include "util/region.h"
#include "util/status.h"

#include <ldns/ldns.h>

enum zone_zl_status_enum {
    ZONE_ZL_OK = 0,
    ZONE_ZL_ADDED,
    ZONE_ZL_UPDATED,
    ZONE_ZL_REMOVED
};
typedef enum zone_zl_status_enum zone_zl_status;

/**
 * Zone.
 *
 */
typedef struct zone_struct zone_type;
struct zone_struct {
    region_type* region;           /* zone memory region */
    dname_type* apex;              /* zone owner domain name */
    ldns_rr_class klass;           /* class */
    uint32_t default_ttl;          /* default ttl */
    zone_zl_status zl_status;      /* zonelist status */
    task_type* task;               /* next assigned task */
    signconf_type* signconf;       /* signer configuration */
    namedb_type* namedb;           /* zone data */
    /* from conf.xml */
    const char* notify_ns;         /* name server reload command */
    /* from zonelist.xml */
    const char* name;              /* zone name */
    const char* policy_name;       /* kasp name */
    const char* signconf_filename; /* signconf filename */
    /* adapters */
    adapter_type* adapter_in;
    adapter_type* adapter_out;
    /* zone transfers */
    /* worker variables */
    /* statistics */
    lock_basic_type zone_lock;

    /* 4x int, 4x ptr, 4x charptr */
    /* est.mem: Z: 320 bytes + 2*A + SC (with avg strlen 32) */
};

/**
 * Create a new zone.
 * @param name:  zone name.
 * @param klass: zone class.
 * @return:      (zone_type*) zone.
 *
 */
zone_type* zone_create(char* name, uint16_t klass);

/**
 * Load signer configuration for zone.
 * @param zone:         zone.
 * @return:             (ods_status) status.
 *                      ODS_STATUS_OK: signconf loaded.
 *                      ODS_STATUS_UNCHANGED: signconf has not changed.
 *                      other: signconf not loaded, error occurred.
 *
 */
ods_status zone_load_signconf(zone_type* zone);

/**
 * Merge zones. Values that are merged:
 * - policy name
 * - signconf filename
 * - input and output adapter
 *
 * @param z1: zone.
 * @param z2: zone with new values.
 *
 */
void zone_merge(zone_type* z1, zone_type* z2);

/**
 * Reschedule task for zone.
 * @param zone: zone.
 * @param s:    schedule.
 * @param what: new task identifier.
 * @return:     (ods_status) status.
 *
 */
ods_status zone_reschedule_task(zone_type* zone, schedule_type* s, int what);

/**
 * Add rr to zone.
 * @param zone:     zone.
 * @param rr:       rr.
 * @param do_stats: do we need to maintain stats.
 * @return:         (ods_status) status.
 *
 */
ods_status zone_add_rr(zone_type* zone, rr_type* rr, int do_stats);

/**
 * Print zone.
 * @param fd:   file descriptor.
 * @param zone: zone.
 * @return:     (ods_status) status.
 *
 */
ods_status zone_print(FILE* fd, zone_type* zone);

/**
 * Clean up zone.
 * @param zone: zone.
 *
 */
void zone_cleanup(zone_type* zone);

#endif /* SIGNER_ZONE_H */

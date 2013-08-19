/*
 * $Id: zone.c 7039 2013-02-15 08:10:15Z matthijs $
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

#include "config.h"
#include "dns/dname.h"
#include "signer/signconf.h"
#include "rzonec/zonec.h"
#include "signer/zone.h"
#include "util/duration.h"
#include "util/log.h"
#include "util/str.h"

static const char* logstr = "zone";


/**
 * Initialize zone.
 *
 */
static void
zone_init(zone_type* zone)
{
    zone->signconf = signconf_create(zone->region);
    zone->namedb = namedb_create(zone);
    zone->default_ttl = DEFAULT_TTL;
    zone->policy_name = NULL;
    zone->signconf_filename = NULL;
    zone->task = NULL;
    zone->adapter_in = NULL;
    zone->adapter_out = NULL;
    lock_basic_init(&zone->zone_lock);
    return;
}


/**
 * Create a new zone.
 *
 */
zone_type*
zone_create(char* name, uint16_t klass)
{
    region_type* region = NULL;
    zone_type* zone = NULL;
    ods_log_assert(name);
    ods_log_assert(klass);
    region = region_create();
    if (!region) {
        ods_log_crit("[%s] region create failed", logstr);
        exit(1);
    }
    zone = (zone_type*) region_alloc(region,  sizeof(zone_type));
    zone->region = region;
    zone->klass = klass;
    /* [start] PS 9218653: Drop trailing dot in domain name */
    if (strlen(name) > 1 && name[strlen(name)-1] == '.') {
        name[strlen(name)-1] = '\0';
    }
    /* [end] PS 9218653 */
    zone->name = (const char*) region_strdup(region, name);
    zone->apex = dname_create(region, name);
    if (!zone->apex) {
        ods_log_crit("[%s] apex %s create failed", logstr, name);
        exit(1);
    }
    zone_init(zone);
    return zone;
}


/**
 * Load signer configuration for zone.
 *
 */
ods_status
zone_load_signconf(zone_type* zone)
{
    ods_status status = ODS_STATUS_OK;
    char* datestamp = NULL;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->signconf);
    ods_log_assert(zone->signconf_filename);
    status = signconf_update(zone->signconf, zone->signconf_filename);
    if (status == ODS_STATUS_OK) {
        (void)time_datestamp(zone->signconf->last_modified, "%Y-%m-%d %T",
            &datestamp);
        ods_log_debug("[%s] zone %s signconf file %s is modified since %s",
            logstr, zone->name, zone->signconf_filename,
            datestamp?datestamp:"Unknown");
        free((void*)datestamp);
    } else if (status == ODS_STATUS_UNCHANGED) {
        (void)time_datestamp(zone->signconf->last_modified,
            "%Y-%m-%d %T", &datestamp);
        ods_log_verbose("[%s] zone %s signconf file %s is unchanged since "
            "%s", logstr, zone->name, zone->signconf_filename,
            datestamp?datestamp:"Unknown");
        free((void*)datestamp);
    } else {
        ods_log_error("[%s] zone %s update signconf %s failed: %s", logstr,
            zone->name, zone->signconf_filename, ods_status2str(status));
    }
    return status;
}



/**
 * Merge zones.
 *
 */
void
zone_merge(zone_type* z1, zone_type* z2)
{
    const char* str;
    if (!z1 || !z2) {
        return;
    }
    /* policy name */
    if (ods_strcmp(z2->policy_name, z1->policy_name) != 0) {
        if (z2->policy_name) {
            str = strdup(z2->policy_name);
            if (!str) {
                ods_log_crit("[%s] strdup(%s) failed: insufficient memory",
                    logstr, z2->policy_name);
            } else {
                free((void*)z1->policy_name);
                z1->policy_name = str;
                z1->zl_status = ZONE_ZL_UPDATED;
            }
        } else {
            free((void*)z1->policy_name);
            z1->policy_name = NULL;
            z1->zl_status = ZONE_ZL_UPDATED;
        }
    }
    /* signconf filename */
    if (ods_strcmp(z2->signconf_filename, z1->signconf_filename) != 0) {
        if (z2->signconf_filename) {
            str = strdup(z2->signconf_filename);
            if (!str) {
                ods_log_crit("[%s] strdup(%s) failed: insufficient memory",
                    logstr, z2->signconf_filename);
            } else {
                free((void*)z1->signconf_filename);
                z1->signconf_filename = str;
                z1->zl_status = ZONE_ZL_UPDATED;
            }
        } else {
            free((void*)z1->signconf_filename);
            z1->signconf_filename = NULL;
            z1->zl_status = ZONE_ZL_UPDATED;
        }
    }
    /* adapters */
    return;
}


/**
 * Reschedule task for zone.
 *
 */
ods_status
zone_reschedule_task(zone_type* zone, schedule_type* s, int what)
{
     task_type* task = NULL;
     ods_status status = ODS_STATUS_OK;
     ods_log_assert(zone);
     ods_log_assert(zone->name);
     ods_log_assert(zone->task);
     ods_log_assert(s);
     ods_log_debug("[%s] reschedule task for zone %s", logstr, zone->name);
     lock_basic_lock(&s->s_lock);
     task = unschedule_task(s, (task_type*) zone->task);
     if (task != NULL) {
         if (task->what != (task_id) what) {
             task->halted = task->what;
             task->halted_when = task->when;
             task->interrupt = (task_id) what;
         }
         /** Only reschedule if what to do is lower than what was scheduled. */
         if (task->what > (task_id) what) {
             task->what = (task_id) what;
         }
         task->when = time_now();
         status = schedule_task(s, task, 0);
     } else {
         /* task not queued, being worked on? */
         ods_log_verbose("[%s] unable to reschedule task for zone %s now: "
             "task is not queued (task will be rescheduled when it is put "
             "back on the queue)", logstr, zone->name);
         task = (task_type*) zone->task;
         task->interrupt = (task_id) what;
         /* task->halted(_when) set by worker */
     }
     lock_basic_unlock(&s->s_lock);
     return status;
}


/**
 * Add rr to zone.
 *
 */
ods_status
zone_add_rr(zone_type* zone, rr_type* rr, int do_stats)
{
    ods_status status;
    domain_type* domain;
    rrset_type* rrset;
    record_type* record;
    rr_type* clone;
    ods_log_assert(zone);
    ods_log_assert(rr);
    clone = rr_clone(zone->region, rr);
    domain = namedb_lookup_domain(zone->namedb, clone->owner);
    if (!domain) {
        domain = namedb_add_domain(zone->namedb, clone->owner);
        ods_log_assert(domain);
        if (dname_compare(domain->dname, zone->apex) == 0) {
            domain->is_apex = 1;
        } else {
            status = namedb_entize(zone->namedb, domain, zone->apex);
            if (status != ODS_STATUS_OK) {
                char str[DNAME_MAXLEN*5];
                dname_str(domain->dname, &str[0]);
                ods_log_error("[%s] failed to entize domain %s: %s", logstr,
                    str, ods_status2str(status));
                return ODS_STATUS_ENTIZEERR;
            }
        }
    }
    rrset = domain_lookup_rrset(domain, clone->type);
    if (!rrset) {
        rrset = rrset_create(domain, clone->type);
        ods_log_assert(rrset);
        domain_add_rrset(domain, rrset);
    }
    record = rrset_lookup_rr(rrset, clone);
    if (record) {
        record->is_added = 1; /* already exists, just mark added */
        record->is_removed = 0; /* unset is_removed */
        /* set ttl */
        rrset->needs_singing = 1;
        return ODS_STATUS_UNCHANGED;
    }
    record = rrset_add_rr(rrset, clone);
    ods_log_assert(record);
    ods_log_assert(record->rr);
    ods_log_assert(record->is_added);
    rr_log(record->rr, "[namedb] +RR", LOG_DEEEBUG);
    return ODS_STATUS_OK;
}


/**
 * Commit differences in zone as a result of reading an unsigned zone.
 *
 */
void
zone_commit_diff(zone_type* zone, unsigned incremental, unsigned more_coming)
{
    return;
}


/**
 * Clean up zone.
 *
 */
ods_status
zone_print(FILE* fd, zone_type* zone)
{
    ods_status status = ODS_STATUS_OK;
    ods_log_assert(fd);
    ods_log_assert(zone);
    namedb_print(fd, zone->namedb, &status);
    return status;
}


/**
 * Clean up zone.
 *
 */
void
zone_cleanup(zone_type* zone)
{
    lock_basic_type zone_lock;
    if (!zone) {
        return;
    }
    zone_lock = zone->zone_lock;
    free((void*) zone->policy_name);
    free((void*) zone->signconf_filename);
    adapter_cleanup(zone->adapter_in);
    adapter_cleanup(zone->adapter_out);
    dname_cleanup(zone->apex);
    namedb_cleanup(zone->namedb);
    signconf_cleanup(zone->signconf);
    region_cleanup(zone->region);
    lock_basic_destroy(&zone_lock);
    return;
}

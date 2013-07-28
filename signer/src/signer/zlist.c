/*
 * $Id: zlist.c 6166 2012-02-14 15:36:44Z matthijs $
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

#include "config.h"
#include "parser/confparser.h"
#include "parser/zlistparser.h"
#include "signer/zlist.h"
#include "signer/zone.h"
#include "util/duration.h"
#include "util/file.h"
#include "util/log.h"

static const char* logstr = "zonelist";


/**
 * Compare two zones.
 *
 */
static int
zone_compare(const void* a, const void* b)
{
    zone_type* x = (zone_type*)a;
    zone_type* y = (zone_type*)b;
    ods_log_assert(x);
    ods_log_assert(y);
    if (x->klass != y->klass) {
        if (x->klass < y->klass) {
            return -1;
        }
        return 1;
    }
    return strncmp(x->name, y->name, strlen(x->name));
}


/**
 * Create a new zone list.
 *
 */
zlist_type*
zlist_create(region_type* r)
{
    zlist_type* zlist;
    ods_log_assert(r);
    zlist = (zlist_type*) region_alloc(r, sizeof(zlist_type));
    if (!zlist) {
        ods_log_crit("[%s] region_alloc failed", logstr);
        return NULL;
    }
    zlist->zones = ldns_rbtree_create(zone_compare);
    if (!zlist->zones) {
        ods_log_crit("[%s] rbtree create failed", logstr);
        free((void*) zlist);
        return NULL;
    }
    zlist->last_modified = 0;
    zlist->just_added = 0;
    zlist->just_updated = 0;
    zlist->just_removed = 0;
    lock_basic_init(&zlist->zl_lock);
    return zlist;
}


/**
 * Convert a zone to a tree node.
 *
 */
static ldns_rbnode_t*
zone2node(zone_type* zone)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) calloc(1, sizeof(ldns_rbnode_t));
    if (!node) {
        return NULL;
    }
    node->key = zone;
    node->data = zone;
    return node;
}


/**
 * Lookup zone.
 *
 */
static zone_type*
zlist_lookup_zone(zlist_type* zlist, zone_type* zone)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    if (zlist && zlist->zones && zone) {
        node = ldns_rbtree_search(zlist->zones, zone);
        if (node) {
            return (zone_type*) node->data;
        }
    }
    return NULL;
}


/**
 * Add zone.
 *
 */
zone_type*
zlist_add_zone(zlist_type* zlist, zone_type* zone)
{
    ldns_rbnode_t* new_node = NULL;
    ods_log_assert(zlist);
    ods_log_assert(zlist->zones);
    ods_log_assert(zone);
    /* look up */
    if (zlist_lookup_zone(zlist, zone) != NULL) {
        ods_log_warning("[%s] failed to add zone %s: already present",
            logstr, zone->name);
        zone_cleanup(zone);
        return NULL;
    }
    /* add */
    new_node = zone2node(zone);
    if (ldns_rbtree_insert(zlist->zones, new_node) == NULL) {
        ods_log_error("[%s] rbtree insert failed", logstr, zone->name);
        free((void*) new_node);
        zone_cleanup(zone);
        return NULL;
    }
    zone->zl_status = ZONE_ZL_ADDED;
    zlist->just_added++;
    return zone;
}


/**
 * Delete zone.
 *
 */
zone_type*
zlist_del_zone(zlist_type* zlist, zone_type* zone)
{
    ldns_rbnode_t* old_node = LDNS_RBTREE_NULL;
    if (!zlist || !zlist->zones || !zone) {
        goto zlist_del_zone_notpresent;
    }
    old_node = ldns_rbtree_delete(zlist->zones, zone);
    if (!old_node) {
        goto zlist_del_zone_notpresent;
    }
    /* decrement zonelist's just_removed in merge */
    free((void*) old_node);
    return zone;

zlist_del_zone_notpresent:
    ods_log_warning("[%s] zone %s not present", logstr, zone->name);
    return zone;
}


/**
 * Read a zonelist file.
 *
 */
static ods_status
zlist_read(zlist_type* zl, const char* zlfile)
{
    const char* rngfile = ODS_SE_RNGDIR "/zonelist.rng";
    ods_status status = ODS_STATUS_OK;
    ods_log_assert(zl);
    ods_log_assert(zlfile);
    ods_log_verbose("[%s] read file %s", logstr, zlfile);
    status = parser_filecheck(zlfile, rngfile);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] parse error in zonelist %s", logstr, zlfile);
        return status;
    }
    return parser_zlist_zones((struct zlist_struct*) zl, zlfile);
}


/**
 * Merge zone lists.
 *
 */
static void
zlist_merge(zlist_type* zl1, zlist_type* zl2)
{
    zone_type* z1 = NULL;
    zone_type* z2 = NULL;
    ldns_rbnode_t* n1 = LDNS_RBTREE_NULL;
    ldns_rbnode_t* n2 = LDNS_RBTREE_NULL;
    int ret = 0;
    ods_log_assert(zl1);
    ods_log_assert(zl2);
    ods_log_assert(zl1->zones);
    ods_log_assert(zl2->zones);
    ods_log_debug("[%s] merge two zone lists", logstr);
    n1 = ldns_rbtree_first(zl1->zones);
    n2 = ldns_rbtree_first(zl2->zones);
    while (n2 && n2 != LDNS_RBTREE_NULL) {
        z2 = (zone_type*) n2->data;
        if (n1 && n1 != LDNS_RBTREE_NULL) {
            z1 = (zone_type*) n1->data;
        } else {
            z1 = NULL;
        }
        if (!z2) {
            /* no more zones to merge into zl1 */
            return;
        } else if (!z1) {
            /* just add remaining zones from zl2 */
            z2 = zlist_add_zone(zl1, z2);
            if (!z2) {
                ods_log_crit("[%s] merge failed: z2 not added", logstr);
                return;
            }
            n2 = ldns_rbtree_next(n2);
        } else {
            /* compare the zones z1 and z2 */
            ret = zone_compare(z1, z2);
            if (ret < 0) {
                /* remove zone z1, it is not present in the new list zl2 */
                z1->zl_status = ZONE_ZL_REMOVED;
                zl1->just_removed++;
                n1 = ldns_rbtree_next(n1);
            } else if (ret > 0) {
                /* add the new zone z2 */
                z2 = zlist_add_zone(zl1, z2);
                if (!z2) {
                    ods_log_crit("[%s] merge failed: z2 not added", logstr);
                    return;
                }
                n2 = ldns_rbtree_next(n2);
            } else {
                /* just update zone z1 */
                n1 = ldns_rbtree_next(n1);
                n2 = ldns_rbtree_next(n2);
                zone_merge(z1, z2);
                zone_cleanup(z2);
                if (z1->zl_status == ZONE_ZL_UPDATED) {
                    zl1->just_updated++;
                }
                z1->zl_status = ZONE_ZL_UPDATED;
            }
        }
    }
    /* remove remaining zones from z1 */
    while (n1 && n1 != LDNS_RBTREE_NULL) {
        z1 = (zone_type*) n1->data;
        z1->zl_status = ZONE_ZL_REMOVED;
        zl1->just_removed++;
        n1 = ldns_rbtree_next(n1);
    }
    zl1->last_modified = zl2->last_modified;
    return;
}


/**
 * Update zone list.
 *
 */
ods_status
zlist_update(zlist_type* zl, const char* zlfile)
{
    region_type* r = NULL;
    zlist_type* new_zlist = NULL;
    time_t st_mtime = 0;
    ods_status status = ODS_STATUS_OK;
    char* datestamp = NULL;
    ods_log_debug("[%s] update zone list", logstr);
    ods_log_assert(zl);
    ods_log_assert(zl->zones);
    ods_log_assert(zlfile);
    /* is the file updated? */
    st_mtime = ods_fstat(zlfile);
    if (st_mtime <= zl->last_modified) {
        (void)time_datestamp(zl->last_modified, "%Y-%m-%d %T", &datestamp);
        ods_log_debug("[%s] zonelist file %s is unchanged since %s",
            logstr, zlfile, datestamp?datestamp:"Unknown");
        free((void*)datestamp);
        return ODS_STATUS_UNCHANGED;
    }
    /* create new zonelist */
    r = region_create();
    if (!r) {
        ods_log_error("[%s] region create failed", logstr);
        return ODS_STATUS_MALLOCERR;
    }
    new_zlist = zlist_create(r);
    if (!new_zlist) {
        ods_log_error("[%s] create zonelist failed", logstr);
        return ODS_STATUS_MALLOCERR;
    }
    /* read zonelist */
    status = zlist_read(new_zlist, zlfile);
    if (status == ODS_STATUS_OK) {
        zl->just_added = 0;
        zl->just_updated = 0;
        zl->just_removed = 0;
        new_zlist->last_modified = st_mtime;
        zlist_merge(zl, new_zlist);
        (void)time_datestamp(zl->last_modified, "%Y-%m-%d %T", &datestamp);
        ods_log_debug("[%s] file %s is modified since %s", logstr, zlfile,
            datestamp?datestamp:"Unknown");
        free((void*)datestamp);
    } else {
        ods_log_error("[%s] read file %s failed (%s)", logstr, zlfile,
            ods_status2str(status));
    }
    zlist_free(new_zlist);
    region_cleanup(r);
    zl->just_removed = 0;
    zl->just_added = 0;
    zl->just_updated = 0;
    return status;
}


/**
 * Internal node cleanup function.
 *
 */
static void
node_delfunc(ldns_rbnode_t* elem)
{
    if (elem && elem != LDNS_RBTREE_NULL) {
        node_delfunc(elem->left);
        node_delfunc(elem->right);
        free((void*)elem);
    }
    return;
}


/**
 * Free zonelist.
 *
 */
void
zlist_free(zlist_type* zl)
{
    if (!zl) {
        return;
    }
    if (zl->zones) {
        node_delfunc(zl->zones->root);
        ldns_rbtree_free(zl->zones);
    }
    lock_basic_destroy(&zl->zl_lock);
    return;
}


/**
 * Internal zone cleanup function.
 *
 */
static void
zone_delfunc(ldns_rbnode_t* elem)
{
    zone_type* zone;
    if (elem && elem != LDNS_RBTREE_NULL) {
        zone = (zone_type*) elem->data;
        zone_delfunc(elem->left);
        zone_delfunc(elem->right);
        ods_log_deeebug("[%s] cleanup zone %s", logstr, zone->name);
        zone_cleanup(zone);
        free((void*)elem);
    }
    return;
}


/**
 * Clean up a zonelist.
 *
 */
void
zlist_cleanup(zlist_type* zl)
{
    if (!zl) {
        return;
    }
    ods_log_debug("[%s] cleanup zones", logstr);
    if (zl->zones) {
        zone_delfunc(zl->zones->root);
        ldns_rbtree_free(zl->zones);
    }
    lock_basic_destroy(&zl->zl_lock);
    return;
}


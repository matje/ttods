/*
 * $Id: rrset.c 7178 2013-07-02 10:33:21Z matthijs $
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
 * RRset.
 *
 */

#include "config.h"
#include "util/log.h"
#include "signer/rrset.h"
#include "signer/zone.h"

static const char* logstr = "rrset";


/**
 * Log RRset.
 *
 */
void
rrset_log(dname_type* dname, uint16_t type, const char* pre, int level)
{
    rrstruct_type* rrstruct = dns_rrstruct_by_type(type);
    char str[DNAME_MAXLEN*5];
    char rrtype[10];
    dname_str(dname, &str[0]);
    (void)snprintf(&rrtype[0], 10, "TYPE%u", (unsigned) type);
    if (level == LOG_EMERG) {
        ods_fatal_exit("%s: <%s,%s>",  pre?pre:"", str,
            rrstruct->name?rrstruct->name:rrtype);
    } else if (level == LOG_ALERT) {
        ods_log_alert("%s: <%s,%s>",   pre?pre:"", str,
            rrstruct->name?rrstruct->name:rrtype);
    } else if (level == LOG_CRIT) {
        ods_log_crit("%s: <%s,%s>",    pre?pre:"", str,
            rrstruct->name?rrstruct->name:rrtype);
    } else if (level == LOG_ERR) {
        ods_log_error("%s: <%s,%s>",   pre?pre:"", str,
            rrstruct->name?rrstruct->name:rrtype);
    } else if (level == LOG_WARNING) {
        ods_log_warning("%s: <%s,%s>", pre?pre:"", str,
            rrstruct->name?rrstruct->name:rrtype);
    } else if (level == LOG_NOTICE) {
        ods_log_info("%s: <%s,%s>", pre?pre:"", str,
            rrstruct->name?rrstruct->name:rrtype);
    } else if (level == LOG_INFO) {
        ods_log_verbose("%s: <%s,%s>", pre?pre:"", str,
            rrstruct->name?rrstruct->name:rrtype);
    } else if (level == LOG_DEBUG) {
        ods_log_debug("%s: <%s,%s>", pre?pre:"", str,
            rrstruct->name?rrstruct->name:rrtype);
    } else if (level == LOG_DEEEBUG) {
        ods_log_deeebug("%s: <%s,%s>", pre?pre:"", str,
            rrstruct->name?rrstruct->name:rrtype);
    } else {
        ods_log_deeebug("%s: <%s,%s>", pre?pre:"", str,
            rrstruct->name?rrstruct->name:rrtype);
    }
    return;
}


/**
 * Create RRset.
 *
 */
rrset_type*
rrset_create(struct domain_struct* domain, uint16_t type)
{
    rrset_type* rrset = NULL;
    ods_log_assert(domain);
    ods_log_assert(domain->zone);
    ods_log_assert(domain->zone->region);
    ods_log_assert(type);
    rrset = (rrset_type*) region_alloc(domain->zone->region,
        sizeof(rrset_type));
    rrset->domain = domain;
    rrset->next = NULL;
    rrset->rrs = NULL;
    rrset->rrtype = type;
    rrset->rr_count = 0;
    rrset->needs_singing = 0;
    return rrset;
}


/**
 * Lookup RR in RRset.
 *
 */
record_type*
rrset_lookup_rr(rrset_type* rrset, rr_type* rr)
{
    size_t i = 0;
    if (!rrset || !rr || rrset->rr_count <= 0) {
       return NULL;
    }
    for (i=0; i < rrset->rr_count; i++) {
        if (rr_compare_rdata(rrset->rrs[i].rr, rr) == 0) {
            return &rrset->rrs[i];
        }
    }
    return NULL;
}


/**
 * Add RR to RRset.
 *
 */
record_type*
rrset_add_rr(rrset_type* rrset, rr_type* rr)
{
    rr_type* rrs_old = NULL;
    zone_type* zone = NULL;
    ods_log_assert(rrset);
    ods_log_assert(rr);
    ods_log_assert(rrset->rrtype == rr->type);
    zone = (zone_type*) rrset->domain->zone;
    rrs_old = rrset->rrs;
    rrset->rrs = (rr_type*) region_alloc(zone->region,
        (rrset->rr_count + 1) * sizeof(rr_type));
    if (rrs_old) {
        memcpy(rrset->rrs, rrs_old, (rrset->rr_count) * sizeof(rr_type));
    }
    rrset->rr_count++;
    rrset->rrs[rrset->rr_count - 1].rr = rr;
    rrset->rrs[rrset->rr_count - 1].exists = 0;
    rrset->rrs[rrset->rr_count - 1].is_added = 1;
    rrset->rrs[rrset->rr_count - 1].is_removed = 0;
    rrset->needs_singing = 1;
    return &rrset->rrs[rrset->rr_count -1];
}


/**
 * Apply differences in rrset.
 *
 */
void
rrset_diff(rrset_type* rrset, unsigned incremental, unsigned more_coming)
{
    ods_log_assert(rrset);
    return;
}


/**
 * Print rrset.
 *
 */
void
rrset_print(FILE* fd, rrset_type* rrset, int skipsigs, ods_status* status)
{
    uint16_t i;
    ods_log_assert(fd);
    ods_log_assert(rrset);
    ods_log_assert(status);
    for (i=0; i < rrset->rr_count; i++) {
        rr_print(fd, rrset->rrs[i].rr);
    }
    *status = ODS_STATUS_OK;
    return;
}


/**
 * Clean up RRset.
 *
 */
void
rrset_cleanup(rrset_type* rrset)
{
    if (!rrset) {
       return;
    }
    return;
}

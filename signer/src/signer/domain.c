/*
 * $Id: domain.c 6988 2013-01-29 10:57:11Z matthijs $
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
 * Domain.
 *
 */

#include "config.h"
#include "signer/domain.h"
#include "signer/zone.h"
#include "util/log.h"

static const char* logstr = "domain";


/**
 * Create domain.
 *
 */
domain_type*
domain_create(struct zone_struct* zone, dname_type* dname)
{
    domain_type* domain = NULL;
    ods_log_assert(zone);
    ods_log_assert(zone->region);
    ods_log_assert(dname);
    domain = (domain_type*) region_alloc(zone->region, sizeof(domain_type));
    domain->dname = dname_clone(zone->region, dname);
    domain->zone = zone;
    domain->node = NULL; /* not in db yet */
    domain->parent = NULL;
    domain->is_apex = 0;
    domain->is_new = 0;
    return domain;
}


/**
 * Look up RRset at this domain.
 *
 */
rrset_type*
domain_lookup_rrset(domain_type* domain, uint16_t rrtype)
{
    rrset_type* rrset = NULL;
    ods_log_assert(domain);
    ods_log_assert(rrtype);
    rrset = domain->rrsets;
    while (rrset && rrset->rrtype != rrtype) {
        rrset = rrset->next;
    }
    return rrset;
}


/**
 * Add RRset to domain.
 *
 */
void
domain_add_rrset(domain_type* domain, rrset_type* rrset)
{
    rrset_type** p = NULL;
    ods_log_assert(domain);
    ods_log_assert(rrset);
    if (!domain->rrsets) {
        domain->rrsets = rrset;
    } else {
        p = &domain->rrsets;
        while(*p) {
            p = &((*p)->next);
        }
        *p = rrset;
        rrset->next = NULL;
    }
    rrset_log(domain->dname, rrset->rrtype, "[namedb] +RRSET", LOG_DEEEBUG);
    rrset->domain = (void*) domain;
    /* TODO: update denial */
    return;
}


/**
 * Delete RRset from domain.
 *
 */
/*
rrset_type*
domain_del_rrset(domain_type* domain, ldns_rr_type rrtype)
{
    rrset_type* cur = NULL;
    ods_log_assert(domain);
    ods_log_assert(rrtype);
    if (!domain->rrsets) {
        ods_log_warning("[%s] delete RRset failed: RRset with RRtype %s "
            "does not exist", logstr, rrset_type2str(rrtype));
        return NULL;
    }
    if (domain->rrsets->rrtype == rrtype) {
        cur = domain->rrsets;
        domain->rrsets = cur->next;
        cur->domain = NULL;
        cur->next = NULL;
        log_rrset(domain->dname, rrtype, "-RRSET", LOG_DEEEBUG);
        TODO: update denial
        return cur;
    }
    cur = domain->rrsets;
    while (cur) {
        if (!cur->next) {
            ods_log_warning("[%s] delete RRset failed: RRset with RRtype %s "
                "does not exist", logstr, rrset_type2str(rrtype));
            return NULL;
        }
        ods_log_assert(cur->next);
        if (cur->next->rrtype != rrtype) {
            cur = cur->next;
        } else {
            ods_log_assert(cur->next->rrtype == rrtype);
            cur->next = cur->next->next;
            cur = cur->next;
            cur->domain = NULL;
            cur->next = NULL;
            log_rrset(domain->dname, rrtype, "-RRSET", LOG_DEEEBUG);
            TODO: update denial
            return cur;
        }
    }
    ods_log_warning("[%s] delete RRset failed: RRset with RRtype %s "
        "does not exist", logstr, rrset_type2str(rrtype));
    return NULL;
}
*/


/**
 * Apply differences in domain.
 *
 */
void
domain_diff(domain_type* domain, unsigned incremental, unsigned more_coming)
{
    rrset_type* rrset;
    ods_log_assert(domain);
    rrset = domain->rrsets;
    while (rrset) {
        rrset_diff(rrset, incremental, more_coming);
        rrset = rrset->next;
    }
    return;
}


/**
 * Print domain.
 *
 */
void
domain_print(FILE* fd, domain_type* domain, ods_status* status)
{
    rrset_type* rrset;
    rrset_type* cname_rrset = NULL;
    ods_log_assert(fd);
    ods_log_assert(domain);
    ods_log_assert(status);
    /* empty non-terminal? */
    if (!domain->rrsets) {
        fprintf(fd, ";;Empty non-terminal ");
        dname_print(fd, domain->dname);
        fprintf(fd, "\n");
        return;
    }
    if (cname_rrset) {
        rrset_print(fd, cname_rrset, 0, status);
    } else {
        if (domain->is_apex) {
            rrset = domain_lookup_rrset(domain, DNS_TYPE_SOA);
            if (rrset) {
                rrset_print(fd, rrset, 0, status);
                if (*status != ODS_STATUS_OK) {
                    return;
                }
            }
        }
        rrset = domain->rrsets;
        while (rrset) {
            if (rrset->rrtype != DNS_TYPE_SOA) {
                rrset_print(fd, rrset, 0, status);
                if (*status != ODS_STATUS_OK) {
                    return;
                }
            }
            rrset = rrset->next;
        }
    }
    /* denial of existence */
    return;
}


/**
 * Clean up domain.
 *
 */
void
domain_cleanup(domain_type* domain)
{
    if (!domain) {
        return;
    }
    return;
}

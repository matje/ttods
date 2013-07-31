/*
 * $Id: domain.h 6870 2012-11-27 13:01:48Z matthijs $
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

#ifndef SIGNER_DOMAIN_H
#define SIGNER_DOMAIN_H

#include "config.h"
#include "dns/dname.h"
#include "util/region.h"
#include "util/status.h"
#include "util/tree.h"

#include <time.h>

struct zone_struct;

/**
 * Domain.
 *
 */
typedef struct domain_struct domain_type;
struct domain_struct {
    dname_type* dname;
    struct zone_struct* zone;
    tree_node* node;
    domain_type* parent;
    unsigned is_new : 1;
    unsigned is_apex : 1; /* apex */
};

/**
 * Create domain.
 * @param zone:  corresponding zone.
 * @param dname: domain name.
 * @return:      (domain_type*) domain.
 *
 */
domain_type* domain_create(struct zone_struct* zone, dname_type* dname);

/**
 * Look up rrset at this domain.
 * @param domain: domain.
 * @param rrtype: RRtype.
 * @return:       (rrset_type*) rrset, NULL if not found.
 *
 */
/* rrset_type* domain_lookup_rrset(domain_type* domain, uint16_t rrtype); */

/**
 * Add rrset to domain.
 * @param domain: domain.
 * @param rrset:  rrset.
 *
 */
/* void domain_add_rrset(domain_type* domain, rrset_type* rrset); */

/**
 * Delete RRset from domain.
 * @param domain: domain.
 * @param rrtype: type of rrset.
 * @return:       (rrset_type*) deleted rrset, NULL if not found.
 *
 */
/* rrset_type* domain_del_rrset(domain_type* domain, uint16_t rrtype); */

/**
 * Clean up domain.
 * @param domain: domain to clean up.
 *
 */
void domain_cleanup(domain_type* domain);

#endif /* SIGNER_DOMAIN_H */

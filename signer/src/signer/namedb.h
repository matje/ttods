/*
 * $Id: namedb.h 5465 2011-08-23 14:39:28Z matthijs $
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

#ifndef SIGNER_NAMEDB_H
#define SIGNER_NAMEDB_H

#include "config.h"
#include "dns/dname.h"
#include "util/tree.h"
#include "util/region.h"
#include "util/status.h"
#include "signer/domain.h"

#include <stdio.h>
#include <ldns/ldns.h>

struct zone_struct;

/**
 * Domain name database.
 *
 */
typedef struct namedb_struct namedb_type;
struct namedb_struct {
    struct zone_struct* zone;
    tree_type* domains;
};

/**
 * Create a new namedb.
 * @param zone: corresponding zone.
 * @return:     (namedb_type*) namedb.
 *
 */
namedb_type* namedb_create(struct zone_struct* zone);

/**
 * Add empty non-terminals for domain to the apex.
 * @param db:     namedb.
 * @param domain: start from this domain.
 * @param apex:   zone apex domain name.
 * @return:       (ods_status) status.
 *
 */
ods_status namedb_entize(namedb_type* db, domain_type* domain,
   dname_type* apex);

/**
 * Look up domain.
 * @param db:    namedb.
 * @param dname: domain name.
 * @return:      (domain_type*) domain, NULL if not found.
 *
 */
domain_type* namedb_lookup_domain(namedb_type* db, dname_type* dname);

/**
 * Create new domain and add it to namedb.
 * @param db:    namedb.
 * @param dname: domain name.
 * @return:      (domain_type*) new domain.
 *
 */
domain_type* namedb_add_domain(namedb_type* db, dname_type* dname);

/**
 * Apply differences in namedb.
 * @param db:          namedb.
 * @param incremental: full (0) or incremental (1) differences.
 * @param more_coming: can we expect more parts?
 *
 */
void namedb_diff(namedb_type* db, unsigned incremental, unsigned more_coming);

/**
 * Nsecify namedb.
 * @param db: namedb.
 * @return:   (uint32_t) number of NSEC/NSEC3 rrs added.
 *
 */
uint32_t namedb_nsecify(namedb_type* db);

/**
 * Print namedb.
 * @param fd:     file descriptor.
 * @param namedb: namedb.
 * @param status: status.
 *
 */
void namedb_print(FILE* fd, namedb_type* db, ods_status* status);

/**
 * Clean up namedb.
 * @param namedb: namedb.
 *
 */
void namedb_cleanup(namedb_type* db);

#endif /* SIGNER_NAMEDB_H */

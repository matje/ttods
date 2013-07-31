/*
 * $Id: rrset.h 6870 2012-11-27 13:01:48Z matthijs $
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

#ifndef SIGNER_RRSET_H
#define SIGNER_RRSET_H

#include "config.h"
#include "dns/rr.h"
#include "dns/dname.h"
#include "util/status.h"

struct domain_struct;

/**
 * RR structure.
 *
 */
typedef struct record_struct record_type;
struct record_struct {
    rr_type* rr;
    unsigned exists : 1;
    unsigned is_added : 1;
    unsigned is_removed : 1;
};

/**
 * RRset structure.
 *
 */
typedef struct rrset_struct rrset_type;
struct rrset_struct {
    rrset_type* next;
    struct domain_struct* domain;
    uint16_t rrtype;
    record_type* rrs;
    size_t rr_count;
    unsigned needs_singing : 1;
};

/**
 * Log rrset.
 * @param dname: domain name.
 * @param type:  rr type.
 * @param pre:   log message.
 * @param level: log level.
 *
 */
void log_rrset(dname_type* dname, uint16_t type, const char* pre, int level);

/**
 * Create rrset.
 * @param domain: corresponding domain.
 * @param type:   rr type.
 * @return:       (rrset_type*) rrset.
 *
 */
rrset_type* rrset_create(struct domain_struct* domain, uint16_t type);

/**
 * Lookup rr in rrset.
 * @param rrset: rrset.
 * @param rr:    rr.
 * @return       (record_type*) record, NULL if not found.
 *
 */
record_type* rrset_lookup_rr(rrset_type* rrset, rr_type* rr);

/**
 * Add rr to rrset.
 * @param rrset: rrset.
 * @param rr:    rr.
 * @return:      (record_type*) added record.
 *
 */
record_type* rrset_add_rr(rrset_type* rrset, rr_type* rr);

/**
 * Clean up rrset.
 * @param rrset: rrset to be cleaned up.
 *
 */
void rrset_cleanup(rrset_type* rrset);

#endif /* SIGNER_RRSET_H */

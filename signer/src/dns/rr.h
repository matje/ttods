/*
 * $Id: rr.h 6501 2012-08-06 10:52:03Z matthijs $
 *
 * Copyright (c) 2013 NLNet Labs. All rights reserved.
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
 * Resource records.
 *
 */

#ifndef DNS_RR_H
#define DNS_RR_H

#include "dns/dname.h"
#include "dns/dns.h"
#include "dns/rdata.h"
#include "util/region.h"

#include <stdio.h>


/**
 * Resource record structure.
 *
 */
typedef struct rr_struct rr_type;
struct rr_struct {
    dname_type* owner; /* redundant: already in rrset */
    rdata_type* rdata;
    uint32_t ttl;
    uint16_t klass; /* redundant: all rrs in zone is same class */
    uint16_t type;  /* redundant: already in rrset */
    uint16_t rdlen;
};

/**
 * Clone record.
 * @param rr:     rr.
 * @return:       (rr_type*) cloned rr.
 *
 */
rr_type* rr_clone(region_type* region, rr_type* rr);

/**
 * Compare records.
 * @param rr1:    one record.
 * @param rr2:    another record.
 * @return:       (int) 0 if equal, <0 if rr1 is smaller, >0 otherwise.
 *
 */
int rr_compare_rdata(rr_type* rr1, rr_type* rr2);

/**
 * Print rr type.
 * @param fd:     file descriptor.
 * @param rrtype: rr type.
 *
 */
void rr_print_rrtype(FILE* fd, uint16_t rrtype);

/**
 * Print class.
 * @param fd:     file descriptor.
 * @param klass:  class.
 *
 */
void rr_print_class(FILE* fd, uint16_t klass);

/**
 * Print rr.
 * @param fd:     file descriptor.
 * @param rr:     rr.
 *
 */
void rr_print(FILE* fd, rr_type* rr);

/**
 * Log rr.
 * @param rr:     rr.
 * @param pre:    log message.
 * @param level:  log level.
 *
 */
void rr_log(rr_type* rr, const char* pre, int level);

#endif /* DNS_RR_H */


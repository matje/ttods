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
    dname_type* owner; /* TODO: pointer to domain node */
    rdata_type* rdata;
    uint32_t ttl;
    uint16_t type;
    uint16_t klass;
    uint16_t rdlen;
};

/**
 * Print RRtype.
 * @param fd:     file descriptor.
 * @param rrtype: RRtype.
 *
 */
void rr_print_rrtype(FILE* fd, uint16_t rrtype);

/**
 * Print CLASS.
 * @param fd:    file descriptor.
 * @param klass: CLASS.
 *
 */
void rr_print_class(FILE* fd, uint16_t klass);

#endif /* DNS_RR_H */


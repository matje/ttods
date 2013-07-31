/*
 * $Id: rdata.h 6501 2012-08-06 10:52:03Z matthijs $
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
 * RDATA.
 *
 */

#ifndef DNS_RDATA_H
#define DNS_RDATA_H

#include "dns/dname.h"
#include "dns/dns.h"
#include "util/region.h"

/**
 * RDATA structure.
 *
 */
typedef union rdata_union rdata_type;
union rdata_union {
    /** (Un)compressed) domain names */
    dname_type* dname; /* TODO: pointer to domain node */
    /* All other RDATA elements. */
    uint16_t*   data;
};

/**
 * Get data from rdata element.
 * @param rdata: rdata.
 * @return:      (uint8_t*) data.
 *
 */
uint8_t* rdata_get_data(rdata_type* rdata);


/**
 * Get domain name from rdata element.
 * @param rdata: rdata.
 * @return:      (dname_type*) domain name.
 *
 */
dname_type* rdata_get_dname(rdata_type* rdata);


/**
 * Print rdta element.
 * @param fd:     file descriptor.
 * @param rdata:  rdata.
 * @param rrtype: RRtype.
 * @param pos:    position of RDATA element in RR.
 *
 */
void rdata_print(FILE* fd, rdata_type* rdata, uint16_t rrtype, uint8_t pos);

#endif /* DNS_RDATA_H */


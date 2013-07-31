/*
 * $Id: rr.c 6501 2012-08-06 10:52:03Z matthijs $
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

#include "dns.h"
#include "rr.h"

static const char* logstr = "rr";


/**
 * Compare records only on RDATA.
 *
 */
int
rr_compare_rdata(rr_type* rr1, rr_type* rr2)
{
    size_t i;
    int res;
    rrstruct_type* rrstruct;
    ods_log_assert(rr1);
    ods_log_assert(rr2);
    ods_log_assert(!dname_compare(rr1->owner, rr2->owner));
    ods_log_assert(rr1->type == rr2->type);
    ods_log_assert(rr1->klass == rr2->klass);
    ods_log_assert(rr1->rdlen == rr2->rdlen);
    rrstruct = dns_rrstruct_by_type(rr1->type);
    for (i=0; i < rr1->rdlen; i++) {
        switch (rrstruct->rdata[i]) {
            case DNS_RDATA_COMPRESSED_DNAME:
            case DNS_RDATA_UNCOMPRESSED_DNAME:
                res = dname_compare(rdata_get_dname(&rr1->rdata[i]),
                    rdata_get_dname(&rr2->rdata[i]));
                break;
            case DNS_RDATA_IPV4:
            case DNS_RDATA_INT32:
            case DNS_RDATA_TIMEF:
            case DNS_RDATA_BINARY:
            default:
                if (rdata_size(&rr1->rdata[i]) < rdata_size(&rr2->rdata[i])) {
                    return 1;
                }
                if (rdata_size(&rr1->rdata[i]) > rdata_size(&rr2->rdata[i])) {
                    return -1;
                }
                res = memcmp(rdata_get_data(&rr1->rdata[i]),
                    rdata_get_data(&rr2->rdata[i]), rdata_size(&rr1->rdata[i]));
                break;
        }
        if (res) {
            return res;
        }
    }
    return 0;
}


/**
 * Print RRtype.
 *
 */
void
rr_print_rrtype(FILE* fd, uint16_t rrtype)
{
    rrstruct_type* rrstruct = dns_rrstruct_by_type(rrtype);
    if (rrstruct->name) {
        fprintf(fd, "%s", rrstruct->name);
    } else {
        fprintf(fd, "TYPE%d", (int) rrtype);
    }
    return;
}


/**
 * Print CLASS.
 *
 */
void
rr_print_class(FILE* fd, uint16_t klass)
{
    rrclass_type* rrclass = dns_rrclass_by_type(klass);
    if (rrclass->name) {
        fprintf(fd, "%s", rrclass->name);
    } else {
        fprintf(fd, "CLASS%d", (int) klass);
    }
    return;
}


/**
 * Print rr.
 *
 */
void
rr_print(FILE* fd, rr_type* rr)
{
    uint16_t i;
    ods_log_assert(fd);
    ods_log_assert(rr);
    fprintf(fd, "owner:");
    dname_print(fd, rr->owner);
    fprintf(fd, "\t");
    fprintf(fd, "ttl:%u", rr->ttl);
    fprintf(fd, "\t");
    fprintf(fd, "class:");
    rr_print_class(fd, rr->klass);
    fprintf(fd, " ");
    fprintf(fd, "type:");
    rr_print_rrtype(fd, rr->type);
    fprintf(fd, "\t");
    fprintf(fd, "rdata:");
    for (i=0; i < rr->rdlen; i++) {
        rdata_print(fd, &rr->rdata[i], rr->type, i);
    }
    fprintf(fd, "\n");
    return;
}

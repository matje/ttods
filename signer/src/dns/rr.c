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

#include "dns/dns.h"
#include "dns/rr.h"

/*
static const char* logstr = "rr";
*/


/**
 * Clone record.
 *
 */
rr_type*
rr_clone(region_type* region, rr_type* rr)
{
    size_t i;
    rrstruct_type* rrstruct;
    rr_type* clone;
    ods_log_assert(region);
    ods_log_assert(rr);
    rrstruct = dns_rrstruct_by_type(rr->type);
    clone = (rr_type*) region_alloc(region, sizeof(rr_type));
    clone->owner = dname_clone(region, rr->owner);
    clone->rdata = (rdata_type*) region_alloc(region,
        rr->rdlen * sizeof(rdata_type));
    clone->ttl = rr->ttl;
    clone->klass = rr->klass;
    clone->type = rr->type;
    clone->rdlen = rr->rdlen;
    for (i=0; i < rr->rdlen; i++) {
        if (rrstruct->rdata[i] == DNS_RDATA_COMPRESSED_DNAME ||
            rrstruct->rdata[i] == DNS_RDATA_UNCOMPRESSED_DNAME) {
            clone->rdata[i].dname = dname_clone(region, rr->rdata[i].dname);
        } else {
            clone->rdata[i].data = rdata_init_data(region,
                rdata_get_data(&rr->rdata[i]), rdata_size(&rr->rdata[i]));
        }
    }
    return clone;
}


/**
 * Compare records only on RDATA.
 *
 */
int
rr_compare_rdata(rr_type* rr1, rr_type* rr2)
{
    size_t i;
    size_t rdlen;
    int res;
    rrstruct_type* rrstruct;
    ods_log_assert(rr1);
    ods_log_assert(rr2);
    ods_log_assert(!dname_compare(rr1->owner, rr2->owner));
    ods_log_assert(rr1->type == rr2->type);
    ods_log_assert(rr1->klass == rr2->klass);
    rrstruct = dns_rrstruct_by_type(rr1->type);
    rdlen = rr1->rdlen < rr2->rdlen ? rr1->rdlen : rr2->rdlen;

    for (i=0; i < rdlen; i++) {
        switch (rrstruct->rdata[i]) {
            case DNS_RDATA_COMPRESSED_DNAME:
            case DNS_RDATA_UNCOMPRESSED_DNAME:
                res = dname_compare(rdata_get_dname(&rr1->rdata[i]),
                    rdata_get_dname(&rr2->rdata[i]));
                break;
            case DNS_RDATA_NXTBM:
            case DNS_RDATA_IPV4:
            case DNS_RDATA_INT8:
            case DNS_RDATA_INT16:
            case DNS_RDATA_INT32:
            case DNS_RDATA_TIMEF:
            case DNS_RDATA_DATETIME:
            case DNS_RDATA_SERVICES:
            case DNS_RDATA_TEXT:
            case DNS_RDATA_TEXTS:
            case DNS_RDATA_NSAP:
            case DNS_RDATA_RRTYPE:
            case DNS_RDATA_BASE64:
            case DNS_RDATA_UNKNOWN:
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
    if (rr1->rdlen < rr2->rdlen) {
        res = 1;
    } else if (rr1->rdlen > rr2->rdlen) {
        res = -1;
    } else {
        res = 0;
    }
    return res;
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
    dname_print(fd, rr->owner);
    fprintf(fd, "\t");
    fprintf(fd, "%u", rr->ttl);
    fprintf(fd, "\t");
    rr_print_class(fd, rr->klass);
    fprintf(fd, " ");
    rr_print_rrtype(fd, rr->type);
    fprintf(fd, "\t");
    for (i=0; i < rr->rdlen; i++) {
        rdata_print(fd, &rr->rdata[i], rr, i);
        if (i+1 < rr->rdlen) fprintf(fd, " ");
    }
    fprintf(fd, "\n");
    return;
}


/**
 * Log rr.
 *
 */
void
rr_log(rr_type* rr, const char* pre, int level)
{
    rrstruct_type* rrstruct;
    rrclass_type* rrclass;
    char str[DNAME_MAXLEN*5];
    char rrtype[10];
    char rrklass[11];
    ods_log_assert(rr);
    ods_log_assert(rr->owner);
    dname_str(rr->owner, &str[0]);
    (void)snprintf(&rrtype[0], 10, "TYPE%u", (unsigned) rr->type);
    (void)snprintf(&rrklass[0], 10, "CLASS%u", (unsigned) rr->klass);
    rrclass = dns_rrclass_by_type(rr->klass);
    rrstruct = dns_rrstruct_by_type(rr->type);
    if (level == LOG_EMERG) {
        ods_fatal_exit("%s: %s %u %s %s ...",  pre?pre:"", str, rr->ttl,
            rrclass->name?rrclass->name:rrklass,
            rrstruct->name?rrstruct->name:rrtype);
    } else if (level == LOG_ALERT) {
        ods_log_alert("%s: %s %u %s %s ...",   pre?pre:"", str, rr->ttl,
            rrclass->name?rrclass->name:rrklass,
            rrstruct->name?rrstruct->name:rrtype);
    } else if (level == LOG_CRIT) {
        ods_log_crit("%s: %s %u %s %s ...",    pre?pre:"", str, rr->ttl,
            rrclass->name?rrclass->name:rrklass,
            rrstruct->name?rrstruct->name:rrtype);
    } else if (level == LOG_ERR) {
        ods_log_error("%s: %s %u %s %s ...",   pre?pre:"", str, rr->ttl,
            rrclass->name?rrclass->name:rrklass,
            rrstruct->name?rrstruct->name:rrtype);
    } else if (level == LOG_WARNING) {
        ods_log_warning("%s: %s %u %s %s ...", pre?pre:"", str, rr->ttl,
            rrclass->name?rrclass->name:rrklass,
            rrstruct->name?rrstruct->name:rrtype);
    } else if (level == LOG_NOTICE) {
        ods_log_info("%s: %s %u %s %s ...",    pre?pre:"", str, rr->ttl,
            rrclass->name?rrclass->name:rrklass,
            rrstruct->name?rrstruct->name:rrtype);
    } else if (level == LOG_INFO) {
        ods_log_verbose("%s: %s %u %s %s ...", pre?pre:"", str, rr->ttl,
            rrclass->name?rrclass->name:rrklass,
            rrstruct->name?rrstruct->name:rrtype);
    } else if (level == LOG_DEBUG) {
        ods_log_debug("%s: %s %u %s %s ...",   pre?pre:"", str, rr->ttl,
            rrclass->name?rrclass->name:rrklass,
            rrstruct->name?rrstruct->name:rrtype);
    } else if (level == LOG_DEEEBUG) {
        ods_log_deeebug("%s: %s %u %s %s ...", pre?pre:"", str, rr->ttl,
            rrclass->name?rrclass->name:rrklass,
            rrstruct->name?rrstruct->name:rrtype);
    } else {
        ods_log_deeebug("%s: %s %u %s %s ...", pre?pre:"", str, rr->ttl,
            rrclass->name?rrclass->name:rrklass,
            rrstruct->name?rrstruct->name:rrtype);
    }
    return;
}

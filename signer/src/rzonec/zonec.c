/*
 * zonec.c -- zone compiler functions.
 *
 * Copyright (c) 2013, Matthijs Mekking, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "rzonec/zonec.h"
#include "util/log.h"
#include "util/util.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static const char* logstr = "zonec";


/**
 * Allocate memory for RDATA element and initialize with data.
 *
 */
static uint16_t*
zonec_rdata_init(region_type *region, const void *data, size_t size)
{
    uint16_t *result = region_alloc(region, sizeof(uint16_t) + size);
    *result = size;
    memcpy(result + 1, data, size);
    return result;
}


/**
 * Convert IPv4 address into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_ipv4(region_type* region, const char* buf)
{
    in_addr_t address;
    uint16_t *r = NULL;
    if (inet_pton(AF_INET, buf, &address) != 1) {
        ods_log_error("[%s] error: invalid rdata IPv4 address '%s'", logstr,
            buf);
    } else {
        r = zonec_rdata_init(region, &address, sizeof(address));
    }
    return r;
}


/**
 * Convert domain name into RDATA element.
 *
 */
static dname_type*
zonec_rdata_dname(region_type* region, const char* buf)
{
    return dname_create(region, buf);
}


/**
 * Convert serial into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_int32(region_type* region, const char* buf)
{
    uint32_t number = htonl(atoi(buf));
    return zonec_rdata_init(region, &number, sizeof(number));
}


/**
 * Convert time format into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_timef(region_type* region, const char* buf)
{
    uint16_t* r = NULL;
    uint32_t timef;
    const char* end;
    timef = util_str2ttl(buf, &end);
    if (*end != '\0') {
        ods_log_error("[%s] error: invalid rdata time '%s'", logstr,
            buf);
    } else {
        timef = htonl(timef);
        r = zonec_rdata_init(region, &timef, sizeof(timef));
    }
    return r;
}


/**
 * Add parsed RDATA element into currently parsed resource record.
 *
 */
int
zonec_rdata_add(region_type* region, rr_type* rr, dns_rdata_format rdformat,
   const char* rdbuf, size_t rdsize)
{
    char str[DNAME_MAXLEN*5];
    uint16_t* d = NULL;
    dname_type* dname = NULL;
    if (rr->rdlen > DNS_RDATA_MAX) {
        ods_log_error("[%s] error: too many rdata elements", logstr);
        return 0;
    }
    if (!rdsize) {
        ods_log_error("[%s] error: empty rdata element", logstr);
        return 0;
    }

    switch (rdformat) {
        case DNS_RDATA_IPV4:
            d = zonec_rdata_ipv4(region, rdbuf);
            break;
        case DNS_RDATA_COMPRESSED_DNAME:
            dname = zonec_rdata_dname(region, rdbuf);
            dname_str(dname, &str[0]);
            break;
        case DNS_RDATA_INT32:
            d = zonec_rdata_int32(region, rdbuf);
            break;
        case DNS_RDATA_TIMEF:
            d = zonec_rdata_timef(region, rdbuf);
            break;
        case DNS_RDATA_UNCOMPRESSED_DNAME:
        case DNS_RDATA_BINARY:
            d = NULL;
            dname = NULL;
            break;
    }

    if (rdformat == DNS_RDATA_COMPRESSED_DNAME
        || rdformat == DNS_RDATA_UNCOMPRESSED_DNAME) {
        if (!dname) {
            ods_log_error("[%s] error: bad rdata element '%s'", logstr,
                rdbuf);
            return 0;
        }
        rr->rdata[rr->rdlen].dname = dname;
    } else {
        if (!d) {
            ods_log_error("[%s] error: bad rdata element '%s'", logstr,
                rdbuf);
            return 0;
        }
        rr->rdata[rr->rdlen].data = d;
    }
    rr->rdlen++;
    return 1;
}

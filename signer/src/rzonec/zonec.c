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
        ods_log_error("[%s] error: invalid IPv4 address '%s'\n", logstr, buf);
    } else {
        r = zonec_rdata_init(region, &address, sizeof(address));
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
    uint16_t* d = NULL;
    if (rr->rdlen > DNS_RDATA_MAX) {
        ods_log_error("[%s] error: too many rdata elements\n", logstr);
        return 0;
    }
    if (!rdsize) {
        ods_log_error("[%s] error: empty rdata element\n", logstr);
        return 0;
    }

    switch (rdformat) {
        case DNS_RDATA_IPV4:
            d = zonec_rdata_ipv4(region, rdbuf);
    }

    if (!d) {
        ods_log_error("[%s] error: bad rdata element '%s'\n", logstr, rdbuf);
        return 0;
    }
    rr->rdata[rr->rdlen].data = d;
    rr->rdlen++;
    return 1;
}


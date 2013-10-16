/*
 * zonec.c -- zone compiler functions.
 *
 * Copyright (c) 2013, Matthijs Mekking, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "rzonec/zonec.h"
#include "dns/rdata.h"
#include "util/log.h"
#include "util/str.h"
#include "util/util.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* logstr = "zonec";


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
        r = rdata_init_data(region, &address, sizeof(address));
    }
    return r;
}


/**
 * Convert int16 into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_int16(region_type* region, const char* buf)
{
    uint16_t number = htons(atoi(buf));
    return rdata_init_data(region, &number, sizeof(number));
}


/**
 * Convert int32 into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_int32(region_type* region, const char* buf)
{
    uint32_t number = htonl(atoi(buf));
    return rdata_init_data(region, &number, sizeof(number));
}


/**
 * Convert text format into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_text(region_type* region, const char* buf, size_t buflen)
{
    size_t size = buflen+1;
    uint16_t* r = region_alloc(region, sizeof(uint16_t) + size);
    uint8_t* p;
    *r = size;
    p = (uint8_t*) (r+1);
    *p = buflen;
    memcpy(p+1, buf, buflen);
    return r;
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
        ods_log_error("[%s] error: invalid rdata time '%s'", logstr, buf);
    } else {
        timef = htonl(timef);
        r = rdata_init_data(region, &timef, sizeof(timef));
    }
    return r;
}


/**
 * Convert protocol and services into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_wks(region_type* region, const char* buf)
{
    static char rdata[DNS_RDLEN_MAX];
    char sep = ' ';
    uint16_t* r = NULL;
    uint8_t* protocol;
    uint8_t bitmap[65536/8];
    struct protoent* proto;
    char* service;
    char* next = NULL;
    char* delim;
    int max_port = 0;
    size_t size = 0;
    size_t offset = 0;

    (void)memcpy(rdata, buf, strlen(buf));
    ods_strreplace(rdata, '\t', sep);
    service = rdata;

    /* PROTOCOL */
    delim = ods_strchr_and_fwd(rdata, sep, &offset);
    if (delim) {
       next = delim+offset;
       *delim = '\0';
    }
    proto = getprotobyname(rdata);
    if (!proto) {
        getprotobynumber(atoi(rdata));
    }
    if (!proto) {
        ods_log_error("[%s] error: invalid protocol '%s'", logstr, rdata);
    } else {
        /* BITMAP */
        while (next && *next) {
            struct servent* serv;
            int port;
            service = next;
            next = NULL;
            delim = ods_strchr_and_fwd(service, sep, &offset);
            if (delim) {
                next = delim+offset;
                *delim = '\0';
            }
            /* convert service to bit */
            serv = getservbyname(service, proto->p_name);
            if (serv) {
                port = ntohs((uint16_t) serv->s_port);
            } else {
                char* end;
                port = strtol(service, &end, 10);
                if (*end != '\0') {
                    ods_log_error("[%s] error: unknown service '%s'", logstr,
                        service);
                    return NULL;
                }
            }
            if (port < 0 || port > 65535) {
                ods_log_error("[%s] error: invalid port '%u'", logstr,
                    (unsigned) port);
                return NULL;
            } else {
                util_setbit(bitmap, port);
                if (port > max_port) {
                    max_port = port;
                }
            }
        }
        /* variant of rdata_init_data */
        size = sizeof(uint8_t) + (max_port/8) + 1;
        r = region_alloc(region, sizeof(uint16_t) + size);
        *r = size;
        protocol = (uint8_t*) (r+1);
        *protocol = proto->p_proto;
        memcpy(protocol+1, bitmap, *r);
    }
    return r;
}


/**
 * Add parsed RDATA element into currently parsed resource record.
 *
 */
int
zonec_rdata_add(region_type* region, rr_type* rr, dns_rdata_format rdformat,
    dname_type* name, const char* rdbuf, size_t rdsize)
{
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
            dname = name;
            break;
        case DNS_RDATA_INT16:
            d = zonec_rdata_int16(region, rdbuf);
            break;
        case DNS_RDATA_INT32:
            d = zonec_rdata_int32(region, rdbuf);
            break;
        case DNS_RDATA_TIMEF:
            d = zonec_rdata_timef(region, rdbuf);
            break;
        case DNS_RDATA_WKS:
            d = zonec_rdata_wks(region, rdbuf);
            break;
        case DNS_RDATA_TEXT:
        case DNS_RDATA_TEXTS:
            d = zonec_rdata_text(region, rdbuf, rdsize);
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

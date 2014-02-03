/*
 * zonec.c -- zone compiler functions.
 *
 * Copyright (c) 2013, Matthijs Mekking, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "config.h"
#include "rzonec/zonec.h"
#include "compat/b64.h"
#include "dns/rdata.h"
#include "util/log.h"
#include "util/str.h"
#include "util/util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* logstr = "zonec";


/**
 * Parse integer.
 *
 */
static int
zonec_parse_int(const char* str, char** end, int* result,
    const char* name, int min, int max)
{
    *result = (int) strtol(str, end, 10);
    if (*result < min || *result > max) {
        ods_log_error("[%z] error: loc %s must be within the range "
            "[%d...%d]", logstr, name, min, max);
        return 0;
    }
    if (!isspace((int)**end) && **end != '\0' && **end != 'm') {
        ods_log_error("[%z] error: bad %s in loc rdata", logstr, name);
        return 0;
    }
    return 1;
}


/**
 * Convert base64 format into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_base64(region_type* region, const char* buf)
{
    uint8_t rdata[DNS_RDLEN_MAX];
    uint16_t* r = NULL;
    int i;
    bzero(rdata, sizeof(rdata));
    i = b64_pton(buf, rdata, DNS_RDLEN_MAX);
    if (i < 0) {
        ods_log_error("[%s] error: invalid base64 '%s' (ret %d)",
            logstr, buf, i);
    } else {
        r = rdata_init_data(region, rdata, i);
    }
    return r;
}


/**
 * Convert RRtype bitmap into RDATA element (NXT).
 *
 */
static uint16_t*
zonec_rdata_bitmap_nxt(region_type* region, const char* buf)
{
    static char rdata[DNS_RDLEN_MAX];
    char* next = NULL;
    char* delim;
    char* rrtype;
    char sep = ' ';
    uint8_t bitmap[16];
    size_t offset = 0;
    uint16_t i;
    uint16_t last = 0;

    (void)memset(bitmap, 0, sizeof(bitmap));
    (void)memset(rdata, 0, sizeof(rdata));
    (void)memcpy(rdata, buf, strlen(buf));
    (void)ods_strtriml(rdata);
    ods_strreplace(rdata, '\t', sep);
    rrtype = rdata;
    delim = ods_strchr_and_fwd(rrtype, sep, &offset);
    if (delim) {
        next = delim+offset;
        *delim = '\0';
    }

    while (rrtype && *rrtype) {
        uint16_t t = dns_rrtype_by_name(rrtype);
        if (t != 0 && t < 128) {
            util_setbit(bitmap, t);
        } else {
            ods_log_error("[%s] error: invalid rrtype in bitmap '%s'", logstr,
                rrtype);
            return NULL;
        }
        rrtype = next;
        delim = ods_strchr_and_fwd(next, sep, &offset);
        if (delim) {
            next = delim+offset;
            *delim = '\0';
        }
    }

    for (i = 0; i < 16; i++) {
        if (bitmap[i] != 0) last = i + 1;
    }
    return rdata_init_data(region, bitmap, last);
}


/**
 * Convert datetime format into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_datetime(region_type* region, const char* buf)
{
    uint16_t* r = NULL;
    struct tm tm;
    if (!strptime(buf, "%Y%m%d%H%M%S", &tm)) { /* TODO compat function */
        ods_log_error("[%s] error: invalid datetime '%s'", logstr, buf);
    } else {
        uint32_t dt = htonl(util_mktime_from_utc(&tm));
        r = rdata_init_data(region, &dt, sizeof(dt));
    }
    return r;
}


/**
 * Convert hex format into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_hex(region_type* region, const char* buf, size_t buflen)
{
    uint16_t* r = NULL;
    uint8_t* t;
    int i;

    if (buflen % 2 != 0) {
        ods_log_error("[%s] error: invalid hex length %u (must be a multiple "
            "of 2)", logstr, (unsigned) buflen);
    } else {
        r = region_alloc(region, sizeof(uint16_t) + (buflen/2));
        *r = buflen/2;
        t = (uint8_t*) (r+1);
        while (*buf) {
            i = 16;
            *t = 0;
            while (i >= 1) {
                ods_log_assert(isxdigit((int)*buf));
                *t += util_hexdigit2int(*buf) * i;
                i -= 15;
                buf++;
            }
            t++;
        }
    }


    return r;
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
        r = rdata_init_data(region, &address, sizeof(address));
    }
    return r;
}


/**
 * Convert IPv6 address into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_ipv6(region_type* region, const char* buf)
{
    uint8_t address[DNS_IPV6_ADDRLEN];
    uint16_t *r = NULL;

    if (inet_pton(AF_INET6, buf, address) != 1) {
        ods_log_error("[%s] error: invalid rdata IPv6 address '%s'", logstr,
            buf);
    } else {
        r = rdata_init_data(region, address, sizeof(address));
    }
    return r;
}


/**
 * Convert int8 into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_int8(region_type* region, const char* buf)
{
    uint8_t number = atoi(buf);
    return rdata_init_data(region, &number, sizeof(number));
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
 * Convert LOC latitude/longitude.
 *
 */
static int
zonec_rdata_loc_dms(const char* buf, char** end, int* d, int* m, int* s,
    char* c, int degrees, char c1, char c2)
{
    int sec = 0;
    int f = 0;
    /* degrees */
    if (!zonec_parse_int(buf, end, d, "degrees", 0, degrees)) {
        return 0;
    }
    if (!isspace((int)*buf)) {
        return 0;
    }
    while(isspace((int)*buf)) {
        ++buf;
    }
    if (*buf == c1 || *buf == c2) {
        *c = *buf;
        return 1;
    }
    /* minutes */
    if (!zonec_parse_int(buf, end, m, "minutes", 0, 59)) {
        return 0;
    }
    if (!isspace((int)*buf)) {
        return 0;
    }
    while(isspace((int)*buf)) {
        ++buf;
    }
    if (*buf == c1 || *buf == c2) {
        *c = *buf;
        return 1;
    }
    /* seconds */
    if (!zonec_parse_int(buf, end, &sec, "seconds", 0, 59)) {
        return 0;
    }
    if (*buf == '.') {
        ++buf;
        if (!zonec_parse_int(buf, end, &f, "seconds fraction", 0, 999)) {
            return 0;
        }
    }
    *s = (1000*sec + f);
    if (!isspace((int)*buf)) {
        return 0;
    }
    while(isspace((int)*buf)) {
        ++buf;
    }
    if (*buf == c1 || *buf == c2) {
        *c = *buf;
        return 1;
    }
    return 0;
}


/**
 * Convert loc format into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_loc(region_type* region, const char* buf)
{
    uint32_t lat, lon, alt;
    int d, m, s;
    char c;
    /* latitude */
    d = 0;
    m = 0;
    s = 0;
    c = 0;
    if (!zonec_rdata_loc_dms(buf, (char**) &buf, &d, &m, &s, &c, 90,
        'N', 'S')) {
        goto loc_error;
    }
    switch (c) {
        case 'N':
            lat = ((uint32_t)1<<31) + (3600000*d + 60000*m + s);
            break;
        case 'S':
            lat = ((uint32_t)1<<31) - (3600000*d + 60000*m + s);
            break;
        default:
            goto loc_error;
            break;
    }
    /* longitude */
    d = 0;
    m = 0;
    s = 0;
    c = 0;
    if (!zonec_rdata_loc_dms(buf, (char**) &buf, &d, &m, &s, &c, 180,
        'E', 'W')) {
        goto loc_error;
    }
    switch (c) {
        case 'E':
            lon = ((uint32_t)1<<31) + (3600000*d + 60000*m + s);
            break;
        case 'W':
            lon = ((uint32_t)1<<31) - (3600000*d + 60000*m + s);
            break;
        default:
            goto loc_error;
            break;
    }
    /* altitude */

    /* size */

    /* horizontal precision */

    /* vertical precision */

loc_error:
    return NULL;
}


/**
 * Convert nsap format into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_nsap(region_type* region, const char* buf, size_t buflen)
{
    return zonec_rdata_hex(region, buf, buflen);
}


/**
 * Convert rrtype format into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_rrtype(region_type* region, const char* buf)
{
    uint16_t* r = NULL;
    uint16_t type = dns_rrtype_by_name(buf);
    if (!type) {
        ods_log_error("[%s] error: unrecognized RRtype '%s'", logstr, buf);
    } else {
        type = htons(type);
        r = rdata_init_data(region, &type, sizeof(type));
    }
    return r;
}


/**
 * Convert services into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_services(region_type* region, const char* buf)
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

    (void)memset(bitmap, 0, sizeof(bitmap));
    (void)memset(rdata, 0, sizeof(rdata));
    (void)memcpy(rdata, buf, strlen(buf));
    (void)ods_strtriml(rdata);
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
        ods_log_error("[%s] error: empty %s rdata element", logstr,
            dns_rdata_format_str(rdformat));
        return 0;
    }

    ods_log_info("[%s] info: adding %s rdata element '%s'", logstr,
        dns_rdata_format_str(rdformat), rdbuf);

    switch (rdformat) {
        case DNS_RDATA_IPV4:
            d = zonec_rdata_ipv4(region, rdbuf);
            break;
        case DNS_RDATA_IPV6:
            d = zonec_rdata_ipv6(region, rdbuf);
            break;
        case DNS_RDATA_COMPRESSED_DNAME:
        case DNS_RDATA_UNCOMPRESSED_DNAME:
            dname = name;
            break;
        case DNS_RDATA_INT8:
            d = zonec_rdata_int8(region, rdbuf);
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
        case DNS_RDATA_SERVICES:
            d = zonec_rdata_services(region, rdbuf);
            break;
        case DNS_RDATA_FLOAT:
        case DNS_RDATA_TEXT:
        case DNS_RDATA_TEXTS:
            d = zonec_rdata_text(region, rdbuf, rdsize);
            break;
        case DNS_RDATA_NSAP:
            d = zonec_rdata_nsap(region, rdbuf, rdsize);
            break;
        case DNS_RDATA_RRTYPE:
            d = zonec_rdata_rrtype(region, rdbuf);
            break;
        case DNS_RDATA_DATETIME:
            d = zonec_rdata_datetime(region, rdbuf);
            break;
        case DNS_RDATA_BASE64:
            d = zonec_rdata_base64(region, rdbuf);
            break;
        case DNS_RDATA_BITMAP:
            d = zonec_rdata_bitmap_nxt(region, rdbuf);
            break;
        case DNS_RDATA_LOC:
            d = zonec_rdata_loc(region, rdbuf);
            break;
        case DNS_RDATA_BINARY: /* TODO */
            d = NULL;
            dname = NULL;
            break;
    }

    if (rdformat == DNS_RDATA_COMPRESSED_DNAME
        || rdformat == DNS_RDATA_UNCOMPRESSED_DNAME) {
        if (!dname) {
            ods_log_error("[%s] error: bad rdata dname '%s'", logstr,
                rdbuf);
            return 0;
        }
        rr->rdata[rr->rdlen].dname = dname;
    } else {
        if (!d) {
            ods_log_error("[%s] error: bad rdata %s '%s'", logstr,
                dns_rdata_format_str(rdformat), rdbuf);
            return 0;
        }
        rr->rdata[rr->rdlen].data = d;
    }
    rr->rdlen++;
    ods_log_debug("[%s] info: added %s rdata element '%s'", logstr,
        dns_rdata_format_str(rdformat), rdbuf);
    return 1;
}

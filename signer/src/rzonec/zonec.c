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
#include "wire/buffer.h"

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
zonec_parse_int(const char* str, char** end, int32_t* result,
    const char* name, int32_t min, int32_t max)
{
    *result = (int32_t) strtol(str, end, 10);
    if (*result < min || *result > max) {
        ods_log_error("[%z] error: loc %s must be within the range "
            "[%d...%d]", logstr, name, min, max);
        return 0;
    }
    if (!isspace((int)**end) && **end != '\0' && **end != 'm' &&
        **end != 'M' && **end != '.') {
        ods_log_error("[%s] error: bad %s in loc rdata: %c", logstr, name, **end);
        return 0;
    }
    return 1;
}


/**
 * Convert algorithm format into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_algorithm(region_type* region, const char* buf)
{
    uint16_t* r = NULL;
    uint8_t algo;
    if (isdigit((int)*buf)) {
        algo = (uint8_t) atoi(buf);
    } else {
        algo = dns_algorithm_by_name(buf);
        if (!algo) {
            ods_log_error("[%s] error: unrecognized algorithm '%s'",
                logstr, buf);
            return NULL;
        }
    }
    r = rdata_init_data(region, &algo, sizeof(algo));
    return r;
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
 * Convert certificate type format into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_cert_type(region_type* region, const char* buf)
{
    uint16_t* r = NULL;
    uint16_t ct;
    if (isdigit((int)*buf)) {
        ct = (uint16_t) atoi(buf);
    } else {
        ct = dns_cert_type_by_name(buf);
        if (!ct) {
            ods_log_error("[%s] error: unrecognized certificate type '%s'",
                logstr, buf);
            return NULL;
        }
    }
    ct = (uint16_t) htons(ct);
    r = rdata_init_data(region, &ct, sizeof(ct));
    return r;
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


/** RFC 1876 code samples */

/*
 * routines to convert between on-the-wire RR format and zone file
 * format.  Does not contain conversion to/from decimal degrees;
 * divide or multiply by 60*60*1000 for that.
 */
static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
    1000000,10000000,100000000,1000000000};

/* converts ascii size/precision X * 10**Y(cm) to 0xXY. moves pointer.*/
static uint8_t
zonec_rdata_loc_precsize_aton(char* cp, char **endptr)
{
    unsigned int mval = 0, cmval = 0;
    u_int8_t retval = 0;
    int exponent;
    int mantissa;
    while (isdigit((int)*cp)) mval = mval * 10 + (*cp++ - '0');
    /* centimeters */
    if (*cp == '.') {
        cp++;
        if (isdigit(*cp)) {
            cmval = (*cp++ - '0') * 10;
            if (isdigit(*cp)) {
                cmval += (*cp++ - '0');
            }
        }
    }
    cmval = (mval * 100) + cmval;
    for (exponent = 0; exponent < 9; exponent++)
        if (cmval < poweroften[exponent+1])
            break;
    mantissa = cmval / poweroften[exponent];
    if (mantissa > 9) mantissa = 9;
    ods_log_debug("[%s] debug: cmval %d mantissa %d exponent %d", logstr, cmval, mantissa, exponent);
    retval = (mantissa << 4) | exponent;
    if (*cp == 'm') cp++;
    *endptr = cp;
    return (retval);
}


/**
 * Convert LOC latitude/longitude.
 *
 */
static int
zonec_rdata_loc_dms(const char* buf, char** end, int32_t* d, int32_t* m,
    int32_t* s, int32_t* f, char* c, int32_t degrees, char c1, char c2)
{
    /* degrees */
    if (!zonec_parse_int(buf, end, d, "degrees", 0, degrees)) {
        return 0;
    }
    buf = (const char*) *end;
    if (!isspace((int)*buf)) {
        ods_log_error("[%s] error: bad degrees %c in loc rr", logstr, *buf);
        return 0;
    }
    while(isspace((int)*buf)) {
        ++buf;
    }
    if (*buf == c1 || *buf == c2) {
        *c = *buf;
        ++buf;
        *end = (char*) buf;
        return 1;
    }
    /* minutes */
    if (!zonec_parse_int(buf, end, m, "minutes", 0, 59)) {
        return 0;
    }
    buf = (const char*) *end;
    if (!isspace((int)*buf)) {
        ods_log_error("[%s] error: bad minutes %c in loc rr", logstr, *buf);
        return 0;
    }
    while(isspace((int)*buf)) {
        ++buf;
    }
    if (*buf == c1 || *buf == c2) {
        *c = *buf;
        ++buf;
        *end = (char*) buf;
        return 1;
    }
    /* seconds */
    if (!zonec_parse_int(buf, end, s, "seconds", 0, 59)) {
        return 0;
    }
    buf = (const char*) *end;
    if (*buf == '.') {
        ++buf;
        if (!zonec_parse_int(buf, end, f, "seconds fraction", 0, 999)) {
            return 0;
        }
        buf = (const char*) *end;
    }
    if (!isspace((int)*buf)) {
        ods_log_error("[%s] error: bad seconds %c in loc rr", logstr, *buf);
        return 0;
    }
    while(isspace((int)*buf)) {
        ++buf;
    }
    if (*buf == c1 || *buf == c2) {
        *c = *buf;
        ++buf;
        *end = (char*) buf;
        return 1;
    }
    ods_log_error("[%s] error: bad character %c in loc rr", logstr, *buf);
    return 0;
}


/**
 * Convert loc format into RDATA element.
 *
 */
static uint16_t*
zonec_rdata_loc(region_type* region, const char* buf)
{
    int i = 0;
    uint8_t precsize[3] = {0x12, 0x16, 0x13};
    uint32_t lat, lon, alt;
    int32_t d, m, s, f;
    char c;
    uint16_t* r;
    uint8_t* p;
    /* latitude */
    d = 0;
    m = 0;
    s = 0;
    f = 0;
    c = 0;
    if (!zonec_rdata_loc_dms(buf, (char**) &buf, &d, &m, &s, &f, &c, 90,
        'N', 'S')) {
        ods_log_error("[%s] error: bad latitude in loc rr", logstr);
        goto loc_error;
    }
    switch (c) {
        case 'N':
            lat = ((uint32_t)1<<31) + (3600000*d + 60000*m + 1000*s + f);
            break;
        case 'S':
            lat = ((uint32_t)1<<31) - (3600000*d + 60000*m + 1000*s + f);
            break;
        default:
            ods_log_error("[%s] error: bad northiness in loc rr", logstr);
            goto loc_error;
            break;
    }
    ods_log_debug("[%s] debug: latitude: %d %d %d.%d %c = %u", logstr, d, m, s, f, c, lat);

    /* longitude */
    d = 0;
    m = 0;
    s = 0;
    f = 0;
    c = 0;
    if (!zonec_rdata_loc_dms(buf, (char**) &buf, &d, &m, &s, &f, &c, 180,
        'E', 'W')) {
        ods_log_error("[%s] error: bad longitude in loc rr", logstr);
        goto loc_error;
    }
    switch (c) {
        case 'E':
            lon = ((uint32_t)1<<31) + (3600000*d + 60000*m + 1000*s + f);
            break;
        case 'W':
            lon = ((uint32_t)1<<31) - (3600000*d + 60000*m + 1000*s + f);
            break;
        default:
            ods_log_error("[%s] error: bad easterness in loc rr", logstr);
            goto loc_error;
            break;
    }
    ods_log_debug("[%s] debug: longitude: %d %d %d.%d %c = %u", logstr, d, m, s, f, c, lon);
    /* altitude */
    d = 0;
    m = 0;
    if (!zonec_parse_int(buf, (char**) &buf, &d, "altitude", -100000, 42849672)) {
        goto loc_error;
    }
    switch (*buf) {
        case 'm':
            ++buf;
            break;
        case ' ':
        case '\0':
            break;
        case '.':
            ++buf;
            if (!zonec_parse_int(buf, (char**) &buf, &m, "altitude fraction", 0, 99)) {
                goto loc_error;
            }
            if (*buf == 'm') {
               ++buf;
            }
            break;
        default:
            ods_log_error("[%s] error: bad altitude end in loc rr", logstr);
            goto loc_error;
            break;
    }
    alt = (uint32_t) 10000000 + (d*100 + m);
    if (*buf == '\0') {
        goto loc_done;
    }
    /* size */
loc_precsize:
    if (!isspace((int)*buf)) {
        ods_log_error("[%s] error: bad precsize[%i] in loc rr: %c", logstr, i, *buf);
        goto loc_error;
    }
    while(isspace((int)*buf)) {
        ++buf;
    }
    if (*buf == '\0') {
        goto loc_done;
    }
    if (i >= 3) {
        ods_log_error("[%s] error: too many precsizes in loc rr", logstr);
        goto loc_error;
    }
    precsize[i] = zonec_rdata_loc_precsize_aton((char*) buf, (char**) &buf);
    ++i;
    if (*buf == '\0') {
        goto loc_done;
    }
    goto loc_precsize;

loc_done:
    ods_log_debug("[%s] debug: loc rdata: sz %u hp %u vp %u lat %u lon %u alt %u",
        logstr, precsize[0], precsize[1], precsize[2], lat, lon, alt);
    r = region_alloc(region, sizeof(uint16_t) + 16);
    *r = 16;
    p = (uint8_t*) (r+1);
    *p = 0;
    *(p+1) = precsize[0];
    *(p+2) = precsize[1];
    *(p+3) = precsize[2];
    write_uint32(p+4, lat);
    write_uint32(p+8, lon);
    write_uint32(p+12, alt);
    return r;

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
        case DNS_RDATA_CERT_TYPE:
            d = zonec_rdata_cert_type(region, rdbuf);
            break;
        case DNS_RDATA_ALGORITHM:
            d = zonec_rdata_algorithm(region, rdbuf);
            break;
        case DNS_RDATA_UNKNOWN: /* TODO */
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
    ods_log_debug("[%s] debug: added %s rdata element '%s'", logstr,
        dns_rdata_format_str(rdformat), rdbuf);
    return 1;
}

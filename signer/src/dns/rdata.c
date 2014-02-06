/*
 * $Id: rdata.c 6501 2012-08-06 10:52:03Z matthijs $
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

#include "compat/b64.h"
#include "dns/dns.h"
#include "dns/rdata.h"
#include "dns/rr.h"
#include "dns/wf.h"
#include "util/util.h"
#include "wire/buffer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>

static const char* logstr = "rdata";


/**
 * Initialize rdata with data.
 *
 */
uint16_t*
rdata_init_data(region_type *region, const void *data, size_t size)
{
    uint16_t *result = region_alloc(region, sizeof(uint16_t) + size);
    *result = size;
    memcpy(result + 1, data, size);
    return result;
}


/**
 * Get size of rdata element.
 *
 */
uint16_t
rdata_size(rdata_type* rdata)
{
    return *rdata->data;
}


/**
 * Get data from rdata element.
 *
 */
uint8_t*
rdata_get_data(rdata_type* rdata)
{
    return (uint8_t*) (rdata->data + 1);
}


/**
 * Get domain name from rdata element.
 *
 */
dname_type*
rdata_get_dname(rdata_type* rdata)
{
    return rdata->dname;
}


/**
 * Print text format RDATA element.
 *
 */
static void
rdata_print_character_string(FILE* fd, rdata_type* rdata, int quoted)
{
    const uint8_t* d = rdata_get_data(rdata);
    uint8_t l = d[0];
    size_t i;
    if (quoted) fprintf(fd, "\"");
    for (i = 1; i <= l; ++i) {
        char c = (char) d[i];
        if (isprint((int)c)) {
            if (c == '"' || c == '\\') {
                fprintf(fd, "\\");
            }
            fprintf(fd, "%c", c);
        } else {
            fprintf(fd, "\\%03u", (unsigned) d[i]);
        }
    }
    if (quoted) fprintf(fd, "\"");
    return;
}


/**
 * Print apl format RDATA element.
 *
 */
static void
rdata_print_apl(FILE* fd, rdata_type* rdata)
{
    uint8_t* data = rdata_get_data(rdata);
    size_t size = rdata_size(rdata);
    uint16_t addressfamily;
    uint8_t prefix;
    uint8_t afdlen;
    int i, n, af;
    uint8_t afdpart[DNS_IPV6_ADDRLEN];
    char str[200];
    if (size && size < 4) {
        ods_log_error("[%s] error: print apl: too small", logstr);
        return;
    }
    addressfamily = wf_read_uint16(data);
    prefix = data[2];
    afdlen = data[3];
    n = afdlen & DNS_APL_N_MASK;
    afdlen &= DNS_APL_AFDLEN_MASK;
    if (size < 4+afdlen) {
        ods_log_error("[%s] error: print apl: too small", logstr);
        return;
    }
    switch (addressfamily) {
        case 1:  af = AF_INET;  break;
        case 2:  af = AF_INET6; break;
        default: af = 0;        break;
    }
    if (!af) {
        ods_log_error("[%s] error: print apl: unknown address family", logstr);
        return;
    }
    memset(afdpart, 0, sizeof(afdpart));
    for (i = 0; i < afdlen; i++) {
        afdpart[i] = data[4+i];
    }
    if (inet_ntop(af, afdpart, str, sizeof(str))) {
        fprintf(fd, "%s%d:%s/%d", n?"!":"", (int)addressfamily, str,
            (int) prefix);
    } else {
        ods_log_error("[%s] error: print apl: inet_ntop failed: %s", logstr,
            strerror(errno));
    }
    return;
}


/**
 * Print base64 format RDATA element.
 *
 */
static void
rdata_print_base64(FILE* fd, rdata_type* rdata)
{
    region_type* tmp;
    char* buf;
    uint8_t* data = rdata_get_data(rdata);
    size_t size = rdata_size(rdata);
    if (size == 0) {
        ods_log_error("[%s] error: print base64: empty rdata", logstr);
        return;
    }
    tmp = region_create_custom(sizeof(region_type) + size*2 + 1);
    if (!tmp) {
        ods_log_error("[%s] error: print base64: allocation failure", logstr);
        return;
    }
    buf = region_alloc(tmp, size*2 + 1);
    (void) b64_ntop(data, size, buf, size*2+1);
    fprintf(fd, "%s", buf);
    region_cleanup(tmp);
    return;
}


/**
 * Print bitmap format RDATA element (NXT).
 *
 */
static void
rdata_print_bitmap_nxt(FILE* fd, rdata_type* rdata)
{
    size_t i;
    uint8_t* bm = rdata_get_data(rdata);
    size_t size = rdata_size(rdata);
    int sequel = 0;
    for (i = 0; i < size*8; i++) {
       if (util_getbit(bm, i)) {
           if (sequel) fprintf(fd, " ");
           rr_print_rrtype(fd, i);
           sequel = 1;
       }
    }
   return;
}


/**
 * Print datetime format RDATA element.
 *
 */
static void
rdata_print_datetime(FILE* fd, rdata_type* rdata)
{
    time_t data = (time_t) wf_read_uint32(rdata_get_data(rdata));
    struct tm* tm = gmtime(&data);
    char buf[15];
    if (strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm)) {
        fprintf(fd, "%s", buf);
    } else {
        ods_log_error("[%s] error: print datetime: strftime failed", logstr);
    }
    return;
}


/**
 * Print dname RDATA element.
 *
 */
static void
rdata_print_dname(FILE* fd, rdata_type* rdata)
{
    char str[DNAME_MAXLEN*5];
    dname_str(rdata_get_dname(rdata), &str[0]);
    fprintf(fd, "%s", str);
    return;
}


/**
 * Print floating point format RDATA element.
 *
 */
static void
rdata_print_float(FILE* fd, rdata_type* rdata)
{
    rdata_print_character_string(fd, rdata, 0);
    return;
}


/**
 * Print int16 RDATA element.
 *
 */
static void
rdata_print_hex(FILE* fd, rdata_type* rdata)
{
    static const char hexdigit[] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    uint8_t* data = rdata_get_data(rdata);
    size_t size = rdata_size(rdata);
    size_t i;
    for (i=0; i < size; i++) {
        uint8_t octet = *data;
        fprintf(fd, "%c", (unsigned) hexdigit[octet >> 4]);
        fprintf(fd, "%c", (unsigned) hexdigit[octet & 0x0f]);
        data++;
    }
    return;
}


/**
 * Print int8 RDATA element.
 *
 */
static void
rdata_print_int8(FILE* fd, rdata_type* rdata)
{
    uint8_t data = wf_read_uint8(rdata_get_data(rdata));
    fprintf(fd, "%u", (unsigned) data);
    return;
}


/**
 * Print int16 RDATA element.
 *
 */
static void
rdata_print_int16(FILE* fd, rdata_type* rdata)
{
    uint16_t data = wf_read_uint16(rdata_get_data(rdata));
    fprintf(fd, "%lu", (unsigned long) data);
    return;
}


/**
 * Print int32 RDATA element.
 *
 */
static void
rdata_print_int32(FILE* fd, rdata_type* rdata)
{
    uint32_t data = wf_read_uint32(rdata_get_data(rdata));
    fprintf(fd, "%lu", (unsigned long) data);
    return;
}


/**
 * Print IPv4 RDATA element.
 *
 */
static void
rdata_print_ipv4(FILE* fd, rdata_type* rdata)
{
    char str[200];
    if (inet_ntop(AF_INET, rdata_get_data(rdata), str, sizeof(str))) {
        fprintf(fd, "%s", str);
    } else {
        ods_log_error("[%s] error: print ipv4: inet_ntop failed: %s", logstr,
            strerror(errno));
    }
    return;
}


/**
 * Print IPv6 RDATA element.
 *
 */
static void
rdata_print_ipv6(FILE* fd, rdata_type* rdata)
{
    char str[200];
    if (inet_ntop(AF_INET6, rdata_get_data(rdata), str, sizeof(str))) {
        fprintf(fd, "%s", str);
    } else {
        ods_log_error("[%s] error: print ipv6: inet_ntop failed: %s", logstr,
            strerror(errno));
    }
    return;
}


/**
 * Print latitude or longitude.
 *
 */
static void
rdata_print_loc_latlon(FILE* fd, uint32_t ll, char c1, char c2)
{
    char c;
    int d;
    int m;
    int s;
    int f;
    uint32_t llc = ll;
    uint32_t eq = (uint32_t)1 << 31;
    if (ll > eq) {
       c = c1;
       ll = ll - eq;
    } else {
       c = c2;
       ll = eq - ll;
    }
    d = ll / 3600000;
    ll = ll % 3600000;
    m = ll / 60000;
    ll = ll % 60000;
    s = ll / 1000.0;
    ll = ll % 1000;
    f = ll;
    ods_log_debug("[%s] debug: %u = %02u %02u %02u.%03u %c ", logstr, llc, d, m, s, f, c);
    fprintf(fd, "%d", d);
    if (m) fprintf(fd, " %d", m);
    if (s || f) {
        if (f) fprintf(fd, " %d.%d", s, f);
        else   fprintf(fd, " %d", s);
    }
    fprintf(fd, " %c ", c);
    return;
}

/** RFC 1876 code samples */

/*
 * routines to convert between on-the-wire RR format and zone file
 * format.  Does not contain conversion to/from decimal degrees;
 * divide or multiply by 60*60*1000 for that.
 */
static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
    1000000,10000000,100000000,1000000000};

/* takes an XeY precision/size value, returns a string representation.*/
static void
rdata_print_loc_precsize_ntoa(FILE* fd, uint8_t prec)
{
    int b, e;
    unsigned long val;
    int mantissa = (int)((prec >> 4) & 0x0f) % 10;
    int exponent = (int)((prec >> 0) & 0x0f) % 10;
    val = mantissa * poweroften[exponent];
    b = (int) (val/100);
    e = (int) (val%100);
    ods_log_debug("[%s] debug: %u = %d.%.2dm ", logstr, prec, b, e);
    fprintf(fd,"%d.%.2dm", b, e);
    return;
}


/**
 * Print loc RDATA element.
 *
 */
static void
rdata_print_loc(FILE* fd, rdata_type* rdata)
{
    uint8_t* data = rdata_get_data(rdata);
    size_t size = rdata_size(rdata);
    uint8_t version;
    uint8_t sz;
    uint8_t hp;
    uint8_t vp;
    uint32_t latlon;
    uint32_t alt;
    int b, e;
    if (size < 16) {
        ods_log_error("[%s] error: print loc: size too small", logstr);
        return;
    }
    /* version */
    version = data[0];
    if (version != 0) {
        ods_log_error("[%s] error: print loc: version not 0", logstr);
        return;
    }
    /* sz, hp, vp */
    sz = data[1];
    hp = data[2];
    vp = data[3];
    /* latitude */
    latlon = wf_read_uint32(data+4);
    rdata_print_loc_latlon(fd, latlon, 'N', 'S');
    /* longitude */
    latlon = wf_read_uint32(data+8);
    rdata_print_loc_latlon(fd, latlon, 'E', 'W');
    /* altitude */
    alt = wf_read_uint32(data+12);
    b = alt/100;
    b -= 100000;
    e = alt%100;
    ods_log_debug("[%s] debug: %u = %d.%02d", logstr, alt, b, e);
    fprintf(fd, "%d.%02dm ", b, e);
    /* size */
    rdata_print_loc_precsize_ntoa(fd, sz);
    fprintf(fd, " ");
    /* horizontal precision */
    rdata_print_loc_precsize_ntoa(fd, hp);
    fprintf(fd, " ");
    /* vertical precision */
    rdata_print_loc_precsize_ntoa(fd, vp);
    return;
}

/**
 * Print nsap RDATA element.
 *
 */
static void
rdata_print_nsap(FILE* fd, rdata_type* rdata)
{
    fprintf(fd, "0x");
    rdata_print_hex(fd, rdata);
    return;
}


/**
 * Print rrtype RDATA element.
 *
 */
static void
rdata_print_rrtype(FILE* fd, rdata_type* rdata)
{
    uint16_t data = wf_read_uint16(rdata_get_data(rdata));
    rr_print_rrtype(fd, data);
    return;
}


/**
 * Print text format RDATA element.
 *
 */
static void
rdata_print_text(FILE* fd, rdata_type* rdata)
{
    rdata_print_character_string(fd, rdata, 1);
    return;
}


/**
 * Print time format RDATA element.
 *
 */
static void
rdata_print_timef(FILE* fd, rdata_type* rdata)
{
    uint32_t data = wf_read_uint32(rdata_get_data(rdata));
    fprintf(fd, "%lu", (unsigned long) data);
    return;
}


/**
 * Print services RDATA element.
 *
 */
static void
rdata_print_services(FILE* fd, rdata_type* rdata)
{
    buffer_type data;
    buffer_create_from(&data, rdata_get_data(rdata), rdata_size(rdata));
    if (buffer_available(&data, 1)) {
        uint8_t protocol = buffer_read_u8(&data);
        ssize_t bitmap_size = buffer_remaining(&data);
        uint8_t* bitmap = buffer_current(&data);
        struct protoent* proto = getprotobynumber(protocol);
        if (proto) {
            int i;
            fprintf(fd, "%s", proto->p_name);
            for (i=0; i < bitmap_size * 8; i++) {
                if (util_getbit(bitmap, i)) {
                    struct servent* serv = getservbyport((int)htons(i),
                        proto->p_name);
                    if (serv) {
                        fprintf(fd, " %s", serv->s_name);
                    } else {
                        fprintf(fd, " %d", i);
                    }
                }
            }
        }
    }
    return;
}


/**
 * Print RDATA element.
 *
 */
void
rdata_print(FILE* fd, rdata_type* rdata, uint16_t rrtype, uint16_t pos)
{
    rrstruct_type* rrstruct;
    uint16_t p = pos;
    ods_log_assert(fd);
    ods_log_assert(rdata);
    rrstruct = dns_rrstruct_by_type(rrtype);
    /* special handling */
    if (rrstruct->rdata[0] == DNS_RDATA_TEXTS ||
        rrstruct->rdata[0] == DNS_RDATA_APLS) {
        p = 0;
    }
    if (pos && rrstruct->rdata[0] == DNS_RDATA_LOC) {
        return;
    }
    /* regular rdata */
    switch (rrstruct->rdata[p]) {
        case DNS_RDATA_IPV4:
            rdata_print_ipv4(fd, rdata);
            break;
        case DNS_RDATA_IPV6:
            rdata_print_ipv6(fd, rdata);
            break;
        case DNS_RDATA_COMPRESSED_DNAME:
        case DNS_RDATA_UNCOMPRESSED_DNAME:
            rdata_print_dname(fd, rdata);
            break;
        case DNS_RDATA_INT8:
        case DNS_RDATA_ALGORITHM:
            rdata_print_int8(fd, rdata);
            break;
        case DNS_RDATA_INT16:
        case DNS_RDATA_CERT_TYPE:
            rdata_print_int16(fd, rdata);
            break;
        case DNS_RDATA_INT32:
            rdata_print_int32(fd, rdata);
            break;
        case DNS_RDATA_TIMEF:
            rdata_print_timef(fd, rdata);
            break;
        case DNS_RDATA_DATETIME:
            rdata_print_datetime(fd, rdata);
            break;
        case DNS_RDATA_SERVICES:
            rdata_print_services(fd, rdata);
            break;
        case DNS_RDATA_TEXT:
        case DNS_RDATA_TEXTS:
            rdata_print_text(fd, rdata);
            break;
        case DNS_RDATA_NSAP:
            rdata_print_nsap(fd, rdata);
            break;
        case DNS_RDATA_RRTYPE:
            rdata_print_rrtype(fd, rdata);
            break;
        case DNS_RDATA_BASE64:
            rdata_print_base64(fd, rdata);
            break;
        case DNS_RDATA_BITMAP:
            rdata_print_bitmap_nxt(fd, rdata);
            break;
        case DNS_RDATA_FLOAT:
            rdata_print_float(fd, rdata);
            break;
        case DNS_RDATA_LOC:
            rdata_print_loc(fd, rdata);
            break;
        case DNS_RDATA_APLS:
            rdata_print_apl(fd, rdata);
            break;
        case DNS_RDATA_HEX:
            rdata_print_hex(fd, rdata);
            break;
        case DNS_RDATA_UNKNOWN:
        default:
            fprintf(fd, "<unknown>");
            break;
    }
    return;
}

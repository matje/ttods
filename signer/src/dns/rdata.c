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

#include "dns/dns.h"
#include "dns/rdata.h"
#include "dns/wf.h"
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
 * Print IPv4 RDATA element.
 *
 */
static void
rdata_print_ipv4(FILE* fd, rdata_type* rdata)
{
    char str[200];
    /* assert fd, rdata */
    if (inet_ntop(AF_INET, rdata_get_data(rdata), str, sizeof(str))) {
        fprintf(fd, "%s", str);
    } else {
        ods_log_error("[%s] error: inet_ntop failed: %s", logstr,
            strerror(errno));
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
    /* assert fd, rdata */
    dname_str(rdata_get_dname(rdata), &str[0]);
    fprintf(fd, "%s", str);
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
 * Print text format RDATA element.
 *
 */
static void
rdata_print_text(FILE* fd, rdata_type* rdata)
{
    const uint8_t* d = rdata_get_data(rdata);
    uint8_t l = d[0];
    size_t i;
    fprintf(fd, "\"");
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
    fprintf(fd, "\"");
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
 * Print wks RDATA element.
 *
 */
static void
rdata_print_wks(FILE* fd, rdata_type* rdata)
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
rdata_print(FILE* fd, rdata_type* rdata, uint16_t rrtype, uint8_t pos)
{
    rrstruct_type* rrstruct;
    ods_log_assert(fd);
    ods_log_assert(rdata);
    rrstruct = dns_rrstruct_by_type(rrtype);
    switch (rrstruct->rdata[pos]) {
        case DNS_RDATA_IPV4:
            rdata_print_ipv4(fd, rdata);
            break;
        case DNS_RDATA_COMPRESSED_DNAME:
            rdata_print_dname(fd, rdata);
            break;
        case DNS_RDATA_INT16:
            rdata_print_int16(fd, rdata);
            break;
        case DNS_RDATA_INT32:
            rdata_print_int32(fd, rdata);
            break;
        case DNS_RDATA_TEXT:
            rdata_print_text(fd, rdata);
            break;
        case DNS_RDATA_TIMEF:
            rdata_print_timef(fd, rdata);
            break;
        case DNS_RDATA_WKS:
            rdata_print_wks(fd, rdata);
            break;
        case DNS_RDATA_UNCOMPRESSED_DNAME:
        case DNS_RDATA_BINARY:
        default:
            fprintf(fd, "<unknown>");
            break;
    }
    return;
}

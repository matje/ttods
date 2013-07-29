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

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

static const char* logstr = "rdata";


/**
 * Get data from RDATA element.
 *
 */
static uint8_t*
rdata_get_data(rdata_type* rdata)
{
    return (uint8_t*) (rdata->data + 1);
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
 * Print RDATA element.
 *
 */
void
rdata_print(FILE* fd, rdata_type* rdata, uint16_t rrtype, uint8_t pos)
{
    rrstruct_type* rrstruct;
    if (!fd || !rdata) {
        return;
    }
    rrstruct = dns_rrstruct_by_type(rrtype);
    switch (rrstruct->rdata[pos]) {
        case DNS_RDATA_IPV4:
            rdata_print_ipv4(fd, rdata);
            break;
        default:
            fprintf(fd, "<unknown>");
            break;
    }
    return;
}

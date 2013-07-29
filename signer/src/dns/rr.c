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


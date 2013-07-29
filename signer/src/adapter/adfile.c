/*
 * $Id: adfile.c 7040 2013-02-15 08:19:53Z matthijs $
 *
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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
 * File Adapters.
 *
 */

#include "config.h"
#include "adapter/adfile.h"
#include "dns/rr.h"
#include "rzonec/rzonec.h"
#include "signer/zone.h"
#include "util/file.h"
#include "util/str.h"

#include <stdio.h>

static const char* logstr = "adapter";


/**
 * Read zone from zonefile.
 *
 */
ods_status
adfile_read(struct zone_struct* zone)
{
    int ret;
    zparser_type* parser;
    ods_status status = ODS_STATUS_OK;
    ods_log_assert(zone);
    ods_log_assert(zone->adapter_in);
    ods_log_assert(zone->adapter_in->configstr);
    /* create the parser */
    parser = zparser_create();
    if (!parser) {
        ods_log_crit("[%s] create zone parser failed", logstr);
        return ODS_STATUS_ZPARSERERR;
    }
    ret = zparser_read_zone(parser, zone->adapter_in->configstr);
    zparser_cleanup(parser);
    if (ret) {
        status = ODS_STATUS_ZPARSERERR;
    }
    if (status == ODS_STATUS_OK) {
        /* commit transaction */
    }
    return status;
}



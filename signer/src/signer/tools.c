/*
 * $Id: tools.c 6951 2013-01-16 13:39:12Z matthijs $
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
 * Zone signing tools.
 *
 */

#include "config.h"
#include "adapter/adapter.h"
#include "signer/tools.h"
#include "util/duration.h"

static const char* logstr = "tools";


/**
 * Configure zone.
 *
 */
ods_status
tools_conf(zone_type* zone)
{
    ods_status status = ODS_STATUS_OK;
    task_id denial_what = TASK_NONE;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    status = zone_load_signconf(zone);
    if (status == ODS_STATUS_OK) {
        ods_log_debug("[%s] zone %s switch to new signconf", logstr, zone->name);
        signconf_log(zone->signconf, zone->name);
        zone->default_ttl = (uint32_t) duration2time(&(zone->signconf->soa_min));
    } else if (status != ODS_STATUS_UNCHANGED) {
        ods_log_error("[%s] load signconf zone %s failed: %s", logstr,
            zone->name, ods_status2str(status));
    }
    return status;
}


/**
 * Read zone.
 *
 */
ods_status
tools_read(zone_type* zone)
{
    ods_status status;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->signconf);
    ods_log_assert(zone->namedb);
    /* Key Rollover? */

    /* Denial of Existence Rollover? */

    /* Go to Input Adapter */
    status = adapter_read((void*)zone);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] read zone %s failed: %s", logstr, zone->name,
            ods_status2str(status));
        /* rollback */
    }
    return status;
}


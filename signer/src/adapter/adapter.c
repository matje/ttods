/*
 * $Id: adapter.c 6478 2012-07-13 06:40:25Z matthijs $
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
 * Inbound and Outbound Adapters.
 *
 */

#include "config.h"
#include "adapter/adapter.h"
#include "adapter/adfile.h"
#include "signer/zone.h"
#include "util/log.h"

static const char* logstr = "adapter";


/**
 * Create a new adapter.
 *
 */
adapter_type*
adapter_create(region_type* r, const char* str, adapter_mode type, unsigned in)
{
    adapter_type* adapter;
    ods_log_assert(r);
    ods_log_assert(str);
    if (strlen(str)+1 > AD_CONFIGSTR_SIZE) {
        ods_log_error("[%s] config str %s is too long: maximum length of "
            "%d allowed", logstr, str, AD_CONFIGSTR_SIZE-1);
        return NULL;
    }
    adapter = (adapter_type*) region_alloc(r, sizeof(adapter_type));
    strlcpy(&(adapter->configstr[0]), str, strlen(str)+1);
    adapter->config_last_modified = 0;
    adapter->type = type;
    adapter->inbound = in;
    adapter->error = 0;
    return adapter;
}


/*
 * Read zone from input adapter.
 *
 */
ods_status
adapter_read(struct zone_struct* zone)
{
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->adapter_in);
    ods_log_assert(zone->adapter_in->configstr);
    switch (zone->adapter_in->type) {
        case ADAPTER_FILE:
            ods_log_verbose("[%s] read zone %s from file input adapter %s",
                logstr, zone->name, zone->adapter_in->configstr);
            return adfile_read(zone);
            break;
        case ADAPTER_DNS:
            ods_log_warning("[%s] zone %s dns input adapter NOTIMPL",
                logstr, zone->name);
            return ODS_STATUS_NOTIMPL;
            break;
        case ADAPTER_UPDATE:
            ods_log_warning("[%s] zone %s update input adapter NOTIMPL",
                logstr, zone->name);
            return ODS_STATUS_NOTIMPL;
            break;
        default:
            ods_log_error("[%s] read zone %s from adapter failed: unknown "
                "adapter type", logstr, zone->name);
            return ODS_STATUS_UNKNOWN;
            break;
    }
    /* not reached */
    return ODS_STATUS_OK;
}



/**
 * Write zone to output adapter.
 *
 */
ods_status
adapter_write(struct zone_struct* zone)
{
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    ods_log_assert(zone->adapter_out);
    ods_log_assert(zone->adapter_out->configstr);
    switch(zone->adapter_out->type) {
        case ADAPTER_FILE:
            ods_log_verbose("[%s] write zone %s to file input adapter %s",
                logstr, zone->name, zone->adapter_out->configstr);
            return adfile_write(zone);
            break;
        case ADAPTER_DNS:
        case ADAPTER_UPDATE:
            ods_log_warning("[%s] zone %s output adapter NOTIMPL",
                logstr, zone->name);
            return ODS_STATUS_NOTIMPL;
            break;
        default:
            ods_log_error("[%s] write zone %s to adapter failed: unknown "
                "adapter type", logstr, zone->name);
            return ODS_STATUS_UNKNOWN;
            break;
    }
    /* not reached */
    return ODS_STATUS_OK;
}


/**
 * Clean up adapter.
 *
 */
void
adapter_cleanup(adapter_type* ATTR_UNUSED(adapter))
{
    return;
}

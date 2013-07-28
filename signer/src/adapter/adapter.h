/*
 * $Id: adapter.h 6449 2012-06-21 09:45:24Z matthijs $
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

#ifndef ADAPTER_ADAPTER_H
#define ADAPTER_ADAPTER_H

#include "util/region.h"
#include "util/status.h"

#include <time.h>

#define AD_CONFIGSTR_SIZE 256

struct zone_struct;

/** Adapter mode. */
enum adapter_mode_enum
{
    ADAPTER_FILE = 1,
    ADAPTER_DNS,
    ADAPTER_UPDATE
};
typedef enum adapter_mode_enum adapter_mode;

/**
 * Adapter.
 *
 */
typedef struct adapter_struct adapter_type;
struct adapter_struct {
    adapter_mode type;
    time_t config_last_modified;
    char configstr[256];
    unsigned inbound : 1;
    unsigned error : 1;
    /* 2x int, 2x bit, 1x str */
    /* est.mem: A: 273 bytes */
};

/**
 * Create new adapter.
 * @param r:    memory region.
 * @param str:  configuration string.
 * @param type: type of adapter.
 * @param in:   inbound or outbound adapter.
 * @return:     (adapter_type*) created adapter.
 *
 */
adapter_type* adapter_create(region_type* r, const char* str,
    adapter_mode type, unsigned in);

/**
 * Read zone from input adapter.
 * @param zone: zone.
 * @return:     (ods_status) status.
 *
 */
ods_status adapter_read(struct zone_struct* zone);

/**
 * Write zone to output adapter.
 * @param zone: zone.
 * @return:     (ods_status) status.
 *
 */
ods_status adapter_write(struct zone_struct* zone);

/**
 * Clean up adapter.
 * @param adapter: adapter to cleanup.
 *
 */
void adapter_cleanup(adapter_type* adapter);

#endif /* ADAPTER_ADAPTER_H */


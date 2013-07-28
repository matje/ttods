/*
 * $Id: status.c 7057 2013-02-26 09:30:10Z matthijs $
 *
 * Copyright (c) 2009-2011 NLNet Labs. All rights reserved.
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
 * Status utilities.
 *
 */

#include "config.h"
#include "util/status.h"

#include <stdlib.h>

ods_lookup_table ods_status_str[] = {
    { ODS_STATUS_OK, "OK" },
    { ODS_STATUS_EOF, "End of file" },
    { ODS_STATUS_UNCHANGED, "Status unchanged" },
    { ODS_STATUS_NOTIMPL, "Not implemented" },
    { ODS_STATUS_UNKNOWN, "Unknown value" },
    { ODS_STATUS_ASSERT, "Assertion error" },
    { ODS_STATUS_CFGERR, "Configuration error" },
    { ODS_STATUS_XMLERR, "XML error" },
    { ODS_STATUS_RNGERR, "RNG error" },
    { ODS_STATUS_CMDHDLRERR, "Commandhandler error" },
    { ODS_STATUS_CHDIRERR, "Unable to change directory" },
    { ODS_STATUS_FORKERR, "Unable to create child process" },
    { ODS_STATUS_SETSIDERR, "Unable to run program in new session" },
    { ODS_STATUS_PRIVUIDERR, "Unable to get user identifier from username" },
    { ODS_STATUS_PRIVGIDERR, "Unable to get group identifier from username" },
    { ODS_STATUS_CHROOTERR, "Unable to change root" },
    { ODS_STATUS_INITGROUPSERR, "Unable to initialize group access list" },
    { ODS_STATUS_MALLOCERR, "Memory allocation error" },
    { ODS_STATUS_SETEGIDERR, "Unable to set effective group identifier" },
    { ODS_STATUS_SETGIDERR, "Unable to set group identity" },
    { ODS_STATUS_SETEUIDERR, "Unable to set effective user identifier" },
    { ODS_STATUS_SETUIDERR, "Unable to set user identity" },
    { ODS_STATUS_PRIVDROPERR, "Unable to drop privileges" },
    { ODS_STATUS_HSMOPENERR, "Unable to open HSM" },
    { ODS_STATUS_WRITEPIDERR, "Unable to write pidfile" },
    { ODS_STATUS_PARSERR, "Parse error" },
    { ODS_STATUS_SCHEDULERR, "Unable to add to schedule" },
    { ODS_STATUS_RBTREERR, "Insert into red black tree failed" },
    { ODS_STATUS_FOPENERR, "Open file failed" },
    { ODS_STATUS_STRFORMERR, "String format error" },
    { ODS_STATUS_SYNTAXERR, "Syntax error" },

    { 0, NULL }
};


/**
 * Look up status by id in table.
 *
 */
ods_lookup_table*
ods_lookup_by_id(ods_lookup_table *table, int id)
{
    while (table->name != NULL) {
        if (table->id == id) {
            return table;
        }
        table++;
    }
    return NULL;
}


/**
 * Look up a descriptive text by each status.
 *
 */
const char *
ods_status2str(ods_status status)
{
    ods_lookup_table* lt = ods_lookup_by_id(ods_status_str, status);
    if (lt) {
        return lt->name;
    }
    return NULL;
}



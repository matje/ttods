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

#ifndef UTIL_STATUS_H
#define UTIL_STATUS_H

enum ods_enum_status {
    ODS_STATUS_OK,
    ODS_STATUS_EOF,
    ODS_STATUS_UNCHANGED,
    ODS_STATUS_NOTIMPL,
    ODS_STATUS_UNKNOWN,
    ODS_STATUS_ASSERT,
    ODS_STATUS_CFGERR,
    ODS_STATUS_XMLERR,
    ODS_STATUS_RNGERR,
    ODS_STATUS_CMDHDLRERR,
    ODS_STATUS_CHDIRERR,
    ODS_STATUS_FORKERR,
    ODS_STATUS_SETSIDERR,
    ODS_STATUS_PRIVUIDERR,
    ODS_STATUS_PRIVGIDERR,
    ODS_STATUS_CHROOTERR,
    ODS_STATUS_INITGROUPSERR,
    ODS_STATUS_MALLOCERR,
    ODS_STATUS_SETEGIDERR,
    ODS_STATUS_SETGIDERR,
    ODS_STATUS_SETEUIDERR,
    ODS_STATUS_SETUIDERR,
    ODS_STATUS_PRIVDROPERR,
    ODS_STATUS_HSMOPENERR,
    ODS_STATUS_WRITEPIDERR,
    ODS_STATUS_PARSERR,
    ODS_STATUS_SCHEDULERR,
    ODS_STATUS_RBTREERR,
    ODS_STATUS_FOPENERR,
    ODS_STATUS_STRFORMERR,
    ODS_STATUS_SYNTAXERR
};
typedef enum ods_enum_status ods_status;

typedef struct ods_struct_lookup_table ods_lookup_table;
struct ods_struct_lookup_table {
    int id;
    const char* name;
};

extern ods_lookup_table ods_status_str[];

/**
 * Look up status by id in table.
 * @param table: table.
 * @param id:    identifier.
 * @return:      (ods_lookup_table*) entry.
 *
 */
ods_lookup_table* ods_lookup_by_id(ods_lookup_table *table, int id);

/**
 * Look up a descriptive text by each status.
 * @param status: status identifier.
 * @return:       (const char*) corresponding descriptive text.
 *
 */
const char* ods_status2str(ods_status status);

#endif /* UTIL_STATUS_H */

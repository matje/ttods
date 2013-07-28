/*
 * $Id: database_init_rundown.c 2120 2009-10-07 08:40:35Z sion $
 *
 * Copyright (c) 2008-2009 Nominet UK. All rights reserved.
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

/*+
 * database_init_rundown.c - Database Access Initialization
 *
 * Description:
 *      Contains the functions needed to initialize and run down the
 *      database access module.
-*/

#include "ksm/database.h"
#include "ksm/dbsdef.h"
#include "ksm/dbsmsg.h"
#include "ksm/kmedef.h"
#include "ksm/message.h"

/* Flag as to whether the database modules have been initialized */

static int m_initialized = 0;       /* Default is not */



/*+
 * DbInit - Initialize Database Access
 *
 * Description:
 *      Initializes the Database Modules if not already initialized.
 *
 * Arguments:
 *      None.
-*/

void DbInit(void)
{
    if (! m_initialized) {
        MsgRegister(DBS_MIN_VALUE, DBS_MAX_VALUE, d_messages, NULL);
        m_initialized = 1;
    }

    return;
}



/*+
 * DbRundown - Rundown Database Access
 *
 * Description:
 * 		Performs any rundown needed of the database module.
 *
 * Arguments:
 * 		None.
-*/

void DbRundown(void)
{
	return;
}

int DbFlavour(void)
{
#ifdef USE_MYSQL
    return MYSQL_DB;
#else
    return SQLITE_DB;
#endif
}

/*+
 * db_version_check
 *
 * Description:
 *      Check the version of the database against the version in database.h
 *
 * Arguments:
 *      None
-*/

int db_version_check(void)
{
    char*       sql = "select version from dbadmin";     /* SQL query */
    int         status = 0;     /* Status return */
    DB_RESULT	result;         /* Result of the query */
    DB_ROW      row = NULL;     /* Row data */
    int         version = 0;    /* Version returned */

    /* Select rows */
    status = DbExecuteSql(DbHandle(), sql, &result);
    if (status == 0) {
        status = DbFetchRow(result, &row);
        while (status == 0) {
            /* Got a row, print it */
            DbInt(row, 0, &version);

            /* Check it */
            if (version != KSM_DB_VERSION) {
                DbFreeRow(row);
                DbFreeResult(result);
                return MsgLog(KME_WRONG_DB_VER, KSM_DB_VERSION, version);
            }

            status = DbFetchRow(result, &row);
            /* should only have one row */
            if (status == 0) {
                DbFreeRow(row);
                DbFreeResult(result);
                return MsgLog(KME_DB_ADMIN);
            }
        }

        /* Convert EOF status to success */
        if (status == -1) {
            status = 0;
        }

        DbFreeResult(result);
    }

    DbFreeRow(row);
    return status;
}

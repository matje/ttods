/*
 * $Id: ksm_import.c 6013 2012-01-04 15:57:01Z sion $
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

/*
 * ksm_import.c - Import/update configuration data in kasp database
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ksm/database.h"
#include "ksm/database_statement.h"
#include "ksm/datetime.h"
#include "ksm/db_fields.h"
#include "ksm/debug.h"
#include "ksm/ksmdef.h"
#include "ksm/ksm.h"
#include "ksm/ksm_internal.h"
#include "ksm/message.h"
#include "ksm/string_util.h"
#include "ksm/string_util2.h"

/*+
 * KsmImportRepository - Insert or update a repository
 *
 *
 * Arguments:
 *
 *      const char* repo_name
 *          Name of the repository
 *
 *      const char* repo_capacity
 *          Capacity for that repository
 *
 *      int require_backup
 *          flag to indicate if keys in this repo need to be backed up before they can be used
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                         -1 if an unexpected count value was returned
-*/

int KsmImportRepository(const char* repo_name, const char* repo_capacity, int require_backup)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    int         count = 0;      /* Do we already have a repository with this name? */

    /* check the main argument (capacity may be NULL) */
    if (repo_name == NULL) {
        return MsgLog(KSM_INVARG, "NULL repository name");
    }

    /* 
     * First see if this repository exists
     */
    sql = DqsCountInit(DB_SECURITY_MODULE_TABLE);
    DqsConditionString(&sql, "NAME", DQS_COMPARE_EQ, repo_name, 0);
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), &count, sql);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
	}

    /* If the count was 0 then we do an insert, otherwise we do an update */
    if (count == 0)
    {
        sql = DisSpecifyInit(DB_SECURITY_MODULE_TABLE, "name, capacity, requirebackup");
        DisAppendString(&sql, repo_name);
        DisAppendString(&sql, repo_capacity);
        DisAppendInt(&sql, require_backup);
        DisEnd(&sql);

        status = DbExecuteSqlNoResult(DbHandle(), sql);
        DisFree(sql);
    }
    else if (count == 1)
    {
        sql = DusInit(DB_SECURITY_MODULE_TABLE);
        DusSetString(&sql, "capacity", repo_capacity, 0);
        DusSetInt(&sql, "requirebackup", require_backup, 1);
        DusConditionString(&sql, "name", DQS_COMPARE_EQ, repo_name, 0);
        DusEnd(&sql);

        status = DbExecuteSqlNoResult(DbHandle(), sql);
        DusFree(sql);
    }
    else
    {
        return -1;
    }

    return status;
}

/*+
 * KsmImportPolicy - Insert a policy (will not be called if policy exists, unlike above
 *
 *
 * Arguments:
 *
 *      const char* policy_name
 *          Name of the policy
 *
 *      const char* policy_description
 *          Description for that policy
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                         -1 if an unexpected count value was returned
-*/

int KsmImportPolicy(const char* policy_name, const char* policy_description)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */

	char        quoted_desc[KSM_POLICY_DESC_LENGTH];   /* with bad chars quoted */

    /* check the main argument (description may be NULL) */
    if (policy_name == NULL) {
        return MsgLog(KSM_INVARG, "NULL policy name");
    }

	/* Quote description */
    status = DbQuoteString(DbHandle(), policy_description, quoted_desc, KSM_POLICY_DESC_LENGTH);

	if (status != 0) {
		return status;
	}

    /* Insert policy */
    sql = DisSpecifyInit("policies", "name, description");
    DisAppendString(&sql, policy_name);
    DisAppendString(&sql, quoted_desc);
    DisEnd(&sql);

    status = DbExecuteSqlNoResult(DbHandle(), sql);
    DisFree(sql);

    return status;
}

/*+
 * KsmImportZone - Insert or update a zone
 *
 *
 * Arguments:
 *
 *      const char* zone_name
 *          Name of the repository
 *
 *      int policy_id
 *          Policy for the zone
 *
 *      int fail_if_exists
 *          Set to 1 if you don't want to update existing zones
 *
 *      int *new_zone
 *          (returned) indicate if the zone was new to the database
 *
 *      const char* signconf
 *          Where is the signconf saved
 *
 *      const char* input
 *          Where is the input
 *
 *      const char* output
 *          Where is the output
 *
 *      const char* input_type
 *          What adapter type is the input
 *
 *      const char* output_type
 *          What adapter type is the output
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                         -1 if an unexpected count value was returned
 *                         -2 if the zone exists and fail_if_exists == 1
 *                         -3 if the zone exists with and without a trailing dot
-*/
int KsmImportZone(const char* zone_name, int policy_id, int fail_if_exists, int *new_zone, const char* signconf, const char* input, const char* output, const char* input_type, const char* output_type)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    int         count = 0;      /* Do we already have a zone with this name? */
	char*		zone_name_td = NULL; /* zone name with td swapped */
	char 		in_clause[KSM_SQL_SIZE]; /* in part of where clause */

    /* check the arguments */
    if (zone_name == NULL || policy_id == 0) {
        return MsgLog(KSM_INVARG, "NULL zone name or policy");
    }

	/* make copy of zone_name with opposite td to original (unless original is 
	   "."; in which case the copy is identical */
	zone_name_td = StrStrdup(zone_name);
	if (strlen(zone_name_td) > 1 && zone_name_td[strlen(zone_name_td)-1] == '.') {
		zone_name_td[strlen(zone_name_td)-1] = '\0';
	} 
	else if (strlen(zone_name_td) > 1) {
		StrAppend(&zone_name_td, ".");
	}

	snprintf(in_clause, KSM_SQL_SIZE, "(\"%s\",\"%s\")", zone_name, zone_name_td);

    /* 
     * First see if this zone exists
     */
    sql = DqsCountInit(DB_ZONE_TABLE);
    DqsConditionKeyword(&sql, "NAME", DQS_COMPARE_IN, in_clause, 0);
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), &count, sql);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
	}

    /* If the count was 0 then we do an insert, otherwise we do an update */
    if (count == 0)
    {
        sql = DisSpecifyInit(DB_ZONE_TABLE, "name, policy_id, signconf, input, output, in_type, out_type");
        DisAppendString(&sql, zone_name);
        DisAppendInt(&sql, policy_id);
        DisAppendString(&sql, signconf);
        DisAppendString(&sql, input);
        DisAppendString(&sql, output);
        DisAppendString(&sql, input_type);
        DisAppendString(&sql, output_type);
        DisEnd(&sql);

        status = DbExecuteSqlNoResult(DbHandle(), sql);
        DisFree(sql);

        *new_zone = 1;
    }
    else if (count == 1)
    {
        if (fail_if_exists == 1) {
            return -2;
        }
        sql = DusInit(DB_ZONE_TABLE);
        DusSetInt(&sql, "policy_id", policy_id, 0);
        DusSetString(&sql, "signconf", signconf, 1);
        DusSetString(&sql, "input", input, 2);
        DusSetString(&sql, "output", output, 3);
        DusSetString(&sql, "in_type", input_type, 4);
        DusSetString(&sql, "out_type", output_type, 5);
        DusConditionString(&sql, "name", DQS_COMPARE_EQ, zone_name, 0);
        DusEnd(&sql);

        status = DbExecuteSqlNoResult(DbHandle(), sql);
        DusFree(sql);

        *new_zone = 0;
    }
	else if (count == 2)
	{
		return -3;
	}
    else
    {
        return -1;
    }

    return status;
}

/*+
 * KsmImportKeyPair - Create Entry in the KeyPairs table for an existing key
 *
 * Description:
 *      Creates a key in the database. If the retire time is set then it is marked as
 *          fixed (I.e. it will not be changed to fit the policy timings.)
 *
 * Arguments:
 *      policy_id
 *          policy that the key is created for
 *      HSMKeyID
 *          ID the key is refered to in the HSM
 *      smID
 *          security module ID
 *      size
 *          size of key
 *      alg
 *          algorithm used
 *      state
 *          state to set key to
 *      time
 *          timestamp of entry into state given
 *      fixDate
 *      	set to 1 if the retire date should be fixed
 *
 *      DB_ID* id (returned)
 *          ID of the created entry.  This will be undefined on error.
 *
 * Returns:
 *      int
 *          Status return.  0=> Success, non-zero => error.
-*/
int KsmImportKeyPair(int policy_id, const char* HSMKeyID, int smID, int size, int alg, int state, const char* time, int fixDate, DB_ID* id)
{
    unsigned long rowid;			/* ID of last inserted row */
    int         status = 0;         /* Status return */
    char*       sql = NULL;         /* SQL Statement */
    char*       columns = NULL;     /* what columns are we setting */

    /* Check arguments */
    if (id == NULL) {
        return MsgLog(KSM_INVARG, "NULL id");
    }

    StrAppend(&columns, "policy_id, HSMkey_id, securitymodule_id, size, algorithm");
    if (state == KSM_STATE_GENERATE) {
        StrAppend(&columns, ", ");
        StrAppend(&columns, KsmKeywordStateValueToName(state));
    }
    if (state == KSM_STATE_ACTIVE && fixDate == 1) {
        StrAppend(&columns, ", fixedDate");
    }

    sql = DisSpecifyInit("keypairs", columns);
    DisAppendInt(&sql, policy_id);
    DisAppendString(&sql, HSMKeyID);
    DisAppendInt(&sql, smID);
    DisAppendInt(&sql, size);
    DisAppendInt(&sql, alg);
    if (state == KSM_STATE_GENERATE) {
        DisAppendString(&sql, time);
    }
    if (state == KSM_STATE_ACTIVE && fixDate == 1) {
        DisAppendInt(&sql, fixDate);
    }
    DisEnd(&sql);

    /* Execute the statement */

    status = DbExecuteSqlNoResult(DbHandle(), sql);
    DisFree(sql);
    StrFree(columns);

    if (status == 0) {

        /* Succcess, get the ID of the inserted record */

		status = DbLastRowId(DbHandle(), &rowid);
		if (status == 0) {
			*id = (DB_ID) rowid;
		}
    }

    return status;
}

int KsmSmIdFromName(const char* name, int *id)
{
    char*   sql = NULL;         /* SQL query */
    int     status = 0;         /* Status return */

    /* check the argument */
    if (name == NULL) {
        return MsgLog(KSM_INVARG, "NULL name");
    }

    /* Construct the query */

    sql = DqsSpecifyInit(DB_SECURITY_MODULE_TABLE,"id");
    DqsConditionString(&sql, "name", DQS_COMPARE_EQ, name, 0);
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), id, sql);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
	}

    return status;
}

int KsmSerialIdFromName(const char* name, int *id)
{
    char*   sql = NULL;         /* SQL query */
    int     status = 0;         /* Status return */

    /* check the argument */
    if (name == NULL) {
        return MsgLog(KSM_INVARG, "NULL name");
    }

    /* Construct the query */

    sql = DqsSpecifyInit("serialmodes","id");
    DqsConditionString(&sql, "name", DQS_COMPARE_EQ, name, 0);
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), id, sql);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
	}

    return status;
}

/*+
 * KsmPolicyIdFromName - Given a policy name return the id
 *
 *
 * Arguments:
 *      
 *          Name of the policy.
 *
 *
 * Returns:
 *      int
 *          0       Success, value found
 *          Other   Error
-*/
int KsmPolicyIdFromName(const char* name, int *id)
{
    char*   sql = NULL;         /* SQL query */
    int     status = 0;         /* Status return */

    /* check the argument */
    if (name == NULL) {
        return MsgLog(KSM_INVARG, "NULL name");
    }

    /* Construct the query */

    sql = DqsSpecifyInit("policies","id");
    DqsConditionString(&sql, "name", DQS_COMPARE_EQ, name, 0);
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), id, sql);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
	}

    return status;
}

/*+
 * KsmMarkPreBackup - Mark a backup as having been prepared
 *
 *
 * Arguments:
 *
 *      int repo_id
 *          ID of the repository (-1 for all)
 *
 *      const char* datetime
 *          When the pre backup was done
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 */

int KsmMarkPreBackup(int repo_id, const char* datetime)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    int         count = -1;     /* How many keys get marked */

    /* Count how many we will mark */
    sql = DqsCountInit("keypairs");
    if (repo_id != -1) {
        DqsConditionInt(&sql, "securitymodule_id", DQS_COMPARE_EQ, repo_id, 0);
        StrAppend(&sql, " and pre_backup is null");
    } else {
        StrAppend(&sql, " where pre_backup is null");
    }
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), &count, sql);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
	}

    if (count == 0) {
        /* No work to do */
        return -1;
    }

    /* Update rows */
    sql = DusInit("keypairs");
    DusSetString(&sql, "PRE_BACKUP", datetime, 0);
    if (repo_id != -1) {
        DusConditionInt(&sql, "securitymodule_id", DQS_COMPARE_EQ, repo_id, 0);
        StrAppend(&sql, " and pre_backup is null");
    } else {
        StrAppend(&sql, " where pre_backup is null");
    }
    DusEnd(&sql);

    status = DbExecuteSqlNoResult(DbHandle(), sql);
    DusFree(sql);

    return status;
}

/*+
 * KsmRollbackPreBackup - Rollback a backup prepare step
 *
 *
 * Arguments:
 *
 *      int repo_id
 *          ID of the repository (-1 for all)
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 */

int KsmRollbackMarkPreBackup(int repo_id)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    int         count = -1;     /* How many keys get marked */

    /* Count how many we will mark */
    sql = DqsCountInit("keypairs");
    if (repo_id != -1) {
        DqsConditionInt(&sql, "securitymodule_id", DQS_COMPARE_EQ, repo_id, 0);
        StrAppend(&sql, " and pre_backup is not null");
        StrAppend(&sql, " and backup is null");
    } else {
        StrAppend(&sql, " where pre_backup is not null");
        StrAppend(&sql, " and backup is null");
    }
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), &count, sql);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
	}

    if (count == 0) {
        /* No work to do */
        return -1;
    }

    /* Update rows */
    sql = DusInit("keypairs");
    DusSetString(&sql, "PRE_BACKUP", NULL, 0);
    if (repo_id != -1) {
        DusConditionInt(&sql, "securitymodule_id", DQS_COMPARE_EQ, repo_id, 0);
        StrAppend(&sql, " and pre_backup is not null");
        StrAppend(&sql, " and backup is null");
    } else {
        StrAppend(&sql, " where pre_backup is null");
        StrAppend(&sql, " and backup is null");
    }
    DusEnd(&sql);

    status = DbExecuteSqlNoResult(DbHandle(), sql);
    DusFree(sql);

    return status;
}

/*+
 * KsmMarkBackup - Mark a backup as having been done
 *
 *
 * Arguments:
 *
 *      int repo_id
 *          ID of the repository (-1 for all)
 *
 *      const char* datetime
 *          When the backup was done
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                          other on fail
 */

int KsmMarkBackup(int repo_id, const char* datetime)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    int         count = -1;     /* How many keys get marked */

    /* Count how many we will mark */
    sql = DqsCountInit("keypairs");
    if (repo_id != -1) {
        DqsConditionInt(&sql, "securitymodule_id", DQS_COMPARE_EQ, repo_id, 0);
        StrAppend(&sql, " and pre_backup is not null");
        StrAppend(&sql, " and backup is null");
    } else {
        StrAppend(&sql, " where pre_backup is not null");
        StrAppend(&sql, " and backup is null");
    }
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), &count, sql);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
	}

    if (count == 0) {
        /* No work to do */
        return -1;
    }

    /* Update rows */
    sql = DusInit("keypairs");
    DusSetString(&sql, "BACKUP", datetime, 0);
    if (repo_id != -1) {
        DusConditionInt(&sql, "securitymodule_id", DQS_COMPARE_EQ, repo_id, 0);
        StrAppend(&sql, " and backup is null");
        StrAppend(&sql, " and pre_backup is not null");
    } else {
        StrAppend(&sql, " where backup is null");
        StrAppend(&sql, " and pre_backup is not null");
    }
    DusEnd(&sql);

    status = DbExecuteSqlNoResult(DbHandle(), sql);
    DusFree(sql);

    return status;
}

/*+
 * KsmCheckHSMkeyID - Checks if the cka_id exists in the hsm specified
 *
 *
 * Arguments:
 *
 *      int repo_id
 *          ID of the repository (-1 for all)
 *
 *      const char* cka_id
 *          ID to look for
 *
 *      int *exists
 *          Flag to say if the ID exists
 *
 * Returns:
 *      int
 *          Status return.  0 on success.
 *                         -1 if an unexpected count value was returned
-*/

int KsmCheckHSMkeyID(int repo_id, const char* cka_id, int *exists)
{
    char*       sql = NULL;     /* SQL query */
    int         status = 0;     /* Status return */
    int         count = 0;      /* Do we already have a key with this ID? */

    /* check the arguments */
    if (cka_id == NULL) {
        return MsgLog(KSM_INVARG, "NULL cka_id");
    }

    /* 
     * Set up the count
     */
    sql = DqsCountInit("keypairs");
    DqsConditionString(&sql, "HSMkey_id", DQS_COMPARE_EQ, cka_id, 0);
    if (repo_id != -1) {
        DqsConditionInt(&sql, "securitymodule_id", DQS_COMPARE_EQ, repo_id, 1);
    }
    DqsEnd(&sql);

    /* Execute query and free up the query string */
    status = DbIntQuery(DbHandle(), &count, sql);
    DqsFree(sql);
    
    if (status != 0)
    {
        status = MsgLog(KSM_SQLFAIL, DbErrmsg(DbHandle()));
        return status;
	}

    if (count > 0) {
        *exists = 1;
    }
    else {
        *exists = 0;
    }

    return 0;
}


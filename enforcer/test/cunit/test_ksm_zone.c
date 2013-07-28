/*
 * $Id: test_ksm_zone.c 3858 2010-09-01 15:05:02Z sion $
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
 * Filename: test_ksm_zone.c - Test ksm_zone Module
 *
 * Description:
 *      This is a short test module to check the function in the Ksm Zone
 *      module.
 *
 *      The test program makes use of the CUnit framework, as described in
 *      http://cunit.sourceforge.net
-*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "CUnit/Basic.h"

#include "ksm/ksm.h"
#include "test_routines.h"


/*+
 * TestKsmZoneRead - Test
 *
 * Description:
 *      Tests that a zone can be returned
-*/

static void TestKsmZoneRead(void)
{
	int			status;		/* Status return */
	int         policy_id = 2;
    DB_RESULT   result;
	KSM_ZONE*   zone;

	zone = (KSM_ZONE *)malloc(sizeof(KSM_ZONE));

	/* Call KsmZoneInit */
    status = KsmZoneInit(&result, policy_id);
	CU_ASSERT_EQUAL(status, 0);

    /* get the first zone */
    status = KsmZone(result, zone);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_STRING_EQUAL(zone->name, "opendnssec.org");

    /* get the second zone */
    status = KsmZone(result, zone);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_STRING_EQUAL(zone->name, "opendnssec.se");

    DbFreeResult(result);

	free(zone);
}

/*+
 * TestKsmZoneIdFromName - Test
 *
 * Description:
 *      Tests that a zone can be returned
-*/

static void TestKsmZoneIdFromName(void)
{
	int		status;		/* Status return */
    int     zone_id;    /* returned id */

    char*   zone1 = "opendnssec.org";
    char*   zone2 = "opendnssec.se";

    /* get the first zone */
    status = KsmZoneIdFromName(zone1, &zone_id);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(zone_id, 1);

    /* get the first zone */
    status = KsmZoneIdFromName(zone2, &zone_id);
	CU_ASSERT_EQUAL(status, 0);
	CU_ASSERT_EQUAL(zone_id, 2);

}

/*
 * TestKsmZone - Create Test Suite
 *
 * Description:
 *      Adds the test suite to the CUnit test registry and adds all the tests
 *      to it.
 *
 * Arguments:
 *      None.
 *
 * Returns:
 *      int
 *          Return status.  0 => Success.
 */

int TestKsmZone(void);	/* Declaration */
int TestKsmZone(void)
{
    struct test_testdef tests[] = {
        {"KsmZone", TestKsmZoneRead},
        {"KsmZoneIdFromName", TestKsmZoneIdFromName},
        {NULL,                      NULL}
    };

    /* TODO 
     * have been a bit lazy here and reuse TdbSetup etc...
     * this has the consequence of all the setups running for each suite
     * if this gets too slow then we will need to separate them out
     * */
    return TcuCreateSuite("KsmZone", TdbSetup, TdbTeardown, tests);
}

/*
 * $Id: hsms.c 6747 2012-10-19 10:32:45Z matthijs $
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
 * Hardware Security Module Support.
 *
 */

#include "config.h"
#include "daemon/engine.h"
#include "util/hsms.h"
#include "util/log.h"

static const char* logstr = "hsm";


/**
 * Open HSM.
 *
 */
int
hsms_open(const char* filename)
{
    int result = hsm_open(filename, hsm_check_pin);
    if (result != HSM_OK) {
        char* error =  hsm_get_error(NULL);
        if (error != NULL) {
            ods_log_error("[%s] %s", logstr, error);
            free(error);
        } else {
            ods_log_crit("[%s] error opening libhsm (errno %i)", logstr,
                result);
        }
        /* exit(1)? */
    } else {
        ods_log_verbose("[%s] libhsm connection opened succesfully", logstr);
    }
    return result;
}


/**
 * Reopen HSM.
 *
 */
int
hsms_reopen(const char* filename)
{
    if (hsm_check_context(NULL) != HSM_OK) {
        ods_log_warning("[%s] idle libhsm connection, trying to reopen",
            logstr);
        hsm_close();
        return hsms_open(filename);
    }
    return HSM_OK;
}


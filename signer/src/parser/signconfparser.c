/*
 * $Id: signconfparser.c 6660 2012-09-12 09:34:40Z matthijs $
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
 * Parsing signer configuration files.
 *
 */

#include "config.h"
#include "parser/confparser.h"
#include "parser/signconfparser.h"
#include "signer/signconf.h"
#include "util/duration.h"
#include "util/log.h"

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/xmlreader.h>
#include <stdlib.h>

static const char* logstr = "parser";

static ods_status
parser_sc_duration(const char* cfgfile, duration_type* d, const char* expr)
{
    ods_status status;
    const char* str = parser_conf_string(cfgfile, expr, 1);
    if (!str) {
        ods_log_error("[%s] failed to parse %s in %s", logstr, expr, cfgfile);
        return ODS_STATUS_CFGERR;
    }
    status = str2duration(str, d);
    free((void*)str);
    return status;
}




/**
 * Parse durations from the configuration file.
 *
 */
ods_status
parser_sc_sig_resign_interval(const char* cfgfile, duration_type* d)
{
    return parser_sc_duration(cfgfile, d,
        "//SignerConfiguration/Zone/Signatures/Resign");
}
ods_status
parser_sc_sig_refresh_interval(const char* cfgfile, duration_type* d)
{
    return parser_sc_duration(cfgfile, d,
        "//SignerConfiguration/Zone/Signatures/Refresh");
}
ods_status
parser_sc_sig_validity_default(const char* cfgfile, duration_type* d)
{
    return parser_sc_duration(cfgfile, d,
        "//SignerConfiguration/Zone/Signatures/Validity/Default");
}
ods_status
parser_sc_sig_validity_denial(const char* cfgfile, duration_type* d)
{
    return parser_sc_duration(cfgfile, d,
        "//SignerConfiguration/Zone/Signatures/Validity/Denial");
}
ods_status
parser_sc_sig_jitter(const char* cfgfile, duration_type* d)
{
    return parser_sc_duration(cfgfile, d,
        "//SignerConfiguration/Zone/Signatures/Jitter");
}
ods_status
parser_sc_sig_inception_offset(const char* cfgfile, duration_type* d)
{
    return parser_sc_duration(cfgfile, d,
        "//SignerConfiguration/Zone/Signatures/InceptionOffset");
}
ods_status
parser_sc_dnskey_ttl(const char* cfgfile, duration_type* d)
{
    return parser_sc_duration(cfgfile, d,
        "//SignerConfiguration/Zone/Keys/TTL");
}
ods_status
parser_sc_soa_ttl(const char* cfgfile, duration_type* d)
{
    return parser_sc_duration(cfgfile, d,
        "//SignerConfiguration/Zone/SOA/TTL");
}
ods_status
parser_sc_soa_min(const char* cfgfile, duration_type* d)
{
    return parser_sc_duration(cfgfile, d,
        "//SignerConfiguration/Zone/SOA/Minimum");
}


/**
 * Parse denial of existence type from the configuration file.
 *
 */
ldns_rr_type
parser_sc_nsec_type(const char* cfgfile)
{
    const char* str = parser_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Denial/NSEC3",
        0);
    if (str) {
        free((void*)str);
        return LDNS_RR_TYPE_NSEC3;
    }
    str = parser_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Denial/NSEC",
        0);
    if (str) {
        free((void*)str);
        return LDNS_RR_TYPE_NSEC;
    }
    return LDNS_RR_TYPE_FIRST;
}


/**
 * Parse uint32_t values from the configuration file.
 *
 */
uint32_t
parser_sc_nsec3_algorithm(const char* cfgfile)
{
    int ret = 0;
    const char* str = parser_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Denial/NSEC3/Hash/Algorithm",
        1);
    if (str) {
        if (strlen(str) > 0) {
            ret = atoi(str);
        }
        free((void*)str);
    }
    return ret;
}
uint32_t
parser_sc_nsec3_iterations(const char* cfgfile)
{
    int ret = 0;
    const char* str = parser_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Denial/NSEC3/Hash/Iterations",
        1);
    if (str) {
        if (strlen(str) > 0) {
            ret = atoi(str);
        }
        free((void*)str);
    }
    return ret;
}


/**
 * Parse NSEC3 Opt-Out from the configuration file.
 *
 */
int
parser_sc_nsec3_optout(const char* cfgfile)
{
    int ret = 0;
    const char* str = parser_conf_string(cfgfile,
        "//SignerConfiguration/Zone/Denial/NSEC3/OptOut",
        0);
    if (str) {
        ret = 1;
        free((void*)str);
    }
    return ret;
}


/**
 * Parse strings from the configuration file.
 *
 */
ods_status
parser_sc_soa_serial(const char* cfgfile, char* buf)
{
    const char* expr = "//SignerConfiguration/Zone/SOA/Serial";
    const char* str = parser_conf_string(cfgfile, expr, 1);
    if (str) {
        ods_status status = ODS_STATUS_OK;
        if (strlen(str)+1 <= SC_SERIAL_SIZE) {
            strlcpy(buf, str, strlen(str)+1);
        } else {
            ods_log_error("[%s] serial %s in %s is too long: maximum length of "
                "%d allowed", logstr, str, cfgfile, SC_SERIAL_SIZE-1);
            status = ODS_STATUS_CFGERR;
        }
        free((void*)str);
        return status;
    }
    ods_log_error("[%s] failed to parse %s in %s", logstr, expr, cfgfile);
    return ODS_STATUS_CFGERR;

}
ods_status
parser_sc_nsec3_salt(const char* cfgfile, char* buf)
{
    const char* expr = "//SignerConfiguration/Zone/Denial/NSEC3/Hash/Salt";
    const char* str = parser_conf_string(cfgfile, expr, 1);
    if (str) {
        ods_status status = ODS_STATUS_OK;
        if (strlen(str)+1 <= SC_SALT_SIZE) {
            strlcpy(buf, str, strlen(str)+1);
        } else {
            ods_log_error("[%s] salt %s in %s is too long: maximum length of "
                "%d allowed", logstr, str, cfgfile, SC_SALT_SIZE-1);
            status = ODS_STATUS_CFGERR;
        }
        free((void*)str);
        return status;
    }
    ods_log_error("[%s] failed to parse %s in %s", logstr, expr, cfgfile);
    return ODS_STATUS_CFGERR;
}


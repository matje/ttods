/*
 * $Id: confparser.c 6660 2012-09-12 09:34:40Z matthijs $
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
 * Parsing configuration files.
 *
 */

#include "config.h"
#include "parser/confparser.h"
#include "util/log.h"
#include "util/status.h"

#include <libxml/xpath.h>
#include <libxml/relaxng.h>
#include <libxml/xmlreader.h>
#include <string.h>
#include <stdlib.h>

static const char* logstr = "parser";


/**
 * Check config file with rng file.
 *
 */
ods_status
parser_filecheck(const char* cfgfile, const char* rngfile)
{
    xmlDocPtr doc = NULL;
    xmlDocPtr rngdoc = NULL;
    xmlRelaxNGParserCtxtPtr rngpctx = NULL;
    xmlRelaxNGValidCtxtPtr rngctx = NULL;
    xmlRelaxNGPtr schema = NULL;
    int status = 0;
    ods_log_debug("[%s] check cfgfile %s with rngfile %s", logstr,
        cfgfile, rngfile);
    ods_log_assert(cfgfile);
    ods_log_assert(rngfile);
    /* Load xml document */
    doc = xmlParseFile(cfgfile);
    if (doc == NULL) {
        ods_log_error("[%s] parse cfgfile %s failed", logstr, cfgfile);
        return ODS_STATUS_XMLERR;
    }
    /* Load rng document */
    rngdoc = xmlParseFile(rngfile);
    if (rngdoc == NULL) {
        ods_log_error("[%s] parse rngfile %s failed", logstr, rngfile);
        xmlFreeDoc(doc);
        return ODS_STATUS_XMLERR;
    }
    /* Create an XML RelaxNGs parser context for the relax-ng document. */
    rngpctx = xmlRelaxNGNewDocParserCtxt(rngdoc);
    if (rngpctx == NULL) {
        ods_log_error("[%s] create parser failed", logstr);
        xmlFreeDoc(rngdoc);
        xmlFreeDoc(doc);
        return ODS_STATUS_XMLERR;
    }
    /* Parse a schema definition resource and
     * build an internal XML schema structure.
     */
    schema = xmlRelaxNGParse(rngpctx);
    if (schema == NULL) {
        ods_log_error("[%s] relaxng parse failed", logstr);
        xmlRelaxNGFreeParserCtxt(rngpctx);
        xmlFreeDoc(rngdoc);
        xmlFreeDoc(doc);
        return ODS_STATUS_RNGERR;
    }
    /* Create an XML RelaxNGs validation context. */
    rngctx = xmlRelaxNGNewValidCtxt(schema);
    if (rngctx == NULL) {
        ods_log_error("[%s] relaxng create failed", logstr);
        xmlRelaxNGFree(schema);
        xmlRelaxNGFreeParserCtxt(rngpctx);
        xmlFreeDoc(rngdoc);
        xmlFreeDoc(doc);
        return ODS_STATUS_RNGERR;
    }
    /* Validate a document tree in memory. */
    status = xmlRelaxNGValidateDoc(rngctx,doc);
    if (status != 0) {
        ods_log_error("[%s] relaxng validate failed", logstr);
        xmlRelaxNGFreeValidCtxt(rngctx);
        xmlRelaxNGFree(schema);
        xmlRelaxNGFreeParserCtxt(rngpctx);
        xmlFreeDoc(rngdoc);
        xmlFreeDoc(doc);
        return ODS_STATUS_RNGERR;
    }
    xmlRelaxNGFreeValidCtxt(rngctx);
    xmlRelaxNGFree(schema);
    xmlRelaxNGFreeParserCtxt(rngpctx);
    xmlFreeDoc(rngdoc);
    xmlFreeDoc(doc);
    return ODS_STATUS_OK;
}


/**
 * Parse elements from the configuration file, given an expression.
 *
 */
const char*
parser_conf_string(const char* cfgfile, const char* expr, int required)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlChar *xexpr = NULL;
    const char* string = NULL;
    ods_log_assert(cfgfile);
    ods_log_assert(expr);
    /* Load XML document */
    doc = xmlParseFile(cfgfile);
    if (doc == NULL) {
        ods_log_error("[%s] parse cfgfile %s failed", logstr, cfgfile);
        return NULL;
    }
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if (xpathCtx == NULL) {
        ods_log_error("[%s] create ctx failed", logstr);
        xmlFreeDoc(doc);
        return NULL;
    }
    /* Get string */
    xexpr = (unsigned char*) expr;
    xpathObj = xmlXPathEvalExpression(xexpr, xpathCtx);
    if (xpathObj == NULL || xpathObj->nodesetval == NULL ||
        xpathObj->nodesetval->nodeNr <= 0) {
        if (required) {
            ods_log_error("[%s] unable to evaluate expression %s in cfgile %s",
                logstr, (char*) xexpr, cfgfile);
        }
        xmlXPathFreeContext(xpathCtx);
        if (xpathObj) {
            xmlXPathFreeObject(xpathObj);
        }
        xmlFreeDoc(doc);
        return NULL;
    }
    if (xpathObj->nodesetval != NULL &&
        xpathObj->nodesetval->nodeNr > 0) {
        string = (const char*) xmlXPathCastToString(xpathObj);
        xmlXPathFreeContext(xpathCtx);
        xmlXPathFreeObject(xpathObj);
        xmlFreeDoc(doc);
        return string;
    }
    xmlXPathFreeContext(xpathCtx);
    xmlXPathFreeObject(xpathObj);
    xmlFreeDoc(doc);
    return NULL;
}


/**
 * Parse string elements from the configuration file.
 *
 */
const char*
parser_conf_log_filename(region_type* r, const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parser_conf_string(cfgfile,
        "//Configuration/Common/Logging/Syslog/Facility",
        0);
    ods_log_assert(r);
    if (!str) {
        str = parser_conf_string(cfgfile,
            "//Configuration/Common/Logging/File/Filename",
            0);
    }
    if (str) {
        dup = region_strdup(r, str);
        free((void*)str);
    }
    return dup; /* NULL, Facility or Filename */
}

const char*
parser_conf_zonelist_filename(region_type* r, const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parser_conf_string(
        cfgfile,
        "//Configuration/Common/ZoneListFile",
        1);
    ods_log_assert(r);
    if (str) {
        dup = region_strdup(r, str);
        free((void*)str);
    }
    return dup;
}

const char*
parser_conf_clisock_filename(region_type* r, const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parser_conf_string(
        cfgfile,
        "//Configuration/Signer/SocketFile",
        0);
    ods_log_assert(r);
    if (str) {
        dup = region_strdup(r, str);
        free((void*)str);
    } else {
        dup = region_strdup(r, ODS_SE_SOCKFILE);
    }
    return dup;

}

const char*
parser_conf_notify_command(region_type* r, const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parser_conf_string(
        cfgfile,
        "//Configuration/Signer/NotifyCommand",
        0);
    ods_log_assert(r);
    if (str) {
        dup = region_strdup(r, str);
        free((void*)str);
    }
    return dup;
}

const char*
parser_conf_pid_filename(region_type* r, const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parser_conf_string(
        cfgfile,
        "//Configuration/Signer/PidFile",
        0);
    ods_log_assert(r);
    if (str) {
        dup = region_strdup(r, str);
        free((void*)str);
    } else {
        dup = region_strdup(r, ODS_SE_PIDFILE);
    }
    return dup;
}

const char*
parser_conf_working_dir(region_type* r, const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parser_conf_string(
        cfgfile,
        "//Configuration/Signer/WorkingDirectory",
        0);
    ods_log_assert(r);
    if (str) {
        dup = region_strdup(r, str);
        free((void*)str);
    } else {
        dup = region_strdup(r, ODS_SE_WORKDIR);
    }
    return dup;
}

const char*
parser_conf_username(region_type* r, const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parser_conf_string(
        cfgfile,
        "//Configuration/Signer/Privileges/User",
        0);
    ods_log_assert(r);
    if (str) {
        dup = region_strdup(r, str);
        free((void*)str);
    }
    return dup;
}

const char*
parser_conf_group(region_type* r, const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parser_conf_string(
        cfgfile,
        "//Configuration/Signer/Privileges/Group",
        0);
    ods_log_assert(r);
    if (str) {
        dup = region_strdup(r, str);
        free((void*)str);
    }
    return dup;
}

const char*
parser_conf_chroot(region_type* r, const char* cfgfile)
{
    const char* dup = NULL;
    const char* str = parser_conf_string(
        cfgfile,
        "//Configuration/Signer/Privileges/Directory",
        0);
    ods_log_assert(r);
    if (str) {
        dup = region_strdup(r, str);
        free((void*)str);
    }
    return dup;
}


/**
 * Parse elements from the configuration file.
 *
 */
int
parser_conf_use_syslog(const char* cfgfile)
{
    const char* str = parser_conf_string(cfgfile,
        "//Configuration/Common/Logging/Syslog/Facility",
        0);
    if (str) {
        free((void*)str);
        return 1;
    }
    return 0;
}

int
parser_conf_verbosity(const char* cfgfile)
{
    int verbosity = ODS_SE_VERBOSITY;
    const char* str = parser_conf_string(cfgfile,
        "//Configuration/Common/Logging/Verbosity",
        0);
    if (str) {
        if (strlen(str) > 0) {
            verbosity = atoi(str);
        }
        free((void*)str);
    }
    return verbosity;
}

int
parser_conf_worker_threads(const char* cfgfile)
{
    int numwt = ODS_SE_WORKERTHREADS;
    const char* str = parser_conf_string(cfgfile,
        "//Configuration/Signer/WorkerThreads",
        0);
    if (str) {
        if (strlen(str) > 0) {
            numwt = atoi(str);
        }
        free((void*)str);
    }
    return numwt;
}

int
parser_conf_signer_threads(const char* cfgfile)
{
    int numwt = ODS_SE_WORKERTHREADS;
    const char* str = parser_conf_string(cfgfile,
        "//Configuration/Signer/SignerThreads",
        0);
    if (str) {
        if (strlen(str) > 0) {
            numwt = atoi(str);
        }
        free((void*)str);
        return numwt;
    }
    /* no SignerThreads value configured, look at WorkerThreads */
    return parser_conf_worker_threads(cfgfile);
}

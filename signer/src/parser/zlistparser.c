/*
 * $Id: zlistparser.c 7041 2013-02-15 09:09:02Z matthijs $
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
 * Parsing zonelist files.
 *
 */

#include "config.h"
#include "adapter/adapter.h"
#include "parser/zlistparser.h"
#include "util/file.h"
#include "util/log.h"
#include "util/status.h"
#include "util/str.h"
#include "signer/zlist.h"
#include "signer/zone.h"

#include <libxml/xpath.h>
#include <libxml/xmlreader.h>
#include <stdlib.h>
#include <string.h>

static const char* logstr = "parser";


/**
 * Parse expr inside XPath Context.
 *
 */
static const char*
parser_zlist_element(xmlXPathContextPtr xpathCtx, xmlChar* expr)
{
    xmlXPathObjectPtr xpathObj = NULL;
    const char* str = NULL;
    ods_log_assert(xpathCtx);
    ods_log_assert(expr);
    xpathObj = xmlXPathEvalExpression(expr, xpathCtx);
    if (xpathObj == NULL) {
        ods_log_error("[%s] failed to evaluate xpath expression %s",
            logstr, expr);
        return NULL;
    }
    str = (const char*) xmlXPathCastToString(xpathObj);
    xmlXPathFreeObject(xpathObj);
    return str;
}


/**
 * Create adapter from configuration.
 *
 */
static adapter_type*
pzl_adapter(xmlNode* curNode, region_type* r, adapter_mode type, unsigned in)
{
    const char* file = NULL;
    adapter_type* adapter = NULL;
    ods_log_assert(curNode);
    ods_log_assert(r);
    file = (const char*) xmlNodeGetContent(curNode);
    if (!file) {
        ods_log_error("[%s] read %s adapter failed", logstr,
            in?"input":"output");
        return NULL;
    }
    adapter = adapter_create(r, file, type, in);
    free((void*)file);
    return adapter;
}


/**
 * Parse adapter.
 *
 */
adapter_type*
parser_zlist_adapter(xmlXPathContextPtr xpathCtx, xmlChar* expr,
    region_type* r, int in)
{
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode* curNode = NULL;
    xmlChar* type = NULL;
    adapter_type* adapter = NULL;
    int i = 0;
    if (!xpathCtx || !expr || !r) {
        return NULL;
    }
    xpathObj = xmlXPathEvalExpression(expr, xpathCtx);
    if (xpathObj == NULL) {
        ods_log_error("[%s] xmlPathEvalExpression() failed (expr=%s)",
            logstr, expr);
        return NULL;
    }
    if (xpathObj->nodesetval) {
        for (i=0; i < xpathObj->nodesetval->nodeNr; i++) {
            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar*)"File")) {
                    adapter = pzl_adapter(curNode, r, ADAPTER_FILE, in);
                } else if (xmlStrEqual(curNode->name,
                    (const xmlChar*)"Adapter")) {
                    type = xmlGetProp(curNode, (const xmlChar*)"type");
                    if (xmlStrEqual(type, (const xmlChar*)"File")) {
                        adapter = pzl_adapter(curNode, r, ADAPTER_FILE, in);
                    } else if (xmlStrEqual(type, (const xmlChar*)"DNS")) {
                        adapter = pzl_adapter(curNode, r, ADAPTER_DNS, in);
                    } else if (xmlStrEqual(type, (const xmlChar*)"Update")) {
                        adapter = pzl_adapter(curNode, r, ADAPTER_UPDATE, in);
                    } else {
                        ods_log_error("[%s] unable to parse %s adapter: "
                            "unknown type", logstr, (const char*) type);
                    }
                    free((void*)type);
                    type = NULL;
                }
                if (adapter) {
                    break;
                }
                curNode = curNode->next;
            }
        }
    }
    xmlXPathFreeObject(xpathObj);
    return adapter;
}


/**
 * Parse the adapters.
 *
 */
static void
parser_zlist_adapters(xmlXPathContextPtr xpathCtx, zone_type* z)
{
    xmlChar* i_expr = (xmlChar*) "//Zone/Adapters/Input";
    xmlChar* o_expr = (xmlChar*) "//Zone/Adapters/Output";
    if (!xpathCtx || !z) {
        return;
    }
    z->adapter_in = parser_zlist_adapter(xpathCtx, i_expr, z->region, 1);
    z->adapter_out = parser_zlist_adapter(xpathCtx, o_expr, z->region, 0);
    return;
}


/**
 * Parse the zonelist file.
 *
 */
ods_status
parser_zlist_zones(struct zlist_struct* zlist, const char* zlfile)
{
    char* tag_name = NULL;
    char* zone_name = NULL;
    zone_type* new_zone = NULL;
    int ret = 0;
    int error = 0;
    xmlTextReaderPtr reader = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlChar* name_expr = (unsigned char*) "name";
    xmlChar* policy_expr = (unsigned char*) "//Zone/Policy";
    xmlChar* signconf_expr = (unsigned char*) "//Zone/SignerConfiguration";

    ods_log_assert(zlist);
    ods_log_assert(zlfile);
    reader = xmlNewTextReaderFilename(zlfile);
    if (!reader) {
        ods_log_error("[%s] failed to open file %s", logstr, zlfile);
        return ODS_STATUS_XMLERR;
    }
    ret = xmlTextReaderRead(reader);
    while (ret == XML_READER_TYPE_ELEMENT) {
        tag_name = (char*) xmlTextReaderLocalName(reader);
        if (ods_strcmp(tag_name, "Zone") == 0 &&
            ods_strcmp(tag_name, "ZoneList") != 0 &&
            xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
            /* Found a zone */
            zone_name = (char*) xmlTextReaderGetAttribute(reader,
                name_expr);
            if (!zone_name || strlen(zone_name) <= 0) {
                ods_log_alert("[%s] failed to extract zone name from "
                    "zonelist %s, skipping...", logstr, zlfile);
                if (zone_name) {
                    free((void*) zone_name);
                }
                free((void*) tag_name);
                ret = xmlTextReaderRead(reader);
                continue;
            }
            /* Expand this node to get the rest of the info */
            xmlTextReaderExpand(reader);
            doc = xmlTextReaderCurrentDoc(reader);
            if (doc) {
                xpathCtx = xmlXPathNewContext(doc);
            }
            if (doc == NULL || xpathCtx == NULL) {
                ods_log_alert("[%s] failed to read zone %s, skipping...",
                   logstr, zone_name);
                ret = xmlTextReaderRead(reader);
                free((void*) zone_name);
                free((void*) tag_name);
                continue;
            }
            /* That worked, now read out the contents... */
            new_zone = zone_create(zone_name, LDNS_RR_CLASS_IN);
            if (new_zone) {
                new_zone->policy_name = parser_zlist_element(xpathCtx,
                    policy_expr);
                new_zone->signconf_filename = parser_zlist_element(xpathCtx,
                    signconf_expr);
                parser_zlist_adapters(xpathCtx, new_zone);
                if (!new_zone->policy_name || !new_zone->signconf_filename
                  || !new_zone->adapter_in || !new_zone->adapter_out) {
                    zone_cleanup(new_zone);
                    new_zone = NULL;
                    ods_log_crit("[%s] unable to create zone %s", logstr,
                        zone_name);
                    error = 1;
                } else if (zlist_add_zone((zlist_type*) zlist, new_zone)
                    == NULL) {
                    ods_log_crit("[%s] unable to add zone %s", logstr,
                        zone_name);
                    zone_cleanup(new_zone);
                    new_zone = NULL;
                    error = 1;
                }
            } else {
                ods_log_crit("[%s] unable to create zone %s", logstr,
                    zone_name);
                error = 1;
            }
            xmlXPathFreeContext(xpathCtx);
            xpathCtx = NULL;
            free((void*) zone_name);
            if (error) {
                free((void*) tag_name);
                tag_name = NULL;
                ret = 1;
                break;
            }
            ods_log_debug("[%s] zone %s added", logstr, new_zone->name);
        }
        free((void*) tag_name);
        ret = xmlTextReaderRead(reader);
    }
    /* no more zones */
    ods_log_debug("[%s] no more zones", logstr);
    xmlFreeTextReader(reader);
    if (doc) {
        xmlFreeDoc(doc);
    }
    if (ret != 0) {
        ods_log_error("[%s] parse error in %s", logstr, zlfile);
        return ODS_STATUS_PARSERR;
    }
    return ODS_STATUS_OK;
}

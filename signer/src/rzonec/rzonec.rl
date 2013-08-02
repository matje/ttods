/*
 * zonec.rl -- zone compiler based on ragel.
 *
 * Copyright (c) 2013, Matthijs Mekking, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "adapter/adfile.h"
#include "dns/dname.h"
#include "dns/dns.h"
#include "rzonec/rzonec.h"
#include "util/log.h"
#include "util/status.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAX_BUFSIZE 1024

static const char* logstr = "rzonec";


/**
 * State machine.
 *
 */
%%{
    machine zparser;

    include "zparser.rl";
 
    write data;
}%%


/**
 * Create parser.
 *
 */
zparser_type*
zparser_create(zone_type* zone)
{
    zparser_type* parser;
    region_type* r = region_create();
    if (!r) {
        return NULL;
    }
    parser = (zparser_type*) region_alloc(r, sizeof(zparser_type));
    parser->tmp_rdata = (rdata_type*) region_alloc(r, DNS_RDATA_MAX *
        sizeof(rdata_type));
    parser->region = r;
    parser->zone = zone;
    parser->origin = zone->apex;
    parser->ttl = zone->default_ttl;
    parser->klass = zone->klass;
    parser->cs = zparser_start;
    parser->line = 1;
    parser->comments = 0;
    parser->numrrs = 0;
    parser->totalerrors = 0;
    parser->rdsize = 0;
    parser->number = 0;
    parser->seconds = 0;
    parser->dname = NULL;
    parser->label = NULL;
    parser->dname_size = 0;
    parser->label_head = 0;
    parser->label_count = 0;
    /* resource records */
    parser->current_rr.ttl = parser->ttl;
    parser->current_rr.type = 0;
    parser->current_rr.klass = DNS_CLASS_IN;
    parser->current_rr.rdlen = 0;
    parser->current_rr.rdata = parser->tmp_rdata;
    return parser;
}


/**
 * Cleanup parser.
 *
 */
void
zparser_cleanup(zparser_type* parser)
{
    region_cleanup(parser->region);
    return;
}


/**
 * Reads the specified zone into the memory.
 *
 */
int
zparser_read_zone(zparser_type* parser, const char* file)
{
    char buf[MAX_BUFSIZE];
    char last[MAX_BUFSIZE];
    ssize_t r1;
    ssize_t r2;
    int fd = open(file, O_RDONLY);
    if (fd == -1) {
        return ODS_STATUS_FOPENERR;
    }
    r1 = read(fd, buf, MAX_BUFSIZE);
    r2 = read(fd, last, MAX_BUFSIZE);
    while (r1 > 0) {
        int cs = parser->cs;
        char* p = &buf[0];
        char* pe = p + r1 + 1;
        char* eof = NULL;
        if (!r2) {
           eof = pe;
        }

        %% write init;
        %% write exec;

        ods_log_debug("[%s] read %lu bytes.\n", logstr, r1);

        parser->cs = cs;

        r1 = r2;
        (void) memcpy(&buf[0], &last[0], r1);
        r2 = read(fd, last, MAX_BUFSIZE);
    }
    close(fd);
    fflush(stdout);
    return parser->totalerrors;
}


/**
 * Process resource record.
 *
 */
int
zparser_process_rr(zparser_type* parser)
{
    ods_status status;

    /* supported CLASS */
    if (parser->current_rr.klass != DNS_CLASS_IN) {
        ods_log_error("[%s] error: only class IN is supported", logstr);
        return 0;
    }
    /* supported TYPE */
    if (parser->current_rr.type == DNS_TYPE_MD ||
        parser->current_rr.type == DNS_TYPE_MF) {
        rrstruct_type* rrstruct = dns_rrstruct_by_type(parser->current_rr.type);
        ods_log_warning("[%s] warning: type %s in zone %s is obsoleted",
            logstr, rrstruct->name, parser->zone->name);
    }
    
    /* if soa: update new serial */

    /* add rr to zone */
    status = zone_add_rr(parser->zone, &parser->current_rr, 1);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] error: adding rr failed", logstr);
        return 0;
    }

    /* all fine */
    parser->numrrs++;
    return 1;
}

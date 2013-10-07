/*
 * rzonec.h -- zone compiler based on ragel.
 *
 * Copyright (c) 2013, Matthijs Mekking, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef RZONEC_RZONEC_H
#define RZONEC_RZONEC_H

#include <stdint.h>

#include "rzonec/zonec.h"
#include "signer/zone.h"
#include "util/region.h"

/**
 * Zone parser structure.
 *
 */
typedef struct zparser zparser_type;
struct zparser {
    region_type* region;      /* global memory region */
    dname_type* origin;       /* current origin */
    zone_type* zone;          /* currently parsed zone */
    /* We could handle ttl as a duration */
    uint64_t ttl;             /* current ttl */
    uint32_t klass;           /* zone class */

    /* Ragel variables */
    int cs;

    unsigned int line;        /* number of lines */
    unsigned int line_update; /* for debug printing */
    unsigned int comments;    /* number of comments */
    unsigned int numrrs;      /* number of rrs */
    unsigned int totalerrors; /* number of errors */

    /* Temporary storage: rdata */
    size_t rdsize;
    char rdbuf[DNS_RDLEN_MAX];

    /* Temporary storage: numbers */
    uint64_t number;
    uint64_t seconds;

    /* Temporary storage: domain names */
    dname_type* dname;
    const uint8_t* label;
    size_t dname_size;
    size_t label_head;
    uint8_t dname_wire[DNAME_MAXLEN];
    uint8_t label_offsets[DNAME_MAXLEN];
    uint8_t label_count;
    uint8_t dname_is_absolute;

    /* Temporary storage: resource records */
    rr_type current_rr;
    rdata_type* tmp_rdata;
};


/**
 * Create parser.
 * @param zone: zone to be parsed.
 * @return: (zparser_type*) parser.
 *
 */
zparser_type* zparser_create(zone_type* zone);

/**
 * Cleanup parser.
 * @param parser: parser.
 *
 */
void zparser_cleanup(zparser_type* parser);

/**
 * Process resource record.
 * @param parser: parser.
 * @return: (int) status.
 *
 */
int zparser_process_rr(zparser_type* parser);

/**
 * Reads the specified zone into the memory.
 * @param parser: parser.
 * @param file: file name.
 * @param:      (int) number of errors.
 *
 */
int zparser_read_zone(zparser_type* parser, const char* file);

#endif /* RZONEC_RZONEC_H */


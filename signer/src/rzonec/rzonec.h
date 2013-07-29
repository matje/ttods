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

#include "util/region.h"
#include "rzonec/zonec.h"

/**
 * Zone parser structure.
 *
 */
typedef struct zparser zparser_type;
struct zparser {
    region_type* region;      /* global memory region */
    region_type* rr_region;   /* memory for resource records */
    dname_type* origin;       /* current origin */
    /* We could handle ttl as a duration */
    uint64_t ttl;             /* current ttl */
    uint32_t klass;           /* zone class */

    unsigned int line;        /* number of lines */
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

    /* Temporary storage: resource records */
    rr_type current_rr;
    rdata_type* tmp_rdata;
};


/**
 * Create parser.
 * @return: (int) 1 on success, 0 on error.
 *
 */
int zparser_create();

/**
 * Cleanup parser.
 *
 */
void zparser_cleanup(void);

/**
 * Process resource record.
 * @return: (int) status.
 *
 */
int rzonec_process_rr(void);

/**
 * Reads the specified zone into the memory.
 * @param file: file name.
 * @param:      (int) number of errors.
 *
 */
int rzonec_read_zone(const char* file);

#endif /* RZONEC_RZONEC_H */


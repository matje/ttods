/*
 * zonec.h -- zone compiler functions.
 *
 * Copyright (c) 2013, Matthijs Mekking, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef RZONEC_ZONEC_H
#define RZONEC_ZONEC_H

#include "dns/dname.h"
#include "dns/dns.h"
#include "dns/rr.h"
#include "util/region.h"

#include <stdint.h>


/**
 * Add parsed RDATA element into currently parsed resource record.
 * @param region:   memory region.
 * @param rr:       currently parsed resource record.
 * @param rdformat: type of RDATA.
 * @param rdbuf:    buffer containing human-readable RDATA element.
 * @return:         (int) 1 on success, 0 on failure.
 *
 */
int zonec_rdata_add(region_type* region, rr_type* rr,
   dns_rdata_format rdformat, const char* rdbuf, size_t rdlen);

#endif /* RZONEC_ZONEC_H */


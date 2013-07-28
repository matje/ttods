/*
 * $Id: signconf.h 6215 2012-03-20 13:30:51Z matthijs $
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
 * Signer configuration.
 *
 */

#ifndef SIGNER_SIGNCONF_H
#define SIGNER_SIGNCONF_H

#include "util/duration.h"
#include "util/region.h"
#include "util/status.h"

#include <ldns/ldns.h>

#define SC_SALT_SIZE 511
#define SC_SERIAL_SIZE 12

/**
 * Signconf structure.
 *
 */
typedef struct signconf_struct signconf_type;
struct signconf_struct {
    /* Signatures */
    duration_type sig_resign_interval;
    duration_type sig_refresh_interval;
    duration_type sig_validity_default;
    duration_type sig_validity_denial;
    duration_type sig_jitter;
    duration_type sig_inception_offset;
    /* Denial of existence */
    ldns_rr_type nsec_type;
    int nsec3_optout;
    uint32_t nsec3_algo;
    uint32_t nsec3_iterations;
    char nsec3_salt[SC_SALT_SIZE];
    /* Keys */
    duration_type dnskey_ttl;
    /* Source of authority */
    duration_type soa_ttl;
    duration_type soa_min;
    char soa_serial[SC_SERIAL_SIZE];
    /* Other useful information */
    time_t last_modified;

    /* 2x str, 5x int, 9x duration */
    /* est.mem: SC: 1056 */
};

/**
 * Create a new signer configuration with the 'empty' settings.
 * @param r: memory region.
 * @return:  (signconf_type*) signer configuration.
 *
 */
signconf_type* signconf_create(region_type* r);

/**
 * Update signer configuration.
 * @param sc:     signer configuration.
 * @param scfile: signer configuration file name.
 * @return:       (ods_status) status.
 *
 */
ods_status signconf_update(signconf_type* sc, const char* scfile);

/**
 * Log signer configuration.
 * @param sc:   signconf to log.
 * @param name: zone name.
 *
 */
void signconf_log(signconf_type* sc, const char* name);

/**
 * Clean up signer configuration.
 * @param sc: signconf to cleanup.
 *
 */
void signconf_cleanup(signconf_type* sc);

#endif /* SIGNER_SIGNCONF_H */

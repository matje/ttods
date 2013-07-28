/*
 * $Id: signconfparser.h 6036 2012-01-06 12:08:45Z matthijs $
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

#ifndef PARSER_SIGNCONFPARSER_H
#define PARSER_SIGNCONFPARSER_H

#include "parser/confparser.h"
#include "util/duration.h"
#include "util/status.h"

#include <ldns/ldns.h>

/**
 * Parse durations from the configuration file.
 * @param cfgfile: configuration file name.
 * @param d:       duration.
 * @return:        (ods_status) status.
 *
 */
ods_status parser_sc_sig_resign_interval(const char* cfgfile,
     duration_type* d);
ods_status parser_sc_sig_refresh_interval(const char* cfgfile,
    duration_type* d);
ods_status parser_sc_sig_validity_default(const char* cfgfile,
    duration_type* d);
ods_status parser_sc_sig_validity_denial(const char* cfgfile,
    duration_type* d);
ods_status parser_sc_sig_jitter(const char* cfgfile, duration_type* d);
ods_status parser_sc_sig_inception_offset(const char* cfgfile,
    duration_type* d);
ods_status parser_sc_dnskey_ttl(const char* cfgfile, duration_type* d);
ods_status parser_sc_soa_ttl(const char* cfgfile, duration_type* d);
ods_status parser_sc_soa_min(const char* cfgfile, duration_type* d);

/**
 * Parse denial of existence type from the configuration file.
 * @param cfgfile: configuration file name.
 * @return:        (ldns_rr_type) rr type.
 *
 */
ldns_rr_type parser_sc_nsec_type(const char* cfgfile);

/**
 * Parse uint32_t values from the configuration file.
 * @param cfgfile: configuration file name.
 * @return:        (uint32_t) value.
 *
 */
uint32_t parser_sc_nsec3_algorithm(const char* cfgfile);
uint32_t parser_sc_nsec3_iterations(const char* cfgfile);

/**
 * Parse NSEC3 Opt-Out from the configuration file.
 * @param cfgfile: configuration file name.
 * @return:        (int) 1 if Opt-Out, 0 otherwise.
 *
 */
int parser_sc_nsec3_optout(const char* cfgfile);

/**
 * Parse strings from the configuration file.
 * @param cfgfile: configuration file name.
 * @param buf:     string buffer.
 * @return:        (ods_status) status.
 *
 */
ods_status parser_sc_soa_serial(const char* cfgfile, char* buf);
ods_status parser_sc_nsec3_salt(const char* cfgfile, char* buf);

#endif /* PARSER_SIGNCONFPARSER_H */

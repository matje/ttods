/*
 * $Id: confparser.h 6065 2012-01-16 09:45:47Z jerry $
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

#ifndef PARSER_CONFPARSER_H
#define PARSER_CONFPARSER_H

#include "util/region.h"
#include "util/status.h"

/**
 * Check config file with rng file.
 * @param cfgfile: the configuration file name.
 * @param rngfile: the rng file name.
 * @return:        (ods_status) status.
 *
 */
ods_status parser_filecheck(const char* cfgfile, const char* rngfile);

/**
 * Parse elements from the configuration file, given an expression.
 * @param cfgfile:  configuration file.
 * @param expr:     xml expression.
 * @param required: if the element is required.
 * @return:         (const char*) string value.
 *
 */
const char* parser_conf_string(const char* cfgfile, const char* expr,
    int required);

/**
 * Parse string elements from the configuration file.
 * @param cfgfile: configuration file.
 * @return:        (const char*) string.
 *
 */
/** Common specific */
const char* parser_conf_log_filename(region_type* r, const char* cfgfile);
const char* parser_conf_zonelist_filename(region_type* r, const char* cfgfile);
/** Signer specific */
const char* parser_conf_clisock_filename(region_type* r, const char* cfgfile);
const char* parser_conf_notify_command(region_type* r, const char* cfgfile);
const char* parser_conf_pid_filename(region_type* r, const char* cfgfile);
const char* parser_conf_working_dir(region_type* r, const char* cfgfile);
const char* parser_conf_username(region_type* r, const char* cfgfile);
const char* parser_conf_group(region_type* r, const char* cfgfile);
const char* parser_conf_chroot(region_type* r, const char* cfgfile);

/**
 * Parse integer elements from the configuration file.
 * @param cfgfile: configuration file.
 * @return:        (int) integer.
 *
 */

/** Common */
int parser_conf_use_syslog(const char* cfgfile);
int parser_conf_verbosity(const char* cfgfile);

/** Signer specific */
int parser_conf_worker_threads(const char* cfgfile);
int parser_conf_signer_threads(const char* cfgfile);

#endif /* PARSE_CONFPARSER_H */

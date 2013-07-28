/*
 * $Id: cfg.h 5945 2011-11-30 11:54:30Z matthijs $
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
 * Signer engine configuration.
 *
 */

#ifndef DAEMON_CFG_H
#define DAEMON_CFG_H

#include "util/region.h"
#include "util/status.h"

#include <stdio.h>

/**
 * Signer engine configuration.
 *
 */
typedef struct cfg_struct cfg_type;
struct cfg_struct {
    const char* cfg_filename;
    const char* log_filename;
    const char* zonelist_filename;
    const char* clisock_filename;
    const char* notify_command;
    const char* pid_filename;
    const char* working_dir;
    const char* username;
    const char* group;
    const char* chroot;
    int use_syslog;
    int num_worker_threads;
    int num_signer_threads;
    int verbosity;

    /* 10x charptr, 4x int */
    /* est.mem: C: 416 bytes (with avg strlen 32) */
};

/**
 * Create cfg.
 * @param r:                 memory region.
 * @param cfgfile:           config file.
 * @param cmdline_verbosity: log level from the command line.
 * @return:                  (cfg_type*) signer engine configuration.
 *
 */
cfg_type* cfg_create(region_type* r, const char* cfgfile,
    int cmdline_verbosity);

/**
 * Check cfg.
 * @param cfg: signer engine configuration.
 * @return:    (ods_status) status, ok if cfg is ok, else error.
 *
 */
ods_status cfg_check(cfg_type* cfg);

/**
 * Print cfg.
 * @param out: output file descriptor.
 * @param cfg: signer engine configuration.
 *
 */
void cfg_print(FILE* out, cfg_type* cfg);

/**
 * Clean up cfg.
 * @param cfg: signer engine configuration.
 *
 */
void cfg_cleanup(cfg_type* cfg);

#endif /* DAEMON_CFG_H */


/*
 * $Id: cfg.c 6655 2012-09-12 09:04:07Z matthijs $
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

#include "config.h"
#include "daemon/cfg.h"
#include "parser/confparser.h"
#include "util/file.h"
#include "util/log.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static const char* logstr = "config";


/**
 * Create cfg.
 *
 */
cfg_type*
cfg_create(region_type* r, const char* cfgfile, int cmdline_verbosity)
{
    const char* rngfile = ODS_SE_RNGDIR "/conf.rng";
    ods_status status = ODS_STATUS_OK;
    FILE* cfgfd = NULL;
    cfg_type* cfg;
    ods_log_assert(r);
    ods_log_assert(cfgfile);
    /* check syntax (slows down parsing configuration file) */
    status = parser_filecheck(cfgfile, rngfile);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] parse error in %s", logstr, cfgfile,
            ods_status2str(status));
        return NULL;
    }
    /* open file */
    cfgfd = ods_fopen(cfgfile, NULL, "r");
    if (cfgfd) {
        ods_log_verbose("[%s] read cfgfile: %s", logstr, cfgfile);
        cfg = (cfg_type*) region_alloc(r, sizeof(cfg_type));
        if (!cfg) {
            ods_log_crit("[%s] region alloc failed", logstr);
            ods_fclose(cfgfd);
            return NULL;
        }
        cfg->cfg_filename = region_strdup(r, cfgfile);
        cfg->log_filename = parser_conf_log_filename(r, cfgfile);
        cfg->zonelist_filename = parser_conf_zonelist_filename(r, cfgfile);
        cfg->clisock_filename = parser_conf_clisock_filename(r, cfgfile);
        cfg->notify_command = parser_conf_notify_command(r, cfgfile);
        cfg->pid_filename = parser_conf_pid_filename(r, cfgfile);
        cfg->working_dir = parser_conf_working_dir(r, cfgfile);
        cfg->username = parser_conf_username(r, cfgfile);
        cfg->group = parser_conf_group(r, cfgfile);
        cfg->chroot = parser_conf_chroot(r, cfgfile);
        cfg->use_syslog = parser_conf_use_syslog(cfgfile);
        cfg->num_worker_threads = parser_conf_worker_threads(cfgfile);
        cfg->num_signer_threads = parser_conf_signer_threads(cfgfile);
        cfg->verbosity = cmdline_verbosity;
        /* If any verbosity has been specified at cmd line we will use that */
        if (cmdline_verbosity <= 0) {
            cfg->verbosity = parser_conf_verbosity(cfgfile);
        }
        ods_fclose(cfgfd);
        return cfg;
    }
    ods_log_error("[%s] open cfgfile %s failed: %s", logstr, cfgfile,
        strerror(errno));
    return NULL;
}


/**
 * Check cfg.
 *
 */
ods_status
cfg_check(cfg_type* cfg)
{
    if (!cfg) {
        return ODS_STATUS_ASSERT;
    }
    return ODS_STATUS_OK;
}


/**
 * Print cfg.
 *
 */
void
cfg_print(FILE* out, cfg_type* cfg)
{
    if (!out) {
        return;
    }
    fprintf(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    if (!cfg) {
        return;
    }
    fprintf(out, "<Configuration>\n");
    /* Common */
    fprintf(out, "\t<Common>\n");
    fprintf(out, "\t</Common>\n");
    /* Signer */
    fprintf(out, "\t<Signer>\n");
    fprintf(out, "\t</Signer>\n");
    fprintf(out, "</Configuration>\n");
    return;
}


/**
 * Clean up cfg.
 *
 */
void
cfg_cleanup(cfg_type* ATTR_UNUSED(cfg))
{
    return;
}


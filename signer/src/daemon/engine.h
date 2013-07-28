/*
 * $Id: engine.h 6450 2012-06-21 13:19:03Z matthijs $
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
 * The engine.
 *
 */

#ifndef DAEMON_ENGINE_H
#define DAEMON_ENGINE_H

#include "daemon/cfg.h"
#include "daemon/cmdhandler.h"
#include "daemon/signal.h"
#include "daemon/worker.h"
#include "schedule/fifoq.h"
#include "schedule/schedule.h"
#include "signer/zlist.h"
#include "util/locks.h"
#include "util/region.h"


/**
 * Engine structure.
 *
 */
typedef struct engine_struct engine_type;
struct engine_struct {
    region_type* region;
    cfg_type* cfg;
    zlist_type* zlist;
    cmdhandler_type* cmdhandler;
    worker_type** workers;
    worker_type** drudgers;
    schedule_type* taskq;
    fifoq_type* signq;
    pid_t pid;
    uid_t uid;
    gid_t gid;
    int daemonize;
    int cmdhandler_done;
    int need_to_exit;
    int need_to_reload;
    sig_atomic_t signal;
    cond_basic_type signal_cond;
    lock_basic_type signal_lock;

    /* 7x ptr, 10x int */
    /* est.mem: 96 + C + ZL + CMD + 16*W + TQ + SQ bytes*/
};

/**
 * Start signer engine.
 * @param cfgfile:           configuration file.
 * @param cmdline_verbosity: how many -v on the command line.
 * @param daemonize:         to run as daemon or not.
 * @param info:              print info and exit.
 * @param single_run:        run once.
 *
 */
void engine_start(const char* cfgfile, int cmdline_verbosity,
    int daemonize, int info, int single_run);

/**
 * Update zones.
 * @param engine:     signer engine.
 * @param zl_changed: whether the zonelist has changed or not.
 *
 */
void engine_update_zones(engine_type* engine, ods_status zl_changed);

/**
 * Wake up all workers.
 * @param engine:     signer engine.
 *
 */
void engine_wakeup_workers(engine_type* engine);

#endif /* DAEMON_ENGINE_H */

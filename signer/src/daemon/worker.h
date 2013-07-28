/*
 * $Id: worker.h 6890 2012-12-12 14:33:49Z matthijs $
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
 * The hard workers.
 *
 */

struct engine_struct;

#ifndef DAEMON_WORKER_H
#define DAEMON_WORKER_H

#include "schedule/task.h"
#include "util/locks.h"


enum worker_enum {
    WORKER_NONE = 0,
    WORKER_WORKER = 1,
    WORKER_DRUDGER
};
typedef enum worker_enum worker_id;

/**
 * Worker structure.
 *
 */
typedef struct worker_struct worker_type;
struct worker_struct {
    int thread_num;
    ods_thread_type thread_id;
    worker_id type;
    cond_basic_type worker_alarm;
    lock_basic_type worker_lock;
    struct engine_struct* engine;
    task_type* task;
    task_id working_with;
    time_t clock_in;
    unsigned sleeping : 1;
    unsigned waiting : 1;
    unsigned need_to_exit : 1;

    /* 2x ptr, 6x int, 3x bit */
    /* est.mem: W: 41 bytes */
};

/**
 * Create worker.
 * @param engine: global shared engine structure.
 * @param num:    thread number.
 * @param type:   type of worker.
 * @return:       (worker_type*) created worker.
 *
 */
worker_type* worker_create(struct engine_struct* engine, int num,
    worker_id type);

/**
 * Start working.
 * @param worker: worker to start.
 *
 */
void worker_start(worker_type* worker);

/**
 * Wake up worker.
 * @param worker: worker to wake up.
 *
 */
void worker_wakeup(worker_type* worker);

/**
 * Notify all workers.
 * @param lock: lock to use.
 * @param cond: condition that has been met.
 *
 */
void worker_notify_all(lock_basic_type* lock, cond_basic_type* cond);

/**
 * Clean up worker.
 * @param worker: worker to clean up.
 *
 */
void worker_cleanup(worker_type* worker);

#endif /* DAEMON_WORKER_H */

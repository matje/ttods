/*
 * $Id$
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
 * Task scheduling.
 *
 */

#ifndef SCHEDULE_SCHEDULE_H
#define SCHEDULE_SCHEDULE_H

#include "util/locks.h"
#include "util/region.h"
#include "util/status.h"

#include <ldns/ldns.h>

/**
 * Schedule structure.
 *
 */
typedef struct schedule_struct schedule_type;
struct schedule_struct {
    ldns_rbtree_t* tasks;
    int flushcount;
    int loading;
    lock_basic_type s_lock;
    cond_basic_type s_cond;

    /* 1x tree, 4x int */
    /* est.mem: TQ: 24 + 77N bytes (N = #zones) */
};

/**
 * Create new schedule.
 & @param r: memory region.
 * @return:  (schedule_type*) created schedule.
 *
 */
schedule_type* schedule_create(region_type* r);

/**
 * Look up task.
 * @param s:   schedule.
 * @param t:   task.
 * @return:    (void*) task, if found.
 *
 */
void* schedule_lookup_task(schedule_type* s, void* t);

/**
 * Get next task (if it is time to work on it).
 * @param s:   schedule.
 * @return:    (void*) task pointer.
 *
 */
void* schedule_next(schedule_type* s);

/**
 * Peek at first scheduled task.
 * @param s:   schedule.
 * @return:    (void*) task pointer.
 *
 */
void* schedule_peek(schedule_type* s);

/**
 * Schedule task.
 * @param s:   schedule.
 * @param t:   task.
 * @param log: whether to add a log entry for this task.
 * @return:    (ods_status) status.
 *
 */
ods_status schedule_task(schedule_type* s, void* t, int log);

/**
 * Unschedule task.
 * @param s:   schedule.
 * @param t:   task.
 * @return:    (void*) task, if it was scheduled.
 *
 */
void* unschedule_task(schedule_type* s, void* t);

/**
 * Reschedule task.
 * @param s:    schedule.
 * @param t:    task to delete.
 * @param what: new task.
 * @param when: new time.
 * @return:     (ods_status) status.
 *
 */
ods_status reschedule_task(schedule_type* s, void* t, int what, time_t when);

/**
 * Clean up schedule.
 * @param schedule: schedule to be cleaned up.
 *
 */
void schedule_cleanup(schedule_type* schedule);

#endif /* SCHEDULE_SCHEDULE_H */


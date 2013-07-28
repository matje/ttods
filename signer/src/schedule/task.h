/*
 * $Id: task.h 6181 2012-02-21 14:12:17Z matthijs $
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
 * Tasks.
 *
 */

#ifndef SCHEDULE_TASK_H
#define SCHEDULE_TASK_H

#include <ldns/ldns.h>

enum task_id_enum {
    TASK_NONE = 0,
    TASK_CONF,     /* ods-signer update */
    TASK_READ,     /* ods-signer sign */
    TASK_SIGN,     /* ods-signer flush */
    TASK_WRITE
};
typedef enum task_id_enum task_id;

struct zone_struct;

/**
 * Task.
 */
typedef struct task_struct task_type;
struct task_struct {
    struct zone_struct* zone;
    task_id what;
    task_id interrupt;
    task_id halted;
    time_t when;
    time_t halted_when;
    time_t backoff;
    int flush;

    /* 1x ptr, 7x int */
    /* est.mem: T: 36 bytes */
};

/**
 * Create a new task.
 * @param what: task identifier.
 * @param when: scheduled time.
 * @param zone: zone reference.
 * @return:     (task_type*) created task.
 *
 */
task_type* task_create(task_id what, time_t when, struct zone_struct* zone);

/**
 * Compare tasks.
 * @param a: one task.
 * @param b: another task.
 * @return:  (int) -1, 0 or 1.
 *
 */
int task_compare(const void* a, const void* b);

/**
 * Convert task to string.
 * @param task: task.
 * @param buf:  buffer to store string.
 * @return:     (char*) string-format of task.
 *
 */
char* task2str(task_type* task, char* buf);

/**
 * String-format of who.
 * @param task: task.
 * @return:     (const char*) string-format of who.
 */
const char* task_who2str(task_type* task);

/**
 * String-format of what.
 * @param what: task identifier.
 * @return:     (const char*) string-format of what.
 *
 */
const char* task_what2str(task_id what);

/**
 * Log task.
 * @param task: task.
 *
 */
void task_log(task_type* task);

/**
 * Clean up task.
 * @param task: task.
 *
 */
void task_cleanup(task_type* task);

#endif /* SCHEDULE_TASK_H */


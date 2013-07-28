/*
 * $Id: worker.c 7005 2013-02-05 10:31:30Z matthijs $
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

#include "config.h"
#include "daemon/engine.h"
#include "daemon/worker.h"
#include "signer/tools.h"

static ods_lookup_table logstr[] = {
    { WORKER_WORKER, "worker" },
    { WORKER_DRUDGER, "drudger" },
    { 0, NULL }
};


/**
 * Convert worker type to string.
 *
 */
static const char*
worker2str(worker_id type)
{
    ods_lookup_table *lt = ods_lookup_by_id(logstr, type);
    if (lt) {
        return lt->name;
    }
    return NULL;
}


/**
 * Create worker.
 *
 */
worker_type*
worker_create(struct engine_struct* engine, int num, worker_id type)
{
    worker_type* worker;
    ods_log_assert(engine);
    ods_log_assert(engine->region);
    worker = (worker_type*) region_alloc(engine->region, sizeof(worker_type));
    if (!worker) {
        ods_log_crit("[%s[%i]] region alloc failed",
            worker2str(type), num+1);
        return NULL;
    }
    ods_log_debug("[%s[%i]] create", worker2str(type), num+1);
    lock_basic_init(&worker->worker_lock);
    lock_basic_set(&worker->worker_alarm);
    lock_basic_lock(&worker->worker_lock);
    worker->thread_num = num +1;
    worker->engine = engine;
    worker->task = NULL;
    worker->type = type;
    worker->sleeping = 0;
    worker->waiting = 0;
    worker->need_to_exit = 0;
    worker->clock_in = 0;
    lock_basic_unlock(&worker->worker_lock);
    return worker;
}


/**
 * Worker working with...
 *
 */
static void
worker_working_with(worker_type* worker, task_id with, task_id next,
    const char* str, const char* name, task_id* what, time_t* when)
{
    worker->working_with = with;
    ods_log_verbose("[%s[%i]] %s zone %s", worker2str(worker->type),
       worker->thread_num, str, name);
    *what = next;
    *when = time_now();
    return;
}


/**
 * Perform task.
 *
 */
static void
worker_perform_task(worker_type* worker)
{
    zone_type* zone;
    task_id what = TASK_NONE;
    time_t when = 0;
    ods_status status = ODS_STATUS_OK;
    ods_log_assert(worker);
    ods_log_assert(worker->task);
    ods_log_assert(worker->task->zone);
    ods_log_assert(worker->engine);
    zone = (zone_type*) worker->task->zone;
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    worker->working_with = worker->task->what;
    ods_log_debug("[%s[%i]] perform task %s for zone %s at %u",
       worker2str(worker->type), worker->thread_num,
       task_what2str(worker->task->what), task_who2str(worker->task),
       (uint32_t) worker->clock_in);
    /* do what you have been told to do */
    switch (worker->working_with) {
        case TASK_CONF:

worker_perform_task_conf:
            /* perform 'load signconf' task */
            worker_working_with(worker, TASK_CONF, TASK_READ, "configure",
                task_who2str(worker->task), &what, &when);
            status = tools_conf(zone);
            if (status == ODS_STATUS_OK) {
                worker->task->halted = TASK_NONE;
                worker->task->interrupt = TASK_NONE;
                goto worker_perform_task_read;
            } else if (status == ODS_STATUS_UNCHANGED) {
                if (!zone->signconf->last_modified) {
                    status = ODS_STATUS_CFGERR;
                    goto worker_perform_task_fail;
                } else if (worker->task->halted > TASK_CONF) {
                    goto worker_perform_task_continue;
                } else {
                    status = ODS_STATUS_OK;
                    worker->task->halted = TASK_NONE;
                    worker->task->interrupt = TASK_NONE;
                    goto worker_perform_task_read;
                }
            } else if (worker->task->halted == TASK_NONE) {
                goto worker_perform_task_fail;
            } else {
                goto worker_perform_task_continue;
            }
            break;
        case TASK_READ:

worker_perform_task_read:
            /* perform 'read' task */
            worker_working_with(worker, TASK_READ, TASK_SIGN, "read",
                task_who2str(worker->task), &what, &when);
            /* make sure there is a signconf */
            if (!zone->signconf->last_modified) {
                ods_log_warning("[%s[%i]] no signconf for zone %s yet, "
                    "will first configure zone", worker2str(worker->type),
                    worker->thread_num, task_who2str(worker->task));
                goto worker_perform_task_conf;
            }
            status = tools_read(zone);
            if (status == ODS_STATUS_UNCHANGED) {
                status = ODS_STATUS_OK;
            }
            if (status == ODS_STATUS_OK) {
                if (worker->task->interrupt > TASK_CONF) {
                    worker->task->halted = TASK_NONE;
                    worker->task->interrupt = TASK_NONE;
                }
                goto worker_perform_task_sign;
            } else if (worker->task->halted == TASK_NONE) {
                goto worker_perform_task_fail;
            } else {
                goto worker_perform_task_continue;
            }
            break;
        case TASK_SIGN:

worker_perform_task_sign:
            /* perform 'load signconf' task */
            worker_working_with(worker, TASK_SIGN, TASK_SIGN, "sign",
                task_who2str(worker->task), &what, &when);
            when += 60;
            break;
        default:
            ods_log_warning("[%s[%i]] task %s not supported",
                worker2str(worker->type), worker->thread_num,
                task_what2str(worker->task->what));
            break;
    }
    /* no error */
    worker->task->backoff = 0;
    if (worker->task->interrupt != TASK_NONE &&
        worker->task->interrupt != what) {
        ods_log_debug("[%s[%i]] interrupt task %s for zone %s",
            worker2str(worker->type), worker->thread_num,
            task_what2str(what), task_who2str(worker->task));
        worker->task->halted = what;
        worker->task->halted_when = when;
        worker->task->what = worker->task->interrupt;
        worker->task->when = time_now();
    } else {
        ods_log_debug("[%s[%i]] next task %s for zone %s",
            worker2str(worker->type), worker->thread_num,
            task_what2str(what), task_who2str(worker->task));
        worker->task->what = what;
        worker->task->when = when;
        worker->task->interrupt = TASK_NONE;
        worker->task->halted = TASK_NONE;
        worker->task->halted_when = 0;
    }
    /* backup state */

    worker->working_with = TASK_NONE;
    return;

worker_perform_task_fail:
    /* failure */
    if (worker->task->backoff) {
        worker->task->backoff *= 2;
    } else {
        worker->task->backoff = 60;
    }
    if (worker->task->backoff > ODS_SE_MAX_BACKOFF) {
        worker->task->backoff = ODS_SE_MAX_BACKOFF;
    }
    ods_log_info("[%s[%i]] backoff task %s for zone %s with %u seconds",
        worker2str(worker->type), worker->thread_num,
        task_what2str(worker->task->what), task_who2str(worker->task),
        worker->task->backoff);
    worker->task->when = time_now() + worker->task->backoff;
    return;

    worker->working_with = TASK_NONE;
    return;

worker_perform_task_continue:
    /* continue halted task */
    ods_log_info("[%s[%i]] continue task %s for zone %s",
        worker2str(worker->type), worker->thread_num,
        task_what2str(worker->task->halted), task_who2str(worker->task));
    worker->task->what = worker->task->halted;
    worker->task->when = worker->task->halted_when;
    worker->task->interrupt = TASK_NONE;
    worker->task->halted = TASK_NONE;
    worker->task->halted_when = 0;
    worker->working_with = TASK_NONE;
    return;
}


/**
 * Work.
 *
 */
static void
worker_work(worker_type* worker)
{
    engine_type* engine;
    zone_type* zone;
    task_type* task;
    ods_status status;
    time_t timeout = 1;
    ods_log_assert(worker);
    ods_log_assert(worker->engine);
    ods_log_assert(worker->type == WORKER_WORKER);
    engine = (engine_type*) worker->engine;
    while (!worker->need_to_exit) {
        /* report for duty */
        time_t now = time_now();
        ods_log_deeebug("[%s[%i]] report for duty", worker2str(worker->type),
            worker->thread_num);
        lock_basic_lock(&engine->taskq->s_lock);
        worker->task = (task_type*) schedule_next(engine->taskq);
        if (!worker->task) {
            /**
             * Apparently there is no task to perform currently. Wait until
             * task is ready, or new task is queued. The worker will release
             * the taskq lock while sleeping and will automatically grab the
             * lock when there is a task that requires attention.
             */
            task = schedule_peek(engine->taskq);
            timeout = task?(task->when - now):timeout*2;
            if (timeout > ODS_SE_MAX_BACKOFF) {
                timeout = ODS_SE_MAX_BACKOFF;
            }
            ods_log_deeebug("[%s[%i]] nothing to do, wait %u seconds",
                worker2str(worker->type), worker->thread_num, timeout);
            lock_basic_sleep(&engine->taskq->s_cond,
                &engine->taskq->s_lock, timeout);
            worker->task = (task_type*) schedule_next(engine->taskq);
        }
        lock_basic_unlock(&engine->taskq->s_lock);
        /* do some work */
        if (worker->task) {
            zone = (zone_type*) worker->task->zone;
            lock_basic_lock(&zone->zone_lock);
            ods_log_debug("[%s[%i]] start working on zone %s",
                worker2str(worker->type), worker->thread_num, zone->name);
            worker->clock_in = now;
            worker_perform_task(worker);
            /* schedule new task */
            lock_basic_lock(&engine->taskq->s_lock);
            ods_log_debug("[%s[%i]] finished working on zone %s",
                worker2str(worker->type), worker->thread_num, zone->name);
            worker->task->when += 60;
            status = schedule_task(engine->taskq, worker->task, 1);
            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s[%i]] schedule task for zone %s failed: "
                "%s", worker2str(worker->type), worker->thread_num,
                zone->name, ods_status2str(status));
            }
            worker->task = NULL;
            lock_basic_unlock(&engine->taskq->s_lock);
            lock_basic_unlock(&zone->zone_lock);
            timeout = 1;
            /** Do we need to tell the engine that we require a reload? */
            lock_basic_lock(&engine->signal_lock);
            if (engine->need_to_reload) {
                lock_basic_alarm(&engine->signal_cond);
            }
            lock_basic_unlock(&engine->signal_lock);
        }
        ods_log_info("[%s[%i]] did some work",
            worker2str(worker->type), worker->thread_num);
    }
    return;
}


/**
 * Drudge.
 *
 */
static void
worker_drudge(worker_type* worker)
{
    engine_type* engine;
    ods_log_assert(worker);
    ods_log_assert(worker->engine);
    ods_log_assert(worker->type == WORKER_DRUDGER);
    engine = (engine_type*) worker->engine;
    while (!worker->need_to_exit) {
        /* report for duty */
        ods_log_deeebug("[%s[%i]] report for duty", worker2str(worker->type),
            worker->thread_num);

        lock_basic_lock(&engine->signq->q_lock);
        /**
         * Apparently the queue is empty. Wait until new work is queued.
         * The drudger will release the signq lock while sleeping and
         * will automatically grab the lock when the threshold is reached.
         * Threshold is at 1 and MAX (after a number of tries).
         */
        ods_log_deeebug("[%s[%i]] nothing to do, wait",
            worker2str(worker->type), worker->thread_num);
        lock_basic_sleep(&engine->signq->q_threshold,
            &engine->signq->q_lock, 0);

        lock_basic_unlock(&engine->signq->q_lock);
        /* do some work */
        ods_log_info("[%s[%i]] did some drudging",
            worker2str(worker->type), worker->thread_num);
    }
    return;
}


/**
 * Start worker.
 *
 */
void
worker_start(worker_type* worker)
{
    ods_log_assert(worker);
    switch (worker->type) {
        case WORKER_DRUDGER:
            worker_drudge(worker);
            break;
        case WORKER_WORKER:
            worker_work(worker);
            break;
        default:
            ods_log_error("[worker] illegal worker (id=%i)", worker->type);
            break;
    }
    return;
}


/**
 * Wake up worker.
 *
 */
void
worker_wakeup(worker_type* worker)
{
    ods_log_assert(worker);
    if (worker->sleeping && !worker->waiting) {
        ods_log_debug("[%s[%i]] wake up", worker2str(worker->type),
           worker->thread_num);
        lock_basic_lock(&worker->worker_lock);
        lock_basic_alarm(&worker->worker_alarm);
        worker->sleeping = 0;
        lock_basic_unlock(&worker->worker_lock);
    }
    return;
}


/**
 * Notify all workers.
 *
 */
void
worker_notify_all(lock_basic_type* lock, cond_basic_type* cond)
{
    lock_basic_lock(lock);
    lock_basic_broadcast(cond);
    lock_basic_unlock(lock);
    return;
}


/**
 * Clean up worker.
 *
 */
void
worker_cleanup(worker_type* worker)
{
    if (!worker) {
        return;
    }
    lock_basic_destroy(&worker->worker_lock);
    lock_basic_off(&worker->worker_alarm);
    return;
}

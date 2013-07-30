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

#include "config.h"
#include "schedule/schedule.h"
#include "schedule/task.h"
#include "util/duration.h"
#include "util/log.h"

static const char* logstr = "schedule";


/**
 * Create new schedule.
 *
 */
schedule_type*
schedule_create(region_type* r)
{
    schedule_type* s;
    ods_log_assert(r);
    s = (schedule_type*) region_alloc(r, sizeof(schedule_type));
    s->region = r;
    s->loading = 0;
    s->flushcount = 0;
    s->tasks = tree_create(r, task_compare);
    lock_basic_init(&s->s_lock);
    lock_basic_set(&s->s_cond);
    return s;
}


/**
 * Look up task.
 *
 */
void*
schedule_lookup_task(schedule_type* s, void* t)
{
    tree_node* node = TREE_NULL;
    void* lookup = NULL;
    if (!s || !t || !s->tasks) {
        return NULL;
    }
    node = tree_search(s->tasks, t);
    if (node && node != TREE_NULL) {
        lookup = (void*) node->data;
    }
    return lookup;
}


/**
 * Get next task (if it is time to work on it).
 *
 */
void*
schedule_next(schedule_type* s)
{
    task_type* next = NULL;
    time_t now = time_now();
    if (!s || !s->tasks) {
        return NULL;
    }
    next = schedule_peek(s);
    if (next && (next->flush || next->when <= now)) {
        if (next->flush) {
            ods_log_debug("[%s] flush task for zone %s", logstr,
                task_who2str(next));
        } else {
            ods_log_debug("[%s] pop task for zone %s", logstr,
                task_who2str(next));
        }
        return unschedule_task(s, next);
    }
    return NULL;
}


/**
 * Peek at first scheduled task.
 *
 */
void*
schedule_peek(schedule_type* s)
{
    tree_node* first_node = TREE_NULL;
    tree_node* node = TREE_NULL;
    task_type* first = NULL;
    if (!s || !s->tasks) {
        return NULL;
    }
    first_node = tree_first(s->tasks);
    if (!first_node) {
        return NULL;
    }
    if (s->flushcount > 0) {
        /* find remaining to be flushed tasks */
        node = first_node;
        while (node && node != TREE_NULL) {
            first = (task_type*) node->data;
            if (first->flush) {
                return (void*) first;
            }
            node = tree_next(node);
        }
        /* no more to be flushed tasks found */
        ods_log_warning("[%s] failed to find flush-task, while there should "
            "be %i flush-tasks left", logstr, s->flushcount);
        ods_log_info("[%s] reset flush count to 0", logstr);
        s->flushcount = 0;
    }
    /* no more tasks to be flushed, return first task in schedule */
    return (void*) first_node->data;
}


/**
 * Convert task to a tree node.
 *
 */
static tree_node*
task2node(schedule_type* s, void* t)
{
    tree_node* node = (tree_node*) region_alloc(s->region, sizeof(tree_node));
    node->key = t;
    node->data = t;
    return node;
}


/**
 * Schedule task.
 *
 */
ods_status
schedule_task(schedule_type* s, void* t, int log)
{
    ldns_rbnode_t* new_node = NULL;
    ldns_rbnode_t* ins_node = NULL;
    task_type* task = (task_type*) t;
    ods_log_assert(s);
    ods_log_assert(s->tasks);
    ods_log_assert(t);
    ods_log_debug("[%s] schedule task %s for zone %s", logstr,
        task_what2str(task->what), task_who2str(task));
    if (schedule_lookup_task(s, t) != NULL) {
        ods_log_error("[%s] already present", logstr,
            task_what2str(task->what), task_who2str(task));
        return ODS_STATUS_SCHEDULERR;
    }
    new_node = task2node(s, t);
    if (!new_node) {
        ods_log_error("[%s] convert task to node failed", logstr,
            task_what2str(task->what), task_who2str(task));
        return ODS_STATUS_MALLOCERR;
    }
    ins_node = tree_insert(s->tasks, new_node);
    if (!ins_node) {
        ods_log_error("[%s] rbtree insert failed", logstr,
            task_what2str(task->what), task_who2str(task));
        free((void*)new_node);
        return ODS_STATUS_RBTREERR;
    }
    if (task->flush) {
        s->flushcount++;
    }
    if (log) {
        task_log(task);
    }
    return ODS_STATUS_OK;
}


/**
 * Unschedule task.
 *
 */
void*
unschedule_task(schedule_type* s, void* t)
{
    tree_node* del_node = TREE_NULL;
    task_type* del_task = (task_type*) t;
    ods_log_assert(s);
    ods_log_assert(s->tasks);
    ods_log_assert(t);
    ods_log_debug("[%s] unschedule task %s for zone %s",
        logstr, task_what2str(del_task->what), task_who2str(del_task));
    del_node = tree_delete(s->tasks, t);
    if (del_node) {
        del_task = (task_type*) del_node->data;
        free((void*)del_node);
    } else {
        ods_log_warning("[%s] unable to unschedule task %s for zone %s: not "
            "scheduled", logstr, task_what2str(del_task->what),
            task_who2str(del_task));
        return NULL;
    }
    if (del_task->flush) {
        del_task->flush = 0;
        s->flushcount--;
    }
    return (void*) del_task;
}


/**
 * Reschedule task.
 *
 */
ods_status
reschedule_task(schedule_type* s, void* t, int what, time_t when)
{
    task_type* del_task = NULL;
    ods_log_assert(s);
    ods_log_assert(s->tasks);
    ods_log_assert(t);
    del_task = (task_type*) unschedule_task(s, t);
    if (!del_task) {
        del_task = (task_type*) t;
    }
    del_task->what = (task_id) what;
    del_task->when = when;
    return schedule_task(s, (void*) del_task, 1);
}


/**
 * Clean up schedule.
 *
 */
void
schedule_cleanup(schedule_type* s)
{
    if (!s) {
        return;
    }
    ods_log_debug("[%s] cleanup tasks", logstr);
    tree_cleanup(s->tasks);
    lock_basic_destroy(&s->s_lock);
    lock_basic_off(&s->s_cond);
    return;
}


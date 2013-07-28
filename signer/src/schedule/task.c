/*
 * $Id: task.c 7040 2013-02-15 08:19:53Z matthijs $
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

#include "config.h"
#include "schedule/task.h"
#include "signer/zone.h"
#include "util/log.h"
#include "util/str.h"

static const char* logstr = "task";


/**
 * Create a new task.
 *
 */
task_type*
task_create(task_id what, time_t when, struct zone_struct* zone)
{
    task_type* task = NULL;
    ods_log_assert(zone);
    ods_log_assert(zone->region);
    task = (task_type*) region_alloc(zone->region, sizeof(task_type));
    if (!task) {
        ods_log_crit("[%s] region alloc failed", logstr);
        return NULL;
    }
    task->what = what;
    task->when = when;
    task->interrupt = TASK_NONE;
    task->halted = TASK_NONE;
    task->halted_when = 0;
    task->backoff = 0;
    task->flush = 0;
    task->zone = zone;
    zone->task = task;
    return task;
}


/**
 * Compare tasks.
 *
 */
int
task_compare(const void* a, const void* b)
{
    task_type* x = (task_type*)a;
    task_type* y = (task_type*)b;
    zone_type* zx = NULL;
    zone_type* zy = NULL;
    ods_log_assert(x);
    ods_log_assert(y);
    zx = (zone_type*) x->zone;
    zy = (zone_type*) y->zone;
    if (!ods_strcmp(zx->name, zy->name)) { return 0; }
    /* order task on time, what to do, dname */
    if (x->when != y->when) {
        return (int) x->when - y->when;
    }
    if (x->what != y->what) {
        return (int) x->what - y->what;
    }
    return ods_strcmp(zx->name, zy->name);
}


/**
 * Convert task to string.
 *
 */
char* task2str(task_type* task, char* buf)
{
    if (task && buf) {
        char* strtime = ctime(&task->when);
        if (strtime) {
            strtime[strlen(strtime)-1] = '\0';
        }
        (void)snprintf(buf, ODS_SE_MAXLINE, "%s %s I will %s zone %s\n",
            task->flush?"Flush":"On", strtime?strtime:"(null)",
            task_what2str(task->what), task_who2str(task));
        return buf;
    }
    return NULL;
}


/**
 * String-format of who.
 *
 */
const char*
task_who2str(task_type* task)
{
    zone_type* zone = NULL;
    if (task) {
        zone = (zone_type*) task->zone;
    }
    if (zone && zone->name) {
        return zone->name;
    }
    return "(null)";
}


/**
 * String-format of what.
 *
 */
const char*
task_what2str(task_id what)
{
    switch (what) {
        case TASK_NONE:

            return "[ignore]";
            break;
        case TASK_CONF:
            return "[configure]";
            break;
        case TASK_READ:
            return "[read]";
            break;
        case TASK_SIGN:
            return "[sign]";
            break;
        case TASK_WRITE:
            return "[write]";
            break;
        default:
            break;
    }
    return "[???]";
}


/**
 * Log task.
 *
 */
void
task_log(task_type* task)
{
    char* strtime = NULL;
    if (task) {
        strtime = ctime(&task->when);
        if (strtime) {
            strtime[strlen(strtime)-1] = '\0';
        }
        ods_log_debug("[%s] %s %s I will %s zone %s", logstr,
            task->flush?"Flush":"On", strtime?strtime:"(null)",
            task_what2str(task->what), task_who2str(task));
    }
    return;
}


/**
 * Clean up task.
 *
 */
void
task_cleanup(task_type* ATTR_UNUSED(task))
{
    return;
}



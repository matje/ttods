/*
 * $Id$
 *
 * Copyright (c) 2011 NLNet Labs. All rights reserved.
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
 * FIFO Queue.
 *
 */

#include "config.h"
#include "schedule/fifoq.h"
#include "util/log.h"

#include <errno.h>
#include <string.h>

static const char* logstr = "fifo";


/**
 * Create new FIFO queue.
 *
 */
fifoq_type*
fifoq_create(region_type* r)
{
    fifoq_type* fifoq;
    ods_log_assert(r);
    fifoq = (fifoq_type*) region_alloc(r, sizeof(fifoq_type));
    if (!fifoq) {
        ods_log_crit("[%s] region alloc failed", logstr);
        return NULL;
    }
    fifoq_wipe(fifoq);
    lock_basic_init(&fifoq->q_lock);
    lock_basic_set(&fifoq->q_threshold);
    lock_basic_set(&fifoq->q_nonfull);
    return fifoq;
}


/**
 * Wipe queue.
 *
 */
void
fifoq_wipe(fifoq_type* q)
{
    size_t i;
    if (!q) {
        return;
    }
    for (i=0; i < FIFOQ_MAX_COUNT; i++) {
        q->blob[i] = NULL;
        q->owner[i] = NULL;
    }
    q->count = 0;
    return;
}



/**
 * Clean up queue.
 *
 */
void
fifoq_cleanup(fifoq_type* q)
{
    if (!q) {
        return;
    }
    lock_basic_off(&q->q_threshold);
    lock_basic_off(&q->q_nonfull);
    lock_basic_destroy(&q->q_lock);
    return;
}


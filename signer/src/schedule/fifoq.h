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

#ifndef SCHEDULE_FIFOQ_H
#define SCHEDULE_FIFOQ_H

#include "daemon/worker.h"
#include "util/region.h"
#include "util/locks.h"

#define FIFOQ_MAX_COUNT 1000

/**
 * Queue structure.
 *
 */
typedef struct fifoq_struct fifoq_type;
struct fifoq_struct {
    void* blob[FIFOQ_MAX_COUNT];
    worker_type* owner[FIFOQ_MAX_COUNT];
    size_t count;
    lock_basic_type q_lock;
    cond_basic_type q_threshold;
    cond_basic_type q_nonfull;

    /* 4x int, 2x ptr, 2x array */
    /* est.mem: SQ: 1632 bytes */
};

/**
 * Create new FIFO queue.
 * @param r: memory region.
 * @return:  (fifoq_type*) created queue.
 *
 */
fifoq_type* fifoq_create(region_type* r);

/**
 * Wipe queue.
 * @param q: queue to be wiped.
 *
 */
void fifoq_wipe(fifoq_type* q);

/**
 * Clean up queue.
 * @param q: queue to be cleaned up.
 *
 */
void fifoq_cleanup(fifoq_type* q);

#endif /* SCHEDULE_FIFOQ_H */


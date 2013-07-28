/*
 * $Id: locks.h 5946 2011-11-30 11:55:04Z matthijs $
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
 * Threading and locking.
 *
 */

#ifndef UTIL_LOCKS_H
#define UTIL_LOCKS_H

#include "util/log.h"

#include <errno.h>
#include <stdlib.h>

#define LOCKRET(func) do { \
        int err; \
        if ( (err=(func)) != 0) \
                ods_log_error("%s at %d could not " #func ": %s", \
                __FILE__, __LINE__, strerror(err)); \
        } while(0)

#if defined(HAVE_PTHREAD)

#include <pthread.h>

/** use pthread mutex for basic lock */
typedef pthread_mutex_t lock_basic_type;
/** use pthread cond for basic condition */
typedef pthread_cond_t cond_basic_type;

/** small front for pthread init func, NULL is default attrs. */
#define lock_basic_init(lock) LOCKRET(pthread_mutex_init(lock, NULL))
#define lock_basic_destroy(lock) LOCKRET(pthread_mutex_destroy(lock))
#define lock_basic_lock(lock) LOCKRET(pthread_mutex_lock(lock))
#define lock_basic_unlock(lock) LOCKRET(pthread_mutex_unlock(lock))

/** our own alarm clock */
#define lock_basic_set(cond) LOCKRET(pthread_cond_init(cond, NULL))
#define lock_basic_sleep(cond, lock, sleep) LOCKRET(ods_thread_wait(cond, lock, sleep))
#define lock_basic_alarm(cond) LOCKRET(pthread_cond_signal(cond))
#define lock_basic_broadcast(cond) LOCKRET(pthread_cond_broadcast(cond))
#define lock_basic_off(cond) LOCKRET(pthread_cond_destroy(cond))

/** thread creation */
typedef pthread_t ods_thread_type;
/** Pass where to store tread_t in thr. Use default NULL attributes. */
#define ods_thread_create(thr, func, arg) LOCKRET(pthread_create(thr, NULL, func, arg))
#define ods_thread_detach(thr) LOCKRET(pthread_detach(thr))
#define ods_thread_self() pthread_self()
#define ods_thread_join(thr) LOCKRET(pthread_join(thr, NULL))
#define ods_thread_kill(thr, sig) LOCKRET(pthread_kill(thr, sig))

/**
 * Make a thread wait until a certain condition holds, with a maximum waiting
 * time.
 * @param cond: condition.
 * @param lock: corresponding lock.
 * @param wait: maximum waiting time.
 * @return:     (int) 0 if success, 1 on error.
 *
 */
int ods_thread_wait(cond_basic_type* cond, lock_basic_type* lock, time_t wait);

#else /* !HAVE_PTHREAD */

/* we do not have PTHREADS */
#define PTHREADS_DISABLED 1

typedef int lock_basic_type;
#define lock_basic_init(lock)           /* nop */
#define lock_basic_destroy(lock)        /* nop */
#define lock_basic_lock(lock)           /* nop */
#define lock_basic_unlock(lock)         /* nop */

#define lock_basic_set(cond)       /* nop */
#define lock_basic_sleep(cond, lock, sleep) /* nop */
#define lock_basic_alarm(cond)     /* nop */
#define lock_basic_broadcast(cond)     /* nop */
#define lock_basic_off(cond)       /* nop */

typedef pid_t ods_thread_type;
#define ods_thread_create(thr, func, arg) ods_thr_fork_create(thr, func, arg)
#define ods_thread_detach(thr)      /* nop */
#define ods_thread_self() getpid()
#define ods_thread_join(thr) ods_thr_fork_wait(thr)

/**
 * No threading available: fork a new process.
 * This means no shared data structure, and no locking.
 * Only the main thread ever returns. Exits on errors.
 * @param thr:  the location where to store the thread-id.
 * @param func: function body of the thread. Return value of func is lost.
 * @param arg:  user argument to func.
 *
 */
void ods_thr_fork_create(ods_thread_type* thr, void* (*func)(void*), void* arg);

/**
 * There is no threading. Wait for a process to terminate.
 * Note that ub_thread_t is defined as pid_t.
 * @param thread: the process id to wait for.
 *
 */
void ods_thr_fork_wait(ods_thread_type thread);

#endif /* HAVE_PTHREAD */

/**
 * Change block signals.
 *
 */
void ods_thread_blocksigs(void);

#endif /* UTIL_LOCKS_H */

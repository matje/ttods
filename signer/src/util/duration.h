/*
 * $Id: duration.h 4341 2011-01-31 15:21:09Z matthijs $
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
 * Durations utilities.
 *
 */

#ifndef UTIL_DURATION_H
#define UTIL_DURATION_H

#include "util/region.h"
#include "util/status.h"

#include <stdint.h>
#include <time.h>

/**
 * Duration.
 *
 */
typedef struct duration_struct duration_type;
struct duration_struct
{
    time_t years;
    time_t months;
    time_t weeks;
    time_t days;
    time_t hours;
    time_t minutes;
    time_t seconds;

    /* 7x int */
    /* est.mem: D: 28 bytes */
};

/**
 * Create a new 'instant' duration.
 * @return: (duration_type*) created duration.
 *
 */
duration_type* duration_create(void);

/**
 * Convert a string to a duration.
 * @param str:      string.
 * @param duration: duration.
 * @return:         (ods_status) status.
 *
 */
ods_status str2duration(const char* str, duration_type* duration);

/**
 * Convert a duration to a string.
 * @param r:        memory region.
 * @param duration: duration.
 * @return:         (char*) string.
 *
 */
char* duration2str(region_type* r, duration_type* duration);

/**
 * Convert a duration to a time.
 * @param duration: duration.
 * @return:         (time_t) time.
 *
 */
time_t duration2time(duration_type* duration);

/**
 * Initialize duration values.
 * @param d: duration.
 *
 */
void duration_init(duration_type* d);

/**
 * Copy duration values.
 * @param dto:   duration destination.
 * @param dfrom: duration source.
 *
 */
void duration_copy(duration_type* dto, duration_type* dfrom);

/**
 * Return the time since Epoch, measured in seconds.
 * If the timeshift is enabled, return the environment variable.
 * @return: (time_t) now, or timeshift.
 *
 */
time_t time_now(void);

/**
 * Return time in datestamp.
 * @param tt:     time.
 * @param format: stamp format.
 * @param str:    store string.
 * @return:       (uint32_t) datestamp.
 *
 */
uint32_t time_datestamp(time_t tt, const char* format, char** str);

#endif /* UTIL_DURATION_H */

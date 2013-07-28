/*
 * $Id: duration.c 7039 2013-02-15 08:10:15Z matthijs $
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
 * Duration utilities.
 *
 */

#include "config.h"
#include "util/duration.h"
#include "util/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char* logstr = "duration";


/**
 * Convert a string to a duration.
 *
 */
ods_status
str2duration(const char* str, duration_type* duration)
{
    char* P, *X, *T, *W;
    int not_weeks = 0;
    ods_log_assert(str);
    ods_log_assert(duration);
    P = strchr(str, 'P');
    if (!P) {
        ods_log_error("[%s] read duration from string %s failed: P not found",
            logstr, str);
        return ODS_STATUS_STRFORMERR;
    }
    T = strchr(str, 'T');
    X = strchr(str, 'Y');
    if (X) {
        duration->years = atoi(str+1);
        str = X;
        not_weeks = 1;
    }
    X = strchr(str, 'M');
    if (X && (!T || (size_t) (X-P) < (size_t) (T-P))) {
        duration->months = atoi(str+1);
        str = X;
        not_weeks = 1;
    }
    X = strchr(str, 'D');
    if (X) {
        duration->days = atoi(str+1);
        str = X;
        not_weeks = 1;
    }
    if (T) {
        str = T;
        not_weeks = 1;
    }
    X = strchr(str, 'H');
    if (X && T) {
        duration->hours = atoi(str+1);
        str = X;
        not_weeks = 1;
    }
    X = strrchr(str, 'M');
    if (X && T && (size_t) (X-P) > (size_t) (T-P)) {
        duration->minutes = atoi(str+1);
        str = X;
        not_weeks = 1;
    }
    X = strchr(str, 'S');
    if (X && T) {
        duration->seconds = atoi(str+1);
        str = X;
        not_weeks = 1;
    }
    W = strchr(str, 'W');
    if (W) {
        if (not_weeks) {
            ods_log_error("[%s] read duration from string %s failed: W not "
                "expected", logstr, str);
            return ODS_STATUS_STRFORMERR;
        } else {
            duration->weeks = atoi(str+1);
            str = W;
        }
    }
    return ODS_STATUS_OK;
}


/**
 * Get the number of digits in a number.
 *
 */
static size_t
digits_in_number(time_t duration)
{
    uint32_t period = (uint32_t) duration;
    size_t count = 0;

    while (period > 0) {
        count++;
        period /= 10;
    }
    return count;
}


/*
 * Convert a duration to a string.
 *
 */
char*
duration2str(region_type* r, duration_type* duration)
{
    char* str = NULL, *num = NULL;
    size_t count = 2;
    int T = 0;
    if (!r || !duration) {
        return NULL;
    }
    if (duration->years > 0) {
        count = count + 1 + digits_in_number(duration->years);
    }
    if (duration->months > 0) {
        count = count + 1 + digits_in_number(duration->months);
    }
    if (duration->weeks > 0) {
        count = count + 1 + digits_in_number(duration->weeks);
    }
    if (duration->days > 0) {
        count = count + 1 + digits_in_number(duration->days);
    }
    if (duration->hours > 0) {
        count = count + 1 + digits_in_number(duration->hours);
        T = 1;
    }
    if (duration->minutes > 0) {
        count = count + 1 + digits_in_number(duration->minutes);
        T = 1;
    }
    if (duration->seconds > 0) {
        count = count + 1 + digits_in_number(duration->seconds);
        T = 1;
    }
    if (T) {
        count++;
    }
    str = (char*) region_alloc(r, count * sizeof(char));
    if (!str) {
        goto duration2string_num_ralloc_failed;
    }
    str[0] = 'P';
    str[1] = '\0';
    if (duration->years > 0) {
        count = digits_in_number(duration->years);
        num = (char*) region_alloc(r, (count+2) * sizeof(char));
        if (num) {
            snprintf(num, count+2, "%uY", (uint32_t) duration->years);
            str = strncat(str, num, count+2);
        } else {
            goto duration2string_num_ralloc_failed;
        }
    }
    if (duration->months > 0) {
        count = digits_in_number(duration->months);
        num = (char*) region_alloc(r, (count+2) * sizeof(char));
        if (num) {
            snprintf(num, count+2, "%uM", (uint32_t) duration->months);
            str = strncat(str, num, count+2);
        } else {
            goto duration2string_num_ralloc_failed;
        }
    }
    if (duration->weeks > 0) {
        count = digits_in_number(duration->weeks);
        num = (char*) region_alloc(r, (count+2) * sizeof(char));
        if (num) {
            snprintf(num, count+2, "%uW", (uint32_t) duration->weeks);
            str = strncat(str, num, count+2);
        } else {
            goto duration2string_num_ralloc_failed;
        }
    }
    if (duration->days > 0) {
        count = digits_in_number(duration->days);
        num = (char*) region_alloc(r, (count+2) * sizeof(char));
        if (num) {
            snprintf(num, count+2, "%uD", (uint32_t) duration->days);
            str = strncat(str, num, count+2);
        } else {
            goto duration2string_num_ralloc_failed;
        }
    }
    if (T) {
        str = strncat(str, "T", 1);
    }
    if (duration->hours > 0) {
        count = digits_in_number(duration->hours);
        num = (char*) region_alloc(r, (count+2) * sizeof(char));
        if (num) {
            snprintf(num, count+2, "%uH", (uint32_t) duration->hours);
            str = strncat(str, num, count+2);
        } else {
            goto duration2string_num_ralloc_failed;
        }
    }
    if (duration->minutes > 0) {
        count = digits_in_number(duration->minutes);
        num = (char*) region_alloc(r, (count+2) * sizeof(char));
        if (num) {
            snprintf(num, count+2, "%uM", (uint32_t) duration->minutes);
            str = strncat(str, num, count+2);
        } else {
            goto duration2string_num_ralloc_failed;
        }
    }
    if (duration->seconds > 0) {
        count = digits_in_number(duration->seconds);
        num = (char*) region_alloc(r, (count+2) * sizeof(char));
        if (num) {
            snprintf(num, count+2, "%uS", (uint32_t) duration->seconds);
            str = strncat(str, num, count+2);
        } else {
            goto duration2string_num_ralloc_failed;
        }
    }
    return str;

duration2string_num_ralloc_failed:
    ods_log_error("[%s] region alloc failed", logstr);
    return NULL;
}


/**
 * Convert a duration to a time.
 *
 */
time_t
duration2time(duration_type* duration)
{
    time_t period = 0;
    if (duration) {
        period += (duration->seconds);
        period += (duration->minutes)*60;
        period += (duration->hours)*3600;
        period += (duration->days)*86400;
        period += (duration->weeks)*86400*7;
        period += (duration->months)*86400*31;
        period += (duration->years)*86400*365;
        if (duration->months || duration->years) {
            /* [TODO] calculate correct number of days in this month/year */
            region_type* tmpregion = region_create();
            char* dstr = duration2str(tmpregion, duration);
            ods_log_warning("[%s] converting duration %s to approximate value",
                logstr, dstr?dstr:"(null)");
            region_cleanup(tmpregion);
        }
    }
    return period;
}


/**
 * Initialize duration values.
 *
 */
void
duration_init(duration_type* d)
{
    if (!d) {
        return;
    }
    d->years = 0;
    d->months = 0;
    d->weeks = 0;
    d->days = 0;
    d->hours = 0;
    d->minutes = 0;
    d->seconds = 0;
    return;
}


/**
 * Copy duration values.
 *
 */
void
duration_copy(duration_type* dto, duration_type* dfrom)
{
    dto->years = dfrom->years;
    dto->months = dfrom->months;
    dto->weeks = dfrom->weeks;
    dto->days = dfrom->days;
    dto->hours = dfrom->hours;
    dto->minutes = dfrom->minutes;
    dto->seconds = dfrom->seconds;
    return;
}


#ifdef ENFORCER_TIMESHIFT
/* Number of days per month (except for February in leap years). */
static const int mdays[] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};


/**
 * Whether year is a leap year.
 *
 */
static int
is_leap_year(int year)
{
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}


/**
 * How many leap days between two years.
 *
 */
static int
leap_days(int y1, int y2)
{
    --y1;
    --y2;
    return (y2/4 - y1/4) - (y2/100 - y1/100) + (y2/400 - y1/400);
}


/**
 * Code taken from NSD 3.2.5, which is
 * code adapted from Python 2.4.1 sources (Lib/calendar.py).
 */
static time_t
mktime_from_utc(const struct tm *tm)
{
    int year = 1900 + tm->tm_year;
    time_t days = 365 * ((time_t) (year - 1970)) +
        ((time_t) leap_days(1970, year));
    time_t hours, minutes, seconds;
    int i;
    for (i = 0; i < tm->tm_mon; ++i) {
        days += mdays[i];
    }
    if (tm->tm_mon > 1 && is_leap_year(year)) {
        ++days;
    }
    days += tm->tm_mday - 1;
    hours = days * 24 + tm->tm_hour;
    minutes = hours * 60 + tm->tm_min;
    seconds = minutes * 60 + tm->tm_sec;
    return seconds;
}


/**
 * Convert time in string format into seconds.
 *
 */
static time_t
timeshift2time(const char *time)
{
    /* convert a string in format YYMMDDHHMMSS to time_t */
    struct tm tm;
    time_t timeshift = 0;
    /* try to scan the time */
    if (strptime(time, "%Y%m%d%H%M%S", &tm)) {
        timeshift = mktime_from_utc(&tm);
    }
    return timeshift;
}
#endif


/**
 * Return the time since Epoch, measured in seconds.
 *
 */
time_t
time_now(void)
{
#ifdef ENFORCER_TIMESHIFT
    const char* env = getenv("ENFORCER_TIMESHIFT");
    if (env) {
        return timeshift2time(env);
    } else
#endif /* ENFORCER_TIMESHIFT */

    return time(NULL);
}


/**
 * copycode: This code is based on the EXAMPLE in the strftime manual.
 *
 */
uint32_t
time_datestamp(time_t tt, const char* format, char** str)
{
    time_t t;
    struct tm *tmp;
    uint32_t ut = 0;
    char outstr[32];
    if (tt) {
        t = tt;
    } else {
        t = time_now();
    }
    tmp = localtime(&t);
    if (tmp == NULL) {
        ods_log_error("[%s] localtime failed", logstr);
        return 0;
    }
    if (strftime(outstr, sizeof(outstr), format, tmp) == 0) {
        ods_log_error("[%s] strftime failed", logstr);
        return 0;
    }
    ut = (uint32_t) strtoul(outstr, NULL, 10);
    if (str) {
        *str = strdup(outstr);
    }
    return ut;
}


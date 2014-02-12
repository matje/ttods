/*
 * $Id: util.h 6501 2012-08-06 10:52:03Z matthijs $
 *
 * Copyright (c) 2013 NLNet Labs. All rights reserved.
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
 * Useful utilities.
 *
 */

#ifndef UTIL_UTIL_H
#define UTIL_UTIL_H

#include <stdint.h>
#include <time.h>

/**
 * A general purpose lookup table.
 *
 */
typedef struct table_struct table_type;
struct table_struct {
        int id;
        const char *name;
};

/**
 * Looks up the table entry by name.
 * @param table: lookup table.
 * @param name:  search identifier.
 * @return:      (table_type*) item if found, NULL otherwise.
 *
 */
table_type* table_lookup_by_name(table_type table[], const char* name);

/**
 * Looks up the table entry by identifier.
 * @param table: lookup table.
 * @param id:    search identifier.
 * @return:      (table_type*) item if found, NULL otherwise.
 *
 */
table_type* table_lookup_by_id(table_type table[], int id);

/**
 * Simple max function.
 * @param a: one value.
 * @param b: another value.
 * @return:  (int) b if b is larger than a, otherwise a.
 *
 */
int ods_max(int a, int b);

/**
 * Check process id file.
 * @param pidfile: pid filename.
 * @return:        (int) status (0 if process id in pidfile is running).
 *
 */
int util_check_pidfile(const char* pidfile);

/**
 * Write process id to file.
 * @param pidfile: pid filename.
 * @param pid:     process id.
 * @return         (int) status.
 *
 */
int util_write_pidfile(const char* pidfile, pid_t pid);

/**
 * Convert a single (hexidecimal) digit to its integer value.
 * @param hx:   single hexidecimal digit.
 * @return:     (int) integer value.
 *
 */
int util_hexdigit2int(char hx);

/**
 * Convert string to ttl.
 * @param str: string.
 * @param end: last read character.
 * @return:    (uint32_t) ttl.
 *
 */
uint32_t util_str2ttl(const char* str, const char** end);

/**
 * Convert time to seconds since epoch.
 * @param tm:  time.
 * @return:    (time_t) time.
 *
 */
time_t util_mktime_from_utc(const struct tm* tm);

/**
 * Get bit in bitmap.
 * @param bitmap: bitmap.
 * @param index:  which bit to get.
 * @return:       (int) 1 if set, 0 if clear.
 *
 */
int util_getbit(uint8_t bitmap[], size_t index);

/**
 * Set bit in bitmap.
 * @param bitmap: bitmap.
 * @param index:  which bit to set.
 *
 */
void util_setbit(uint8_t bitmap[], size_t index);

/**
 * Encode to base32.
 * @param src:        source string.
 * @param target:     Base32 encoded target.
 * @param targetsize: maximum target size.
 * @return:           (int) number of target bytes.
 *
 */
int util_base32hex_pton(char const* src, uint8_t* target, size_t targetsize);

/**
 * Decode from base32.
 * @param src:        Base32 encoded source.
 * @param srcsize:    number of source bytes.
 * @param target:     target string.
 * @param targetsize: maximum target size.
 * @return:           (int) number of target bytes.
 *
 */
int util_base32hex_ntop(uint8_t const* src, size_t srcsize, char* target,
    size_t targetsize);

#endif /* UTIL_UTIL_H */


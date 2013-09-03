/*
 * $Id: str.h 6501 2012-08-06 10:52:03Z matthijs $
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
 * String utilities.
 *
 */

#ifndef UTIL_STR_H
#define UTIL_STR_H

#include <stdlib.h>

/**
 * Compare strings, case sensitive.
 * @param s1: one string.
 * @param s2: another string.
 * @return:   (int) a value less than, equal to, or greater than zero if the
 *            first s1 is found, respectively, to be less than, to match, or be
 *            greater than s2.
 *
 */
int ods_strcmp(const char* s1, const char* s2);

/**
 * Compare strings, case insensitive.
 * @param s1: one string.
 * @param s2: another string.
 * @return:   (int) a value less than, equal to, or greater than zero if the
 *            first s1 is found, respectively, to be less than, to match, or be
 *            greater than s2.
 *
 */
int ods_strcasecmp(const char* s1, const char* s2);

/**
 * Remove trailing whitespace.
 * @param str: string to trim.
 * @return:    (size_t) number of trimmed characters.
 *
 */
size_t ods_strtrimr(char* str);

/**
 * Remove leading whitespace.
 * @param str: string to trim.
 * @return:    (size_t) number of trimmed characters.
 *
 */
size_t ods_strtriml(char* str);

/**
 * Remove leading and trailing whitespace.
 * @param str: string to trim.
 * @return:    (size_t) number of trimmed characters.
 *
 */
size_t ods_strtrim(char* str);

/**
 * Check if line is all white space.
 * @param line: line to be checked.
 * @param len:  line length.
 * @return:     (int) 1 if is all white space, 0 otherwise.
 *
 */
int ods_is_whitespace_line(char* line, int len);

/**
 * Do strchr and forward to the next character != c.
 * @param s:      string.
 * @param c:      character.
 * @param offset: how many characters forwarded.
 * @return:       (char*) pointer to the matched character or NULL if not found.
 *
 */
char* ods_strchr_and_fwd(const char* s, int c, size_t* offset);

/**
 * Replace all characters c with the character n in string s.
 * @param s:      string.
 * @param c:      character to be replaced.
 * @param n:      new character.
 *
 */
void ods_strreplace(char* s, int c, int n);

#endif /* UTIL_STR_H */

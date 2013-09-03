/*
 * $Id: str.c 6747 2012-10-19 10:32:45Z matthijs $
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

#include "config.h"
#include "util/str.h"

#include <ctype.h>
#include <string.h>


/**
 * Compare strings.
 *
 */
static int
ods_strcmpfunc(const char* s1, const char* s2,
    int (cmp(const char *, const char *, size_t)))
{
    if (!s1 && !s2) {
        return 0;
    } else if (!s1) {
        return -1;
    } else if (!s2) {
        return -1;
    } else if (strlen(s1) != strlen(s2)) {
        if (cmp(s1, s2, strlen(s1)) == 0) {
            return strlen(s1) - strlen(s2);
        }
    }
    return cmp(s1, s2, strlen(s1));
}


/**
 * Compare strings, case sensitive.
 *
 */
int
ods_strcmp(const char* s1, const char* s2)
{
    return ods_strcmpfunc(s1, s2, strncmp);
}


/**
 * Compare strings, case insensitive.
 *
 */
int
ods_strcasecmp(const char* s1, const char* s2)
{
    return ods_strcmpfunc(s1, s2, strncasecmp);
}


/**
 * Remove trailing whitespace.
 *
 */
size_t
ods_strtrimr(char* str)
{
    int i = strlen(str), nl = 0;
    int trimmed = 0;
    /* trailing */
    while (i > 0) {
        --i;
        if (str[i] == '\n') {
            nl = 1;
        }
        if (str[i] == ' ' || str[i] == '\t' || str[i] == '\n') {
            str[i] = '\0';
            trimmed++;
        } else {
            break;
        }
    }
    if (nl) {
        str[++i] = '\n';
    }
    return trimmed;
}


/**
 * Remove leading whitespace.
 *
 */
size_t
ods_strtriml(char* str)
{
    int i = 0;
    int trimmed = 0;
    /* leading */
    i = 0;
    while (str[i] == ' ' || str[i] == '\t') {
        trimmed++;
        i++;
    }
    while (*(str+i) != '\0') {
        *str = *(str+i);
        str++;
    }
    *str = '\0';
    return trimmed;
}


/**
 * Remove leading and trailing whitespace.
 *
 */
size_t
ods_strtrim(char* str)
{
    size_t trimmed = ods_strtrimr(str);
    trimmed += ods_strtriml(str);
    return trimmed;
}


/**
 * Check if line is all white space.
 *
 */
int
ods_is_whitespace_line(char* line, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        if (!isspace((int)line[i])) {
            return 0;
        }
    }
    return 1;
}


/**
 * Do strchr and forward to the next character != c.
 *
 */
char*
ods_strchr_and_fwd(const char* s, int c, size_t* offset)
{
    char* delim = strchr(s, c);
    *offset = 0;
    if (delim) {
        while (delim[*offset] == c) {
            (*offset)++;
        }
    }
    ods_log_info("strchrfwd: offset=%u", (unsigned) *offset);
    return delim;
}


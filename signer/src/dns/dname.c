/*
 * $Id: dname.c 6501 2012-08-06 10:52:03Z matthijs $
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
 * Domain names.
 *
 */

#include "dns/dname.h"
#include "util/util.h"

#include <assert.h>
#include <ctype.h>
#include <string.h>

static const char* logstr = "dname";


/**
 * Is label normal (not a pointer or reserved)?
 *
 */
int
label_is_normal(const uint8_t* label)
{
    assert(label);
    return (label[0] & 0xc0) == 0;
}


/**
 * Is label a pointer?
 *
 */
int
label_is_pointer(const uint8_t* label)
{
    assert(label);
    return (label[0] & 0xc0) == 0xc0;
}


/**
 * Is label the root label?
 *
 */
int
label_is_root(const uint8_t* label)
{
    assert(label);
    return label[0] == 0;
}


/**
 * Length of label.
 *
 */
uint8_t
label_length(const uint8_t* label)
{
    assert(label);
    assert(label_is_normal(label));
    return label[0];
}


/**
 * Data of label.
 *
 */
const uint8_t*
label_data(const uint8_t* label)
{
    assert(label);
    assert(label_is_normal(label));
    return label + 1;
}


/**
 * Get the next label.
 *
 */
const uint8_t*
label_next(const uint8_t* label)
{
    assert(label);
    assert(label_is_normal(label));
    assert(!label_is_root(label));
    return label + label_length(label) + 1;
}


/**
 * Compare labels.
 *
 */
int
label_compare(const uint8_t* label1, const uint8_t* label2)
{
    int length1;
    int lenght2;
    size_t size;
    int result;
    ods_log_assert(label1);
    ods_log_assert(label2);
    ods_log_assert(label_is_normal(label1));
    ods_log_assert(label_is_normal(label2));
    length1 = label_length(label1);
    lenght2 = label_length(label2);
    size = length1 < lenght2 ? length1 : lenght2;
    result = memcmp(label_data(label1), label_data(label2), size);
    if (result) {
        return result;
    } else {
        return (int) length1 - (int) lenght2;
    }
}


/**
 * The total size (in bytes) allocated to store dname.
 *
 */
size_t
dname_total_size(const dname_type* dname)
{
    assert(dname);
    return (sizeof(dname_type) + ((dname->label_count + dname->size)
        * sizeof(uint8_t)));
}


/**
 * Offsets into dname for each label starting with the most significant label.
 *
 */
const uint8_t*
dname_label_offsets(const dname_type* dname)
{
    assert(dname);
    return (const uint8_t*) ((const char *) dname + sizeof(dname_type));
}


/**
 * The actual name in wire format (a sequence of label, each prefixed by a
 * length byte, terminated by a zero length label).
 *
 */
const uint8_t*
dname_name(const dname_type *dname)
{
    assert(dname);
    return (const uint8_t*) ((const char *) dname + sizeof(dname_type)
        + dname->label_count * sizeof(uint8_t));
}


/**
 * Create new domain name.
 *
 */
dname_type*
dname_create(region_type* r, const char* str)
{
    uint8_t wire[DNAME_MAXLEN];
    uint8_t label_offsets[DNAME_MAXLEN];
    uint8_t label_count = 0;
    size_t size = 0;
    const uint8_t* label = wire;
    dname_type *dname;
    ssize_t i;
    assert(r);
    assert(str);
    if (!dname_str2wire(wire, str)) {
        ods_log_error("[%s] parse dname %s failed", logstr, str);
        return NULL;
    }
    while (1) {
        if (label_is_pointer(label)) {
            return NULL;
        }
        label_offsets[label_count] = (uint8_t) (label - wire);
        ++label_count;
        size += label_length(label) + 1;
        if (label_is_root(label)) {
            break;
        }
        label = label_next(label);
    }
    if (size > DNAME_MAXLEN) {
        return NULL;
    }
    assert(label_count <= DNAME_MAXLEN / 2 + 1);
    /* reverse label offsets. */

    /* reverse label offsets. */
    for (i = 0; i < label_count / 2; ++i) {
        uint8_t tmp = label_offsets[i];
        label_offsets[i] = label_offsets[label_count - i - 1];
        label_offsets[label_count - i - 1] = tmp;
    }
    dname = (dname_type *) region_alloc(r, (sizeof(dname_type)
        + (label_count + size) * sizeof(uint8_t)));
    dname->size = size;
    dname->label_count = label_count;
    memcpy((uint8_t *) dname_label_offsets(dname), label_offsets,
        label_count * sizeof(uint8_t));
    memcpy((uint8_t *) dname_name(dname), wire, size * sizeof(uint8_t));
    return dname;
}


/**
 * Clone domain name.
 *
 */
dname_type*
dname_clone(region_type* r, const dname_type* dname)
{
    assert(r);
    assert(dname);
    return (dname_type*) region_alloc_init(r, dname, dname_total_size(dname));
}


/**
 * Compare domain names.
 *
 */
int
dname_compare(dname_type* dname1, dname_type* dname2)
{
    const dname_type* left = (const dname_type*) dname1;
    const dname_type* right = (const dname_type*) dname2;
    int result;
    uint8_t label_count;
    uint8_t i;
    ods_log_assert(left);
    ods_log_assert(right);
    if (left == right) {
        return 0;
    }
    label_count = (left->label_count <= right->label_count ?
        left->label_count : right->label_count);
    /* skip the root label by starting at label 1. */
    for (i = 1; i < label_count; ++i) {
        result = label_compare(dname_label(left, i), dname_label(right, i));
        if (result) {
            return result;
        }
    }
    /* dname with the fewest labels is "first".  */
    return (int) left->label_count - (int) right->label_count;
}


/**
 * Return label of domain name.
 *
 */
const uint8_t*
dname_label(const dname_type* dname, uint8_t index)
{
    uint8_t label_index;
    ods_log_assert(dname != NULL);
    ods_log_assert(index < dname->label_count);
    label_index = dname_label_offsets(dname)[index];
    ods_log_assert(label_index < dname->size);
    return dname_name(dname) + label_index;
}


/**
 * Parse ascii string to wireformat domain name (without compression ptrs).
 *
 */
int
dname_str2wire(uint8_t* wire, const char* str)
{
    const uint8_t* s;
    uint8_t* h;
    uint8_t* p;
    uint8_t* d;
    size_t label_length;
    assert(wire);
    assert(str);
    s = (const uint8_t*) str;
    d = wire;
    if (strlen(str) == 1 && strncmp(str, ".", 1) == 0) {
        /* root domain.  */
        wire[0] = 0;
        return 1;
    }
    for (h = d, p = h + 1; *s; ++s, ++p) {
        if (p - wire >= DNAME_MAXLEN) {
            ods_log_error("[%s] error: max domainlen exceeded", logstr);
            return 0;
        }
        switch (*s) {
            case '.':
                if (p == h + 1) {
                    ods_log_error("[%s] error: empty label", logstr);
                    return 0;
                } else {
                    label_length = p - h - 1;
                    if (label_length > LABEL_MAXLEN) {
                        ods_log_error("[%s] error: max labellen exceeded",
                            logstr);
                        return 0;
                    }
                    *h = label_length;
                    h = p;
                }
                break;
            case '\\':
                /* Handle escaped characters (RFC1035 5.1) */
                if (s[1] && s[2] && s[3]
                    && isdigit(s[1]) && isdigit(s[2]) && isdigit(s[3])) {
                    int val = (util_hexdigit2int(s[1]) * 100 +
                        util_hexdigit2int(s[2]) * 10 +
                        util_hexdigit2int(s[3]));
                    s += 3;
                    if (0 <= val && val <= 255) {
                        *p = val;
                    } else {
                        *p = 0;
                    }
                } else if (s[1] != '\0' && !isdigit(s[1])) {
                    *p = *++s;
                }
                break;
            default:
                *p = *s;
                break;
        }
    }
    if (p != h + 1) {
        /* Terminate last label.  */
        label_length = p - h - 1;
        if (label_length > LABEL_MAXLEN) {
            return 0;
        }
        *h = label_length;
        h = p;
    }
    /* Add root label.  */
    *h = 0;
    return p-wire;
}


/**
 * Print domain name.
 *
 */
void dname_print(FILE* fd, dname_type* dname)
{
    static char buf[DNAME_MAXLEN*5];
    size_t i;
    size_t labels_to_convert;
    char* dst;
    const uint8_t* src;

    if (!dname || !fd) {
        return;
    }
    assert(dname->label_count > 0);
    if (dname->label_count == 1) {
        fprintf(fd, ".");
        return;
    }
    labels_to_convert = dname->label_count - 1;
    dst = buf;
    src = dname_name(dname);
    for (i = 0; i < labels_to_convert; ++i) {
        size_t len = label_length(src);
        size_t j;
        ++src;
        for (j = 0; j < len; ++j) {
            uint8_t ch = *src++;
            if (isalnum(ch) || ch == '-' || ch == '_') {
                *dst++ = ch;
            } else if (ch == '.' || ch == '\\' || ch == '(' || ch == ')'
                || ch == ';') {
                *dst++ = '\\';
                *dst++ = ch;
            } else {
                snprintf(dst, 5, "\\%03u", (unsigned int)ch);
                dst += 4;
            }
        }
        *dst++ = '.';
    }
    *dst = '\0';
    fprintf(fd, "%s", buf);
    return;
}


/**
 * Print domain name.
 *
 */
void dname_str(dname_type* dname, char* buf)
{
    size_t i;
    size_t labels_to_convert;
    char* dst;
    const uint8_t* src;

    if (!dname) {
        return;
    }
    assert(dname->label_count > 0);
    dst = buf;
    if (dname->label_count == 1) {
        *dst++ = '.';
        *dst = '\0';
        return;
    }
    labels_to_convert = dname->label_count - 1;
    dst = buf;
    src = dname_name(dname);
    for (i = 0; i < labels_to_convert; ++i) {
        size_t len = label_length(src);
        size_t j;
        ++src;
        for (j = 0; j < len; ++j) {
            uint8_t ch = *src++;
            if (isalnum(ch) || ch == '-' || ch == '_') {
                *dst++ = ch;
            } else if (ch == '.' || ch == '\\' || ch == '(' || ch == ')'
                || ch == ';') {
                *dst++ = '\\';
                *dst++ = ch;
            } else {
                snprintf(dst, 5, "\\%03u", (unsigned int)ch);
                dst += 4;
            }
        }
        *dst++ = '.';
    }
    *dst = '\0';
    return;
}


/**
 * Log domain name.
 *
 */
void
dname_log(dname_type* dname, const char* pre, int level)
{
    char str[DNAME_MAXLEN*5];
    dname_str(dname, str);
    if (level == LOG_EMERG) {
        ods_fatal_exit("[%s] %s: %s",  logstr, pre?pre:"", str);
    } else if (level == LOG_ALERT) {
        ods_log_alert("[%s] %s: %s",   logstr, pre?pre:"", str);
    } else if (level == LOG_CRIT) {
        ods_log_crit("[%s] %s: %s",    logstr, pre?pre:"", str);
    } else if (level == LOG_ERR) {
        ods_log_error("[%s] %s: %s",   logstr, pre?pre:"", str);
    } else if (level == LOG_WARNING) {
        ods_log_warning("[%s] %s: %s", logstr, pre?pre:"", str);
    } else if (level == LOG_NOTICE) {
        ods_log_info("[%s] %s: %s",    logstr, pre?pre:"", str);
    } else if (level == LOG_INFO) {
        ods_log_verbose("[%s] %s: %s", logstr, pre?pre:"", str);
    } else if (level == LOG_DEBUG) {
        ods_log_debug("[%s] %s: %s",   logstr, pre?pre:"", str);
    } else if (level == LOG_DEEEBUG) {
        ods_log_deeebug("[%s] %s: %s", logstr, pre?pre:"", str);
    } else {
        ods_log_deeebug("[%s] %s: %s", logstr, pre?pre:"", str);
    }
    return;
}

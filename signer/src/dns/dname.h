/*
 * $Id: dname.h 6501 2012-08-06 10:52:03Z matthijs $
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

#ifndef DNS_DNAME_H
#define DNS_DNAME_H

#include "util/log.h"
#include "util/region.h"

#include <stdio.h>
#include <stdint.h>

#define DNAME_MAXLEN 255
#define LABEL_MAXLEN 63

/**
 * Domain name structure.
 *
 */
typedef struct dname_struct dname_type;
struct dname_struct {
    uint8_t size;
    uint8_t label_count;
    /*
    uint8_t label_offsets[label_count];
    uint8_t name[name_size];
    */
};

/**
 * Create new domain name.
 * @param r:           memory region.
 * @param str:         presentation format.
 * @return:            (dname_type*) created domain name.
 *
 */
dname_type* dname_create(region_type* r, const char* str);

/**
 * Clone domain name.
 * @param r:           memory region.
 * @param dname:       domain name.
 * @return:            (dname_type*) cloned domain name.
 *
 */
dname_type* dname_clone(region_type* r, const dname_type* dname);

/**
 * Parse ascii string to wireformat domain name (without compression ptrs).
 * @param wire: wireformat domain name.
 * @param str:  ascii string.
 * @return:     0 on error, length of wireformat domain name otherwise.
 *
 */
int dname_str2wire(uint8_t* wire, const char* name);

/**
 * Print domain name.
 * @param fd:    file descriptor.
 * @param dname: domain name.
 *
 */
void dname_print(FILE* fd, dname_type* dname);

/**
 * Is label normal (not a pointer or reserved)?
 *
 */
int label_is_normal(const uint8_t* label);

/**
 * Is label a pointer?
 *
 */
int label_is_pointer(const uint8_t* label);

/**
 * Is label the root label?
 *
 */
int label_is_root(const uint8_t* label);

/**
 * Length of label.
 *
 */
uint8_t label_length(const uint8_t* label);

/**
 * Get the next label.
 *
 */
const uint8_t* label_next(const uint8_t* label);

/**
 * The total size (in bytes) allocated to store dname.
 *
 */
size_t dname_total_size(const dname_type* dname);

/**
 * Offsets into dname for each label starting with the most significant label.
 *
 */
const uint8_t* dname_label_offsets(const dname_type* dname);

/**
 * The actual name in wire format (a sequence of label, each prefixed by a
 * length byte, terminated by a zero length label).
 *
 */
const uint8_t* dname_name(const dname_type *dname);

#endif /* DNS_DNAME_H */

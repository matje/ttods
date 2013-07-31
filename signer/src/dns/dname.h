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
 * Is label normal (not a pointer or reserved)?
 * @param label:       label.
 * @return:            (int) 1 if label is normal, 0 if a pointer or reserved.
 *
 */
int label_is_normal(const uint8_t* label);

/**
 * Is label a pointer?
 * @param label:       label.
 * @return:            (int) 1 if label is a pointer, 0 otherwise.
 *
 */
int label_is_pointer(const uint8_t* label);

/**
 * Is label the root label?
 * @param label:       label.
 * @return:            (int) 1 if label is a root label, 0 otherwise.
 *
 */
int label_is_root(const uint8_t* label);

/**
 * Length of label.
 * @param label:       label.
 * @return:            (uint8_t) label length.
 *
 */
uint8_t label_length(const uint8_t* label);

/**
 * Data of label.
 * @param label:       label.
 * @return:            (const uint8_t*) label data.
 *
 */
const uint8_t* label_data(const uint8_t* label);

/**
 * Get the next label.
 * @param label:       label.
 * @return:            (const uint8_t*) next label.
 *
 */
const uint8_t* label_next(const uint8_t* label);

/**
 * Compare labels.
 * @param label1:      one label.
 * @param label2:      another label.
 * @return:            0 if equal, <0 if label1 is smaller, >0 otherwise.
 *
 */
int label_compare(const uint8_t* label1, const uint8_t* label2);

/**
 * The total size (in bytes) allocated to store dname.
 * @param dname:       dname.
 * @return:            (size_t) total size in bytes of dname.
 *
 */
size_t dname_total_size(const dname_type* dname);

/**
 * Offsets into dname for each label starting with the most significant label.
 * @param dname:       dname.
 * @return:            (const uint8_t*) offsets.
 *
 */
const uint8_t* dname_label_offsets(const dname_type* dname);

/**
 * The actual name in wire format (a sequence of label, each prefixed by a
 * length byte, terminated by a zero length label).
 * @param dname:       dname.
 * @return:            (const uint8_t*) actual name in wire format.
 *
 */
const uint8_t* dname_name(const dname_type* dname);

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
 * Check if left domain name is sub domain of right domain name.
 * @param left:  possible sub domain.
 * @param right: possible top domain.
 *
 */
int dname_is_subdomain(const dname_type* left, const dname_type* right);

/**
 * Compare domain names.
 * @param dname1:      one domain name.
 * @param dname2:      another domain name.
 * @return:            0 if equal, <0 if dname1 is smaller, >0 otherwise.
 *
 */
int dname_compare(dname_type* dname1, dname_type* dname2);

/**
 * Return label of domain name.
 * @param dname:       domain name.
 * @param i:           label index.
 * @return:            (const uint8_t*) label.
 *
 */
const uint8_t* dname_label(const dname_type* dname, uint8_t index);

/**
 * Parse ascii string to wireformat domain name (without compression ptrs).
 * @param wire:        wireformat domain name.
 * @param str:         ascii string.
 * @return:            0 on error, length of wireformat domain name otherwise.
 *
 */
int dname_str2wire(uint8_t* wire, const char* name);

/**
 * Create domain name without most left label.
 * @param region: region.
 * @param dname:  domain name.
 * @return:       (dname_type*) domain name without most left label.
 *
 */
dname_type* dname_leftchop(region_type* region, dname_type* dname);

/**
 * Print domain name.
 * @param fd:          file descriptor.
 * @param dname:       domain name.
 *
 */
void dname_print(FILE* fd, dname_type* dname);

/**
 * Convert domain name to human readable format.
 * @param dname:       domain name.
 * @param buf:         human readable format of dname.
 *
 */
void dname_str(dname_type* dname, char* buf);

/**
 * Log domain name.
 * @param dname: domain name.
 * @param pre:   log message.
 * @param level: log level
 *
 */
void dname_log(dname_type* dname, const char* pre, int level);

#endif /* DNS_DNAME_H */

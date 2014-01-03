/*
 * $Id: region.h 6501 2012-08-06 10:52:03Z matthijs $
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
 * Region based memory allocator.
 *
 */

#ifndef UTIL_REGION_H
#define UTIL_REGION_H

#include <stdlib.h>

#define DEFAULT_INITIAL_CLEANUP 16

#ifdef ALIGNMENT
#  undef ALIGNMENT
#endif
/** increase size until it fits alignment of s bytes */
#define ALIGN_UP(x, s)     (((x) + s - 1) & (~(s - 1)))
/** what size to align on; make sure a char* fits in it. */
#define ALIGNMENT          (sizeof(uint64_t))

/** Default reasonable size for chunks */
#define REGION_CHUNK_SIZE         8192
/** Default size for large objects - allocated outside of chunks. */
#define REGION_LARGE_OBJECT_SIZE  2048

/**
 * Cleanup structure.
 *
 */
typedef struct cleanup_struct cleanup_type;
struct cleanup_struct {
    void *data;
};

/**
 * Recycle structure.
 *
 */
typedef struct recycle_struct recycle_type;
struct recycle_struct {
    struct recycle_struct* next;
};

/**
 * Region structure.
 *
 */
typedef struct region_struct region_type;
struct region_struct {
    char* next;
    char* data;
    char* large_list;
    size_t total_large;
    size_t chunk_size;
    size_t available;
    size_t small_objects;
    size_t large_objects;
    size_t chunk_count;
    /* clean up */
    size_t cleanup_max;
    size_t cleanup_count;
    cleanup_type* cleanups;
    /* recycle */
    recycle_type** recyclebin;
    size_t recyclebin_size;
};

/**
 * Create a new region.
 * @return: (region_type*) new region.
 *
 */
region_type* region_create(void);

/**
 * Create custom region.
 * @param size: size of region.
 * @return: (region_type*) new region.
 *
 */
region_type* region_create_custom(size_t size);

/**
 * Allocate size bytes of memory inside region.
 * The memory is deallocated when region_free is called for this region.
 * @param r:    memory region.
 * @param size: number of bytes.
 * @return:     (void*) pointer to memory allocated.
 *
 */
void* region_alloc(region_type* r, size_t size);

/**
 * Allocate size bytes of memory inside region and copy init into it.
 * The memory is deallocated when region_free is called for this region.
 * @param r:    memory region.
 * @param size: number of bytes.
 * @return:     (void*) pointer to memory allocated.
 *
 */
void* region_alloc_init(region_type* r, const void* init, size_t size);

/**
 * Allocate size bytes of memory inside region that are initialized to zero.
 * The memory is deallocated when region_free is called for this region.
 * @param r:    memory region.
 * @param size: number of bytes.
 * @return:     (void*) pointer to memory allocated.
 *
 */
void* region_alloc_zero(region_type* r, size_t size);

/**
 * Duplicate string and allocate the result in region.
 * @param r:      memory region.
 * @param string: null terminated string.
 * @return:       pointer to memory allocated.
 *
 */
char* region_strdup(region_type* r, const char* str);

/**
 * Recycle allocated data.
 * Free data in region and place block in recycle bin for future allocations.
 * @param r:      memory region.
 * @param block:  data block to recycle.
 * @param size:   size of data block.
 *
 */
void region_recycle(region_type* r, void* block, size_t size);

/**
 * Log region stats.
 * @param r:   memory region.
 * @param str: region identifier.
 *
 */
void region_log(region_type* r, const char* str);

/**
 * Get total memory size in use by region.
 * @param r: memory region.
 * @return:  (size_t) total memory size.
 *
 */
size_t region_size(region_type* r);

/**
 * Free all memory associated with region.
 * @param r: memory region.
 *
 */
void region_free(region_type* r);

/**
 * Clean up region.
 * @param r: memory region.
 *
 */
void region_cleanup(region_type* r);

#endif /* UTIL_REGION_H */

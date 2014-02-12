/*
 * $Id: region.c 6747 2012-10-19 10:32:45Z matthijs $
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

#include "config.h"
#include "util/log.h"
#include "util/region.h"

#include <stdint.h>
#include <string.h>

static const char* logstr = "region";


/**
 * Initialize region.
 *
 */
static void
region_init(region_type* r)
{
    size_t a = ALIGN_UP(sizeof(region_type), ALIGNMENT);
    r->next = NULL;
    r->data = (char*)r + a;
    r->available = r->chunk_size - a;
    r->large_list = NULL;
    r->total_large = 0;
    r->small_objects = 0;
    r->large_objects = 0;
    r->chunk_count = 1;
    r->cleanup_count = 0;
    r->cleanup_max = DEFAULT_INITIAL_CLEANUP;
    r->cleanups = (cleanup_type*) calloc(r->cleanup_max,
        sizeof(cleanup_type));
    return;
}


/**
 * Create custom region.
 *
 */
region_type*
region_create_custom(size_t size)
{
    region_type* r = (region_type*) malloc(size);
    ods_log_assert(sizeof(region_type) <= size);
    if (!r) {
        ods_log_crit("[%s] malloc failed: insufficient memory", logstr);
        return NULL;
    }
    r->chunk_size = size;
    region_init(r);
    if (!r->cleanups) {
        ods_log_crit("[%s] calloc failed: insufficient memory", logstr);
        region_cleanup(r);
        return NULL;
    }
    r->recyclebin_size = 0;
    r->recyclebin = malloc(sizeof(recycle_type*) *
        (REGION_LARGE_OBJECT_SIZE / ALIGNMENT) );
    if (!r->recyclebin) {
        ods_log_crit("[%s] calloc failed: insufficient memory", logstr);
        region_cleanup(r);
        return NULL;
    }
    memset(r->recyclebin, 0, sizeof(recycle_type*) *
        (REGION_LARGE_OBJECT_SIZE / ALIGNMENT) );
    return r;
}


/**
 * Create region.
 *
 */
region_type*
region_create(void)
{
    return region_create_custom(REGION_CHUNK_SIZE);
}


/**
 * Add cleanup.
 *
 */
static int
region_add_cleanup(region_type* r, void* data)
{
    ods_log_assert(r);
    ods_log_assert(data);
    if (r->cleanup_count >= r->cleanup_max) {
        cleanup_type* cleanups = (cleanup_type*) calloc(r->cleanup_max * 2,
            sizeof(cleanup_type));
        if (!cleanups) {
            ods_log_crit("[%s] calloc failed: insufficient memory", logstr);
            return 0;
        }
        memmove(cleanups, r->cleanups, r->cleanup_count * sizeof(cleanup_type));
        free(r->cleanups);
        r->cleanups = cleanups;
        r->cleanup_max *= 2;
    }
    r->cleanups[r->cleanup_count].data = data;
    ++r->cleanup_count;
    return 1;
}


/**
 * Allocate size bytes of memory inside region.
 *
 */
void*
region_alloc(region_type* r, size_t size)
{
    size_t a = ALIGN_UP(size, ALIGNMENT);
    size_t ra = a/ALIGNMENT;
    void* s;
    /* large objects */
    if (a >= REGION_LARGE_OBJECT_SIZE) {
        s = malloc(ALIGNMENT+size);
        if (!s) {
            ods_log_crit("[%s] malloc failed: insufficient memory", logstr);
            return NULL;
        }
        /* add cleanup */
        if (!region_add_cleanup(r, s)) {
            ods_log_crit("[%s] add cleanup failed", logstr);
            free(s);
            return NULL;
        }
        /* region management */
        r->total_large += ALIGNMENT+size;
        *(char**)s = r->large_list;
        r->large_list = (char*)s;
        ++r->large_objects;
        return (char*)s+ALIGNMENT;
    }
    /* can we recycle? */
    if (r->recyclebin && r->recyclebin[ra]) {
        s = (void*) r->recyclebin[ra];
        r->recyclebin[ra] = r->recyclebin[ra]->next;
        r->recyclebin_size -= a;
    }
    /* do we need a new chunk? */
    if (a > r->available) {
        s = malloc(REGION_CHUNK_SIZE);
        if (!s) {
            ods_log_crit("[%s] malloc failed: insufficient memory", logstr);
            return NULL;
        }
        ++r->chunk_count;
        *(char**)s = r->next;
        r->next = (char*)s;
        r->data = (char*)s + ALIGNMENT;
        r->available = REGION_CHUNK_SIZE - ALIGNMENT;
    }
    /* put in this chunk */
    r->available -= a;
    ++r->small_objects;
    s = r->data;
    r->data += a;
    return s;
}


/**
 * Allocate size bytes of memory inside region and copy init into it.
 *
 */
void*
region_alloc_init(region_type* r, const void* init, size_t size)
{
    void* s = region_alloc(r, size);
    if (!s) {
        return NULL;
    }
    memmove(s, init, size);
    return s;
}


/**
 * Allocate size bytes of memory inside region that are initialized to zero.
 *
 */
void*
region_alloc_zero(region_type* r, size_t size)
{
    void *s = region_alloc(r, size);
    if (!s) {
        return NULL;
    }
    memset(s, 0, size);
    return s;
}


/**
 * Duplicate string and allocate the result in region.
 *
 */
char*
region_strdup(region_type* r, const char* str)
{
    return (char*)region_alloc_init(r, str, strlen(str)+1);
}


/**
 * Recycle allocated data.
 * Free data in region and place block in recycle bin for future allocations.
 *
 */
void region_recycle(region_type* r, void* block, size_t size)
{
    size_t a = ALIGN_UP(size, ALIGNMENT);
    size_t ra = a/ALIGNMENT;
    size_t i;
    if (!r || !r->recyclebin || !block || size == 0) {
        return;
    }
    if (a >= REGION_LARGE_OBJECT_SIZE) {
        r->total_large -= (size+ALIGNMENT);
        --r->large_objects;
        for (i=0; i < r->cleanup_count; i++) {
            while (r->cleanups[i].data == block) {
                /* perform action (deallocator) on block */
                free(r->cleanups[i].data);
                /* move last entry here */
                --r->cleanup_count;
                r->cleanups[i].data =
                    r->cleanups[r->cleanup_count].data;
            }
        }
    } else {
        recycle_type* recycled = (recycle_type*) block;
        ods_log_assert(a >= sizeof(recycle_type));
        /* make sure the same ptr is not freed twice. */
        if (1) {
            recycle_type* p = r->recyclebin[ra];
            while (p) {
                ods_log_assert(p != recycled);
                p = p->next;
            }
        }
        recycled->next = r->recyclebin[ra];
        r->recyclebin[ra] = recycled;
        r->recyclebin_size += a;
    }
    return;
}


/**
 * Count the number of chunks in use.
 *
 */
static size_t
count_chunks(region_type* r)
{
    size_t c = 1;
    char* p = r->next;
    while (p) {
        c++;
        p = *(char**)p;
    }
    return c;
}


/**
 * Count the number of large objects.
 *
 */
static size_t
count_large(region_type* r)
{
    size_t c = 0;
    char* p = r->large_list;
    while (p) {
        c++;
        p = *(char**)p;
    }
    return c;
}


/**
 * Cleanup size of region.
 *
 */
static size_t
region_cleanup_size(region_type* r)
{
    return (r->cleanup_max * sizeof(cleanup_type));
}


/**
 * Log region stats.
 *
 */
void
region_log(region_type* r, const char* str)
{
    size_t chunks = 0;
    size_t large = 0;
    if (!r) {
        return;
    }
    ods_log_assert(ALIGNMENT >= sizeof(char*));
    ods_log_assert(REGION_CHUNK_SIZE > ALIGNMENT);
    ods_log_assert(REGION_CHUNK_SIZE-ALIGNMENT > REGION_LARGE_OBJECT_SIZE);
    ods_log_assert(REGION_CHUNK_SIZE >= sizeof(region_type));
    chunks = count_chunks(r);
    large = count_large(r);
    ods_log_info("[%s] %s: small %lu, chunks %lu, large %lu, cleanup %lu "
        "recycle %lu, size %u", logstr, str?str:"-",
        r->small_objects,
        r->chunk_count,
        r->large_objects,
        region_cleanup_size(r),
        r->recyclebin_size,
        (unsigned) region_size(r));
    if (chunks != r->chunk_count) {
        ods_log_warning("[%s] %s: chunk count mismatch (%lu vs. %lu)", logstr,
            str?str:"-", chunks, r->chunk_count);
    }
    if (large != r->large_objects) {
        ods_log_warning("[%s] %s: large object count mismatch (%lu vs. %lu)",
            logstr, str?str:"-", large, r->large_objects);
    }
    return;
}


/**
 * Get total memory size in use by region.
 *
 */
size_t
region_size(region_type* r)
{
    if (!r) {
        return 0;
    }
    return (
        count_chunks(r)) * REGION_CHUNK_SIZE +
        r->total_large +
        region_cleanup_size(r) +
        (sizeof(recycle_type*) * (REGION_LARGE_OBJECT_SIZE / ALIGNMENT)
    );
}


/**
 * Free all memory associated with region.
 *
 */
void
region_free(region_type* r)
{
    char* p = r->next, *np;
    while (p) {
        np = *(char**)p;
        free(p);
        p = np;
    }
    p = r->large_list;
    while (p) {
        np = *(char**)p;
        free(p);
        p = np;
    }
    free(r->cleanups);
    free(r->recyclebin);
    region_init(r);
    return;
}


/**
 * Clean up region.
 *
 */
void
region_cleanup(region_type* r)
{
    if (!r) {
        return;
    }
    region_free(r);
    free(r);
    return;
}

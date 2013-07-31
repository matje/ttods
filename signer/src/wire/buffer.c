/*
 * $Id: buffer.c 4958 2011-04-18 07:11:09Z matthijs $
 *
 * Copyright (c) 2011 NLNet Labs. All rights reserved.
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
 * Packet buffer.
 *
 *                                    1  1  1  1  1  1
 *      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 01 |                      ID                       |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 23 |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 45 |                    QDCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 67 |                    ANCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 89 |                    NSCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 01 |                    ARCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */


#include "config.h"
#include "util/log.h"
#include "util/str.h"
#include "wire/buffer.h"

#include <string.h>

static const char* logstr = "buffer";


/**
 * Create a new buffer with the specified capacity.
 *
 */
buffer_type*
buffer_create(region_type* r, size_t capacity)
{
    buffer_type* buffer = NULL;
    if (!r || !capacity) {
        ods_log_error("[%s] create buffer requires region and capacity",
            logstr);
        return NULL;
    }
    buffer = (buffer_type*) region_alloc(r, sizeof(buffer_type));
    buffer->data = (uint8_t*) region_alloc(r, capacity * sizeof(uint8_t));
    buffer->position = 0;
    buffer->limit = capacity;
    buffer->capacity = capacity;
    buffer->fixed = 0;
    return buffer;
}


/**
 * Create a buffer with the specified data.
 *
 */
void
buffer_create_from(buffer_type* buffer, void* data, size_t size)
{
    ods_log_assert(buffer);
    buffer->data = (uint8_t*) data;
    buffer->position = 0;
    buffer->limit = size;
    buffer->capacity = size;
    buffer->fixed = 1;
    return;
}


/**
 * Clear the buffer and make it ready for writing.
 *
 */
void
buffer_clear(buffer_type* buffer)
{
    ods_log_assert(buffer);
    buffer->position = 0;
    buffer->limit = buffer->capacity;
    return;
}


/**
 * Flip the buffer and make it ready for reading.
 *
 */
void
buffer_flip(buffer_type* buffer)
{
    ods_log_assert(buffer);
    buffer->limit = buffer->position;
    buffer->position = 0;
    return;
}


/**
 * Make the buffer ready for re-reading the data.
 *
 */
void
buffer_rewind(buffer_type* buffer)
{
    ods_log_assert(buffer);
    buffer->position = 0;
    return;
}


/**
 * Get the buffer's position.
 *
 */
size_t
buffer_position(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer->position;
}


/**
 * Set the buffer's position.
 *
 */
void
buffer_set_position(buffer_type* buffer, size_t pos)
{
    ods_log_assert(buffer);
    ods_log_assert(pos <= buffer->limit);
    buffer->position = pos;
    return;
}


/**
 * Change the buffer's position.
 *
 */
void
buffer_skip(buffer_type* buffer, ssize_t count)
{
    ods_log_assert(buffer);
    ods_log_assert(buffer->position + count <= buffer->limit);
    buffer->position += count;
    return;
}


/**
 * Get bit.
 *
 */
static int
get_bit(uint8_t bits[], size_t index)
{
    return bits[index / 8] & (1 << (7 - index % 8));
}


/**
 * Set bit.
 *
 */
static void
set_bit(uint8_t bits[], size_t index)
{
    bits[index / 8] |= (1 << (7 - index % 8));
    return;
}


/**
 * Is pointer label>
 *
 */
static int
label_is_pointer(const uint8_t* label)
{
    ods_log_assert(label);
    return (label[0] & 0xc0) == 0xc0;
}


/**
 * Pointer label location.
 *
 */
static uint16_t
label_pointer_location(const uint8_t* label)
{
    ods_log_assert(label);
    ods_log_assert(label_is_pointer(label));
    return ((uint16_t) (label[0] & ~0xc0) << 8) | (uint16_t) label[1];
}


/**
 * Is normal label?
 *
 */
static int
label_is_normal(const uint8_t* label)
{
    ods_log_assert(label);
    return (label[0] & 0xc0) == 0;
}

/*
 * Is root label?
 *
 */
static inline int
label_is_root(const uint8_t* label)
{
    ods_log_assert(label);
    return label[0] == 0;
}


/*
 * Label length.
 *
 */
static uint8_t
label_length(const uint8_t* label)
{
    ods_log_assert(label);
    ods_log_assert(label_is_normal(label));
    return label[0];
}


/**
 * Read dname from buffer.
 *
 */
size_t
buffer_read_dname(buffer_type* buffer, uint8_t* dname, unsigned allow_pointers)
{
    int done = 0;
    uint8_t visited[(MAX_PACKET_SIZE+7)/8];
    size_t dname_length = 0;
    const uint8_t *label = NULL;
    ssize_t mark = -1;
    ods_log_assert(buffer);
    memset(visited, 0, (buffer_limit(buffer)+7)/8);

    while (!done) {
        if (!buffer_available(buffer, 1)) {
            return 0;
        }
        if (get_bit(visited, buffer_position(buffer))) {
            ods_log_error("[%s] dname loop!", logstr);
            return 0;
        }
        set_bit(visited, buffer_position(buffer));
        label = buffer_current(buffer);
        if (label_is_pointer(label)) {
            size_t pointer = 0;
            if (!allow_pointers) {
                return 0;
            }
            if (!buffer_available(buffer, 2)) {
                return 0;
            }
            pointer = label_pointer_location(label);
            if (pointer >= buffer_limit(buffer)) {
                return 0;
            }
            buffer_skip(buffer, 2);
            if (mark == -1) {
                mark = buffer_position(buffer);
            }
            buffer_set_position(buffer, pointer);
        } else if (label_is_normal(label)) {
            size_t length = label_length(label) + 1;
            done = label_is_root(label);
            if (!buffer_available(buffer, length)) {
                return 0;
            }
            if (dname_length + length >= MAXDOMAINLEN+1) {
                return 0;
            }
            buffer_read(buffer, dname + dname_length, length);
            dname_length += length;
        } else {
            return 0;
        }
     }
     if (mark != -1) {
        buffer_set_position(buffer, mark);
     }
     return dname_length;
}


/**
 * Change the buffer's position so that one dname is skipped.
 *
 */
int
buffer_skip_dname(buffer_type* buffer)
{
    ods_log_assert(buffer);
    while (1) {
        uint8_t label_size = 0;
        if (!buffer_available(buffer, 1)) {
            return 0;
        }
        label_size = buffer_read_u8(buffer);
        if (label_size == 0) {
            break;
        } else if ((label_size & 0xc0) != 0) {
            if (!buffer_available(buffer, 1)) {
                return 0;
            }
            buffer_skip(buffer, 1);
            break;
        } else if (!buffer_available(buffer, label_size)) {
            return 0;
        } else {
            buffer_skip(buffer, label_size);
        }
    }
    return 1;
}


/**
 * Change the buffer's position so that one RR is skipped.
 *
 */
int
buffer_skip_rr(buffer_type* buffer, unsigned qrr)
{
    if (!buffer_skip_dname(buffer)) {
        return 0;
    }
    if (qrr) {
        if (!buffer_available(buffer, 4)) {
            return 0;
        }
        buffer_skip(buffer, 4);
    } else {
        uint16_t rdata_size;
        if (!buffer_available(buffer, 10)) {
            return 0;
        }
        buffer_skip(buffer, 8);
        rdata_size = buffer_read_u16(buffer);
        if (!buffer_available(buffer, rdata_size)) {
            return 0;
        }
        buffer_skip(buffer, rdata_size);
    }
    return 1;
}


/**
 * Get the buffer's limit.
 *
 */
size_t
buffer_limit(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer->limit;
}


/**
 * Set the buffer's limit.
 *
 */
void
buffer_set_limit(buffer_type* buffer, size_t limit)
{
    ods_log_assert(buffer);
    ods_log_assert(limit <= buffer->capacity);
    buffer->limit = limit;
    if (buffer->position > buffer->limit) {
        buffer->position = buffer->limit;
    }
    return;
}


/**
 * Get the buffer's capacity.
 *
 */
size_t
buffer_capacity(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer->capacity;
}


/**
 * Return a pointer to the data at the indicated position.
 *
 */
uint8_t*
buffer_at(buffer_type* buffer, size_t at)
{
    ods_log_assert(buffer);
    ods_log_assert(at <= buffer->limit);
    return buffer->data + at;
}


/**
 * Return a pointer to the data at the beginning of the buffer.
 *
 */
uint8_t*
buffer_begin(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_at(buffer, 0);
}


/**
 * Return a pointer to the data at the end of the buffer.
 *
 */
uint8_t*
buffer_end(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_at(buffer, buffer->limit);
}


/**
 * Return a pointer to the data at the buffer's current position.
 *
 */
uint8_t*
buffer_current(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_at(buffer, buffer->position);
}


/**
 * The number of bytes remaining between the at and limit.
 *
 */
static size_t
buffer_remaining_at(buffer_type* buffer, size_t at)
{
    ods_log_assert(buffer);
    ods_log_assert(at <= buffer->limit);
    return buffer->limit - at;
}


/**
 * The number of bytes remaining between the buffer's position and limit.
 *
 */
size_t
buffer_remaining(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_remaining_at(buffer, buffer->position);
}


/**
 * Check if the buffer has enough bytes available at indicated position.
 *
 */
static int
buffer_available_at(buffer_type *buffer, size_t at, size_t count)
{
    ods_log_assert(buffer);
    return count <= buffer_remaining_at(buffer, at);
}


/**
 * Check if the buffer has enough bytes available.
 *
 */
int
buffer_available(buffer_type *buffer, size_t count)
{
    ods_log_assert(buffer);
    return buffer_available_at(buffer, buffer->position, count);
}


/**
 * Write to buffer at indicated position.
 *
 */
static void
buffer_write_u8_at(buffer_type* buffer, size_t at, uint8_t data)
{
    ods_log_assert(buffer);
    ods_log_assert(buffer_available_at(buffer, at, sizeof(data)));
    buffer->data[at] = data;
    return;
}


/**
 * Write to buffer at indicated position.
 *
 */
void
buffer_write_u16_at(buffer_type* buffer, size_t at, uint16_t data)
{
    ods_log_assert(buffer);
    ods_log_assert(buffer_available_at(buffer, at, sizeof(data)));
    write_uint16(buffer->data + at, data);
    return;
}


/**
 * Write to buffer at indicated position.
 *
 */
static void
buffer_write_u32_at(buffer_type* buffer, size_t at, uint32_t data)
{
    ods_log_assert(buffer);
    ods_log_assert(buffer_available_at(buffer, at, sizeof(data)));
    write_uint32(buffer->data + at, data);
    return;
}


/**
 * Write to buffer.
 *
 */
void
buffer_write(buffer_type* buffer, const void* data, size_t count)
{
    ods_log_assert(buffer);
    ods_log_assert(buffer_available(buffer, count));
    memcpy(buffer->data + buffer->position, data, count);
    buffer->position += count;
    return;
}


/**
 * Write uint8_t to buffer.
 *
 */
void
buffer_write_u8(buffer_type* buffer, uint8_t data)
{
    ods_log_assert(buffer);
    buffer_write_u8_at(buffer, buffer->position, data);
    buffer->position += sizeof(data);
    return;
}


/**
 * Write uint16_t to buffer.
 *
 */
void
buffer_write_u16(buffer_type* buffer, uint16_t data)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, buffer->position, data);
    buffer->position += sizeof(data);
    return;
}


/**
 * Write uint32_t to buffer.
 *
 */
void
buffer_write_u32(buffer_type* buffer, uint32_t data)
{
    ods_log_assert(buffer);
    buffer_write_u32_at(buffer, buffer->position, data);
    buffer->position += sizeof(data);
    return;
}


/**
 * Read uint8_t from buffer at indicated position.
 *
 */
static uint8_t
buffer_read_u8_at(buffer_type* buffer, size_t at)
{
    ods_log_assert(buffer);
    ods_log_assert(at < buffer->capacity);
    return buffer->data[at];

}


/**
 * Read uint16_t from buffer at indicated position.
 *
 */
static uint16_t
buffer_read_u16_at(buffer_type* buffer, size_t at)
{
    ods_log_assert(buffer);
    return read_uint16(buffer->data + at);
}


/**
 * Read uint32_t from buffer at indicated position.
 *
 */
static uint32_t
buffer_read_u32_at(buffer_type* buffer, size_t at)
{
    ods_log_assert(buffer);
    return read_uint32(buffer->data + at);
}


/**
 * Read from buffer.
 *
 */
void
buffer_read(buffer_type* buffer, void* data, size_t count)
{
    ods_log_assert(buffer);
    ods_log_assert(buffer_available(buffer, count));
    memcpy(data, buffer->data + buffer->position, count);
    buffer->position += count;
    return;
}


/**
 * Read uint8_t from buffer.
 *
 */
uint8_t
buffer_read_u8(buffer_type* buffer)
{
    uint16_t result = 0;
    ods_log_assert(buffer);
    result = buffer_read_u8_at(buffer, buffer->position);
    buffer->position += sizeof(uint8_t);
    return result;
}


/**
 * Read uint16_t from buffer.
 *
 */
uint16_t
buffer_read_u16(buffer_type* buffer)
{
    uint16_t result = 0;
    ods_log_assert(buffer);
    result = buffer_read_u16_at(buffer, buffer->position);
    buffer->position += sizeof(uint16_t);
    return result;
}


/**
 * Read uint32_t from buffer.
 *
 */
uint32_t
buffer_read_u32(buffer_type* buffer)
{
    uint32_t result = 0;
    ods_log_assert(buffer);
    result = buffer_read_u32_at(buffer, buffer->position);
    buffer->position += sizeof(uint32_t);
    return result;
}


/**
 * Get query id from buffer.
 *
 */
uint16_t
buffer_pkt_id(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_read_u16_at(buffer, 0);
}

/**
 * Get a random query id.
 *
 */
static uint16_t
random_id(void)
{
    return ldns_get_random();
}

/**
 * Set random query id in buffer.
 *
 */
void
buffer_pkt_set_random_id(buffer_type* buffer)
{
    uint16_t qid = 0;
    ods_log_assert(buffer);
    qid = random_id();
    buffer_write_u16_at(buffer, 0, qid);
    return;
}


/**
 * Get flags from buffer.
 *
 */
uint16_t
buffer_pkt_flags(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (uint16_t) buffer_read_u16_at(buffer, 2);
}


/**
 * Set flags in buffer.
 *
 */
void
buffer_pkt_set_flags(buffer_type* buffer, uint16_t flags)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, 2, flags);
    return;
}


/**
 * Get QR bit from buffer.
 *
 */
int
buffer_pkt_qr(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) QR(buffer);
}


/**
 * Set QR bit in buffer.
 *
 */
void
buffer_pkt_set_qr(buffer_type* buffer)
{
    ods_log_assert(buffer);
    QR_SET(buffer);
    return;
}


/**
 * Clear QR bit in buffer.
 *
 */
void
buffer_pkt_clear_qr(buffer_type* buffer)
{
    ods_log_assert(buffer);
    QR_CLR(buffer);
    return;
}


/**
 * Get AA bit from buffer.
 *
 */
int
buffer_pkt_aa(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) AA(buffer);
}


/**
 * Set AA bit in buffer.
 *
 */
void
buffer_pkt_set_aa(buffer_type* buffer)
{
    ods_log_assert(buffer);
    AA_SET(buffer);
    return;
}


/**
 * Get TC bit from buffer.
 *
 */
int
buffer_pkt_tc(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) TC(buffer);
}


/**
 * Get RD bit from buffer.
 *
 */
int
buffer_pkt_rd(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) RD(buffer);
}


/**
 * Get RA bit from buffer.
 *
 */
int
buffer_pkt_ra(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) RA(buffer);
}


/**
 * Get AD bit from buffer.
 *
 */
int
buffer_pkt_ad(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) AD(buffer);
}


/**
 * Get CD bit from buffer.
 *
 */
int
buffer_pkt_cd(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) CD(buffer);
}


/**
 * Get QDCOUNT from buffer.
 *
 */
uint16_t
buffer_pkt_qdcount(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_read_u16_at(buffer, 4);
}


/**
 * Set QDCOUNT in buffer.
 *
 */
void
buffer_pkt_set_qdcount(buffer_type* buffer, uint16_t count)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, 4, count);
    return;
}


/**
 * Get ANCOUNT from buffer.
 *
 */
uint16_t
buffer_pkt_ancount(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_read_u16_at(buffer, 6);
}


/**
 * Set ANCOUNT in buffer.
 *
 */
void
buffer_pkt_set_ancount(buffer_type* buffer, uint16_t count)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, 6, count);
    return;
}


/**
 * Get NSCOUNT from buffer.
 *
 */
uint16_t
buffer_pkt_nscount(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_read_u16_at(buffer, 8);
}


/**
 * Set NSCOUNT in buffer.
 *
 */
void
buffer_pkt_set_nscount(buffer_type* buffer, uint16_t count)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, 8, count);
    return;
}


/**
 * Get ARCOUNT from buffer.
 *
 */
uint16_t
buffer_pkt_arcount(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_read_u16_at(buffer, 10);
}


/**
 * Set ARCOUNT in buffer.
 *
 */
void
buffer_pkt_set_arcount(buffer_type* buffer, uint16_t count)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, 10, count);
    return;
}


/**
 * Returns the next character from a buffer. Advances the position pointer
 * with 1. When end of buffer is reached, EOF is returned. This is the
 * buffer's equivalent for getc().
 *
 */
static int
buffer_getc(buffer_type* buffer)
{
    if (!buffer_available_at(buffer, buffer->position, sizeof(uint8_t))) {
        buffer_set_position(buffer, buffer_limit(buffer));
        return EOF;
    }
    return (int) buffer_read_u8(buffer);
}


/**
 * Skips all of the characters in the given string in the buffer, moving
 * the position to the first character that is not in s.
 *
 */
static void
buffer_skipcs(buffer_type* buffer, const char* s)
{
   int found;
   char c;
   const char* d;
   ods_log_assert(buffer);
   ods_log_assert(s);
   while (buffer_available_at(buffer, buffer->position, sizeof(char))) {
       c = (char) buffer_read_u8_at(buffer, buffer->position);
       found = 0;
       for (d = s; *d; d++) {
           if (*d == c) {
               found = 1;
           }
        }
        if (found && buffer->limit > buffer->position) {
            buffer->position += sizeof(char);
        } else {
            return;
        }
    }
    return;
}


/**
 * Get token from buffer.
 *
 */
int
buffer_get_token(buffer_type* buffer, char* token, const char* delim,
    size_t limit)
{
    int c = 0, lc = 0, p = 0, com = 0, quoted = 0;
    size_t i = 0;
    char* t;
    const char* d;
    ods_log_assert(buffer);
    ods_log_assert(token);
    ods_log_assert(delim);
    ods_log_assert(limit);
    t = token;
    if (delim[0] == '"') {
        quoted = 1;
    }
    while ((c = buffer_getc(buffer)) != EOF) {
        if (c == '\r') {
            /* carriage return */
            c = ' ';
        }
        if (c == '(' && lc != '\\' && !quoted) {
            /* this only counts for non-comments */
            if (com == 0) {
                p++;
            }
            lc = c;
            continue;
        }
        /* do something with parentheses */
        if (c == ')' && lc != '\\' && !quoted) {
            /* this only counts for non-comments */
            if (com == 0) {
                p--;
            }
            lc = c;
            continue;
        }
        if (p < 0) {
            /* more ) then ( */
            *t = '\0';
            return -1;
        }
        /* do something with comments (;) */
        if (c == ';' && quoted == 0) {
            if (lc != '\\') {
                com = 1;
            }
        }
        if (c == '\n' && com != 0) {
            /* comments */
            com = 0;
            *t = ' ';
            lc = c;
            continue;
        }
        if (com == 1) {
            *t = ' ';
            lc = c;
            continue;
        }
        if (c == '\n' && p != 0) {
            /* in parentheses */
            *t++ = ' ';
            lc = c;
            continue;
        }
        /* do something with quotes (") */
        if (c == '"' && com == 0 && lc != '\\') {
            quoted = 1 - quoted;
        }
        /* check if we hit the delim */
        for (d = delim; *d; d++) {
            if (c == *d && lc != '\\' && p == 0) {
                buffer_skipcs(buffer, delim);
                goto buffer_get_token_done;
            }
        }
        i++;
        if (limit > 0 && i >= limit) {
            *t = '\0';
            return -1;
        }
        *t++ = c;
        if (c == '\\' && lc == '\\') {
            lc = 0;
        } else {
            lc = c;
        }
    }

buffer_get_token_done:
    *t = '\0';
    if (p != 0) {
        /* parentheses mismatch */
        return -1;
    }
    return (ssize_t)i;
}


/**
 * Clean up buffer.
 *
 */
void
buffer_cleanup(buffer_type* ATTR_UNUSED(buffer))
{
    return;
}



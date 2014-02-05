/*
 * $Id: b64.c 7057 2013-02-26 09:30:10Z matthijs $
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
 * Base64 Data Encoding.
 *
 */

#include "compat/b64.h"
#include "util/log.h"

#include <ctype.h>
#include <stdlib.h>

static const char b64pad = '=';
static const char numb64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const uint8_t b64num[] = {
    ['A'] =  0, ['B'] =  1, ['C'] =  2, ['D'] =  3,
    ['E'] =  4, ['F'] =  5, ['G'] =  6, ['H'] =  7,
    ['I'] =  8, ['J'] =  9, ['K'] = 10, ['L'] = 11,
    ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15,
    ['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19,
    ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
    ['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27,
    ['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31,
    ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35,
    ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39,
    ['o'] = 40, ['p'] = 41, ['q'] = 42, ['r'] = 43,
    ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
    ['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51,
    ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55,
    ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
    ['8'] = 60, ['9'] = 61, ['+'] = 62, ['/'] = 63,
};

/**
 * Encode to base64.
 *
 */
int
b64_pton(char const* src, uint8_t* target, size_t targetsize)
{
    /**
     * src:    00AAAAAA 00BBBBBB 00CCCCCC 00DDDDDD
     * target: AAAAAABB BBBBCCCC CCDDDDDD
     */

    /**
     * target[0] = ((src[0] & 0x3f) << 2) + ((src[1] & 0x30) >> 4);
     * target[1] = ((src[1] & 0x0f) << 4) + ((src[2] & 0x3c) >> 2);
     * target[2] = ((src[2] & 0x03) << 6) + ((src[3] & 0x3f) >> 0);
     */

    uint8_t* start = target;
    size_t target_bytes = 0;
    int src_index = 0;
    int ch;

    while (*src) {
        ch = *src;
        if (ch == b64pad) {
            /* padding means we are done */
            break;
        } else if (isspace(ch)) {
            /* ignore whitespace */
            src++;
            continue;
        }
        /* else assert(isbase64(ch)) */

        switch (src_index) {
            case 0:
                target_bytes += 3;
                if (target_bytes >= targetsize) {
                    return -1;
                }
                *target = ((b64num[*src] & 0x3f) << 2);
                break;
            case 1:
                *(target++) |= ((b64num[*src] & 0x30) >> 4);
                *target = ((b64num[*src] & 0x0f) << 4);
                break;
            case 2:
                *(target++) |= ((b64num[*src] & 0x3c) >> 2);
                *target = ((b64num[*src] & 0x03) << 6);
                break;
            case 3:
                *(target++) |= (b64num[*src] & 0x3f);
                break;
            default:
                return -2;
                break;
        }
        src++;
        src_index = (src_index+1) % 4;
    }

    if (ch == b64pad) {
        switch (src_index) {
            case 0:
            case 1:
                return -3; /* invalid position for padding */
            case 2:
                ch = *src++;
                while (isspace(ch)) {
                    ch = *src++;
                }
                if (ch != b64pad) {
                    return -4;
                }
            case 3:
                ch = *src++;
                while (isspace(ch)) {
                    ch = *src++;
                }
                if (*target != 0) {
                    return -5;
                }
                break;
            default:
                return -6;
                break;
        }
    } else if (src_index != 0) {
        return -7;
    }
    target_bytes = target - start;
    return target_bytes;
}


/**
 * Decode from base64.
 *
 */
int
b64_ntop(uint8_t const* src, size_t srcsize, char* target,
     size_t targetsize)
{
    /**
     * src:    AAAAAABB BBBBCCCC CCDDDDDD
     * target: 00AAAAAA 00BBBBBB 00CCCCCC 00DDDDDD
     */

    /**
     * target[0] = ((src[0] & 0xfc) >> 2);
     * target[1] = ((src[0] & 0x03) << 4) + ((src[1] & 0xf0) >> 4);
     * target[2] = ((src[1] & 0x0f) << 2) + ((src[2] & 0xc0 >> 6);
     * target[3] = ((src[2] & 0x3f) << 0);
     */

    size_t target_bytes = 0;
    int src_index = 0;
    uint8_t output;

    while (srcsize) {
        switch (src_index) {
            case 0:
                target_bytes += 4;
                if (target_bytes > targetsize) {
                    return -1;
                }
                output = (*src & 0xfc) >> 2;
                ods_log_assert(output < 64);
                *target = numb64[output];
                ++target;

                output = (*src & 0x03) << 4;
                break;
            case 1:
                output += (*src & 0xf0) >> 4;
                ods_log_assert(output < 64);
                *target = numb64[output];
                ++target;

                output = (*src & 0x0f) << 2;
                break;
            case 2:
                output += (*src & 0xc0) >> 6;
                ods_log_assert(output < 64);
                *target = numb64[output];
                ++target;

                output = (*src & 0x3f);
                ods_log_assert(output < 64);
                *target = numb64[output];
                ++target;
                break;
            default:
                return -2;
                break;
        }
        src_index = (src_index+1) % 3;
        srcsize--;
        src++;
    }

    if (src_index != 0) {
        switch (src_index) {
            case 0:
                return -3;
                break;
            case 1:
                ods_log_assert(output < 64);
                *target = numb64[output];
                ++target;

                *target = b64pad;
                ++target;

                *target = b64pad;
                ++target;
                break;
            case 2:
                ods_log_assert(output < 64);
                *target = numb64[output];
                ++target;

                *target = b64pad;
                ++target;
                break;
            default:
                return -4;
                break;
        }
    }
    return target_bytes;
}

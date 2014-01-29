/*
 * $Id: b64.h 7057 2013-02-26 09:30:10Z matthijs $
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

#ifndef COMPAT_B64_H
#define COMPAT_B64_H

#include <stdint.h>
#include <string.h>

/**
 * Encode to base64.
 * @param src:        source to encode.
 * @param target:     where to store the base64 encoding.
 * @param targetsize: size of target.
 * @return:    (int) -1 on error, otherwise: base64 length.
 *
 */
int b64_pton(char const* src, uint8_t* target, size_t targetsize);

/**
 * Decode from base64.
 * @param src:        source to decode.
 * @param srcsize:    size of src.
 * @param target:     where to store the base64 decoding.
 * @param targetsize: size of target.
 * @return:    (int) -1 on error, otherwise: string length.
 *
 */
int b64_ntop(uint8_t const* src, size_t srcsize, char* target,
     size_t targetsize);

int nsd_b64_pton(char const* src, uint8_t* target, size_t targsize);
int nsd_b64_ntop(uint8_t const* src, size_t srclength, char* target, size_t targsize);

#endif /* COMPAT_B64_H */

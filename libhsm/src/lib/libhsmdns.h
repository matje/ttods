/* $Id: libhsmdns.h 6560 2012-08-28 06:31:40Z rb $ */

/*
 * Copyright (c) 2009 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2009 NLNet Labs.
 * All rights reserved.
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
 */

#ifndef HSMDNS_H
#define HSMDNS_H 1

#include <ldns/ldns.h>


/*! Extra information for signing rrsets (algorithm, expiration, etc) */
typedef struct {
    /** The DNS signing algorithm identifier */
    ldns_algorithm algorithm;
    /** Key flags */
    uint16_t flags;
    /** The inception date of signatures made with this key. */
    uint32_t inception;
    /** The expiration date of signatures made with this key. */
    uint32_t expiration;
    /** The keytag of the key (is this necessary?) */
    uint16_t keytag;
    /** The owner name of the key */
    ldns_rdf *owner;
} hsm_sign_params_t;


/*!
 * Returns an allocated hsm_sign_params_t with some defaults
 */
hsm_sign_params_t *
hsm_sign_params_new();


/*!
Free the signer parameters structure

If params->owner has been set, ldns_rdf_deep_free() will be called
on it.

\param params The signer parameters to free
*/
void
hsm_sign_params_free(hsm_sign_params_t *params);


/*! Sign RRset using key

The returned ldns_rr structure can be freed with ldns_rr_free()

\param context HSM context
\param rrset RRset to sign
\param key Key pair used to sign
\return ldns_rr* Signed RRset
*/
ldns_rr*
hsm_sign_rrset(hsm_ctx_t *ctx,
               const ldns_rr_list* rrset,
               const hsm_key_t *key,
               const hsm_sign_params_t *sign_params);


/*! Generate a base32 encoded hashed NSEC3 name

\param ctx HSM context
\param name Domain name to hash
\param algorithm NSEC3 algorithm (must be 1 atm)
\param iteration number of hash iterations
\param salt_length the length of the salt
\param salt the salt
*/
ldns_rdf *
hsm_nsec3_hash_name(hsm_ctx_t *ctx,
                    ldns_rdf *name,
                    uint8_t algorithm,
                    uint16_t iterations,
                    uint8_t salt_length,
                    uint8_t *salt);


/*! Get DNSKEY RR

The returned ldns_rr structure can be freed with ldns_rr_free()

\param context HSM context
\param key Key to get DNSKEY RR from
\param sign_params the signing parameters (flags, algorithm, etc)
\return ldns_rr*
*/
ldns_rr*
hsm_get_dnskey(hsm_ctx_t *ctx,
               const hsm_key_t *key,
               const hsm_sign_params_t *sign_params);


/*! Check if a given DNSSEC algorithm is supported

\param ldns_algorithm algorithm number
\return 0 if supported, -1 otherwise
*/
int
hsm_supported_algorithm(ldns_algorithm algorithm);

#endif /* HSMDNS_H */

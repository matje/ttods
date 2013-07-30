/*
 * $Id: dns.h 6501 2012-08-06 10:52:03Z matthijs $
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
 * DNS definitions.
 *
 */

#ifndef DNS_DNS_H
#define DNS_DNS_H

#include <stdint.h>
#include <string.h>

/** CLASS */
#define DNS_CLASS_IN     1 /* RFC 1035: Internet class */
#define DNS_CLASS_CS     2 /* RFC 1035: CSNET class */
#define DNS_CLASS_CH     3 /* RFC 1035: Chaos class */
#define DNS_CLASS_HS     4 /* RFC 1035: Hesiod class */
#define DNS_CLASS_NONE 254 /* Class NONE */
#define DNS_CLASS_ANY  255 /* Class ANY */

/** TYPE */
#define DNS_TYPE_A       1 /* RFC 1035: an IPv4 host address */
#define DNS_TYPE_NS      2 /* RFC 1035: an authoritative name server */
#define DNS_TYPE_MD      3 /* RFC 1035: a mail destination (Obsolete - use MX) */
#define DNS_TYPE_MF      4 /* RFC 1035: a mail forwarder (Obsolete - use MX) */
#define DNS_TYPE_CNAME   5 /* RFC 1035: the canonical name for an alias */
#define DNS_TYPE_SOA     6 /* RFC 1035: marks the start of authority of a zone */

#define DNS_NUMRRCLASSES DNS_CLASS_HS+1 /* +1 for TYPE0 */
#define DNS_NUMRRTYPES   DNS_TYPE_SOA+1 /* +1 for TYPE0 */

/** RDATA */
/*
 * The different types of RDATA wireformat data.
 */
enum dns_rdata_format_enum {
    DNS_RDATA_IPV4,               /* 32-bit IPv4 address. */
    DNS_RDATA_COMPRESSED_DNAME,   /* Possibly compressed domain name. */
    DNS_RDATA_UNCOMPRESSED_DNAME, /* Uncompressed domain name. */
    DNS_RDATA_INT32,              /* 32-bit integer. */
    DNS_RDATA_TIMEF,              /* 32-bit integer representing time. */
    DNS_RDATA_BINARY              /* Binary data (unknown length). */
};
typedef enum dns_rdata_format_enum dns_rdata_format;

#define DNS_RDATA_MAX 7
#define DNS_RDLEN_MAX 65535

/**
 * RR class structure.
 *
 */
typedef struct rrclass_struct rrclass_type;
struct rrclass_struct {
    const char* name; /* Textual name */
    uint16_t type; /* CLASS */
};

/**
 * RR structure structure.
 *
 */
typedef struct rrstruct_struct rrstruct_type;
struct rrstruct_struct {
    const char* name; /* Textual name */
    uint16_t type; /* RRtype */
    uint8_t minimum; /* Minimum number of RDATAs */
    uint8_t maximum; /* Maximum number of RDATAs */
    uint8_t rdata[DNS_RDATA_MAX]; /* RDATAs */
};

/**
 * Get RR class by name.
 * @param name: name.
 * @return:     (rrclass_type*) RR class.
 *
 */
rrclass_type* dns_rrclass_by_name(const char* name);

/**
 * Get RR class by type.
 * @param type: type.
 * @return:     (rrclass_type*) RR class.
 *
 */
rrclass_type* dns_rrclass_by_type(uint16_t type);

/**
 * Get RR structure by name.
 * @param name: name.
 * @return:     (rrstruct_type*) RR structure.
 *
 */
rrstruct_type* dns_rrstruct_by_name(const char* name);

/**
 * Get RR structure by type.
 * @param type: type.
 * @return:     (rrstruct_type*) RR structure.
 *
 */
rrstruct_type* dns_rrstruct_by_type(uint16_t type);

#endif /* DNS_DNS_H */


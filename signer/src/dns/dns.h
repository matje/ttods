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

#include "util/status.h"

/** CLASS */
#define DNS_CLASS_IN     1 	/* RFC 1035: Internet class */
#define DNS_CLASS_CS     2 	/* RFC 1035: CSNET class */
#define DNS_CLASS_CH     3 	/* RFC 1035: Chaos class */
#define DNS_CLASS_HS     4 	/* RFC 1035: Hesiod class */
#define DNS_CLASS_NONE 254 	/* Class NONE */
#define DNS_CLASS_ANY  255 	/* Class ANY */

/** TYPE */
#define DNS_TYPE_A          1	/* RFC 1035: IPv4 host address */
#define DNS_TYPE_NS         2	/* RFC 1035: authoritative name server */
#define DNS_TYPE_MD         3	/* RFC 1035: mail destination (Obsolete - use MX) */
#define DNS_TYPE_MF         4	/* RFC 1035: mail forwarder (Obsolete - use MX) */
#define DNS_TYPE_CNAME      5	/* RFC 1035: the canonical name for an alias */
#define DNS_TYPE_SOA        6	/* RFC 1035: marks the start of authority of a zone */
#define DNS_TYPE_MB         7	/* RFC 1035: mail box domain name (Experimental) */
#define DNS_TYPE_MG         8	/* RFC 1035: mail group member (Experimental) */
#define DNS_TYPE_MR         9	/* RFC 1035: mail rename domain name (Experimental) */
#define DNS_TYPE_NULL      10	/* RFC 1035: null record (Experimental) */
#define DNS_TYPE_WKS       11	/* RFC 1035: well known service description */
#define DNS_TYPE_PTR       12	/* RFC 1035: domain name pointer */
#define DNS_TYPE_HINFO     13	/* RFC 1035: host information */
#define DNS_TYPE_MINFO     14	/* RFC 1035: mailbox or mail list information */
#define DNS_TYPE_MX        15	/* RFC 1035: mail exchange */
#define DNS_TYPE_TXT       16	/* RFC 1035: text strings */
#define DNS_TYPE_RP        17	/* RFC 1183: responsible person */
#define DNS_TYPE_AFSDB     18	/* RFC 1183: AFS database location (Deprecated - use SRV) */
#define DNS_TYPE_X25       19	/* RFC 1183: X.25 PSDN address */
#define DNS_TYPE_ISDN      20	/* RFC 1183: ISDN address */
#define DNS_TYPE_RT        21	/* RFC 1183: route through */
#define DNS_TYPE_NSAP      22	/* RFC 1706: NSAP address */
#define DNS_TYPE_NSAP_PTR  23	/* RFC 1706: NSAP domain name pointer (Obsolete - use PTR) */
#define DNS_TYPE_SIG       24	/* RFC 2535: security signature */
#define DNS_TYPE_KEY       25	/* RFC 2535: security key */
#define DNS_TYPE_PX        26	/* RFC 2163: X.400 mail mapping information */
#define DNS_TYPE_GPOS      27	/* RFC 1712: geographical position */
#define DNS_TYPE_AAAA      28	/* RFC 3596: IP6 address */
#define DNS_TYPE_LOC       29	/* RFC 3596: local information */
#define DNS_TYPE_NXT       30   /* RFC 2535: next domain (Obsolete - use NSEC) */
#define DNS_TYPE_EID       31   /* endpoint identifier */
#define DNS_TYPE_NIMLOC    32   /* nimrod locator */
#define DNS_TYPE_SRV       33   /* RFC 2782: server selection */
#define DNS_TYPE_ATMA      34   /* ATM address */
#define DNS_TYPE_NAPTR     35   /* RFC 3403: naming authority pointer */
#define DNS_TYPE_KX        36   /* RFC 2230: key exchanger */
#define DNS_TYPE_CERT      37   /* RFC 4398: certificate */
#define DNS_TYPE_A6        38   /* RFC 2874: IPv6 address */
#define DNS_TYPE_DNAME     39   /* RFC 6672: DNAME redirection */
#define DNS_TYPE_SINK      40   /* RFC 6672: DNAME redirection */
#define DNS_TYPE_OPT       41   /* RFC 6672: DNAME redirection */
#define DNS_TYPE_APL       42   /* RFC 3123: list of address prefixes */
#define DNS_TYPE_DS        43   /* RFC 4034: delegation signer */
#define DNS_TYPE_SSHFP     44   /* RFC 4255: SSH key fingerprint */
#define DNS_TYPE_IPSECKEY  45   /* RFC 4025: IPsec keying material */

#define DNS_NUMRRCLASSES DNS_CLASS_HS+1 /* +1 for CLASS0 */
#define DNS_NUMRRTYPES   DNS_TYPE_IPSECKEY+1  /* +1 for TYPE0 */

/** RDATA */

/*
 * The different types of RDATA wireformat data.
 */
enum dns_rdata_format_enum {
    DNS_RDATA_IPV4,               /* 32-bit IPv4 address. */
    DNS_RDATA_COMPRESSED_DNAME,   /* Possibly compressed domain name. */
    DNS_RDATA_UNCOMPRESSED_DNAME, /* Uncompressed domain name. */
    DNS_RDATA_INT8,               /* 8-bit integer. */
    DNS_RDATA_INT16,              /* 16-bit integer. */
    DNS_RDATA_INT32,              /* 32-bit integer. */
    DNS_RDATA_TIMEF,              /* 32-bit integer representing time. */
    DNS_RDATA_DATETIME,           /* 32-bit integer representing datetime. */
    DNS_RDATA_SERVICES,           /* RFC 1010 style services. */
    DNS_RDATA_TEXT,               /* Text string. */
    DNS_RDATA_TEXTS,              /* One or more text strings. */
    DNS_RDATA_NSAP,               /* NSAP address. */
    DNS_RDATA_RRTYPE,             /* RRtype. */
    DNS_RDATA_BASE64,             /* Base64 binary data. */
    DNS_RDATA_BITMAP,             /* RRtype bitmap. */
    DNS_RDATA_FLOAT,              /* Floating point number. */
    DNS_RDATA_IPV6,               /* 128-bit IPv6 address. */
    DNS_RDATA_LOC,                /* LOC RDATA. */
    DNS_RDATA_CERT_TYPE,          /* Certificate number or mnemonic. */
    DNS_RDATA_ALGORITHM,          /* Algorithm number or mnemonic. */
    DNS_RDATA_APLS,               /* One ore more list of address prefixes. */
    DNS_RDATA_HEX,                /* Hexadecimal binary data. */
    DNS_RDATA_IPSECGATEWAY,       /* IPSEC gateway. */
    DNS_RDATA_UNKNOWN             /* Binary data (unknown length). */
};
typedef enum dns_rdata_format_enum dns_rdata_format;

#define DNS_RDATA_MAX 9
#define DNS_STRLEN_MAX 256
#define DNS_IPV6_ADDRLEN (128/8)
#define DNS_RDLEN_MAX 65535
#define DNS_APL_N_MASK 0x80U
#define DNS_APL_AFDLEN_MASK (~DNS_APL_N_MASK)

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
    dns_rdata_format rdata[DNS_RDATA_MAX]; /* RDATAs */
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

/**
 * Get RR type by name.
 * @param name: name.
 * @return:     (uint16_t) RR type.
 *
 */
uint16_t dns_rrtype_by_name(const char* name);

/**
 * Get certificate type by name.
 * @param name: name.
 * @return:     (uint16_t) certificate type.
 *
 */
uint16_t dns_cert_type_by_name(const char* name);

/**
 * Get algorithm by name.
 * @param name: name.
 * @return:     (uint8_t) algorithm.
 *
 */
uint8_t dns_algorithm_by_name(const char* name);

/**
 * Return RDATA format.
 * @param rd:   rdata format.
 * @return:     (const char*) string.
 *
 */
const char* dns_rdata_format_str(dns_rdata_format rd);

#endif /* DNS_DNS_H */


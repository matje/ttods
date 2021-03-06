/*
 * $Id: dns.c 6501 2012-08-06 10:52:03Z matthijs $
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

#include "dns/dns.h"
#include "util/str.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Classes defined in RFC 1035 */
static rrclass_type dns_rrclasses[DNS_NUMRRCLASSES+1] = {
/*    0 */ { NULL, 0 },
/*    1 */ { "IN", DNS_CLASS_IN },
/*    2 */ { "CS", DNS_CLASS_CS },
/*    3 */ { "CH", DNS_CLASS_CH },
/*    4 */ { "HS", DNS_CLASS_HS },
};

/* Certificate types defined in RFC 4398 */
static ods_lookup_table rdata_cert_types[] = {
/*  { 0 }, */              /* Reserved                                     */
    { 1,     "PKIX" },     /* X.509 as per PKIX                            */
    { 2,     "SPKI" },     /* SPKI certificate                             */
    { 3,     "PGP" },      /* OpenPGP packet                               */
    { 4,     "IPKIX" },    /* The URL of an X.509 data object              */
    { 5,     "ISPKI" },    /* The URL of an SPKI certificate               */
    { 6,     "IPGP" },     /* The fingerprint and URL of an OpenPGP packet */
    { 7,     "ACPKIX" },   /* Attribute Certificate                        */
    { 8,     "IACPKIX" },  /* The URL of an Attribute Certificate          */

    { 253,   "URI" },      /* URI private                                  */
    { 254,   "OID" },      /* OID private                                  */
/*  { 255,   NULL }, */    /* Reserved                                     */

/*  { 65280-65534 } */     /* Experimental                                 */
/*  { 65535 } */           /* Reserved                                     */
    { 0, NULL }
};

/* Algorithms defined in RFC 4034, 5155, 5702, 5933, 6605 */
static ods_lookup_table rdata_algorithms[] = {
/*  { 0 }, */                      /* Reserved */
    { 1,   "RSAMD5" },             /* RSA/MD5 */
    { 2,   "DH" },                 /* Diffie-Hellamn */
    { 3,   "DSA" },                /* DSA/SHA-1 */
    { 4,   "ECC" },                /* Elliptic Curve */
    { 5,   "RSASHA1" },            /* RSA/SHA-1 */
    { 6,   "DSA-NSEC3-SHA1" },     /* DSA/SHA-1 NSEC3 */
    { 7,   "RSASHA1-NSEC3-SHA1" }, /* RSA/SHA-1 NSEC3 */
    { 8,   "RSASHA256" },          /* RSA/SHA-256 */

    { 10,  "RSASHA512" },          /* RSA/SHA-512 */

    { 12,  "ECC-GOST" },           /* GOST R 34.10-2001 */
    { 13,  "ECDSAP256SHA256" },    /* ECDSA Curve P-256 with SHA-256 */
    { 14,  "ECDSAP384SHA384" },    /* ECDSA Curve P-384 with SHA-384 */

    { 252, "INDIRECT" },        /* Indirect */
    { 253, "PRIVATEDNS" },      /* Private  */
    { 254, "PRIVATEOID" },      /* Private  */
/*  { 255, NULL }, */           /* Reserved */
    { 0, NULL }
};


static rrstruct_type dns_rrstructs[(DNS_NUMRRTYPES+1)] = {
/*     0 */ { NULL, 0, 1, 1, { DNS_RDATA_UNKNOWN } },
/*     1 */ { "A", DNS_TYPE_A, 1, 1, { DNS_RDATA_IPV4 } },
/*     2 */ { "NS", DNS_TYPE_NS, 1, 1, { DNS_RDATA_COMPRESSED_DNAME } },
/*     3 */ { "MD", DNS_TYPE_MD, 1, 1, { DNS_RDATA_UNCOMPRESSED_DNAME } },
/*     4 */ { "MF", DNS_TYPE_MF, 1, 1, { DNS_RDATA_UNCOMPRESSED_DNAME } },
/*     5 */ { "CNAME", DNS_TYPE_CNAME, 1, 1, { DNS_RDATA_COMPRESSED_DNAME } },
/*     6 */ { "SOA", DNS_TYPE_SOA, 7, 7,
              { DNS_RDATA_COMPRESSED_DNAME, DNS_RDATA_COMPRESSED_DNAME,
                DNS_RDATA_INT32, DNS_RDATA_TIMEF, DNS_RDATA_TIMEF,
                DNS_RDATA_TIMEF, DNS_RDATA_TIMEF } },
/*     7 */ { "MB", DNS_TYPE_MB, 1, 1, { DNS_RDATA_COMPRESSED_DNAME } },
/*     8 */ { "MG", DNS_TYPE_MG, 1, 1, { DNS_RDATA_COMPRESSED_DNAME } },
/*     9 */ { "MR", DNS_TYPE_MR, 1, 1, { DNS_RDATA_COMPRESSED_DNAME } },
/*    10 */ { "NULL", DNS_TYPE_NULL, 1, 1, { DNS_RDATA_UNKNOWN } },
/*    11 */ { "WKS", DNS_TYPE_WKS, 2, 2,
              { DNS_RDATA_IPV4, DNS_RDATA_SERVICES } },
/*    12 */ { "PTR", DNS_TYPE_PTR, 1, 1, { DNS_RDATA_COMPRESSED_DNAME } },
/*    13 */ { "HINFO", DNS_TYPE_MINFO, 2, 2,
              { DNS_RDATA_TEXT, DNS_RDATA_TEXT } },
/*    14 */ { "MINFO", DNS_TYPE_HINFO, 2, 2,
              { DNS_RDATA_COMPRESSED_DNAME, DNS_RDATA_COMPRESSED_DNAME } },
/*    15 */ { "MX", DNS_TYPE_MX, 2, 2,
              { DNS_RDATA_INT16, DNS_RDATA_COMPRESSED_DNAME } } ,
/*    16 */ { "TXT", DNS_TYPE_TXT, 1, 1, { DNS_RDATA_TEXTS } },
/*    17 */ { "RP", DNS_TYPE_RP, 2, 2,
              { DNS_RDATA_UNCOMPRESSED_DNAME, DNS_RDATA_UNCOMPRESSED_DNAME } },
/*    18 */ { "AFSDB", DNS_TYPE_AFSDB, 2, 2,
              { DNS_RDATA_INT16, DNS_RDATA_UNCOMPRESSED_DNAME } },
/*    19 */ { "X25", DNS_TYPE_X25, 1, 1, { DNS_RDATA_TEXT } },
/*    20 */ { "ISDN", DNS_TYPE_ISDN, 1, 2, { DNS_RDATA_TEXT, DNS_RDATA_TEXT } },
/*    21 */ { "RT", DNS_TYPE_RT, 2, 2,
              { DNS_RDATA_INT16, DNS_RDATA_UNCOMPRESSED_DNAME } },
/*    22 */ { "NSAP", DNS_TYPE_NSAP, 1, 1, { DNS_RDATA_NSAP } },
/*    23 */ { "NSAP-PTR", DNS_TYPE_NSAP_PTR, 1, 1,
              { DNS_RDATA_UNCOMPRESSED_DNAME } },
/*    24 */ { "SIG", DNS_TYPE_SIG, 9, 9,
              { DNS_RDATA_RRTYPE, DNS_RDATA_ALGORITHM, DNS_RDATA_INT8,
                DNS_RDATA_TIMEF, DNS_RDATA_DATETIME, DNS_RDATA_DATETIME,
                DNS_RDATA_INT16, DNS_RDATA_UNCOMPRESSED_DNAME,
                DNS_RDATA_BASE64 } },
/*    25 */ { "KEY", DNS_TYPE_KEY, 4, 4,
              { DNS_RDATA_INT16, DNS_RDATA_INT8, DNS_RDATA_ALGORITHM,
                DNS_RDATA_BASE64 } },
/*    26 */ { "PX", DNS_TYPE_PX, 3, 3, { DNS_RDATA_INT16,
                DNS_RDATA_UNCOMPRESSED_DNAME, DNS_RDATA_UNCOMPRESSED_DNAME } },
/*    27 */ { "GPOS", DNS_TYPE_GPOS, 3, 3,
              { DNS_RDATA_FLOAT, DNS_RDATA_FLOAT, DNS_RDATA_FLOAT } },
/*    28 */ { "AAAA", DNS_TYPE_AAAA, 1, 1, { DNS_RDATA_IPV6 } },
/*    29 */ { "LOC", DNS_TYPE_LOC, 1, 1, { DNS_RDATA_LOC } },
/*    30 */ { "NXT", DNS_TYPE_NXT, 2, 2,
              { DNS_RDATA_UNCOMPRESSED_DNAME, DNS_RDATA_NXTBM } },
/*    31 */ { "EID", DNS_TYPE_EID, 1, 1, { DNS_RDATA_UNKNOWN } },
/*    32 */ { "NIMLOC", DNS_TYPE_NIMLOC, 1, 1, { DNS_RDATA_UNKNOWN } },
/*    33 */ { "SRV", DNS_TYPE_SRV, 4, 4,
              { DNS_RDATA_INT16, DNS_RDATA_INT16, DNS_RDATA_INT16,
                DNS_RDATA_UNCOMPRESSED_DNAME } },
/*    34 */ { "ATMA", DNS_TYPE_ATMA, 1, 1, { DNS_RDATA_UNKNOWN } },
/*    35 */ { "NAPTR", DNS_TYPE_NAPTR, 6, 6,
              { DNS_RDATA_INT16, DNS_RDATA_INT16, DNS_RDATA_TEXT,
                DNS_RDATA_TEXT, DNS_RDATA_TEXT,
                DNS_RDATA_UNCOMPRESSED_DNAME } },
/*    36 */ { "KX", DNS_TYPE_KX, 2, 2,
              { DNS_RDATA_INT16, DNS_RDATA_UNCOMPRESSED_DNAME } },
/*    37 */ { "CERT", DNS_TYPE_CERT, 4, 4,
              { DNS_RDATA_CERT_TYPE, DNS_RDATA_INT8, DNS_RDATA_ALGORITHM,
                DNS_RDATA_BASE64 } },
/*    38 */ { "A6", DNS_TYPE_A6, 1, 1, { DNS_RDATA_UNKNOWN } },
/*    39 */ { "DNAME", DNS_TYPE_DNAME, 1, 1, { DNS_RDATA_UNCOMPRESSED_DNAME } },
/*    40 */ { "SINK", DNS_TYPE_SINK, 1, 1, { DNS_RDATA_UNKNOWN } },
/*    41 */ { "OPT", DNS_TYPE_OPT, 1, 1, { DNS_RDATA_UNKNOWN } },
/*    42 */ { "APL", DNS_TYPE_APL, 1, 1, { DNS_RDATA_APLS } },
/*    43 */ { "DS", DNS_TYPE_DS, 4, 4,
              { DNS_RDATA_INT16, DNS_RDATA_ALGORITHM, DNS_RDATA_INT8,
                DNS_RDATA_HEX } },
/*    44 */ { "SSHFP", DNS_TYPE_SSHFP, 3, 3,
              { DNS_RDATA_INT8, DNS_RDATA_INT8, DNS_RDATA_HEX } },
/*    45 */ { "IPSECKEY", DNS_TYPE_IPSECKEY, 4, 5,
              { DNS_RDATA_INT8, DNS_RDATA_INT8, DNS_RDATA_INT8,
                DNS_RDATA_IPSECGATEWAY, DNS_RDATA_BASE64 } },
/*    46 */ { "RRSIG", DNS_TYPE_RRSIG, 9, 9,
              { DNS_RDATA_RRTYPE, DNS_RDATA_ALGORITHM, DNS_RDATA_INT8,
                DNS_RDATA_TIMEF, DNS_RDATA_DATETIME, DNS_RDATA_DATETIME,
                DNS_RDATA_INT16, DNS_RDATA_UNCOMPRESSED_DNAME,
                DNS_RDATA_BASE64 } },
/*    47 */ { "NSEC", DNS_TYPE_NSEC, 2, 2,
              { DNS_RDATA_UNCOMPRESSED_DNAME, DNS_RDATA_NSECBM } },
/*    48 */ { "DNSKEY", DNS_TYPE_DNSKEY, 4, 4,
              { DNS_RDATA_INT16, DNS_RDATA_INT8, DNS_RDATA_ALGORITHM,
                DNS_RDATA_BASE64 } },
/*    49 */ { "DHCID", DNS_TYPE_DHCID, 1, 1, { DNS_RDATA_BASE64 } },
/*    50 */ { "NSEC3", DNS_TYPE_NSEC3, 6, 6,
              { DNS_RDATA_INT8, DNS_RDATA_INT8, DNS_RDATA_INT16,
                DNS_RDATA_HEXLEN, DNS_RDATA_BASE32HEX, DNS_RDATA_NSECBM } },
/*    51 */ { "NSEC3PARAM", DNS_TYPE_NSEC3PARAM, 4, 4,
              { DNS_RDATA_INT8, DNS_RDATA_INT8, DNS_RDATA_INT16,
                DNS_RDATA_HEXLEN } },
};


/**
 * Get RR class by name.
 *
 */
rrclass_type*
dns_rrclass_by_name(const char* name)
{
    int i;
    for (i = 1; i < DNS_NUMRRCLASSES; i++) {
        if (dns_rrclasses[i].name &&
            strcasecmp(dns_rrclasses[i].name, name) == 0) {
            return &dns_rrclasses[i];
        }
    }
    return &dns_rrclasses[0];
}


/**
 * Get RR class by type.
 *
 */
rrclass_type*
dns_rrclass_by_type(uint16_t type)
{
    if (type < DNS_NUMRRCLASSES) {
        return &dns_rrclasses[type];
    }
    return &dns_rrclasses[0];
}


/**
 * Get RR structure by name.
 *
 */
rrstruct_type*
dns_rrstruct_by_name(const char* name)
{
    int i;
    for (i = 1; i < DNS_NUMRRTYPES; i++) {
        if (dns_rrstructs[i].name &&
            strcasecmp(dns_rrstructs[i].name, name) == 0) {
            return &dns_rrstructs[i];
        }
    }
    return &dns_rrstructs[0];
}


/**
 * Get RR type by name.
 *
 */
uint16_t
dns_rrtype_by_name(const char* name)
{
    char* end;
    long type;
    rrstruct_type* rstruct = dns_rrstruct_by_name(name);
    if (rstruct && rstruct->name) { return rstruct->type; }
    if (strlen(name) < 5) { return 0; }
    if (strncasecmp(name, "TYPE", 4) != 0) { return 0; }
    if (!isdigit((int)name[4])) { return 0; }
    type = strtol(name+4, &end, 10);
    if (*end != '\0') { return 0; }
    if (type < 0 || type > 65535L) { return 0; }
    return (uint16_t) type;
}


/**
 * Get certificate type by name.
 *
 */
uint16_t
dns_cert_type_by_name(const char* name)
{
    ods_lookup_table* table = rdata_cert_types;
    while (table->name != NULL) {
        if (ods_strcmp(name, table->name) == 0)
            return (uint16_t) table->id;
        table++;
    }
    return (uint16_t) atoi(name);
}


/**
 * Get algorithm by name.
 *
 */
uint8_t
dns_algorithm_by_name(const char* name)
{
    ods_lookup_table* table = rdata_algorithms;
    while (table->name != NULL) {
        if (ods_strcmp(name, table->name) == 0)
            return (uint8_t) table->id;
        table++;
    }
    return (uint8_t) atoi(name);
}


/**
 * Get RR structure by type.
 *
 */
rrstruct_type*
dns_rrstruct_by_type(uint16_t type)
{
    if (type < DNS_NUMRRTYPES) {
        return &dns_rrstructs[type];
    }
    return &dns_rrstructs[0];
}


/**
 * Return RDATA format.
 *
 */
const char*
dns_rdata_format_str(dns_rdata_format rd)
{
    switch (rd) {
        case DNS_RDATA_IPV4: return "ipv4addr"; break;
        case DNS_RDATA_IPV6: return "ipv6addr"; break;
        case DNS_RDATA_COMPRESSED_DNAME: return "dname"; break;
        case DNS_RDATA_UNCOMPRESSED_DNAME: return "dname"; break;
        case DNS_RDATA_INT8: return "int8"; break;
        case DNS_RDATA_INT16: return "int16"; break;
        case DNS_RDATA_INT32: return "int32"; break;
        case DNS_RDATA_CERT_TYPE: return "certificate-type"; break;
        case DNS_RDATA_ALGORITHM: return "algorithm"; break;
        case DNS_RDATA_TIMEF: return "period"; break;
        case DNS_RDATA_DATETIME: return "datetime"; break;
        case DNS_RDATA_SERVICES: return "services"; break;
        case DNS_RDATA_TEXT: return "character-string"; break;
        case DNS_RDATA_TEXTS: return "character-strings"; break;
        case DNS_RDATA_NSAP: return "nsap"; break;
        case DNS_RDATA_RRTYPE: return "rrtype"; break;
        case DNS_RDATA_BASE32HEX: return "base32hex"; break;
        case DNS_RDATA_BASE64: return "base64"; break;
        case DNS_RDATA_HEX: return "hex"; break;
        case DNS_RDATA_HEXLEN: return "hexlen"; break;
        case DNS_RDATA_FLOAT: return "float"; break;
        case DNS_RDATA_LOC: return "loc"; break;
        case DNS_RDATA_APLS: return "apl"; break;
        case DNS_RDATA_IPSECGATEWAY: return "ipsecgateway"; break;
        case DNS_RDATA_NXTBM: return "bitmap-nxt"; break;
        case DNS_RDATA_NSECBM: return "bitmap-nsec"; break;
        case DNS_RDATA_UNKNOWN: return "unknown"; break;
        default:
            break;
    }
    return "unspecified";
}

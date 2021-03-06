/*
 * zparser.rl -- ragel grammar for DNS zone files.
 *
 * Copyright (c) 2013, Matthijs Mekking, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */


%%{
    machine zparser;

    # Actions.
    action zparser_goto_main {
        fgoto main;
    }
    action zparser_hold_ret {
        fhold; fret;
    }

    # Actions: line parsing.
    action zparser_reinitialize {
        parser->group_lines = 0;
    }
    action zparser_newline {
        if (parser->line > parser->line_update) {
            ods_log_debug("[zparser] ...at line %i", parser->line);
            parser->line_update += AD_LINE_INTERVAL;
        }
        parser->line++;
    }
    action zparser_comment {
        parser->comments++;
    }
    action zparser_parentheses_open {
        if (parser->group_lines) {
            ods_log_error("[zparser] line %d: nested parentheses",
                parser->line);
            parser->totalerrors++;
            fhold; fgoto line_error;
        }
        ods_log_debug("[zparser] line %d: open parentheses", parser->line);
        parser->group_lines = 1;
    }
    action zparser_parentheses_close {
        if (!parser->group_lines) {
            ods_log_error("[zparser] line %d: closing parentheses without "
                "opening parentheses", parser->line);
            parser->totalerrors++;
            fhold; fgoto line_error;
        }
        ods_log_debug("[zparser] line %d: close parentheses", parser->line);
        parser->group_lines = 0;
    }
    action zparser_single_line { parser->group_lines == 0 }
    action zparser_group_lines { parser->group_lines == 1 }

    # Actions: numbers.
    action zparser_decimal_digit {
        parser->number *= 10;
        parser->number += (fc - '0');
    }
    action zparser_timeformat {
        switch (fc) {
            case 'w':
            case 'W':
                parser->number *= (60*60*24*7);
                break;
            case 'd':
            case 'D':
                parser->number *= (60*60*24);
                break;
            case 'h':
            case 'H':
                parser->number *= (60*60);
                break;
            case 'm':
            case 'M':
                parser->number *= 60;
                break;
            case 's':
            case 'S':
            default:
                break;
        }
        parser->seconds += parser->number;
        parser->number = 0;
    }
    action zparser_ttl_start {
        parser->seconds = 0;
        parser->number = 0;
    }
    action zparser_ttl_end {
        parser->seconds += parser->number;
        parser->number = parser->seconds;
    }
    action zparser_dollar_ttl {
        parser->ttl = parser->number;
        ods_log_debug("[zparser] line %d: $TTL set to %u", parser->line-1,
            (unsigned int) parser->ttl);
    }

    # Actions: character strings.
    action zparser_text_char2wire {
        if (parser->rdsize < DNS_STRLEN_MAX) {
            parser->rdbuf[parser->rdsize] = fc;
            parser->rdsize++;
        } else {
            ods_log_error("[zparser] error: line %d: character string overflow",
                parser->line);
            parser->totalerrors++;
            fhold; fgoto line_error;
        }
    }
    action zparser_text_octet2wire_init {
        if (parser->rdsize < DNS_STRLEN_MAX) {
            parser->rdbuf[parser->dname_size] = 0;
            parser->rdsize++;
        } else {
            ods_log_error("[zparser] error: line %d: character string overflow",
                parser->line);
            parser->totalerrors++;
            fhold; fgoto line_error;
        }
    }
    action zparser_text_octet2wire {
        parser->rdbuf[parser->rdsize-1] *= 10;
        parser->rdbuf[parser->rdsize-1] += (fc - '0');
    }

    # Actions: labels and domain names.
    action zparser_label_start {
        parser->label_head = parser->dname_size;
        parser->dname_size++;
        parser->dname_is_absolute = 0;
    }
    action zparser_label_char2wire {
        if (parser->dname_size <= DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = fc;
            parser->dname_size++;
        } else {
            ods_log_error("[zparser] error: line %d: domain name overflow",
                parser->line);
            parser->totalerrors++;
            fhold; fgoto line_error;
        }
    }
    action zparser_label_octet2wire_init {
        if (parser->dname_size <= DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            ods_log_error("[zparser] error: line %d: domain name overflow",
                parser->line);
            parser->totalerrors++;
            fhold; fgoto line_error;
        }
    }
    action zparser_label_octet2wire {
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += (fc - '0');
    }
    action zparser_label_end {
        parser->dname_wire[parser->label_head] =
            (parser->dname_size - parser->label_head - 1);
    }
    action zparser_dname_origin {
        parser->dname = parser->origin;
    }
    action zparser_dname_previous {
        parser->dname = parser->previous;
    }
    action zparser_dname_start {
        bzero(&parser->dname_wire[0], DNAME_MAXLEN);
        bzero(&parser->label_offsets[0], DNAME_MAXLEN);
        parser->dname_size = 0;
        parser->label_count = 0;
        parser->label = parser->dname_wire;
        parser->dname_is_absolute = 0;
    }
    action zparser_dname_absolute {
        parser->dname_is_absolute = 1;
    }
    action zparser_dname_end {
        int i;
        parser->dname_size++;
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
        } else {
            ods_log_error("[zparser] line %d: domain name overflow",
                parser->line);
            parser->totalerrors++;
            fhold; fgoto line_error;
        }
        if (!parser->dname_is_absolute) {
            if ((parser->dname_size + dname_len(parser->origin))
                <= DNAME_MAXLEN) {
                memcpy(parser->dname_wire + parser->dname_size - 1,
                    dname_name(parser->origin), dname_len(parser->origin));
                parser->dname_size += (dname_len(parser->origin) - 1);
            } else{
                ods_log_error("[zparser] line %d: domain name overflow",
                    parser->line);
                parser->totalerrors++;
                fhold; fgoto line_error;
            }
        }
        while (1) {
            if (label_is_pointer(parser->label)) {
                ods_log_error("[zparser] line %d: domain has pointer label",
                    parser->line);
                parser->totalerrors++;
                fhold; fgoto line_error;
            }
            parser->label_offsets[parser->label_count] =
                (uint8_t)(parser->label - parser->dname_wire);
            ++parser->label_count;
            if (label_is_root(parser->label)) {
                break;
            }
            parser->label = label_next(parser->label);
        }
        assert(parser->label_count <= DNAME_MAXLEN / 2 + 1);
        /* reverse label offsets. */
        for (i = 0; i < parser->label_count / 2; ++i) {
            uint8_t tmp = parser->label_offsets[i];
            parser->label_offsets[i] =
                parser->label_offsets[parser->label_count - i - 1];
            parser->label_offsets[parser->label_count - i - 1] = tmp;
        }
        parser->dname = (dname_type *) region_alloc(parser->region,
            (sizeof(dname_type) +
            (parser->label_count + parser->dname_size) * sizeof(uint8_t)));
        if (!parser->dname) {
            ods_log_error("[zparser] line %d: domain create failed",
                parser->line);
            parser->totalerrors++;
            fhold; fgoto line_error;
        }
        parser->dname->size = parser->dname_size;
        parser->dname->label_count = parser->label_count;
        memmove((uint8_t *) dname_label_offsets(parser->dname),
            parser->label_offsets, parser->label_count * sizeof(uint8_t));
        memmove((uint8_t *) dname_name(parser->dname), parser->dname_wire,
            parser->dname_size * sizeof(uint8_t));
    }
    action zparser_dollar_origin {
        char str[DNAME_MAXLEN*5]; /* all \DDD */
        parser->origin = dname_clone(parser->region, parser->dname);
        dname_str(parser->origin, &str[0]);
        ods_log_debug("[zparser] line %d: $ORIGIN set to %s", parser->line-1,
            str);
    }

    # Actions: rdata.
    action zparser_rdata_call {
        char t[10];
        rrstruct_type* rs = dns_rrstruct_by_type(parser->current_rr.type);

        fhold;
        switch (parser->current_rr.type) {
           case DNS_TYPE_A:
               fcall rdata_a;
           case DNS_TYPE_NS:
           case DNS_TYPE_MD:
           case DNS_TYPE_MF:
           case DNS_TYPE_CNAME:
           case DNS_TYPE_MB:
           case DNS_TYPE_MG:
           case DNS_TYPE_MR:
           case DNS_TYPE_PTR:
           case DNS_TYPE_NSAP_PTR:
                fcall rdata_ns;
           case DNS_TYPE_SOA:
                fcall rdata_soa;
           case DNS_TYPE_WKS:
                fcall rdata_wks;
           case DNS_TYPE_HINFO:
                fcall rdata_hinfo;
           case DNS_TYPE_MINFO:
           case DNS_TYPE_RP:
                fcall rdata_minfo;
           case DNS_TYPE_MX:
           case DNS_TYPE_AFSDB:
           case DNS_TYPE_RT:
           case DNS_TYPE_KX:
                fcall rdata_mx;
           case DNS_TYPE_TXT:
                fcall rdata_txt;
           case DNS_TYPE_X25:
                fcall rdata_x25;
           case DNS_TYPE_ISDN:
                fcall rdata_isdn;
           case DNS_TYPE_NSAP:
                fcall rdata_nsap;
           case DNS_TYPE_SIG:
           case DNS_TYPE_RRSIG:
                fcall rdata_sig;
           case DNS_TYPE_KEY:
           case DNS_TYPE_DNSKEY:
                fcall rdata_key;
           case DNS_TYPE_PX:
                fcall rdata_px;
           case DNS_TYPE_GPOS:
                fcall rdata_gpos;
           case DNS_TYPE_AAAA:
                fcall rdata_aaaa;
           case DNS_TYPE_LOC:
                fcall rdata_loc;
           case DNS_TYPE_NXT:
           case DNS_TYPE_NSEC:
                fcall rdata_nxt;
           case DNS_TYPE_SRV:
                fcall rdata_srv;
           case DNS_TYPE_NAPTR:
                fcall rdata_naptr;
           case DNS_TYPE_CERT:
                fcall rdata_cert;
           case DNS_TYPE_DNAME:
                fcall rdata_dname;
           case DNS_TYPE_APL:
                fcall rdata_apl;
           case DNS_TYPE_DS:
                fcall rdata_ds;
           case DNS_TYPE_SSHFP:
                fcall rdata_sshfp;
           case DNS_TYPE_IPSECKEY:
                fcall rdata_ipseckey;
           case DNS_TYPE_DHCID:
                fcall rdata_dhcid;
           case DNS_TYPE_NSEC3:
                fcall rdata_nsec3;
           case DNS_TYPE_NSEC3PARAM:
                fcall rdata_nsec3param;
           case DNS_TYPE_NULL:
           default:
                if (!rs->name) {
                    snprintf(&t[0], 10, "TYPE%u",
                        (unsigned) parser->current_rr.type);
                }
                ods_log_error("[zparser] line %d: rrtype %s not supported",
                    parser->line, rs->name?rs->name:&t[0]);
                parser->totalerrors++;
                fgoto line_error;
       }
    }
    action zparser_rdata_start {
        bzero(&parser->rdbuf[0], DNS_RDLEN_MAX);
        parser->rdsize = 0;
    }
    action zparser_rdata_char {
        if (parser->rdsize <= DNS_RDLEN_MAX) {
            parser->rdbuf[parser->rdsize] = fc;
            parser->rdsize++;
        } else {
            ods_log_error("[zparser] error: line %d: rdata overflow",
                parser->line);
            parser->totalerrors++;
            fhold; fgoto line_error;
        }
    }
    action zparser_rdata_char_b64 {
        if (parser->rdsize <= DNS_RDLEN_MAX) {
            if (isalnum((int) fc) || fc == '+' || fc == '/' || fc == '=') {
                parser->rdbuf[parser->rdsize] = fc;
                parser->rdsize++;
            }
        } else {
            ods_log_error("[zparser] error: line %d: rdata overflow",
                parser->line);
            parser->totalerrors++;
            fhold; fgoto line_error;
        }
    }
    action zparser_rdata_char_hex {
        if (parser->rdsize <= DNS_RDLEN_MAX) {
            if (isxdigit((int) fc)) {
                parser->rdbuf[parser->rdsize] = fc;
                parser->rdsize++;
            }
        } else {
            ods_log_error("[zparser] error: line %d: rdata overflow",
                parser->line);
            parser->totalerrors++;
            fhold; fgoto line_error;
        }
    }
    action zparser_rdata_char_nsap {
        if (parser->rdsize <= DNS_RDLEN_MAX) {
            if (fc != '.') {
                parser->rdbuf[parser->rdsize] = fc;
                parser->rdsize++;
            }
        } else {
            ods_log_error("[zparser] error: line %d: rdata overflow",
                parser->line);
            parser->totalerrors++;
            fhold; fgoto line_error;
        }
    }
    action zparser_rdata_end {
        rrstruct_type* rs = dns_rrstruct_by_type(parser->current_rr.type);
        parser->rdbuf[parser->rdsize] = '\0';
        if (!zonec_rdata_add(parser->region, &parser->current_rr,
            rs->rdata[parser->current_rr.rdlen], parser->dname,
            parser->rdbuf, parser->rdsize)) {
            parser->totalerrors++;
            fhold; fgoto line_error;
        }
    }
    action zparser_rdata_str_end {
        parser->rdbuf[parser->rdsize] = '\0';
        if (!zonec_rdata_add(parser->region, &parser->current_rr,
            DNS_RDATA_TEXT, parser->dname, parser->rdbuf, parser->rdsize)) {
            parser->totalerrors++;
            fhold; fgoto line_error;
        }
    }
    action zparser_rdata_apl_end {
        parser->rdbuf[parser->rdsize] = '\0';
        if (!zonec_rdata_add(parser->region, &parser->current_rr,
            DNS_RDATA_APLS, parser->dname, parser->rdbuf, parser->rdsize)) {
            parser->totalerrors++;
            fhold; fgoto line_error;
        }
    }

    # Actions: resource records.
    action zparser_rr_start {
        if (!parser->group_lines) {
            parser->current_rr.ttl = parser->ttl;
            parser->current_rr.klass = parser->klass;
            parser->current_rr.type = 0;
            parser->current_rr.rdlen = 0;
            parser->current_rr.rdata = parser->tmp_rdata;
        }
    }
    action zparser_rr_owner {
        parser->current_rr.owner = parser->dname;
    }
    action zparser_rr_class {
        parser->current_rr.klass = DNS_CLASS_IN;
    }
    action zparser_rr_ttl {
        parser->current_rr.ttl = parser->number;
    }
    action zparser_rr_end {
        if (!parser->group_lines) {
            if (!zparser_process_rr(parser)) {
                ods_log_error("[zparser] error: line %d: unable to process rr",
                    parser->line);
                parser->totalerrors++;
                fhold; fgoto line_error;
            }
            parser->previous = parser->current_rr.owner;
        }
    }
    # Actions: errors.
    action zerror_entry {
        ods_log_error("[zparser] error: line %d: bad entry (fc=%c)", 
            parser->line, fc);
        parser->totalerrors++;
        fhold; fgoto line_error;
    }
    action zerror_dollar_origin {
        ods_log_error("[zparser] error: line %d: bad $origin directive (fc=%c)",
            parser->line, fc);
        parser->totalerrors++;
        fhold; fgoto line_error;
    }
    action zerror_dollar_ttl {
        ods_log_error("[zparser] error: line %d: bad $ttl directive (fc=%c)",
            parser->line, fc);
        parser->totalerrors++;
        fhold; fgoto line_error;
    }
    action zerror_timeformat {
        ods_log_error("[zparser] error: line %d: ttl time format error (fc=%c)",
            parser->line, fc);
        parser->totalerrors++;
        fhold; fgoto line_error;
    }
    action zerror_text_ddd {
        ods_log_error("[zparser] error: line %d: bad octet in text",
            parser->line);
        parser->totalerrors++;
        fhold; fgoto line_error;
    }
    action zerror_float {
        ods_log_error("[zparser] error: line %d: bad float number",
            parser->line);
        parser->totalerrors++;
        fhold; fgoto line_error;
    }
    action zerror_text_x {
        ods_log_error("[zparser] error: line %d: bad escape in text",
            parser->line);
        parser->totalerrors++;
        fhold; fgoto line_error;
    }
    action zerror_str_seq {
        ods_log_error("[zparser] error: line %d: bad character string (fc=%c)",
            parser->line, fc);
        parser->totalerrors++;
        fhold; fgoto line_error;
    }
    action zerror_label_ddd {
        ods_log_error("[zparser] error: line %d: bad octet in label (fc=%c)",
            parser->line, fc);
        parser->totalerrors++;
        fhold; fgoto line_error;
    }
    action zerror_label_x {
        ods_log_error("[zparser] error: line %d: bad escape in label (fc=%c)",
            parser->line, fc);
        parser->totalerrors++;
        fhold; fgoto line_error;
    }
    action zerror_label_char {
        ods_log_error("[zparser] error: line %d: bad char in label (fc=%c)",
            parser->line, fc);
        parser->totalerrors++;
        fhold; fgoto line_error;
    }
    action zerror_label_overflow {
        ods_log_error("[zparser] error: line %d: label overflow (fc=%c)",
            parser->line, fc);
        parser->totalerrors++;
        fhold; fgoto line_error;
    }
    action zerror_rr {
        ods_log_error("[zparser] error: line %d: bad rr format (fc=%c)",
            parser->line, fc);
        parser->totalerrors++;
        fhold; fgoto line_error;
    }
    action zerror_rr_typedata {
        ods_log_error("[zparser] error: line %d: bad rr typedata (fc=%c)",
            parser->line, fc);
        parser->totalerrors++;
        fhold; fgoto line_error;
    }
    action zerror_rdata {
        ods_log_error("[zparser] error: line %d: bad rdata (fc=%c)",
            parser->line, fc);
        parser->totalerrors++;
        fhold; fgoto line_error;
    }
    action zerror_rdata_err {
        rrstruct_type* rs = dns_rrstruct_by_type(parser->current_rr.type);
        parser->rdbuf[parser->rdsize] = '\0';
        ods_log_error("[zparser] error: line %d: bad %s rdata %s (fc=%c)",
            parser->line,
            dns_rdata_format_str(rs->rdata[parser->current_rr.rdlen]),
            parser->rdbuf, fc);
        parser->totalerrors++;
        fhold; fgoto line_error;
    }

    ## Utility parsing, newline, comments, delimeters, numbers, time values.

    special_char     = [$;() \t\n\\];
    special_char_end = [$;\n\\] when zparser_single_line;

    newline          = '\n' $zparser_newline;

    # RFC 1035: Semicolon is used to start a comment; the remainder of the
    # line is ignored.
    comment          = (';' . (^newline)*) >zparser_comment;

    sp               = [ \t];

    delim            =
                     ( sp
                     | (comment? . newline) when zparser_group_lines
                     | '(' $zparser_parentheses_open
                     | ')' $zparser_parentheses_close
                     )+;

    endline          = (delim? :> (comment? when zparser_single_line))
                     . newline;

    # http://www.zytrax.com/books/dns/apa/time.html
    timeformat       = ( 's'i | 'm'i | 'h'i | 'd'i | 'w'i )
                     $zparser_timeformat
                     $!zerror_timeformat;

    decimal_number   = digit+ $zparser_decimal_digit;

    float_number     = digit+ . digit+;

    time_value       = (decimal_number . timeformat)+ . decimal_number?;

    # mnemonic: for example "TCP", "UDP", "DNS", ...
    mnemonic         = alpha+;

    # RFC 1035: TTL is a decimal integer
    # The $TTL field may take any time value.
    ttl              = (decimal_number | time_value)
                     >zparser_ttl_start
                     %zparser_ttl_end;

    ## Domain name parsing, absolute dnames, relative dnames, labels,
    ## character strings.

    # RFC 1035: \DDD where each D is a digit is the octet corresponding to
    #                the decimal number described by DDD.  The resulting
    #                octet is assumed to be text and is not checked for
    #                special meaning.
    label_ddd        = [0-7] {3}
                     >zparser_label_octet2wire_init
                     $zparser_label_octet2wire
                     $!zerror_label_ddd;
    text_ddd         = [0-7] {3}
                     >zparser_text_octet2wire_init
                     $zparser_text_octet2wire
                     $!zerror_text_ddd;

    # RFC 1035: \X   where X is any character other than a digit (0-9), is
    #                used to quote that character so that its special meaning
    #                does not apply.  For example, "\." can be used to place
    #                a dot character in a label.
    label_x          = ^digit
                     $zparser_label_char2wire
                     $!zerror_label_x;
    text_x           = ^digit
                     $zparser_text_char2wire
                     $!zerror_text_x;

    label_escape     = '\\' . (label_x | label_ddd);
    label_char       = ([^@().\"\$\\; \t\n])
                     $zparser_label_char2wire
                     $!zerror_label_char;

    label_character  = (label_char | label_escape);

    text_escape      = '\\' . (text_x | text_ddd);
    text_char        =  ([^@().\"\$\\; \t\n])
                     $zparser_text_char2wire;

    text_delim       =  ([@().\"\$\\; \t\n])
                     $zparser_text_char2wire;

    text_character   = (text_char | text_escape);
    text_character_delim = (text_character | text_delim);

    str_seq          = ('\"' . (text_character_delim* :>> '\"')
                     | text_character+)
                     $!zerror_str_seq;

    str_float        = (('-')? . digit+ . '.' . digit+ )
                     $zparser_text_char2wire
                     $!zerror_float;

    # RFC 1035: The labels in the domain name are expressed as character
    # strings. MM: But requires different processing then for non-labels.
    label            = label_character{1,63}
                     >zparser_label_start
                     %zparser_label_end
                     $!zerror_label_overflow;

    labels           = (label . '.')* . label;

    # RFC 1035: Domain names which do not end in a dot are called relative.
    rel_dname       = labels
                    >zparser_dname_start
                    %zparser_dname_end;

    # RFC 1035: Domain names that end in a dot are called absolute.
    abs_dname        = (labels? . ('.' $zparser_dname_absolute))
                     >zparser_dname_start
                     %zparser_dname_end;

    owner            = abs_dname
                     | rel_dname
                     | '@' >zparser_dname_origin
                     | zlen %zparser_dname_previous;

    addr_prefix      = '/' . digit{1,3};

    ipv4_label       = digit {1,3} . '.';
    ipv4_label_end   = digit {1,3};

    ipv4_addr        = ipv4_label{3} . ipv4_label_end;

    # RFC 5952: A Recommendation for IPv6 Address Text Representation
    # Section 4.1:   Leading zeros MUST be suppressed. INCOMPATIBLE
    # Section 4.2.3: Choice in Placement of "::". INCOMPATIBLE
    # Section 4.3:   Lowercase. INCOMPATIBLE
    # Section 5:     IPv4 mapped addresses solely with well known prefix. INCOMPATIBLE
    ipv6_label       = xdigit {1,4} . ':';
    ipv6_label_end   = xdigit {1,4};

    # RFC 3513: IPv6 Text Representation.

    # 1. x:x:x:x:x:x:x:x
    ipv6_xxxxxxxx    = ipv6_label{7} . ipv6_label_end;

    # 2. Compressed: ::
    ipv6_compressed  = ipv6_label{1,6} . ':'
                     | ipv6_label{1,5} . ':'                   . ipv6_label_end
                     | ipv6_label{1,4} . ':' . ipv6_label{0,1} . ipv6_label_end
                     | ipv6_label{1,3} . ':' . ipv6_label{0,2} . ipv6_label_end
                     | ipv6_label{1,2} . ':' . ipv6_label{0,3} . ipv6_label_end
                     | ipv6_label      . ':' . ipv6_label{0,4} . ipv6_label_end
                     | ':'             . ':' . ipv6_label{0,5} . ipv6_label_end?
                     ;

    # 3. with IPv4
    ipv6_mapped      = ipv6_label{6}                           . ipv4_addr
                     | ipv6_label{1,4} . ':'                   . ipv4_addr
                     | ipv6_label{1,3} . ':' . ipv6_label{0,1} . ipv4_addr
                     | ipv6_label{1,2} . ':' . ipv6_label{0,2} . ipv4_addr
                     | ipv6_label      . ':' . ipv6_label{0,3} . ipv4_addr
                     | ':'             . ':' . ipv6_label{0,4} . ipv4_addr
                     ;

    ipv6_addr        = ( ipv6_xxxxxxxx | ipv6_compressed | ipv6_mapped );

    ## RDATA parsing.
    rd_ipv4          = ipv4_addr
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_ipv6          = ipv6_addr
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_abs_dname     = (abs_dname)
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_dname         = (abs_dname | rel_dname)
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_int           = digit+
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_float         = str_float
                     >zparser_rdata_start
                     %zparser_rdata_end $!zerror_rdata_err;

    rd_timef         = ttl
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_services      = ((delim . (mnemonic | decimal_number))+ . delim?)
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_str           = str_seq
                     >zparser_rdata_start
                     %zparser_rdata_str_end $!zerror_rdata_err;

    rd_nsap          = (xdigit | '.')+
                     >zparser_rdata_start $zparser_rdata_char_nsap
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_rrtype        = (upper | digit | '-')+
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_datetime      = digit{14}
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_bitmap        = ((delim . (upper | digit | '-')+)* . delim?)
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_loc           =
                     ( ([0-8][0-9] | "90")                        . delim
                     . ([0-5]?[0-9]                               . delim)?
                     . ([0-5]?[0-9] . ('.' . [0-9]{1,3})?         . delim)?
                     . ('N'i | 'S'i)                              . delim

                     . ([0-9]{1,2} | '1' . [0-7][0-9] | "180")    . delim
                     . ([0-5]?[0-9]                               . delim)?
                     . ([0-5]?[0-9] . ('.' . [0-9]{1,3})?         . delim)?
                     . ('E'i | 'W'i)                              . delim

                     # Not completely RFC 1876 compliant
                     . '-'? . digit+ . ('.' . [0-9]{1,2})? . ('m'i)?
                     . (delim . [0-9]{1,8} . ('.' . [0-9]{1,2})? . ('m'i)?){0,2}
                     . (delim . [0-9]{1,8} . ('.' . [0-9]{1,2})? . ('m'i)?)?
                     . delim?
                     )
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_algorithm     = ( (alpha . (alnum | '-')*) | decimal_number )
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_apl           = ( '!'? . ( ("1:" . ipv4_addr) | ("2:" . ipv6_addr) )
                     . addr_prefix )
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_apl_end $!zerror_rdata_err;

    rd_hex           = (xdigit+ . delim?)+
                     >zparser_rdata_start $zparser_rdata_char_hex
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_hexlen        = (xdigit+ | '-')
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_ipsecgateway  = ( ipv4_addr | ipv6_addr | abs_dname | rel_dname )
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_0             = '0'
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_1             = '1'
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_2             = '2'
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_3             = '3'
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_12            = [12]
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_dot           = '.'
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    # RFC4648: Base16, Base32 and Base64 Data Encodings
    rd_b32hex        = ([0-9A-Va-v]+)
                     >zparser_rdata_start $zparser_rdata_char
                     %zparser_rdata_end   $!zerror_rdata_err;

    rd_b64           = (((alnum | [+/])+ . delim?)+ . '='{0,2} . delim?)
                     >zparser_rdata_start $zparser_rdata_char_b64
                     %zparser_rdata_end   $!zerror_rdata_err;

    ## Resource records parsing.
    rdata_a         := rd_ipv4
                     %zparser_hold_ret . special_char;

    rdata_ns        := rd_dname
                     %zparser_hold_ret . special_char;

    rdata_soa       := ( rd_dname . delim . rd_dname . delim . rd_int . delim
                     .  rd_timef . delim . rd_timef . delim . rd_timef . delim
                     .  rd_timef )
                     %zparser_hold_ret . special_char;

    rdata_wks       := ( rd_ipv4 . rd_services )
                     %zparser_hold_ret . special_char_end;

    rdata_hinfo     := ( rd_str . delim . rd_str )
                     %zparser_hold_ret . special_char;

    rdata_minfo     := ( rd_dname . delim . rd_dname )
                     %zparser_hold_ret . special_char;

    rdata_mx        := ( rd_int . delim . rd_dname )
                     %zparser_hold_ret . special_char;

    rdata_txt       := ( rd_str . (delim . rd_str)* . delim? )
                     %zparser_hold_ret . special_char_end;

    rdata_x25       := rd_str
                     %zparser_hold_ret . special_char;

    rdata_isdn      := ( rd_str . (delim . rd_str)? . delim? )
                     %zparser_hold_ret . special_char_end;

    rdata_nsap      := '0x' . rd_nsap
                     %zparser_hold_ret . special_char;

    rdata_sig       := ( rd_rrtype . delim . rd_algorithm . delim . rd_int 
                       . delim . rd_timef . delim . rd_datetime . delim
                       . rd_datetime . delim . rd_int . delim . rd_dname
                       . delim . rd_b64 )
                     %zparser_hold_ret . special_char_end;

    rdata_key       := ( rd_int . delim . rd_int . delim . rd_algorithm
                       . delim . rd_b64 )
                     %zparser_hold_ret . special_char_end;

    rdata_px        := ( rd_int . delim . rd_dname . delim . rd_dname )
                     %zparser_hold_ret . special_char;

    rdata_gpos      := ( rd_float . delim . rd_float . delim . rd_float )
                     %zparser_hold_ret . special_char;

    rdata_aaaa      := rd_ipv6
                     %zparser_hold_ret . special_char;

    rdata_loc       := rd_loc
                     %zparser_hold_ret . special_char_end;

    rdata_nxt       := ( rd_dname . rd_bitmap )
                     %zparser_hold_ret . special_char_end;

    rdata_srv       := ( (rd_int . delim){3} . rd_dname )
                     %zparser_hold_ret . special_char;

    rdata_naptr     := ( (rd_int . delim){2} . (rd_str . delim){3}
                       . rd_abs_dname )
                     %zparser_hold_ret . special_char;

    rdata_cert      := ( rd_algorithm . delim . rd_int . delim . rd_algorithm
                       . delim . rd_b64 )
                     %zparser_hold_ret . special_char_end;

    rdata_dname     := rd_abs_dname
                     %zparser_hold_ret . special_char;

    rdata_apl       := ( rd_apl? . ( delim . rd_apl)* . delim? )
                    %zparser_hold_ret . special_char_end;

    rdata_ds        := ( rd_int . delim . rd_algorithm . delim . rd_int
                       . delim . rd_hex . delim? )
                    %zparser_hold_ret . special_char_end;

    rdata_sshfp     := ( rd_int . delim . rd_int . delim . rd_hex . delim? )
                    %zparser_hold_ret . special_char_end;

    rdata_ipseckey_trail =
                         ( (rd_0 . delim . rd_0  . delim . rd_dot)
                         | (rd_0 . delim . rd_12 . delim . rd_dot   . delim . rd_b64)
                         | (rd_1 . delim . rd_0  . delim . rd_ipv4)
                         | (rd_1 . delim . rd_12 . delim . rd_ipv4  . delim . rd_b64)
                         | (rd_2 . delim . rd_0  . delim . rd_ipv6)
                         | (rd_2 . delim . rd_12 . delim . rd_ipv6  . delim . rd_b64)
                         | (rd_3 . delim . rd_0  . delim . rd_dname)
                         | (rd_3 . delim . rd_12 . delim . rd_dname . delim . rd_b64)
                         );

    rdata_ipseckey  := ( rd_int . delim . rdata_ipseckey_trail )
                    %zparser_hold_ret . special_char_end;

    rdata_dhcid     := rd_b64
                     %zparser_hold_ret . special_char_end;

    rdata_nsec3     := ( (rd_int . delim){3} . rd_hexlen . delim . rd_b32hex
                       . rd_bitmap )
                     %zparser_hold_ret . special_char_end;

    rdata_nsec3param := ( (rd_int . delim){3} . rd_hexlen )
                     %zparser_hold_ret . special_char;

    rdata            = (delim . ^special_char) @zparser_rdata_call;

    rrtype           =
                     ( "A"          @{parser->current_rr.type = DNS_TYPE_A;}
                     | "NS"         @{parser->current_rr.type = DNS_TYPE_NS;}
                     | "MD"         @{parser->current_rr.type = DNS_TYPE_MD;}
                     | "MF"         @{parser->current_rr.type = DNS_TYPE_MF;}
                     | "CNAME"      @{parser->current_rr.type = DNS_TYPE_CNAME;}
                     | "SOA"        @{parser->current_rr.type = DNS_TYPE_SOA;}
                     | "MB"         @{parser->current_rr.type = DNS_TYPE_MB;}
                     | "MG"         @{parser->current_rr.type = DNS_TYPE_MG;}
                     | "MR"         @{parser->current_rr.type = DNS_TYPE_MR;}
                     # "NULL"       @{parser->current_rr.type = DNS_TYPE_NULL;}
                     | "WKS"        @{parser->current_rr.type = DNS_TYPE_WKS;}
                     | "PTR"        @{parser->current_rr.type = DNS_TYPE_PTR;}
                     | "HINFO"      @{parser->current_rr.type = DNS_TYPE_HINFO;}
                     | "MINFO"      @{parser->current_rr.type = DNS_TYPE_MINFO;}
                     | "MX"         @{parser->current_rr.type = DNS_TYPE_MX;}
                     | "TXT"        @{parser->current_rr.type = DNS_TYPE_TXT;}
                     | "RP"         @{parser->current_rr.type = DNS_TYPE_RP;}
                     | "AFSDB"      @{parser->current_rr.type = DNS_TYPE_AFSDB;}
                     | "X25"        @{parser->current_rr.type = DNS_TYPE_X25;}
                     | "ISDN"       @{parser->current_rr.type = DNS_TYPE_ISDN;}
                     | "RT"         @{parser->current_rr.type = DNS_TYPE_RT;}
                     | "NSAP"       @{parser->current_rr.type = DNS_TYPE_NSAP;}
                     | "NSAP-PTR"   @{parser->current_rr.type = DNS_TYPE_NSAP_PTR;}
                     | "SIG"        @{parser->current_rr.type = DNS_TYPE_SIG;}
                     | "KEY"        @{parser->current_rr.type = DNS_TYPE_KEY;}
                     | "PX"         @{parser->current_rr.type = DNS_TYPE_PX;}
                     | "GPOS"       @{parser->current_rr.type = DNS_TYPE_GPOS;}
                     | "AAAA"       @{parser->current_rr.type = DNS_TYPE_AAAA;}
                     | "LOC"        @{parser->current_rr.type = DNS_TYPE_LOC;}
                     | "NXT"        @{parser->current_rr.type = DNS_TYPE_NXT;}
                     # "EID"        @{parser->current_rr.type = DNS_TYPE_EID;}
                     # "NIMLOC"     @{parser->current_rr.type = DNS_TYPE_NIMLOC;}
                     | "SRV"        @{parser->current_rr.type = DNS_TYPE_SRV;}
                     # "ATMA"       @{parser->current_rr.type = DNS_TYPE_ATMA;}
                     | "NAPTR"      @{parser->current_rr.type = DNS_TYPE_NAPTR;}
                     | "KX"         @{parser->current_rr.type = DNS_TYPE_KX;}
                     | "CERT"       @{parser->current_rr.type = DNS_TYPE_CERT;}
                     # "A6"         @{parser->current_rr.type = DNS_TYPE_A6;}
                     | "DNAME"      @{parser->current_rr.type = DNS_TYPE_DNAME;}
                     # "SINK"       @{parser->current_rr.type = DNS_TYPE_SINK;}
                     # "OPT"        @{parser->current_rr.type = DNS_TYPE_OPT;}
                     | "APL"        @{parser->current_rr.type = DNS_TYPE_APL;}
                     | "DS"         @{parser->current_rr.type = DNS_TYPE_DS;}
                     | "SSHFP"      @{parser->current_rr.type = DNS_TYPE_SSHFP;}
                     | "IPSECKEY"   @{parser->current_rr.type = DNS_TYPE_IPSECKEY;}
                     | "RRSIG"      @{parser->current_rr.type = DNS_TYPE_RRSIG;}
                     | "NSEC"       @{parser->current_rr.type = DNS_TYPE_NSEC;}
                     | "DNSKEY"     @{parser->current_rr.type = DNS_TYPE_DNSKEY;}
                     | "DHCID"      @{parser->current_rr.type = DNS_TYPE_DHCID;}
                     | "NSEC3"      @{parser->current_rr.type = DNS_TYPE_NSEC3;}
                     | "NSEC3PARAM" @{parser->current_rr.type = DNS_TYPE_NSEC3PARAM;}
                     )
                     $!zerror_rr_typedata;

    rrclass          = "IN" %zparser_rr_class;

    # RFC 1035: <rr> contents take one of the following forms:
    # [<TTL>] [<class>] <type> <RDATA>
    # [<class>] [<TTL>] <type> <RDATA>
    rr               =
                     ( owner >zparser_rr_start %zparser_rr_owner
                     . delim
                     . ( (rrclass . delim)? . (ttl %zparser_rr_ttl . delim)?
                       | (ttl %zparser_rr_ttl . delim)? . (rrclass . delim?)
                       )
                     . rrtype . rdata . endline
                     )
                     %zparser_rr_end
                     $!zerror_rr;

    ## Main line parsing, entries, directives, records.

    dollar_origin    = ("$ORIGIN" . delim . abs_dname . endline)
                     %zparser_dollar_origin
                     $!zerror_dollar_origin;

    dollar_ttl       = ("$TTL" . delim . ttl . endline)
                     %zparser_dollar_ttl
                     $!zerror_dollar_ttl;

    blank            = endline;

    # RFC 1035: The following entries are defined:
    # blank:         <blank>[<comment>]
    # rr:            <domain-name><rr> [<comment>]
    # rr:            <blank><rr> [<comment>]
    # dollar_origin: $ORIGIN <domain-name> [<comment>]
    # RFC 2038: The Master File format is extended to include the following...
    # blank:         $TTL <TTL> [comment]
    entry            =
                     ( blank
                     | rr
                     | dollar_origin
                     | dollar_ttl
                     ) $!zerror_entry;

    line_error      := [^\n]* @zparser_reinitialize
                     . newline @zparser_goto_main;

    # RFC 1035: The format of these files is a sequence of entries.
    main            := entry*;

}%%


#line 1 "rzonec.rl"
/*
 * zonec.rl -- zone compiler based on ragel.
 *
 * Copyright (c) 2013, Matthijs Mekking, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "rzonec/rzonec.h"
#include "util/log.h"
#include "util/status.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAX_BUFSIZE 1024
#define DEFAULT_TTL 3600

static zparser_type* parser;

static const char* logstr = "rzonec";


/**
 * State machine.
 *
 */

#line 40 "rzonec.c"
static const int zparser_start = 810;
static const int zparser_first_final = 810;
static const int zparser_error = 0;

static const int zparser_en_line = 809;
static const int zparser_en_main = 810;


#line 42 "rzonec.rl"



/**
 * Create parser.
 *
 */
int
zparser_create()
{
    region_type* r = region_create();
    region_type* rrr = region_create();
    if (!r || !rrr) {
        return 0;
    }
    parser = (zparser_type*) region_alloc(r, sizeof(zparser_type));
    parser->tmp_rdata = (rdata_type*) region_alloc(r, DNS_RDATA_MAX *
        sizeof(rdata_type));
    parser->region = r;
    parser->rr_region = rrr;
    parser->origin = NULL;
    parser->ttl = DEFAULT_TTL;
    parser->klass = DNS_CLASS_IN;
    parser->line = 1;
    parser->comments = 0;
    parser->numrrs = 0;
    parser->totalerrors = 0;
    parser->rdsize = 0;
    parser->number = 0;
    parser->seconds = 0;
    parser->dname = NULL;
    parser->label = NULL;
    parser->dname_size = 0;
    parser->label_head = 0;
    parser->label_count = 0;
    /* resource records */
    parser->current_rr.ttl = DEFAULT_TTL;
    parser->current_rr.type = 0;
    parser->current_rr.klass = DNS_CLASS_IN;
    parser->current_rr.rdlen = 0;
    parser->current_rr.rdata = parser->tmp_rdata;
    return 1;
}


/**
 * Cleanup parser.
 *
 */
void
zparser_cleanup(void)
{
    region_cleanup(parser->rr_region);
    region_cleanup(parser->region);
    parser = NULL;
    return;
}


/**
 * Reads the specified zone into the memory.
 *
 */
int
zparser_read_zone(const char* file)
{
    char buf[MAX_BUFSIZE];
    ssize_t r;
    int fd = open(file, O_RDONLY);
    if (fd == -1) {
        return ODS_STATUS_FOPENERR;
    }
    r = read(fd, buf, MAX_BUFSIZE);
    ods_log_debug("[%s] read %lu bytes.\n", logstr, r);
    if (r > 0) {
        int cs = 0;
/*        int res = 0; */
        char* p = &buf[0];
        char* pe = p + r + 1;
        char* eof = NULL;
        
#line 131 "rzonec.c"
	{
	cs = zparser_start;
	}

#line 123 "rzonec.rl"
        
#line 138 "rzonec.c"
	{
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
tr154:
#line 215 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = '\0';
        if (!zonec_rdata_add(parser->rr_region, &parser->current_rr,
            DNS_RDATA_IPV4, parser->rdbuf, parser->rdsize)) {
            fprintf(stderr, "[zparser] error: line %d: bad IPv4 address "
                "'%s'\n", parser->line, parser->rdbuf);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 191 "zparser.rl"
	{
        int i;
        zparser_process_rr();
        dname_print(stderr, parser->current_rr.owner);
        fprintf(stderr, "\t%u", parser->current_rr.ttl);
        fprintf(stderr, "\t");
        rr_print_class(stderr, parser->current_rr.klass);
        fprintf(stderr, "\t");
        rr_print_rrtype(stderr, parser->current_rr.type);
        for (i = 0; i < parser->current_rr.rdlen; i++) {
            fprintf(stderr, " ");
            rdata_print(stderr, &parser->current_rr.rdata[i],
                parser->current_rr.type, i);
        }
        fprintf(stderr, "\n");
    }
#line 17 "zparser.rl"
	{
        parser->line++;
    }
	goto st810;
tr159:
#line 17 "zparser.rl"
	{
        parser->line++;
    }
	goto st810;
tr162:
#line 20 "zparser.rl"
	{
        parser->comments++;
    }
#line 17 "zparser.rl"
	{
        parser->line++;
    }
	goto st810;
tr577:
#line 117 "zparser.rl"
	{
        int i;
        parser->dname_size++;
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
        } else {
            fprintf(stderr, "[zparser] line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
        while (1) {
            if (label_is_pointer(parser->label)) {
                fprintf(stderr, "[zparser] line %d: domain has pointer label\n",
                    parser->line);
                parser->totalerrors++;
                p--; {goto st809;}
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
            fprintf(stderr, "[zparser] line %d: domain create failed\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
        parser->dname->size = parser->dname_size;
        parser->dname->label_count = parser->label_count;
        memcpy((uint8_t *) dname_label_offsets(parser->dname),
            parser->label_offsets, parser->label_count * sizeof(uint8_t));
        memcpy((uint8_t *) dname_name(parser->dname), parser->dname_wire,
            parser->dname_size * sizeof(uint8_t));
    }
#line 167 "zparser.rl"
	{
        parser->origin = parser->dname;
        fprintf(stderr, "[zparser] line %d: origin ", parser->line);
        dname_print(stderr, parser->origin);
        fprintf(stderr, "\n");
    }
#line 17 "zparser.rl"
	{
        parser->line++;
    }
	goto st810;
tr844:
#line 59 "zparser.rl"
	{
        parser->seconds += parser->number;
        parser->number = parser->seconds;
    }
#line 63 "zparser.rl"
	{
        parser->ttl = parser->number;
        fprintf(stderr, "[zparser] line %d: ttl %u\n", parser->line,
            (unsigned int) parser->ttl);
    }
#line 17 "zparser.rl"
	{
        parser->line++;
    }
	goto st810;
st810:
	if ( ++p == pe )
		goto _test_eof810;
case 810:
#line 279 "rzonec.c"
	switch( (*p) ) {
		case 9: goto st76;
		case 10: goto tr159;
		case 32: goto st76;
		case 34: goto tr852;
		case 36: goto st413;
		case 46: goto tr854;
		case 59: goto st77;
		case 64: goto tr855;
		case 92: goto tr856;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr852;
	} else if ( (*p) >= 11 )
		goto tr852;
	goto tr851;
tr179:
#line 70 "zparser.rl"
	{
        parser->label_head = parser->dname_size;
        parser->dname_size++;
    }
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st1;
tr851:
#line 174 "zparser.rl"
	{
        parser->current_rr.owner = NULL;
        parser->current_rr.ttl = parser->ttl;
        parser->current_rr.klass = parser->klass;
        parser->current_rr.type = 0;
        parser->current_rr.rdlen = 0;
        parser->current_rr.rdata = parser->tmp_rdata;
    }
#line 104 "zparser.rl"
	{
        bzero(&parser->dname_wire[0], DNAME_MAXLEN);
        bzero(&parser->label_offsets[0], DNAME_MAXLEN);
        parser->dname_size = 0;
        parser->label_count = 0;
        parser->label = parser->dname_wire;
    }
#line 70 "zparser.rl"
	{
        parser->label_head = parser->dname_size;
        parser->dname_size++;
    }
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st1;
st1:
	if ( ++p == pe )
		goto _test_eof1;
case 1:
#line 356 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st100;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr0;
tr0:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st2;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
#line 391 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st102;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr5;
tr5:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st3;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
#line 426 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st104;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr7;
tr7:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st4;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
#line 461 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st106;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr9;
tr9:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 496 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st108;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr11;
tr11:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st6;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
#line 531 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st110;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr13;
tr13:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st7;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
#line 566 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st112;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr15;
tr15:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st8;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
#line 601 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st114;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr17;
tr17:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 636 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st116;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr19;
tr19:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 671 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st118;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr21;
tr21:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st11;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
#line 706 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st120;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr23;
tr23:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st12;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
#line 741 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st122;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr25;
tr25:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st13;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
#line 776 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st124;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr27;
tr27:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st14;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
#line 811 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st126;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr29;
tr29:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st15;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
#line 846 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st128;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr31;
tr31:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st16;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
#line 881 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st130;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr33;
tr33:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st17;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
#line 916 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st132;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr35;
tr35:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st18;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
#line 951 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st134;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr37;
tr37:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st19;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
#line 986 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st136;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr39;
tr39:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st20;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
#line 1021 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st138;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr41;
tr41:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st21;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
#line 1056 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st140;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr43;
tr43:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st22;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
#line 1091 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st142;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr45;
tr45:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st23;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
#line 1126 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st144;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr47;
tr47:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st24;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
#line 1161 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st146;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr49;
tr49:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st25;
st25:
	if ( ++p == pe )
		goto _test_eof25;
case 25:
#line 1196 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st148;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr51;
tr51:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st26;
st26:
	if ( ++p == pe )
		goto _test_eof26;
case 26:
#line 1231 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st150;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr53;
tr53:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st27;
st27:
	if ( ++p == pe )
		goto _test_eof27;
case 27:
#line 1266 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st152;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr55;
tr55:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st28;
st28:
	if ( ++p == pe )
		goto _test_eof28;
case 28:
#line 1301 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st154;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr57;
tr57:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st29;
st29:
	if ( ++p == pe )
		goto _test_eof29;
case 29:
#line 1336 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st156;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr59;
tr59:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st30;
st30:
	if ( ++p == pe )
		goto _test_eof30;
case 30:
#line 1371 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st158;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr61;
tr61:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st31;
st31:
	if ( ++p == pe )
		goto _test_eof31;
case 31:
#line 1406 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st160;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr63;
tr63:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st32;
st32:
	if ( ++p == pe )
		goto _test_eof32;
case 32:
#line 1441 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st162;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr65;
tr65:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st33;
st33:
	if ( ++p == pe )
		goto _test_eof33;
case 33:
#line 1476 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st164;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr67;
tr67:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st34;
st34:
	if ( ++p == pe )
		goto _test_eof34;
case 34:
#line 1511 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st166;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr69;
tr69:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st35;
st35:
	if ( ++p == pe )
		goto _test_eof35;
case 35:
#line 1546 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st168;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr71;
tr71:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st36;
st36:
	if ( ++p == pe )
		goto _test_eof36;
case 36:
#line 1581 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st170;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr73;
tr73:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st37;
st37:
	if ( ++p == pe )
		goto _test_eof37;
case 37:
#line 1616 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st172;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr75;
tr75:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st38;
st38:
	if ( ++p == pe )
		goto _test_eof38;
case 38:
#line 1651 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st174;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr77;
tr77:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st39;
st39:
	if ( ++p == pe )
		goto _test_eof39;
case 39:
#line 1686 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st176;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr79;
tr79:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st40;
st40:
	if ( ++p == pe )
		goto _test_eof40;
case 40:
#line 1721 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st178;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr81;
tr81:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st41;
st41:
	if ( ++p == pe )
		goto _test_eof41;
case 41:
#line 1756 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st180;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr83;
tr83:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st42;
st42:
	if ( ++p == pe )
		goto _test_eof42;
case 42:
#line 1791 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st182;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr85;
tr85:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st43;
st43:
	if ( ++p == pe )
		goto _test_eof43;
case 43:
#line 1826 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st184;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr87;
tr87:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st44;
st44:
	if ( ++p == pe )
		goto _test_eof44;
case 44:
#line 1861 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st186;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr89;
tr89:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st45;
st45:
	if ( ++p == pe )
		goto _test_eof45;
case 45:
#line 1896 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st188;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr91;
tr91:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st46;
st46:
	if ( ++p == pe )
		goto _test_eof46;
case 46:
#line 1931 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st190;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr93;
tr93:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st47;
st47:
	if ( ++p == pe )
		goto _test_eof47;
case 47:
#line 1966 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st192;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr95;
tr95:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st48;
st48:
	if ( ++p == pe )
		goto _test_eof48;
case 48:
#line 2001 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st194;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr97;
tr97:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st49;
st49:
	if ( ++p == pe )
		goto _test_eof49;
case 49:
#line 2036 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st196;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr99;
tr99:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st50;
st50:
	if ( ++p == pe )
		goto _test_eof50;
case 50:
#line 2071 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st198;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr101;
tr101:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st51;
st51:
	if ( ++p == pe )
		goto _test_eof51;
case 51:
#line 2106 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st200;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr103;
tr103:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st52;
st52:
	if ( ++p == pe )
		goto _test_eof52;
case 52:
#line 2141 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st202;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr105;
tr105:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st53;
st53:
	if ( ++p == pe )
		goto _test_eof53;
case 53:
#line 2176 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st204;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr107;
tr107:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st54;
st54:
	if ( ++p == pe )
		goto _test_eof54;
case 54:
#line 2211 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st206;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr109;
tr109:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st55;
st55:
	if ( ++p == pe )
		goto _test_eof55;
case 55:
#line 2246 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st208;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr111;
tr111:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st56;
st56:
	if ( ++p == pe )
		goto _test_eof56;
case 56:
#line 2281 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st210;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr113;
tr113:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st57;
st57:
	if ( ++p == pe )
		goto _test_eof57;
case 57:
#line 2316 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st212;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr115;
tr115:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st58;
st58:
	if ( ++p == pe )
		goto _test_eof58;
case 58:
#line 2351 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st214;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr117;
tr117:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st59;
st59:
	if ( ++p == pe )
		goto _test_eof59;
case 59:
#line 2386 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st216;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr119;
tr119:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st60;
st60:
	if ( ++p == pe )
		goto _test_eof60;
case 60:
#line 2421 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st218;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr121;
tr121:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st61;
st61:
	if ( ++p == pe )
		goto _test_eof61;
case 61:
#line 2456 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st220;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr123;
tr123:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st62;
st62:
	if ( ++p == pe )
		goto _test_eof62;
case 62:
#line 2491 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr3;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto st222;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr125;
tr125:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st63;
st63:
	if ( ++p == pe )
		goto _test_eof63;
case 63:
#line 2526 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 46: goto tr3;
	}
	goto tr2;
tr2:
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr127:
#line 281 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr typedata\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr132:
#line 269 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: ttl time format error\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr140:
#line 287 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad IPv4 address format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 281 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr typedata\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr152:
#line 287 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad IPv4 address format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 281 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr typedata\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 234 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad entry\n", parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr157:
#line 234 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad entry\n", parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr168:
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr184:
#line 257 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad escape in label\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 251 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad octet in label\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr185:
#line 257 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad escape in label\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr310:
#line 251 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad octet in label\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr447:
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 239 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad origin directive\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr578:
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 239 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad origin directive\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 234 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad entry\n", parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr583:
#line 257 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad escape in label\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 251 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad octet in label\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 239 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad origin directive\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr584:
#line 257 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad escape in label\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 239 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad origin directive\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr709:
#line 251 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad octet in label\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 239 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad origin directive\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr836:
#line 239 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad origin directive\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 234 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad entry\n", parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr840:
#line 245 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad ttl directive\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr842:
#line 269 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: ttl time format error\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 245 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad ttl directive\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 234 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad entry\n", parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
tr852:
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 234 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad entry\n", parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	goto st0;
#line 2908 "rzonec.c"
st0:
cs = 0;
	goto _out;
tr1:
#line 100 "zparser.rl"
	{
        parser->dname_wire[parser->label_head] =
            (parser->dname_size - parser->label_head - 1);
    }
#line 117 "zparser.rl"
	{
        int i;
        parser->dname_size++;
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
        } else {
            fprintf(stderr, "[zparser] line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
        while (1) {
            if (label_is_pointer(parser->label)) {
                fprintf(stderr, "[zparser] line %d: domain has pointer label\n",
                    parser->line);
                parser->totalerrors++;
                p--; {goto st809;}
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
            fprintf(stderr, "[zparser] line %d: domain create failed\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
        parser->dname->size = parser->dname_size;
        parser->dname->label_count = parser->label_count;
        memcpy((uint8_t *) dname_label_offsets(parser->dname),
            parser->label_offsets, parser->label_count * sizeof(uint8_t));
        memcpy((uint8_t *) dname_name(parser->dname), parser->dname_wire,
            parser->dname_size * sizeof(uint8_t));
    }
#line 182 "zparser.rl"
	{
        parser->current_rr.owner = parser->dname;
    }
	goto st64;
tr180:
#line 117 "zparser.rl"
	{
        int i;
        parser->dname_size++;
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
        } else {
            fprintf(stderr, "[zparser] line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
        while (1) {
            if (label_is_pointer(parser->label)) {
                fprintf(stderr, "[zparser] line %d: domain has pointer label\n",
                    parser->line);
                parser->totalerrors++;
                p--; {goto st809;}
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
            fprintf(stderr, "[zparser] line %d: domain create failed\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
        parser->dname->size = parser->dname_size;
        parser->dname->label_count = parser->label_count;
        memcpy((uint8_t *) dname_label_offsets(parser->dname),
            parser->label_offsets, parser->label_count * sizeof(uint8_t));
        memcpy((uint8_t *) dname_name(parser->dname), parser->dname_wire,
            parser->dname_size * sizeof(uint8_t));
    }
#line 182 "zparser.rl"
	{
        parser->current_rr.owner = parser->dname;
    }
	goto st64;
tr848:
#line 182 "zparser.rl"
	{
        parser->current_rr.owner = parser->dname;
    }
	goto st64;
st64:
	if ( ++p == pe )
		goto _test_eof64;
case 64:
#line 3041 "rzonec.c"
	switch( (*p) ) {
		case 9: goto st64;
		case 32: goto st64;
		case 65: goto st67;
		case 73: goto st91;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr129;
	goto tr127;
tr129:
#line 55 "zparser.rl"
	{
        parser->seconds = 0;
        parser->number = 0;
    }
#line 25 "zparser.rl"
	{
        parser->number *= 10;
        parser->number += ((*p) - '0');
    }
	goto st65;
tr134:
#line 25 "zparser.rl"
	{
        parser->number *= 10;
        parser->number += ((*p) - '0');
    }
	goto st65;
st65:
	if ( ++p == pe )
		goto _test_eof65;
case 65:
#line 3074 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr133;
		case 32: goto tr133;
		case 68: goto tr135;
		case 72: goto tr135;
		case 77: goto tr135;
		case 83: goto tr135;
		case 87: goto tr135;
		case 100: goto tr135;
		case 104: goto tr135;
		case 109: goto tr135;
		case 115: goto tr135;
		case 119: goto tr135;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr134;
	goto tr132;
tr133:
#line 59 "zparser.rl"
	{
        parser->seconds += parser->number;
        parser->number = parser->seconds;
    }
	goto st66;
st66:
	if ( ++p == pe )
		goto _test_eof66;
case 66:
#line 3103 "rzonec.c"
	switch( (*p) ) {
		case 9: goto st66;
		case 32: goto st66;
		case 65: goto tr137;
		case 73: goto tr138;
	}
	goto tr127;
tr137:
#line 188 "zparser.rl"
	{
        parser->current_rr.ttl = parser->number;
    }
	goto st67;
tr171:
#line 185 "zparser.rl"
	{
        parser->current_rr.klass = DNS_CLASS_IN;
    }
	goto st67;
st67:
	if ( ++p == pe )
		goto _test_eof67;
case 67:
#line 3127 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr139;
		case 32: goto tr139;
	}
	goto tr127;
tr139:
#line 381 "zparser.rl"
	{parser->current_rr.type = DNS_TYPE_A;}
	goto st68;
st68:
	if ( ++p == pe )
		goto _test_eof68;
case 68:
#line 3141 "rzonec.c"
	switch( (*p) ) {
		case 9: goto st68;
		case 32: goto st68;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr142;
	goto tr140;
tr142:
#line 207 "zparser.rl"
	{
        bzero(&parser->rdbuf[0], DNS_RDLEN_MAX);
        parser->rdsize = 0;
    }
#line 211 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = (*p);
        parser->rdsize++;
    }
	goto st69;
st69:
	if ( ++p == pe )
		goto _test_eof69;
case 69:
#line 3165 "rzonec.c"
	if ( (*p) == 46 )
		goto tr143;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr144;
	goto tr140;
tr143:
#line 211 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = (*p);
        parser->rdsize++;
    }
	goto st70;
st70:
	if ( ++p == pe )
		goto _test_eof70;
case 70:
#line 3182 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr145;
	goto tr140;
tr145:
#line 211 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = (*p);
        parser->rdsize++;
    }
	goto st71;
st71:
	if ( ++p == pe )
		goto _test_eof71;
case 71:
#line 3197 "rzonec.c"
	if ( (*p) == 46 )
		goto tr146;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr147;
	goto tr140;
tr146:
#line 211 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = (*p);
        parser->rdsize++;
    }
	goto st72;
st72:
	if ( ++p == pe )
		goto _test_eof72;
case 72:
#line 3214 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr148;
	goto tr140;
tr148:
#line 211 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = (*p);
        parser->rdsize++;
    }
	goto st73;
st73:
	if ( ++p == pe )
		goto _test_eof73;
case 73:
#line 3229 "rzonec.c"
	if ( (*p) == 46 )
		goto tr149;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr150;
	goto tr140;
tr149:
#line 211 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = (*p);
        parser->rdsize++;
    }
	goto st74;
st74:
	if ( ++p == pe )
		goto _test_eof74;
case 74:
#line 3246 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr151;
	goto tr140;
tr151:
#line 211 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = (*p);
        parser->rdsize++;
    }
	goto st75;
st75:
	if ( ++p == pe )
		goto _test_eof75;
case 75:
#line 3261 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr153;
		case 10: goto tr154;
		case 32: goto tr153;
		case 59: goto tr156;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr155;
	goto tr152;
tr153:
#line 215 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = '\0';
        if (!zonec_rdata_add(parser->rr_region, &parser->current_rr,
            DNS_RDATA_IPV4, parser->rdbuf, parser->rdsize)) {
            fprintf(stderr, "[zparser] error: line %d: bad IPv4 address "
                "'%s'\n", parser->line, parser->rdbuf);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 191 "zparser.rl"
	{
        int i;
        zparser_process_rr();
        dname_print(stderr, parser->current_rr.owner);
        fprintf(stderr, "\t%u", parser->current_rr.ttl);
        fprintf(stderr, "\t");
        rr_print_class(stderr, parser->current_rr.klass);
        fprintf(stderr, "\t");
        rr_print_rrtype(stderr, parser->current_rr.type);
        for (i = 0; i < parser->current_rr.rdlen; i++) {
            fprintf(stderr, " ");
            rdata_print(stderr, &parser->current_rr.rdata[i],
                parser->current_rr.type, i);
        }
        fprintf(stderr, "\n");
    }
	goto st76;
tr576:
#line 117 "zparser.rl"
	{
        int i;
        parser->dname_size++;
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
        } else {
            fprintf(stderr, "[zparser] line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
        while (1) {
            if (label_is_pointer(parser->label)) {
                fprintf(stderr, "[zparser] line %d: domain has pointer label\n",
                    parser->line);
                parser->totalerrors++;
                p--; {goto st809;}
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
            fprintf(stderr, "[zparser] line %d: domain create failed\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
        parser->dname->size = parser->dname_size;
        parser->dname->label_count = parser->label_count;
        memcpy((uint8_t *) dname_label_offsets(parser->dname),
            parser->label_offsets, parser->label_count * sizeof(uint8_t));
        memcpy((uint8_t *) dname_name(parser->dname), parser->dname_wire,
            parser->dname_size * sizeof(uint8_t));
    }
#line 167 "zparser.rl"
	{
        parser->origin = parser->dname;
        fprintf(stderr, "[zparser] line %d: origin ", parser->line);
        dname_print(stderr, parser->origin);
        fprintf(stderr, "\n");
    }
	goto st76;
tr843:
#line 59 "zparser.rl"
	{
        parser->seconds += parser->number;
        parser->number = parser->seconds;
    }
#line 63 "zparser.rl"
	{
        parser->ttl = parser->number;
        fprintf(stderr, "[zparser] line %d: ttl %u\n", parser->line,
            (unsigned int) parser->ttl);
    }
	goto st76;
st76:
	if ( ++p == pe )
		goto _test_eof76;
case 76:
#line 3378 "rzonec.c"
	switch( (*p) ) {
		case 9: goto st76;
		case 10: goto tr159;
		case 32: goto st76;
		case 59: goto st77;
	}
	goto tr157;
tr156:
#line 215 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = '\0';
        if (!zonec_rdata_add(parser->rr_region, &parser->current_rr,
            DNS_RDATA_IPV4, parser->rdbuf, parser->rdsize)) {
            fprintf(stderr, "[zparser] error: line %d: bad IPv4 address "
                "'%s'\n", parser->line, parser->rdbuf);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 191 "zparser.rl"
	{
        int i;
        zparser_process_rr();
        dname_print(stderr, parser->current_rr.owner);
        fprintf(stderr, "\t%u", parser->current_rr.ttl);
        fprintf(stderr, "\t");
        rr_print_class(stderr, parser->current_rr.klass);
        fprintf(stderr, "\t");
        rr_print_rrtype(stderr, parser->current_rr.type);
        for (i = 0; i < parser->current_rr.rdlen; i++) {
            fprintf(stderr, " ");
            rdata_print(stderr, &parser->current_rr.rdata[i],
                parser->current_rr.type, i);
        }
        fprintf(stderr, "\n");
    }
	goto st77;
tr579:
#line 117 "zparser.rl"
	{
        int i;
        parser->dname_size++;
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
        } else {
            fprintf(stderr, "[zparser] line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
        while (1) {
            if (label_is_pointer(parser->label)) {
                fprintf(stderr, "[zparser] line %d: domain has pointer label\n",
                    parser->line);
                parser->totalerrors++;
                p--; {goto st809;}
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
            fprintf(stderr, "[zparser] line %d: domain create failed\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
        parser->dname->size = parser->dname_size;
        parser->dname->label_count = parser->label_count;
        memcpy((uint8_t *) dname_label_offsets(parser->dname),
            parser->label_offsets, parser->label_count * sizeof(uint8_t));
        memcpy((uint8_t *) dname_name(parser->dname), parser->dname_wire,
            parser->dname_size * sizeof(uint8_t));
    }
#line 167 "zparser.rl"
	{
        parser->origin = parser->dname;
        fprintf(stderr, "[zparser] line %d: origin ", parser->line);
        dname_print(stderr, parser->origin);
        fprintf(stderr, "\n");
    }
	goto st77;
tr846:
#line 59 "zparser.rl"
	{
        parser->seconds += parser->number;
        parser->number = parser->seconds;
    }
#line 63 "zparser.rl"
	{
        parser->ttl = parser->number;
        fprintf(stderr, "[zparser] line %d: ttl %u\n", parser->line,
            (unsigned int) parser->ttl);
    }
	goto st77;
st77:
	if ( ++p == pe )
		goto _test_eof77;
case 77:
#line 3493 "rzonec.c"
	if ( (*p) == 10 )
		goto tr162;
	goto tr161;
tr161:
#line 20 "zparser.rl"
	{
        parser->comments++;
    }
	goto st78;
st78:
	if ( ++p == pe )
		goto _test_eof78;
case 78:
#line 3507 "rzonec.c"
	if ( (*p) == 10 )
		goto tr159;
	goto st78;
tr155:
#line 211 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = (*p);
        parser->rdsize++;
    }
	goto st79;
st79:
	if ( ++p == pe )
		goto _test_eof79;
case 79:
#line 3522 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr153;
		case 10: goto tr154;
		case 32: goto tr153;
		case 59: goto tr156;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr164;
	goto tr152;
tr164:
#line 211 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = (*p);
        parser->rdsize++;
    }
	goto st80;
st80:
	if ( ++p == pe )
		goto _test_eof80;
case 80:
#line 3543 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr153;
		case 10: goto tr154;
		case 32: goto tr153;
		case 59: goto tr156;
	}
	goto tr152;
tr150:
#line 211 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = (*p);
        parser->rdsize++;
    }
	goto st81;
st81:
	if ( ++p == pe )
		goto _test_eof81;
case 81:
#line 3562 "rzonec.c"
	if ( (*p) == 46 )
		goto tr149;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr165;
	goto tr140;
tr165:
#line 211 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = (*p);
        parser->rdsize++;
    }
	goto st82;
st82:
	if ( ++p == pe )
		goto _test_eof82;
case 82:
#line 3579 "rzonec.c"
	if ( (*p) == 46 )
		goto tr149;
	goto tr140;
tr147:
#line 211 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = (*p);
        parser->rdsize++;
    }
	goto st83;
st83:
	if ( ++p == pe )
		goto _test_eof83;
case 83:
#line 3594 "rzonec.c"
	if ( (*p) == 46 )
		goto tr146;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr166;
	goto tr140;
tr166:
#line 211 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = (*p);
        parser->rdsize++;
    }
	goto st84;
st84:
	if ( ++p == pe )
		goto _test_eof84;
case 84:
#line 3611 "rzonec.c"
	if ( (*p) == 46 )
		goto tr146;
	goto tr140;
tr144:
#line 211 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = (*p);
        parser->rdsize++;
    }
	goto st85;
st85:
	if ( ++p == pe )
		goto _test_eof85;
case 85:
#line 3626 "rzonec.c"
	if ( (*p) == 46 )
		goto tr143;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr167;
	goto tr140;
tr167:
#line 211 "zparser.rl"
	{
        parser->rdbuf[parser->rdsize] = (*p);
        parser->rdsize++;
    }
	goto st86;
st86:
	if ( ++p == pe )
		goto _test_eof86;
case 86:
#line 3643 "rzonec.c"
	if ( (*p) == 46 )
		goto tr143;
	goto tr140;
tr138:
#line 188 "zparser.rl"
	{
        parser->current_rr.ttl = parser->number;
    }
	goto st87;
st87:
	if ( ++p == pe )
		goto _test_eof87;
case 87:
#line 3657 "rzonec.c"
	if ( (*p) == 78 )
		goto st88;
	goto tr168;
st88:
	if ( ++p == pe )
		goto _test_eof88;
case 88:
	switch( (*p) ) {
		case 9: goto st89;
		case 32: goto st89;
	}
	goto tr168;
st89:
	if ( ++p == pe )
		goto _test_eof89;
case 89:
	switch( (*p) ) {
		case 9: goto st89;
		case 32: goto st89;
		case 65: goto tr171;
	}
	goto tr127;
tr135:
#line 29 "zparser.rl"
	{
        switch ((*p)) {
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
	goto st90;
st90:
	if ( ++p == pe )
		goto _test_eof90;
case 90:
#line 3713 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr133;
		case 32: goto tr133;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr134;
	goto tr132;
st91:
	if ( ++p == pe )
		goto _test_eof91;
case 91:
	if ( (*p) == 78 )
		goto st92;
	goto tr168;
st92:
	if ( ++p == pe )
		goto _test_eof92;
case 92:
	switch( (*p) ) {
		case 9: goto st93;
		case 32: goto st93;
	}
	goto tr168;
st93:
	if ( ++p == pe )
		goto _test_eof93;
case 93:
	switch( (*p) ) {
		case 9: goto st93;
		case 32: goto st93;
		case 65: goto tr171;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr174;
	goto tr127;
tr176:
#line 25 "zparser.rl"
	{
        parser->number *= 10;
        parser->number += ((*p) - '0');
    }
	goto st94;
tr174:
#line 185 "zparser.rl"
	{
        parser->current_rr.klass = DNS_CLASS_IN;
    }
#line 55 "zparser.rl"
	{
        parser->seconds = 0;
        parser->number = 0;
    }
#line 25 "zparser.rl"
	{
        parser->number *= 10;
        parser->number += ((*p) - '0');
    }
	goto st94;
st94:
	if ( ++p == pe )
		goto _test_eof94;
case 94:
#line 3776 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr175;
		case 32: goto tr175;
		case 68: goto tr177;
		case 72: goto tr177;
		case 77: goto tr177;
		case 83: goto tr177;
		case 87: goto tr177;
		case 100: goto tr177;
		case 104: goto tr177;
		case 109: goto tr177;
		case 115: goto tr177;
		case 119: goto tr177;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr176;
	goto tr132;
tr175:
#line 59 "zparser.rl"
	{
        parser->seconds += parser->number;
        parser->number = parser->seconds;
    }
	goto st95;
st95:
	if ( ++p == pe )
		goto _test_eof95;
case 95:
#line 3805 "rzonec.c"
	switch( (*p) ) {
		case 9: goto st95;
		case 32: goto st95;
		case 65: goto tr137;
	}
	goto tr127;
tr177:
#line 29 "zparser.rl"
	{
        switch ((*p)) {
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
	goto st96;
st96:
	if ( ++p == pe )
		goto _test_eof96;
case 96:
#line 3845 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr175;
		case 32: goto tr175;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr176;
	goto tr132;
tr3:
#line 100 "zparser.rl"
	{
        parser->dname_wire[parser->label_head] =
            (parser->dname_size - parser->label_head - 1);
    }
	goto st97;
st97:
	if ( ++p == pe )
		goto _test_eof97;
case 97:
#line 3864 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr180;
		case 32: goto tr180;
		case 34: goto tr2;
		case 36: goto tr2;
		case 46: goto tr2;
		case 59: goto tr2;
		case 64: goto tr2;
		case 92: goto tr181;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr2;
	} else if ( (*p) >= 10 )
		goto tr2;
	goto tr179;
tr181:
#line 70 "zparser.rl"
	{
        parser->label_head = parser->dname_size;
        parser->dname_size++;
    }
	goto st98;
tr856:
#line 174 "zparser.rl"
	{
        parser->current_rr.owner = NULL;
        parser->current_rr.ttl = parser->ttl;
        parser->current_rr.klass = parser->klass;
        parser->current_rr.type = 0;
        parser->current_rr.rdlen = 0;
        parser->current_rr.rdata = parser->tmp_rdata;
    }
#line 104 "zparser.rl"
	{
        bzero(&parser->dname_wire[0], DNAME_MAXLEN);
        bzero(&parser->label_offsets[0], DNAME_MAXLEN);
        parser->dname_size = 0;
        parser->label_count = 0;
        parser->label = parser->dname_wire;
    }
#line 70 "zparser.rl"
	{
        parser->label_head = parser->dname_size;
        parser->dname_size++;
    }
	goto st98;
st98:
	if ( ++p == pe )
		goto _test_eof98;
case 98:
#line 3916 "rzonec.c"
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr183;
	goto tr182;
tr182:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st99;
st99:
	if ( ++p == pe )
		goto _test_eof99;
case 99:
#line 3941 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st100;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr0;
st100:
	if ( ++p == pe )
		goto _test_eof100;
case 100:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr187;
	goto tr186;
tr186:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st101;
st101:
	if ( ++p == pe )
		goto _test_eof101;
case 101:
#line 3986 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st102;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr5;
st102:
	if ( ++p == pe )
		goto _test_eof102;
case 102:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr189;
	goto tr188;
tr188:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st103;
st103:
	if ( ++p == pe )
		goto _test_eof103;
case 103:
#line 4031 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st104;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr7;
st104:
	if ( ++p == pe )
		goto _test_eof104;
case 104:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr191;
	goto tr190;
tr190:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st105;
st105:
	if ( ++p == pe )
		goto _test_eof105;
case 105:
#line 4076 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st106;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr9;
st106:
	if ( ++p == pe )
		goto _test_eof106;
case 106:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr193;
	goto tr192;
tr192:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st107;
st107:
	if ( ++p == pe )
		goto _test_eof107;
case 107:
#line 4121 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st108;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr11;
st108:
	if ( ++p == pe )
		goto _test_eof108;
case 108:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr195;
	goto tr194;
tr194:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st109;
st109:
	if ( ++p == pe )
		goto _test_eof109;
case 109:
#line 4166 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st110;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr13;
st110:
	if ( ++p == pe )
		goto _test_eof110;
case 110:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr197;
	goto tr196;
tr196:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st111;
st111:
	if ( ++p == pe )
		goto _test_eof111;
case 111:
#line 4211 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st112;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr15;
st112:
	if ( ++p == pe )
		goto _test_eof112;
case 112:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr199;
	goto tr198;
tr198:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st113;
st113:
	if ( ++p == pe )
		goto _test_eof113;
case 113:
#line 4256 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st114;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr17;
st114:
	if ( ++p == pe )
		goto _test_eof114;
case 114:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr201;
	goto tr200;
tr200:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st115;
st115:
	if ( ++p == pe )
		goto _test_eof115;
case 115:
#line 4301 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st116;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr19;
st116:
	if ( ++p == pe )
		goto _test_eof116;
case 116:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr203;
	goto tr202;
tr202:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st117;
st117:
	if ( ++p == pe )
		goto _test_eof117;
case 117:
#line 4346 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st118;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr21;
st118:
	if ( ++p == pe )
		goto _test_eof118;
case 118:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr205;
	goto tr204;
tr204:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st119;
st119:
	if ( ++p == pe )
		goto _test_eof119;
case 119:
#line 4391 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st120;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr23;
st120:
	if ( ++p == pe )
		goto _test_eof120;
case 120:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr207;
	goto tr206;
tr206:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st121;
st121:
	if ( ++p == pe )
		goto _test_eof121;
case 121:
#line 4436 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st122;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr25;
st122:
	if ( ++p == pe )
		goto _test_eof122;
case 122:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr209;
	goto tr208;
tr208:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st123;
st123:
	if ( ++p == pe )
		goto _test_eof123;
case 123:
#line 4481 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st124;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr27;
st124:
	if ( ++p == pe )
		goto _test_eof124;
case 124:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr211;
	goto tr210;
tr210:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st125;
st125:
	if ( ++p == pe )
		goto _test_eof125;
case 125:
#line 4526 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st126;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr29;
st126:
	if ( ++p == pe )
		goto _test_eof126;
case 126:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr213;
	goto tr212;
tr212:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st127;
st127:
	if ( ++p == pe )
		goto _test_eof127;
case 127:
#line 4571 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st128;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr31;
st128:
	if ( ++p == pe )
		goto _test_eof128;
case 128:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr215;
	goto tr214;
tr214:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st129;
st129:
	if ( ++p == pe )
		goto _test_eof129;
case 129:
#line 4616 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st130;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr33;
st130:
	if ( ++p == pe )
		goto _test_eof130;
case 130:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr217;
	goto tr216;
tr216:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st131;
st131:
	if ( ++p == pe )
		goto _test_eof131;
case 131:
#line 4661 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st132;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr35;
st132:
	if ( ++p == pe )
		goto _test_eof132;
case 132:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr219;
	goto tr218;
tr218:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st133;
st133:
	if ( ++p == pe )
		goto _test_eof133;
case 133:
#line 4706 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st134;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr37;
st134:
	if ( ++p == pe )
		goto _test_eof134;
case 134:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr221;
	goto tr220;
tr220:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st135;
st135:
	if ( ++p == pe )
		goto _test_eof135;
case 135:
#line 4751 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st136;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr39;
st136:
	if ( ++p == pe )
		goto _test_eof136;
case 136:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr223;
	goto tr222;
tr222:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st137;
st137:
	if ( ++p == pe )
		goto _test_eof137;
case 137:
#line 4796 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st138;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr41;
st138:
	if ( ++p == pe )
		goto _test_eof138;
case 138:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr225;
	goto tr224;
tr224:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st139;
st139:
	if ( ++p == pe )
		goto _test_eof139;
case 139:
#line 4841 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st140;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr43;
st140:
	if ( ++p == pe )
		goto _test_eof140;
case 140:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr227;
	goto tr226;
tr226:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st141;
st141:
	if ( ++p == pe )
		goto _test_eof141;
case 141:
#line 4886 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st142;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr45;
st142:
	if ( ++p == pe )
		goto _test_eof142;
case 142:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr229;
	goto tr228;
tr228:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st143;
st143:
	if ( ++p == pe )
		goto _test_eof143;
case 143:
#line 4931 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st144;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr47;
st144:
	if ( ++p == pe )
		goto _test_eof144;
case 144:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr231;
	goto tr230;
tr230:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st145;
st145:
	if ( ++p == pe )
		goto _test_eof145;
case 145:
#line 4976 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st146;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr49;
st146:
	if ( ++p == pe )
		goto _test_eof146;
case 146:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr233;
	goto tr232;
tr232:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st147;
st147:
	if ( ++p == pe )
		goto _test_eof147;
case 147:
#line 5021 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st148;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr51;
st148:
	if ( ++p == pe )
		goto _test_eof148;
case 148:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr235;
	goto tr234;
tr234:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st149;
st149:
	if ( ++p == pe )
		goto _test_eof149;
case 149:
#line 5066 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st150;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr53;
st150:
	if ( ++p == pe )
		goto _test_eof150;
case 150:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr237;
	goto tr236;
tr236:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st151;
st151:
	if ( ++p == pe )
		goto _test_eof151;
case 151:
#line 5111 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st152;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr55;
st152:
	if ( ++p == pe )
		goto _test_eof152;
case 152:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr239;
	goto tr238;
tr238:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st153;
st153:
	if ( ++p == pe )
		goto _test_eof153;
case 153:
#line 5156 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st154;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr57;
st154:
	if ( ++p == pe )
		goto _test_eof154;
case 154:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr241;
	goto tr240;
tr240:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st155;
st155:
	if ( ++p == pe )
		goto _test_eof155;
case 155:
#line 5201 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st156;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr59;
st156:
	if ( ++p == pe )
		goto _test_eof156;
case 156:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr243;
	goto tr242;
tr242:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st157;
st157:
	if ( ++p == pe )
		goto _test_eof157;
case 157:
#line 5246 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st158;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr61;
st158:
	if ( ++p == pe )
		goto _test_eof158;
case 158:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr245;
	goto tr244;
tr244:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st159;
st159:
	if ( ++p == pe )
		goto _test_eof159;
case 159:
#line 5291 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st160;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr63;
st160:
	if ( ++p == pe )
		goto _test_eof160;
case 160:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr247;
	goto tr246;
tr246:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st161;
st161:
	if ( ++p == pe )
		goto _test_eof161;
case 161:
#line 5336 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st162;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr65;
st162:
	if ( ++p == pe )
		goto _test_eof162;
case 162:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr249;
	goto tr248;
tr248:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st163;
st163:
	if ( ++p == pe )
		goto _test_eof163;
case 163:
#line 5381 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st164;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr67;
st164:
	if ( ++p == pe )
		goto _test_eof164;
case 164:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr251;
	goto tr250;
tr250:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st165;
st165:
	if ( ++p == pe )
		goto _test_eof165;
case 165:
#line 5426 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st166;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr69;
st166:
	if ( ++p == pe )
		goto _test_eof166;
case 166:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr253;
	goto tr252;
tr252:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st167;
st167:
	if ( ++p == pe )
		goto _test_eof167;
case 167:
#line 5471 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st168;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr71;
st168:
	if ( ++p == pe )
		goto _test_eof168;
case 168:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr255;
	goto tr254;
tr254:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st169;
st169:
	if ( ++p == pe )
		goto _test_eof169;
case 169:
#line 5516 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st170;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr73;
st170:
	if ( ++p == pe )
		goto _test_eof170;
case 170:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr257;
	goto tr256;
tr256:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st171;
st171:
	if ( ++p == pe )
		goto _test_eof171;
case 171:
#line 5561 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st172;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr75;
st172:
	if ( ++p == pe )
		goto _test_eof172;
case 172:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr259;
	goto tr258;
tr258:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st173;
st173:
	if ( ++p == pe )
		goto _test_eof173;
case 173:
#line 5606 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st174;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr77;
st174:
	if ( ++p == pe )
		goto _test_eof174;
case 174:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr261;
	goto tr260;
tr260:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st175;
st175:
	if ( ++p == pe )
		goto _test_eof175;
case 175:
#line 5651 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st176;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr79;
st176:
	if ( ++p == pe )
		goto _test_eof176;
case 176:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr263;
	goto tr262;
tr262:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st177;
st177:
	if ( ++p == pe )
		goto _test_eof177;
case 177:
#line 5696 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st178;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr81;
st178:
	if ( ++p == pe )
		goto _test_eof178;
case 178:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr265;
	goto tr264;
tr264:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st179;
st179:
	if ( ++p == pe )
		goto _test_eof179;
case 179:
#line 5741 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st180;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr83;
st180:
	if ( ++p == pe )
		goto _test_eof180;
case 180:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr267;
	goto tr266;
tr266:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st181;
st181:
	if ( ++p == pe )
		goto _test_eof181;
case 181:
#line 5786 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st182;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr85;
st182:
	if ( ++p == pe )
		goto _test_eof182;
case 182:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr269;
	goto tr268;
tr268:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st183;
st183:
	if ( ++p == pe )
		goto _test_eof183;
case 183:
#line 5831 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st184;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr87;
st184:
	if ( ++p == pe )
		goto _test_eof184;
case 184:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr271;
	goto tr270;
tr270:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st185;
st185:
	if ( ++p == pe )
		goto _test_eof185;
case 185:
#line 5876 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st186;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr89;
st186:
	if ( ++p == pe )
		goto _test_eof186;
case 186:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr273;
	goto tr272;
tr272:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st187;
st187:
	if ( ++p == pe )
		goto _test_eof187;
case 187:
#line 5921 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st188;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr91;
st188:
	if ( ++p == pe )
		goto _test_eof188;
case 188:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr275;
	goto tr274;
tr274:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st189;
st189:
	if ( ++p == pe )
		goto _test_eof189;
case 189:
#line 5966 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st190;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr93;
st190:
	if ( ++p == pe )
		goto _test_eof190;
case 190:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr277;
	goto tr276;
tr276:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st191;
st191:
	if ( ++p == pe )
		goto _test_eof191;
case 191:
#line 6011 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st192;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr95;
st192:
	if ( ++p == pe )
		goto _test_eof192;
case 192:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr279;
	goto tr278;
tr278:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st193;
st193:
	if ( ++p == pe )
		goto _test_eof193;
case 193:
#line 6056 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st194;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr97;
st194:
	if ( ++p == pe )
		goto _test_eof194;
case 194:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr281;
	goto tr280;
tr280:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st195;
st195:
	if ( ++p == pe )
		goto _test_eof195;
case 195:
#line 6101 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st196;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr99;
st196:
	if ( ++p == pe )
		goto _test_eof196;
case 196:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr283;
	goto tr282;
tr282:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st197;
st197:
	if ( ++p == pe )
		goto _test_eof197;
case 197:
#line 6146 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st198;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr101;
st198:
	if ( ++p == pe )
		goto _test_eof198;
case 198:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr285;
	goto tr284;
tr284:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st199;
st199:
	if ( ++p == pe )
		goto _test_eof199;
case 199:
#line 6191 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st200;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr103;
st200:
	if ( ++p == pe )
		goto _test_eof200;
case 200:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr287;
	goto tr286;
tr286:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st201;
st201:
	if ( ++p == pe )
		goto _test_eof201;
case 201:
#line 6236 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st202;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr105;
st202:
	if ( ++p == pe )
		goto _test_eof202;
case 202:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr289;
	goto tr288;
tr288:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st203;
st203:
	if ( ++p == pe )
		goto _test_eof203;
case 203:
#line 6281 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st204;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr107;
st204:
	if ( ++p == pe )
		goto _test_eof204;
case 204:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr291;
	goto tr290;
tr290:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st205;
st205:
	if ( ++p == pe )
		goto _test_eof205;
case 205:
#line 6326 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st206;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr109;
st206:
	if ( ++p == pe )
		goto _test_eof206;
case 206:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr293;
	goto tr292;
tr292:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st207;
st207:
	if ( ++p == pe )
		goto _test_eof207;
case 207:
#line 6371 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st208;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr111;
st208:
	if ( ++p == pe )
		goto _test_eof208;
case 208:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr295;
	goto tr294;
tr294:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st209;
st209:
	if ( ++p == pe )
		goto _test_eof209;
case 209:
#line 6416 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st210;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr113;
st210:
	if ( ++p == pe )
		goto _test_eof210;
case 210:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr297;
	goto tr296;
tr296:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st211;
st211:
	if ( ++p == pe )
		goto _test_eof211;
case 211:
#line 6461 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st212;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr115;
st212:
	if ( ++p == pe )
		goto _test_eof212;
case 212:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr299;
	goto tr298;
tr298:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st213;
st213:
	if ( ++p == pe )
		goto _test_eof213;
case 213:
#line 6506 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st214;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr117;
st214:
	if ( ++p == pe )
		goto _test_eof214;
case 214:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr301;
	goto tr300;
tr300:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st215;
st215:
	if ( ++p == pe )
		goto _test_eof215;
case 215:
#line 6551 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st216;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr119;
st216:
	if ( ++p == pe )
		goto _test_eof216;
case 216:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr303;
	goto tr302;
tr302:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st217;
st217:
	if ( ++p == pe )
		goto _test_eof217;
case 217:
#line 6596 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st218;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr121;
st218:
	if ( ++p == pe )
		goto _test_eof218;
case 218:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr305;
	goto tr304;
tr304:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st219;
st219:
	if ( ++p == pe )
		goto _test_eof219;
case 219:
#line 6641 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st220;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr123;
st220:
	if ( ++p == pe )
		goto _test_eof220;
case 220:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr307;
	goto tr306;
tr306:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st221;
st221:
	if ( ++p == pe )
		goto _test_eof221;
case 221:
#line 6686 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr185;
		case 36: goto tr185;
		case 46: goto tr3;
		case 59: goto tr185;
		case 64: goto tr185;
		case 92: goto st222;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr185;
	} else if ( (*p) >= 10 )
		goto tr185;
	goto tr125;
st222:
	if ( ++p == pe )
		goto _test_eof222;
case 222:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr184;
	} else if ( (*p) >= 48 )
		goto tr309;
	goto tr308;
tr308:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st223;
st223:
	if ( ++p == pe )
		goto _test_eof223;
case 223:
#line 6731 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 46: goto tr3;
	}
	goto tr185;
tr309:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st224;
st224:
	if ( ++p == pe )
		goto _test_eof224;
case 224:
#line 6761 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr311;
	goto tr310;
tr311:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st225;
st225:
	if ( ++p == pe )
		goto _test_eof225;
case 225:
#line 6776 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr312;
	goto tr310;
tr312:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st226;
st226:
	if ( ++p == pe )
		goto _test_eof226;
case 226:
#line 6791 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 46: goto tr3;
	}
	goto tr310;
tr307:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st227;
st227:
	if ( ++p == pe )
		goto _test_eof227;
case 227:
#line 6821 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr313;
	goto tr310;
tr313:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st228;
st228:
	if ( ++p == pe )
		goto _test_eof228;
case 228:
#line 6836 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr314;
	goto tr310;
tr314:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st229;
st229:
	if ( ++p == pe )
		goto _test_eof229;
case 229:
#line 6851 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st222;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr125;
tr305:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st230;
st230:
	if ( ++p == pe )
		goto _test_eof230;
case 230:
#line 6891 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr315;
	goto tr310;
tr315:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st231;
st231:
	if ( ++p == pe )
		goto _test_eof231;
case 231:
#line 6906 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr316;
	goto tr310;
tr316:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st232;
st232:
	if ( ++p == pe )
		goto _test_eof232;
case 232:
#line 6921 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st220;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr123;
tr303:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st233;
st233:
	if ( ++p == pe )
		goto _test_eof233;
case 233:
#line 6961 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr317;
	goto tr310;
tr317:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st234;
st234:
	if ( ++p == pe )
		goto _test_eof234;
case 234:
#line 6976 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr318;
	goto tr310;
tr318:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st235;
st235:
	if ( ++p == pe )
		goto _test_eof235;
case 235:
#line 6991 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st218;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr121;
tr301:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st236;
st236:
	if ( ++p == pe )
		goto _test_eof236;
case 236:
#line 7031 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr319;
	goto tr310;
tr319:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st237;
st237:
	if ( ++p == pe )
		goto _test_eof237;
case 237:
#line 7046 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr320;
	goto tr310;
tr320:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st238;
st238:
	if ( ++p == pe )
		goto _test_eof238;
case 238:
#line 7061 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st216;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr119;
tr299:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st239;
st239:
	if ( ++p == pe )
		goto _test_eof239;
case 239:
#line 7101 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr321;
	goto tr310;
tr321:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st240;
st240:
	if ( ++p == pe )
		goto _test_eof240;
case 240:
#line 7116 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr322;
	goto tr310;
tr322:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st241;
st241:
	if ( ++p == pe )
		goto _test_eof241;
case 241:
#line 7131 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st214;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr117;
tr297:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st242;
st242:
	if ( ++p == pe )
		goto _test_eof242;
case 242:
#line 7171 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr323;
	goto tr310;
tr323:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st243;
st243:
	if ( ++p == pe )
		goto _test_eof243;
case 243:
#line 7186 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr324;
	goto tr310;
tr324:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st244;
st244:
	if ( ++p == pe )
		goto _test_eof244;
case 244:
#line 7201 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st212;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr115;
tr295:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st245;
st245:
	if ( ++p == pe )
		goto _test_eof245;
case 245:
#line 7241 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr325;
	goto tr310;
tr325:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st246;
st246:
	if ( ++p == pe )
		goto _test_eof246;
case 246:
#line 7256 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr326;
	goto tr310;
tr326:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st247;
st247:
	if ( ++p == pe )
		goto _test_eof247;
case 247:
#line 7271 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st210;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr113;
tr293:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st248;
st248:
	if ( ++p == pe )
		goto _test_eof248;
case 248:
#line 7311 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr327;
	goto tr310;
tr327:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st249;
st249:
	if ( ++p == pe )
		goto _test_eof249;
case 249:
#line 7326 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr328;
	goto tr310;
tr328:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st250;
st250:
	if ( ++p == pe )
		goto _test_eof250;
case 250:
#line 7341 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st208;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr111;
tr291:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st251;
st251:
	if ( ++p == pe )
		goto _test_eof251;
case 251:
#line 7381 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr329;
	goto tr310;
tr329:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st252;
st252:
	if ( ++p == pe )
		goto _test_eof252;
case 252:
#line 7396 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr330;
	goto tr310;
tr330:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st253;
st253:
	if ( ++p == pe )
		goto _test_eof253;
case 253:
#line 7411 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st206;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr109;
tr289:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st254;
st254:
	if ( ++p == pe )
		goto _test_eof254;
case 254:
#line 7451 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr331;
	goto tr310;
tr331:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st255;
st255:
	if ( ++p == pe )
		goto _test_eof255;
case 255:
#line 7466 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr332;
	goto tr310;
tr332:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st256;
st256:
	if ( ++p == pe )
		goto _test_eof256;
case 256:
#line 7481 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st204;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr107;
tr287:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st257;
st257:
	if ( ++p == pe )
		goto _test_eof257;
case 257:
#line 7521 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr333;
	goto tr310;
tr333:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st258;
st258:
	if ( ++p == pe )
		goto _test_eof258;
case 258:
#line 7536 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr334;
	goto tr310;
tr334:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st259;
st259:
	if ( ++p == pe )
		goto _test_eof259;
case 259:
#line 7551 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st202;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr105;
tr285:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st260;
st260:
	if ( ++p == pe )
		goto _test_eof260;
case 260:
#line 7591 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr335;
	goto tr310;
tr335:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st261;
st261:
	if ( ++p == pe )
		goto _test_eof261;
case 261:
#line 7606 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr336;
	goto tr310;
tr336:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st262;
st262:
	if ( ++p == pe )
		goto _test_eof262;
case 262:
#line 7621 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st200;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr103;
tr283:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st263;
st263:
	if ( ++p == pe )
		goto _test_eof263;
case 263:
#line 7661 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr337;
	goto tr310;
tr337:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st264;
st264:
	if ( ++p == pe )
		goto _test_eof264;
case 264:
#line 7676 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr338;
	goto tr310;
tr338:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st265;
st265:
	if ( ++p == pe )
		goto _test_eof265;
case 265:
#line 7691 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st198;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr101;
tr281:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st266;
st266:
	if ( ++p == pe )
		goto _test_eof266;
case 266:
#line 7731 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr339;
	goto tr310;
tr339:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st267;
st267:
	if ( ++p == pe )
		goto _test_eof267;
case 267:
#line 7746 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr340;
	goto tr310;
tr340:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st268;
st268:
	if ( ++p == pe )
		goto _test_eof268;
case 268:
#line 7761 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st196;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr99;
tr279:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st269;
st269:
	if ( ++p == pe )
		goto _test_eof269;
case 269:
#line 7801 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr341;
	goto tr310;
tr341:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st270;
st270:
	if ( ++p == pe )
		goto _test_eof270;
case 270:
#line 7816 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr342;
	goto tr310;
tr342:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st271;
st271:
	if ( ++p == pe )
		goto _test_eof271;
case 271:
#line 7831 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st194;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr97;
tr277:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st272;
st272:
	if ( ++p == pe )
		goto _test_eof272;
case 272:
#line 7871 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr343;
	goto tr310;
tr343:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st273;
st273:
	if ( ++p == pe )
		goto _test_eof273;
case 273:
#line 7886 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr344;
	goto tr310;
tr344:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st274;
st274:
	if ( ++p == pe )
		goto _test_eof274;
case 274:
#line 7901 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st192;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr95;
tr275:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st275;
st275:
	if ( ++p == pe )
		goto _test_eof275;
case 275:
#line 7941 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr345;
	goto tr310;
tr345:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st276;
st276:
	if ( ++p == pe )
		goto _test_eof276;
case 276:
#line 7956 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr346;
	goto tr310;
tr346:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st277;
st277:
	if ( ++p == pe )
		goto _test_eof277;
case 277:
#line 7971 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st190;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr93;
tr273:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st278;
st278:
	if ( ++p == pe )
		goto _test_eof278;
case 278:
#line 8011 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr347;
	goto tr310;
tr347:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st279;
st279:
	if ( ++p == pe )
		goto _test_eof279;
case 279:
#line 8026 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr348;
	goto tr310;
tr348:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st280;
st280:
	if ( ++p == pe )
		goto _test_eof280;
case 280:
#line 8041 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st188;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr91;
tr271:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st281;
st281:
	if ( ++p == pe )
		goto _test_eof281;
case 281:
#line 8081 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr349;
	goto tr310;
tr349:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st282;
st282:
	if ( ++p == pe )
		goto _test_eof282;
case 282:
#line 8096 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr350;
	goto tr310;
tr350:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st283;
st283:
	if ( ++p == pe )
		goto _test_eof283;
case 283:
#line 8111 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st186;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr89;
tr269:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st284;
st284:
	if ( ++p == pe )
		goto _test_eof284;
case 284:
#line 8151 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr351;
	goto tr310;
tr351:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st285;
st285:
	if ( ++p == pe )
		goto _test_eof285;
case 285:
#line 8166 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr352;
	goto tr310;
tr352:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st286;
st286:
	if ( ++p == pe )
		goto _test_eof286;
case 286:
#line 8181 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st184;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr87;
tr267:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st287;
st287:
	if ( ++p == pe )
		goto _test_eof287;
case 287:
#line 8221 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr353;
	goto tr310;
tr353:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st288;
st288:
	if ( ++p == pe )
		goto _test_eof288;
case 288:
#line 8236 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr354;
	goto tr310;
tr354:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st289;
st289:
	if ( ++p == pe )
		goto _test_eof289;
case 289:
#line 8251 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st182;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr85;
tr265:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st290;
st290:
	if ( ++p == pe )
		goto _test_eof290;
case 290:
#line 8291 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr355;
	goto tr310;
tr355:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st291;
st291:
	if ( ++p == pe )
		goto _test_eof291;
case 291:
#line 8306 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr356;
	goto tr310;
tr356:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st292;
st292:
	if ( ++p == pe )
		goto _test_eof292;
case 292:
#line 8321 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st180;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr83;
tr263:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st293;
st293:
	if ( ++p == pe )
		goto _test_eof293;
case 293:
#line 8361 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr357;
	goto tr310;
tr357:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st294;
st294:
	if ( ++p == pe )
		goto _test_eof294;
case 294:
#line 8376 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr358;
	goto tr310;
tr358:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st295;
st295:
	if ( ++p == pe )
		goto _test_eof295;
case 295:
#line 8391 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st178;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr81;
tr261:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st296;
st296:
	if ( ++p == pe )
		goto _test_eof296;
case 296:
#line 8431 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr359;
	goto tr310;
tr359:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st297;
st297:
	if ( ++p == pe )
		goto _test_eof297;
case 297:
#line 8446 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr360;
	goto tr310;
tr360:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st298;
st298:
	if ( ++p == pe )
		goto _test_eof298;
case 298:
#line 8461 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st176;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr79;
tr259:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st299;
st299:
	if ( ++p == pe )
		goto _test_eof299;
case 299:
#line 8501 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr361;
	goto tr310;
tr361:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st300;
st300:
	if ( ++p == pe )
		goto _test_eof300;
case 300:
#line 8516 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr362;
	goto tr310;
tr362:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st301;
st301:
	if ( ++p == pe )
		goto _test_eof301;
case 301:
#line 8531 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st174;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr77;
tr257:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st302;
st302:
	if ( ++p == pe )
		goto _test_eof302;
case 302:
#line 8571 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr363;
	goto tr310;
tr363:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st303;
st303:
	if ( ++p == pe )
		goto _test_eof303;
case 303:
#line 8586 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr364;
	goto tr310;
tr364:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st304;
st304:
	if ( ++p == pe )
		goto _test_eof304;
case 304:
#line 8601 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st172;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr75;
tr255:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st305;
st305:
	if ( ++p == pe )
		goto _test_eof305;
case 305:
#line 8641 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr365;
	goto tr310;
tr365:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st306;
st306:
	if ( ++p == pe )
		goto _test_eof306;
case 306:
#line 8656 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr366;
	goto tr310;
tr366:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st307;
st307:
	if ( ++p == pe )
		goto _test_eof307;
case 307:
#line 8671 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st170;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr73;
tr253:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st308;
st308:
	if ( ++p == pe )
		goto _test_eof308;
case 308:
#line 8711 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr367;
	goto tr310;
tr367:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st309;
st309:
	if ( ++p == pe )
		goto _test_eof309;
case 309:
#line 8726 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr368;
	goto tr310;
tr368:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st310;
st310:
	if ( ++p == pe )
		goto _test_eof310;
case 310:
#line 8741 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st168;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr71;
tr251:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st311;
st311:
	if ( ++p == pe )
		goto _test_eof311;
case 311:
#line 8781 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr369;
	goto tr310;
tr369:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st312;
st312:
	if ( ++p == pe )
		goto _test_eof312;
case 312:
#line 8796 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr370;
	goto tr310;
tr370:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st313;
st313:
	if ( ++p == pe )
		goto _test_eof313;
case 313:
#line 8811 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st166;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr69;
tr249:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st314;
st314:
	if ( ++p == pe )
		goto _test_eof314;
case 314:
#line 8851 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr371;
	goto tr310;
tr371:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st315;
st315:
	if ( ++p == pe )
		goto _test_eof315;
case 315:
#line 8866 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr372;
	goto tr310;
tr372:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st316;
st316:
	if ( ++p == pe )
		goto _test_eof316;
case 316:
#line 8881 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st164;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr67;
tr247:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st317;
st317:
	if ( ++p == pe )
		goto _test_eof317;
case 317:
#line 8921 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr373;
	goto tr310;
tr373:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st318;
st318:
	if ( ++p == pe )
		goto _test_eof318;
case 318:
#line 8936 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr374;
	goto tr310;
tr374:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st319;
st319:
	if ( ++p == pe )
		goto _test_eof319;
case 319:
#line 8951 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st162;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr65;
tr245:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st320;
st320:
	if ( ++p == pe )
		goto _test_eof320;
case 320:
#line 8991 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr375;
	goto tr310;
tr375:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st321;
st321:
	if ( ++p == pe )
		goto _test_eof321;
case 321:
#line 9006 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr376;
	goto tr310;
tr376:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st322;
st322:
	if ( ++p == pe )
		goto _test_eof322;
case 322:
#line 9021 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st160;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr63;
tr243:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st323;
st323:
	if ( ++p == pe )
		goto _test_eof323;
case 323:
#line 9061 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr377;
	goto tr310;
tr377:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st324;
st324:
	if ( ++p == pe )
		goto _test_eof324;
case 324:
#line 9076 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr378;
	goto tr310;
tr378:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st325;
st325:
	if ( ++p == pe )
		goto _test_eof325;
case 325:
#line 9091 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st158;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr61;
tr241:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st326;
st326:
	if ( ++p == pe )
		goto _test_eof326;
case 326:
#line 9131 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr379;
	goto tr310;
tr379:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st327;
st327:
	if ( ++p == pe )
		goto _test_eof327;
case 327:
#line 9146 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr380;
	goto tr310;
tr380:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st328;
st328:
	if ( ++p == pe )
		goto _test_eof328;
case 328:
#line 9161 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st156;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr59;
tr239:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st329;
st329:
	if ( ++p == pe )
		goto _test_eof329;
case 329:
#line 9201 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr381;
	goto tr310;
tr381:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st330;
st330:
	if ( ++p == pe )
		goto _test_eof330;
case 330:
#line 9216 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr382;
	goto tr310;
tr382:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st331;
st331:
	if ( ++p == pe )
		goto _test_eof331;
case 331:
#line 9231 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st154;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr57;
tr237:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st332;
st332:
	if ( ++p == pe )
		goto _test_eof332;
case 332:
#line 9271 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr383;
	goto tr310;
tr383:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st333;
st333:
	if ( ++p == pe )
		goto _test_eof333;
case 333:
#line 9286 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr384;
	goto tr310;
tr384:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st334;
st334:
	if ( ++p == pe )
		goto _test_eof334;
case 334:
#line 9301 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st152;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr55;
tr235:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st335;
st335:
	if ( ++p == pe )
		goto _test_eof335;
case 335:
#line 9341 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr385;
	goto tr310;
tr385:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st336;
st336:
	if ( ++p == pe )
		goto _test_eof336;
case 336:
#line 9356 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr386;
	goto tr310;
tr386:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st337;
st337:
	if ( ++p == pe )
		goto _test_eof337;
case 337:
#line 9371 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st150;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr53;
tr233:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st338;
st338:
	if ( ++p == pe )
		goto _test_eof338;
case 338:
#line 9411 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr387;
	goto tr310;
tr387:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st339;
st339:
	if ( ++p == pe )
		goto _test_eof339;
case 339:
#line 9426 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr388;
	goto tr310;
tr388:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st340;
st340:
	if ( ++p == pe )
		goto _test_eof340;
case 340:
#line 9441 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st148;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr51;
tr231:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st341;
st341:
	if ( ++p == pe )
		goto _test_eof341;
case 341:
#line 9481 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr389;
	goto tr310;
tr389:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st342;
st342:
	if ( ++p == pe )
		goto _test_eof342;
case 342:
#line 9496 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr390;
	goto tr310;
tr390:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st343;
st343:
	if ( ++p == pe )
		goto _test_eof343;
case 343:
#line 9511 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st146;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr49;
tr229:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st344;
st344:
	if ( ++p == pe )
		goto _test_eof344;
case 344:
#line 9551 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr391;
	goto tr310;
tr391:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st345;
st345:
	if ( ++p == pe )
		goto _test_eof345;
case 345:
#line 9566 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr392;
	goto tr310;
tr392:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st346;
st346:
	if ( ++p == pe )
		goto _test_eof346;
case 346:
#line 9581 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st144;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr47;
tr227:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st347;
st347:
	if ( ++p == pe )
		goto _test_eof347;
case 347:
#line 9621 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr393;
	goto tr310;
tr393:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st348;
st348:
	if ( ++p == pe )
		goto _test_eof348;
case 348:
#line 9636 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr394;
	goto tr310;
tr394:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st349;
st349:
	if ( ++p == pe )
		goto _test_eof349;
case 349:
#line 9651 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st142;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr45;
tr225:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st350;
st350:
	if ( ++p == pe )
		goto _test_eof350;
case 350:
#line 9691 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr395;
	goto tr310;
tr395:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st351;
st351:
	if ( ++p == pe )
		goto _test_eof351;
case 351:
#line 9706 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr396;
	goto tr310;
tr396:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st352;
st352:
	if ( ++p == pe )
		goto _test_eof352;
case 352:
#line 9721 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st140;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr43;
tr223:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st353;
st353:
	if ( ++p == pe )
		goto _test_eof353;
case 353:
#line 9761 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr397;
	goto tr310;
tr397:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st354;
st354:
	if ( ++p == pe )
		goto _test_eof354;
case 354:
#line 9776 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr398;
	goto tr310;
tr398:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st355;
st355:
	if ( ++p == pe )
		goto _test_eof355;
case 355:
#line 9791 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st138;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr41;
tr221:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st356;
st356:
	if ( ++p == pe )
		goto _test_eof356;
case 356:
#line 9831 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr399;
	goto tr310;
tr399:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st357;
st357:
	if ( ++p == pe )
		goto _test_eof357;
case 357:
#line 9846 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr400;
	goto tr310;
tr400:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st358;
st358:
	if ( ++p == pe )
		goto _test_eof358;
case 358:
#line 9861 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st136;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr39;
tr219:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st359;
st359:
	if ( ++p == pe )
		goto _test_eof359;
case 359:
#line 9901 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr401;
	goto tr310;
tr401:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st360;
st360:
	if ( ++p == pe )
		goto _test_eof360;
case 360:
#line 9916 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr402;
	goto tr310;
tr402:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st361;
st361:
	if ( ++p == pe )
		goto _test_eof361;
case 361:
#line 9931 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st134;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr37;
tr217:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st362;
st362:
	if ( ++p == pe )
		goto _test_eof362;
case 362:
#line 9971 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr403;
	goto tr310;
tr403:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st363;
st363:
	if ( ++p == pe )
		goto _test_eof363;
case 363:
#line 9986 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr404;
	goto tr310;
tr404:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st364;
st364:
	if ( ++p == pe )
		goto _test_eof364;
case 364:
#line 10001 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st132;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr35;
tr215:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st365;
st365:
	if ( ++p == pe )
		goto _test_eof365;
case 365:
#line 10041 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr405;
	goto tr310;
tr405:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st366;
st366:
	if ( ++p == pe )
		goto _test_eof366;
case 366:
#line 10056 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr406;
	goto tr310;
tr406:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st367;
st367:
	if ( ++p == pe )
		goto _test_eof367;
case 367:
#line 10071 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st130;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr33;
tr213:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st368;
st368:
	if ( ++p == pe )
		goto _test_eof368;
case 368:
#line 10111 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr407;
	goto tr310;
tr407:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st369;
st369:
	if ( ++p == pe )
		goto _test_eof369;
case 369:
#line 10126 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr408;
	goto tr310;
tr408:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st370;
st370:
	if ( ++p == pe )
		goto _test_eof370;
case 370:
#line 10141 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st128;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr31;
tr211:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st371;
st371:
	if ( ++p == pe )
		goto _test_eof371;
case 371:
#line 10181 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr409;
	goto tr310;
tr409:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st372;
st372:
	if ( ++p == pe )
		goto _test_eof372;
case 372:
#line 10196 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr410;
	goto tr310;
tr410:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st373;
st373:
	if ( ++p == pe )
		goto _test_eof373;
case 373:
#line 10211 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st126;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr29;
tr209:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st374;
st374:
	if ( ++p == pe )
		goto _test_eof374;
case 374:
#line 10251 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr411;
	goto tr310;
tr411:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st375;
st375:
	if ( ++p == pe )
		goto _test_eof375;
case 375:
#line 10266 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr412;
	goto tr310;
tr412:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st376;
st376:
	if ( ++p == pe )
		goto _test_eof376;
case 376:
#line 10281 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st124;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr27;
tr207:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st377;
st377:
	if ( ++p == pe )
		goto _test_eof377;
case 377:
#line 10321 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr413;
	goto tr310;
tr413:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st378;
st378:
	if ( ++p == pe )
		goto _test_eof378;
case 378:
#line 10336 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr414;
	goto tr310;
tr414:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st379;
st379:
	if ( ++p == pe )
		goto _test_eof379;
case 379:
#line 10351 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st122;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr25;
tr205:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st380;
st380:
	if ( ++p == pe )
		goto _test_eof380;
case 380:
#line 10391 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr415;
	goto tr310;
tr415:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st381;
st381:
	if ( ++p == pe )
		goto _test_eof381;
case 381:
#line 10406 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr416;
	goto tr310;
tr416:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st382;
st382:
	if ( ++p == pe )
		goto _test_eof382;
case 382:
#line 10421 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st120;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr23;
tr203:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st383;
st383:
	if ( ++p == pe )
		goto _test_eof383;
case 383:
#line 10461 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr417;
	goto tr310;
tr417:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st384;
st384:
	if ( ++p == pe )
		goto _test_eof384;
case 384:
#line 10476 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr418;
	goto tr310;
tr418:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st385;
st385:
	if ( ++p == pe )
		goto _test_eof385;
case 385:
#line 10491 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st118;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr21;
tr201:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st386;
st386:
	if ( ++p == pe )
		goto _test_eof386;
case 386:
#line 10531 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr419;
	goto tr310;
tr419:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st387;
st387:
	if ( ++p == pe )
		goto _test_eof387;
case 387:
#line 10546 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr420;
	goto tr310;
tr420:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st388;
st388:
	if ( ++p == pe )
		goto _test_eof388;
case 388:
#line 10561 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st116;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr19;
tr199:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st389;
st389:
	if ( ++p == pe )
		goto _test_eof389;
case 389:
#line 10601 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr421;
	goto tr310;
tr421:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st390;
st390:
	if ( ++p == pe )
		goto _test_eof390;
case 390:
#line 10616 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr422;
	goto tr310;
tr422:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st391;
st391:
	if ( ++p == pe )
		goto _test_eof391;
case 391:
#line 10631 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st114;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr17;
tr197:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st392;
st392:
	if ( ++p == pe )
		goto _test_eof392;
case 392:
#line 10671 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr423;
	goto tr310;
tr423:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st393;
st393:
	if ( ++p == pe )
		goto _test_eof393;
case 393:
#line 10686 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr424;
	goto tr310;
tr424:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st394;
st394:
	if ( ++p == pe )
		goto _test_eof394;
case 394:
#line 10701 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st112;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr15;
tr195:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st395;
st395:
	if ( ++p == pe )
		goto _test_eof395;
case 395:
#line 10741 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr425;
	goto tr310;
tr425:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st396;
st396:
	if ( ++p == pe )
		goto _test_eof396;
case 396:
#line 10756 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr426;
	goto tr310;
tr426:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st397;
st397:
	if ( ++p == pe )
		goto _test_eof397;
case 397:
#line 10771 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st110;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr13;
tr193:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st398;
st398:
	if ( ++p == pe )
		goto _test_eof398;
case 398:
#line 10811 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr427;
	goto tr310;
tr427:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st399;
st399:
	if ( ++p == pe )
		goto _test_eof399;
case 399:
#line 10826 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr428;
	goto tr310;
tr428:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st400;
st400:
	if ( ++p == pe )
		goto _test_eof400;
case 400:
#line 10841 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st108;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr11;
tr191:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st401;
st401:
	if ( ++p == pe )
		goto _test_eof401;
case 401:
#line 10881 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr429;
	goto tr310;
tr429:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st402;
st402:
	if ( ++p == pe )
		goto _test_eof402;
case 402:
#line 10896 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr430;
	goto tr310;
tr430:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st403;
st403:
	if ( ++p == pe )
		goto _test_eof403;
case 403:
#line 10911 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st106;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr9;
tr189:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st404;
st404:
	if ( ++p == pe )
		goto _test_eof404;
case 404:
#line 10951 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr431;
	goto tr310;
tr431:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st405;
st405:
	if ( ++p == pe )
		goto _test_eof405;
case 405:
#line 10966 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr432;
	goto tr310;
tr432:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st406;
st406:
	if ( ++p == pe )
		goto _test_eof406;
case 406:
#line 10981 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st104;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr7;
tr187:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st407;
st407:
	if ( ++p == pe )
		goto _test_eof407;
case 407:
#line 11021 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr433;
	goto tr310;
tr433:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st408;
st408:
	if ( ++p == pe )
		goto _test_eof408;
case 408:
#line 11036 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr434;
	goto tr310;
tr434:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st409;
st409:
	if ( ++p == pe )
		goto _test_eof409;
case 409:
#line 11051 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st102;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr5;
tr183:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st410;
st410:
	if ( ++p == pe )
		goto _test_eof410;
case 410:
#line 11091 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr435;
	goto tr310;
tr435:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st411;
st411:
	if ( ++p == pe )
		goto _test_eof411;
case 411:
#line 11106 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr436;
	goto tr310;
tr436:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st412;
st412:
	if ( ++p == pe )
		goto _test_eof412;
case 412:
#line 11121 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr1;
		case 32: goto tr1;
		case 34: goto tr310;
		case 36: goto tr310;
		case 46: goto tr3;
		case 59: goto tr310;
		case 64: goto tr310;
		case 92: goto st100;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr310;
	} else if ( (*p) >= 10 )
		goto tr310;
	goto tr0;
st413:
	if ( ++p == pe )
		goto _test_eof413;
case 413:
	switch( (*p) ) {
		case 79: goto st414;
		case 84: goto st801;
	}
	goto st0;
st414:
	if ( ++p == pe )
		goto _test_eof414;
case 414:
	if ( (*p) == 82 )
		goto st415;
	goto st0;
st415:
	if ( ++p == pe )
		goto _test_eof415;
case 415:
	if ( (*p) == 73 )
		goto st416;
	goto st0;
st416:
	if ( ++p == pe )
		goto _test_eof416;
case 416:
	if ( (*p) == 71 )
		goto st417;
	goto st0;
st417:
	if ( ++p == pe )
		goto _test_eof417;
case 417:
	if ( (*p) == 73 )
		goto st418;
	goto st0;
st418:
	if ( ++p == pe )
		goto _test_eof418;
case 418:
	if ( (*p) == 78 )
		goto st419;
	goto st0;
st419:
	if ( ++p == pe )
		goto _test_eof419;
case 419:
	switch( (*p) ) {
		case 9: goto st420;
		case 32: goto st420;
	}
	goto st0;
st420:
	if ( ++p == pe )
		goto _test_eof420;
case 420:
	switch( (*p) ) {
		case 9: goto st420;
		case 32: goto st420;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr448;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto tr449;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 10 )
		goto tr447;
	goto tr446;
tr575:
#line 70 "zparser.rl"
	{
        parser->label_head = parser->dname_size;
        parser->dname_size++;
    }
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st421;
tr446:
#line 104 "zparser.rl"
	{
        bzero(&parser->dname_wire[0], DNAME_MAXLEN);
        bzero(&parser->label_offsets[0], DNAME_MAXLEN);
        parser->dname_size = 0;
        parser->label_count = 0;
        parser->label = parser->dname_wire;
    }
#line 70 "zparser.rl"
	{
        parser->label_head = parser->dname_size;
        parser->dname_size++;
    }
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st421;
st421:
	if ( ++p == pe )
		goto _test_eof421;
case 421:
#line 11261 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st487;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr450;
tr450:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st422;
st422:
	if ( ++p == pe )
		goto _test_eof422;
case 422:
#line 11295 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st489;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr453;
tr453:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st423;
st423:
	if ( ++p == pe )
		goto _test_eof423;
case 423:
#line 11329 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st491;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr455;
tr455:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st424;
st424:
	if ( ++p == pe )
		goto _test_eof424;
case 424:
#line 11363 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st493;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr457;
tr457:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st425;
st425:
	if ( ++p == pe )
		goto _test_eof425;
case 425:
#line 11397 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st495;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr459;
tr459:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st426;
st426:
	if ( ++p == pe )
		goto _test_eof426;
case 426:
#line 11431 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st497;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr461;
tr461:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st427;
st427:
	if ( ++p == pe )
		goto _test_eof427;
case 427:
#line 11465 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st499;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr463;
tr463:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st428;
st428:
	if ( ++p == pe )
		goto _test_eof428;
case 428:
#line 11499 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st501;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr465;
tr465:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st429;
st429:
	if ( ++p == pe )
		goto _test_eof429;
case 429:
#line 11533 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st503;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr467;
tr467:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st430;
st430:
	if ( ++p == pe )
		goto _test_eof430;
case 430:
#line 11567 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st505;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr469;
tr469:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st431;
st431:
	if ( ++p == pe )
		goto _test_eof431;
case 431:
#line 11601 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st507;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr471;
tr471:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st432;
st432:
	if ( ++p == pe )
		goto _test_eof432;
case 432:
#line 11635 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st509;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr473;
tr473:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st433;
st433:
	if ( ++p == pe )
		goto _test_eof433;
case 433:
#line 11669 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st511;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr475;
tr475:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st434;
st434:
	if ( ++p == pe )
		goto _test_eof434;
case 434:
#line 11703 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st513;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr477;
tr477:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st435;
st435:
	if ( ++p == pe )
		goto _test_eof435;
case 435:
#line 11737 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st515;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr479;
tr479:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st436;
st436:
	if ( ++p == pe )
		goto _test_eof436;
case 436:
#line 11771 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st517;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr481;
tr481:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st437;
st437:
	if ( ++p == pe )
		goto _test_eof437;
case 437:
#line 11805 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st519;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr483;
tr483:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st438;
st438:
	if ( ++p == pe )
		goto _test_eof438;
case 438:
#line 11839 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st521;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr485;
tr485:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st439;
st439:
	if ( ++p == pe )
		goto _test_eof439;
case 439:
#line 11873 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st523;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr487;
tr487:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st440;
st440:
	if ( ++p == pe )
		goto _test_eof440;
case 440:
#line 11907 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st525;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr489;
tr489:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st441;
st441:
	if ( ++p == pe )
		goto _test_eof441;
case 441:
#line 11941 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st527;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr491;
tr491:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st442;
st442:
	if ( ++p == pe )
		goto _test_eof442;
case 442:
#line 11975 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st529;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr493;
tr493:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st443;
st443:
	if ( ++p == pe )
		goto _test_eof443;
case 443:
#line 12009 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st531;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr495;
tr495:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st444;
st444:
	if ( ++p == pe )
		goto _test_eof444;
case 444:
#line 12043 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st533;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr497;
tr497:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st445;
st445:
	if ( ++p == pe )
		goto _test_eof445;
case 445:
#line 12077 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st535;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr499;
tr499:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st446;
st446:
	if ( ++p == pe )
		goto _test_eof446;
case 446:
#line 12111 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st537;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr501;
tr501:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st447;
st447:
	if ( ++p == pe )
		goto _test_eof447;
case 447:
#line 12145 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st539;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr503;
tr503:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st448;
st448:
	if ( ++p == pe )
		goto _test_eof448;
case 448:
#line 12179 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st541;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr505;
tr505:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st449;
st449:
	if ( ++p == pe )
		goto _test_eof449;
case 449:
#line 12213 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st543;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr507;
tr507:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st450;
st450:
	if ( ++p == pe )
		goto _test_eof450;
case 450:
#line 12247 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st545;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr509;
tr509:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st451;
st451:
	if ( ++p == pe )
		goto _test_eof451;
case 451:
#line 12281 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st547;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr511;
tr511:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st452;
st452:
	if ( ++p == pe )
		goto _test_eof452;
case 452:
#line 12315 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st549;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr513;
tr513:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st453;
st453:
	if ( ++p == pe )
		goto _test_eof453;
case 453:
#line 12349 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st551;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr515;
tr515:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st454;
st454:
	if ( ++p == pe )
		goto _test_eof454;
case 454:
#line 12383 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st553;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr517;
tr517:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st455;
st455:
	if ( ++p == pe )
		goto _test_eof455;
case 455:
#line 12417 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st555;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr519;
tr519:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st456;
st456:
	if ( ++p == pe )
		goto _test_eof456;
case 456:
#line 12451 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st557;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr521;
tr521:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st457;
st457:
	if ( ++p == pe )
		goto _test_eof457;
case 457:
#line 12485 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st559;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr523;
tr523:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st458;
st458:
	if ( ++p == pe )
		goto _test_eof458;
case 458:
#line 12519 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st561;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr525;
tr525:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st459;
st459:
	if ( ++p == pe )
		goto _test_eof459;
case 459:
#line 12553 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st563;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr527;
tr527:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st460;
st460:
	if ( ++p == pe )
		goto _test_eof460;
case 460:
#line 12587 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st565;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr529;
tr529:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st461;
st461:
	if ( ++p == pe )
		goto _test_eof461;
case 461:
#line 12621 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st567;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr531;
tr531:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st462;
st462:
	if ( ++p == pe )
		goto _test_eof462;
case 462:
#line 12655 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st569;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr533;
tr533:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st463;
st463:
	if ( ++p == pe )
		goto _test_eof463;
case 463:
#line 12689 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st571;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr535;
tr535:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st464;
st464:
	if ( ++p == pe )
		goto _test_eof464;
case 464:
#line 12723 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st573;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr537;
tr537:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st465;
st465:
	if ( ++p == pe )
		goto _test_eof465;
case 465:
#line 12757 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st575;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr539;
tr539:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st466;
st466:
	if ( ++p == pe )
		goto _test_eof466;
case 466:
#line 12791 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st577;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr541;
tr541:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st467;
st467:
	if ( ++p == pe )
		goto _test_eof467;
case 467:
#line 12825 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st579;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr543;
tr543:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st468;
st468:
	if ( ++p == pe )
		goto _test_eof468;
case 468:
#line 12859 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st581;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr545;
tr545:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st469;
st469:
	if ( ++p == pe )
		goto _test_eof469;
case 469:
#line 12893 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st583;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr547;
tr547:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st470;
st470:
	if ( ++p == pe )
		goto _test_eof470;
case 470:
#line 12927 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st585;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr549;
tr549:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st471;
st471:
	if ( ++p == pe )
		goto _test_eof471;
case 471:
#line 12961 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st587;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr551;
tr551:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st472;
st472:
	if ( ++p == pe )
		goto _test_eof472;
case 472:
#line 12995 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st589;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr553;
tr553:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st473;
st473:
	if ( ++p == pe )
		goto _test_eof473;
case 473:
#line 13029 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st591;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr555;
tr555:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st474;
st474:
	if ( ++p == pe )
		goto _test_eof474;
case 474:
#line 13063 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st593;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr557;
tr557:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st475;
st475:
	if ( ++p == pe )
		goto _test_eof475;
case 475:
#line 13097 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st595;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr559;
tr559:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st476;
st476:
	if ( ++p == pe )
		goto _test_eof476;
case 476:
#line 13131 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st597;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr561;
tr561:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st477;
st477:
	if ( ++p == pe )
		goto _test_eof477;
case 477:
#line 13165 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st599;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr563;
tr563:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st478;
st478:
	if ( ++p == pe )
		goto _test_eof478;
case 478:
#line 13199 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st601;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr565;
tr565:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st479;
st479:
	if ( ++p == pe )
		goto _test_eof479;
case 479:
#line 13233 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st603;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr567;
tr567:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st480;
st480:
	if ( ++p == pe )
		goto _test_eof480;
case 480:
#line 13267 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st605;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr569;
tr569:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st481;
st481:
	if ( ++p == pe )
		goto _test_eof481;
case 481:
#line 13301 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st607;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr571;
tr571:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st482;
st482:
	if ( ++p == pe )
		goto _test_eof482;
case 482:
#line 13335 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr447;
		case 34: goto tr447;
		case 36: goto tr447;
		case 46: goto tr451;
		case 59: goto tr447;
		case 64: goto tr447;
		case 92: goto st609;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr447;
	} else if ( (*p) >= 9 )
		goto tr447;
	goto tr573;
tr573:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st483;
st483:
	if ( ++p == pe )
		goto _test_eof483;
case 483:
#line 13369 "rzonec.c"
	if ( (*p) == 46 )
		goto tr451;
	goto tr447;
tr451:
#line 100 "zparser.rl"
	{
        parser->dname_wire[parser->label_head] =
            (parser->dname_size - parser->label_head - 1);
    }
	goto st484;
st484:
	if ( ++p == pe )
		goto _test_eof484;
case 484:
#line 13384 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr576;
		case 10: goto tr577;
		case 32: goto tr576;
		case 34: goto tr578;
		case 36: goto tr578;
		case 46: goto tr578;
		case 59: goto tr579;
		case 64: goto tr578;
		case 92: goto tr580;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr578;
	} else if ( (*p) >= 11 )
		goto tr578;
	goto tr575;
tr580:
#line 70 "zparser.rl"
	{
        parser->label_head = parser->dname_size;
        parser->dname_size++;
    }
	goto st485;
tr449:
#line 104 "zparser.rl"
	{
        bzero(&parser->dname_wire[0], DNAME_MAXLEN);
        bzero(&parser->label_offsets[0], DNAME_MAXLEN);
        parser->dname_size = 0;
        parser->label_count = 0;
        parser->label = parser->dname_wire;
    }
#line 70 "zparser.rl"
	{
        parser->label_head = parser->dname_size;
        parser->dname_size++;
    }
	goto st485;
st485:
	if ( ++p == pe )
		goto _test_eof485;
case 485:
#line 13428 "rzonec.c"
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr582;
	goto tr581;
tr581:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st486;
st486:
	if ( ++p == pe )
		goto _test_eof486;
case 486:
#line 13453 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st487;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr450;
st487:
	if ( ++p == pe )
		goto _test_eof487;
case 487:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr586;
	goto tr585;
tr585:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st488;
st488:
	if ( ++p == pe )
		goto _test_eof488;
case 488:
#line 13497 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st489;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr453;
st489:
	if ( ++p == pe )
		goto _test_eof489;
case 489:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr588;
	goto tr587;
tr587:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st490;
st490:
	if ( ++p == pe )
		goto _test_eof490;
case 490:
#line 13541 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st491;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr455;
st491:
	if ( ++p == pe )
		goto _test_eof491;
case 491:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr590;
	goto tr589;
tr589:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st492;
st492:
	if ( ++p == pe )
		goto _test_eof492;
case 492:
#line 13585 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st493;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr457;
st493:
	if ( ++p == pe )
		goto _test_eof493;
case 493:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr592;
	goto tr591;
tr591:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st494;
st494:
	if ( ++p == pe )
		goto _test_eof494;
case 494:
#line 13629 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st495;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr459;
st495:
	if ( ++p == pe )
		goto _test_eof495;
case 495:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr594;
	goto tr593;
tr593:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st496;
st496:
	if ( ++p == pe )
		goto _test_eof496;
case 496:
#line 13673 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st497;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr461;
st497:
	if ( ++p == pe )
		goto _test_eof497;
case 497:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr596;
	goto tr595;
tr595:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st498;
st498:
	if ( ++p == pe )
		goto _test_eof498;
case 498:
#line 13717 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st499;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr463;
st499:
	if ( ++p == pe )
		goto _test_eof499;
case 499:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr598;
	goto tr597;
tr597:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st500;
st500:
	if ( ++p == pe )
		goto _test_eof500;
case 500:
#line 13761 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st501;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr465;
st501:
	if ( ++p == pe )
		goto _test_eof501;
case 501:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr600;
	goto tr599;
tr599:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st502;
st502:
	if ( ++p == pe )
		goto _test_eof502;
case 502:
#line 13805 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st503;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr467;
st503:
	if ( ++p == pe )
		goto _test_eof503;
case 503:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr602;
	goto tr601;
tr601:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st504;
st504:
	if ( ++p == pe )
		goto _test_eof504;
case 504:
#line 13849 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st505;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr469;
st505:
	if ( ++p == pe )
		goto _test_eof505;
case 505:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr604;
	goto tr603;
tr603:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st506;
st506:
	if ( ++p == pe )
		goto _test_eof506;
case 506:
#line 13893 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st507;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr471;
st507:
	if ( ++p == pe )
		goto _test_eof507;
case 507:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr606;
	goto tr605;
tr605:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st508;
st508:
	if ( ++p == pe )
		goto _test_eof508;
case 508:
#line 13937 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st509;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr473;
st509:
	if ( ++p == pe )
		goto _test_eof509;
case 509:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr608;
	goto tr607;
tr607:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st510;
st510:
	if ( ++p == pe )
		goto _test_eof510;
case 510:
#line 13981 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st511;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr475;
st511:
	if ( ++p == pe )
		goto _test_eof511;
case 511:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr610;
	goto tr609;
tr609:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st512;
st512:
	if ( ++p == pe )
		goto _test_eof512;
case 512:
#line 14025 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st513;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr477;
st513:
	if ( ++p == pe )
		goto _test_eof513;
case 513:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr612;
	goto tr611;
tr611:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st514;
st514:
	if ( ++p == pe )
		goto _test_eof514;
case 514:
#line 14069 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st515;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr479;
st515:
	if ( ++p == pe )
		goto _test_eof515;
case 515:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr614;
	goto tr613;
tr613:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st516;
st516:
	if ( ++p == pe )
		goto _test_eof516;
case 516:
#line 14113 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st517;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr481;
st517:
	if ( ++p == pe )
		goto _test_eof517;
case 517:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr616;
	goto tr615;
tr615:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st518;
st518:
	if ( ++p == pe )
		goto _test_eof518;
case 518:
#line 14157 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st519;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr483;
st519:
	if ( ++p == pe )
		goto _test_eof519;
case 519:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr618;
	goto tr617;
tr617:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st520;
st520:
	if ( ++p == pe )
		goto _test_eof520;
case 520:
#line 14201 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st521;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr485;
st521:
	if ( ++p == pe )
		goto _test_eof521;
case 521:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr620;
	goto tr619;
tr619:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st522;
st522:
	if ( ++p == pe )
		goto _test_eof522;
case 522:
#line 14245 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st523;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr487;
st523:
	if ( ++p == pe )
		goto _test_eof523;
case 523:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr622;
	goto tr621;
tr621:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st524;
st524:
	if ( ++p == pe )
		goto _test_eof524;
case 524:
#line 14289 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st525;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr489;
st525:
	if ( ++p == pe )
		goto _test_eof525;
case 525:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr624;
	goto tr623;
tr623:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st526;
st526:
	if ( ++p == pe )
		goto _test_eof526;
case 526:
#line 14333 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st527;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr491;
st527:
	if ( ++p == pe )
		goto _test_eof527;
case 527:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr626;
	goto tr625;
tr625:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st528;
st528:
	if ( ++p == pe )
		goto _test_eof528;
case 528:
#line 14377 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st529;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr493;
st529:
	if ( ++p == pe )
		goto _test_eof529;
case 529:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr628;
	goto tr627;
tr627:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st530;
st530:
	if ( ++p == pe )
		goto _test_eof530;
case 530:
#line 14421 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st531;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr495;
st531:
	if ( ++p == pe )
		goto _test_eof531;
case 531:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr630;
	goto tr629;
tr629:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st532;
st532:
	if ( ++p == pe )
		goto _test_eof532;
case 532:
#line 14465 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st533;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr497;
st533:
	if ( ++p == pe )
		goto _test_eof533;
case 533:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr632;
	goto tr631;
tr631:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st534;
st534:
	if ( ++p == pe )
		goto _test_eof534;
case 534:
#line 14509 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st535;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr499;
st535:
	if ( ++p == pe )
		goto _test_eof535;
case 535:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr634;
	goto tr633;
tr633:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st536;
st536:
	if ( ++p == pe )
		goto _test_eof536;
case 536:
#line 14553 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st537;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr501;
st537:
	if ( ++p == pe )
		goto _test_eof537;
case 537:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr636;
	goto tr635;
tr635:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st538;
st538:
	if ( ++p == pe )
		goto _test_eof538;
case 538:
#line 14597 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st539;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr503;
st539:
	if ( ++p == pe )
		goto _test_eof539;
case 539:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr638;
	goto tr637;
tr637:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st540;
st540:
	if ( ++p == pe )
		goto _test_eof540;
case 540:
#line 14641 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st541;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr505;
st541:
	if ( ++p == pe )
		goto _test_eof541;
case 541:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr640;
	goto tr639;
tr639:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st542;
st542:
	if ( ++p == pe )
		goto _test_eof542;
case 542:
#line 14685 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st543;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr507;
st543:
	if ( ++p == pe )
		goto _test_eof543;
case 543:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr642;
	goto tr641;
tr641:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st544;
st544:
	if ( ++p == pe )
		goto _test_eof544;
case 544:
#line 14729 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st545;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr509;
st545:
	if ( ++p == pe )
		goto _test_eof545;
case 545:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr644;
	goto tr643;
tr643:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st546;
st546:
	if ( ++p == pe )
		goto _test_eof546;
case 546:
#line 14773 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st547;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr511;
st547:
	if ( ++p == pe )
		goto _test_eof547;
case 547:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr646;
	goto tr645;
tr645:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st548;
st548:
	if ( ++p == pe )
		goto _test_eof548;
case 548:
#line 14817 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st549;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr513;
st549:
	if ( ++p == pe )
		goto _test_eof549;
case 549:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr648;
	goto tr647;
tr647:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st550;
st550:
	if ( ++p == pe )
		goto _test_eof550;
case 550:
#line 14861 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st551;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr515;
st551:
	if ( ++p == pe )
		goto _test_eof551;
case 551:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr650;
	goto tr649;
tr649:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st552;
st552:
	if ( ++p == pe )
		goto _test_eof552;
case 552:
#line 14905 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st553;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr517;
st553:
	if ( ++p == pe )
		goto _test_eof553;
case 553:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr652;
	goto tr651;
tr651:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st554;
st554:
	if ( ++p == pe )
		goto _test_eof554;
case 554:
#line 14949 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st555;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr519;
st555:
	if ( ++p == pe )
		goto _test_eof555;
case 555:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr654;
	goto tr653;
tr653:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st556;
st556:
	if ( ++p == pe )
		goto _test_eof556;
case 556:
#line 14993 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st557;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr521;
st557:
	if ( ++p == pe )
		goto _test_eof557;
case 557:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr656;
	goto tr655;
tr655:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st558;
st558:
	if ( ++p == pe )
		goto _test_eof558;
case 558:
#line 15037 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st559;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr523;
st559:
	if ( ++p == pe )
		goto _test_eof559;
case 559:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr658;
	goto tr657;
tr657:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st560;
st560:
	if ( ++p == pe )
		goto _test_eof560;
case 560:
#line 15081 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st561;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr525;
st561:
	if ( ++p == pe )
		goto _test_eof561;
case 561:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr660;
	goto tr659;
tr659:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st562;
st562:
	if ( ++p == pe )
		goto _test_eof562;
case 562:
#line 15125 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st563;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr527;
st563:
	if ( ++p == pe )
		goto _test_eof563;
case 563:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr662;
	goto tr661;
tr661:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st564;
st564:
	if ( ++p == pe )
		goto _test_eof564;
case 564:
#line 15169 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st565;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr529;
st565:
	if ( ++p == pe )
		goto _test_eof565;
case 565:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr664;
	goto tr663;
tr663:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st566;
st566:
	if ( ++p == pe )
		goto _test_eof566;
case 566:
#line 15213 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st567;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr531;
st567:
	if ( ++p == pe )
		goto _test_eof567;
case 567:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr666;
	goto tr665;
tr665:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st568;
st568:
	if ( ++p == pe )
		goto _test_eof568;
case 568:
#line 15257 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st569;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr533;
st569:
	if ( ++p == pe )
		goto _test_eof569;
case 569:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr668;
	goto tr667;
tr667:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st570;
st570:
	if ( ++p == pe )
		goto _test_eof570;
case 570:
#line 15301 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st571;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr535;
st571:
	if ( ++p == pe )
		goto _test_eof571;
case 571:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr670;
	goto tr669;
tr669:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st572;
st572:
	if ( ++p == pe )
		goto _test_eof572;
case 572:
#line 15345 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st573;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr537;
st573:
	if ( ++p == pe )
		goto _test_eof573;
case 573:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr672;
	goto tr671;
tr671:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st574;
st574:
	if ( ++p == pe )
		goto _test_eof574;
case 574:
#line 15389 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st575;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr539;
st575:
	if ( ++p == pe )
		goto _test_eof575;
case 575:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr674;
	goto tr673;
tr673:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st576;
st576:
	if ( ++p == pe )
		goto _test_eof576;
case 576:
#line 15433 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st577;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr541;
st577:
	if ( ++p == pe )
		goto _test_eof577;
case 577:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr676;
	goto tr675;
tr675:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st578;
st578:
	if ( ++p == pe )
		goto _test_eof578;
case 578:
#line 15477 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st579;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr543;
st579:
	if ( ++p == pe )
		goto _test_eof579;
case 579:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr678;
	goto tr677;
tr677:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st580;
st580:
	if ( ++p == pe )
		goto _test_eof580;
case 580:
#line 15521 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st581;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr545;
st581:
	if ( ++p == pe )
		goto _test_eof581;
case 581:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr680;
	goto tr679;
tr679:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st582;
st582:
	if ( ++p == pe )
		goto _test_eof582;
case 582:
#line 15565 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st583;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr547;
st583:
	if ( ++p == pe )
		goto _test_eof583;
case 583:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr682;
	goto tr681;
tr681:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st584;
st584:
	if ( ++p == pe )
		goto _test_eof584;
case 584:
#line 15609 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st585;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr549;
st585:
	if ( ++p == pe )
		goto _test_eof585;
case 585:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr684;
	goto tr683;
tr683:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st586;
st586:
	if ( ++p == pe )
		goto _test_eof586;
case 586:
#line 15653 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st587;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr551;
st587:
	if ( ++p == pe )
		goto _test_eof587;
case 587:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr686;
	goto tr685;
tr685:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st588;
st588:
	if ( ++p == pe )
		goto _test_eof588;
case 588:
#line 15697 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st589;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr553;
st589:
	if ( ++p == pe )
		goto _test_eof589;
case 589:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr688;
	goto tr687;
tr687:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st590;
st590:
	if ( ++p == pe )
		goto _test_eof590;
case 590:
#line 15741 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st591;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr555;
st591:
	if ( ++p == pe )
		goto _test_eof591;
case 591:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr690;
	goto tr689;
tr689:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st592;
st592:
	if ( ++p == pe )
		goto _test_eof592;
case 592:
#line 15785 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st593;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr557;
st593:
	if ( ++p == pe )
		goto _test_eof593;
case 593:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr692;
	goto tr691;
tr691:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st594;
st594:
	if ( ++p == pe )
		goto _test_eof594;
case 594:
#line 15829 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st595;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr559;
st595:
	if ( ++p == pe )
		goto _test_eof595;
case 595:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr694;
	goto tr693;
tr693:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st596;
st596:
	if ( ++p == pe )
		goto _test_eof596;
case 596:
#line 15873 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st597;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr561;
st597:
	if ( ++p == pe )
		goto _test_eof597;
case 597:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr696;
	goto tr695;
tr695:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st598;
st598:
	if ( ++p == pe )
		goto _test_eof598;
case 598:
#line 15917 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st599;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr563;
st599:
	if ( ++p == pe )
		goto _test_eof599;
case 599:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr698;
	goto tr697;
tr697:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st600;
st600:
	if ( ++p == pe )
		goto _test_eof600;
case 600:
#line 15961 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st601;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr565;
st601:
	if ( ++p == pe )
		goto _test_eof601;
case 601:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr700;
	goto tr699;
tr699:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st602;
st602:
	if ( ++p == pe )
		goto _test_eof602;
case 602:
#line 16005 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st603;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr567;
st603:
	if ( ++p == pe )
		goto _test_eof603;
case 603:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr702;
	goto tr701;
tr701:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st604;
st604:
	if ( ++p == pe )
		goto _test_eof604;
case 604:
#line 16049 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st605;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr569;
st605:
	if ( ++p == pe )
		goto _test_eof605;
case 605:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr704;
	goto tr703;
tr703:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st606;
st606:
	if ( ++p == pe )
		goto _test_eof606;
case 606:
#line 16093 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st607;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr571;
st607:
	if ( ++p == pe )
		goto _test_eof607;
case 607:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr706;
	goto tr705;
tr705:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st608;
st608:
	if ( ++p == pe )
		goto _test_eof608;
case 608:
#line 16137 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr584;
		case 34: goto tr584;
		case 36: goto tr584;
		case 46: goto tr451;
		case 59: goto tr584;
		case 64: goto tr584;
		case 92: goto st609;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr584;
	} else if ( (*p) >= 9 )
		goto tr584;
	goto tr573;
st609:
	if ( ++p == pe )
		goto _test_eof609;
case 609:
	if ( (*p) > 55 ) {
		if ( 56 <= (*p) && (*p) <= 57 )
			goto tr583;
	} else if ( (*p) >= 48 )
		goto tr708;
	goto tr707;
tr707:
#line 74 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = (*p);
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
	goto st610;
st610:
	if ( ++p == pe )
		goto _test_eof610;
case 610:
#line 16181 "rzonec.c"
	if ( (*p) == 46 )
		goto tr451;
	goto tr584;
tr708:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st611;
st611:
	if ( ++p == pe )
		goto _test_eof611;
case 611:
#line 16208 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr710;
	goto tr709;
tr710:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st612;
st612:
	if ( ++p == pe )
		goto _test_eof612;
case 612:
#line 16223 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr711;
	goto tr709;
tr711:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st613;
st613:
	if ( ++p == pe )
		goto _test_eof613;
case 613:
#line 16238 "rzonec.c"
	if ( (*p) == 46 )
		goto tr451;
	goto tr709;
tr706:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st614;
st614:
	if ( ++p == pe )
		goto _test_eof614;
case 614:
#line 16265 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr712;
	goto tr709;
tr712:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st615;
st615:
	if ( ++p == pe )
		goto _test_eof615;
case 615:
#line 16280 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr713;
	goto tr709;
tr713:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st616;
st616:
	if ( ++p == pe )
		goto _test_eof616;
case 616:
#line 16295 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st609;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr573;
tr704:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st617;
st617:
	if ( ++p == pe )
		goto _test_eof617;
case 617:
#line 16334 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr714;
	goto tr709;
tr714:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st618;
st618:
	if ( ++p == pe )
		goto _test_eof618;
case 618:
#line 16349 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr715;
	goto tr709;
tr715:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st619;
st619:
	if ( ++p == pe )
		goto _test_eof619;
case 619:
#line 16364 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st607;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr571;
tr702:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st620;
st620:
	if ( ++p == pe )
		goto _test_eof620;
case 620:
#line 16403 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr716;
	goto tr709;
tr716:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st621;
st621:
	if ( ++p == pe )
		goto _test_eof621;
case 621:
#line 16418 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr717;
	goto tr709;
tr717:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st622;
st622:
	if ( ++p == pe )
		goto _test_eof622;
case 622:
#line 16433 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st605;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr569;
tr700:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st623;
st623:
	if ( ++p == pe )
		goto _test_eof623;
case 623:
#line 16472 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr718;
	goto tr709;
tr718:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st624;
st624:
	if ( ++p == pe )
		goto _test_eof624;
case 624:
#line 16487 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr719;
	goto tr709;
tr719:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st625;
st625:
	if ( ++p == pe )
		goto _test_eof625;
case 625:
#line 16502 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st603;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr567;
tr698:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st626;
st626:
	if ( ++p == pe )
		goto _test_eof626;
case 626:
#line 16541 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr720;
	goto tr709;
tr720:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st627;
st627:
	if ( ++p == pe )
		goto _test_eof627;
case 627:
#line 16556 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr721;
	goto tr709;
tr721:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st628;
st628:
	if ( ++p == pe )
		goto _test_eof628;
case 628:
#line 16571 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st601;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr565;
tr696:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st629;
st629:
	if ( ++p == pe )
		goto _test_eof629;
case 629:
#line 16610 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr722;
	goto tr709;
tr722:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st630;
st630:
	if ( ++p == pe )
		goto _test_eof630;
case 630:
#line 16625 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr723;
	goto tr709;
tr723:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st631;
st631:
	if ( ++p == pe )
		goto _test_eof631;
case 631:
#line 16640 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st599;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr563;
tr694:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st632;
st632:
	if ( ++p == pe )
		goto _test_eof632;
case 632:
#line 16679 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr724;
	goto tr709;
tr724:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st633;
st633:
	if ( ++p == pe )
		goto _test_eof633;
case 633:
#line 16694 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr725;
	goto tr709;
tr725:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st634;
st634:
	if ( ++p == pe )
		goto _test_eof634;
case 634:
#line 16709 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st597;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr561;
tr692:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st635;
st635:
	if ( ++p == pe )
		goto _test_eof635;
case 635:
#line 16748 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr726;
	goto tr709;
tr726:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st636;
st636:
	if ( ++p == pe )
		goto _test_eof636;
case 636:
#line 16763 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr727;
	goto tr709;
tr727:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st637;
st637:
	if ( ++p == pe )
		goto _test_eof637;
case 637:
#line 16778 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st595;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr559;
tr690:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st638;
st638:
	if ( ++p == pe )
		goto _test_eof638;
case 638:
#line 16817 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr728;
	goto tr709;
tr728:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st639;
st639:
	if ( ++p == pe )
		goto _test_eof639;
case 639:
#line 16832 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr729;
	goto tr709;
tr729:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st640;
st640:
	if ( ++p == pe )
		goto _test_eof640;
case 640:
#line 16847 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st593;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr557;
tr688:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st641;
st641:
	if ( ++p == pe )
		goto _test_eof641;
case 641:
#line 16886 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr730;
	goto tr709;
tr730:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st642;
st642:
	if ( ++p == pe )
		goto _test_eof642;
case 642:
#line 16901 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr731;
	goto tr709;
tr731:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st643;
st643:
	if ( ++p == pe )
		goto _test_eof643;
case 643:
#line 16916 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st591;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr555;
tr686:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st644;
st644:
	if ( ++p == pe )
		goto _test_eof644;
case 644:
#line 16955 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr732;
	goto tr709;
tr732:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st645;
st645:
	if ( ++p == pe )
		goto _test_eof645;
case 645:
#line 16970 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr733;
	goto tr709;
tr733:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st646;
st646:
	if ( ++p == pe )
		goto _test_eof646;
case 646:
#line 16985 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st589;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr553;
tr684:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st647;
st647:
	if ( ++p == pe )
		goto _test_eof647;
case 647:
#line 17024 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr734;
	goto tr709;
tr734:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st648;
st648:
	if ( ++p == pe )
		goto _test_eof648;
case 648:
#line 17039 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr735;
	goto tr709;
tr735:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st649;
st649:
	if ( ++p == pe )
		goto _test_eof649;
case 649:
#line 17054 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st587;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr551;
tr682:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st650;
st650:
	if ( ++p == pe )
		goto _test_eof650;
case 650:
#line 17093 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr736;
	goto tr709;
tr736:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st651;
st651:
	if ( ++p == pe )
		goto _test_eof651;
case 651:
#line 17108 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr737;
	goto tr709;
tr737:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st652;
st652:
	if ( ++p == pe )
		goto _test_eof652;
case 652:
#line 17123 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st585;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr549;
tr680:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st653;
st653:
	if ( ++p == pe )
		goto _test_eof653;
case 653:
#line 17162 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr738;
	goto tr709;
tr738:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st654;
st654:
	if ( ++p == pe )
		goto _test_eof654;
case 654:
#line 17177 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr739;
	goto tr709;
tr739:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st655;
st655:
	if ( ++p == pe )
		goto _test_eof655;
case 655:
#line 17192 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st583;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr547;
tr678:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st656;
st656:
	if ( ++p == pe )
		goto _test_eof656;
case 656:
#line 17231 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr740;
	goto tr709;
tr740:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st657;
st657:
	if ( ++p == pe )
		goto _test_eof657;
case 657:
#line 17246 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr741;
	goto tr709;
tr741:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st658;
st658:
	if ( ++p == pe )
		goto _test_eof658;
case 658:
#line 17261 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st581;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr545;
tr676:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st659;
st659:
	if ( ++p == pe )
		goto _test_eof659;
case 659:
#line 17300 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr742;
	goto tr709;
tr742:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st660;
st660:
	if ( ++p == pe )
		goto _test_eof660;
case 660:
#line 17315 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr743;
	goto tr709;
tr743:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st661;
st661:
	if ( ++p == pe )
		goto _test_eof661;
case 661:
#line 17330 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st579;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr543;
tr674:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st662;
st662:
	if ( ++p == pe )
		goto _test_eof662;
case 662:
#line 17369 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr744;
	goto tr709;
tr744:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st663;
st663:
	if ( ++p == pe )
		goto _test_eof663;
case 663:
#line 17384 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr745;
	goto tr709;
tr745:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st664;
st664:
	if ( ++p == pe )
		goto _test_eof664;
case 664:
#line 17399 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st577;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr541;
tr672:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st665;
st665:
	if ( ++p == pe )
		goto _test_eof665;
case 665:
#line 17438 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr746;
	goto tr709;
tr746:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st666;
st666:
	if ( ++p == pe )
		goto _test_eof666;
case 666:
#line 17453 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr747;
	goto tr709;
tr747:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st667;
st667:
	if ( ++p == pe )
		goto _test_eof667;
case 667:
#line 17468 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st575;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr539;
tr670:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st668;
st668:
	if ( ++p == pe )
		goto _test_eof668;
case 668:
#line 17507 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr748;
	goto tr709;
tr748:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st669;
st669:
	if ( ++p == pe )
		goto _test_eof669;
case 669:
#line 17522 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr749;
	goto tr709;
tr749:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st670;
st670:
	if ( ++p == pe )
		goto _test_eof670;
case 670:
#line 17537 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st573;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr537;
tr668:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st671;
st671:
	if ( ++p == pe )
		goto _test_eof671;
case 671:
#line 17576 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr750;
	goto tr709;
tr750:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st672;
st672:
	if ( ++p == pe )
		goto _test_eof672;
case 672:
#line 17591 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr751;
	goto tr709;
tr751:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st673;
st673:
	if ( ++p == pe )
		goto _test_eof673;
case 673:
#line 17606 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st571;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr535;
tr666:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st674;
st674:
	if ( ++p == pe )
		goto _test_eof674;
case 674:
#line 17645 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr752;
	goto tr709;
tr752:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st675;
st675:
	if ( ++p == pe )
		goto _test_eof675;
case 675:
#line 17660 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr753;
	goto tr709;
tr753:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st676;
st676:
	if ( ++p == pe )
		goto _test_eof676;
case 676:
#line 17675 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st569;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr533;
tr664:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st677;
st677:
	if ( ++p == pe )
		goto _test_eof677;
case 677:
#line 17714 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr754;
	goto tr709;
tr754:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st678;
st678:
	if ( ++p == pe )
		goto _test_eof678;
case 678:
#line 17729 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr755;
	goto tr709;
tr755:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st679;
st679:
	if ( ++p == pe )
		goto _test_eof679;
case 679:
#line 17744 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st567;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr531;
tr662:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st680;
st680:
	if ( ++p == pe )
		goto _test_eof680;
case 680:
#line 17783 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr756;
	goto tr709;
tr756:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st681;
st681:
	if ( ++p == pe )
		goto _test_eof681;
case 681:
#line 17798 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr757;
	goto tr709;
tr757:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st682;
st682:
	if ( ++p == pe )
		goto _test_eof682;
case 682:
#line 17813 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st565;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr529;
tr660:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st683;
st683:
	if ( ++p == pe )
		goto _test_eof683;
case 683:
#line 17852 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr758;
	goto tr709;
tr758:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st684;
st684:
	if ( ++p == pe )
		goto _test_eof684;
case 684:
#line 17867 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr759;
	goto tr709;
tr759:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st685;
st685:
	if ( ++p == pe )
		goto _test_eof685;
case 685:
#line 17882 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st563;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr527;
tr658:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st686;
st686:
	if ( ++p == pe )
		goto _test_eof686;
case 686:
#line 17921 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr760;
	goto tr709;
tr760:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st687;
st687:
	if ( ++p == pe )
		goto _test_eof687;
case 687:
#line 17936 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr761;
	goto tr709;
tr761:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st688;
st688:
	if ( ++p == pe )
		goto _test_eof688;
case 688:
#line 17951 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st561;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr525;
tr656:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st689;
st689:
	if ( ++p == pe )
		goto _test_eof689;
case 689:
#line 17990 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr762;
	goto tr709;
tr762:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st690;
st690:
	if ( ++p == pe )
		goto _test_eof690;
case 690:
#line 18005 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr763;
	goto tr709;
tr763:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st691;
st691:
	if ( ++p == pe )
		goto _test_eof691;
case 691:
#line 18020 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st559;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr523;
tr654:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st692;
st692:
	if ( ++p == pe )
		goto _test_eof692;
case 692:
#line 18059 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr764;
	goto tr709;
tr764:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st693;
st693:
	if ( ++p == pe )
		goto _test_eof693;
case 693:
#line 18074 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr765;
	goto tr709;
tr765:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st694;
st694:
	if ( ++p == pe )
		goto _test_eof694;
case 694:
#line 18089 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st557;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr521;
tr652:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st695;
st695:
	if ( ++p == pe )
		goto _test_eof695;
case 695:
#line 18128 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr766;
	goto tr709;
tr766:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st696;
st696:
	if ( ++p == pe )
		goto _test_eof696;
case 696:
#line 18143 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr767;
	goto tr709;
tr767:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st697;
st697:
	if ( ++p == pe )
		goto _test_eof697;
case 697:
#line 18158 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st555;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr519;
tr650:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st698;
st698:
	if ( ++p == pe )
		goto _test_eof698;
case 698:
#line 18197 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr768;
	goto tr709;
tr768:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st699;
st699:
	if ( ++p == pe )
		goto _test_eof699;
case 699:
#line 18212 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr769;
	goto tr709;
tr769:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st700;
st700:
	if ( ++p == pe )
		goto _test_eof700;
case 700:
#line 18227 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st553;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr517;
tr648:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st701;
st701:
	if ( ++p == pe )
		goto _test_eof701;
case 701:
#line 18266 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr770;
	goto tr709;
tr770:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st702;
st702:
	if ( ++p == pe )
		goto _test_eof702;
case 702:
#line 18281 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr771;
	goto tr709;
tr771:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st703;
st703:
	if ( ++p == pe )
		goto _test_eof703;
case 703:
#line 18296 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st551;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr515;
tr646:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st704;
st704:
	if ( ++p == pe )
		goto _test_eof704;
case 704:
#line 18335 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr772;
	goto tr709;
tr772:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st705;
st705:
	if ( ++p == pe )
		goto _test_eof705;
case 705:
#line 18350 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr773;
	goto tr709;
tr773:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st706;
st706:
	if ( ++p == pe )
		goto _test_eof706;
case 706:
#line 18365 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st549;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr513;
tr644:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st707;
st707:
	if ( ++p == pe )
		goto _test_eof707;
case 707:
#line 18404 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr774;
	goto tr709;
tr774:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st708;
st708:
	if ( ++p == pe )
		goto _test_eof708;
case 708:
#line 18419 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr775;
	goto tr709;
tr775:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st709;
st709:
	if ( ++p == pe )
		goto _test_eof709;
case 709:
#line 18434 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st547;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr511;
tr642:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st710;
st710:
	if ( ++p == pe )
		goto _test_eof710;
case 710:
#line 18473 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr776;
	goto tr709;
tr776:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st711;
st711:
	if ( ++p == pe )
		goto _test_eof711;
case 711:
#line 18488 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr777;
	goto tr709;
tr777:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st712;
st712:
	if ( ++p == pe )
		goto _test_eof712;
case 712:
#line 18503 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st545;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr509;
tr640:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st713;
st713:
	if ( ++p == pe )
		goto _test_eof713;
case 713:
#line 18542 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr778;
	goto tr709;
tr778:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st714;
st714:
	if ( ++p == pe )
		goto _test_eof714;
case 714:
#line 18557 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr779;
	goto tr709;
tr779:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st715;
st715:
	if ( ++p == pe )
		goto _test_eof715;
case 715:
#line 18572 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st543;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr507;
tr638:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st716;
st716:
	if ( ++p == pe )
		goto _test_eof716;
case 716:
#line 18611 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr780;
	goto tr709;
tr780:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st717;
st717:
	if ( ++p == pe )
		goto _test_eof717;
case 717:
#line 18626 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr781;
	goto tr709;
tr781:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st718;
st718:
	if ( ++p == pe )
		goto _test_eof718;
case 718:
#line 18641 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st541;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr505;
tr636:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st719;
st719:
	if ( ++p == pe )
		goto _test_eof719;
case 719:
#line 18680 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr782;
	goto tr709;
tr782:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st720;
st720:
	if ( ++p == pe )
		goto _test_eof720;
case 720:
#line 18695 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr783;
	goto tr709;
tr783:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st721;
st721:
	if ( ++p == pe )
		goto _test_eof721;
case 721:
#line 18710 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st539;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr503;
tr634:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st722;
st722:
	if ( ++p == pe )
		goto _test_eof722;
case 722:
#line 18749 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr784;
	goto tr709;
tr784:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st723;
st723:
	if ( ++p == pe )
		goto _test_eof723;
case 723:
#line 18764 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr785;
	goto tr709;
tr785:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st724;
st724:
	if ( ++p == pe )
		goto _test_eof724;
case 724:
#line 18779 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st537;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr501;
tr632:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st725;
st725:
	if ( ++p == pe )
		goto _test_eof725;
case 725:
#line 18818 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr786;
	goto tr709;
tr786:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st726;
st726:
	if ( ++p == pe )
		goto _test_eof726;
case 726:
#line 18833 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr787;
	goto tr709;
tr787:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st727;
st727:
	if ( ++p == pe )
		goto _test_eof727;
case 727:
#line 18848 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st535;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr499;
tr630:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st728;
st728:
	if ( ++p == pe )
		goto _test_eof728;
case 728:
#line 18887 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr788;
	goto tr709;
tr788:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st729;
st729:
	if ( ++p == pe )
		goto _test_eof729;
case 729:
#line 18902 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr789;
	goto tr709;
tr789:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st730;
st730:
	if ( ++p == pe )
		goto _test_eof730;
case 730:
#line 18917 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st533;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr497;
tr628:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st731;
st731:
	if ( ++p == pe )
		goto _test_eof731;
case 731:
#line 18956 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr790;
	goto tr709;
tr790:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st732;
st732:
	if ( ++p == pe )
		goto _test_eof732;
case 732:
#line 18971 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr791;
	goto tr709;
tr791:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st733;
st733:
	if ( ++p == pe )
		goto _test_eof733;
case 733:
#line 18986 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st531;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr495;
tr626:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st734;
st734:
	if ( ++p == pe )
		goto _test_eof734;
case 734:
#line 19025 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr792;
	goto tr709;
tr792:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st735;
st735:
	if ( ++p == pe )
		goto _test_eof735;
case 735:
#line 19040 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr793;
	goto tr709;
tr793:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st736;
st736:
	if ( ++p == pe )
		goto _test_eof736;
case 736:
#line 19055 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st529;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr493;
tr624:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st737;
st737:
	if ( ++p == pe )
		goto _test_eof737;
case 737:
#line 19094 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr794;
	goto tr709;
tr794:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st738;
st738:
	if ( ++p == pe )
		goto _test_eof738;
case 738:
#line 19109 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr795;
	goto tr709;
tr795:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st739;
st739:
	if ( ++p == pe )
		goto _test_eof739;
case 739:
#line 19124 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st527;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr491;
tr622:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st740;
st740:
	if ( ++p == pe )
		goto _test_eof740;
case 740:
#line 19163 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr796;
	goto tr709;
tr796:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st741;
st741:
	if ( ++p == pe )
		goto _test_eof741;
case 741:
#line 19178 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr797;
	goto tr709;
tr797:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st742;
st742:
	if ( ++p == pe )
		goto _test_eof742;
case 742:
#line 19193 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st525;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr489;
tr620:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st743;
st743:
	if ( ++p == pe )
		goto _test_eof743;
case 743:
#line 19232 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr798;
	goto tr709;
tr798:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st744;
st744:
	if ( ++p == pe )
		goto _test_eof744;
case 744:
#line 19247 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr799;
	goto tr709;
tr799:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st745;
st745:
	if ( ++p == pe )
		goto _test_eof745;
case 745:
#line 19262 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st523;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr487;
tr618:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st746;
st746:
	if ( ++p == pe )
		goto _test_eof746;
case 746:
#line 19301 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr800;
	goto tr709;
tr800:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st747;
st747:
	if ( ++p == pe )
		goto _test_eof747;
case 747:
#line 19316 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr801;
	goto tr709;
tr801:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st748;
st748:
	if ( ++p == pe )
		goto _test_eof748;
case 748:
#line 19331 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st521;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr485;
tr616:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st749;
st749:
	if ( ++p == pe )
		goto _test_eof749;
case 749:
#line 19370 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr802;
	goto tr709;
tr802:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st750;
st750:
	if ( ++p == pe )
		goto _test_eof750;
case 750:
#line 19385 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr803;
	goto tr709;
tr803:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st751;
st751:
	if ( ++p == pe )
		goto _test_eof751;
case 751:
#line 19400 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st519;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr483;
tr614:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st752;
st752:
	if ( ++p == pe )
		goto _test_eof752;
case 752:
#line 19439 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr804;
	goto tr709;
tr804:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st753;
st753:
	if ( ++p == pe )
		goto _test_eof753;
case 753:
#line 19454 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr805;
	goto tr709;
tr805:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st754;
st754:
	if ( ++p == pe )
		goto _test_eof754;
case 754:
#line 19469 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st517;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr481;
tr612:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st755;
st755:
	if ( ++p == pe )
		goto _test_eof755;
case 755:
#line 19508 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr806;
	goto tr709;
tr806:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st756;
st756:
	if ( ++p == pe )
		goto _test_eof756;
case 756:
#line 19523 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr807;
	goto tr709;
tr807:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st757;
st757:
	if ( ++p == pe )
		goto _test_eof757;
case 757:
#line 19538 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st515;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr479;
tr610:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st758;
st758:
	if ( ++p == pe )
		goto _test_eof758;
case 758:
#line 19577 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr808;
	goto tr709;
tr808:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st759;
st759:
	if ( ++p == pe )
		goto _test_eof759;
case 759:
#line 19592 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr809;
	goto tr709;
tr809:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st760;
st760:
	if ( ++p == pe )
		goto _test_eof760;
case 760:
#line 19607 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st513;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr477;
tr608:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st761;
st761:
	if ( ++p == pe )
		goto _test_eof761;
case 761:
#line 19646 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr810;
	goto tr709;
tr810:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st762;
st762:
	if ( ++p == pe )
		goto _test_eof762;
case 762:
#line 19661 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr811;
	goto tr709;
tr811:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st763;
st763:
	if ( ++p == pe )
		goto _test_eof763;
case 763:
#line 19676 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st511;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr475;
tr606:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st764;
st764:
	if ( ++p == pe )
		goto _test_eof764;
case 764:
#line 19715 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr812;
	goto tr709;
tr812:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st765;
st765:
	if ( ++p == pe )
		goto _test_eof765;
case 765:
#line 19730 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr813;
	goto tr709;
tr813:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st766;
st766:
	if ( ++p == pe )
		goto _test_eof766;
case 766:
#line 19745 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st509;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr473;
tr604:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st767;
st767:
	if ( ++p == pe )
		goto _test_eof767;
case 767:
#line 19784 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr814;
	goto tr709;
tr814:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st768;
st768:
	if ( ++p == pe )
		goto _test_eof768;
case 768:
#line 19799 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr815;
	goto tr709;
tr815:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st769;
st769:
	if ( ++p == pe )
		goto _test_eof769;
case 769:
#line 19814 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st507;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr471;
tr602:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st770;
st770:
	if ( ++p == pe )
		goto _test_eof770;
case 770:
#line 19853 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr816;
	goto tr709;
tr816:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st771;
st771:
	if ( ++p == pe )
		goto _test_eof771;
case 771:
#line 19868 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr817;
	goto tr709;
tr817:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st772;
st772:
	if ( ++p == pe )
		goto _test_eof772;
case 772:
#line 19883 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st505;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr469;
tr600:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st773;
st773:
	if ( ++p == pe )
		goto _test_eof773;
case 773:
#line 19922 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr818;
	goto tr709;
tr818:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st774;
st774:
	if ( ++p == pe )
		goto _test_eof774;
case 774:
#line 19937 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr819;
	goto tr709;
tr819:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st775;
st775:
	if ( ++p == pe )
		goto _test_eof775;
case 775:
#line 19952 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st503;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr467;
tr598:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st776;
st776:
	if ( ++p == pe )
		goto _test_eof776;
case 776:
#line 19991 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr820;
	goto tr709;
tr820:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st777;
st777:
	if ( ++p == pe )
		goto _test_eof777;
case 777:
#line 20006 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr821;
	goto tr709;
tr821:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st778;
st778:
	if ( ++p == pe )
		goto _test_eof778;
case 778:
#line 20021 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st501;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr465;
tr596:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st779;
st779:
	if ( ++p == pe )
		goto _test_eof779;
case 779:
#line 20060 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr822;
	goto tr709;
tr822:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st780;
st780:
	if ( ++p == pe )
		goto _test_eof780;
case 780:
#line 20075 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr823;
	goto tr709;
tr823:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st781;
st781:
	if ( ++p == pe )
		goto _test_eof781;
case 781:
#line 20090 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st499;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr463;
tr594:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st782;
st782:
	if ( ++p == pe )
		goto _test_eof782;
case 782:
#line 20129 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr824;
	goto tr709;
tr824:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st783;
st783:
	if ( ++p == pe )
		goto _test_eof783;
case 783:
#line 20144 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr825;
	goto tr709;
tr825:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st784;
st784:
	if ( ++p == pe )
		goto _test_eof784;
case 784:
#line 20159 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st497;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr461;
tr592:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st785;
st785:
	if ( ++p == pe )
		goto _test_eof785;
case 785:
#line 20198 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr826;
	goto tr709;
tr826:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st786;
st786:
	if ( ++p == pe )
		goto _test_eof786;
case 786:
#line 20213 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr827;
	goto tr709;
tr827:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st787;
st787:
	if ( ++p == pe )
		goto _test_eof787;
case 787:
#line 20228 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st495;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr459;
tr590:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st788;
st788:
	if ( ++p == pe )
		goto _test_eof788;
case 788:
#line 20267 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr828;
	goto tr709;
tr828:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st789;
st789:
	if ( ++p == pe )
		goto _test_eof789;
case 789:
#line 20282 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr829;
	goto tr709;
tr829:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st790;
st790:
	if ( ++p == pe )
		goto _test_eof790;
case 790:
#line 20297 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st493;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr457;
tr588:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st791;
st791:
	if ( ++p == pe )
		goto _test_eof791;
case 791:
#line 20336 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr830;
	goto tr709;
tr830:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st792;
st792:
	if ( ++p == pe )
		goto _test_eof792;
case 792:
#line 20351 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr831;
	goto tr709;
tr831:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st793;
st793:
	if ( ++p == pe )
		goto _test_eof793;
case 793:
#line 20366 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st491;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr455;
tr586:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st794;
st794:
	if ( ++p == pe )
		goto _test_eof794;
case 794:
#line 20405 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr832;
	goto tr709;
tr832:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st795;
st795:
	if ( ++p == pe )
		goto _test_eof795;
case 795:
#line 20420 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr833;
	goto tr709;
tr833:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st796;
st796:
	if ( ++p == pe )
		goto _test_eof796;
case 796:
#line 20435 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st489;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr453;
tr582:
#line 85 "zparser.rl"
	{
        if (parser->dname_size < DNAME_MAXLEN) {
            parser->dname_wire[parser->dname_size] = 0;
            parser->dname_size++;
        } else {
            fprintf(stderr, "[zparser] error: line %d: domain name overflow\n",
                parser->line);
            parser->totalerrors++;
            p--; {goto st809;}
        }
    }
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st797;
st797:
	if ( ++p == pe )
		goto _test_eof797;
case 797:
#line 20474 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr834;
	goto tr709;
tr834:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st798;
st798:
	if ( ++p == pe )
		goto _test_eof798;
case 798:
#line 20489 "rzonec.c"
	if ( 48 <= (*p) && (*p) <= 55 )
		goto tr835;
	goto tr709;
tr835:
#line 96 "zparser.rl"
	{
        parser->dname_wire[parser->dname_size-1] *= 10;
        parser->dname_wire[parser->dname_size-1] += ((*p) - '0');
    }
	goto st799;
st799:
	if ( ++p == pe )
		goto _test_eof799;
case 799:
#line 20504 "rzonec.c"
	switch( (*p) ) {
		case 32: goto tr709;
		case 34: goto tr709;
		case 36: goto tr709;
		case 46: goto tr451;
		case 59: goto tr709;
		case 64: goto tr709;
		case 92: goto st487;
	}
	if ( (*p) > 13 ) {
		if ( 40 <= (*p) && (*p) <= 41 )
			goto tr709;
	} else if ( (*p) >= 9 )
		goto tr709;
	goto tr450;
tr448:
#line 104 "zparser.rl"
	{
        bzero(&parser->dname_wire[0], DNAME_MAXLEN);
        bzero(&parser->label_offsets[0], DNAME_MAXLEN);
        parser->dname_size = 0;
        parser->label_count = 0;
        parser->label = parser->dname_wire;
    }
	goto st800;
st800:
	if ( ++p == pe )
		goto _test_eof800;
case 800:
#line 20534 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr576;
		case 10: goto tr577;
		case 32: goto tr576;
		case 59: goto tr579;
	}
	goto tr836;
st801:
	if ( ++p == pe )
		goto _test_eof801;
case 801:
	if ( (*p) == 84 )
		goto st802;
	goto st0;
st802:
	if ( ++p == pe )
		goto _test_eof802;
case 802:
	if ( (*p) == 76 )
		goto st803;
	goto st0;
st803:
	if ( ++p == pe )
		goto _test_eof803;
case 803:
	switch( (*p) ) {
		case 9: goto st804;
		case 32: goto st804;
	}
	goto st0;
st804:
	if ( ++p == pe )
		goto _test_eof804;
case 804:
	switch( (*p) ) {
		case 9: goto st804;
		case 32: goto st804;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr841;
	goto tr840;
tr841:
#line 55 "zparser.rl"
	{
        parser->seconds = 0;
        parser->number = 0;
    }
#line 25 "zparser.rl"
	{
        parser->number *= 10;
        parser->number += ((*p) - '0');
    }
	goto st805;
tr845:
#line 25 "zparser.rl"
	{
        parser->number *= 10;
        parser->number += ((*p) - '0');
    }
	goto st805;
st805:
	if ( ++p == pe )
		goto _test_eof805;
case 805:
#line 20599 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr843;
		case 10: goto tr844;
		case 32: goto tr843;
		case 59: goto tr846;
		case 68: goto tr847;
		case 72: goto tr847;
		case 77: goto tr847;
		case 83: goto tr847;
		case 87: goto tr847;
		case 100: goto tr847;
		case 104: goto tr847;
		case 109: goto tr847;
		case 115: goto tr847;
		case 119: goto tr847;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr845;
	goto tr842;
tr847:
#line 29 "zparser.rl"
	{
        switch ((*p)) {
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
	goto st806;
st806:
	if ( ++p == pe )
		goto _test_eof806;
case 806:
#line 20652 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr843;
		case 10: goto tr844;
		case 32: goto tr843;
		case 59: goto tr846;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr845;
	goto tr842;
tr854:
#line 174 "zparser.rl"
	{
        parser->current_rr.owner = NULL;
        parser->current_rr.ttl = parser->ttl;
        parser->current_rr.klass = parser->klass;
        parser->current_rr.type = 0;
        parser->current_rr.rdlen = 0;
        parser->current_rr.rdata = parser->tmp_rdata;
    }
#line 104 "zparser.rl"
	{
        bzero(&parser->dname_wire[0], DNAME_MAXLEN);
        bzero(&parser->label_offsets[0], DNAME_MAXLEN);
        parser->dname_size = 0;
        parser->label_count = 0;
        parser->label = parser->dname_wire;
    }
	goto st807;
st807:
	if ( ++p == pe )
		goto _test_eof807;
case 807:
#line 20685 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr180;
		case 32: goto tr180;
	}
	goto tr168;
tr855:
#line 174 "zparser.rl"
	{
        parser->current_rr.owner = NULL;
        parser->current_rr.ttl = parser->ttl;
        parser->current_rr.klass = parser->klass;
        parser->current_rr.type = 0;
        parser->current_rr.rdlen = 0;
        parser->current_rr.rdata = parser->tmp_rdata;
    }
#line 111 "zparser.rl"
	{
        parser->dname = parser->origin;
    }
	goto st808;
st808:
	if ( ++p == pe )
		goto _test_eof808;
case 808:
#line 20710 "rzonec.c"
	switch( (*p) ) {
		case 9: goto tr848;
		case 32: goto tr848;
	}
	goto tr168;
st809:
	if ( ++p == pe )
		goto _test_eof809;
case 809:
	if ( (*p) == 10 )
		goto tr850;
	goto st809;
tr850:
#line 17 "zparser.rl"
	{
        parser->line++;
    }
#line 421 "zparser.rl"
	{ {goto st810;} }
	goto st811;
st811:
	if ( ++p == pe )
		goto _test_eof811;
case 811:
#line 20735 "rzonec.c"
	goto st0;
	}
	_test_eof810: cs = 810; goto _test_eof; 
	_test_eof1: cs = 1; goto _test_eof; 
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof11: cs = 11; goto _test_eof; 
	_test_eof12: cs = 12; goto _test_eof; 
	_test_eof13: cs = 13; goto _test_eof; 
	_test_eof14: cs = 14; goto _test_eof; 
	_test_eof15: cs = 15; goto _test_eof; 
	_test_eof16: cs = 16; goto _test_eof; 
	_test_eof17: cs = 17; goto _test_eof; 
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 
	_test_eof24: cs = 24; goto _test_eof; 
	_test_eof25: cs = 25; goto _test_eof; 
	_test_eof26: cs = 26; goto _test_eof; 
	_test_eof27: cs = 27; goto _test_eof; 
	_test_eof28: cs = 28; goto _test_eof; 
	_test_eof29: cs = 29; goto _test_eof; 
	_test_eof30: cs = 30; goto _test_eof; 
	_test_eof31: cs = 31; goto _test_eof; 
	_test_eof32: cs = 32; goto _test_eof; 
	_test_eof33: cs = 33; goto _test_eof; 
	_test_eof34: cs = 34; goto _test_eof; 
	_test_eof35: cs = 35; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
	_test_eof40: cs = 40; goto _test_eof; 
	_test_eof41: cs = 41; goto _test_eof; 
	_test_eof42: cs = 42; goto _test_eof; 
	_test_eof43: cs = 43; goto _test_eof; 
	_test_eof44: cs = 44; goto _test_eof; 
	_test_eof45: cs = 45; goto _test_eof; 
	_test_eof46: cs = 46; goto _test_eof; 
	_test_eof47: cs = 47; goto _test_eof; 
	_test_eof48: cs = 48; goto _test_eof; 
	_test_eof49: cs = 49; goto _test_eof; 
	_test_eof50: cs = 50; goto _test_eof; 
	_test_eof51: cs = 51; goto _test_eof; 
	_test_eof52: cs = 52; goto _test_eof; 
	_test_eof53: cs = 53; goto _test_eof; 
	_test_eof54: cs = 54; goto _test_eof; 
	_test_eof55: cs = 55; goto _test_eof; 
	_test_eof56: cs = 56; goto _test_eof; 
	_test_eof57: cs = 57; goto _test_eof; 
	_test_eof58: cs = 58; goto _test_eof; 
	_test_eof59: cs = 59; goto _test_eof; 
	_test_eof60: cs = 60; goto _test_eof; 
	_test_eof61: cs = 61; goto _test_eof; 
	_test_eof62: cs = 62; goto _test_eof; 
	_test_eof63: cs = 63; goto _test_eof; 
	_test_eof64: cs = 64; goto _test_eof; 
	_test_eof65: cs = 65; goto _test_eof; 
	_test_eof66: cs = 66; goto _test_eof; 
	_test_eof67: cs = 67; goto _test_eof; 
	_test_eof68: cs = 68; goto _test_eof; 
	_test_eof69: cs = 69; goto _test_eof; 
	_test_eof70: cs = 70; goto _test_eof; 
	_test_eof71: cs = 71; goto _test_eof; 
	_test_eof72: cs = 72; goto _test_eof; 
	_test_eof73: cs = 73; goto _test_eof; 
	_test_eof74: cs = 74; goto _test_eof; 
	_test_eof75: cs = 75; goto _test_eof; 
	_test_eof76: cs = 76; goto _test_eof; 
	_test_eof77: cs = 77; goto _test_eof; 
	_test_eof78: cs = 78; goto _test_eof; 
	_test_eof79: cs = 79; goto _test_eof; 
	_test_eof80: cs = 80; goto _test_eof; 
	_test_eof81: cs = 81; goto _test_eof; 
	_test_eof82: cs = 82; goto _test_eof; 
	_test_eof83: cs = 83; goto _test_eof; 
	_test_eof84: cs = 84; goto _test_eof; 
	_test_eof85: cs = 85; goto _test_eof; 
	_test_eof86: cs = 86; goto _test_eof; 
	_test_eof87: cs = 87; goto _test_eof; 
	_test_eof88: cs = 88; goto _test_eof; 
	_test_eof89: cs = 89; goto _test_eof; 
	_test_eof90: cs = 90; goto _test_eof; 
	_test_eof91: cs = 91; goto _test_eof; 
	_test_eof92: cs = 92; goto _test_eof; 
	_test_eof93: cs = 93; goto _test_eof; 
	_test_eof94: cs = 94; goto _test_eof; 
	_test_eof95: cs = 95; goto _test_eof; 
	_test_eof96: cs = 96; goto _test_eof; 
	_test_eof97: cs = 97; goto _test_eof; 
	_test_eof98: cs = 98; goto _test_eof; 
	_test_eof99: cs = 99; goto _test_eof; 
	_test_eof100: cs = 100; goto _test_eof; 
	_test_eof101: cs = 101; goto _test_eof; 
	_test_eof102: cs = 102; goto _test_eof; 
	_test_eof103: cs = 103; goto _test_eof; 
	_test_eof104: cs = 104; goto _test_eof; 
	_test_eof105: cs = 105; goto _test_eof; 
	_test_eof106: cs = 106; goto _test_eof; 
	_test_eof107: cs = 107; goto _test_eof; 
	_test_eof108: cs = 108; goto _test_eof; 
	_test_eof109: cs = 109; goto _test_eof; 
	_test_eof110: cs = 110; goto _test_eof; 
	_test_eof111: cs = 111; goto _test_eof; 
	_test_eof112: cs = 112; goto _test_eof; 
	_test_eof113: cs = 113; goto _test_eof; 
	_test_eof114: cs = 114; goto _test_eof; 
	_test_eof115: cs = 115; goto _test_eof; 
	_test_eof116: cs = 116; goto _test_eof; 
	_test_eof117: cs = 117; goto _test_eof; 
	_test_eof118: cs = 118; goto _test_eof; 
	_test_eof119: cs = 119; goto _test_eof; 
	_test_eof120: cs = 120; goto _test_eof; 
	_test_eof121: cs = 121; goto _test_eof; 
	_test_eof122: cs = 122; goto _test_eof; 
	_test_eof123: cs = 123; goto _test_eof; 
	_test_eof124: cs = 124; goto _test_eof; 
	_test_eof125: cs = 125; goto _test_eof; 
	_test_eof126: cs = 126; goto _test_eof; 
	_test_eof127: cs = 127; goto _test_eof; 
	_test_eof128: cs = 128; goto _test_eof; 
	_test_eof129: cs = 129; goto _test_eof; 
	_test_eof130: cs = 130; goto _test_eof; 
	_test_eof131: cs = 131; goto _test_eof; 
	_test_eof132: cs = 132; goto _test_eof; 
	_test_eof133: cs = 133; goto _test_eof; 
	_test_eof134: cs = 134; goto _test_eof; 
	_test_eof135: cs = 135; goto _test_eof; 
	_test_eof136: cs = 136; goto _test_eof; 
	_test_eof137: cs = 137; goto _test_eof; 
	_test_eof138: cs = 138; goto _test_eof; 
	_test_eof139: cs = 139; goto _test_eof; 
	_test_eof140: cs = 140; goto _test_eof; 
	_test_eof141: cs = 141; goto _test_eof; 
	_test_eof142: cs = 142; goto _test_eof; 
	_test_eof143: cs = 143; goto _test_eof; 
	_test_eof144: cs = 144; goto _test_eof; 
	_test_eof145: cs = 145; goto _test_eof; 
	_test_eof146: cs = 146; goto _test_eof; 
	_test_eof147: cs = 147; goto _test_eof; 
	_test_eof148: cs = 148; goto _test_eof; 
	_test_eof149: cs = 149; goto _test_eof; 
	_test_eof150: cs = 150; goto _test_eof; 
	_test_eof151: cs = 151; goto _test_eof; 
	_test_eof152: cs = 152; goto _test_eof; 
	_test_eof153: cs = 153; goto _test_eof; 
	_test_eof154: cs = 154; goto _test_eof; 
	_test_eof155: cs = 155; goto _test_eof; 
	_test_eof156: cs = 156; goto _test_eof; 
	_test_eof157: cs = 157; goto _test_eof; 
	_test_eof158: cs = 158; goto _test_eof; 
	_test_eof159: cs = 159; goto _test_eof; 
	_test_eof160: cs = 160; goto _test_eof; 
	_test_eof161: cs = 161; goto _test_eof; 
	_test_eof162: cs = 162; goto _test_eof; 
	_test_eof163: cs = 163; goto _test_eof; 
	_test_eof164: cs = 164; goto _test_eof; 
	_test_eof165: cs = 165; goto _test_eof; 
	_test_eof166: cs = 166; goto _test_eof; 
	_test_eof167: cs = 167; goto _test_eof; 
	_test_eof168: cs = 168; goto _test_eof; 
	_test_eof169: cs = 169; goto _test_eof; 
	_test_eof170: cs = 170; goto _test_eof; 
	_test_eof171: cs = 171; goto _test_eof; 
	_test_eof172: cs = 172; goto _test_eof; 
	_test_eof173: cs = 173; goto _test_eof; 
	_test_eof174: cs = 174; goto _test_eof; 
	_test_eof175: cs = 175; goto _test_eof; 
	_test_eof176: cs = 176; goto _test_eof; 
	_test_eof177: cs = 177; goto _test_eof; 
	_test_eof178: cs = 178; goto _test_eof; 
	_test_eof179: cs = 179; goto _test_eof; 
	_test_eof180: cs = 180; goto _test_eof; 
	_test_eof181: cs = 181; goto _test_eof; 
	_test_eof182: cs = 182; goto _test_eof; 
	_test_eof183: cs = 183; goto _test_eof; 
	_test_eof184: cs = 184; goto _test_eof; 
	_test_eof185: cs = 185; goto _test_eof; 
	_test_eof186: cs = 186; goto _test_eof; 
	_test_eof187: cs = 187; goto _test_eof; 
	_test_eof188: cs = 188; goto _test_eof; 
	_test_eof189: cs = 189; goto _test_eof; 
	_test_eof190: cs = 190; goto _test_eof; 
	_test_eof191: cs = 191; goto _test_eof; 
	_test_eof192: cs = 192; goto _test_eof; 
	_test_eof193: cs = 193; goto _test_eof; 
	_test_eof194: cs = 194; goto _test_eof; 
	_test_eof195: cs = 195; goto _test_eof; 
	_test_eof196: cs = 196; goto _test_eof; 
	_test_eof197: cs = 197; goto _test_eof; 
	_test_eof198: cs = 198; goto _test_eof; 
	_test_eof199: cs = 199; goto _test_eof; 
	_test_eof200: cs = 200; goto _test_eof; 
	_test_eof201: cs = 201; goto _test_eof; 
	_test_eof202: cs = 202; goto _test_eof; 
	_test_eof203: cs = 203; goto _test_eof; 
	_test_eof204: cs = 204; goto _test_eof; 
	_test_eof205: cs = 205; goto _test_eof; 
	_test_eof206: cs = 206; goto _test_eof; 
	_test_eof207: cs = 207; goto _test_eof; 
	_test_eof208: cs = 208; goto _test_eof; 
	_test_eof209: cs = 209; goto _test_eof; 
	_test_eof210: cs = 210; goto _test_eof; 
	_test_eof211: cs = 211; goto _test_eof; 
	_test_eof212: cs = 212; goto _test_eof; 
	_test_eof213: cs = 213; goto _test_eof; 
	_test_eof214: cs = 214; goto _test_eof; 
	_test_eof215: cs = 215; goto _test_eof; 
	_test_eof216: cs = 216; goto _test_eof; 
	_test_eof217: cs = 217; goto _test_eof; 
	_test_eof218: cs = 218; goto _test_eof; 
	_test_eof219: cs = 219; goto _test_eof; 
	_test_eof220: cs = 220; goto _test_eof; 
	_test_eof221: cs = 221; goto _test_eof; 
	_test_eof222: cs = 222; goto _test_eof; 
	_test_eof223: cs = 223; goto _test_eof; 
	_test_eof224: cs = 224; goto _test_eof; 
	_test_eof225: cs = 225; goto _test_eof; 
	_test_eof226: cs = 226; goto _test_eof; 
	_test_eof227: cs = 227; goto _test_eof; 
	_test_eof228: cs = 228; goto _test_eof; 
	_test_eof229: cs = 229; goto _test_eof; 
	_test_eof230: cs = 230; goto _test_eof; 
	_test_eof231: cs = 231; goto _test_eof; 
	_test_eof232: cs = 232; goto _test_eof; 
	_test_eof233: cs = 233; goto _test_eof; 
	_test_eof234: cs = 234; goto _test_eof; 
	_test_eof235: cs = 235; goto _test_eof; 
	_test_eof236: cs = 236; goto _test_eof; 
	_test_eof237: cs = 237; goto _test_eof; 
	_test_eof238: cs = 238; goto _test_eof; 
	_test_eof239: cs = 239; goto _test_eof; 
	_test_eof240: cs = 240; goto _test_eof; 
	_test_eof241: cs = 241; goto _test_eof; 
	_test_eof242: cs = 242; goto _test_eof; 
	_test_eof243: cs = 243; goto _test_eof; 
	_test_eof244: cs = 244; goto _test_eof; 
	_test_eof245: cs = 245; goto _test_eof; 
	_test_eof246: cs = 246; goto _test_eof; 
	_test_eof247: cs = 247; goto _test_eof; 
	_test_eof248: cs = 248; goto _test_eof; 
	_test_eof249: cs = 249; goto _test_eof; 
	_test_eof250: cs = 250; goto _test_eof; 
	_test_eof251: cs = 251; goto _test_eof; 
	_test_eof252: cs = 252; goto _test_eof; 
	_test_eof253: cs = 253; goto _test_eof; 
	_test_eof254: cs = 254; goto _test_eof; 
	_test_eof255: cs = 255; goto _test_eof; 
	_test_eof256: cs = 256; goto _test_eof; 
	_test_eof257: cs = 257; goto _test_eof; 
	_test_eof258: cs = 258; goto _test_eof; 
	_test_eof259: cs = 259; goto _test_eof; 
	_test_eof260: cs = 260; goto _test_eof; 
	_test_eof261: cs = 261; goto _test_eof; 
	_test_eof262: cs = 262; goto _test_eof; 
	_test_eof263: cs = 263; goto _test_eof; 
	_test_eof264: cs = 264; goto _test_eof; 
	_test_eof265: cs = 265; goto _test_eof; 
	_test_eof266: cs = 266; goto _test_eof; 
	_test_eof267: cs = 267; goto _test_eof; 
	_test_eof268: cs = 268; goto _test_eof; 
	_test_eof269: cs = 269; goto _test_eof; 
	_test_eof270: cs = 270; goto _test_eof; 
	_test_eof271: cs = 271; goto _test_eof; 
	_test_eof272: cs = 272; goto _test_eof; 
	_test_eof273: cs = 273; goto _test_eof; 
	_test_eof274: cs = 274; goto _test_eof; 
	_test_eof275: cs = 275; goto _test_eof; 
	_test_eof276: cs = 276; goto _test_eof; 
	_test_eof277: cs = 277; goto _test_eof; 
	_test_eof278: cs = 278; goto _test_eof; 
	_test_eof279: cs = 279; goto _test_eof; 
	_test_eof280: cs = 280; goto _test_eof; 
	_test_eof281: cs = 281; goto _test_eof; 
	_test_eof282: cs = 282; goto _test_eof; 
	_test_eof283: cs = 283; goto _test_eof; 
	_test_eof284: cs = 284; goto _test_eof; 
	_test_eof285: cs = 285; goto _test_eof; 
	_test_eof286: cs = 286; goto _test_eof; 
	_test_eof287: cs = 287; goto _test_eof; 
	_test_eof288: cs = 288; goto _test_eof; 
	_test_eof289: cs = 289; goto _test_eof; 
	_test_eof290: cs = 290; goto _test_eof; 
	_test_eof291: cs = 291; goto _test_eof; 
	_test_eof292: cs = 292; goto _test_eof; 
	_test_eof293: cs = 293; goto _test_eof; 
	_test_eof294: cs = 294; goto _test_eof; 
	_test_eof295: cs = 295; goto _test_eof; 
	_test_eof296: cs = 296; goto _test_eof; 
	_test_eof297: cs = 297; goto _test_eof; 
	_test_eof298: cs = 298; goto _test_eof; 
	_test_eof299: cs = 299; goto _test_eof; 
	_test_eof300: cs = 300; goto _test_eof; 
	_test_eof301: cs = 301; goto _test_eof; 
	_test_eof302: cs = 302; goto _test_eof; 
	_test_eof303: cs = 303; goto _test_eof; 
	_test_eof304: cs = 304; goto _test_eof; 
	_test_eof305: cs = 305; goto _test_eof; 
	_test_eof306: cs = 306; goto _test_eof; 
	_test_eof307: cs = 307; goto _test_eof; 
	_test_eof308: cs = 308; goto _test_eof; 
	_test_eof309: cs = 309; goto _test_eof; 
	_test_eof310: cs = 310; goto _test_eof; 
	_test_eof311: cs = 311; goto _test_eof; 
	_test_eof312: cs = 312; goto _test_eof; 
	_test_eof313: cs = 313; goto _test_eof; 
	_test_eof314: cs = 314; goto _test_eof; 
	_test_eof315: cs = 315; goto _test_eof; 
	_test_eof316: cs = 316; goto _test_eof; 
	_test_eof317: cs = 317; goto _test_eof; 
	_test_eof318: cs = 318; goto _test_eof; 
	_test_eof319: cs = 319; goto _test_eof; 
	_test_eof320: cs = 320; goto _test_eof; 
	_test_eof321: cs = 321; goto _test_eof; 
	_test_eof322: cs = 322; goto _test_eof; 
	_test_eof323: cs = 323; goto _test_eof; 
	_test_eof324: cs = 324; goto _test_eof; 
	_test_eof325: cs = 325; goto _test_eof; 
	_test_eof326: cs = 326; goto _test_eof; 
	_test_eof327: cs = 327; goto _test_eof; 
	_test_eof328: cs = 328; goto _test_eof; 
	_test_eof329: cs = 329; goto _test_eof; 
	_test_eof330: cs = 330; goto _test_eof; 
	_test_eof331: cs = 331; goto _test_eof; 
	_test_eof332: cs = 332; goto _test_eof; 
	_test_eof333: cs = 333; goto _test_eof; 
	_test_eof334: cs = 334; goto _test_eof; 
	_test_eof335: cs = 335; goto _test_eof; 
	_test_eof336: cs = 336; goto _test_eof; 
	_test_eof337: cs = 337; goto _test_eof; 
	_test_eof338: cs = 338; goto _test_eof; 
	_test_eof339: cs = 339; goto _test_eof; 
	_test_eof340: cs = 340; goto _test_eof; 
	_test_eof341: cs = 341; goto _test_eof; 
	_test_eof342: cs = 342; goto _test_eof; 
	_test_eof343: cs = 343; goto _test_eof; 
	_test_eof344: cs = 344; goto _test_eof; 
	_test_eof345: cs = 345; goto _test_eof; 
	_test_eof346: cs = 346; goto _test_eof; 
	_test_eof347: cs = 347; goto _test_eof; 
	_test_eof348: cs = 348; goto _test_eof; 
	_test_eof349: cs = 349; goto _test_eof; 
	_test_eof350: cs = 350; goto _test_eof; 
	_test_eof351: cs = 351; goto _test_eof; 
	_test_eof352: cs = 352; goto _test_eof; 
	_test_eof353: cs = 353; goto _test_eof; 
	_test_eof354: cs = 354; goto _test_eof; 
	_test_eof355: cs = 355; goto _test_eof; 
	_test_eof356: cs = 356; goto _test_eof; 
	_test_eof357: cs = 357; goto _test_eof; 
	_test_eof358: cs = 358; goto _test_eof; 
	_test_eof359: cs = 359; goto _test_eof; 
	_test_eof360: cs = 360; goto _test_eof; 
	_test_eof361: cs = 361; goto _test_eof; 
	_test_eof362: cs = 362; goto _test_eof; 
	_test_eof363: cs = 363; goto _test_eof; 
	_test_eof364: cs = 364; goto _test_eof; 
	_test_eof365: cs = 365; goto _test_eof; 
	_test_eof366: cs = 366; goto _test_eof; 
	_test_eof367: cs = 367; goto _test_eof; 
	_test_eof368: cs = 368; goto _test_eof; 
	_test_eof369: cs = 369; goto _test_eof; 
	_test_eof370: cs = 370; goto _test_eof; 
	_test_eof371: cs = 371; goto _test_eof; 
	_test_eof372: cs = 372; goto _test_eof; 
	_test_eof373: cs = 373; goto _test_eof; 
	_test_eof374: cs = 374; goto _test_eof; 
	_test_eof375: cs = 375; goto _test_eof; 
	_test_eof376: cs = 376; goto _test_eof; 
	_test_eof377: cs = 377; goto _test_eof; 
	_test_eof378: cs = 378; goto _test_eof; 
	_test_eof379: cs = 379; goto _test_eof; 
	_test_eof380: cs = 380; goto _test_eof; 
	_test_eof381: cs = 381; goto _test_eof; 
	_test_eof382: cs = 382; goto _test_eof; 
	_test_eof383: cs = 383; goto _test_eof; 
	_test_eof384: cs = 384; goto _test_eof; 
	_test_eof385: cs = 385; goto _test_eof; 
	_test_eof386: cs = 386; goto _test_eof; 
	_test_eof387: cs = 387; goto _test_eof; 
	_test_eof388: cs = 388; goto _test_eof; 
	_test_eof389: cs = 389; goto _test_eof; 
	_test_eof390: cs = 390; goto _test_eof; 
	_test_eof391: cs = 391; goto _test_eof; 
	_test_eof392: cs = 392; goto _test_eof; 
	_test_eof393: cs = 393; goto _test_eof; 
	_test_eof394: cs = 394; goto _test_eof; 
	_test_eof395: cs = 395; goto _test_eof; 
	_test_eof396: cs = 396; goto _test_eof; 
	_test_eof397: cs = 397; goto _test_eof; 
	_test_eof398: cs = 398; goto _test_eof; 
	_test_eof399: cs = 399; goto _test_eof; 
	_test_eof400: cs = 400; goto _test_eof; 
	_test_eof401: cs = 401; goto _test_eof; 
	_test_eof402: cs = 402; goto _test_eof; 
	_test_eof403: cs = 403; goto _test_eof; 
	_test_eof404: cs = 404; goto _test_eof; 
	_test_eof405: cs = 405; goto _test_eof; 
	_test_eof406: cs = 406; goto _test_eof; 
	_test_eof407: cs = 407; goto _test_eof; 
	_test_eof408: cs = 408; goto _test_eof; 
	_test_eof409: cs = 409; goto _test_eof; 
	_test_eof410: cs = 410; goto _test_eof; 
	_test_eof411: cs = 411; goto _test_eof; 
	_test_eof412: cs = 412; goto _test_eof; 
	_test_eof413: cs = 413; goto _test_eof; 
	_test_eof414: cs = 414; goto _test_eof; 
	_test_eof415: cs = 415; goto _test_eof; 
	_test_eof416: cs = 416; goto _test_eof; 
	_test_eof417: cs = 417; goto _test_eof; 
	_test_eof418: cs = 418; goto _test_eof; 
	_test_eof419: cs = 419; goto _test_eof; 
	_test_eof420: cs = 420; goto _test_eof; 
	_test_eof421: cs = 421; goto _test_eof; 
	_test_eof422: cs = 422; goto _test_eof; 
	_test_eof423: cs = 423; goto _test_eof; 
	_test_eof424: cs = 424; goto _test_eof; 
	_test_eof425: cs = 425; goto _test_eof; 
	_test_eof426: cs = 426; goto _test_eof; 
	_test_eof427: cs = 427; goto _test_eof; 
	_test_eof428: cs = 428; goto _test_eof; 
	_test_eof429: cs = 429; goto _test_eof; 
	_test_eof430: cs = 430; goto _test_eof; 
	_test_eof431: cs = 431; goto _test_eof; 
	_test_eof432: cs = 432; goto _test_eof; 
	_test_eof433: cs = 433; goto _test_eof; 
	_test_eof434: cs = 434; goto _test_eof; 
	_test_eof435: cs = 435; goto _test_eof; 
	_test_eof436: cs = 436; goto _test_eof; 
	_test_eof437: cs = 437; goto _test_eof; 
	_test_eof438: cs = 438; goto _test_eof; 
	_test_eof439: cs = 439; goto _test_eof; 
	_test_eof440: cs = 440; goto _test_eof; 
	_test_eof441: cs = 441; goto _test_eof; 
	_test_eof442: cs = 442; goto _test_eof; 
	_test_eof443: cs = 443; goto _test_eof; 
	_test_eof444: cs = 444; goto _test_eof; 
	_test_eof445: cs = 445; goto _test_eof; 
	_test_eof446: cs = 446; goto _test_eof; 
	_test_eof447: cs = 447; goto _test_eof; 
	_test_eof448: cs = 448; goto _test_eof; 
	_test_eof449: cs = 449; goto _test_eof; 
	_test_eof450: cs = 450; goto _test_eof; 
	_test_eof451: cs = 451; goto _test_eof; 
	_test_eof452: cs = 452; goto _test_eof; 
	_test_eof453: cs = 453; goto _test_eof; 
	_test_eof454: cs = 454; goto _test_eof; 
	_test_eof455: cs = 455; goto _test_eof; 
	_test_eof456: cs = 456; goto _test_eof; 
	_test_eof457: cs = 457; goto _test_eof; 
	_test_eof458: cs = 458; goto _test_eof; 
	_test_eof459: cs = 459; goto _test_eof; 
	_test_eof460: cs = 460; goto _test_eof; 
	_test_eof461: cs = 461; goto _test_eof; 
	_test_eof462: cs = 462; goto _test_eof; 
	_test_eof463: cs = 463; goto _test_eof; 
	_test_eof464: cs = 464; goto _test_eof; 
	_test_eof465: cs = 465; goto _test_eof; 
	_test_eof466: cs = 466; goto _test_eof; 
	_test_eof467: cs = 467; goto _test_eof; 
	_test_eof468: cs = 468; goto _test_eof; 
	_test_eof469: cs = 469; goto _test_eof; 
	_test_eof470: cs = 470; goto _test_eof; 
	_test_eof471: cs = 471; goto _test_eof; 
	_test_eof472: cs = 472; goto _test_eof; 
	_test_eof473: cs = 473; goto _test_eof; 
	_test_eof474: cs = 474; goto _test_eof; 
	_test_eof475: cs = 475; goto _test_eof; 
	_test_eof476: cs = 476; goto _test_eof; 
	_test_eof477: cs = 477; goto _test_eof; 
	_test_eof478: cs = 478; goto _test_eof; 
	_test_eof479: cs = 479; goto _test_eof; 
	_test_eof480: cs = 480; goto _test_eof; 
	_test_eof481: cs = 481; goto _test_eof; 
	_test_eof482: cs = 482; goto _test_eof; 
	_test_eof483: cs = 483; goto _test_eof; 
	_test_eof484: cs = 484; goto _test_eof; 
	_test_eof485: cs = 485; goto _test_eof; 
	_test_eof486: cs = 486; goto _test_eof; 
	_test_eof487: cs = 487; goto _test_eof; 
	_test_eof488: cs = 488; goto _test_eof; 
	_test_eof489: cs = 489; goto _test_eof; 
	_test_eof490: cs = 490; goto _test_eof; 
	_test_eof491: cs = 491; goto _test_eof; 
	_test_eof492: cs = 492; goto _test_eof; 
	_test_eof493: cs = 493; goto _test_eof; 
	_test_eof494: cs = 494; goto _test_eof; 
	_test_eof495: cs = 495; goto _test_eof; 
	_test_eof496: cs = 496; goto _test_eof; 
	_test_eof497: cs = 497; goto _test_eof; 
	_test_eof498: cs = 498; goto _test_eof; 
	_test_eof499: cs = 499; goto _test_eof; 
	_test_eof500: cs = 500; goto _test_eof; 
	_test_eof501: cs = 501; goto _test_eof; 
	_test_eof502: cs = 502; goto _test_eof; 
	_test_eof503: cs = 503; goto _test_eof; 
	_test_eof504: cs = 504; goto _test_eof; 
	_test_eof505: cs = 505; goto _test_eof; 
	_test_eof506: cs = 506; goto _test_eof; 
	_test_eof507: cs = 507; goto _test_eof; 
	_test_eof508: cs = 508; goto _test_eof; 
	_test_eof509: cs = 509; goto _test_eof; 
	_test_eof510: cs = 510; goto _test_eof; 
	_test_eof511: cs = 511; goto _test_eof; 
	_test_eof512: cs = 512; goto _test_eof; 
	_test_eof513: cs = 513; goto _test_eof; 
	_test_eof514: cs = 514; goto _test_eof; 
	_test_eof515: cs = 515; goto _test_eof; 
	_test_eof516: cs = 516; goto _test_eof; 
	_test_eof517: cs = 517; goto _test_eof; 
	_test_eof518: cs = 518; goto _test_eof; 
	_test_eof519: cs = 519; goto _test_eof; 
	_test_eof520: cs = 520; goto _test_eof; 
	_test_eof521: cs = 521; goto _test_eof; 
	_test_eof522: cs = 522; goto _test_eof; 
	_test_eof523: cs = 523; goto _test_eof; 
	_test_eof524: cs = 524; goto _test_eof; 
	_test_eof525: cs = 525; goto _test_eof; 
	_test_eof526: cs = 526; goto _test_eof; 
	_test_eof527: cs = 527; goto _test_eof; 
	_test_eof528: cs = 528; goto _test_eof; 
	_test_eof529: cs = 529; goto _test_eof; 
	_test_eof530: cs = 530; goto _test_eof; 
	_test_eof531: cs = 531; goto _test_eof; 
	_test_eof532: cs = 532; goto _test_eof; 
	_test_eof533: cs = 533; goto _test_eof; 
	_test_eof534: cs = 534; goto _test_eof; 
	_test_eof535: cs = 535; goto _test_eof; 
	_test_eof536: cs = 536; goto _test_eof; 
	_test_eof537: cs = 537; goto _test_eof; 
	_test_eof538: cs = 538; goto _test_eof; 
	_test_eof539: cs = 539; goto _test_eof; 
	_test_eof540: cs = 540; goto _test_eof; 
	_test_eof541: cs = 541; goto _test_eof; 
	_test_eof542: cs = 542; goto _test_eof; 
	_test_eof543: cs = 543; goto _test_eof; 
	_test_eof544: cs = 544; goto _test_eof; 
	_test_eof545: cs = 545; goto _test_eof; 
	_test_eof546: cs = 546; goto _test_eof; 
	_test_eof547: cs = 547; goto _test_eof; 
	_test_eof548: cs = 548; goto _test_eof; 
	_test_eof549: cs = 549; goto _test_eof; 
	_test_eof550: cs = 550; goto _test_eof; 
	_test_eof551: cs = 551; goto _test_eof; 
	_test_eof552: cs = 552; goto _test_eof; 
	_test_eof553: cs = 553; goto _test_eof; 
	_test_eof554: cs = 554; goto _test_eof; 
	_test_eof555: cs = 555; goto _test_eof; 
	_test_eof556: cs = 556; goto _test_eof; 
	_test_eof557: cs = 557; goto _test_eof; 
	_test_eof558: cs = 558; goto _test_eof; 
	_test_eof559: cs = 559; goto _test_eof; 
	_test_eof560: cs = 560; goto _test_eof; 
	_test_eof561: cs = 561; goto _test_eof; 
	_test_eof562: cs = 562; goto _test_eof; 
	_test_eof563: cs = 563; goto _test_eof; 
	_test_eof564: cs = 564; goto _test_eof; 
	_test_eof565: cs = 565; goto _test_eof; 
	_test_eof566: cs = 566; goto _test_eof; 
	_test_eof567: cs = 567; goto _test_eof; 
	_test_eof568: cs = 568; goto _test_eof; 
	_test_eof569: cs = 569; goto _test_eof; 
	_test_eof570: cs = 570; goto _test_eof; 
	_test_eof571: cs = 571; goto _test_eof; 
	_test_eof572: cs = 572; goto _test_eof; 
	_test_eof573: cs = 573; goto _test_eof; 
	_test_eof574: cs = 574; goto _test_eof; 
	_test_eof575: cs = 575; goto _test_eof; 
	_test_eof576: cs = 576; goto _test_eof; 
	_test_eof577: cs = 577; goto _test_eof; 
	_test_eof578: cs = 578; goto _test_eof; 
	_test_eof579: cs = 579; goto _test_eof; 
	_test_eof580: cs = 580; goto _test_eof; 
	_test_eof581: cs = 581; goto _test_eof; 
	_test_eof582: cs = 582; goto _test_eof; 
	_test_eof583: cs = 583; goto _test_eof; 
	_test_eof584: cs = 584; goto _test_eof; 
	_test_eof585: cs = 585; goto _test_eof; 
	_test_eof586: cs = 586; goto _test_eof; 
	_test_eof587: cs = 587; goto _test_eof; 
	_test_eof588: cs = 588; goto _test_eof; 
	_test_eof589: cs = 589; goto _test_eof; 
	_test_eof590: cs = 590; goto _test_eof; 
	_test_eof591: cs = 591; goto _test_eof; 
	_test_eof592: cs = 592; goto _test_eof; 
	_test_eof593: cs = 593; goto _test_eof; 
	_test_eof594: cs = 594; goto _test_eof; 
	_test_eof595: cs = 595; goto _test_eof; 
	_test_eof596: cs = 596; goto _test_eof; 
	_test_eof597: cs = 597; goto _test_eof; 
	_test_eof598: cs = 598; goto _test_eof; 
	_test_eof599: cs = 599; goto _test_eof; 
	_test_eof600: cs = 600; goto _test_eof; 
	_test_eof601: cs = 601; goto _test_eof; 
	_test_eof602: cs = 602; goto _test_eof; 
	_test_eof603: cs = 603; goto _test_eof; 
	_test_eof604: cs = 604; goto _test_eof; 
	_test_eof605: cs = 605; goto _test_eof; 
	_test_eof606: cs = 606; goto _test_eof; 
	_test_eof607: cs = 607; goto _test_eof; 
	_test_eof608: cs = 608; goto _test_eof; 
	_test_eof609: cs = 609; goto _test_eof; 
	_test_eof610: cs = 610; goto _test_eof; 
	_test_eof611: cs = 611; goto _test_eof; 
	_test_eof612: cs = 612; goto _test_eof; 
	_test_eof613: cs = 613; goto _test_eof; 
	_test_eof614: cs = 614; goto _test_eof; 
	_test_eof615: cs = 615; goto _test_eof; 
	_test_eof616: cs = 616; goto _test_eof; 
	_test_eof617: cs = 617; goto _test_eof; 
	_test_eof618: cs = 618; goto _test_eof; 
	_test_eof619: cs = 619; goto _test_eof; 
	_test_eof620: cs = 620; goto _test_eof; 
	_test_eof621: cs = 621; goto _test_eof; 
	_test_eof622: cs = 622; goto _test_eof; 
	_test_eof623: cs = 623; goto _test_eof; 
	_test_eof624: cs = 624; goto _test_eof; 
	_test_eof625: cs = 625; goto _test_eof; 
	_test_eof626: cs = 626; goto _test_eof; 
	_test_eof627: cs = 627; goto _test_eof; 
	_test_eof628: cs = 628; goto _test_eof; 
	_test_eof629: cs = 629; goto _test_eof; 
	_test_eof630: cs = 630; goto _test_eof; 
	_test_eof631: cs = 631; goto _test_eof; 
	_test_eof632: cs = 632; goto _test_eof; 
	_test_eof633: cs = 633; goto _test_eof; 
	_test_eof634: cs = 634; goto _test_eof; 
	_test_eof635: cs = 635; goto _test_eof; 
	_test_eof636: cs = 636; goto _test_eof; 
	_test_eof637: cs = 637; goto _test_eof; 
	_test_eof638: cs = 638; goto _test_eof; 
	_test_eof639: cs = 639; goto _test_eof; 
	_test_eof640: cs = 640; goto _test_eof; 
	_test_eof641: cs = 641; goto _test_eof; 
	_test_eof642: cs = 642; goto _test_eof; 
	_test_eof643: cs = 643; goto _test_eof; 
	_test_eof644: cs = 644; goto _test_eof; 
	_test_eof645: cs = 645; goto _test_eof; 
	_test_eof646: cs = 646; goto _test_eof; 
	_test_eof647: cs = 647; goto _test_eof; 
	_test_eof648: cs = 648; goto _test_eof; 
	_test_eof649: cs = 649; goto _test_eof; 
	_test_eof650: cs = 650; goto _test_eof; 
	_test_eof651: cs = 651; goto _test_eof; 
	_test_eof652: cs = 652; goto _test_eof; 
	_test_eof653: cs = 653; goto _test_eof; 
	_test_eof654: cs = 654; goto _test_eof; 
	_test_eof655: cs = 655; goto _test_eof; 
	_test_eof656: cs = 656; goto _test_eof; 
	_test_eof657: cs = 657; goto _test_eof; 
	_test_eof658: cs = 658; goto _test_eof; 
	_test_eof659: cs = 659; goto _test_eof; 
	_test_eof660: cs = 660; goto _test_eof; 
	_test_eof661: cs = 661; goto _test_eof; 
	_test_eof662: cs = 662; goto _test_eof; 
	_test_eof663: cs = 663; goto _test_eof; 
	_test_eof664: cs = 664; goto _test_eof; 
	_test_eof665: cs = 665; goto _test_eof; 
	_test_eof666: cs = 666; goto _test_eof; 
	_test_eof667: cs = 667; goto _test_eof; 
	_test_eof668: cs = 668; goto _test_eof; 
	_test_eof669: cs = 669; goto _test_eof; 
	_test_eof670: cs = 670; goto _test_eof; 
	_test_eof671: cs = 671; goto _test_eof; 
	_test_eof672: cs = 672; goto _test_eof; 
	_test_eof673: cs = 673; goto _test_eof; 
	_test_eof674: cs = 674; goto _test_eof; 
	_test_eof675: cs = 675; goto _test_eof; 
	_test_eof676: cs = 676; goto _test_eof; 
	_test_eof677: cs = 677; goto _test_eof; 
	_test_eof678: cs = 678; goto _test_eof; 
	_test_eof679: cs = 679; goto _test_eof; 
	_test_eof680: cs = 680; goto _test_eof; 
	_test_eof681: cs = 681; goto _test_eof; 
	_test_eof682: cs = 682; goto _test_eof; 
	_test_eof683: cs = 683; goto _test_eof; 
	_test_eof684: cs = 684; goto _test_eof; 
	_test_eof685: cs = 685; goto _test_eof; 
	_test_eof686: cs = 686; goto _test_eof; 
	_test_eof687: cs = 687; goto _test_eof; 
	_test_eof688: cs = 688; goto _test_eof; 
	_test_eof689: cs = 689; goto _test_eof; 
	_test_eof690: cs = 690; goto _test_eof; 
	_test_eof691: cs = 691; goto _test_eof; 
	_test_eof692: cs = 692; goto _test_eof; 
	_test_eof693: cs = 693; goto _test_eof; 
	_test_eof694: cs = 694; goto _test_eof; 
	_test_eof695: cs = 695; goto _test_eof; 
	_test_eof696: cs = 696; goto _test_eof; 
	_test_eof697: cs = 697; goto _test_eof; 
	_test_eof698: cs = 698; goto _test_eof; 
	_test_eof699: cs = 699; goto _test_eof; 
	_test_eof700: cs = 700; goto _test_eof; 
	_test_eof701: cs = 701; goto _test_eof; 
	_test_eof702: cs = 702; goto _test_eof; 
	_test_eof703: cs = 703; goto _test_eof; 
	_test_eof704: cs = 704; goto _test_eof; 
	_test_eof705: cs = 705; goto _test_eof; 
	_test_eof706: cs = 706; goto _test_eof; 
	_test_eof707: cs = 707; goto _test_eof; 
	_test_eof708: cs = 708; goto _test_eof; 
	_test_eof709: cs = 709; goto _test_eof; 
	_test_eof710: cs = 710; goto _test_eof; 
	_test_eof711: cs = 711; goto _test_eof; 
	_test_eof712: cs = 712; goto _test_eof; 
	_test_eof713: cs = 713; goto _test_eof; 
	_test_eof714: cs = 714; goto _test_eof; 
	_test_eof715: cs = 715; goto _test_eof; 
	_test_eof716: cs = 716; goto _test_eof; 
	_test_eof717: cs = 717; goto _test_eof; 
	_test_eof718: cs = 718; goto _test_eof; 
	_test_eof719: cs = 719; goto _test_eof; 
	_test_eof720: cs = 720; goto _test_eof; 
	_test_eof721: cs = 721; goto _test_eof; 
	_test_eof722: cs = 722; goto _test_eof; 
	_test_eof723: cs = 723; goto _test_eof; 
	_test_eof724: cs = 724; goto _test_eof; 
	_test_eof725: cs = 725; goto _test_eof; 
	_test_eof726: cs = 726; goto _test_eof; 
	_test_eof727: cs = 727; goto _test_eof; 
	_test_eof728: cs = 728; goto _test_eof; 
	_test_eof729: cs = 729; goto _test_eof; 
	_test_eof730: cs = 730; goto _test_eof; 
	_test_eof731: cs = 731; goto _test_eof; 
	_test_eof732: cs = 732; goto _test_eof; 
	_test_eof733: cs = 733; goto _test_eof; 
	_test_eof734: cs = 734; goto _test_eof; 
	_test_eof735: cs = 735; goto _test_eof; 
	_test_eof736: cs = 736; goto _test_eof; 
	_test_eof737: cs = 737; goto _test_eof; 
	_test_eof738: cs = 738; goto _test_eof; 
	_test_eof739: cs = 739; goto _test_eof; 
	_test_eof740: cs = 740; goto _test_eof; 
	_test_eof741: cs = 741; goto _test_eof; 
	_test_eof742: cs = 742; goto _test_eof; 
	_test_eof743: cs = 743; goto _test_eof; 
	_test_eof744: cs = 744; goto _test_eof; 
	_test_eof745: cs = 745; goto _test_eof; 
	_test_eof746: cs = 746; goto _test_eof; 
	_test_eof747: cs = 747; goto _test_eof; 
	_test_eof748: cs = 748; goto _test_eof; 
	_test_eof749: cs = 749; goto _test_eof; 
	_test_eof750: cs = 750; goto _test_eof; 
	_test_eof751: cs = 751; goto _test_eof; 
	_test_eof752: cs = 752; goto _test_eof; 
	_test_eof753: cs = 753; goto _test_eof; 
	_test_eof754: cs = 754; goto _test_eof; 
	_test_eof755: cs = 755; goto _test_eof; 
	_test_eof756: cs = 756; goto _test_eof; 
	_test_eof757: cs = 757; goto _test_eof; 
	_test_eof758: cs = 758; goto _test_eof; 
	_test_eof759: cs = 759; goto _test_eof; 
	_test_eof760: cs = 760; goto _test_eof; 
	_test_eof761: cs = 761; goto _test_eof; 
	_test_eof762: cs = 762; goto _test_eof; 
	_test_eof763: cs = 763; goto _test_eof; 
	_test_eof764: cs = 764; goto _test_eof; 
	_test_eof765: cs = 765; goto _test_eof; 
	_test_eof766: cs = 766; goto _test_eof; 
	_test_eof767: cs = 767; goto _test_eof; 
	_test_eof768: cs = 768; goto _test_eof; 
	_test_eof769: cs = 769; goto _test_eof; 
	_test_eof770: cs = 770; goto _test_eof; 
	_test_eof771: cs = 771; goto _test_eof; 
	_test_eof772: cs = 772; goto _test_eof; 
	_test_eof773: cs = 773; goto _test_eof; 
	_test_eof774: cs = 774; goto _test_eof; 
	_test_eof775: cs = 775; goto _test_eof; 
	_test_eof776: cs = 776; goto _test_eof; 
	_test_eof777: cs = 777; goto _test_eof; 
	_test_eof778: cs = 778; goto _test_eof; 
	_test_eof779: cs = 779; goto _test_eof; 
	_test_eof780: cs = 780; goto _test_eof; 
	_test_eof781: cs = 781; goto _test_eof; 
	_test_eof782: cs = 782; goto _test_eof; 
	_test_eof783: cs = 783; goto _test_eof; 
	_test_eof784: cs = 784; goto _test_eof; 
	_test_eof785: cs = 785; goto _test_eof; 
	_test_eof786: cs = 786; goto _test_eof; 
	_test_eof787: cs = 787; goto _test_eof; 
	_test_eof788: cs = 788; goto _test_eof; 
	_test_eof789: cs = 789; goto _test_eof; 
	_test_eof790: cs = 790; goto _test_eof; 
	_test_eof791: cs = 791; goto _test_eof; 
	_test_eof792: cs = 792; goto _test_eof; 
	_test_eof793: cs = 793; goto _test_eof; 
	_test_eof794: cs = 794; goto _test_eof; 
	_test_eof795: cs = 795; goto _test_eof; 
	_test_eof796: cs = 796; goto _test_eof; 
	_test_eof797: cs = 797; goto _test_eof; 
	_test_eof798: cs = 798; goto _test_eof; 
	_test_eof799: cs = 799; goto _test_eof; 
	_test_eof800: cs = 800; goto _test_eof; 
	_test_eof801: cs = 801; goto _test_eof; 
	_test_eof802: cs = 802; goto _test_eof; 
	_test_eof803: cs = 803; goto _test_eof; 
	_test_eof804: cs = 804; goto _test_eof; 
	_test_eof805: cs = 805; goto _test_eof; 
	_test_eof806: cs = 806; goto _test_eof; 
	_test_eof807: cs = 807; goto _test_eof; 
	_test_eof808: cs = 808; goto _test_eof; 
	_test_eof809: cs = 809; goto _test_eof; 
	_test_eof811: cs = 811; goto _test_eof; 

	_test_eof: {}
	if ( p == eof )
	{
	switch ( cs ) {
	case 76: 
	case 77: 
	case 78: 
#line 234 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad entry\n", parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 804: 
#line 245 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad ttl directive\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 87: 
	case 88: 
	case 91: 
	case 92: 
	case 807: 
	case 808: 
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 800: 
#line 239 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad origin directive\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 234 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad entry\n", parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 420: 
	case 421: 
	case 422: 
	case 423: 
	case 424: 
	case 425: 
	case 426: 
	case 427: 
	case 428: 
	case 429: 
	case 430: 
	case 431: 
	case 432: 
	case 433: 
	case 434: 
	case 435: 
	case 436: 
	case 437: 
	case 438: 
	case 439: 
	case 440: 
	case 441: 
	case 442: 
	case 443: 
	case 444: 
	case 445: 
	case 446: 
	case 447: 
	case 448: 
	case 449: 
	case 450: 
	case 451: 
	case 452: 
	case 453: 
	case 454: 
	case 455: 
	case 456: 
	case 457: 
	case 458: 
	case 459: 
	case 460: 
	case 461: 
	case 462: 
	case 463: 
	case 464: 
	case 465: 
	case 466: 
	case 467: 
	case 468: 
	case 469: 
	case 470: 
	case 471: 
	case 472: 
	case 473: 
	case 474: 
	case 475: 
	case 476: 
	case 477: 
	case 478: 
	case 479: 
	case 480: 
	case 481: 
	case 482: 
	case 483: 
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 239 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad origin directive\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 1: 
	case 2: 
	case 3: 
	case 4: 
	case 5: 
	case 6: 
	case 7: 
	case 8: 
	case 9: 
	case 10: 
	case 11: 
	case 12: 
	case 13: 
	case 14: 
	case 15: 
	case 16: 
	case 17: 
	case 18: 
	case 19: 
	case 20: 
	case 21: 
	case 22: 
	case 23: 
	case 24: 
	case 25: 
	case 26: 
	case 27: 
	case 28: 
	case 29: 
	case 30: 
	case 31: 
	case 32: 
	case 33: 
	case 34: 
	case 35: 
	case 36: 
	case 37: 
	case 38: 
	case 39: 
	case 40: 
	case 41: 
	case 42: 
	case 43: 
	case 44: 
	case 45: 
	case 46: 
	case 47: 
	case 48: 
	case 49: 
	case 50: 
	case 51: 
	case 52: 
	case 53: 
	case 54: 
	case 55: 
	case 56: 
	case 57: 
	case 58: 
	case 59: 
	case 60: 
	case 61: 
	case 62: 
	case 63: 
	case 97: 
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 65: 
	case 90: 
	case 94: 
	case 96: 
#line 269 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: ttl time format error\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 64: 
	case 66: 
	case 67: 
	case 89: 
	case 93: 
	case 95: 
#line 281 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr typedata\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 611: 
	case 612: 
	case 613: 
	case 614: 
	case 615: 
	case 616: 
	case 617: 
	case 618: 
	case 619: 
	case 620: 
	case 621: 
	case 622: 
	case 623: 
	case 624: 
	case 625: 
	case 626: 
	case 627: 
	case 628: 
	case 629: 
	case 630: 
	case 631: 
	case 632: 
	case 633: 
	case 634: 
	case 635: 
	case 636: 
	case 637: 
	case 638: 
	case 639: 
	case 640: 
	case 641: 
	case 642: 
	case 643: 
	case 644: 
	case 645: 
	case 646: 
	case 647: 
	case 648: 
	case 649: 
	case 650: 
	case 651: 
	case 652: 
	case 653: 
	case 654: 
	case 655: 
	case 656: 
	case 657: 
	case 658: 
	case 659: 
	case 660: 
	case 661: 
	case 662: 
	case 663: 
	case 664: 
	case 665: 
	case 666: 
	case 667: 
	case 668: 
	case 669: 
	case 670: 
	case 671: 
	case 672: 
	case 673: 
	case 674: 
	case 675: 
	case 676: 
	case 677: 
	case 678: 
	case 679: 
	case 680: 
	case 681: 
	case 682: 
	case 683: 
	case 684: 
	case 685: 
	case 686: 
	case 687: 
	case 688: 
	case 689: 
	case 690: 
	case 691: 
	case 692: 
	case 693: 
	case 694: 
	case 695: 
	case 696: 
	case 697: 
	case 698: 
	case 699: 
	case 700: 
	case 701: 
	case 702: 
	case 703: 
	case 704: 
	case 705: 
	case 706: 
	case 707: 
	case 708: 
	case 709: 
	case 710: 
	case 711: 
	case 712: 
	case 713: 
	case 714: 
	case 715: 
	case 716: 
	case 717: 
	case 718: 
	case 719: 
	case 720: 
	case 721: 
	case 722: 
	case 723: 
	case 724: 
	case 725: 
	case 726: 
	case 727: 
	case 728: 
	case 729: 
	case 730: 
	case 731: 
	case 732: 
	case 733: 
	case 734: 
	case 735: 
	case 736: 
	case 737: 
	case 738: 
	case 739: 
	case 740: 
	case 741: 
	case 742: 
	case 743: 
	case 744: 
	case 745: 
	case 746: 
	case 747: 
	case 748: 
	case 749: 
	case 750: 
	case 751: 
	case 752: 
	case 753: 
	case 754: 
	case 755: 
	case 756: 
	case 757: 
	case 758: 
	case 759: 
	case 760: 
	case 761: 
	case 762: 
	case 763: 
	case 764: 
	case 765: 
	case 766: 
	case 767: 
	case 768: 
	case 769: 
	case 770: 
	case 771: 
	case 772: 
	case 773: 
	case 774: 
	case 775: 
	case 776: 
	case 777: 
	case 778: 
	case 779: 
	case 780: 
	case 781: 
	case 782: 
	case 783: 
	case 784: 
	case 785: 
	case 786: 
	case 787: 
	case 788: 
	case 789: 
	case 790: 
	case 791: 
	case 792: 
	case 793: 
	case 794: 
	case 795: 
	case 796: 
	case 797: 
	case 798: 
	case 799: 
#line 251 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad octet in label\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 239 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad origin directive\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 224: 
	case 225: 
	case 226: 
	case 227: 
	case 228: 
	case 229: 
	case 230: 
	case 231: 
	case 232: 
	case 233: 
	case 234: 
	case 235: 
	case 236: 
	case 237: 
	case 238: 
	case 239: 
	case 240: 
	case 241: 
	case 242: 
	case 243: 
	case 244: 
	case 245: 
	case 246: 
	case 247: 
	case 248: 
	case 249: 
	case 250: 
	case 251: 
	case 252: 
	case 253: 
	case 254: 
	case 255: 
	case 256: 
	case 257: 
	case 258: 
	case 259: 
	case 260: 
	case 261: 
	case 262: 
	case 263: 
	case 264: 
	case 265: 
	case 266: 
	case 267: 
	case 268: 
	case 269: 
	case 270: 
	case 271: 
	case 272: 
	case 273: 
	case 274: 
	case 275: 
	case 276: 
	case 277: 
	case 278: 
	case 279: 
	case 280: 
	case 281: 
	case 282: 
	case 283: 
	case 284: 
	case 285: 
	case 286: 
	case 287: 
	case 288: 
	case 289: 
	case 290: 
	case 291: 
	case 292: 
	case 293: 
	case 294: 
	case 295: 
	case 296: 
	case 297: 
	case 298: 
	case 299: 
	case 300: 
	case 301: 
	case 302: 
	case 303: 
	case 304: 
	case 305: 
	case 306: 
	case 307: 
	case 308: 
	case 309: 
	case 310: 
	case 311: 
	case 312: 
	case 313: 
	case 314: 
	case 315: 
	case 316: 
	case 317: 
	case 318: 
	case 319: 
	case 320: 
	case 321: 
	case 322: 
	case 323: 
	case 324: 
	case 325: 
	case 326: 
	case 327: 
	case 328: 
	case 329: 
	case 330: 
	case 331: 
	case 332: 
	case 333: 
	case 334: 
	case 335: 
	case 336: 
	case 337: 
	case 338: 
	case 339: 
	case 340: 
	case 341: 
	case 342: 
	case 343: 
	case 344: 
	case 345: 
	case 346: 
	case 347: 
	case 348: 
	case 349: 
	case 350: 
	case 351: 
	case 352: 
	case 353: 
	case 354: 
	case 355: 
	case 356: 
	case 357: 
	case 358: 
	case 359: 
	case 360: 
	case 361: 
	case 362: 
	case 363: 
	case 364: 
	case 365: 
	case 366: 
	case 367: 
	case 368: 
	case 369: 
	case 370: 
	case 371: 
	case 372: 
	case 373: 
	case 374: 
	case 375: 
	case 376: 
	case 377: 
	case 378: 
	case 379: 
	case 380: 
	case 381: 
	case 382: 
	case 383: 
	case 384: 
	case 385: 
	case 386: 
	case 387: 
	case 388: 
	case 389: 
	case 390: 
	case 391: 
	case 392: 
	case 393: 
	case 394: 
	case 395: 
	case 396: 
	case 397: 
	case 398: 
	case 399: 
	case 400: 
	case 401: 
	case 402: 
	case 403: 
	case 404: 
	case 405: 
	case 406: 
	case 407: 
	case 408: 
	case 409: 
	case 410: 
	case 411: 
	case 412: 
#line 251 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad octet in label\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 486: 
	case 488: 
	case 490: 
	case 492: 
	case 494: 
	case 496: 
	case 498: 
	case 500: 
	case 502: 
	case 504: 
	case 506: 
	case 508: 
	case 510: 
	case 512: 
	case 514: 
	case 516: 
	case 518: 
	case 520: 
	case 522: 
	case 524: 
	case 526: 
	case 528: 
	case 530: 
	case 532: 
	case 534: 
	case 536: 
	case 538: 
	case 540: 
	case 542: 
	case 544: 
	case 546: 
	case 548: 
	case 550: 
	case 552: 
	case 554: 
	case 556: 
	case 558: 
	case 560: 
	case 562: 
	case 564: 
	case 566: 
	case 568: 
	case 570: 
	case 572: 
	case 574: 
	case 576: 
	case 578: 
	case 580: 
	case 582: 
	case 584: 
	case 586: 
	case 588: 
	case 590: 
	case 592: 
	case 594: 
	case 596: 
	case 598: 
	case 600: 
	case 602: 
	case 604: 
	case 606: 
	case 608: 
	case 610: 
#line 257 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad escape in label\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 239 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad origin directive\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 99: 
	case 101: 
	case 103: 
	case 105: 
	case 107: 
	case 109: 
	case 111: 
	case 113: 
	case 115: 
	case 117: 
	case 119: 
	case 121: 
	case 123: 
	case 125: 
	case 127: 
	case 129: 
	case 131: 
	case 133: 
	case 135: 
	case 137: 
	case 139: 
	case 141: 
	case 143: 
	case 145: 
	case 147: 
	case 149: 
	case 151: 
	case 153: 
	case 155: 
	case 157: 
	case 159: 
	case 161: 
	case 163: 
	case 165: 
	case 167: 
	case 169: 
	case 171: 
	case 173: 
	case 175: 
	case 177: 
	case 179: 
	case 181: 
	case 183: 
	case 185: 
	case 187: 
	case 189: 
	case 191: 
	case 193: 
	case 195: 
	case 197: 
	case 199: 
	case 201: 
	case 203: 
	case 205: 
	case 207: 
	case 209: 
	case 211: 
	case 213: 
	case 215: 
	case 217: 
	case 219: 
	case 221: 
	case 223: 
#line 257 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad escape in label\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 484: 
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 239 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad origin directive\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 234 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad entry\n", parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 805: 
	case 806: 
#line 269 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: ttl time format error\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 245 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad ttl directive\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 234 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad entry\n", parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 68: 
	case 69: 
	case 70: 
	case 71: 
	case 72: 
	case 73: 
	case 74: 
	case 81: 
	case 82: 
	case 83: 
	case 84: 
	case 85: 
	case 86: 
#line 287 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad IPv4 address format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 281 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr typedata\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 485: 
	case 487: 
	case 489: 
	case 491: 
	case 493: 
	case 495: 
	case 497: 
	case 499: 
	case 501: 
	case 503: 
	case 505: 
	case 507: 
	case 509: 
	case 511: 
	case 513: 
	case 515: 
	case 517: 
	case 519: 
	case 521: 
	case 523: 
	case 525: 
	case 527: 
	case 529: 
	case 531: 
	case 533: 
	case 535: 
	case 537: 
	case 539: 
	case 541: 
	case 543: 
	case 545: 
	case 547: 
	case 549: 
	case 551: 
	case 553: 
	case 555: 
	case 557: 
	case 559: 
	case 561: 
	case 563: 
	case 565: 
	case 567: 
	case 569: 
	case 571: 
	case 573: 
	case 575: 
	case 577: 
	case 579: 
	case 581: 
	case 583: 
	case 585: 
	case 587: 
	case 589: 
	case 591: 
	case 593: 
	case 595: 
	case 597: 
	case 599: 
	case 601: 
	case 603: 
	case 605: 
	case 607: 
	case 609: 
#line 257 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad escape in label\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 251 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad octet in label\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 239 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad origin directive\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 98: 
	case 100: 
	case 102: 
	case 104: 
	case 106: 
	case 108: 
	case 110: 
	case 112: 
	case 114: 
	case 116: 
	case 118: 
	case 120: 
	case 122: 
	case 124: 
	case 126: 
	case 128: 
	case 130: 
	case 132: 
	case 134: 
	case 136: 
	case 138: 
	case 140: 
	case 142: 
	case 144: 
	case 146: 
	case 148: 
	case 150: 
	case 152: 
	case 154: 
	case 156: 
	case 158: 
	case 160: 
	case 162: 
	case 164: 
	case 166: 
	case 168: 
	case 170: 
	case 172: 
	case 174: 
	case 176: 
	case 178: 
	case 180: 
	case 182: 
	case 184: 
	case 186: 
	case 188: 
	case 190: 
	case 192: 
	case 194: 
	case 196: 
	case 198: 
	case 200: 
	case 202: 
	case 204: 
	case 206: 
	case 208: 
	case 210: 
	case 212: 
	case 214: 
	case 216: 
	case 218: 
	case 220: 
	case 222: 
#line 257 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad escape in label\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 251 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad octet in label\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 263 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: label overflow\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
	case 75: 
	case 79: 
	case 80: 
#line 287 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad IPv4 address format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 281 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr typedata\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 275 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad rr format\n",
            parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
#line 234 "zparser.rl"
	{
        fprintf(stderr, "[zparser] error: line %d: bad entry\n", parser->line);
        parser->totalerrors++;
        p--; {goto st809;}
    }
	break;
#line 22687 "rzonec.c"
	}
	}

	_out: {}
	}

#line 124 "rzonec.rl"
    }
    close(fd);
    fflush(stdout);
    return parser->totalerrors;
}


/**
 * Process resource record.
 *
 */
int
zparser_process_rr(void)
{
    /* supported CLASS */
    if (parser->current_rr.klass != DNS_CLASS_IN) {
        fprintf(stderr, "[%s] only class IN is supported\n", logstr);
        return 0;
    }

    /* all fine */
    parser->numrrs++;
    return 1;
}


/**
 * Print usage.
 *
 */
static void
usage(void)
{
    fprintf(stderr, "usage: rzonec [-h] [-o origin] [-f database] [-z zonefile]\n\n");
    fprintf(stderr, "zone compiler, creates database from zone files.\n");
    fprintf(stderr, "-h\tPrint this help information.\n");
    fprintf(stderr, "-o\tSpecify a zone's origin (only used with -z).\n");
    fprintf(stderr, "-f\tSpecify database file to use.\n");
    fprintf(stderr, "-z\tSpecify a zonefile to read (read from stdin with \'-\').\n");
    return;
}


extern char *optarg;
extern int optind;

int
rzonec(int argc, char **argv)
{
    char* origin = NULL;
    char* dbfile = NULL;
    char* zonefile = NULL;
    int ret = 0;
    int c;
/*
    namedb_type* db = NULL;
*/

    /* Parse the command line... */
    while ((c = getopt(argc, argv, "f:ho:z:")) != -1) {
        switch (c) {
            case 'f':
                dbfile = optarg;
                break;
            case 'o':
                origin = optarg;
                break;
            case 'z':
                zonefile = optarg;
                break;
            case 'h':
                usage();
                exit(0);
            case '?':
            default:
                usage();
                exit(1);
        }
    }
    argc -= optind;
    argv += optind;
    if (argc != 0) {
        usage();
        exit(1);
    }
    if (!zonefile || !dbfile || !origin) {
        fprintf(stderr, "[%s] missing arguments: %s%s%s\n", logstr,
            zonefile?"":"zonefile ", dbfile?"":"dbfile ", origin?"":"origin");
        exit(1);
    }
    /* Create the database */
/*
    if ((db = namedb_create(dbfile)) == NULL) {
        fprintf(stderr, "[%s] error creating the database (%s)\n", logstr,
            dbfile);
        exit(1);
    }
*/
    /* Create the parser */
    zparser_create();
    if (!parser) {
        fprintf(stderr, "[%s] error creating the parser\n", logstr);
        exit(1);
    }

    /*
     * Read zone file with the specified origin
     */
    fprintf(stdout, "[%s] reading zone %s file %s db %s.\n", logstr, origin,
        zonefile, dbfile);
    ret = zparser_read_zone(zonefile);

    fprintf(stdout, "[%s] read %d lines in zone %s.\n", logstr, parser->line,
        origin);
    fprintf(stdout, "[%s] encountered %d comments in zone %s.\n", logstr,
        parser->comments, origin);
    fprintf(stdout, "[%s] processed %d RRs in zone %s.\n", logstr,
        parser->numrrs, origin);

    /* Close the database */
/*
    if (namedb_save(db) != 0) {
        fprintf(stderr, "[%s] error writing the database (%s)\n", logstr,
            db->filename);
        namedb_cleanup(db);
        exit(1);
    }
*/

    region_log(parser->region, "global region");
    region_log(parser->rr_region, "rr region");

    /* Cleanup the parser */
    zparser_cleanup();

    /* Print the total number of errors */
    if (ret > 0) {
        fprintf(stderr, "[%s] done with %d errors.\n", logstr, ret);
    } else {
        fprintf(stdout, "[%s] done with no errors.\n", logstr);
    }
    return ret;
}

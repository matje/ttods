# $Id: Makefile.am 6620 2012-09-05 07:56:36Z matthijs $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

LIBCOMPAT = ${top_builddir}/common/libcompat.a

AM_CPPFLAGS = \
		-I$(top_srcdir)/common \
		-I$(top_builddir)/common \
		-I$(srcdir)/../lib \
		@LDNS_INCLUDES@ @XML2_INCLUDES@

AM_CFLAGS =	-std=c99

bin_PROGRAMS = ttods-hsmutil ttods-hsmspeed

man1_MANS = ttods-hsmutil.1 ttods-hsmspeed.1

ttods_hsmutil_SOURCES = hsmutil.c hsmtest.c hsmtest.h
ttods_hsmutil_LDADD = ../lib/libhsm.a @LDNS_LIBS@ @XML2_LIBS@ $(LIBCOMPAT)

ttods_hsmspeed_SOURCES = hsmspeed.c
ttods_hsmspeed_LDADD = ../lib/libhsm.a -lpthread @LDNS_LIBS@ @XML2_LIBS@ $(LIBCOMPAT)

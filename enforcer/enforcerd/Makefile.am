# $Id: Makefile.am 1829 2009-09-18 22:11:48Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

LIBHSM = ${top_builddir}/libhsm/src/lib/libhsm.a
LIBKSM = ../ksm/libksm.a
LIBENFORCER = ../common/libenforcer.a
LIBCOMPAT = ${top_builddir}/common/libcompat.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/common \
	-I$(top_builddir)/common \
	-I$(top_srcdir)/libhsm/src/lib \
	-I$(srcdir)/../common \
	-I$(builddir)/../common \
	-I$(srcdir)/../ksm/include \
	-I$(builddir)/../ksm/include \
	@XML2_INCLUDES@ \
	@DB_INCLUDES@ \
	@LDNS_INCLUDES@

sbin_PROGRAMS = ttods-enforcerd
man8_MANS = ttods-enforcerd.8

ttods_enforcerd_SOURCES = enforcer.c enforcer.h
ttods_enforcerd_LDADD = $(LIBENFORCER) $(LIBKSM) $(LIBHSM) $(LIBCOMPAT)
ttods_enforcerd_LDADD += @XML2_LIBS@ @DB_LIBS@ @LDNS_LIBS@

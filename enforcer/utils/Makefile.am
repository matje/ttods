# $Id: Makefile.am 1441 2009-07-30 12:32:04Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

LIBHSM = ${top_builddir}/libhsm/src/lib/libhsm.a
LIBKSM = ../ksm/libksm.a
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

opendnssecdatadir = $(datadir)/opendnssec

if USE_MYSQL
dist_opendnssecdata_DATA = database_create.mysql
else
dist_opendnssecdata_DATA = database_create.sqlite3
endif

bin_PROGRAMS =	ttods-ksmutil ttods-kaspcheck
man1_MANS =	ttods-ksmutil.1 ttods-kaspcheck.1

ttods_ksmutil_SOURCES = ksmutil.c
ttods_ksmutil_LDADD = $(LIBKSM) $(LIBHSM) $(LIBCOMPAT)
ttods_ksmutil_LDADD += @XML2_LIBS@ @DB_LIBS@ @LDNS_LIBS@

ttods_kaspcheck_SOURCES = kaspcheck.c kaspcheck.h \
						kc_helper.c kc_helper.h

ttods_kaspcheck_LDADD = $(LIBHSM) $(LIBCOMPAT)
ttods_kaspcheck_LDADD += @XML2_LIBS@

EXTRA_DIST = $(srcdir)/migrate_*.pl
EXTRA_DIST += $(srcdir)/migrate_adapters_1.*
EXTRA_DIST += $(srcdir)/convert_database.pl
EXTRA_DIST += $(srcdir)/migrate_zone_delete.mysql

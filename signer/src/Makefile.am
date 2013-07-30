# $Id: Makefile.am 6368 2012-06-04 10:11:42Z matthijs $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

LIBHSM = ${top_builddir}/libhsm/src/lib/libhsm.a
LIBCOMPAT = ${top_builddir}/common/libcompat.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/common \
	-I$(top_builddir)/common \
	-I$(top_srcdir)/libhsm/src/lib \
	@SSL_INCLUDES@ \
	@XML2_INCLUDES@ \
	@LDNS_INCLUDES@

signerdir =     @libdir@/opendnssec/signer

sbin_PROGRAMS = ttods-signerd ttods-signer
# man8_MANS =     man/ttods-signer.8 man/ttods-signerd.8

ttods_signerd_SOURCES=		ods-signerd.c \
				adapter/adapter.c adapter\adapter.h \
				adapter/adfile.c adapter\adfile.h \
				daemon/cfg.c daemon/cfg.h \
				daemon/cmdhandler.c daemon/cmdhandler.h \
				daemon/engine.c daemon/engine.h \
				daemon/signal.c daemon/signal.h \
				daemon/worker.c daemon/worker.h \
				dns/dname.c dns/dname.h \
				dns/dns.c dns/dns.h \
				dns/rdata.c dns/rdata.h \
				dns/rr.c dns/rr.h \
				dns/wf.c dns/wf.h \
				parser/confparser.c parser/confparser.h \
				parser/signconfparser.c parser/signconfparser.h \
				parser/zlistparser.c parser/zlistparser.h \
				rzonec/rzonec.c rzonec/rzonec.h \
				rzonec/zonec.c rzonec/zonec.h \
				schedule/fifoq.c schedule/fifoq.h \
				schedule/schedule.c schedule/schedule.h \
				schedule/task.c schedule/task.h \
				signer/namedb.c signer/namedb.h \
				signer/signconf.c signer/signconf.h \
				signer/tools.c signer/tools.h \
				signer/zlist.c signer/zlist.h \
				signer/zone.c signer/zone.h \
				util/duration.c util/duration.h \
				util/file.c util/file.h \
				util/hsms.c util/hsms.h \
				util/locks.c util/locks.h \
				util/log.c util/log.h \
				util/privdrop.c util/privdrop.h \
				util/region.c util/region.h \
				util/status.c util/status.h \
				util/str.c util/str.h \
				util/tree.c util/tree.h \
				util/util.c util/util.h \
				wire/buffer.c wire/buffer.h

ttods_signerd_LDADD=		$(LIBHSM)
ttods_signerd_LDADD+=		$(LIBCOMPAT)
ttods_signerd_LDADD+=		@LDNS_LIBS@ @XML2_LIBS@ @PTHREAD_LIBS@ @RT_LIBS@ @SSL_LIBS@ @C_LIBS@

ttods_signer_SOURCES=		ods-signer.c \
				util/duration.c util/duration.h \
				util/file.c util/file.h \
				util/log.c util/log.h \
				util/region.c util/region.h \
				util/str.c util/str.h \
				util/util.c util/util.h

ttods_signer_LDADD=		$(LIBHSM)
ttods_signer_LDADD+=		@LDNS_LIBS@ @XML2_LIBS@

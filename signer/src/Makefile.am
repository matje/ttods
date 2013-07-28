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

signerdir =     @libdir@/opendnssec/signerv3

sbin_PROGRAMS = ods-signerd ods-signer
# man8_MANS =     man/ods-signer.8 man/ods-signerd.8

ods_signerd_SOURCES=		ods-signerd.c \
				daemon/cfg.c daemon/cfg.h \
				daemon/cmdhandler.c daemon/cmdhandler.h \
				daemon/engine.c daemon/engine.h \
				daemon/signal.c daemon/signal.h \
				daemon/worker.c daemon/worker.h \
				parser/confparser.c parser/confparser.h \
				parser/signconfparser.c parser/signconfparser.h \
				parser/zlistparser.c parser/zlistparser.h \
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
				util/util.c util/util.h \
				wire/buffer.c wire/buffer.h

ods_signerd_LDADD=		$(LIBHSM)
ods_signerd_LDADD+=		$(LIBCOMPAT)
ods_signerd_LDADD+=		@LDNS_LIBS@ @XML2_LIBS@ @PTHREAD_LIBS@ @RT_LIBS@ @SSL_LIBS@ @C_LIBS@

ods_signer_SOURCES=		ods-signer.c \
				util/duration.c util/duration.h \
				util/file.c util/file.h \
				util/log.c util/log.h \
				util/region.c util/region.h \
				util/str.c util/str.h \
				util/util.c util/util.h

ods_signer_LDADD=		$(LIBHSM)
ods_signer_LDADD+=		@LDNS_LIBS@ @XML2_LIBS@

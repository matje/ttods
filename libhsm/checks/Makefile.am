# $Id: Makefile.am 6603 2012-09-04 10:16:09Z matthijs $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = token.db othertoken.db

LIBCOMPAT = ${top_builddir}/common/libcompat.a

AM_CPPFLAGS = \
		-I$(top_builddir)/common \
		-I$(srcdir)/../src/lib \
		@LDNS_INCLUDES@

AM_CFLAGS =	-std=c99

EXTRA_DIST =	*.xml $(srcdir)/softhsm.conf

noinst_PROGRAMS = hsmcheck
 
hsmcheck_LDADD = ../src/lib/libhsm.a @LDNS_LIBS@ @XML2_LIBS@ $(LIBCOMPAT)
hsmcheck_LDFLAGS = -no-install

SOFTHSM_ENV = SOFTHSM_CONF=$(srcdir)/softhsm.conf


token.db othertoken.db:
	env $(SOFTHSM_ENV) \
	softhsm --slot 0 --init-token --label softHSM \
		--so-pin 12345678 --pin 123456
	env $(SOFTHSM_ENV) \
	softhsm --slot 1 --init-token --label xyzzy \
		--so-pin 12345678 --pin 123456

check: regress-softhsm

regress:
	@echo use target 'regress-{aepkeyper,sca6000,softhsm,etoken,opensc,ncipher,multi}'

regress-aepkeyper: hsmcheck
	./hsmcheck -c conf-aepkeyper.xml -gsdr

regress-sca6000: hsmcheck
	./hsmcheck -c conf-sca6000.xml -gsdr

regress-softhsm: hsmcheck token.db
	env $(SOFTHSM_ENV) \
	./hsmcheck -c conf-softhsm.xml -gsdr

regress-etoken: hsmcheck
	./hsmcheck -c conf-etoken.xml -gsdr

regress-opensc: hsmcheck
	./hsmcheck -c conf-opensc.xml -gsdr

regress-ncipher: hsmcheck
	./hsmcheck -c conf-ncipher.xml -gsdr

regress-multi: hsmcheck token.db othertoken.db
	env $(SOFTHSM_ENV) \
	./hsmcheck -c conf-multi.xml -gsdr


# $Id: Makefile.am 4098 2010-10-13 14:40:53Z matthijs $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = src man

doxygen:
	rm -fr $(top_builddir)/signer/doxygen-doc
	env $(DX_ENV) \
		PROJECT_NAME="OpenDNSSEC-signer" \
		SRCDIR=$(top_srcdir)/signer \
		OUTPUTDIR=$(top_builddir)/signer/doxygen-doc \
		$(DX_DOXYGEN) $(top_builddir)/$(DX_CONFIG)

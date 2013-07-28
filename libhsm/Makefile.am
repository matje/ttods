# $Id: Makefile.am 3682 2010-08-09 11:55:02Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = src checks

doxygen:
	rm -fr $(top_builddir)/libhsm/doxygen-doc
	env $(DX_ENV) \
		PROJECT_NAME="OpenDNSSEC-libhsm" \
		SRCDIR=$(top_srcdir)/libhsm \
		OUTPUTDIR=$(top_builddir)/libhsm/doxygen-doc \
		$(DX_DOXYGEN) $(top_builddir)/$(DX_CONFIG)

# $Id: acx_pedantic.m4 1122 2009-06-24 10:37:50Z jakob $

AC_DEFUN([ACX_GPROF],[
	AC_ARG_ENABLE(
		[gprof],
		[AS_HELP_STRING([--enable-gprof],[enable profiling compile mode @<:@enabled@:>@])],
		,
		[enable_gprof="yes"]
	)
	if test "${enable_gprof}" = "yes"; then
		CFLAGS="${CFLAGS} -pg"
	fi
])

# $Id: acx_c99.m4 1122 2009-06-24 10:37:50Z jakob $

AC_DEFUN([ACX_C99],[
	AC_ARG_ENABLE(
		[c99],
		[AS_HELP_STRING([--enable-c99],[enable c99 compile mode @<:@enabled@:>@])],
		,
		[enable_c99="yes"]
	)
	if test "${enable_c99}" = "yes"; then
		enable_strict="yes";
		CFLAGS="${CFLAGS} -std=c99"
	fi
])

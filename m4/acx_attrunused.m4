AC_DEFUN([ACX_ATTRUNUSED], [
	AC_REQUIRE([AC_PROG_CC])
	AC_MSG_CHECKING(whether the C compiler (${CC-cc}) accepts the "unused" attribute)
	AC_CACHE_VAL(ac_cv_c_unused_attribute,
	[ac_cv_c_unused_attribute=no
		AC_TRY_COMPILE(
		[#include <stdio.h>
		void f (char *u __attribute__((unused)));
		], [
		   f ("x");
		],
		[ac_cv_c_unused_attribute="yes"],
		[ac_cv_c_unused_attribute="no"])
	])

	AC_MSG_RESULT($ac_cv_c_unused_attribute)
	if test $ac_cv_c_unused_attribute = yes; then
		AC_DEFINE(HAVE_ATTR_UNUSED, 1, [Whether the C compiler accepts the "unused" attribute])
	fi
])dnl


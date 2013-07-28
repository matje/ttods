# $Id: acx_mysql.m4 5071 2011-05-06 13:40:00Z rb $

AC_DEFUN([ACX_MYSQL],[
	AC_ARG_WITH(mysql,
        	AC_HELP_STRING([--with-mysql=DIR],[Specify prefix of path of MySQL]),
		[
			MYSQL_PATH="$withval"
			AC_PATH_PROGS(MYSQL_CONFIG, mysql_config, mysql_config, $MYSQL_PATH/bin)
			AC_PATH_PROGS(MYSQL, mysql, mysql, $MYSQL_PATH/bin)
		],[
			MYSQL_PATH="/usr/local"
			AC_PATH_PROGS(MYSQL_CONFIG, mysql_config, mysql_config, $PATH)
			AC_PATH_PROGS(MYSQL, mysql, mysql)
		])


	if test -x "$MYSQL_CONFIG"; then
		AC_MSG_CHECKING(mysql version)
		MYSQL_VERSION="`$MYSQL_CONFIG --version`"
		MYSQL_VERSION_MAJOR=`echo "$MYSQL_VERSION" | sed -e 's/\..*//'`
		AC_MSG_RESULT($MYSQL_VERSION)
		if test ${MYSQL_VERSION_MAJOR} -le 4 ; then
			AC_MSG_ERROR([mysql must be newer than 5.0.0])
		fi
	
		AC_MSG_CHECKING(what are the MySQL includes)
		MYSQL_INCLUDES="`$MYSQL_CONFIG --include` -DBIG_JOINS=1 -DUSE_MYSQL -Wno-long-long"
		AC_MSG_RESULT($MYSQL_INCLUDES)

		AC_MSG_CHECKING(what are the MySQL libs)
		MYSQL_LIBS="`$MYSQL_CONFIG --libs_r`"
		AC_MSG_RESULT($MYSQL_LIBS)
  	fi

	if ! test -x "$MYSQL"; then
		AC_MSG_ERROR([mysql command not found])
	fi

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $MYSQL_INCLUDES"
	LIBS="$LIBS $MYSQL_LIBS"

	AC_CHECK_HEADERS(mysql.h,,[AC_MSG_ERROR([Can't find MySQL headers])])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(MYSQL_INCLUDES)
	AC_SUBST(MYSQL_LIBS)
])

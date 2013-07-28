#!/bin/sh
#
# $Id: autogen.sh 6304 2012-05-04 08:30:36Z jerry $

VERSION=version.m4

if [ `dirname $0` = ".." ]; then
	if [ -f ../${VERSION} ]; then
		echo Creating ${VERSION} &&
		rm -f ${VERSION} &&
		ln ../${VERSION} ${VERSION} 2>/dev/null ||
		ln -s ../${VERSION} ${VERSION} 2>/dev/null ||
		cp ../${VERSION} ${VERSION}
	fi
fi &&

echo "Running autoreconf" &&
autoreconf --install --force

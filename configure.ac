#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

#  radreplay - radius test program which replays tcpdumps
#  Copyright (C) 2011 Ben Brown, Plusnet plc
#  
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ([2.67])
AC_INIT([radreplay], [0.1], [bbrown@plus.net])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([radreplay.h])
AC_CONFIG_HEADERS([config.h])

CPPFLAGS="$CPPFLAGS -Wall"

# Checks for programs.
AC_PROG_CC_STDC
AX_CHECK_COMPILE_FLAG([-pedantic], [CPPFLAGS="$CPPFLAGS -pedantic"])

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/socket.h stdint.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_INT32_T
AC_SYS_LARGEFILE

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset select socket strchr strdup strtoull inet_ntoa inet_aton htons htonl inet_ntop])

AC_ARG_WITH([dictionary],
  AC_HELP_STRING([--with-dictionary=FILE],[Set the default path for the radius dictionary file to FILE. Defaults to ${prefix}/share/radreplay/dictionary]),
  [DEFDICTIONARY=$withval],[DEFDICTIONARY=/share/radreplay/dictionary])

if test "$prefix" == "NONE"
then
  DEFDICTIONARY=/usr/local$DEFDICTIONARY
else
  DEFDICTIONARY=$prefix$DEFDICTIONARY
fi

AC_DEFINE_UNQUOTED([DEFDICTIONARY], "$DEFDICTIONARY", [The Default radius dictionary file])

AC_ARG_WITH([conf-file],
  AC_HELP_STRING([--with-conf-file=FILE],[Set the default config file to FILE. Defaults to ${prefix}/etc/radreplay.conf]),
  [DEFCONFFILE=$withval],[DEFCONFFILE=/etc/radreplay.conf])

if test "$prefix" == "NONE"
then
  DEFCONFFILE=/usr/local$DEFCONFFILE
else
  DEFCONFFILE=$prefix$DEFCONFFILE
fi

AC_DEFINE_UNQUOTED([DEFCONFFILE], "$DEFCONFFILE", [The Default config file])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

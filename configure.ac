#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([radreplay], [0.1], [bbrown@plus.net])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([radreplay.h])
AC_CONFIG_HEADERS([config.h])

CPPFLAGS="$CPPFLAGS -Wall -pedantic"

# Checks for programs.
AC_PROG_CC_STDC

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/socket.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

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

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

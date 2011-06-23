#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([rad-pcap-test], [0.1], [bbrown@plus.net])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([rad-pcap-test.h])
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

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([inet_ntoa])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

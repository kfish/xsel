# Process this file with autoconf to produce a configure script.
AC_INIT([xsel],[1.2.1])
AM_INIT_AUTOMAKE([1.14 foreign dist-xz subdir-objects])
AC_CONFIG_SRCDIR([xsel.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
PKG_CHECK_MODULES([X], [x11])

# Error out on compile warnings
dnl Add some useful warnings if we have gcc.
dnl changequote(,)dnl
AS_IF([test "x$ac_cv_c_compiler_gnu" = xyes], [
  CFLAGS="$CFLAGS -fno-strict-aliasing -Wall -Wdeclaration-after-statement -Wno-unused"
])
dnl changequote([,])dnl

# Checks for header files.
AC_CHECK_HEADERS([errno.h fcntl.h stdlib.h string.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_TYPE_UID_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([dup2 select strdup strerror strtol])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

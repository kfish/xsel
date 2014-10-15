# Process this file with autoconf to produce a configure script.
AC_INIT([xsel.c])
AM_INIT_AUTOMAKE(xsel, 1.2.0)
AC_CONFIG_SRCDIR([xsel.c])
AM_CONFIG_HEADER(config.h)

# Checks for programs.
AC_ISC_POSIX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
AC_PATH_XTRA
AC_SUBST(X_CFLAGS)
AC_SUBST(X_LDFLAGS)
AC_SUBST(X_LIBS)
AC_SUBST(X_EXTRA_LIBS)

AC_SEARCH_LIBS([XOpenDisplay], [X11], [], [AC_MSG_ERROR([libX11 is required])])

# Error out on compile warnings
dnl Add some useful warnings if we have gcc.
dnl changequote(,)dnl
if test "x$ac_cv_prog_gcc" = xyes ; then
  CFLAGS="$CFLAGS -fno-strict-aliasing -Wall -Werror -g -std=gnu99 -Wdeclaration-after-statement -Wno-unused"
fi
dnl changequote([,])dnl

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([errno.h fcntl.h stdlib.h string.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_HEADER_TIME
AC_TYPE_UID_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([dup2 select strdup strerror strtol])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

## Process this file with automake to produce Makefile.in

EXTRA_DIST = xsel.1x

CFLAGS = @X_CFLAGS@
LDADD = @X_LIBS@ @X_PRE_LIBS@ -lXext -lX11 @X_EXTRA_LIBS@

bin_PROGRAMS = xsel

xsel_SOURCES = xsel.c xsel.h

man_MANS = xsel.1x

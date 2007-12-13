/*
 * xsel -- manipulate the X selection
 * Copyright (C) 2001 Conrad Parker <conrad@vergenet.net>
 *
 * Permission to use, copy, modify, distribute, and sell this software and
 * its documentation for any purpose is hereby granted without fee, provided
 * that the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation.  No representations are made about the suitability of this
 * software for any purpose.  It is provided "as is" without express or
 * implied warranty.
 */

#define AUTHOR "Conrad Parker <conrad@vergenet.net>"

/* Default debug level (ship at 0) */
#define DEBUG_LEVEL 0

#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))

#define empty_string(s) (s==NULL||s[0]=='\0')
#define free_string(s) { free(s); s=NULL; }

/* Maximum line length for error messages */
#define MAXLINE 4096

/* Maximum filename length */
#define MAXFNAME 1024

/* Maximum incremental selection size. (Ripped from Xt) */
#define MAX_SELECTION_INCR(dpy) (((65536 < XMaxRequestSize(dpy)) ? \
        (65536 << 2)  : (XMaxRequestSize(dpy) << 2))-100)

/*
 * Debug levels (for print_debug()):
 *
 *   0  -  Fatal errors (default/unmaskable)
 *   1  -  Non-fatal warning (essential debugging info)
 *   2  -  Informative (generally useful debugging info)
 *   3  -  Obscure (more detailed debugging info)
 *   4  -  Trace (sequential trace of progress)
 */

#define D_FATAL 0
#define D_WARN  1
#define D_INFO  2
#define D_OBSC  3
#define D_TRACE 4

/* An instance of a MULTIPLE SelectionRequest being served */
typedef struct _MultTrack MultTrack;

struct _MultTrack {
  MultTrack * mparent;
  Display * display;
  Window requestor;
  Atom property;
  Atom selection;
  Time time;
  Atom * atoms;
  unsigned long length;
  unsigned long index;
  unsigned char * sel;
};

/* Selection serving states */
typedef enum {
  S_NULL=0,
  S_INCR_1,
  S_INCR_2
} IncrState;

/* An instance of a selection being served */
typedef struct _IncrTrack IncrTrack;

struct _IncrTrack {
  MultTrack * mparent;
  IncrTrack * prev, * next;
  IncrState state;
  Display * display;
  Window requestor;
  Atom property;
  Atom selection;
  Time time;
  Atom target;
  int format;
  unsigned char * data;
  int nelements; /* total */
  int offset, chunk, max_elements; /* all in terms of nelements */
};

/* Status of request handling */
typedef int HandleResult;
#define HANDLE_OK         0
#define HANDLE_ERR        (1<<0)
#define HANDLE_INCOMPLETE (1<<1)
#define DID_DELETE        (1<<2)

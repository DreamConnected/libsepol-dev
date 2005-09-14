#include <stdarg.h>
#include <stdio.h>

#include <sepol/sepol.h>
#include <sepol/debug.h>
#include "debug.h"

#ifdef __GNUC__
__attribute__ ((format (printf, 2, 3))) 
#endif
static void default_printf(
	const char* fname, 
	const char *fmt, ...) {

	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "libsepol.%s: ", fname);
	vfprintf (stderr, fmt, ap);
	va_end(ap);
}

#ifdef __GNUC__
__attribute__ ((format (printf, 2, 3)))
#endif
static void suppress_printf(
	const char* unused1, 
	const char* unused2, ...) { 
		unused1 = NULL;
		unused2 = NULL;
}

void (*DEBUG) (const char* fname, const char* fmt, ...) = default_printf;

void sepol_debug_compat(int on) {
	DEBUG = (on)? default_printf : suppress_printf;
}

void sepol_enable_debug(
	void (*fn)(const char* fname, const char *fmt, ...)) {

	DEBUG = (fn)? fn: default_printf;	

	/* Compatibility  - old debug system */
	sepol_debug(1);
}

void sepol_disable_debug() {
	DEBUG = suppress_printf;

	/* Compatibility - old debug system */
	sepol_debug(0);
}

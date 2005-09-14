#ifndef _SEPOL_INTERNAL_DEBUG_H_
#define _SEPOL_INTERNAL_DEBUG_H_

#define STATUS_SUCCESS 0
#define STATUS_ERR -1
#define STATUS_NODATA 1

extern void sepol_debug_compat(int on);

#ifdef __GNUC__
__attribute__ ((format (printf, 2, 3)))
#endif
extern void (*DEBUG) (
	const char* fname,
	const char* fmt, ...);

#endif /* _SEPOL_INTERNAL_DEBUG_H_ */

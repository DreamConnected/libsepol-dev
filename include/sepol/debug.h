#ifndef _SEPOL_DEBUG_H_
#define _SEPOL_DEBUG_H_

extern void sepol_enable_debug(
	void (*fn)(const char* fname, const char *fmt, ...));

extern void sepol_disable_debug();

#endif /* _SEPOL_DEBUG_H_ */

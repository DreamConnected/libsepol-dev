#ifndef _SEPOL_CONTEXT_RECORD_H_
#define _SEPOL_CONTEXT_RECORD_H_ 

struct sepol_context;
typedef struct sepol_context* sepol_context_t;

/* We don't need a key, because the context is never stored
 * in a data collection by itself */

/* User */
extern const char* sepol_context_get_user(sepol_context_t con);
extern int sepol_context_set_user(sepol_context_t con, const char* user);

/* Role */
extern const char* sepol_context_get_role(sepol_context_t con);
extern int sepol_context_set_role(sepol_context_t con, const char* role);

/* Type */
extern const char* sepol_context_get_type(sepol_context_t con);
extern int sepol_context_set_type(sepol_context_t con, const char* type);

/* MLS */
extern const char* sepol_context_get_mls(sepol_context_t con);
extern int sepol_context_set_mls(sepol_context_t con, const char* mls_range);

/* Create/Clone/Destroy */
extern int sepol_context_create(sepol_context_t* con_ptr);
extern int sepol_context_clone(sepol_context_t con, sepol_context_t* con_ptr);
extern void sepol_context_free(sepol_context_t con);

/* Parse to/from string */
extern int sepol_context_from_string(const char* str, sepol_context_t* con);
extern char* sepol_context_to_string(sepol_context_t con);

#endif 

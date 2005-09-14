#ifndef _SEPOL_USER_RECORD_H_
#define _SEPOL_USER_RECORD_H_

struct sepol_user;
struct sepol_user_key;
typedef struct sepol_user* sepol_user_t;
typedef struct sepol_user_key* sepol_user_key_t;

/* Key */
extern int sepol_user_key_create(
	const char* name,
	sepol_user_key_t* key);

extern int sepol_user_key_extract(
	sepol_user_t user,
	sepol_user_key_t* key_ptr);

extern void sepol_user_key_free(
	sepol_user_key_t key);

extern int sepol_user_compare(
	sepol_user_t user,
	sepol_user_key_t key);
	
/* Name */
extern const char* sepol_user_get_name(sepol_user_t user);
extern int sepol_user_set_name(sepol_user_t user, const char* name);

/* MLS */
extern const char* sepol_user_get_mlslevel(
	sepol_user_t user);

extern int sepol_user_set_mlslevel(
	sepol_user_t user, 
	const char* mls_level);

extern const char* sepol_user_get_mlsrange(
	sepol_user_t user);

extern int sepol_user_set_mlsrange(
	sepol_user_t user, 
	const char* mls_range);

/* Role management */
extern int sepol_user_get_num_roles(sepol_user_t user);
extern const char* sepol_user_get_defrole(sepol_user_t user);
extern int sepol_user_add_role(sepol_user_t user, const char* role);
extern int sepol_user_del_role(sepol_user_t user, const char* role);
extern int sepol_user_has_role(sepol_user_t user, const char* role);
extern int sepol_user_set_defrole(sepol_user_t user, const char* role);
extern int sepol_user_get_roles(
	sepol_user_t user,
	const char*** roles_arr, 
	size_t* num_roles);
extern int sepol_user_set_roles(
	sepol_user_t user,
	const char** roles_arr,
	size_t num_roles);

/* Create/Clone/Destroy */
extern int sepol_user_create(sepol_user_t* user_ptr);
extern int sepol_user_clone(sepol_user_t user, sepol_user_t* user_ptr);
extern void sepol_user_free(sepol_user_t user);

#endif

#ifndef _SEPOL_USERS_H_
#define _SEPOL_USERS_H_

#include <sepol/policydb.h>
#include <sepol/user_record.h>
#include <sys/types.h>

/* Clear unused users */
extern void sepol_clear_unused_users(
	policydb_t* policydb);

/* Add/delete/load users from the policy 
   Load allows duplicates, but add does not. */
extern int sepol_user_add(
	policydb_t* policydb,
	sepol_user_t user); 

extern int sepol_user_del(
	policydb_t* policydb, 
	const char *username);

extern int sepol_user_load(
	policydb_t* policydb, 
	sepol_user_t user);

/* Check if users or roles are valid */
extern int sepol_user_is_valid(
	policydb_t* policydb,
	const char* user);

extern int sepol_role_is_valid(
	policydb_t* policydb,
	const char* role);

/* Obtain an array of all valid users/roles */
extern int sepol_get_valid_users(
	policydb_t* policydb,
	char*** users,
	size_t* nusers);

extern int sepol_get_valid_roles(
	policydb_t* policydb, 
	char*** roles, 
	size_t* nroles);

#endif /* _SEPOL_USERS_H_ */

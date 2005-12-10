#ifndef _SEPOL_ROLES_H_
#define _SEPOL_ROLES_H_

extern int sepol_role_exists(
	sepol_policydb_t* policydb,
	const char* role,
	int* response);

extern int sepol_role_list(
	sepol_policydb_t* policydb,
	char*** roles,
	size_t* nroles);

#endif

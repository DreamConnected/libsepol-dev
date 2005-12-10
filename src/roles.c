#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include <sepol/policydb/policydb.h>

#include "debug.h"
#include "handle.h"

/* Check if a role exists */
int sepol_role_exists(
	sepol_handle_t* handle,
	sepol_policydb_t* p, 
	const char* role,
	int* response) {

  	policydb_t *policydb = &p->p;
	char* role_copy = strdup(role);
	if (!role_copy) {
		ERR(handle, "out of memory, role check failed");
		return STATUS_ERR;
	}

	*response = (hashtab_search(policydb->p_roles.table, role_copy) != NULL);
	free(role_copy);
	return STATUS_SUCCESS;
}


/* Fill an array with all valid roles */
int sepol_role_list(
	sepol_handle_t* handle,
	sepol_policydb_t* p, 
	char*** roles, 
	size_t* nroles) {

	policydb_t *policydb = &p->p;
	size_t tmp_nroles = policydb->p_roles.nprim;
	char **tmp_roles = (char**) malloc(tmp_nroles * sizeof(char*));
	char **ptr;
	size_t i;
	if (!tmp_roles) 
		goto omem;

	for (i =0; i < tmp_nroles; i++) {
		tmp_roles[i] = strdup(policydb->p_role_val_to_name[i]);
		if (!tmp_roles[i]) 
			goto omem;
	}	 

	*nroles = tmp_nroles;
	*roles = tmp_roles;

        return STATUS_SUCCESS;

	omem:
	ERR(handle, "out of memory, could not list roles");
	
	ptr = tmp_roles;
	while (ptr && *ptr) 
		free(*ptr++);
	free(tmp_roles);
	return STATUS_ERR;
}



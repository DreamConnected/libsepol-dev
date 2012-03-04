#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <sepol/user_record.h>
#include "debug.h"

struct sepol_user {
	/* This user's name */
	char* name;

	/* This user's mls level (only required for mls) */
	char* mls_level;

	/* This user's mls range (only required for mls) */
	char* mls_range;

	/* The role array */
	char** roles;

	/* The number of roles */
	unsigned int num_roles;

	/* The default role */
	char* def_role;
};

struct sepol_user_key {
	/* This user's name */
	const char* name;
};

int sepol_user_key_create(
	const char* name,
	sepol_user_key_t* key_ptr) {

	sepol_user_key_t tmp_key = 
		(sepol_user_key_t) malloc(sizeof (struct sepol_user_key));

	if (!tmp_key) {
		DEBUG(__FUNCTION__, "out of memory, "
			"could not create selinux user key\n");
		return STATUS_ERR;
	}

	tmp_key->name = name;

	*key_ptr = tmp_key;
	return STATUS_SUCCESS;
}

int sepol_user_key_extract(sepol_user_t user, sepol_user_key_t* key_ptr) {
	if (sepol_user_key_create(user->name, key_ptr) < 0) {
		DEBUG(__FUNCTION__, "could not extract key from user %s\n",
			user->name);
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}	

void sepol_user_key_free(sepol_user_key_t key) {
	free(key);
}

int sepol_user_compare(
	sepol_user_t user,
	sepol_user_key_t key) {
	
	if (!strcmp(user->name, key->name))
		return 0;
	return 1;
}

/* Name */
const char* sepol_user_get_name(sepol_user_t user) {
	return user->name;
}

int sepol_user_set_name(sepol_user_t user, const char* name) {
	user->name = strdup(name);
	if (!user->name) {
		DEBUG(__FUNCTION__, "out of memory, "
			"could not set name\n");
		return STATUS_ERR;
	}
	return STATUS_SUCCESS;
}

/* MLS */
const char* sepol_user_get_mlslevel(sepol_user_t user) {
	return user->mls_level;
}

int sepol_user_set_mlslevel(sepol_user_t user, const char* mls_level) {
	user->mls_level = strdup(mls_level);
	if (!user->mls_level) {
		DEBUG(__FUNCTION__, "out of memory, "
			"could not set MLS default level\n");
		return STATUS_ERR;
	}
	return STATUS_SUCCESS;
}

const char* sepol_user_get_mlsrange(sepol_user_t user) {
	return user->mls_range;
}

int sepol_user_set_mlsrange(sepol_user_t user, const char* mls_range) {
	user->mls_range = strdup(mls_range);
	if (!user->mls_range) {
		DEBUG(__FUNCTION__, "out of memory, "
			"could not set MLS allowed range\n");
		return STATUS_ERR;
	}
	return STATUS_SUCCESS;
}

/* Roles */
int sepol_user_get_numroles(sepol_user_t user) {
	return user->num_roles;
}

const char* sepol_user_get_defrole(sepol_user_t user) {
	 return (user->def_role == NULL)? NULL : user->def_role;
}

int sepol_user_add_role(sepol_user_t user, const char* role) {

	char* role_cp = strdup(role);
	char* role_cp2 = strdup(role); 
	char** roles_realloc = realloc(user->roles, user->num_roles + 1);
	if (!role_cp || !role_cp2 || !roles_realloc) 
		goto omem;

	user->num_roles++;
	user->roles = roles_realloc;
	user->roles[user->num_roles - 1] = role_cp;
	if (!user->def_role)
		user->def_role = role_cp2;

        return STATUS_SUCCESS;

	omem:
	DEBUG(__FUNCTION__, "out of memory, "
		"could not add role %s\n", role);
	free(role_cp);
	free(role_cp2);
	free(roles_realloc);
	return STATUS_ERR;
}

int sepol_user_has_role(sepol_user_t user, const char* role) {
	unsigned int i;

	for (i = 0; i < user->num_roles; i++)
		if (!strcmp(user->roles[i], role)) 
			return 1;
	return 0;
}

int sepol_user_set_roles(
	sepol_user_t user,
	const char** roles_arr,
	size_t num_roles) {

	unsigned int i;
	char** tmp_roles =
		(char**) calloc(1, sizeof(char*) * num_roles);
	if (!tmp_roles) 
		goto omem;
	
	for (i = 0; i < num_roles; i++) {
		tmp_roles[i] = strdup(roles_arr[i]); 
		if (!tmp_roles[i])
			goto omem;	
	}

	user->roles = tmp_roles;
	user->num_roles = num_roles;
	return STATUS_SUCCESS;

	omem:
	DEBUG(__FUNCTION__, "out of memory, could not "
		"allocate roles array for user %s\n", user->name);

	if (tmp_roles) {
		for (i = 0; i < num_roles; i++ ) {
			if (!tmp_roles[i])
				break;
			free(tmp_roles[i]);
		}
		free(tmp_roles);
	}
	return STATUS_ERR;	
}

int sepol_user_get_roles(
	sepol_user_t user, 
	const char*** roles_arr, 
	size_t* num_roles) {

	unsigned int i;	
	const char** tmp_roles = 
		(const char**) malloc(sizeof (char*) * user->num_roles);
	if (!tmp_roles)
		goto omem;

	for (i = 0; i < user->num_roles; i++)
		tmp_roles[i] = user->roles[i];

	*roles_arr = tmp_roles;
	*num_roles = user->num_roles;
	return STATUS_SUCCESS;

	omem:
	DEBUG(__FUNCTION__, "out of memory, could not "
		"allocate roles array for user %s\n", user->name);
	free(tmp_roles);
	return STATUS_ERR;
}

int sepol_user_del_role(sepol_user_t user, const char* role) {
	unsigned int i;
	for (i = 0; i < user->num_roles; i++) {
		if (!strcmp(user->roles[i], role)) {

			if (user->num_roles == 1) {
				DEBUG(__FUNCTION__,
					"cannot delete last role "
					"for user %s\n", user->name);
				goto err;
			}

			free(user->roles[i]);
			user->roles[i] = user->roles[user->num_roles-1];
			user->num_roles--;

			if (!strcmp(user->def_role, role))  {
				free(user->def_role);
				user->def_role = strdup(user->roles[0]);
				if (!user->def_role)
					goto omem;
			}
			return STATUS_SUCCESS;
		}
	}

	omem:
	DEBUG(__FUNCTION__, "out of memory\n");
	
	err:
	DEBUG(__FUNCTION__, "could not allocate new default role\n");
	return STATUS_ERR;
}

int sepol_user_set_defrole(sepol_user_t user, const char* role) {

	/* First, add the role if we don't have it */
	if (!sepol_user_has_role(user, role)) {
		if (sepol_user_add_role(user, role) < 0)
			goto err;
	}

	/* Set as default */
	user->def_role = strdup(role);
	if (!user->def_role)
		goto omem;		


	return STATUS_SUCCESS;
	omem:
	DEBUG(__FUNCTION__, "out of memory\n");
	
	err:
	DEBUG(__FUNCTION__, "could not set default role for %s to %s\n",
		user->name, role);
	return STATUS_ERR;
}

/* Create */
int sepol_user_create(sepol_user_t* user_ptr) {
	sepol_user_t user = (sepol_user_t) 
		malloc(sizeof (struct sepol_user));

        if (!user) {
		DEBUG(__FUNCTION__, "out of memory, "
			"could not create selinux user record\n"); 
		return STATUS_ERR;
	}

        user->roles = NULL;
        user->def_role = NULL;
        user->num_roles = 0;
        user->name = NULL;
	user->mls_level = NULL;
	user->mls_range = NULL;
	
	*user_ptr = user;
	return STATUS_SUCCESS;
}

/* Deep copy clone */
int sepol_user_clone(sepol_user_t user, sepol_user_t* user_ptr) {
	sepol_user_t new_user = NULL;
	unsigned int i;

	if (sepol_user_create(&new_user) < 0)
		goto err;

	if (sepol_user_set_name(new_user, user->name) < 0)
		goto err;

	for (i = 0; i < user->num_roles; i++) {
		if (sepol_user_add_role(new_user, user->roles[i]) < 0) 
			goto err;
	}

	if (sepol_user_set_defrole(new_user, user->def_role) < 0)
		goto err;	

	if (user->mls_level &&
	    (sepol_user_set_mlslevel(new_user, user->mls_level) < 0))
		goto err;

	if (user->mls_range &&
	    (sepol_user_set_mlsrange(new_user, user->mls_range) < 0))
		goto err;

	*user_ptr = new_user;
	return STATUS_SUCCESS;

	err:
	DEBUG(__FUNCTION__, "could not clone selinux user record\n");
	sepol_user_free(new_user);
	return STATUS_ERR;
}

/* Destroy */
void sepol_user_free(sepol_user_t user) {
	unsigned int i;

	if (!user)
		return;
	
	free(user->name);
	for (i = 0; i < user->num_roles; i++)
		free(user->roles[i]);
	free(user->roles);
	free(user->mls_level);
	free(user->mls_range);
	free(user);
}

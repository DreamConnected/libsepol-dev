#include <stdlib.h>
#include <sys/types.h>

#include "private.h"
#include "debug.h"

#include <sepol/sepol.h>
#include <sepol/policydb.h>
#include <sepol/expand.h>
#include <sepol/mls.h>
#include <sepol/users.h>
#include <sepol/user_record.h>

int selinux_delusers = 0;

void sepol_set_delusers(int on) {
	selinux_delusers = on;
}

/* Select users for removal based on whether they were defined in the
   new users configuration. */
static int select_user(
	hashtab_key_t key __attribute__ ((unused)), 
	hashtab_datum_t datum, 
	void *datap __attribute__ ((unused))) {
	user_datum_t *usrdatum = datum;

	if (!usrdatum->defined)
		return 1;
	return 0;
}

/* Kill the user entries selected by select_user, and
   record that their slots are free. */
static void kill_user(
	hashtab_key_t key, 
	hashtab_datum_t datum, 
	void *arg)
{
	user_datum_t *usrdatum = (user_datum_t*) datum;
	policydb_t* policydb = (policydb_t*) arg;

	/* Locations of user we're deleting, and last user */
	int old_pos = usrdatum->value - 1;
	int last_pos = policydb->p_users.nprim - 1;

	/* Fill hole with last user/data pair */
	if (old_pos != last_pos) {

		char* last_name = policydb->p_user_val_to_name[last_pos];
		user_datum_t* last_data = 
			policydb->user_val_to_struct[last_pos];

		/* Decrement prim */
		last_data->value--;
	
		/* Update sid in reverse mapings */
		policydb->p_user_val_to_name[old_pos] = last_name;
		policydb->user_val_to_struct[old_pos] = last_data;
	}

	/* Decrement prim */
	policydb->p_users.nprim--;
	
	/* Free key and data */
	if (key)
		free(key);
	role_set_destroy(&usrdatum->roles);
	free(datum);
}

void sepol_clear_unused_users(policydb_t* policydb) {
	if (selinux_delusers) {
		hashtab_map_remove_on_error(
			policydb->p_users.table,
			&select_user, 
			&kill_user, 
			policydb);
        }
}

/* Add a user to the given policydb. The user may not exist already */

int sepol_user_add(policydb_t* policydb, sepol_user_t user) {

	char* name = NULL;
	user_datum_t* usrdatum;

	/* See if a user exists */
	name = strdup(sepol_user_get_name(user));
	if (!name) 
		goto omem;

        usrdatum = hashtab_search(policydb->p_users.table, name);

	/* If it does, fail */
	if (usrdatum) {
		DEBUG(__FUNCTION__,"%s is already in policy\n", name);
		goto err;
	}
	
	if (sepol_user_load(policydb, user) < 0) 
		goto err;

	return STATUS_SUCCESS;

	omem:
	DEBUG(__FUNCTION__, "out of memory\n");

	err:
	DEBUG(__FUNCTION__, "could not add %s to policy\n", 
		sepol_user_get_name(user));
	free(name);
	return STATUS_ERR;
}

/* Delete a user from the given policydb. This function will
 * fail if the user does not exist. */

int sepol_user_del(policydb_t* policydb, const char* username) {
	user_datum_t* usrdatum;
	char* name = NULL;

	name = strdup(username);
	if (!name) 
		goto omem;
	
	/* See if such a user exists */
	usrdatum = hashtab_search(policydb->p_users.table, name);

	/* If not, fail */
	if (usrdatum == NULL) {
		DEBUG(__FUNCTION__, "%s does not exist in policy\n", name);
		goto err;
	}
	else {
		if ( hashtab_remove(
			policydb->p_users.table, name, 
			&kill_user, policydb) < 0)
			goto err;
	}

	free(name);
	return STATUS_SUCCESS;

	omem:
	DEBUG(__FUNCTION__, "out of memory\n");

	err:
	DEBUG(__FUNCTION__, "could not remove %s from policy\n", name);
	free(name);
	return STATUS_ERR;
}

/* Load a user into policydb. The user may exist already, in
 * which case the supplied data replaces the existing data. Alternatively,
 * the user could be new. */

int sepol_user_load(policydb_t* policydb, sepol_user_t user) {

	/* For user data */	
	const char *tmp_mlslevel, *tmp_mlsrange;
	char *name = NULL;
	char *mls_level = NULL, *mls_range = NULL;
	const char **roles = NULL;
	size_t num_roles = 0;
	char *role = NULL;

	/* Low-level representation */
	user_datum_t* usrdatum = NULL;
	role_datum_t* roldatum;
	unsigned int i;

	context_struct_t context;
	unsigned bit;
	int new = 0;

	ebitmap_node_t *rnode;

	/* First, extract all the data */
	name = strdup(sepol_user_get_name(user));
	tmp_mlslevel = sepol_user_get_mlslevel(user);
	tmp_mlsrange = sepol_user_get_mlsrange(user);
	mls_level = tmp_mlslevel? strdup(tmp_mlslevel): NULL;
	mls_range = tmp_mlsrange? strdup(tmp_mlsrange): NULL;

	/* Make sure that worked properly */
	if (sepol_user_get_roles(user, &roles, &num_roles) < 0)
		goto err;

	if (!name || (tmp_mlslevel && !mls_level) ||
		(tmp_mlsrange && !mls_range))
		goto omem;
		
	/* Now, see if a user exists */
	usrdatum = hashtab_search(policydb->p_users.table, name);

	/* If it does, we will modify it */
	if (usrdatum) {
		role_set_destroy(&usrdatum->roles);
		role_set_init(&usrdatum->roles);
		usrdatum->defined = 1;

	/* Otherwise, create a new one */
	} else {
		usrdatum = (user_datum_t *) malloc(sizeof(user_datum_t));
		if (!usrdatum) 
			goto omem;
		memset(usrdatum, 0, sizeof(user_datum_t));
		role_set_init(&usrdatum->roles);
		usrdatum->defined = 1;
		new = 1;
	}

	/* For every role */
	for (i = 0; i < num_roles; i++) {
		char* role = strdup(roles[i]);
		if (!role)
			goto omem;

		/* Search for the role */
		roldatum = hashtab_search(policydb->p_roles.table, role);
		if (!roldatum) {
			DEBUG(__FUNCTION__, "undefined role %s for user %s\n", 
				role, name);
			goto err;	
		}

		/* Set the role and every role it dominates */
		ebitmap_for_each_bit(&roldatum->dominates, rnode, bit) {
			if (ebitmap_node_get_bit(rnode, bit)) {
				if (ebitmap_set_bit(&(usrdatum->roles.roles), bit, 1)) 
					goto omem;
			}
		}
		
		free(role);
		role = NULL;
	}

	/* For MLS systems */
	if (mls_enabled) {
		char* mls_tmp;
		context_init(&context);

		/* MLS level */
		if (mls_level == NULL) {
			DEBUG(__FUNCTION__, "mls is enabled, but no mls "
				"level found for user %s\n", name);
			goto err;
		}

		mls_tmp = mls_level;
		if (mls_context_to_sid(policydb, '$', &mls_tmp, &context)) {
			DEBUG(__FUNCTION__, "invalid level %s for user %s\n", 
				mls_level, name);
			goto err;
		}
		memcpy(&usrdatum->dfltlevel, &context.range.level[0], 
		        sizeof(usrdatum->dfltlevel));
		
		/* MLS range */
		context_init(&context);
		if (mls_range == NULL) {
			DEBUG(__FUNCTION__, "mls is enabled, but no mls"
				"range found for user %s\n", name);
			goto err;
		}	

		mls_tmp = mls_range; 
		if (mls_context_to_sid(policydb, '$', &mls_tmp, &context)) {
			DEBUG(__FUNCTION__, "invalid range %s for user %s\n", 
				mls_range, name);
			goto err;
		}
		memcpy(&usrdatum->range, &context.range, sizeof(usrdatum->range));
	}

	/* If there are no errors, and this is a new user, add the user to policy */
	if (new) {
		void *tmp_ptr;

		/* Ensure reverse lookup array has enough space */
		tmp_ptr = realloc(policydb->user_val_to_struct, 
			(policydb->p_users.nprim + 1) * sizeof(user_datum_t *));
		if (!tmp_ptr)
			goto omem;
		policydb->user_val_to_struct = tmp_ptr;

		tmp_ptr = realloc(policydb->sym_val_to_name[SYM_USERS],
			(policydb->p_users.nprim + 1) * sizeof(user_datum_t *));
		if (!tmp_ptr)
			goto omem;
		policydb->sym_val_to_name[SYM_USERS] = tmp_ptr;

		/* Store user */
		usrdatum->value = ++policydb->p_users.nprim;
		if (hashtab_insert(policydb->p_users.table, name, 
			(hashtab_datum_t) usrdatum) < 0) 
			goto omem;

		/* Set up reverse entry */
		policydb->p_user_val_to_name[usrdatum->value - 1] = name;
		policydb->user_val_to_struct[usrdatum->value - 1] = usrdatum;
		name = NULL;

		/* Expand roles */
		if (role_set_expand(&usrdatum->roles, &usrdatum->cache, policydb)) {
			DEBUG(__FUNCTION__, "unable to expand role set\n");
			goto err;
		}
	}	
	
	free(name);
	free(roles);
	free(mls_range);
	free(mls_level);
	return STATUS_SUCCESS;

	omem:
	DEBUG(__FUNCTION__, "out of memory\n");

	err:
	DEBUG(__FUNCTION__, "could not load %s into policy\n", name);

	free(name);
	free(role);
	free(roles);
	free(mls_range);
	free(mls_level);
	if (new && usrdatum) {
		role_set_destroy(&usrdatum->roles);
		free(usrdatum);
	}
	return STATUS_ERR;
}

/* Check if a user is valid */

int sepol_user_is_valid(policydb_t* policydb, const char* user) {
	int status;	
	char* user_copy = strdup(user);
	if (!user_copy) {
		DEBUG(__FUNCTION__, "out of memory, user check failed\n");
		return STATUS_ERR;
	}
	
	status = hashtab_search(policydb->p_users.table, user_copy) != NULL;
	free(user_copy);
	return status;
}

/* Check if a role is valid */

int sepol_role_is_valid(policydb_t* policydb, const char* role) {
	int status;
	char* role_copy = strdup(role);
	if (!role_copy) {
		DEBUG(__FUNCTION__, "out of memory, role check failed\n");
		return STATUS_ERR;
	}

	status = hashtab_search(policydb->p_roles.table, role_copy) != NULL;
	free(role_copy);
	return status;
}

/* Fill an array with all valid users */

int sepol_get_valid_users(policydb_t* policydb, char*** users, size_t* nusers) {
	size_t tmp_nusers = policydb->p_users.nprim;
	char **tmp_users = (char**) malloc(tmp_nusers * sizeof(char*));
	char **ptr;
	size_t i;
	if (!tmp_users)
		goto omem;
	
	for (i = 0; i < tmp_nusers; i++) {
		tmp_users[i] = strdup(policydb->p_user_val_to_name[i]);
		if (!tmp_users[i])
			goto omem;
	}

	*nusers = tmp_nusers;
	*users = tmp_users;

	return STATUS_SUCCESS;

	omem:
	DEBUG(__FUNCTION__, "out of memory, could not "
		"allocate list of valid users\n");

	ptr = tmp_users;
	while (ptr && *ptr) 
		free(*ptr++);
	free(tmp_users);
	return STATUS_ERR;
}

/* Fill an array with all valid roles */

int sepol_get_valid_roles(policydb_t* policydb, char*** roles, size_t* nroles) {
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
	DEBUG(__FUNCTION__, "out of memory, could not "
		"allocate list of valid roles\n");
	
	ptr = tmp_roles;
	while (ptr && *ptr) 
		free(*ptr++);
	free(tmp_roles);
	return STATUS_ERR;
}

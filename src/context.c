#include <stdlib.h>

#include <sepol/policydb.h>
#include <sepol/context.h>
#include <sepol/mls.h>
#include <sepol/context_record.h>

#include "debug.h"

/*
 * Return 1 if the fields in the security context
 * structure `c' are valid.  Return 0 otherwise.
 */
int sepol_ctx_struct_is_valid(policydb_t *p, context_struct_t *c)
{
	role_datum_t *role;
	user_datum_t *usrdatum;
	ebitmap_t types, roles;
	int ret = 1;

	ebitmap_init(&types);
	ebitmap_init(&roles);
	if (!c->role || c->role > p->p_roles.nprim)
		return 0;

	if (!c->user || c->user > p->p_users.nprim)
		return 0;

	if (!c->type || c->type > p->p_types.nprim)
		return 0;

	if (c->role != OBJECT_R_VAL) {
		/*
		 * Role must be authorized for the type.
		 */
		role = p->role_val_to_struct[c->role - 1];
		if (!ebitmap_get_bit(&role->cache, c->type - 1))
			/* role may not be associated with type */
			return 0;

		/*
		 * User must be authorized for the role.
		 */
		usrdatum = p->user_val_to_struct[c->user - 1];
		if (!usrdatum)
			return 0;

		if (!ebitmap_get_bit(&usrdatum->cache, c->role - 1)) 
			/* user may not be associated with role */
			return 0;
	}

	if (!mls_context_isvalid(p, c))
		return 0;

	return ret;
}

/*
 * Write the security context string representation of
 * the context structure `context' into a dynamically
 * allocated string of the correct size.  Set `*scontext'
 * to point to this string and set `*scontext_len' to
 * the length of the string.
 */
int sepol_ctx_struct_to_string(
	policydb_t* policydb,
	context_struct_t * context,
	char **result,
	size_t *result_len) {

	char *scontext = NULL;
	size_t scontext_len = 0;
	char* ptr;

	/* Compute the size of the context. */
	scontext_len += strlen(policydb->p_user_val_to_name[context->user-1])+1;
	scontext_len += strlen(policydb->p_role_val_to_name[context->role-1])+1;
	scontext_len += strlen(policydb->p_type_val_to_name[context->type-1]);
	scontext_len += mls_compute_context_len(policydb, context);
	
	/* We must null terminate the string */
	scontext_len += 1;

	/* Allocate space for the context; caller must free this space. */
	scontext = malloc(scontext_len);
	if (!scontext) 
		goto omem;
	scontext[scontext_len-1] = '\0';

	/*
	 * Copy the user name, role name and type name into the context.
	 */
	ptr = scontext;
	sprintf(ptr, "%s:%s:%s",
		policydb->p_user_val_to_name[context->user - 1],
		policydb->p_role_val_to_name[context->role - 1],
		policydb->p_type_val_to_name[context->type - 1]);

	ptr += 
		strlen(policydb->p_user_val_to_name[context->user - 1]) + 1 + 
		strlen(policydb->p_role_val_to_name[context->role - 1]) + 1 + 
		strlen(policydb->p_type_val_to_name[context->type - 1]);

	mls_sid_to_context(policydb, context, &ptr);

	*result = scontext;
	*result_len = scontext_len;
	return STATUS_SUCCESS;

	omem:
	DEBUG(__FUNCTION__, "out of memory, could not convert "
		"context to string\n");
	free(scontext);
	return STATUS_ERR;
}


/* Create a policy-dependent context structure, corresponding
 * to the provided high level representation */

int sepol_ctx_struct_create(
	policydb_t* policydb, 
	context_struct_t** cptr, 
	sepol_context_t data) {

	context_struct_t* scontext = NULL;
	user_datum_t* usrdatum;
	role_datum_t* roldatum;
	type_datum_t* typdatum;

	/* Hashtab keys are not constant - suppress warnings */
	char* user = strdup(sepol_context_get_user(data)); 
	char* role = strdup(sepol_context_get_role(data));
	char* type = strdup(sepol_context_get_type(data));
 
 	const char* tmp = sepol_context_get_mls(data);
 	char* mls = tmp ? strdup(tmp): NULL;
 	char* mls_ptr = mls;

	scontext = (context_struct_t*) malloc(sizeof(context_struct_t));
 	if (!user || !role || !type || (tmp && !mls) || !scontext) {
		DEBUG(__FUNCTION__, "out of memory\n"); 
		goto err;
	}
	context_init(scontext);

	/* User */
	usrdatum = (user_datum_t*) hashtab_search(policydb->p_users.table,
                                        (hashtab_key_t) user);
	if (!usrdatum) {
		DEBUG(__FUNCTION__, "user %s is not defined\n", user);
		goto err_destroy;
	}
	scontext->user = usrdatum->value;

	/* Role */
	roldatum = (role_datum_t*) hashtab_search(policydb->p_roles.table,
					(hashtab_key_t) role);
	if (!roldatum) {
		DEBUG(__FUNCTION__, "role %s is not defined\n", role);
		goto err_destroy;
	}
	scontext->role = roldatum->value;

	/* Type */
	typdatum = (type_datum_t *) hashtab_search(policydb->p_types.table,
					(hashtab_key_t) type);
	if (!typdatum || typdatum->isattr) {
		DEBUG(__FUNCTION__, "type %s is not defined\n", type);
		goto err_destroy;
	}
	scontext->type = typdatum->value;

	/* MLS */
	if (mls && !sepol_mls_enabled()) {
 		DEBUG(__FUNCTION__, "Warning! mls context \"%s\" found, "
 			"but mls is disabled\n", mls);
 		free(mls);
		mls = NULL;
	}
	else if (!mls && sepol_mls_enabled()) {
 		DEBUG(__FUNCTION__, "mls is enabled, but no "
 			"mls context found\n");
		goto err_destroy;
	}
 	if (mls && (mls_context_to_sid(policydb, '$', &mls_ptr, scontext) < 0)) {
 		DEBUG(__FUNCTION__, "invalid mls context: %s\n", mls);
		goto err_destroy;
	}

	/* Validity check */
 	if (!sepol_ctx_struct_is_valid(policydb, scontext)) {
		if (mls)
			DEBUG(__FUNCTION__, 
				"invalid security context: %s:%s:%s:%s\n",
				user, role, type, mls);
		else
			DEBUG(__FUNCTION__, 
				"invalid security context: %s:%s:%s\n",
				user, role, type);
		goto err_destroy;
	}

	*cptr = scontext;
	free(user);	
	free(type);
	free(role);
	free(mls);
	return STATUS_SUCCESS;

	err_destroy:
	context_destroy(scontext);

	err: 
	free(scontext);
	free(user);
	free(type);
	free(role);
	free(mls);	
	DEBUG(__FUNCTION__, "error creating context structure\n");
	return STATUS_ERR;
}

/*
 * Create a context structure from the provided string.
 */
int sepol_ctx_struct_from_string(
	policydb_t* policydb,
	context_struct_t** cptr,
	const char* con_str,
	size_t con_str_len) { 

	char* con_cpy = NULL;
	sepol_context_t ctx_info = NULL;

	/* sepol_context_from_string expects a NULL-terminated string */
	con_cpy = malloc(con_str_len + 1);
	if (!con_cpy) {
		DEBUG(__FUNCTION__, "out of memory\n");
		goto err;
	}
	memcpy(con_cpy, con_str, con_str_len);
	con_cpy[con_str_len] = '\0';

	if (sepol_context_from_string(con_cpy, &ctx_info) < 0)
		goto err;

	/* Now create from the data structure */
	if (sepol_ctx_struct_create(policydb, cptr, ctx_info) < 0)
		goto err;

	free(con_cpy);
	sepol_context_free(ctx_info);
	return STATUS_SUCCESS;
	
	err:
	DEBUG(__FUNCTION__, "unable to create context structure\n");
	free(con_cpy);
	sepol_context_free(ctx_info);
	return STATUS_ERR;
}

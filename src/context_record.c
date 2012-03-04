#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sepol/context_record.h>
#include "debug.h"

struct sepol_context {

	/* Selinux user */
	char* user;

	/* Selinux role */
	char* role;

	/* Selinux type */
	char* type;

	/* MLS */
	char* mls;
};

/* User */
const char* sepol_context_get_user(sepol_context_t con) {
	return con->user;
}

int sepol_context_set_user(sepol_context_t con, const char* user) {
	con->user = strdup(user);
	if (!con->user) { 
		DEBUG(__FUNCTION__, "out of memory, could not set "
			"context user to %s\n", user);
		return STATUS_ERR;
	}
	return STATUS_SUCCESS;
}

/* Role */
const char* sepol_context_get_role(sepol_context_t con) {
	return con->role;
}

int sepol_context_set_role(sepol_context_t con, const char* role) {
	con->role = strdup(role);
	if (!con->role) {
		DEBUG(__FUNCTION__, "out of memory, could not set "
			"context role to %s\n", role);
		return STATUS_ERR;
	}
	return STATUS_SUCCESS;
}

/* Type */
const char* sepol_context_get_type(sepol_context_t con) {
	return con->type;
}

int sepol_context_set_type(sepol_context_t con, const char* type) {
	con->type = strdup(type);
	if (!con->role) {
		DEBUG(__FUNCTION__, "out of memory, could not set "
			"context type to %s\n", type);
		return STATUS_ERR;
	}
	return STATUS_SUCCESS;
}

/* MLS */
const char* sepol_context_get_mls(sepol_context_t con) {
	return con->mls;
}

int sepol_context_set_mls(sepol_context_t con, const char* mls) {
	con->mls = strdup(mls);
	if (!con->mls) {
		DEBUG(__FUNCTION__, "out of memory, could not set "
			"MLS fields to %s\n", mls);
		return STATUS_ERR;
	}	
	return STATUS_SUCCESS;
}

/* Create */
int sepol_context_create(sepol_context_t* con_ptr) {
	sepol_context_t con =
                (sepol_context_t) malloc(sizeof(struct sepol_context));

        if (!con) {
		DEBUG(__FUNCTION__, "out of memory, could not "
			"create context\n");
		return STATUS_ERR;
	}

	con->user = NULL;
	con->role = NULL;
	con->type = NULL;
	con->mls = NULL;
	*con_ptr = con;
	return STATUS_SUCCESS;
}

/* Deep copy clone */
int sepol_context_clone(
	sepol_context_t con,
	sepol_context_t* con_ptr) {

	sepol_context_t new_con = NULL;	
	if (sepol_context_create(&new_con) < 0)
		goto err;

	if (!(new_con->user = strdup(con->user)))
		goto omem;

	if (!(new_con->role = strdup(con->role)))
		goto omem;

	if (!(new_con->type = strdup(con->type)))
		goto omem;

	if (con->mls && !(new_con->mls = strdup(con->mls)))
		goto omem;

	*con_ptr = new_con;
	return STATUS_SUCCESS;
		
	omem:
	DEBUG(__FUNCTION__, "out of memory\n");

	err:
	DEBUG(__FUNCTION__, "could not clone context record\n");
	sepol_context_free(new_con);
	return STATUS_ERR;
}

/* Destroy */
void sepol_context_free(sepol_context_t con) {
	if (!con)
		return;

	free(con->user);
	free(con->role);
	free(con->type);
	free(con->mls);
	free(con);
}

int sepol_context_from_string(const char* str, sepol_context_t* con) {

	char *tmp = NULL, *low, *high;
	sepol_context_t tmp_con = NULL;

	if (!strcmp(str, "<<none>>")) {
		*con = NULL;
		return STATUS_SUCCESS;
	}

	if (sepol_context_create(&tmp_con) < 0)
		goto err;

	/* Working copy context */
	tmp = strdup(str);
	if (!tmp) {
		DEBUG(__FUNCTION__, "out of memory\n");
		goto err;
	}
	low = tmp;

	/* Then, break it into its components */

	/* User */
	if (!(high = strchr(low, ':')))
		goto mcontext;
	else
		*high++ = '\0';
	if (sepol_context_set_user(tmp_con, low) < 0)
		goto err;	
	low = high;

	/* Role */
	if (!(high = strchr(low, ':')))
		goto mcontext;
	else
		*high++ = '\0';
	if (sepol_context_set_role(tmp_con, low) < 0)
		goto err;
	low = high;

	/* Type, and possibly MLS */
	if (!(high = strchr(low, ':'))) {
		if (sepol_context_set_type(tmp_con, low) < 0)
			goto err;
	}
	else {
		*high++ = '\0';
		if (sepol_context_set_type(tmp_con, low) < 0)
			goto err;
		low = high;
		if (sepol_context_set_mls(tmp_con, low) < 0)
			goto err;
	}

	free(tmp);
	*con = tmp_con;
	
	return STATUS_SUCCESS;

	mcontext:
	DEBUG(__FUNCTION__, "malformed context \"%s\"\n", str);

	err:
	DEBUG(__FUNCTION__, "could not construct context from string\n");
	free(tmp);
	sepol_context_free(tmp_con);
	return STATUS_ERR;
}

char* sepol_context_to_string(sepol_context_t con) {

	const int user_sz = strlen(con->user);
	const int role_sz = strlen(con->role);
	const int type_sz = strlen(con->type);
	const int mls_sz = (con->mls)? strlen(con->mls): 0;	

	const int total_sz = user_sz + role_sz + type_sz + 
		mls_sz + ((con->mls)? 3:2);

	char* str = malloc(total_sz + 1);
	int rc;

	if (!str)
		goto omem;
	
	if (con->mls) {
		rc = snprintf(str, total_sz + 1, "%s:%s:%s:%s", 
			con->user, con->role, con->type, con->mls);
		if (rc < 0 || (rc == total_sz + 1)) {
			DEBUG(__FUNCTION__, "print error\n");
			goto err;
		}
	}
	else { 		
		rc = snprintf(str, total_sz + 1, "%s:%s:%s",
			con->user, con->role, con->type);
		if (rc < 0 || (rc == total_sz + 1)) {
			DEBUG(__FUNCTION__, "print error\n");
			goto err;
		}
	}

	return str; 
	omem:
	DEBUG(__FUNCTION__, "out of memory\n");

	err:
	DEBUG(__FUNCTION__, "could not convert context to string\n");
	if (str)
		free(str);
	return NULL;
}

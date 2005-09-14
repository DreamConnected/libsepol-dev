#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include <sepol/policydb.h>
#include <sepol/conditional.h>

#include "private.h"

static char *strtrim(char *dest, char *source, int size) {
	int i=0;
	char *ptr=source;
	i=0;
	while(isspace(*ptr) && i < size) {
		ptr++;
		i++;
	}
	strncpy(dest,ptr,size);
	for(i=strlen(dest)-1; i> 0; i--) {
		if (!isspace(dest[i])) break;
	}
	dest[i+1]='\0';
	return dest;
}

static int process_boolean(char *buffer, char *name, int namesize, int *val) {
	char name1[BUFSIZ];
	char *ptr;
	char *tok=strtok_r(buffer,"=",&ptr);
	if (tok) {
		strncpy(name1,tok, BUFSIZ-1);
		strtrim(name,name1,namesize-1);
		if ( name[0]=='#' ) return 0;
		tok=strtok_r(NULL,"\0",&ptr);
		if (tok) {
			while (isspace(*tok)) tok++;
			*val = -1;
			if (isdigit(tok[0]))
				*val=atoi(tok);
			else if (!strncasecmp(tok, "true", sizeof("true")-1))
				*val = 1;
			else if (!strncasecmp(tok, "false", sizeof("false")-1))
				*val = 0;
			if (*val != 0 && *val != 1) {
				fprintf(stderr,"illegal value for boolean %s=%s\n", name, tok);
				return -1;
			}
			
		}
	}
	return 1;
}

static int load_booleans(struct policydb *policydb, const char *path) {
	FILE *boolf;
	char *buffer=NULL;
	size_t size=0;
	char localbools[BUFSIZ];
	char name[BUFSIZ];
	int val;
	int errors=0;
	struct cond_bool_datum *datum;

	boolf = fopen(path,"r");
	if (boolf == NULL) 
		goto localbool;

	while (getline(&buffer, &size, boolf) > 0) {
		int ret=process_boolean(buffer, name, sizeof(name), &val);
		if (ret==-1) 
			errors++;
		if (ret==1) {
			datum = hashtab_search(policydb->p_bools.table, name);
			if (!datum) {
				fprintf(stderr,"unknown boolean %s\n", name);
				errors++;
				continue;
			}
			datum->state = val;
		}
	}
	fclose(boolf);
localbool:
	snprintf(localbools,sizeof(localbools), "%s.local", path);
	boolf = fopen(localbools,"r");
	if (boolf != NULL) {
		while (getline(&buffer, &size, boolf) > 0) {
			int ret=process_boolean(buffer, name, sizeof(name), &val);
			if (ret==-1) 
				errors++;
			if (ret==1) {
				datum = hashtab_search(policydb->p_bools.table, name);
				if (!datum) {
					fprintf(stderr,"unknown boolean %s\n", name);
					errors++;
					continue;
				}
				datum->state = val;
			}
		}
		fclose(boolf);
	}
	free(buffer);
	if (errors)
		errno = EINVAL;

	return errors ? -1 : 0;
}

int sepol_genbools(void *data, size_t len, char *booleans)
{
	struct policydb policydb;
	struct policy_file pf;
	int rc;

	if (policydb_from_image(data, len, &policydb) < 0)
		goto err;

	/* Preserve the policy version of the original policy
	   for the new policy. */
	sepol_set_policyvers(policydb.policy_type, policydb.policyvers);

	if (load_booleans(&policydb, booleans) < 0) {
		__sepol_debug_printf("%s:  Warning!  Error while reading %s\n",
				     __FUNCTION__, booleans);
	}

	if (evaluate_conds(&policydb) < 0) {
		__sepol_debug_printf("%s:  Error while re-evaluating conditionals\n",
				     __FUNCTION__);
		errno = EINVAL;
		goto err_destroy;
	}

	pf.type = PF_USE_MEMORY;
	pf.data = data;
	pf.len = len;
	rc = policydb_write(&policydb, &pf);
	if (rc) {
		__sepol_debug_printf("%s: Can't write new binary policy image\n",
				     __FUNCTION__);
		errno = EINVAL;
		goto err_destroy;
	}

	policydb_destroy(&policydb);
	return 0;

	err_destroy:
	policydb_destroy(&policydb);

	err:
	return -1;
}

int sepol_genbools_policydb(policydb_t *policydb, const char *booleans)
{
	int rc;

	rc = load_booleans(policydb, booleans);
	if (!rc)
		rc = evaluate_conds(policydb);
	if (rc)
		errno = EINVAL;
	return rc;
}

int sepol_genbools_array(void *data, size_t len, char **names, int *values, int nel)
{
	struct policydb policydb;
	struct policy_file pf;
	int rc, i, errors = 0;
	struct cond_bool_datum *datum;

	/* Create policy database from image */
	if (policydb_from_image(data, len, &policydb) < 0) 
		goto err;

	/* Preserve the policy version of the original policy
	   for the new policy. */
	sepol_set_policyvers(policydb.policy_type, policydb.policyvers);

	for (i = 0; i < nel; i++) {
		datum = hashtab_search(policydb.p_bools.table, names[i]);
		if (!datum) {
			__sepol_debug_printf("%s:  boolean %s no longer in policy\n", 
					     __FUNCTION__, names[i]);
			errors++;
			continue;
		}
		if (values[i] != 0 && values[i] != 1) {
			fprintf(stderr,"illegal value %d for boolean %s\n", values[i], names[i]);
			errors++;
			continue;
		}
		datum->state = values[i];
	}

	if (evaluate_conds(&policydb) < 0) {
		__sepol_debug_printf("%s:  Error while re-evaluating conditionals\n",
				     __FUNCTION__);
		errno = EINVAL;
		goto err_destroy;
	}

	pf.type = PF_USE_MEMORY;
	pf.data = data;
	pf.len = len;
	rc = policydb_write(&policydb, &pf);
	if (rc) {
		__sepol_debug_printf("%s:  Can't write binary policy\n",
				     __FUNCTION__);
		errno = EINVAL;
		goto err_destroy;
	}
	if (errors) {
		errno = EINVAL;
		goto err_destroy;
	}

	policydb_destroy(&policydb);
	return 0;

	err_destroy:
	policydb_destroy(&policydb);

	err:
	return -1;
}



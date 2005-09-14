#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "private.h"
#include "debug.h"

#include <sepol/booleans.h>
#include <sepol/hashtab.h>
#include <sepol/policydb.h>
#include <sepol/conditional.h>

static inline int bool_update (
	policydb_t* policydb,
	sepol_boolinfo_t* boolean) {

	cond_bool_datum_t *datum = 
		hashtab_search(policydb->p_bools.table, boolean->name);
	if (!datum) {
		DEBUG(__FUNCTION__, "boolean %s no longer in policy\n",
			boolean->name);
		return STATUS_ERR;
        }
	if (boolean->value != 0 && boolean->value != 1) {
		DEBUG(__FUNCTION__, "illegal value %d for boolean %s\n",
			boolean->value, boolean->name);
		return STATUS_ERR;
        }
        datum->state = boolean->value;
	return STATUS_SUCCESS;
}

int sepol_bool_load (
	policydb_t* policydb, sepol_boolinfo_t* boolean) {

	if (bool_update(policydb, boolean) < 0)
		goto err;	
	
        if (evaluate_conds(policydb) < 0) {
		DEBUG(__FUNCTION__, "error while re-evaluating conditionals\n");
		goto err;
	}

	return STATUS_SUCCESS;

	err:
	DEBUG(__FUNCTION__, "could not load boolean %s\n", boolean->name);
	errno = EINVAL;
	return STATUS_ERR;
}

int sepol_bool_load_array(
	policydb_t* policydb,
	sepol_boolinfo_t* bool_arr,
	int bool_arr_len) {	

	int i, errors = 0;

	for (i = 0; i < bool_arr_len; i++)
		if (bool_update(policydb, &bool_arr[i]) < 0) {
			errors++;
			continue;
		}	

	if (evaluate_conds(policydb) < 0) {
		DEBUG("%s: error while re-evaluating conditionals\n", 
			__FUNCTION__);
		goto err;
	}

	if (errors) 
		goto err;

	return STATUS_SUCCESS;
	err:
	errno = EINVAL;
	DEBUG("%s: error while loading booleans\n", __FUNCTION__);
	return STATUS_ERR;
}

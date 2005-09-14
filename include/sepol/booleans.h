#ifndef _SEPOL_BOOLEANS_H_
#define _SEPOL_BOOLEANS_H_

#include <sepol/policydb.h>

/* High level representation of a boolean */
typedef struct sepol_boolinfo {
	char* name;
	int value;
} sepol_boolinfo_t;

/* Load a boolean into the policy */
extern int sepol_bool_load (
	policydb_t* policydb, 
	sepol_boolinfo_t* boolean);

/* Load a boolean array into the policy */
extern int sepol_bool_load_array(
	policydb_t* policydb,
	sepol_boolinfo_t* bool_arr,
	int bool_arr_len);

#endif /* _SEPOL_BOOLEANS_H_ */

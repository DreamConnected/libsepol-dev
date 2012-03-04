#ifndef _SEPOL_PORTS_H_
#define _SEPOL_PORTS_H_

#include <sepol/policydb.h>
#include <sepol/port_record.h>

/* Create a port structure from high level representation */
extern int sepol_port_struct_create(
	policydb_t* policydb,
	ocontext_t** port,
	sepol_port_t data);

/* Get the current context mapping
 * for this port. Returns 1 if no match, -1 on error, 0 on
 * success. The returned data is allocated on the heap */
int sepol_port_get_context(
	policydb_t* policydb,
	sepol_port_t data,
	char** con_str,
	size_t* con_str_len);

/* Load the given port into policy. No shadowing is allowed. */
extern int sepol_port_load(
	policydb_t* policydb, 
	sepol_port_t data);

#endif

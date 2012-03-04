#include <netinet/in.h>
#include <stdlib.h>

#include "debug.h"
#include <sepol/sepol.h>
#include <sepol/policydb.h>
#include <sepol/context.h>
#include <sepol/sidtab.h>
#include <sepol/services.h>
#include <sepol/ports.h>
#include <sepol/port_record.h>

static int sepol2ipproto(int proto) {
	switch(proto) {
		case SEPOL_PROTO_TCP:
			return IPPROTO_TCP;
		case SEPOL_PROTO_UDP:
			return IPPROTO_UDP;
		default:
			DEBUG(__FUNCTION__, "unsupported protocol %d\n",
                                proto);
			return -1;
	}
}

/* Create a low level port structure from
 * a high level representation */
int sepol_port_struct_create(
	policydb_t* policydb,
	ocontext_t** port,
	sepol_port_t data) {

	ocontext_t* tmp_port = NULL;
	context_struct_t* tmp_con = NULL;
	int tmp_proto;

	tmp_port = (ocontext_t *) calloc(1, sizeof(ocontext_t));
	if (!tmp_port) {
		DEBUG(__FUNCTION__, "out of memory\n");
		goto err;
	}
	
	/* Process protocol */
	tmp_proto = sepol2ipproto(sepol_port_get_proto(data));
	if (tmp_proto < 0)
		goto err;
	tmp_port->u.port.protocol = tmp_proto;

	/* Port range */
	tmp_port->u.port.low_port = sepol_port_get_low(data);
	tmp_port->u.port.high_port = sepol_port_get_high(data);
	if (tmp_port->u.port.low_port > tmp_port->u.port.high_port) {
		DEBUG(__FUNCTION__, "low port %d exceeds high port %d\n",
			tmp_port->u.port.low_port, 
			tmp_port->u.port.high_port);
		goto err;
	}

	/* Context */
	if (sepol_ctx_struct_create(policydb, &tmp_con, 
		sepol_port_get_con(data)) < 0)
		goto err;
	context_cpy(&tmp_port->context[0], tmp_con);
	free(tmp_con);

	*port = tmp_port;
	return STATUS_SUCCESS;

	err:
	free(tmp_port);
	DEBUG(__FUNCTION__, "error creating port structure\n");
	return STATUS_ERR;
}

/* Get the current context mapping for this port */
int sepol_port_get_context(
	policydb_t* policydb,
	sepol_port_t data,
	char** con_str,	
	size_t* con_str_len) {

	int low = sepol_port_get_low(data);	
	int high = sepol_port_get_high(data);

	int proto = sepol2ipproto(sepol_port_get_proto(data));
	if (proto < 0)
		goto err;

	ocontext_t *c, *l, *head;

	head = policydb->ocontexts[OCON_PORT];
	for (l = NULL, c = head; c; l = c, c = c->next) {
		int proto2 = c->u.port.protocol;
		int low2 = c->u.port.low_port;
		int high2 = c->u.port.high_port;
		context_struct_t* con2 = &c->context[0];

		if (proto != proto2)
			continue;

		if ((low == low2 && high == high2) ||
		    (low2 <= low && high2 >= high)) {
			if (sepol_ctx_struct_to_string(policydb, con2, 
				con_str, con_str_len) < 0)
				goto err;		
	
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NODATA;

	err: 
	DEBUG(__FUNCTION__, "could not retrieve context string for "
		"port entry %s %d-%d\n", 
			sepol_port_get_proto_str(data), low, high);
	return STATUS_ERR;

}

/* Load a port into policy */
int sepol_port_load(
	policydb_t* policydb, 
	sepol_port_t data) {

	ocontext_t* port = NULL;
	char* dup_match;
	size_t dup_size; 
	int rc;

	if (sepol_port_struct_create(policydb, &port, data) < 0)
		goto err;

	rc = sepol_port_get_context(policydb, data, &dup_match, &dup_size);
	if (rc < 0) 
		goto err;

	else if (rc != STATUS_NODATA) {
		DEBUG(__FUNCTION__, "port entry for %s %d-%d "
			"is already mapped to context %s\n",
			sepol_port_get_proto_str(data),
			sepol_port_get_low(data),
			sepol_port_get_high(data), dup_match);
		goto err;
	}
	
	/* Attach to context list */
	port->next = policydb->ocontexts[OCON_PORT];
	policydb->ocontexts[OCON_PORT] = port;

	return STATUS_SUCCESS;

	err:
	DEBUG(__FUNCTION__, "error while loading port %s %d-%d\n",
		sepol_port_get_proto_str(data),
		sepol_port_get_low(data),
		sepol_port_get_high(data));
	free(port);
	return STATUS_ERR;
}

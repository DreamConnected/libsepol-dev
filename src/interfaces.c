#include <netinet/in.h>
#include <stdlib.h>

#include "debug.h"
#include <sepol/sepol.h>
#include <sepol/policydb.h>
#include <sepol/context.h>
#include <sepol/sidtab.h>
#include <sepol/services.h>
#include <sepol/interfaces.h>

/* Create a low level interface structure from
 * a high level representation */
int sepol_iface_create(
	policydb_t* policydb,
	ocontext_t** iface,
	sepol_iface_t* data) {

	ocontext_t* tmp_iface = NULL;
	context_struct_t* tmp_ifcon = NULL;
	context_struct_t* tmp_msgcon = NULL;

	tmp_iface = (ocontext_t *) calloc(1, sizeof(ocontext_t));
	if (!tmp_iface) 	
		goto omem;

	/* Name */
	tmp_iface->u.name = strdup(data->name);
	if (!tmp_iface->u.name)
		goto omem;

	/* Interface Context */
	if (sepol_ctx_struct_create(policydb, 
		&tmp_ifcon, data->netif_con) < 0)
		goto err;
	context_cpy(&tmp_iface->context[0], tmp_ifcon);
	free(tmp_ifcon);

	/* Message Context */
	if (sepol_ctx_struct_create(policydb, &tmp_msgcon, 
		data->netmsg_con) < 0)
		goto err;
	context_cpy(&tmp_iface->context[1], tmp_msgcon);
	free(tmp_msgcon);

	*iface = tmp_iface;
	return STATUS_SUCCESS;

	omem:
	DEBUG(__FUNCTION__, "out of memory\n");

	err:
	free(tmp_iface);
	DEBUG(__FUNCTION__, "error creating interface structure\n");
	return STATUS_ERR;
}

/* Get the current context mapping for this interface */
int sepol_iface_get_context(
	policydb_t* policydb,
	sepol_iface_t* data,
	char** ifcon_str, size_t* ifcon_str_len,	
	char** msgcon_str, size_t* msgcon_str_len) {

	ocontext_t *c, *head;

	head = policydb->ocontexts[OCON_NETIF];
	for (c = head; c; c = c->next) {
		if (!strcmp(data->name, c->u.name)) { 
			if (sepol_ctx_struct_to_string(policydb, 
				&c->context[0], ifcon_str, ifcon_str_len) < 0)
				goto err;
	
			if (sepol_ctx_struct_to_string(policydb,
				&c->context[1], msgcon_str, msgcon_str_len) < 0)
				goto err;

			return STATUS_SUCCESS;
		}
	}

	return STATUS_NODATA;

	err: 
	DEBUG(__FUNCTION__, "could not construct context string for "
		"interface %s\n", data->name);
	return STATUS_ERR;
}

/* Load an interface into policy */
int sepol_iface_load(
	policydb_t* policydb, 
	sepol_iface_t* data) {

	ocontext_t* iface = NULL;
	char *ifcon_str, *msgcon_str;
	size_t ifcon_str_len, msgcon_str_len;
	int rc;

	if (sepol_iface_create(policydb, &iface, data) < 0)
		goto err;

	rc = sepol_iface_get_context(
		policydb, data, 
		&ifcon_str, &ifcon_str_len,
		&msgcon_str, &msgcon_str_len);
	if (rc < 0) 
		goto err;

	else if (rc != STATUS_NODATA) {
		DEBUG(__FUNCTION__, "interface %s is already mapped to " 
			"context %s with message context %s\n", 
			data->name, ifcon_str, msgcon_str);
		goto err;
	}
	
	/* Attach to context list */
	iface->next = policydb->ocontexts[OCON_NETIF];
	policydb->ocontexts[OCON_NETIF] = iface;

	return STATUS_SUCCESS;

	err:
	DEBUG(__FUNCTION__, "error while loading interface %s\n",
		data->name);
	free(iface);
	return STATUS_ERR;
}

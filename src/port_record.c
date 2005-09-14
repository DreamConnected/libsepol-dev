#include <stdlib.h>
#include <string.h>

#include <sepol/port_record.h>
#include <sepol/context_record.h>
#include "debug.h"

struct sepol_port {
	/* Low - High range. Same for single ports. */
	int low, high;
	
	/* Protocol */
	int proto;

	/* Context */
	sepol_context_t con;
};

struct sepol_port_key {
	/* Low - High range. Same for single ports. */
	int low, high;
	
	/* Protocol */
	int proto;	
};

/* Key */
int sepol_port_key_create(
	int low, int high, int proto, 
	sepol_port_key_t* key_ptr) {

	sepol_port_key_t tmp_key = 
		(sepol_port_key_t) malloc(sizeof(struct sepol_port_key));

	if (!tmp_key) {
		DEBUG(__FUNCTION__, "out of memory, could not create "
			"port key\n");
		return STATUS_ERR;
	}

	tmp_key->low = low;
	tmp_key->high = high;
	tmp_key->proto = proto;
	
	*key_ptr = tmp_key;
	return STATUS_SUCCESS;
}

int sepol_port_key_extract(sepol_port_t port, sepol_port_key_t* key_ptr) {
	if (sepol_port_key_create(
		port->low, port->high, port->proto, key_ptr) < 0) {
		DEBUG(__FUNCTION__, "could not extract key from "
			"port %s %d:%d\n", sepol_port_get_proto_str(port),
			port->low, port->high);
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

void sepol_port_key_free(sepol_port_key_t key) {
	free(key);
}

int sepol_port_compare(
	sepol_port_t port, 
	sepol_port_key_t key) {

	if ((port->low <= key->low) && 
	    (port->high >= key->high) &&
	    (port->proto == key->proto))
		return 0;

	return 1;
}

/* Port */
int sepol_port_get_low(sepol_port_t port) {
	return port->low;
}

int sepol_port_get_high(sepol_port_t port) {
	return port->high;
}

int sepol_port_set_port(sepol_port_t port, int port_num) {
	port->low = port_num;
	port->high = port_num;
	return STATUS_SUCCESS;
}

int sepol_port_set_range(sepol_port_t port, int low, int high) {
	port->low = low;
	port->high = high;
	return STATUS_SUCCESS;
}

/* Protocol */
int sepol_port_get_proto(sepol_port_t port) {
	return port->proto;
}

const char* sepol_port_get_proto_str(sepol_port_t port) {
	switch (port->proto) {
		case SEPOL_PROTO_UDP:
			return "udp";
		case SEPOL_PROTO_TCP:
			return "tcp";
		default:
			return "???";
	}	
}

int sepol_port_set_proto(sepol_port_t port, int proto) {
	port->proto = proto;
	return STATUS_SUCCESS;
}

/* Create */
int sepol_port_create(sepol_port_t* port) {
	sepol_port_t tmp_port = 
		(sepol_port_t) malloc(sizeof(struct sepol_port));

        if (!tmp_port) {
		DEBUG(__FUNCTION__, "out of memory, could not create "
			"port record\n");
		return STATUS_ERR;
	}

	tmp_port->low = 0;
	tmp_port->high = 0;
	tmp_port->proto = SEPOL_PROTO_UDP;
	tmp_port->con = NULL;
	*port = tmp_port;	

	return STATUS_SUCCESS;
}

/* Deep copy clone */
int sepol_port_clone(sepol_port_t port, sepol_port_t* port_ptr) {

	sepol_port_t new_port = NULL;
	if (sepol_port_create(&new_port) < 0)
		goto err;

	new_port->low = port->low;
	new_port->high = port->high;
	new_port->proto = port->proto;

	if (port->con && 
	   (sepol_context_clone(port->con, &new_port->con) < 0))
		goto err;	

	*port_ptr = new_port;
	return STATUS_SUCCESS;

	err:
	DEBUG(__FUNCTION__, "could not clone port record\n");
	sepol_port_free(new_port);
	return STATUS_ERR;
}

/* Destroy */
void sepol_port_free(sepol_port_t port) {
	if (!port)
		return;
	
	sepol_context_free(port->con);
	free(port);
}

/* Context */
sepol_context_t sepol_port_get_con(sepol_port_t port) {
	return port->con;
}

int sepol_port_set_con(sepol_port_t port, sepol_context_t con) {
	port->con = con;
	return STATUS_SUCCESS;
}

#include <sepol/policydb.h>
#include <sepol/context_record.h>

/* High level representation of an interface */
typedef struct sepol_iface {
        const char* name;
        sepol_context_t netif_con;
        sepol_context_t netmsg_con;
} sepol_iface_t;

/* Create a low level interface structure from
 * a high level representation */
extern int sepol_iface_create(
	policydb_t* policydb,
	ocontext_t** iface,
	sepol_iface_t* data);

/* Get the current context mapping for this interface */
extern int sepol_iface_get_context(
	policydb_t* policydb,
	sepol_iface_t* data,
	char** ifcon_str, size_t* ifcon_str_len,
	char** msgcon_str, size_t* msgcon_str_len);

/* Load an interface into policy */
extern int sepol_iface_load(
	policydb_t* policydb,
	sepol_iface_t* data);

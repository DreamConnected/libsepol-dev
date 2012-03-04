#ifndef _SEPOL_PORT_RECORD_H_
#define _SEPOL_PORT_RECORD_H_ 

#include <sepol/context_record.h>

struct sepol_port;
struct sepol_port_key;
typedef struct sepol_port* sepol_port_t;
typedef struct sepol_port_key* sepol_port_key_t;

#define SEPOL_PROTO_UDP 0
#define SEPOL_PROTO_TCP 1

/* Key */
extern int sepol_port_compare(
	sepol_port_t port, 
	sepol_port_key_t key);

extern int sepol_port_key_create(
	int low, int high, int proto,
	sepol_port_key_t* key_ptr);

extern int sepol_port_key_extract(
	sepol_port_t port, 
	sepol_port_key_t* key_ptr);

extern void sepol_port_key_free(
	sepol_port_key_t key);

/* Protocol */
extern int sepol_port_get_proto(sepol_port_t port);
extern int sepol_port_set_proto(sepol_port_t port, int proto);
extern const char* sepol_port_get_proto_str(sepol_port_t port);

/* Port */
extern int sepol_port_get_low(sepol_port_t port);
extern int sepol_port_get_high(sepol_port_t port);
extern int sepol_port_set_port(sepol_port_t port, int port_num);
extern int sepol_port_set_range(sepol_port_t port, int low, int high);

/* Context */
extern sepol_context_t sepol_port_get_con(sepol_port_t port);
extern int sepol_port_set_con(sepol_port_t port, sepol_context_t con);

/* Create/Clone/Destroy */
extern int sepol_port_create(sepol_port_t* port_ptr);
extern int sepol_port_clone(sepol_port_t port, sepol_port_t* port_ptr);
extern void sepol_port_free(sepol_port_t port);

#endif

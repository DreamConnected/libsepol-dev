/* Authors: Jason Tang <jtang@tresys.com>
 *
 * Copyright (C) 2005 Tresys Technology, LLC
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

#ifndef AVRULE_BLOCK_H
#define AVRULE_BLOCK_H

#include <sepol/policydb.h>

extern avrule_block_t *avrule_block_create(void);
extern avrule_decl_t *avrule_decl_create(uint32_t decl_id);
extern void avrule_block_destroy(avrule_block_t *x);
extern void avrule_block_list_destroy(avrule_block_t *x);
extern avrule_decl_t *get_avrule_decl(policydb_t *p, uint32_t decl_id);
extern cond_list_t *get_decl_cond_list(policydb_t *p, 
	avrule_decl_t *decl, cond_list_t *cond);
extern int is_id_enabled(char *id, policydb_t *p, int symbol_table);
extern int is_perm_enabled(char *class_id, char *perm_id, policydb_t *p);

#endif

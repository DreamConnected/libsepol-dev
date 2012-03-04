/* Author: Karl MacMillan <kmacmillan@tresys.com>
 *
 * Copyright (C) 2004-2005 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
 
#ifndef _SEPOL_MODULE_H_
#define _SEPOL_MODULE_H_

#include <stdlib.h>

#include <sepol/policydb.h>
#include <sepol/conditional.h>

#define SEPOL_MODULE_PACKAGE_MAGIC 0xf97cff8e

typedef struct sepol_module_package {
	policydb_t	*policy;
	char 		*file_contexts;
	uint32_t	file_contexts_len;
} sepol_module_package_t;

 /* link a base module and an array of modules - base module is modified and will
 * contain the base policy and modules
 */ 
extern int sepol_module_package_init(sepol_module_package_t *p);
extern void sepol_module_package_destroy(sepol_module_package_t *p);
extern int sepol_link_packages(sepol_module_package_t *base,
                               sepol_module_package_t **modules, int num_modules,
                               int verbose, char *error_buf, size_t error_buf_size);
extern int sepol_module_package_read(sepol_module_package_t *mod, struct policy_file *file, int verbose);
extern int sepol_module_package_info(struct policy_file *file, int *type, char **name, char **version);
extern int sepol_module_package_write(sepol_module_package_t *p, struct policy_file *file);
extern int sepol_module_package_create(struct policy_file *policy, struct policy_file *fc, struct policy_file *file);

#endif

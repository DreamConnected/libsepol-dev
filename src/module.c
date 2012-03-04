/* Author: Karl MacMillan <kmacmillan@tresys.com>
 *         Jason Tang     <jtang@tresys.com>
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

#include <sepol/link.h>
#include <sepol/module.h>
#include "private.h"

#include <stdio.h>
#include <stdlib.h>

int sepol_module_package_init(sepol_module_package_t *p)
{
	memset(p, 0, sizeof(sepol_module_package_t));
	p->policy = (policydb_t*)calloc(1, sizeof(policydb_t));
	if (!p->policy)
		return -1;
	return 0;
}

/* Deallocates all memory associated with a module package, including
 * the pointer itself.  Does nothing if p is NULL.
 */
void sepol_module_package_destroy(sepol_module_package_t *p) {
        if (p == NULL) {
                return;
        }
        policydb_destroy(p->policy);
        free(p->file_contexts);
        free(p);
}

/* Append each of the file contexts from each module to the base
 * policy's file context.  'base_context' will be reallocated to a
 * larger size (and thus it is an in/out reference
 * variable). 'base_fc_len' is the length of base's file context; it
 * too is a reference variable.  Return 0 on success, -1 if out of
 * memory. */
static int link_file_contexts(sepol_module_package_t *base,
                              sepol_module_package_t **modules, int num_modules) {
        size_t fc_len;
        int i;
        char *s;

        fc_len = base->file_contexts_len;
        for (i = 0; i < num_modules; i++) {
        	fc_len += modules[i]->file_contexts_len;
        }

        if ((s = (char*)realloc(base->file_contexts, fc_len)) == NULL) {
                return -1;
        }
        base->file_contexts = s;
        for (i = 0; i < num_modules; i++) {
                memcpy(base->file_contexts + base->file_contexts_len,
                       modules[i]->file_contexts,
                       modules[i]->file_contexts_len);
                base->file_contexts_len += modules[i]->file_contexts_len;
        }
        return 0;
}


/* Links the module packages into the base.  Returns 0 on success, -1
 * if a requirement was not met, or -2 for all other errors. */
int sepol_link_packages(sepol_module_package_t *base,
                        sepol_module_package_t **modules, int num_modules,
                        int verbose, char *error_buf, size_t error_buf_size) {
        policydb_t **mod_pols = NULL;
        int i, retval;
        if ((mod_pols = calloc(num_modules, sizeof(*mod_pols))) == NULL) {
                if (error_buf != NULL) {
                        snprintf(error_buf, error_buf_size, "Out of memory!");
                }
                return -2;
        }
        for (i = 0; i < num_modules; i++) {
                mod_pols[i] = modules[i]->policy;
        }

        retval = link_modules(base->policy, mod_pols, num_modules,
                              verbose, error_buf, error_buf_size);
        free(mod_pols);
        if (retval == -3) {
                return -1;
        }
        else if (retval < 0) {
                return -2;
        }

        if (link_file_contexts(base, modules, num_modules) == -1) {
                if (error_buf != NULL) {
                        snprintf(error_buf, error_buf_size, "Out of memory!");
                }
                return -2;
        }
        return 0;
}


/* buf must be large enough - no checks are performed */
#define _read_helper_bufsize 512
static int read_helper(char *buf, struct policy_file *file, uint32_t bytes)
{
	uint32_t offset, nel, read_len;
	void *tmp;
	
	offset = 0;
	nel = bytes;
	
	while (nel) {
		if (nel < _read_helper_bufsize)
			read_len = nel;
		else
			read_len = _read_helper_bufsize;
		tmp = next_entry(file, read_len);
		if (!tmp)
			return -1;
		memcpy(&buf[offset], tmp, read_len);
		offset += read_len;
		nel -= read_len;
	}
	return 0;
}
 
int sepol_module_package_read(sepol_module_package_t *mod, struct policy_file *file, int verbose)
{
	uint32_t *buf;
	
	buf = next_entry(file, sizeof(uint32_t) * 2);
	if (!buf)
		return -1;
	if (le32_to_cpu(buf[0]) != SEPOL_MODULE_PACKAGE_MAGIC) {
		return -1;	
	}
	mod->file_contexts_len = le32_to_cpu(buf[1]);
	
	if (mod->file_contexts_len) {		
		mod->file_contexts = (char *)malloc(mod->file_contexts_len);
		if (!mod->file_contexts) {
			return -1;	
		}
		if (read_helper(mod->file_contexts, file, mod->file_contexts_len))
			return -1;
	}
	
	return policydb_read(mod->policy, file, verbose);	
}

int sepol_module_package_info(struct policy_file *file, int *type, char **name, char **version)
{
	uint32_t *buf, *buf2, len;
	
	buf = next_entry(file, sizeof(uint32_t) * 2);
	if (!buf)
		return -1;
	if (le32_to_cpu(buf[0]) != SEPOL_MODULE_PACKAGE_MAGIC) {
		return -1;	
	}
	
	/* skip file contexts */
	len = le32_to_cpu(buf[1]);
	if (len) {
		buf2 = malloc(len);
		if (!buf2) {
			return -1;	
		}
		if (read_helper((char*)buf2, file, len))
			return -1;
		free(buf2);
	}
	
	buf = next_entry(file, sizeof(uint32_t)* 2);
	if (!buf) {
		return -1;
	}
        if (le32_to_cpu(buf[0]) != POLICYDB_MOD_MAGIC) {
                return -1;
        }

	len = le32_to_cpu(buf[1]);
	if (len != strlen(POLICYDB_MOD_STRING)) {
		return -1;
	}
	
	/* skip id */
	buf = next_entry(file, len);
	if (!buf) {
		return -1;
	}
	
	buf = next_entry(file, sizeof(uint32_t)* 5);
	if (!buf)
		return -1;
	
	*type = le32_to_cpu(buf[0]);
	/* if base - we're done */
	if (*type == POLICY_BASE) {
		*name = NULL;
		*version = NULL;
		return 0;
	} else if (*type != POLICY_MOD) {
		return -1;	
	}
	
	/* read the name and version */
	buf = next_entry(file, sizeof(uint32_t));
        if (!buf)
                return -1;
        len = le32_to_cpu(buf[0]);
        buf = next_entry(file, len);
        if (!buf)
                return -1;
        *name = malloc(len + 1);
        if (!*name) {
                return -1;
        }
        memcpy(*name, buf, len);
        (*name)[len] = '\0';
        buf = next_entry(file, sizeof(uint32_t));
        if (!buf)
                return -1;
        len = le32_to_cpu(buf[0]);
        buf = next_entry(file, len);
        if (!buf)
                return -1;
        *version = malloc(len + 1);
        if (!*version)
                return -1;
        memcpy(*version, buf, len);
        (*version)[len] = '\0';
	
	return 0;
}

#define BUF_SIZE 2048
static int sepol_module_write_helper(struct policy_file *in, struct policy_file *out, int write_len)
{
	uint32_t buf[1], *buf2, len, len2;
	long start, end;
	
	if (in->type == PF_USE_MEMORY) {
		len = in->len;
	} else {
		/* get the length - this doesn't assume that the stream
		 * was at the beginning */
		if ((start = ftell(in->fp)) == -1)
			return -1;
		if (fseek(in->fp, 0, SEEK_END))
			return -1;
		if ((end = ftell(in->fp)) == -1)
			return -1;
		len = end - start;
		if (fseek(in->fp, start, SEEK_SET))
			return -1;
	}
	
	if (write_len) {
		buf[0] = cpu_to_le32(len);	
		if (put_entry(buf, sizeof(uint32_t), 1, out) != 1)
			return -1;
	}
	while (len) {
		if (len > BUF_SIZE)
			len2 = BUF_SIZE;
		else
			len2 = len;
		buf2 = next_entry(in, len2);
		if (!buf2) {
			return -1;
		}
		if (put_entry(buf2, 1, len2, out) != len2) {
			perror("error writing file");
			return -1;
		}
		len -= len2;
	}
	return 0;
}

int sepol_module_package_write(sepol_module_package_t *p, struct policy_file *file)
{
	uint32_t buf[1], len, len2, index;
		
	buf[0] = cpu_to_le32(SEPOL_MODULE_PACKAGE_MAGIC);
	if (put_entry(buf, sizeof(uint32_t), 1, file) != 1)
		return -1;
		
	buf[0] = cpu_to_le32(p->file_contexts_len);
	if (put_entry(buf, sizeof(uint32_t), 1, file) != 1)
		return -1;
		
	len = p->file_contexts_len;
	index = 0;
	while (len) {
		if (len > BUF_SIZE)
			len2 = BUF_SIZE;
		else
			len2 = len;

		if (put_entry(&p->file_contexts[index], 1, len2, file) != len2) {
			perror("error writing file");
			return -1;
		}
		len -= len2;
		index += len2;
	}
	
	return policydb_write(p->policy, file);
}

/* file must use stdio */
int sepol_module_package_create(struct policy_file *policy, struct policy_file *fc, struct policy_file *file)
{
	uint32_t buf[BUF_SIZE];

	
	if (!file->type == PF_USE_STDIO)
		return -1;
	
	buf[0] = cpu_to_le32(SEPOL_MODULE_PACKAGE_MAGIC);
	if (put_entry(buf, sizeof(uint32_t), 1, file) != 1)
		return -1;
		
	if (!fc) {
		buf[0] = cpu_to_le32(0);
		if (put_entry(buf, sizeof(uint32_t), 1, file) != 1)
			return -1;
	} else {	
		if (sepol_module_write_helper(fc, file, 1)) {
			return -1;
		}
	}
	if (sepol_module_write_helper(policy, file, 0)) {
		return -1;	
	}
	
	return 0;
}

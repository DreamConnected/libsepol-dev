/* Authors: Joshua Brindle <jbrindle@tresys.com>
 *              
 * Assertion checker for avtab entries, taken from 
 * checkpolicy.c by Steve Smalley
 *              
 * Copyright (C) 2005 Tresys Technology, LLC
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

#include <sepol/avtab.h>
#include <sepol/policydb.h>
#include <sepol/expand.h>


/* This isn't exactly the best place to put this but it will do 
   until something else needs it */
struct val_to_name {
	unsigned int val;
	char *name;
};

static int perm_name(hashtab_key_t key, hashtab_datum_t datum, void *data)
{       
        struct val_to_name *v = data;
        perm_datum_t *perdatum;
                
        perdatum = (perm_datum_t *) datum;

        if (v->val == perdatum->value) {
                v->name = key;
                return 1;
        }       
        
        return 0;
}       
   
static char *av_to_string(policydb_t *policydbp, uint32_t tclass, sepol_access_vector_t av)
{               
        struct val_to_name v;
        static char avbuf[1024];
        class_datum_t *cladatum;
        char *perm = NULL, *p;
        unsigned int i;
        int rc; 
                
        cladatum = policydbp->class_val_to_struct[tclass-1];
        p = avbuf;
        for (i = 0; i < cladatum->permissions.nprim; i++) {
                if (av & (1 << i)) {
                        v.val = i+1;
                        rc = hashtab_map(cladatum->permissions.table,
                                         perm_name, &v);
                        if (!rc && cladatum->comdatum) {
                                rc = hashtab_map(
                                        cladatum->comdatum->permissions.table,
                                        perm_name, &v);
                        }
                        if (rc)
                                perm = v.name;
                        if (perm) {
                                sprintf(p, " %s", perm);
                                p += strlen(p);
                        }
                }
        }

        return avbuf;
}

/* These should probably return the error to the caller but it may get very long
   when there are lots of assertion violations, may try to fix this later */
static int check_assertion_helper(policydb_t *p, 
				  avtab_t *te_avtab, avtab_t *te_cond_avtab,
				  unsigned int stype, unsigned int ttype,
				  class_perm_node_t *perm, unsigned long line)
{
        avtab_key_t avkey;
	avtab_ptr_t node;
        class_perm_node_t *curperm;

	for (curperm = perm; curperm != NULL; curperm = curperm->next) { 
		avkey.source_type = stype + 1;
		avkey.target_type = ttype + 1;
                avkey.target_class = curperm->class;
		avkey.specified = AVTAB_ALLOWED;
		for (node = avtab_search_node(te_avtab, &avkey);
		     node != NULL;
		     node = avtab_search_node_next(node, avkey.specified)) {
			if (node->datum.data & curperm->data)
				goto err;
		}
		for (node = avtab_search_node(te_cond_avtab, &avkey);
		     node != NULL;
		     node = avtab_search_node_next(node, avkey.specified)) {
			if (node->datum.data & curperm->data)
				goto err;
		}
	}

        return 0;

err:
	fprintf(stderr, "assertion on line %lu violated by allow %s %s:%s {%s };\n",
		line, p->p_type_val_to_name[stype], p->p_type_val_to_name[ttype],
		p->p_class_val_to_name[curperm->class - 1],
		av_to_string(p, curperm->class, node->datum.data & curperm->data));
	return -1;
}

int check_assertions(policydb_t *p, avrule_t *avrules)
{
        avrule_t *a;
	avtab_t te_avtab, te_cond_avtab;
	ebitmap_node_t *snode, *tnode;
        unsigned int i, j;
	int errors = 0;

	if (avrules) {
		if (avtab_init(&te_avtab))
			goto oom;
		if (avtab_init(&te_cond_avtab)) {
			avtab_destroy(&te_avtab);
			goto oom;
		}
		if (expand_avtab(p, &p->te_avtab, &te_avtab) ||
		    expand_avtab(p, &p->te_cond_avtab, &te_cond_avtab)) {
			avtab_destroy(&te_avtab);
			avtab_destroy(&te_cond_avtab);
			goto oom;
		}
	}

	for (a = avrules; a != NULL; a = a->next) {
		ebitmap_t *stypes = &a->stypes.types;
		ebitmap_t *ttypes = &a->ttypes.types;

                if (!(a->specified & AVRULE_NEVERALLOW))
       			continue; 

		/* The assertions pretty much have to be pre-expanded since we no 
		   longer have access to attributes and such */
			
		ebitmap_for_each_bit(stypes, snode, i) {
                        if (!ebitmap_node_get_bit(snode, i))
                                continue;
                        if (a->flags & RULE_SELF) {
				if (check_assertion_helper(p, &te_avtab, &te_cond_avtab, i, i, a->perms, a->line))
                                        errors++;
                        }
			ebitmap_for_each_bit(ttypes, tnode, j) {
                                if (!ebitmap_node_get_bit(tnode, j))
                                        continue;
                                if (check_assertion_helper(p, &te_avtab, &te_cond_avtab, i, j, a->perms, a->line))
                                    errors++;
                        }
                }
        }

	if (errors) {
		fprintf(stderr, "%d assertion violations occured\n", errors);
		avtab_destroy(&te_avtab);
		avtab_destroy(&te_cond_avtab);
		return -1;
	}

	avtab_destroy(&te_avtab);
	avtab_destroy(&te_cond_avtab);
        return 0;

oom:
    fprintf(stderr, "Out of memory - unable to check assertions\n");	
    return -1;
}

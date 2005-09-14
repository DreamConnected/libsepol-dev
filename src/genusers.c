#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#include <sepol/policydb.h>
#include <sepol/mls.h>
#include <stdarg.h>

#include "debug.h"
#include "private.h"

static int gdebug=1;

void sepol_debug(int on) { 
	gdebug=on; 

	/* New debug system */
	sepol_debug_compat(on);
};

#ifdef __GNUC__
__attribute__ ((format (printf, 1, 2)))
#endif
void __sepol_debug_printf(const char *fmt, ...) {
	if (gdebug) {
		va_list ap;
		va_start(ap, fmt);
		vfprintf (stderr, fmt, ap);
		va_end(ap);
	}
}

extern int selinux_delusers;

#undef BADLINE
#define BADLINE() { \
	__sepol_debug_printf("%s:  invalid entry %s on line %u\n", \
		path, buffer, lineno); \
	continue; \
}

static int load_users(struct policydb *policydb, const char *path) {
	FILE *fp;
	char *buffer = NULL, *p, *q, oldc;
	size_t len = 0;
	ssize_t nread;
	int rc;
	unsigned lineno = 0, islist = 0, bit;
	user_datum_t *usrdatum;
	role_datum_t *roldatum;
	ebitmap_node_t *rnode;

	fp = fopen(path,"r");
	if (fp == NULL) 
		return -1;
	__fsetlocking(fp, FSETLOCKING_BYCALLER);

        while ((nread = getline(&buffer, &len, fp)) > 0) {
		lineno++;
		if (buffer[nread - 1] == '\n')
			buffer[nread - 1] = 0;
		p = buffer;
		while (*p && isspace(*p))
			p++;
		if (!(*p) || *p == '#')
			continue;

		if (strncasecmp(p, "user", 4))
			BADLINE();
		p += 4;
		if (!isspace(*p))
			BADLINE();
		while (*p && isspace(*p))
			p++;
		if (!(*p))
			BADLINE();
		q = p;
		while (*p && !isspace(*p)) 
			p++;
		if (!(*p)) 
			BADLINE();
		*p++ = 0;

		usrdatum = hashtab_search(policydb->p_users.table, q);
		if (usrdatum) {
			/* Replacing an existing user definition. */
			ebitmap_destroy(&usrdatum->roles.roles);
			ebitmap_init(&usrdatum->roles.roles);
			usrdatum->defined = 1;
		} else {
			char *id = strdup(q);
			
			/* Adding a new user definition. */
			usrdatum = (user_datum_t *) malloc(sizeof(user_datum_t));
			if (!id || !usrdatum) {
				__sepol_debug_printf("%s:  out of memory for %s on line %u\n",
					path, buffer, lineno);
				errno = ENOMEM;
				free(buffer);
				fclose(fp);
				return -1;
			}
			memset(usrdatum, 0, sizeof(user_datum_t));
			usrdatum->value = ++policydb->p_users.nprim;
			ebitmap_init(&usrdatum->roles.roles);
			usrdatum->defined = 1;
			rc = hashtab_insert(policydb->p_users.table,
					    id, (hashtab_datum_t) usrdatum);
			if (rc) {
				__sepol_debug_printf("%s:  out of memory for %s on line %u\n",
					path, buffer, lineno);
				errno = ENOMEM;
				free(buffer);
				fclose(fp);
				return -1;
			}
		}

		while (*p && isspace(*p))
			p++;
		if (!(*p))
			BADLINE();
		if (strncasecmp(p, "roles", 5))
			BADLINE();
		p += 5;
		if (!isspace(*p))
			BADLINE();
		while (*p && isspace(*p))
			p++;
		if (!(*p))
			BADLINE();
		if (*p == '{') {
			islist = 1;
			p++;
		} else 
			islist = 0;

		do { 
			while (*p && isspace(*p))
				p++;
			if (!(*p))
				BADLINE();

			q = p;
			while (*p && *p != ';' && *p != '}' && !isspace(*p)) 
				p++;
			if (!(*p)) 
				BADLINE();
			if (*p == '}') 
				islist = 0;
			oldc = *p;
			*p++ = 0;
			if (!q[0])
				break;

			roldatum = hashtab_search(policydb->p_roles.table, q);
			if (!roldatum) {
				__sepol_debug_printf("%s:  undefined role %s in %s on line %u\n",
					path, q, buffer, lineno);
				continue;
			}
			/* Set the role and every role it dominates */
			ebitmap_for_each_bit(&roldatum->dominates, rnode, bit) {
				if (ebitmap_node_get_bit(rnode, bit))
					if (ebitmap_set_bit(&usrdatum->roles.roles, bit, 1)) {
						__sepol_debug_printf("%s:  out of memory for %s on line %u\n",
							path, buffer, lineno);
						errno = ENOMEM;
						free(buffer);
						fclose(fp);
						return -1;
					}
			}
		} while (islist);

		if (mls_enabled) {
			context_struct_t context;
			char *scontext, *r, *s;

			while (*p && isspace(*p))
				p++;
			if (!(*p))
				BADLINE();
			if (strncasecmp(p, "level", 5))
				BADLINE();
			p += 5;
			if (!isspace(*p))
				BADLINE();
			while (*p && isspace(*p))
				p++;
			if (!(*p))
				BADLINE();
			q = p;
			while (*p && strncasecmp(p, "range", 5))
				p++;
			if (!(*p)) 
				BADLINE();
			*--p = 0;
			p++;

			scontext = malloc(p - q);
			if (!scontext) {
				__sepol_debug_printf("%s:  out of memory for %s on line %u\n",
					path, buffer, lineno);
				errno = ENOMEM;
				free(buffer);
				fclose(fp);
				return -1;
			}
			r = scontext;
			s = q;
			while (*s) {
				if (!isspace(*s))
					*r++ = *s;
				s++;
			}
			*r = 0;
			r = scontext;

			context_init(&context);
			rc = mls_context_to_sid(policydb, oldc, &r, &context);
			if (rc) {
				__sepol_debug_printf("%s:  invalid level %s in %s on line %u\n",
					path, scontext, buffer, lineno);
				free(scontext);
				continue;

			}
			free(scontext);
			memcpy(&usrdatum->dfltlevel, &context.range.level[0], sizeof(usrdatum->dfltlevel));

			if (strncasecmp(p, "range", 5))
				BADLINE();
			p += 5;
			if (!isspace(*p))
				BADLINE();
			while (*p && isspace(*p))
				p++;
			if (!(*p))
				BADLINE();
			q = p;
			while (*p && *p != ';')
				p++;
			if (!(*p)) 
				BADLINE();
			*p++ = 0;

			scontext = malloc(p - q);
			if (!scontext) {
				__sepol_debug_printf("%s:  out of memory for %s on line %u\n",
					path, buffer, lineno);
				errno = ENOMEM;
				free(buffer);
				fclose(fp);
				return -1;
			}
			r = scontext;
			s = q;
			while (*s) {
				if (!isspace(*s))
					*r++ = *s;
				s++;
			}
			*r = 0;
			r = scontext;

			context_init(&context);
			rc = mls_context_to_sid(policydb, oldc, &r, &context);
			if (rc) {
				__sepol_debug_printf("%s:  invalid range %s in %s on line %u\n",
					path, scontext, buffer, lineno);
				free(scontext);
				continue;
			}
			free(scontext);
			memcpy(&usrdatum->range, &context.range, sizeof(usrdatum->range));
		}
	}

	free(buffer);
	fclose(fp);
	return 0;
}

/* Select users for removal based on whether they were defined in the
   new users configuration. */
static int select_user(hashtab_key_t key __attribute__ ((unused)), hashtab_datum_t datum, void *datap __attribute__ ((unused)))
{
	user_datum_t *usrdatum = datum;
	
	if (!usrdatum->defined)
		return 1;
	return 0;
}

struct kill_user_data {
	struct policydb *policydb;
	ebitmap_t *free_users;
};

/* Kill the user entries selected by select_user, and
   record that their slots are free. */
static void kill_user(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	user_datum_t *usrdatum;
	struct kill_user_data *kud = p;
	struct policydb *pol = kud->policydb;
	ebitmap_t *free_users = kud->free_users;

	if (key)
		free(key);

	usrdatum = (user_datum_t *) datum;
	ebitmap_set_bit(free_users, usrdatum->value - 1, 1);

	ebitmap_destroy(&usrdatum->roles.roles);
	free(datum);
	pol->p_users.nprim--;
}

/* Fold user values down to avoid holes generated by removal.
   As the SID table is remapped by the kernel upon a policy reload,
   this is safe for existing SIDs.  But it could be a problem for
   constraints if they refer to the particular user.  */
static int remap_users(hashtab_key_t key __attribute__ ((unused)), hashtab_datum_t datum, void *p)
{
	user_datum_t *usrdatum = datum;
	struct kill_user_data *kud = p;
	struct policydb *pol = kud->policydb;
	ebitmap_t *free_users = kud->free_users;
	ebitmap_node_t *node;
	unsigned int i;

	if (usrdatum->value > pol->p_users.nprim) {
		ebitmap_for_each_bit(free_users, node, i) {
			if (ebitmap_node_get_bit(node, i)) {
				usrdatum->value = i+1;
				ebitmap_set_bit(free_users, i, 0);
				return 0;
			}
		}
	}
	return 0;
}

int sepol_genusers(void *data, size_t len,
		   const char *usersdir,
		   void **newdata, size_t *newlen)
{
	struct policydb policydb;
	struct ebitmap free_users;
	struct kill_user_data kud;
	char path[PATH_MAX];

	/* Construct policy database */
	if (policydb_from_image(data, len, &policydb) < 0)
		goto err;

	/* Load base set of system users from the policy package. */
	snprintf(path, sizeof path, "%s/system.users", usersdir);
	if (load_users(&policydb, path) < 0) {
		__sepol_debug_printf("%s: Can't load system.users:  %s\n",
				     __FUNCTION__, strerror(errno));
		goto err_destroy;
	}

	/* Load locally defined users. */
	snprintf(path, sizeof path, "%s/local.users", usersdir);
	if (load_users(&policydb, path) < 0) {
		__sepol_debug_printf("%s:  Can't load local.users:  %s\n",
				     __FUNCTION__, strerror(errno));
		goto err_destroy;
	}

	if (selinux_delusers) {
		/* Kill unused users and remap to avoid holes. */
		ebitmap_init(&free_users);
		kud.policydb = &policydb;
		kud.free_users = &free_users;
		hashtab_map_remove_on_error(policydb.p_users.table, select_user, kill_user, &kud);
		hashtab_map(policydb.p_users.table, remap_users, &kud);
		ebitmap_destroy(&free_users);
	}

	/* Write policy database */
	if (policydb_to_image(&policydb, newdata, newlen) < 0)
		goto err_destroy;

	policydb_destroy(&policydb);
	return 0;

	err_destroy:
	policydb_destroy(&policydb);

	err:
	return -1;
}

int sepol_genusers_policydb(policydb_t *policydb,
			    const char *usersdir)
{
	char path[PATH_MAX];

	/* Load base set of system users from the policy package. */
	snprintf(path, sizeof path, "%s/system.users", usersdir);
	if (load_users(policydb, path) < 0) {
		__sepol_debug_printf("%s: Can't load system.users:  %s\n",
				     __FUNCTION__, strerror(errno));
		return -1;
	}

	/* Load locally defined users. */
	snprintf(path, sizeof path, "%s/local.users", usersdir);
	if (load_users(policydb, path) < 0) {
		__sepol_debug_printf("%s:  Can't load local.users:  %s\n",
				     __FUNCTION__, strerror(errno));
		return -1;
	}

	if (policydb_reindex_users(policydb) < 0) {
		__sepol_debug_printf("%s:  Can't reindex users:  %s\n",
				     __FUNCTION__, strerror(errno));
		return -1;

	}

	return 0;
}

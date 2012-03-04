
/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */
/*
 * Updated: Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 *
 *	Support for enhanced MLS infrastructure.
 *
 * Copyright (C) 2004-2005 Trusted Computer Solutions, Inc.
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

/* FLASK */

/* 
 * Implementation of the multi-level security (MLS) policy.
 */

#include <sepol/mls.h>
#include <sepol/policydb.h>
#include <sepol/services.h>
#include <sepol/flask.h>

#include <stdlib.h>

#include "private.h"

/*
 * Return the length in bytes for the MLS fields of the
 * security context string representation of `context'.
 */
int mls_compute_context_len(policydb_t *policydb, context_struct_t * context)
{
	int i, l, len, range;

	if (!mls_enabled)
		return 0;

	len = 1; /* for the beginning ":" */
	for (l = 0; l < 2; l++) {
		range = 0;
		len += strlen(policydb->p_sens_val_to_name[context->range.level[l].sens - 1]);

		for (i = 1; i <= ebitmap_length(&context->range.level[l].cat); i++) {
			if (ebitmap_get_bit(&context->range.level[l].cat, i - 1)) {
				if (range) {
					range++;
					continue;
				}

				len += strlen(policydb->p_cat_val_to_name[i - 1]) + 1;
				range++;
			} else {
				if (range > 1)
					len += strlen(policydb->p_cat_val_to_name[i - 2]) + 1;
				range = 0;
			}
		}
		/* Handle case where last category is the end of range */
		if (range > 1)
			len += strlen(policydb->p_cat_val_to_name[i - 2]) + 1;

		if (l == 0) {
			if (mls_level_eq(&context->range.level[0],
			                 &context->range.level[1]))
				break;
			else
				len++;
		}
	}

	return len;
}


/*
 * Write the security context string representation of
 * the MLS fields of `context' into the string `*scontext'.
 * Update `*scontext' to point to the end of the MLS fields.
 */
void mls_sid_to_context(policydb_t *policydb,
                        context_struct_t * context,
                        char **scontext)
{
	char *scontextp;
	int i, l, range, wrote_sep;

	if (!mls_enabled)
		return;

	scontextp = *scontext;

	*scontextp = ':';
	scontextp++;

	for (l = 0; l < 2; l++) {
		range = 0;
		wrote_sep = 0;
		strcpy(scontextp,
		       policydb->p_sens_val_to_name[context->range.level[l].sens - 1]);
		scontextp += strlen(policydb->p_sens_val_to_name[context->range.level[l].sens - 1]);
		/* categories */
		for (i = 1; i <= ebitmap_length(&context->range.level[l].cat); i++) {
			if (ebitmap_get_bit(&context->range.level[l].cat, i - 1)) {
				if (range) {
					range++;
					continue;
				}

				if (!wrote_sep) {
					*scontextp++ = ':';
					wrote_sep = 1;
				} else
					*scontextp++ = ',';
				strcpy(scontextp, policydb->p_cat_val_to_name[i - 1]);
				scontextp += strlen(policydb->p_cat_val_to_name[i - 1]);
				range++;
			} else {
				if (range > 1) {
					if (range > 2)
						*scontextp++ = '.';
					else
						*scontextp++ = ',';

					strcpy(scontextp, policydb->p_cat_val_to_name[i - 2]);
					scontextp += strlen(policydb->p_cat_val_to_name[i - 2]);
				}
				range = 0;
			}
		}
		/* Handle case where last category is the end of range */
		if (range > 1) {
			if (range > 2)
				*scontextp++ = '.';
			else
				*scontextp++ = ',';

			strcpy(scontextp, policydb->p_cat_val_to_name[i - 2]);
			scontextp += strlen(policydb->p_cat_val_to_name[i - 2]);
		}

		if (l == 0) {
			if (mls_level_eq(&context->range.level[0],
			                 &context->range.level[1]))
				break;
			else {
				*scontextp = '-';
				scontextp++;
			}
		}
	}

	*scontext = scontextp;
	return;
}

/*
 * Return 1 if the MLS fields in the security context
 * structure `c' are valid.  Return 0 otherwise.
 */
int mls_context_isvalid(policydb_t *p, context_struct_t * c)
{
	level_datum_t *levdatum;
	user_datum_t *usrdatum;
	int i, l;

	if (!mls_enabled)
		return 1;

	/*
	 * MLS range validity checks: high must dominate low, low level must
	 * be valid (category set <-> sensitivity check), and high level must
	 * be valid (category set <-> sensitivity check)
	 */
	if (!mls_level_dom(&c->range.level[1], &c->range.level[0]))
		/* High does not dominate low. */
		return 0;

	for (l = 0; l < 2; l++) {
		if (!c->range.level[l].sens || c->range.level[l].sens > p->p_levels.nprim)
			return 0;
		levdatum = (level_datum_t *)hashtab_search(p->p_levels.table,
			p->p_sens_val_to_name[c->range.level[l].sens - 1]);
		if (!levdatum)
			return 0;

		for (i = 1; i <= ebitmap_length(&c->range.level[l].cat); i++) {
			if (ebitmap_get_bit(&c->range.level[l].cat, i - 1)) {
				if (i > p->p_cats.nprim)
					return 0;
				if (!ebitmap_get_bit(&levdatum->level->cat, i - 1))
					/*
					 * Category may not be associated with
					 * sensitivity in low level.
					 */
					return 0;
			}
		}
	}

	if (c->role == OBJECT_R_VAL)
		return 1;

	/*
	 * User must be authorized for the MLS range.
	 */
	if (!c->user || c->user > p->p_users.nprim)
		return 0;
	usrdatum = p->user_val_to_struct[c->user - 1];
	if (!mls_range_contains(usrdatum->range, c->range))
		return 0; /* user may not be associated with range */

	return 1;
}

/*
 * Set the MLS fields in the security context structure
 * `context' based on the string representation in
 * the string `*scontext'.  Update `*scontext' to
 * point to the end of the string representation of
 * the MLS fields.
 *
 * This function modifies the string in place, inserting
 * NULL characters to terminate the MLS fields.
 */
int mls_context_to_sid(policydb_t *policydb,
		       char oldc,
		       char **scontext,
		       context_struct_t * context)
{

	char delim;
	char *scontextp, *p, *rngptr;
	level_datum_t *levdatum;
	cat_datum_t *catdatum, *rngdatum;
	int l, rc = -EINVAL;

	if (!mls_enabled)
		return 0;

	/* No MLS component to the security context */
	if (!oldc)
		goto out;

	/* Extract low sensitivity. */
	scontextp = p = *scontext;
	while (*p && *p != ':' && *p != '-')
		p++;

	delim = *p;
	if (delim != 0)
		*p++ = 0;

	for (l = 0; l < 2; l++) {
		levdatum = (level_datum_t *)hashtab_search(policydb->p_levels.table,
					      (hashtab_key_t)scontextp);

		if (!levdatum) {
			rc = -EINVAL;
			goto out;
		}

		context->range.level[l].sens = levdatum->level->sens;

		if (delim == ':') {
			/* Extract category set. */
			while (1) {
				scontextp = p;
				while (*p && *p != ',' && *p != '-')
					p++;
				delim = *p;
				if (delim != 0)
					*p++ = 0;

				/* Separate into range if exists */
				if ((rngptr = strchr(scontextp, '.')) != NULL) {
					/* Remove '.' */
					*rngptr++ = 0;
				}

				catdatum = (cat_datum_t *)hashtab_search(policydb->p_cats.table,
					      (hashtab_key_t)scontextp);

				if (!catdatum) {
					rc = -EINVAL;
					goto out;
				}

				rc = ebitmap_set_bit(&context->range.level[l].cat,
				                     catdatum->value - 1, 1);
				if (rc)
					goto out;

				/* If range, set all categories in range */
				if (rngptr) {
					int i;

					rngdatum = (cat_datum_t *)hashtab_search(policydb->p_cats.table, (hashtab_key_t)rngptr);
					if (!rngdatum) {
						rc = -EINVAL;
						goto out;
					}

					if (catdatum->value >= rngdatum->value) {
						rc = -EINVAL;
						goto out;
					}

					for (i = catdatum->value; i < rngdatum->value; i++) {
						rc = ebitmap_set_bit(&context->range.level[l].cat, i, 1);
						if (rc)
							goto out;
					}
				}

				if (delim != ',')
					break;
			}
		}
		if (delim == '-') {
			/* Extract high sensitivity. */
			scontextp = p;
			while (*p && *p != ':')
				p++;

			delim = *p;
			if (delim != 0)
				*p++ = 0;
		} else
			break;
	}

	if (l == 0) {
		context->range.level[1].sens = context->range.level[0].sens;
		rc = ebitmap_cpy(&context->range.level[1].cat,
				 &context->range.level[0].cat);
		if (rc)
			goto out;
	}
	*scontext = ++p;
	rc = 0;
out:
	return rc;
}

/*
 * Copies the MLS range from `src' into `dst'.
 */
static inline int mls_copy_context(context_struct_t * dst,
				   context_struct_t * src)
{
	int l, rc = 0;

	/* Copy the MLS range from the source context */
	for (l = 0; l < 2; l++) {
		dst->range.level[l].sens = src->range.level[l].sens;
		rc = ebitmap_cpy(&dst->range.level[l].cat,
				 &src->range.level[l].cat);
		if (rc)
			break;
	}

	return rc;
}

/*
 * Copies the effective MLS range from `src' into `dst'.
 */
static inline int mls_scopy_context(context_struct_t *dst,
				    context_struct_t *src)
{
	int l, rc = 0;

	/* Copy the MLS range from the source context */
	for (l = 0; l < 2; l++) {
		dst->range.level[l].sens = src->range.level[0].sens;
		rc = ebitmap_cpy(&dst->range.level[l].cat,
				 &src->range.level[0].cat);
		if (rc)
			break;
	}

	return rc;
}

/*
 * Copies the MLS range `range' into `context'.
 */
static inline int mls_range_set(context_struct_t *context, mls_range_t *range)
{
	int l, rc = 0;

	/* Copy the MLS range into the  context */
	for (l = 0; l < 2; l++) {
		context->range.level[l].sens = range->level[l].sens;
		rc = ebitmap_cpy(&context->range.level[l].cat,
				 &range->level[l].cat);
		if (rc)
			break;
	}

	return rc;
}

int mls_setup_user_range(context_struct_t *fromcon, user_datum_t *user,
                         context_struct_t *usercon)
{
	if (mls_enabled) {
		mls_level_t *fromcon_sen = &(fromcon->range.level[0]);
		mls_level_t *fromcon_clr = &(fromcon->range.level[1]);
		mls_level_t *user_low = &(user->range.level[0]);
		mls_level_t *user_clr = &(user->range.level[1]);
		mls_level_t *user_def = &(user->dfltlevel);
		mls_level_t *usercon_sen = &(usercon->range.level[0]);
		mls_level_t *usercon_clr = &(usercon->range.level[1]);

		/* Honor the user's default level if we can */
		if (mls_level_between(user_def, fromcon_sen, fromcon_clr)) {
			*usercon_sen = *user_def;
		} else if (mls_level_between(fromcon_sen, user_def, user_clr)) {
			*usercon_sen = *fromcon_sen;
		} else if (mls_level_between(fromcon_clr, user_low, user_def)) {
			*usercon_sen = *user_low;
		} else
			return -EINVAL;

		/* Lower the clearance of available contexts
		   if the clearance of "fromcon" is lower than
		   that of the user's default clearance (but
		   only if the "fromcon" clearance dominates
		   the user's computed sensitivity level) */
		if (mls_level_dom(user_clr, fromcon_clr)) {
			*usercon_clr = *fromcon_clr;
		} else if (mls_level_dom(fromcon_clr, user_clr)) {
			*usercon_clr = *user_clr;
		} else
			return -EINVAL;
	}

	return 0;
}

/*
 * Convert the MLS fields in the security context
 * structure `c' from the values specified in the
 * policy `oldp' to the values specified in the policy `newp'.
 */
int mls_convert_context(policydb_t * oldp,
			policydb_t * newp,
			context_struct_t * c)
{
	level_datum_t *levdatum;
	cat_datum_t *catdatum;
	ebitmap_t bitmap;
	int l, i;

	if (!mls_enabled)
		return 0;

	for (l = 0; l < 2; l++) {
		levdatum = (level_datum_t *) hashtab_search(
						    newp->p_levels.table,
		   oldp->p_sens_val_to_name[c->range.level[l].sens - 1]);

		if (!levdatum)
			return -EINVAL;
		c->range.level[l].sens = levdatum->level->sens;

		ebitmap_init(&bitmap);
		for (i = 1; i <= ebitmap_length(&c->range.level[l].cat); i++) {
			if (ebitmap_get_bit(&c->range.level[l].cat, i - 1)) {
				int rc;

				catdatum = (cat_datum_t *) hashtab_search(newp->p_cats.table,
					 oldp->p_cat_val_to_name[i - 1]);
				if (!catdatum)
					return -EINVAL;
				rc = ebitmap_set_bit(&bitmap, catdatum->value - 1, 1);
				if (rc)
					return rc;
			}
		}
		ebitmap_destroy(&c->range.level[l].cat);
		c->range.level[l].cat = bitmap;
	}

	return 0;
}

int mls_compute_sid(policydb_t *policydb,
		    context_struct_t *scontext,
		    context_struct_t *tcontext,
		    sepol_security_class_t tclass,
		    uint32_t specified,
		    context_struct_t *newcontext)
{
	if (!mls_enabled)
		return 0;

	switch (specified) {
	case AVTAB_TRANSITION:
		if (tclass == SECCLASS_PROCESS) {
			range_trans_t *rangetr;

			/* Look for a range transition rule. */
			for (rangetr = policydb->range_tr; rangetr;
			     rangetr = rangetr->next) {
				if (rangetr->dom == scontext->type &&
				    rangetr->type == tcontext->type) {
					/* Set the range from the rule */
					return mls_range_set(newcontext,
					                     &rangetr->range);
				}
			}
		}
		/* Fallthrough */
	case AVTAB_CHANGE:
		if (tclass == SECCLASS_PROCESS)
			/* Use the process MLS attributes. */
			return mls_copy_context(newcontext, scontext);
		else
			/* Use the process effective MLS attributes. */
			return mls_scopy_context(newcontext, scontext);
	case AVTAB_MEMBER:
		/* Only polyinstantiate the MLS attributes if
		   the type is being polyinstantiated */
		if (newcontext->type != tcontext->type) {
			/* Use the process effective MLS attributes. */
			return mls_scopy_context(newcontext, scontext);
		} else {
			/* Use the related object MLS attributes. */
			return mls_copy_context(newcontext, tcontext);
		}
	default:
		return -EINVAL;
	}
	return -EINVAL;
}

/* FLASK */


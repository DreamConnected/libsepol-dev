
/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */
/*
 * Updated: Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 *
 *	Support for enhanced MLS infrastructure.
 *
 * Copyright (C) 2004-2005 Trusted Computer Solutions, Inc.
 */

/* FLASK */

/*
 * Multi-level security (MLS) policy operations.
 */

#ifndef _MLS_H_
#define _MLS_H_

#include <sepol/context.h>
#include <sepol/policydb.h>

int mls_compute_context_len(policydb_t *policydb,
			    context_struct_t * context);

void mls_sid_to_context(policydb_t *policydb,
                        context_struct_t *context,
                        char **scontext);

int mls_context_isvalid(policydb_t *p, context_struct_t * c);

int mls_context_to_sid(policydb_t *policydb,
		       char oldc,
	               char **scontext,
		       context_struct_t * context);

int mls_convert_context(policydb_t * oldp,
			policydb_t * newp,
			context_struct_t * context);

int mls_compute_sid(policydb_t *policydb,
		    context_struct_t *scontext,
		    context_struct_t *tcontext,
		    security_class_t tclass,
		    uint32_t specified,
		    context_struct_t *newcontext);

int mls_setup_user_range(context_struct_t *fromcon, user_datum_t *user,
                         context_struct_t *usercon);

#endif	/* _MLS_H_ */


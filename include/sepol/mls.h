
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
		    sepol_security_class_t tclass,
		    uint32_t specified,
		    context_struct_t *newcontext);

int mls_setup_user_range(context_struct_t *fromcon, user_datum_t *user,
                         context_struct_t *usercon);

#endif	/* _MLS_H_ */



/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */

/* FLASK */

/*
 * A security context is a set of security attributes
 * associated with each subject and object controlled
 * by the security policy.  Security contexts are
 * externally represented as variable-length strings
 * that can be interpreted by a user or application
 * with an understanding of the security policy. 
 * Internally, the security server uses a simple
 * structure.  This structure is private to the
 * security server and can be changed without affecting
 * clients of the security server.
 */

#ifndef _SEPOL_CONTEXT_H_
#define _SEPOL_CONTEXT_H_

#include <sepol/ebitmap.h>
#include <sepol/mls_types.h>
#include <sepol/context_record.h>

/*
 * A security context consists of an authenticated user
 * identity, a role, a type and a MLS range.
 */
typedef struct context_struct {
	uint32_t user;
	uint32_t role;
	uint32_t type;
	mls_range_t range;
} context_struct_t;

static inline void mls_context_init(context_struct_t * c)
{
	memset(&c->range, 0, sizeof(c->range));
}

static inline int mls_context_cpy(context_struct_t * dst, 
				  context_struct_t * src)
{
	int rc;

	if (!sepol_mls_enabled())
		return 0;

	dst->range.level[0].sens = src->range.level[0].sens;
	rc = ebitmap_cpy(&dst->range.level[0].cat, &src->range.level[0].cat);
	if (rc)
		goto out;

	dst->range.level[1].sens = src->range.level[1].sens;
	rc = ebitmap_cpy(&dst->range.level[1].cat, &src->range.level[1].cat);
	if (rc)
		ebitmap_destroy(&dst->range.level[0].cat);
out:
	return rc;
}

static inline int mls_context_cmp(context_struct_t * c1,
                                  context_struct_t * c2)
{
	if (!sepol_mls_enabled())
		return 1;

	return ((c1->range.level[0].sens == c2->range.level[0].sens) &&
		ebitmap_cmp(&c1->range.level[0].cat,&c2->range.level[0].cat) &&
		(c1->range.level[1].sens == c2->range.level[1].sens) &&
		ebitmap_cmp(&c1->range.level[1].cat,&c2->range.level[1].cat));
}

static inline void mls_context_destroy(context_struct_t * c)
{
	if (!sepol_mls_enabled())
		return;

	ebitmap_destroy(&c->range.level[0].cat);
	ebitmap_destroy(&c->range.level[1].cat);
	mls_context_init(c);
}

static inline void context_init(context_struct_t * c)
{
	memset(c, 0, sizeof(*c));
}

static inline int context_cpy(context_struct_t * dst,
			      context_struct_t * src)
{
	dst->user = src->user;
	dst->role = src->role;
	dst->type = src->type;
	return mls_context_cpy(dst, src);
}

static inline void context_destroy(context_struct_t * c)
{
	c->user = c->role = c->type = 0;
	mls_context_destroy(c);
}

static inline int context_cmp(context_struct_t * c1,
			      context_struct_t * c2)
{
	return ((c1->user == c2->user) &&
		(c1->role == c2->role) &&
		(c1->type == c2->type) &&
		mls_context_cmp(c1, c2));
}

struct policydb;

/* Create a context structure from high level representation */
extern int sepol_ctx_struct_create(
	struct policydb *policydb,
	context_struct_t** cptr,
	sepol_context_t data);

/* Create a context structure from string representation */
extern int sepol_ctx_struct_from_string(
	struct policydb* policydb,
	context_struct_t** cptr,
	const char* con_str,
	size_t con_str_len);

/* Check if the provided context is valid for this policy */
extern int sepol_ctx_struct_is_valid(
	struct policydb *policydb, 
	context_struct_t *context);

/* Extract the context as string */
extern int sepol_ctx_struct_to_string(
	struct policydb *policydb,
	context_struct_t * context,
	char ** result,
	size_t *result_len);

#endif	/* _SEPOL_CONTEXT_H_ */

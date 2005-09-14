#include <stdlib.h>

#include "private.h"
#include "debug.h"

#include <sepol/policydb.h>

/* Construct a policydb from the supplied (data, len) pair */

int policydb_from_image(void* data, size_t len, policydb_t* policydb) {

        policy_file_t pf;

        pf.type = PF_USE_MEMORY;
        pf.data = data;
        pf.len = len;

        if (policydb_read(policydb, &pf, 0)) {
                DEBUG(__FUNCTION__, "policy image is invalid\n");
                errno = EINVAL;
                return STATUS_ERR;
        }

        return STATUS_SUCCESS;
}

/* Write a policydb to a memory region, and return the (data, len) pair. */

int policydb_to_image(
	policydb_t* policydb, void **newdata, size_t *newlen) {

	void *tmp_data = NULL;
	size_t tmp_len;
	policy_file_t pf;
	struct policydb tmp_policydb;

	/* Set the policy version for the new policy image we are
	   about to generate so that it stays the same as the original,
	   even if we support a newer one. */
	sepol_set_policyvers(policydb->policy_type, policydb->policyvers);

	/* Compute the length for the new policy image. */
	pf.type = PF_LEN;
	pf.data = NULL;
	pf.len = 0;
	if (policydb_write(policydb, &pf)) {
		DEBUG(__FUNCTION__, "could not compute policy length\n"); 
		errno = EINVAL;	
		goto err;
	}

	/* Allocate the new policy image. */
	pf.type = PF_USE_MEMORY;
	pf.data = malloc(pf.len);
	if (!pf.data) {
		DEBUG(__FUNCTION__, "out of memory\n");
		goto err;
        }

	/* Need to save len and data prior to modification by policydb_write.*/
	tmp_len = pf.len;
	tmp_data = pf.data;

	/* Write out the new policy image. */
	if (policydb_write(policydb, &pf)) {
		DEBUG(__FUNCTION__, "could not write policy\n");
		errno = EINVAL;
		goto err;
        }

	/* Verify the new policy image. */
	pf.type = PF_USE_MEMORY;
	pf.data = tmp_data;
        pf.len = tmp_len;
        if (policydb_read(&tmp_policydb, &pf, 0)) {
		DEBUG(__FUNCTION__, "new policy image is invalid\n");
                errno = EINVAL;
		goto err;
        }
	policydb_destroy(&tmp_policydb);

	/* Update (newdata, newlen) */
	*newdata = tmp_data;
	*newlen = tmp_len;

	/* Recover */
	sepol_set_policyvers(POLICY_KERN, POLICYDB_VERSION_MAX);
        return STATUS_SUCCESS;

	err:
	DEBUG(__FUNCTION__, "could not create policy image\n");

	/* Recover */
	sepol_set_policyvers(POLICY_KERN, POLICYDB_VERSION_MAX);
	free(tmp_data);
	return STATUS_ERR;
}

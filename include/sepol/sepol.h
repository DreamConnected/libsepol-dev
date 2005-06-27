#ifndef _SEPOL_H_
#define _SEPOL_H_

#include <sys/types.h>
#include <stdio.h>

/* Given an existing binary policy (starting at 'data', with length 'len')
   and a boolean configuration file named by 'boolpath', rewrite the binary
   policy for the boolean settings in the boolean configuration file.
   The binary policy is rewritten in place in memory.
   Returns 0 upon success, or -1 otherwise. */
extern int sepol_genbools(void *data, size_t len, char *boolpath);

/* Given an existing binary policy (starting at 'data', with length 'len')
   and boolean settings specified by the parallel arrays ('names', 'values')
   with 'nel' elements, rewrite the binary policy for the boolean settings.  
   The binary policy is rewritten in place in memory.
   Returns 0 upon success or -1 otherwise. */
extern int sepol_genbools_array(void *data, size_t len, char **names, int *values, int nel);

/* Given an existing binary policy (starting at 'data with length 'len')
   and user configurations living in 'usersdir', generate a new binary
   policy for the new user configurations.  Sets '*newdata' and '*newlen'
   to refer to the new binary policy image. */
extern int sepol_genusers(void *data, size_t len,
			  const char *usersdir,
			  void **newdata, size_t *newlen);

/* Enable or disable deletion of users by sepol_genusers(3) when
   a user in original binary policy image is not defined by the
   new user configurations.  Defaults to disabled. */
extern void sepol_set_delusers(int on);

/* Set internal policydb from a file for subsequent service calls. */
extern int sepol_set_policydb_from_file(FILE *fp);

/* Check context validity against currently set binary policy. */
extern int sepol_check_context(char *context);

/* Turn on or off sepol error messages. */
extern void sepol_debug(int on);
#endif

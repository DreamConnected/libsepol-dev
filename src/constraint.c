/* Authors: Jason Tang <jtang@tresys.com>
 *
 * Copyright (C) 2005 Tresys Technology, LLC
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

#include <sepol/policydb.h>
#include <sepol/constraint.h>
#include <sepol/expand.h>
#include <sepol/flask_types.h>

#include <assert.h>
#include <stdlib.h>

int constraint_expr_init(constraint_expr_t *expr)
{
	memset(expr, 0, sizeof(*expr));
        ebitmap_init(&expr->names);
        if ((expr->type_names = malloc(sizeof(*expr->type_names))) == NULL) {
                return -1;
        }
        type_set_init(expr->type_names);
        return 0;
}

void constraint_expr_destroy(constraint_expr_t *expr)
{
        if (expr != NULL) {
                ebitmap_destroy(&expr->names);
                type_set_destroy(expr->type_names);
                free(expr->type_names);
                free(expr);
        }
}


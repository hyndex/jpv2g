/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/backend.h"

#include <stddef.h>

static bool default_authorize_contract(void *user_ctx) {
    (void)user_ctx;
    return true;
}

static bool default_authorize_external(void *user_ctx) {
    (void)user_ctx;
    return true;
}

void jpv2g_backend_set_defaults(jpv2g_backend_t *backend) {
    if (!backend) return;
    backend->authorize_contract = default_authorize_contract;
    backend->authorize_external = default_authorize_external;
    backend->user_ctx = NULL;
}

/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdbool.h>

typedef struct {
    bool (*authorize_contract)(void *user_ctx);
    bool (*authorize_external)(void *user_ctx);
    void *user_ctx;
} jpv2g_backend_t;

void jpv2g_backend_set_defaults(jpv2g_backend_t *backend);

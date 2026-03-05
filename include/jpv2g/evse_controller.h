/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdbool.h>

#include "jpv2g/types.h"

typedef struct {
    bool (*is_free_charging)(void *user_ctx);
    bool (*allow_energy_mode)(void *user_ctx, jpv2g_energy_mode_t mode);
    jpv2g_payment_option_t (*select_payment)(void *user_ctx, jpv2g_payment_option_t requested);
    void *user_ctx;
} jpv2g_evse_controller_t;

void jpv2g_evse_controller_set_defaults(jpv2g_evse_controller_t *ctl);

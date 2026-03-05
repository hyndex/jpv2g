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
    jpv2g_payment_option_t (*get_payment_option)(void *user_ctx);
    jpv2g_energy_mode_t (*get_energy_mode)(void *user_ctx);
    jpv2g_charge_params_t (*get_charge_params)(void *user_ctx);
    bool (*is_bulk_complete)(void *user_ctx);
    bool (*is_charge_complete)(void *user_ctx);
    void *user_ctx;
} jpv2g_ev_controller_t;

void jpv2g_ev_controller_set_defaults(jpv2g_ev_controller_t *ctl);

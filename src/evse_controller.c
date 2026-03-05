/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/evse_controller.h"

#include <stddef.h>

static bool default_free(void *user_ctx) {
    (void)user_ctx;
    return false;
}

static bool default_allow_mode(void *user_ctx, jpv2g_energy_mode_t mode) {
    (void)user_ctx;
    (void)mode;
    return true;
}

static jpv2g_payment_option_t default_select_payment(void *user_ctx, jpv2g_payment_option_t requested) {
    (void)user_ctx;
    return requested;
}

void jpv2g_evse_controller_set_defaults(jpv2g_evse_controller_t *ctl) {
    if (!ctl) return;
    ctl->is_free_charging = default_free;
    ctl->allow_energy_mode = default_allow_mode;
    ctl->select_payment = default_select_payment;
    ctl->user_ctx = NULL;
}

/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/ev_controller.h"

#include <stddef.h>

static jpv2g_payment_option_t default_payment(void *user_ctx) {
    (void)user_ctx;
    return JPV2G_PAYMENT_CONTRACT;
}

static jpv2g_energy_mode_t default_energy(void *user_ctx) {
    (void)user_ctx;
    return JPV2G_ENERGY_AC_THREE_PHASE;
}

static jpv2g_charge_params_t default_params(void *user_ctx) {
    (void)user_ctx;
    jpv2g_charge_params_t p = {0};
    p.mode = JPV2G_ENERGY_AC_THREE_PHASE;
    p.max_voltage = (jpv2g_physical_value_t){.value = 400, .multiplier = 0, .unit = "V"};
    p.max_current = (jpv2g_physical_value_t){.value = 32, .multiplier = 0, .unit = "A"};
    p.max_power   = (jpv2g_physical_value_t){.value = 22000, .multiplier = 0, .unit = "W"};
    return p;
}

static bool default_bulk_done(void *user_ctx) {
    (void)user_ctx;
    return false;
}

static bool default_full_done(void *user_ctx) {
    (void)user_ctx;
    return false;
}

void jpv2g_ev_controller_set_defaults(jpv2g_ev_controller_t *ctl) {
    if (!ctl) return;
    ctl->get_payment_option = default_payment;
    ctl->get_energy_mode = default_energy;
    ctl->get_charge_params = default_params;
    ctl->is_bulk_complete = default_bulk_done;
    ctl->is_charge_complete = default_full_done;
    ctl->user_ctx = NULL;
}

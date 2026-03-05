/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    JPV2G_PAYMENT_CONTRACT = 0,
    JPV2G_PAYMENT_EXTERNAL = 1
} jpv2g_payment_option_t;

typedef enum {
    JPV2G_ENERGY_AC_SINGLE_PHASE,
    JPV2G_ENERGY_AC_THREE_PHASE,
    JPV2G_ENERGY_DC_CORE,
    JPV2G_ENERGY_DC_EXTENDED,
    JPV2G_ENERGY_DC_COMBO,
    JPV2G_ENERGY_DC_UNIQUE
} jpv2g_energy_mode_t;

typedef struct {
    int16_t value;
    int8_t multiplier;
    char unit[4]; /* e.g., "V", "A", "W", "Wh" */
} jpv2g_physical_value_t;

typedef struct {
    jpv2g_energy_mode_t mode;
    jpv2g_physical_value_t max_voltage;
    jpv2g_physical_value_t max_current;
    jpv2g_physical_value_t max_power;
} jpv2g_charge_params_t;

typedef enum {
    JPV2G_PROTOCOL_UNKNOWN = 0,
    JPV2G_PROTOCOL_ISO15118_2,
    JPV2G_PROTOCOL_DIN70121
} jpv2g_protocol_t;

/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include "jpv2g/config.h"

int jpv2g_load_evcc_config(const char *path, jpv2g_evcc_config_t *cfg);
int jpv2g_load_secc_config(const char *path, jpv2g_secc_config_t *cfg);

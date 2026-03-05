/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include "jpv2g/evcc.h"
#include "jpv2g/secc.h"

/* Run a minimal SupportedAppProtocol + SessionSetup flow using the configured build/handle hooks.
 * Returns 0 on success, error code otherwise.
 */
int jpv2g_evcc_run_minimal_flow(jpv2g_evcc_t *evcc);

/* Install simple dummy handlers on SECC to answer SupportedAppProtocolReq and SessionSetupReq. */
void jpv2g_secc_set_dummy_handlers(jpv2g_secc_t *secc);

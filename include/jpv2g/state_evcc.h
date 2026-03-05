/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdbool.h>

#include "jpv2g/state_machine.h"
#include "jpv2g/messages.h"
#include "jpv2g/evcc.h"
#include "jpv2g/handler.h"

typedef struct {
    jpv2g_evcc_t *evcc;
    const jpv2g_handler_entry_t *handlers;
    size_t handler_count;
} jpv2g_evcc_sm_ctx_t;

int jpv2g_evcc_state_handler(jpv2g_state_machine_t *sm, const void *msg, size_t msg_len);

/* Build a default AC/DC EVCC response sequence. Returns number of states built (0 on error). */
size_t jpv2g_evcc_build_sequence(jpv2g_state_t *states,
                                   size_t max_states,
                                   jpv2g_evcc_sm_ctx_t *ctx,
                                   bool dc_mode);

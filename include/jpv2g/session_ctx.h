/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "jpv2g/messages.h"
#include "jpv2g/timeouts.h"
#include "jpv2g/v2gtp.h"

typedef struct {
    uint8_t session_id[8];
    jpv2g_message_type_t next_expected;
} jpv2g_session_ctx_t;

void jpv2g_session_ctx_init(jpv2g_session_ctx_t *ctx, const uint8_t sid[8]);
void jpv2g_session_set_expected(jpv2g_session_ctx_t *ctx, jpv2g_message_type_t expected);

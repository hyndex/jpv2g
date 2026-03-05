/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/session_ctx.h"

#include <string.h>

void jpv2g_session_ctx_init(jpv2g_session_ctx_t *ctx, const uint8_t sid[8]) {
    if (!ctx) return;
    if (sid) memcpy(ctx->session_id, sid, 8);
    else memset(ctx->session_id, 0, 8);
    ctx->next_expected = JPV2G_UNKNOWN_MESSAGE;
}

void jpv2g_session_set_expected(jpv2g_session_ctx_t *ctx, jpv2g_message_type_t expected) {
    if (!ctx) return;
    ctx->next_expected = expected;
}

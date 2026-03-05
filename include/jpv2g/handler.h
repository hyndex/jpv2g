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

typedef int (*jpv2g_build_fn)(jpv2g_message_type_t type, void *user_ctx, uint8_t *out, size_t out_len, size_t *written);
typedef int (*jpv2g_handle_fn)(jpv2g_message_type_t type, const void *decoded, void *user_ctx);

typedef struct {
    jpv2g_message_type_t type;
    jpv2g_build_fn builder;
    jpv2g_handle_fn handler;
} jpv2g_handler_entry_t;

/* Find a builder or handler in a table; returns NULL if not found. */
jpv2g_build_fn jpv2g_find_builder(const jpv2g_handler_entry_t *table, size_t count, jpv2g_message_type_t type);
jpv2g_handle_fn jpv2g_find_handler(const jpv2g_handler_entry_t *table, size_t count, jpv2g_message_type_t type);

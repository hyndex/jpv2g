/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/handler.h"

#include <stddef.h>

jpv2g_build_fn jpv2g_find_builder(const jpv2g_handler_entry_t *table, size_t count, jpv2g_message_type_t type) {
    if (!table) return NULL;
    for (size_t i = 0; i < count; ++i) {
        if (table[i].type == type) return table[i].builder;
    }
    return NULL;
}

jpv2g_handle_fn jpv2g_find_handler(const jpv2g_handler_entry_t *table, size_t count, jpv2g_message_type_t type) {
    if (!table) return NULL;
    for (size_t i = 0; i < count; ++i) {
        if (table[i].type == type) return table[i].handler;
    }
    return NULL;
}

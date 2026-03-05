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
#include "jpv2g/log.h"

struct jpv2g_state;
typedef struct jpv2g_state jpv2g_state_t;

typedef struct {
    jpv2g_state_t *current;
    void *user_ctx;
} jpv2g_state_machine_t;

typedef int (*jpv2g_state_handler)(jpv2g_state_machine_t *sm, const void *msg, size_t msg_len);

struct jpv2g_state {
    const char *name;
    jpv2g_message_type_t expected;
    jpv2g_state_handler handler;
    jpv2g_state_t *next;
    void *user_ctx;
};

int jpv2g_sm_init(jpv2g_state_machine_t *sm, jpv2g_state_t *start, void *user_ctx);
int jpv2g_sm_handle(jpv2g_state_machine_t *sm, jpv2g_message_type_t type, const void *msg, size_t msg_len);
void jpv2g_sm_reset(jpv2g_state_machine_t *sm, jpv2g_state_t *start);

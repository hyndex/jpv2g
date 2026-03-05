/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/state_machine.h"

#include <errno.h>

int jpv2g_sm_init(jpv2g_state_machine_t *sm, jpv2g_state_t *start, void *user_ctx) {
    if (!sm || !start) return -EINVAL;
    sm->current = start;
    sm->user_ctx = user_ctx;
    return 0;
}

int jpv2g_sm_handle(jpv2g_state_machine_t *sm, jpv2g_message_type_t type, const void *msg, size_t msg_len) {
    if (!sm || !sm->current) return -EINVAL;
    if (sm->current->expected != JPV2G_UNKNOWN_MESSAGE && type != sm->current->expected) {
        JPV2G_ERROR("Unexpected message type %d in state %s", type, sm->current->name);
        return -EINVAL;
    }
    if (!sm->current->handler) return -ENOSYS;
    return sm->current->handler(sm, msg, msg_len);
}

void jpv2g_sm_reset(jpv2g_state_machine_t *sm, jpv2g_state_t *start) {
    if (!sm) return;
    sm->current = start;
}

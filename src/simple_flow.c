/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/simple_flow.h"

#include <errno.h>
#include <string.h>

#include "jpv2g/constants.h"
#include "jpv2g/log.h"
#include "jpv2g/raw_exi.h"

static const uint8_t dummy_supp_app_req[] = {0x01, 0x00};
static const uint8_t dummy_supp_app_res[] = {0x02, 0x00};
static const uint8_t dummy_session_setup_req[] = {0x10, 0x00};
static const uint8_t dummy_session_setup_res[] = {0x11, 0x00};

int jpv2g_evcc_run_minimal_flow(jpv2g_evcc_t *evcc) {
    if (!evcc) return -EINVAL;
    int rc = jpv2g_evcc_exchange(evcc,
                                   JPV2G_SUPP_APP_PROTOCOL_REQ,
                                   JPV2G_SUPP_APP_PROTOCOL_RES,
                                   2000);
    if (rc != 0) return rc;
    rc = jpv2g_evcc_exchange(evcc,
                               JPV2G_SESSION_SETUP_REQ,
                               JPV2G_SESSION_SETUP_RES,
                               2000);
    return rc;
}

static int dummy_build(jpv2g_message_type_t type, void *user_ctx, uint8_t *out, size_t out_len, size_t *written) {
    (void)user_ctx;
    const uint8_t *src = NULL;
    size_t slen = 0;
    switch (type) {
        case JPV2G_SUPP_APP_PROTOCOL_REQ:
            src = dummy_supp_app_req; slen = sizeof(dummy_supp_app_req); break;
        case JPV2G_SESSION_SETUP_REQ:
            src = dummy_session_setup_req; slen = sizeof(dummy_session_setup_req); break;
        default:
            return -ENOTSUP;
    }
    if (out_len < slen) return -ENOSPC;
    memcpy(out, src, slen);
    if (written) *written = slen;
    return 0;
}

static int dummy_handle_res(jpv2g_message_type_t type, const void *decoded, void *user_ctx) {
    (void)decoded;
    (void)user_ctx;
    switch (type) {
        case JPV2G_SUPP_APP_PROTOCOL_RES:
        case JPV2G_SESSION_SETUP_RES:
            return 0;
        default:
            return -ENOTSUP;
    }
}

static int dummy_handle_req(jpv2g_message_type_t type, const void *decoded, uint8_t *out, size_t out_len, size_t *written, void *user_ctx) {
    (void)user_ctx;
    const jpv2g_secc_request_t *req = (const jpv2g_secc_request_t *)decoded;
    (void)req;
    const uint8_t *src = NULL;
    size_t slen = 0;
    switch (type) {
        case JPV2G_SUPP_APP_PROTOCOL_REQ:
            src = dummy_supp_app_res; slen = sizeof(dummy_supp_app_res); break;
        case JPV2G_SESSION_SETUP_REQ:
            src = dummy_session_setup_res; slen = sizeof(dummy_session_setup_res); break;
        default:
            return -ENOTSUP;
    }
    if (out_len < slen) return -ENOSPC;
    memcpy(out, src, slen);
    if (written) *written = slen;
    return 0;
}

void jpv2g_secc_set_dummy_handlers(jpv2g_secc_t *secc) {
    if (!secc) return;
    secc->handle_request = dummy_handle_req;
    secc->user_ctx = NULL;
}

/* Utility to attach dummy handlers to EVCC for minimal flow */
void jpv2g_evcc_set_dummy_handlers(jpv2g_evcc_t *evcc) __attribute__((weak));
void jpv2g_evcc_set_dummy_handlers(jpv2g_evcc_t *evcc) {
    if (!evcc) return;
    evcc->build_message = dummy_build;
    evcc->handle_message = dummy_handle_res;
    evcc->user_ctx = NULL;
}

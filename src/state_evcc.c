/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/state_evcc.h"

#include <errno.h>
#include <string.h>

#include "jpv2g/constants.h"
#include "jpv2g/log.h"

int jpv2g_evcc_state_handler(jpv2g_state_machine_t *sm, const void *msg, size_t msg_len) {
    (void)msg_len;
    if (!sm || !sm->user_ctx) return -EINVAL;
    jpv2g_evcc_sm_ctx_t *ctx = (jpv2g_evcc_sm_ctx_t *)sm->user_ctx;
    jpv2g_message_type_t expected = sm->current ? sm->current->expected : JPV2G_UNKNOWN_MESSAGE;
    jpv2g_handle_fn handler = jpv2g_find_handler(ctx->handlers, ctx->handler_count, expected);
    if (handler) {
        int rc = handler(expected, msg, ctx->evcc->user_ctx);
        if (rc != 0) return rc;
    }
    if (sm->current && sm->current->next) {
        sm->current = sm->current->next;
    } else if (sm->current && sm->current->next == NULL) {
        /* Remain on final state once reached */
    }
    return 0;
}

static size_t add_state(jpv2g_state_t *states,
                        size_t idx,
                        const char *name,
                        jpv2g_message_type_t expected,
                        jpv2g_state_handler handler) {
    states[idx].name = name;
    states[idx].expected = expected;
    states[idx].handler = handler;
    states[idx].next = NULL;
    states[idx].user_ctx = NULL;
    if (idx > 0) states[idx - 1].next = &states[idx];
    return idx + 1;
}

size_t jpv2g_evcc_build_sequence(jpv2g_state_t *states,
                                   size_t max_states,
                                   jpv2g_evcc_sm_ctx_t *ctx,
                                   bool dc_mode) {
    if (!states || max_states == 0) return 0;
    size_t needed = dc_mode ? 15 : 12;
    if (max_states < needed) return 0;

    size_t idx = 0;
    idx = add_state(states, idx, "WaitSuppAppProtocolRes", JPV2G_SUPP_APP_PROTOCOL_RES, jpv2g_evcc_state_handler);
    idx = add_state(states, idx, "WaitSessionSetupRes", JPV2G_SESSION_SETUP_RES, jpv2g_evcc_state_handler);
    idx = add_state(states, idx, "WaitServiceDiscoveryRes", JPV2G_SERVICE_DISCOVERY_RES, jpv2g_evcc_state_handler);
    idx = add_state(states, idx, "WaitServiceDetailRes", JPV2G_SERVICE_DETAIL_RES, jpv2g_evcc_state_handler);
    idx = add_state(states, idx, "WaitPaymentServiceSelectionRes", JPV2G_PAYMENT_SERVICE_SELECTION_RES, jpv2g_evcc_state_handler);
    idx = add_state(states, idx, "WaitPaymentDetailsRes", JPV2G_PAYMENT_DETAILS_RES, jpv2g_evcc_state_handler);
    idx = add_state(states, idx, "WaitAuthorizationRes", JPV2G_AUTHORIZATION_RES, jpv2g_evcc_state_handler);
    idx = add_state(states, idx, "WaitChargeParameterDiscoveryRes", JPV2G_CHARGE_PARAMETER_DISCOVERY_RES, jpv2g_evcc_state_handler);
    if (dc_mode) {
        idx = add_state(states, idx, "WaitCableCheckRes", JPV2G_CABLE_CHECK_RES, jpv2g_evcc_state_handler);
        idx = add_state(states, idx, "WaitPreChargeRes", JPV2G_PRE_CHARGE_RES, jpv2g_evcc_state_handler);
    }
    idx = add_state(states, idx, "WaitPowerDeliveryRes", JPV2G_POWER_DELIVERY_RES, jpv2g_evcc_state_handler);
    if (dc_mode) {
        idx = add_state(states, idx, "WaitCurrentDemandRes", JPV2G_CURRENT_DEMAND_RES, jpv2g_evcc_state_handler);
        idx = add_state(states, idx, "WaitMeteringReceiptRes", JPV2G_METERING_RECEIPT_RES, jpv2g_evcc_state_handler);
        idx = add_state(states, idx, "WaitWeldingDetectionRes", JPV2G_WELDING_DETECTION_RES, jpv2g_evcc_state_handler);
    } else {
        idx = add_state(states, idx, "WaitChargingStatusRes", JPV2G_CHARGING_STATUS_RES, jpv2g_evcc_state_handler);
        idx = add_state(states, idx, "WaitMeteringReceiptRes", JPV2G_METERING_RECEIPT_RES, jpv2g_evcc_state_handler);
    }
    idx = add_state(states, idx, "WaitSessionStopRes", JPV2G_SESSION_STOP_RES, jpv2g_evcc_state_handler);

    ctx->handlers = NULL;
    ctx->handler_count = 0;
    return idx;
}

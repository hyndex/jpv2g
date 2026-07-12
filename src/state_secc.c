/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/state_secc.h"

#include <errno.h>
#include <string.h>

#include "jpv2g/log.h"

void jpv2g_secc_sequence_init(jpv2g_secc_sequence_t *sequence) {
    if (!sequence) return;
    memset(sequence, 0, sizeof(*sequence));
    sequence->phase = JPV2G_SECC_PHASE_APP_PROTOCOL;
    sequence->protocol = JPV2G_PROTOCOL_UNKNOWN;
}

static int secc_sequence_require_protocol(jpv2g_secc_sequence_t *sequence,
                                          jpv2g_protocol_t protocol) {
    if (!sequence) return -EINVAL;
    if (protocol == JPV2G_PROTOCOL_UNKNOWN) return -EPROTO;
    if (sequence->protocol == JPV2G_PROTOCOL_UNKNOWN) {
        sequence->protocol = protocol;
        return 0;
    }
    return sequence->protocol == protocol ? 0 : -EPROTO;
}

int jpv2g_secc_sequence_accept_power_delivery(jpv2g_secc_sequence_t *sequence,
                                              jpv2g_protocol_t protocol,
                                              bool energy_enabled) {
    if (!sequence || secc_sequence_require_protocol(sequence, protocol) != 0) return -EPROTO;
    switch (sequence->phase) {
        case JPV2G_SECC_PHASE_CHARGE_PARAMETERS:
            if (protocol == JPV2G_PROTOCOL_DIN70121 || !energy_enabled) return -EPROTO;
            /* First passage directly CPD -> PowerDelivery is ISO AC.  During
             * renegotiation mode_known is already true; preserve a negotiated
             * DC mode so the EV may skip repeat CableCheck/PreCharge. */
            if (!sequence->mode_known) {
                sequence->dc_mode = false;
                sequence->mode_known = true;
            }
            break;
        case JPV2G_SECC_PHASE_PRE_CHARGE:
        case JPV2G_SECC_PHASE_POWER_DELIVERY:
        case JPV2G_SECC_PHASE_CHARGING:
            break;
        case JPV2G_SECC_PHASE_POWER_DELIVERY_STOP:
            /* A repeated Stop is idempotent; Start after Stop still requires a
             * new negotiation/session and is deliberately rejected. */
            if (energy_enabled) return -EPROTO;
            break;
        default:
            return -EPROTO;
    }
    sequence->phase = energy_enabled ? JPV2G_SECC_PHASE_POWER_DELIVERY
                                     : JPV2G_SECC_PHASE_POWER_DELIVERY_STOP;
    return 0;
}

int jpv2g_secc_sequence_accept_renegotiation(jpv2g_secc_sequence_t *sequence,
                                             jpv2g_protocol_t protocol) {
    if (!sequence || secc_sequence_require_protocol(sequence, protocol) != 0) return -EPROTO;
    if (protocol != JPV2G_PROTOCOL_ISO15118_2) return -EPROTO;
    if (sequence->phase != JPV2G_SECC_PHASE_POWER_DELIVERY &&
        sequence->phase != JPV2G_SECC_PHASE_CHARGING) {
        return -EPROTO;
    }
    sequence->phase = JPV2G_SECC_PHASE_CHARGE_PARAMETERS;
    return 0;
}

int jpv2g_secc_sequence_accept(jpv2g_secc_sequence_t *sequence,
                               jpv2g_protocol_t protocol,
                               jpv2g_message_type_t type) {
    if (!sequence) return -EINVAL;

    if (sequence->phase == JPV2G_SECC_PHASE_APP_PROTOCOL) {
        /* SupportedAppProtocol is normative, but legacy/lazy DIN stacks are
         * deployed that start directly with SessionSetup.  The stream decoder
         * has already identified their grammar, so accepting that shortcut is
         * both unambiguous and compatible. */
        if (type == JPV2G_SESSION_SETUP_REQ && protocol == JPV2G_PROTOCOL_DIN70121) {
            sequence->protocol = protocol;
            sequence->phase = JPV2G_SECC_PHASE_SERVICE_DISCOVERY;
            return 0;
        }
        if (type != JPV2G_SUPP_APP_PROTOCOL_REQ) return -EPROTO;
        /* UNKNOWN is retained long enough for the handler to return the
         * standards-defined Failed_NoNegotiation response. Any subsequent V2G
         * request still fails the protocol check below. */
        if (protocol != JPV2G_PROTOCOL_UNKNOWN) sequence->protocol = protocol;
        sequence->phase = JPV2G_SECC_PHASE_SESSION_SETUP;
        return 0;
    }

    if (secc_sequence_require_protocol(sequence, protocol) != 0) return -EPROTO;

    /* SessionStop is the EV's graceful abort path and is valid after a session
     * has been established, including during discovery, authorization, CPD,
     * CableCheck or PreCharge.  Rejecting it there turns an orderly vehicle
     * exit into a TCP/sequence fault. */
    if (type == JPV2G_SESSION_STOP_REQ &&
        sequence->phase >= JPV2G_SECC_PHASE_SERVICE_DISCOVERY &&
        sequence->phase < JPV2G_SECC_PHASE_COMPLETE) {
        sequence->phase = JPV2G_SECC_PHASE_COMPLETE;
        return 0;
    }

    switch (sequence->phase) {
        case JPV2G_SECC_PHASE_SESSION_SETUP:
            /* A failed/no-negotiation exchange may be retried on the same TCP
             * connection.  Once a protocol was selected, only that same
             * selection may be repeated. */
            if (type == JPV2G_SUPP_APP_PROTOCOL_REQ) {
                if (sequence->protocol != JPV2G_PROTOCOL_UNKNOWN &&
                    protocol != sequence->protocol) {
                    return -EPROTO;
                }
                if (protocol != JPV2G_PROTOCOL_UNKNOWN) sequence->protocol = protocol;
                return 0;
            }
            if (type != JPV2G_SESSION_SETUP_REQ) return -EPROTO;
            sequence->phase = JPV2G_SECC_PHASE_SERVICE_DISCOVERY;
            return 0;

        case JPV2G_SECC_PHASE_SERVICE_DISCOVERY:
            if (type != JPV2G_SERVICE_DISCOVERY_REQ) return -EPROTO;
            sequence->phase = JPV2G_SECC_PHASE_SERVICE_SELECTION;
            return 0;

        case JPV2G_SECC_PHASE_SERVICE_SELECTION:
            /* ServiceDiscovery and ServiceDetail can legitimately repeat while
             * the EV inspects the offered services. */
            if (type == JPV2G_SERVICE_DISCOVERY_REQ || type == JPV2G_SERVICE_DETAIL_REQ) return 0;
            if (type != JPV2G_PAYMENT_SERVICE_SELECTION_REQ) return -EPROTO;
            sequence->phase = JPV2G_SECC_PHASE_AUTHORIZATION;
            return 0;

        case JPV2G_SECC_PHASE_AUTHORIZATION:
            /* PaymentDetails is optional for EIM and Authorization may repeat
             * while EVSEProcessing is Ongoing. */
            if (type == JPV2G_PAYMENT_SERVICE_SELECTION_REQ ||
                type == JPV2G_PAYMENT_DETAILS_REQ ||
                type == JPV2G_AUTHORIZATION_REQ) return 0;
            if (type != JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ) return -EPROTO;
            sequence->phase = JPV2G_SECC_PHASE_CHARGE_PARAMETERS;
            return 0;

        case JPV2G_SECC_PHASE_CHARGE_PARAMETERS:
            if (type == JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ) return 0;
            if (type == JPV2G_CABLE_CHECK_REQ) {
                sequence->dc_mode = true;
                sequence->mode_known = true;
                sequence->phase = JPV2G_SECC_PHASE_CABLE_CHECK;
                return 0;
            }
            if (type == JPV2G_POWER_DELIVERY_REQ)
                return jpv2g_secc_sequence_accept_power_delivery(sequence, protocol, true);
            return -EPROTO;

        case JPV2G_SECC_PHASE_CABLE_CHECK:
            if (type == JPV2G_CABLE_CHECK_REQ) return 0;
            if (type != JPV2G_PRE_CHARGE_REQ) return -EPROTO;
            sequence->phase = JPV2G_SECC_PHASE_PRE_CHARGE;
            return 0;

        case JPV2G_SECC_PHASE_PRE_CHARGE:
            if (type == JPV2G_PRE_CHARGE_REQ) return 0;
            if (type != JPV2G_POWER_DELIVERY_REQ) return -EPROTO;
            return jpv2g_secc_sequence_accept_power_delivery(sequence, protocol, true);

        case JPV2G_SECC_PHASE_POWER_DELIVERY:
            if (type == JPV2G_POWER_DELIVERY_REQ)
                return jpv2g_secc_sequence_accept_power_delivery(sequence, protocol, true);
            if (type == JPV2G_SESSION_STOP_REQ) {
                sequence->phase = JPV2G_SECC_PHASE_COMPLETE;
                return 0;
            }
            if (sequence->dc_mode && type == JPV2G_CURRENT_DEMAND_REQ) {
                sequence->phase = JPV2G_SECC_PHASE_CHARGING;
                return 0;
            }
            if (!sequence->dc_mode && type == JPV2G_CHARGING_STATUS_REQ) {
                sequence->phase = JPV2G_SECC_PHASE_CHARGING;
                return 0;
            }
            if (sequence->dc_mode && type == JPV2G_WELDING_DETECTION_REQ) {
                sequence->phase = JPV2G_SECC_PHASE_WELDING;
                return 0;
            }
            return -EPROTO;

        case JPV2G_SECC_PHASE_CHARGING:
            if ((sequence->dc_mode && type == JPV2G_CURRENT_DEMAND_REQ) ||
                (!sequence->dc_mode && type == JPV2G_CHARGING_STATUS_REQ) ||
                type == JPV2G_METERING_RECEIPT_REQ) {
                return 0;
            }
            if (type == JPV2G_POWER_DELIVERY_REQ)
                return jpv2g_secc_sequence_accept_power_delivery(sequence, protocol, true);
            if (sequence->dc_mode && type == JPV2G_WELDING_DETECTION_REQ) {
                sequence->phase = JPV2G_SECC_PHASE_WELDING;
                return 0;
            }
            if (type == JPV2G_SESSION_STOP_REQ) {
                sequence->phase = JPV2G_SECC_PHASE_COMPLETE;
                return 0;
            }
            return -EPROTO;

        case JPV2G_SECC_PHASE_POWER_DELIVERY_STOP:
            if (sequence->dc_mode && type == JPV2G_WELDING_DETECTION_REQ) {
                sequence->phase = JPV2G_SECC_PHASE_WELDING;
                return 0;
            }
            if (type == JPV2G_SESSION_STOP_REQ) {
                sequence->phase = JPV2G_SECC_PHASE_COMPLETE;
                return 0;
            }
            return -EPROTO;

        case JPV2G_SECC_PHASE_WELDING:
            if (type == JPV2G_WELDING_DETECTION_REQ) return 0;
            if (type != JPV2G_SESSION_STOP_REQ) return -EPROTO;
            sequence->phase = JPV2G_SECC_PHASE_COMPLETE;
            return 0;

        case JPV2G_SECC_PHASE_COMPLETE:
        case JPV2G_SECC_PHASE_APP_PROTOCOL:
        default:
            return -EPROTO;
    }
}

int jpv2g_secc_state_handler(jpv2g_state_machine_t *sm, const void *msg, size_t msg_len) {
    (void)msg_len;
    if (!sm || !sm->user_ctx) return -EINVAL;
    jpv2g_secc_sm_ctx_t *ctx = (jpv2g_secc_sm_ctx_t *)sm->user_ctx;
    jpv2g_message_type_t expected = sm->current ? sm->current->expected : JPV2G_UNKNOWN_MESSAGE;
    jpv2g_handle_fn handler = jpv2g_find_handler(ctx->handlers, ctx->handler_count, expected);
    if (handler) {
        int rc = handler(expected, msg, ctx->secc ? ctx->secc->user_ctx : NULL);
        if (rc != 0) return rc;
    }
    if (sm->current && sm->current->next) {
        sm->current = sm->current->next;
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

size_t jpv2g_secc_build_sequence(jpv2g_state_t *states,
                                   size_t max_states,
                                   jpv2g_secc_sm_ctx_t *ctx,
                                   bool dc_mode) {
    if (!states || max_states == 0) return 0;
    size_t needed = dc_mode ? 15 : 12;
    if (max_states < needed) return 0;

    size_t idx = 0;
    idx = add_state(states, idx, "WaitSuppAppProtocolReq", JPV2G_SUPP_APP_PROTOCOL_REQ, jpv2g_secc_state_handler);
    idx = add_state(states, idx, "WaitSessionSetupReq", JPV2G_SESSION_SETUP_REQ, jpv2g_secc_state_handler);
    idx = add_state(states, idx, "WaitServiceDiscoveryReq", JPV2G_SERVICE_DISCOVERY_REQ, jpv2g_secc_state_handler);
    idx = add_state(states, idx, "WaitServiceDetailReq", JPV2G_SERVICE_DETAIL_REQ, jpv2g_secc_state_handler);
    idx = add_state(states, idx, "WaitPaymentServiceSelectionReq", JPV2G_PAYMENT_SERVICE_SELECTION_REQ, jpv2g_secc_state_handler);
    idx = add_state(states, idx, "WaitPaymentDetailsReq", JPV2G_PAYMENT_DETAILS_REQ, jpv2g_secc_state_handler);
    idx = add_state(states, idx, "WaitAuthorizationReq", JPV2G_AUTHORIZATION_REQ, jpv2g_secc_state_handler);
    idx = add_state(states, idx, "WaitChargeParameterDiscoveryReq", JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ, jpv2g_secc_state_handler);
    if (dc_mode) {
        idx = add_state(states, idx, "WaitCableCheckReq", JPV2G_CABLE_CHECK_REQ, jpv2g_secc_state_handler);
        idx = add_state(states, idx, "WaitPreChargeReq", JPV2G_PRE_CHARGE_REQ, jpv2g_secc_state_handler);
    }
    idx = add_state(states, idx, "WaitPowerDeliveryReq", JPV2G_POWER_DELIVERY_REQ, jpv2g_secc_state_handler);
    if (dc_mode) {
        idx = add_state(states, idx, "WaitCurrentDemandReq", JPV2G_CURRENT_DEMAND_REQ, jpv2g_secc_state_handler);
        idx = add_state(states, idx, "WaitMeteringReceiptReq", JPV2G_METERING_RECEIPT_REQ, jpv2g_secc_state_handler);
        idx = add_state(states, idx, "WaitWeldingDetectionReq", JPV2G_WELDING_DETECTION_REQ, jpv2g_secc_state_handler);
    } else {
        idx = add_state(states, idx, "WaitChargingStatusReq", JPV2G_CHARGING_STATUS_REQ, jpv2g_secc_state_handler);
        idx = add_state(states, idx, "WaitMeteringReceiptReq", JPV2G_METERING_RECEIPT_REQ, jpv2g_secc_state_handler);
    }
    idx = add_state(states, idx, "WaitSessionStopReq", JPV2G_SESSION_STOP_REQ, jpv2g_secc_state_handler);

    ctx->handlers = NULL;
    ctx->handler_count = 0;
    return idx;
}

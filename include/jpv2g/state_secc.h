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
#include "jpv2g/secc.h"
#include "jpv2g/handler.h"

typedef struct {
    jpv2g_secc_t *secc;
    const jpv2g_handler_entry_t *handlers;
    size_t handler_count;
} jpv2g_secc_sm_ctx_t;

/*
 * Connection-level SECC request sequencer used by the production stream
 * dispatcher.  The older linked-list state-machine API below is retained for
 * source compatibility, but it models one strictly linear happy path and
 * cannot represent optional ServiceDetail/PaymentDetails exchanges or the
 * repeated Authorization, CableCheck, PreCharge and CurrentDemand requests
 * required by ISO 15118/DIN 70121.
 */
typedef enum {
    JPV2G_SECC_PHASE_APP_PROTOCOL = 0,
    JPV2G_SECC_PHASE_SESSION_SETUP,
    JPV2G_SECC_PHASE_SERVICE_DISCOVERY,
    JPV2G_SECC_PHASE_SERVICE_SELECTION,
    JPV2G_SECC_PHASE_AUTHORIZATION,
    JPV2G_SECC_PHASE_CHARGE_PARAMETERS,
    JPV2G_SECC_PHASE_CABLE_CHECK,
    JPV2G_SECC_PHASE_PRE_CHARGE,
    JPV2G_SECC_PHASE_POWER_DELIVERY,
    JPV2G_SECC_PHASE_CHARGING,
    JPV2G_SECC_PHASE_POWER_DELIVERY_STOP,
    JPV2G_SECC_PHASE_WELDING,
    JPV2G_SECC_PHASE_COMPLETE,
} jpv2g_secc_phase_t;

typedef struct {
    jpv2g_secc_phase_t phase;
    jpv2g_protocol_t protocol;
    bool dc_mode;
    bool mode_known;
} jpv2g_secc_sequence_t;

void jpv2g_secc_sequence_init(jpv2g_secc_sequence_t *sequence);

/* Validate and commit one successfully decoded request. Returns -EPROTO for
 * an invalid transition or a protocol switch. Repeatable protocol states are
 * accepted without advancing past the phase. */
int jpv2g_secc_sequence_accept(jpv2g_secc_sequence_t *sequence,
                               jpv2g_protocol_t protocol,
                               jpv2g_message_type_t type);

/* Semantic PowerDelivery Start/Stop transition. The message type alone cannot
 * distinguish ISO Start/Stop or DIN ReadyToChargeState true/false. Production
 * dispatch must use this entry point so CurrentDemand cannot resume after a
 * stop request without a new negotiated power-delivery transition. */
int jpv2g_secc_sequence_accept_power_delivery(jpv2g_secc_sequence_t *sequence,
                                              jpv2g_protocol_t protocol,
                                              bool energy_enabled);

/* ISO 15118-2 ChargeProgress=Renegotiate returns an active charging session to
 * ChargeParameterDiscovery.  The previously negotiated DC/AC mode is retained
 * so a DC EV may proceed CPD -> PowerDelivery(Start) without repeating
 * CableCheck/PreCharge, while stacks that do repeat those stages remain valid. */
int jpv2g_secc_sequence_accept_renegotiation(jpv2g_secc_sequence_t *sequence,
                                             jpv2g_protocol_t protocol);

int jpv2g_secc_state_handler(jpv2g_state_machine_t *sm, const void *msg, size_t msg_len);

size_t jpv2g_secc_build_sequence(jpv2g_state_t *states,
                                   size_t max_states,
                                   jpv2g_secc_sm_ctx_t *ctx,
                                   bool dc_mode);

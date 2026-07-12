/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef JPV2G_ENABLE_CBV2G_CODEC
#include "cbv2g/app_handshake/appHand_Decoder.h"
#include "cbv2g/app_handshake/appHand_Encoder.h"
#include "cbv2g/common/exi_bitstream.h"
#include "cbv2g/din/din_msgDefDecoder.h"
#include "cbv2g/din/din_msgDefDatatypes.h"
#include "cbv2g/iso_2/iso2_msgDefDatatypes.h"
#include "jpv2g/cbv2g_codec.h"
#endif
#include "jpv2g/evcc.h"
#include "jpv2g/handler.h"
#include "jpv2g/secc.h"
#include "jpv2g/state_evcc.h"
#include "jpv2g/state_machine.h"
#include "jpv2g/state_secc.h"
#include "jpv2g/v2gtp.h"

typedef struct {
    size_t calls;
    jpv2g_message_type_t last_type;
} test_handler_stats_t;

static int assert_true(int cond, const char *msg) {
    if (cond) return 0;
    fprintf(stderr, "ASSERT FAILED: %s\n", msg);
    return 1;
}

static int counting_handler(jpv2g_message_type_t type, const void *decoded, void *user_ctx) {
    (void)decoded;
    test_handler_stats_t *stats = (test_handler_stats_t *)user_ctx;
    if (!stats) return -EINVAL;
    stats->calls++;
    stats->last_type = type;
    return 0;
}

static int test_v2gtp_round_trip(void) {
    uint8_t payload[6] = {1, 2, 3, 4, 5, 6};
    uint8_t frame[64];
    size_t frame_len = 0;
    int rc = jpv2g_v2gtp_build(JPV2G_PAYLOAD_EXI, payload, sizeof(payload), frame, sizeof(frame), &frame_len);
    if (assert_true(rc == 0, "jpv2g_v2gtp_build should succeed") != 0) return 1;

    jpv2g_v2gtp_t parsed;
    memset(&parsed, 0, sizeof(parsed));
    rc = jpv2g_v2gtp_parse(frame, frame_len, &parsed);
    if (assert_true(rc == 0, "jpv2g_v2gtp_parse should succeed") != 0) return 1;
    if (assert_true(parsed.payload_type == JPV2G_PAYLOAD_EXI, "payload type must match") != 0) return 1;
    if (assert_true(parsed.payload_length == sizeof(payload), "payload length must match") != 0) return 1;
    if (assert_true(memcmp(parsed.payload, payload, sizeof(payload)) == 0, "payload bytes must round trip") != 0) return 1;
    return 0;
}

static int test_evcc_state_sequence(void) {
    jpv2g_state_t states[20];
    jpv2g_evcc_sm_ctx_t ctx;
    jpv2g_evcc_t evcc;
    jpv2g_handler_entry_t handlers[20];
    test_handler_stats_t stats;
    memset(states, 0, sizeof(states));
    memset(&ctx, 0, sizeof(ctx));
    memset(&evcc, 0, sizeof(evcc));
    memset(handlers, 0, sizeof(handlers));
    memset(&stats, 0, sizeof(stats));

    size_t n = jpv2g_evcc_build_sequence(states, 20, &ctx, true);
    if (assert_true(n == 15, "EVCC DC sequence should contain 15 states") != 0) return 1;

    for (size_t i = 0; i < n; ++i) {
        handlers[i].type = states[i].expected;
        handlers[i].handler = counting_handler;
    }
    evcc.user_ctx = &stats;
    ctx.evcc = &evcc;
    ctx.handlers = handlers;
    ctx.handler_count = n;

    jpv2g_state_machine_t sm;
    if (assert_true(jpv2g_sm_init(&sm, &states[0], &ctx) == 0, "EVCC sm init must succeed") != 0) return 1;
    if (assert_true(jpv2g_sm_handle(&sm, JPV2G_SESSION_SETUP_RES, NULL, 0) == -EINVAL,
                    "EVCC sm must reject unexpected message type") != 0) return 1;

    for (size_t i = 0; i < n; ++i) {
        int rc = jpv2g_sm_handle(&sm, states[i].expected, NULL, 0);
        if (assert_true(rc == 0, "EVCC sm should accept expected message type") != 0) return 1;
        if (i + 1 < n) {
            if (assert_true(sm.current == &states[i + 1], "EVCC sm should advance to next state") != 0) return 1;
        } else {
            if (assert_true(sm.current == &states[n - 1], "EVCC sm should stay on final state") != 0) return 1;
        }
    }

    size_t before = stats.calls;
    if (assert_true(jpv2g_sm_handle(&sm, states[n - 1].expected, NULL, 0) == 0,
                    "EVCC final state should remain re-entrant") != 0) return 1;
    if (assert_true(sm.current == &states[n - 1], "EVCC final state pointer should stay unchanged") != 0) return 1;
    if (assert_true(stats.calls == before + 1, "EVCC final state handler should still be called") != 0) return 1;
    return 0;
}

static int test_secc_state_sequence(void) {
    jpv2g_state_t states[20];
    jpv2g_secc_sm_ctx_t ctx;
    jpv2g_secc_t secc;
    jpv2g_handler_entry_t handlers[20];
    test_handler_stats_t stats;
    memset(states, 0, sizeof(states));
    memset(&ctx, 0, sizeof(ctx));
    memset(&secc, 0, sizeof(secc));
    memset(handlers, 0, sizeof(handlers));
    memset(&stats, 0, sizeof(stats));

    size_t n = jpv2g_secc_build_sequence(states, 20, &ctx, false);
    if (assert_true(n == 12, "SECC AC sequence should contain 12 states") != 0) return 1;

    for (size_t i = 0; i < n; ++i) {
        handlers[i].type = states[i].expected;
        handlers[i].handler = counting_handler;
    }
    secc.user_ctx = &stats;
    ctx.secc = &secc;
    ctx.handlers = handlers;
    ctx.handler_count = n;

    jpv2g_state_machine_t sm;
    if (assert_true(jpv2g_sm_init(&sm, &states[0], &ctx) == 0, "SECC sm init must succeed") != 0) return 1;
    if (assert_true(jpv2g_sm_handle(&sm, JPV2G_SESSION_SETUP_REQ, NULL, 0) == -EINVAL,
                    "SECC sm must reject unexpected message type") != 0) return 1;

    for (size_t i = 0; i < n; ++i) {
        int rc = jpv2g_sm_handle(&sm, states[i].expected, NULL, 0);
        if (assert_true(rc == 0, "SECC sm should accept expected message type") != 0) return 1;
        if (i + 1 < n) {
            if (assert_true(sm.current == &states[i + 1], "SECC sm should advance to next state") != 0) return 1;
        } else {
            if (assert_true(sm.current == &states[n - 1], "SECC sm should stay on final state") != 0) return 1;
        }
    }
    if (assert_true(stats.calls == n, "SECC handlers should run once per expected state") != 0) return 1;

    jpv2g_sm_reset(&sm, &states[0]);
    if (assert_true(sm.current == &states[0], "state machine reset should restore first state") != 0) return 1;
    return 0;
}

static int accept_sequence(jpv2g_secc_sequence_t *sequence,
                           jpv2g_protocol_t protocol,
                           jpv2g_message_type_t type,
                           const char *message) {
    return assert_true(jpv2g_secc_sequence_accept(sequence, protocol, type) == 0, message);
}

static int test_secc_production_sequence(void) {
    jpv2g_secc_sequence_t sequence;
    jpv2g_secc_sequence_init(&sequence);

    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_SUPP_APP_PROTOCOL_REQ,
                        "sequence must start with SupportedAppProtocol") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_SESSION_SETUP_REQ,
                        "SessionSetup must follow negotiation") != 0) return 1;
    if (assert_true(jpv2g_secc_sequence_accept(&sequence,
                                               JPV2G_PROTOCOL_ISO15118_2,
                                               JPV2G_CURRENT_DEMAND_REQ) == -EPROTO,
                    "CurrentDemand before discovery must be rejected") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_SERVICE_DISCOVERY_REQ,
                        "ServiceDiscovery must be accepted") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_SERVICE_DETAIL_REQ,
                        "optional ServiceDetail must be accepted") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_SERVICE_DETAIL_REQ,
                        "ServiceDetail may repeat") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_PAYMENT_SERVICE_SELECTION_REQ,
                        "payment selection must be accepted") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_PAYMENT_DETAILS_REQ,
                        "optional contract payment details must be accepted") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_AUTHORIZATION_REQ,
                        "authorization must be accepted") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_AUTHORIZATION_REQ,
                        "ongoing authorization may repeat") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ,
                        "charge parameters must be accepted") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ,
                        "ongoing charge parameters may repeat") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_CABLE_CHECK_REQ,
                        "DC CableCheck must be accepted") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_CABLE_CHECK_REQ,
                        "CableCheck may repeat") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_PRE_CHARGE_REQ,
                        "PreCharge must be accepted") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_PRE_CHARGE_REQ,
                        "PreCharge may repeat") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_POWER_DELIVERY_REQ,
                        "PowerDelivery must be accepted") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_CURRENT_DEMAND_REQ,
                        "CurrentDemand must be accepted after PowerDelivery") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_CURRENT_DEMAND_REQ,
                        "CurrentDemand may repeat") != 0) return 1;
    if (assert_true(jpv2g_secc_sequence_accept_renegotiation(
                        &sequence, JPV2G_PROTOCOL_ISO15118_2) == 0,
                    "ISO PowerDelivery Renegotiate must return to CPD") != 0) return 1;
    if (assert_true(sequence.phase == JPV2G_SECC_PHASE_CHARGE_PARAMETERS && sequence.dc_mode,
                    "renegotiation must retain the negotiated DC mode") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ,
                        "renegotiated CPD must be accepted") != 0) return 1;
    if (assert_true(jpv2g_secc_sequence_accept_power_delivery(
                        &sequence, JPV2G_PROTOCOL_ISO15118_2, true) == 0,
                    "renegotiated PowerDelivery Start must be accepted") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_CURRENT_DEMAND_REQ,
                        "CurrentDemand must resume after renegotiation") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_METERING_RECEIPT_REQ,
                        "MeteringReceipt may occur during charging") != 0) return 1;
    if (assert_true(jpv2g_secc_sequence_accept_power_delivery(
                        &sequence, JPV2G_PROTOCOL_ISO15118_2, false) == 0,
                    "PowerDelivery stop may occur during charging") != 0) return 1;
    if (assert_true(jpv2g_secc_sequence_accept(&sequence,
                                               JPV2G_PROTOCOL_ISO15118_2,
                                               JPV2G_CURRENT_DEMAND_REQ) == -EPROTO,
                    "CurrentDemand must not resume after PowerDelivery stop") != 0) return 1;
    if (assert_true(jpv2g_secc_sequence_accept_power_delivery(
                        &sequence, JPV2G_PROTOCOL_ISO15118_2, false) == 0,
                    "repeated PowerDelivery Stop must be idempotent") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_WELDING_DETECTION_REQ,
                        "WeldingDetection must be accepted after charging") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_WELDING_DETECTION_REQ,
                        "WeldingDetection may repeat") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_SESSION_STOP_REQ,
                        "SessionStop must complete the sequence") != 0) return 1;
    if (assert_true(jpv2g_secc_sequence_accept(&sequence,
                                               JPV2G_PROTOCOL_ISO15118_2,
                                               JPV2G_CURRENT_DEMAND_REQ) == -EPROTO,
                    "no request is valid after SessionStop") != 0) return 1;

    jpv2g_secc_sequence_init(&sequence);
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_SUPP_APP_PROTOCOL_REQ,
                        "new sequence negotiation") != 0) return 1;
    if (assert_true(jpv2g_secc_sequence_accept(&sequence,
                                               JPV2G_PROTOCOL_DIN70121,
                                               JPV2G_SESSION_SETUP_REQ) == -EPROTO,
                    "protocol switching after negotiation must be rejected") != 0) return 1;

    jpv2g_secc_sequence_init(&sequence);
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_DIN70121, JPV2G_SESSION_SETUP_REQ,
                        "legacy DIN may start directly with SessionSetup") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_DIN70121, JPV2G_SESSION_STOP_REQ,
                        "graceful SessionStop must be accepted before ServiceDiscovery") != 0) return 1;

    jpv2g_secc_sequence_init(&sequence);
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_SUPP_APP_PROTOCOL_REQ,
                        "SApp negotiation for retry variants") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_SUPP_APP_PROTOCOL_REQ,
                        "same-protocol SApp retry must be accepted") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_SESSION_SETUP_REQ,
                        "SessionSetup after SApp retry") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_SERVICE_DISCOVERY_REQ,
                        "ServiceDiscovery after SApp retry") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_PAYMENT_SERVICE_SELECTION_REQ,
                        "PaymentSelection after discovery") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_PAYMENT_SERVICE_SELECTION_REQ,
                        "duplicate PaymentSelection must be idempotent") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_SESSION_STOP_REQ,
                        "graceful SessionStop must be accepted during authorization") != 0) return 1;

    /* OK_OldSessionJoined still restarts service/payment/parameter discovery:
     * a resumed EV must not jump straight from SessionSetup to CPD/PowerDelivery. */
    jpv2g_secc_sequence_init(&sequence);
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_SUPP_APP_PROTOCOL_REQ,
                        "resumed-session SApp") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_SESSION_SETUP_REQ,
                        "resumed SessionSetup") != 0) return 1;
    if (assert_true(jpv2g_secc_sequence_accept(
                        &sequence,
                        JPV2G_PROTOCOL_ISO15118_2,
                        JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ) == -EPROTO,
                    "resumed ISO session must not skip ServiceDiscovery") != 0) return 1;
    if (accept_sequence(&sequence, JPV2G_PROTOCOL_ISO15118_2, JPV2G_SERVICE_DISCOVERY_REQ,
                        "resumed ISO session must restart ServiceDiscovery") != 0) return 1;
    return 0;
}

#ifdef JPV2G_ENABLE_CBV2G_CODEC
static void set_app_offer_version(struct appHand_AppProtocolType *offer,
                                  const char *protocol_namespace,
                                  uint32_t major_version,
                                  uint32_t minor_version,
                                  uint8_t schema_id,
                                  uint8_t priority) {
    init_appHand_AppProtocolType(offer);
    size_t len = strlen(protocol_namespace);
    if (len > appHand_ProtocolNamespace_CHARACTER_SIZE) {
        len = appHand_ProtocolNamespace_CHARACTER_SIZE;
    }
    memcpy(offer->ProtocolNamespace.characters, protocol_namespace, len);
    offer->ProtocolNamespace.charactersLen = (uint16_t)len;
    offer->VersionNumberMajor = major_version;
    offer->VersionNumberMinor = minor_version;
    offer->SchemaID = schema_id;
    offer->Priority = priority;
}

static void set_app_offer(struct appHand_AppProtocolType *offer,
                          const char *protocol_namespace,
                          uint8_t schema_id,
                          uint8_t priority) {
    set_app_offer_version(offer, protocol_namespace, 2, 0, schema_id, priority);
}

static int decode_din_document(const uint8_t *payload,
                               size_t payload_len,
                               struct din_exiDocument *document) {
    memset(document, 0, sizeof(*document));
    init_din_exiDocument(document);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)payload, payload_len, 0, NULL);
    return decode_din_exiDocument(&stream, document);
}

static void transition_set_iso_physical(struct iso2_PhysicalValueType *value,
                                        iso2_unitSymbolType unit,
                                        int16_t raw_value,
                                        int8_t multiplier) {
    init_iso2_PhysicalValueType(value);
    value->Unit = unit;
    value->Value = raw_value;
    value->Multiplier = multiplier;
}

static void transition_set_din_physical(struct din_PhysicalValueType *value,
                                        din_unitSymbolType unit,
                                        int16_t raw_value,
                                        int8_t multiplier) {
    init_din_PhysicalValueType(value);
    value->Unit = unit;
    value->Unit_isUsed = 1;
    value->Value = raw_value;
    value->Multiplier = multiplier;
}

static int transition_iso_physical_equals(
    const struct iso2_PhysicalValueType *value,
    iso2_unitSymbolType unit,
    int16_t raw_value,
    int8_t multiplier) {
    return value->Unit == unit && value->Value == raw_value &&
           value->Multiplier == multiplier;
}

static int transition_din_physical_equals(
    const struct din_PhysicalValueType *value,
    din_unitSymbolType unit,
    int16_t raw_value,
    int8_t multiplier) {
    return value->Unit_isUsed && value->Unit == unit &&
           value->Value == raw_value && value->Multiplier == multiplier;
}

static void transition_set_iso_status(
    struct iso2_DC_EVSEStatusType *status,
    iso2_DC_EVSEStatusCodeType status_code,
    int isolation_valid) {
    init_iso2_DC_EVSEStatusType(status);
    status->NotificationMaxDelay = 0;
    status->EVSENotification = iso2_EVSENotificationType_None;
    status->EVSEStatusCode = status_code;
    status->EVSEIsolationStatus_isUsed = isolation_valid ? 1u : 0u;
    status->EVSEIsolationStatus = isolation_valid
                                      ? iso2_isolationLevelType_Valid
                                      : iso2_isolationLevelType_Invalid;
}

static void transition_set_din_status(
    struct din_DC_EVSEStatusType *status,
    din_DC_EVSEStatusCodeType status_code,
    int isolation_valid) {
    init_din_DC_EVSEStatusType(status);
    status->NotificationMaxDelay = 0;
    status->EVSENotification = din_EVSENotificationType_None;
    status->EVSEStatusCode = status_code;
    status->EVSEIsolationStatus_isUsed = isolation_valid ? 1u : 0u;
    status->EVSEIsolationStatus = isolation_valid
                                      ? din_isolationLevelType_Valid
                                      : din_isolationLevelType_Invalid;
}

static void transition_fill_iso_cpd_limits(
    struct iso2_DC_EVSEChargeParameterType *params,
    int ready) {
    init_iso2_DC_EVSEChargeParameterType(params);
    transition_set_iso_status(
        &params->DC_EVSEStatus,
        ready ? iso2_DC_EVSEStatusCodeType_EVSE_Ready
              : iso2_DC_EVSEStatusCodeType_EVSE_NotReady,
        ready);
    transition_set_iso_physical(
        &params->EVSEMaximumCurrentLimit,
        iso2_unitSymbolType_A,
        ready ? 120 : 0,
        0);
    transition_set_iso_physical(
        &params->EVSEMaximumPowerLimit,
        iso2_unitSymbolType_W,
        ready ? 60 : 0,
        ready ? 3 : 0);
    transition_set_iso_physical(
        &params->EVSEMaximumVoltageLimit,
        iso2_unitSymbolType_V,
        ready ? 500 : 0,
        0);
    transition_set_iso_physical(
        &params->EVSEMinimumCurrentLimit, iso2_unitSymbolType_A, 0, 0);
    transition_set_iso_physical(
        &params->EVSEMinimumVoltageLimit, iso2_unitSymbolType_V, 200, 0);
    transition_set_iso_physical(
        &params->EVSEPeakCurrentRipple, iso2_unitSymbolType_A, 1, 0);
    params->EVSECurrentRegulationTolerance_isUsed = 0;
    params->EVSEEnergyToBeDelivered_isUsed = 0;
}

static void transition_fill_din_cpd_limits(
    struct din_DC_EVSEChargeParameterType *params,
    int ready) {
    init_din_DC_EVSEChargeParameterType(params);
    transition_set_din_status(
        &params->DC_EVSEStatus,
        ready ? din_DC_EVSEStatusCodeType_EVSE_Ready
              : din_DC_EVSEStatusCodeType_EVSE_NotReady,
        ready);
    transition_set_din_physical(
        &params->EVSEMaximumCurrentLimit,
        din_unitSymbolType_A,
        ready ? 120 : 0,
        0);
    params->EVSEMaximumPowerLimit_isUsed = 1;
    transition_set_din_physical(
        &params->EVSEMaximumPowerLimit,
        din_unitSymbolType_W,
        ready ? 60 : 0,
        ready ? 3 : 0);
    transition_set_din_physical(
        &params->EVSEMaximumVoltageLimit,
        din_unitSymbolType_V,
        ready ? 500 : 0,
        0);
    transition_set_din_physical(
        &params->EVSEMinimumCurrentLimit, din_unitSymbolType_A, 0, 0);
    transition_set_din_physical(
        &params->EVSEMinimumVoltageLimit, din_unitSymbolType_V, 200, 0);
    transition_set_din_physical(
        &params->EVSEPeakCurrentRipple, din_unitSymbolType_A, 1, 0);
    params->EVSECurrentRegulationTolerance_isUsed = 0;
    params->EVSEEnergyToBeDelivered_isUsed = 0;
}

static void transition_fill_iso_schedule(
    struct iso2_ChargeParameterDiscoveryResType *response) {
    response->SASchedules_isUsed = 0;
    response->SAScheduleList_isUsed = 1;
    init_iso2_SAScheduleListType(&response->SAScheduleList);
    response->SAScheduleList.SAScheduleTuple.arrayLen = 1;
    struct iso2_SAScheduleTupleType *tuple =
        &response->SAScheduleList.SAScheduleTuple.array[0];
    init_iso2_SAScheduleTupleType(tuple);
    tuple->SAScheduleTupleID = 7;
    tuple->SalesTariff_isUsed = 0;
    init_iso2_PMaxScheduleType(&tuple->PMaxSchedule);
    tuple->PMaxSchedule.PMaxScheduleEntry.arrayLen = 1;
    struct iso2_PMaxScheduleEntryType *entry =
        &tuple->PMaxSchedule.PMaxScheduleEntry.array[0];
    init_iso2_PMaxScheduleEntryType(entry);
    init_iso2_RelativeTimeIntervalType(&entry->RelativeTimeInterval);
    entry->RelativeTimeInterval.start = 0;
    entry->RelativeTimeInterval.duration = 86400;
    entry->RelativeTimeInterval.duration_isUsed = 1;
    entry->RelativeTimeInterval_isUsed = 1;
    transition_set_iso_physical(&entry->PMax, iso2_unitSymbolType_W, 60, 3);
}

static int negotiate_app_protocol(jpv2g_secc_t *secc,
                                  struct appHand_supportedAppProtocolReq *offers,
                                  struct appHand_supportedAppProtocolRes *result) {
    uint8_t response[2048];
    size_t response_len = 0;
    jpv2g_secc_request_t request;
    memset(&request, 0, sizeof(request));
    request.protocol = JPV2G_PROTOCOL_UNKNOWN;
    request.body = offers;
    int rc = jpv2g_secc_default_handle(secc,
                                       JPV2G_SUPP_APP_PROTOCOL_REQ,
                                       &request,
                                       response,
                                       sizeof(response),
                                       &response_len);
    if (rc != 0) return rc;
    return jpv2g_cbv2g_decode_sapp_res(response, response_len, result);
}

static int test_supported_app_protocol_interop(void) {
    uint8_t encoded[8192];
    uint8_t response[2048];
    size_t encoded_len = 0;
    size_t response_len = 0;
    struct appHand_exiDocument request_doc;
    struct appHand_exiDocument decoded_doc;
    struct appHand_supportedAppProtocolRes response_doc;

    init_appHand_exiDocument(&request_doc);
    request_doc.supportedAppProtocolReq_isUsed = 1;
    init_appHand_supportedAppProtocolReq(&request_doc.supportedAppProtocolReq);
    request_doc.supportedAppProtocolReq.AppProtocol.arrayLen =
        appHand_AppProtocolType_20_ARRAY_SIZE;
    for (uint16_t i = 0; i < appHand_AppProtocolType_20_ARRAY_SIZE; ++i) {
        set_app_offer(&request_doc.supportedAppProtocolReq.AppProtocol.array[i],
                      "urn:iso:std:iso:15118:-20:CommonMessages",
                      (uint8_t)(i + 1),
                      (uint8_t)(i + 1));
    }
    set_app_offer(&request_doc.supportedAppProtocolReq.AppProtocol.array[19],
                  "urn:din:70121:2012:MsgDef",
                  77,
                  20);

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, encoded, sizeof(encoded), 0, NULL);
    if (assert_true(encode_appHand_exiDocument(&stream, &request_doc) == 0,
                    "SApp encoder must accept the schema maximum of 20 offers") != 0) return 1;
    encoded_len = exi_bitstream_get_length(&stream);

    init_appHand_exiDocument(&decoded_doc);
    exi_bitstream_init(&stream, encoded, encoded_len, 0, NULL);
    if (assert_true(decode_appHand_exiDocument(&stream, &decoded_doc) == 0,
                    "SApp decoder must accept 20 offers") != 0) return 1;
    if (assert_true(decoded_doc.supportedAppProtocolReq_isUsed &&
                        decoded_doc.supportedAppProtocolReq.AppProtocol.arrayLen == 20 &&
                        decoded_doc.supportedAppProtocolReq.AppProtocol.array[19].SchemaID == 77,
                    "all 20 SApp offers must survive EXI round trip") != 0) return 1;

    request_doc.supportedAppProtocolReq.AppProtocol.arrayLen = 21;
    exi_bitstream_init(&stream, encoded, sizeof(encoded), 0, NULL);
    if (assert_true(encode_appHand_exiDocument(&stream, &request_doc) != 0,
                    "SApp encoder must reject arrayLen beyond schema storage") != 0) return 1;

    jpv2g_secc_t secc;
    jpv2g_secc_request_t request;
    memset(&secc, 0, sizeof(secc));
    memset(&request, 0, sizeof(request));
    jpv2g_secc_config_default(&secc.cfg);
    request.protocol = JPV2G_PROTOCOL_UNKNOWN;
    request.body = &decoded_doc.supportedAppProtocolReq;
    if (assert_true(jpv2g_secc_default_handle(&secc,
                                              JPV2G_SUPP_APP_PROTOCOL_REQ,
                                              &request,
                                              response,
                                              sizeof(response),
                                              &response_len) == 0,
                    "SECC must negotiate an offer at position 20") != 0) return 1;
    if (assert_true(jpv2g_cbv2g_decode_sapp_res(
                        response, response_len, &response_doc) == 0,
                    "decode SApp response for 20-offer request") != 0) return 1;
    if (assert_true(response_doc.ResponseCode ==
                            appHand_responseCodeType_OK_SuccessfulNegotiation &&
                        response_doc.SchemaID_isUsed && response_doc.SchemaID == 77,
                    "SECC must select the supported 20th DIN offer") != 0) return 1;

    struct appHand_supportedAppProtocolReq mixed;
    init_appHand_supportedAppProtocolReq(&mixed);
    mixed.AppProtocol.arrayLen = 2;
    set_app_offer(&mixed.AppProtocol.array[0],
                  "urn:iso:15118:2:2010:MsgDef",
                  10,
                  1);
    set_app_offer(&mixed.AppProtocol.array[1],
                  "urn:iso:15118:2:2013:MsgDef",
                  13,
                  2);
    request.body = &mixed;
    response_len = 0;
    if (assert_true(jpv2g_secc_default_handle(&secc,
                                              JPV2G_SUPP_APP_PROTOCOL_REQ,
                                              &request,
                                              response,
                                              sizeof(response),
                                              &response_len) == 0,
                    "SECC must answer mixed ISO-2010/2013 offers") != 0) return 1;
    if (assert_true(jpv2g_cbv2g_decode_sapp_res(
                        response, response_len, &response_doc) == 0,
                    "decode mixed-schema SApp response") != 0) return 1;
    if (assert_true(response_doc.ResponseCode ==
                            appHand_responseCodeType_OK_SuccessfulNegotiation &&
                        response_doc.SchemaID_isUsed && response_doc.SchemaID == 13,
                    "selected SchemaID must belong to the supported ISO-2013 offer") != 0) return 1;

    mixed.AppProtocol.arrayLen = 1;
    set_app_offer_version(&mixed.AppProtocol.array[0],
                          "urn:iso:15118:2:2013:MsgDef",
                          2,
                          7,
                          27,
                          1);
    if (assert_true(negotiate_app_protocol(&secc, &mixed, &response_doc) == 0 &&
                        response_doc.ResponseCode ==
                            appHand_responseCodeType_OK_SuccessfulNegotiationWithMinorDeviation &&
                        response_doc.SchemaID_isUsed && response_doc.SchemaID == 27,
                    "matching namespace/major with different minor must negotiate with deviation") != 0) return 1;

    mixed.AppProtocol.arrayLen = 3;
    set_app_offer_version(&mixed.AppProtocol.array[0],
                          "urn:iso:15118:2:2013:MsgDef",
                          2,
                          0,
                          30,
                          3);
    set_app_offer_version(&mixed.AppProtocol.array[1],
                          "urn:din:70121:2012:MsgDef",
                          2,
                          4,
                          31,
                          1);
    set_app_offer_version(&mixed.AppProtocol.array[2],
                          "urn:iso:15118:2:2013:MsgDef",
                          2,
                          0,
                          32,
                          2);
    if (assert_true(negotiate_app_protocol(&secc, &mixed, &response_doc) == 0 &&
                        response_doc.ResponseCode ==
                            appHand_responseCodeType_OK_SuccessfulNegotiationWithMinorDeviation &&
                        response_doc.SchemaID_isUsed && response_doc.SchemaID == 31,
                    "EV priority must outrank a lower-priority exact-minor offer") != 0) return 1;

    mixed.AppProtocol.arrayLen = 2;
    set_app_offer_version(&mixed.AppProtocol.array[0],
                          "urn:din:70121:2012:MsgDef",
                          1,
                          0,
                          40,
                          1);
    set_app_offer_version(&mixed.AppProtocol.array[1],
                          "urn:iso:15118:2:2013:MsgDef",
                          2,
                          0,
                          41,
                          2);
    if (assert_true(negotiate_app_protocol(&secc, &mixed, &response_doc) == 0 &&
                        response_doc.ResponseCode ==
                            appHand_responseCodeType_OK_SuccessfulNegotiation &&
                        response_doc.SchemaID_isUsed && response_doc.SchemaID == 41,
                    "major-version mismatch must fall through to the next supported offer") != 0) return 1;

    mixed.AppProtocol.arrayLen = 1;
    set_app_offer_version(&mixed.AppProtocol.array[0],
                          "urn:iso:15118:2:2013:MsgDef",
                          1,
                          0,
                          50,
                          1);
    if (assert_true(negotiate_app_protocol(&secc, &mixed, &response_doc) == 0 &&
                        response_doc.ResponseCode ==
                            appHand_responseCodeType_Failed_NoNegotiation &&
                        !response_doc.SchemaID_isUsed,
                    "major-version mismatch alone must fail without SchemaID") != 0) return 1;

    set_app_offer(&mixed.AppProtocol.array[0],
                  "urn:iso:15118:2:2010:MsgDef",
                  10,
                  1);
    request.body = &mixed;
    response_len = 0;
    if (assert_true(jpv2g_secc_default_handle(&secc,
                                              JPV2G_SUPP_APP_PROTOCOL_REQ,
                                              &request,
                                              response,
                                              sizeof(response),
                                              &response_len) == 0,
                    "SECC must encode Failed_NoNegotiation") != 0) return 1;
    if (assert_true(jpv2g_cbv2g_decode_sapp_res(
                        response, response_len, &response_doc) == 0,
                    "decode Failed_NoNegotiation response") != 0) return 1;
    if (assert_true(response_doc.ResponseCode ==
                            appHand_responseCodeType_Failed_NoNegotiation &&
                        !response_doc.SchemaID_isUsed,
                    "Failed_NoNegotiation must omit optional SchemaID") != 0) return 1;
    return 0;
}

static int test_din_dc_interop_responses(void) {
    static const uint8_t session_id[din_sessionIDType_BYTES_SIZE] =
        {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    uint8_t response[JPV2G_MAX_EXI_SIZE];
    size_t response_len = 0;
    jpv2g_secc_t secc;
    jpv2g_secc_request_t request;
    struct din_MessageHeaderType header;
    struct din_ServiceDiscoveryReqType discovery;
    struct din_ChargeParameterDiscoveryReqType cpd;
    struct din_exiDocument decoded;

    memset(&secc, 0, sizeof(secc));
    memset(&request, 0, sizeof(request));
    jpv2g_secc_config_default(&secc.cfg);
    memcpy(secc.session_id, session_id, sizeof(session_id));
    init_din_MessageHeaderType(&header);
    memcpy(header.SessionID.bytes, session_id, sizeof(session_id));
    header.SessionID.bytesLen = sizeof(session_id);
    init_din_ServiceDiscoveryReqType(&discovery);
    request.protocol = JPV2G_PROTOCOL_DIN70121;
    request.din_header = &header;
    request.body = &discovery;

    if (assert_true(jpv2g_secc_default_handle(&secc,
                                              JPV2G_SERVICE_DISCOVERY_REQ,
                                              &request,
                                              response,
                                              sizeof(response),
                                              &response_len) == 0,
                    "encode default DIN ServiceDiscovery") != 0) return 1;
    if (assert_true(decode_din_document(response, response_len, &decoded) == 0 &&
                        decoded.V2G_Message.Body.ServiceDiscoveryRes_isUsed,
                    "decode default DIN ServiceDiscovery") != 0) return 1;
    if (assert_true(decoded.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.EnergyTransferType ==
                            din_EVSESupportedEnergyTransferType_DC_extended,
                    "CCS DIN ServiceDiscovery must advertise DC_extended") != 0) return 1;

    strcpy(secc.cfg.supported_energy_modes, "DC_core");
    response_len = 0;
    if (assert_true(jpv2g_secc_default_handle(&secc,
                                              JPV2G_SERVICE_DISCOVERY_REQ,
                                              &request,
                                              response,
                                              sizeof(response),
                                              &response_len) == 0,
                    "encode core-only DIN ServiceDiscovery") != 0) return 1;
    if (assert_true(decode_din_document(response, response_len, &decoded) == 0 &&
                        decoded.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.EnergyTransferType ==
                            din_EVSESupportedEnergyTransferType_DC_core,
                    "core-only hardware configuration must advertise DC_core") != 0) return 1;

    jpv2g_secc_config_default(&secc.cfg);
    init_din_ChargeParameterDiscoveryReqType(&cpd);
    cpd.EVRequestedEnergyTransferType = din_EVRequestedEnergyTransferType_DC_core;
    cpd.DC_EVChargeParameter_isUsed = 1;
    init_din_DC_EVChargeParameterType(&cpd.DC_EVChargeParameter);
    request.body = &cpd;
    response_len = 0;
    if (assert_true(jpv2g_secc_default_handle(&secc,
                                              JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ,
                                              &request,
                                              response,
                                              sizeof(response),
                                              &response_len) == 0,
                    "encode DIN DC_core CPD response") != 0) return 1;
    if (assert_true(decode_din_document(response, response_len, &decoded) == 0,
                    "decode DIN DC_core CPD response") != 0) return 1;
    struct din_ChargeParameterDiscoveryResType *cpd_res =
        &decoded.V2G_Message.Body.ChargeParameterDiscoveryRes;
    if (assert_true(decoded.V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed &&
                        cpd_res->ResponseCode == din_responseCodeType_OK &&
                        cpd_res->SAScheduleList_isUsed &&
                        cpd_res->SAScheduleList.SAScheduleTuple.arrayLen == 1,
                    "Finished DIN CPD must include one usable schedule") != 0) return 1;
    struct din_SAScheduleTupleType *tuple = &cpd_res->SAScheduleList.SAScheduleTuple.array[0];
    if (assert_true(tuple->SAScheduleTupleID == 1 &&
                        tuple->PMaxSchedule.PMaxScheduleID == 1 &&
                        tuple->PMaxSchedule.PMaxScheduleEntry.arrayLen == 1 &&
                        tuple->PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval.start == 0 &&
                        tuple->PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval.duration_isUsed &&
                        tuple->PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval.duration == 86400 &&
                        tuple->PMaxSchedule.PMaxScheduleEntry.array[0].PMax == 32767,
                    "DIN schedule IDs, interval and PMax must be deterministic") != 0) return 1;

    cpd.EVRequestedEnergyTransferType = din_EVRequestedEnergyTransferType_DC_extended;
    response_len = 0;
    if (assert_true(jpv2g_secc_default_handle(&secc,
                                              JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ,
                                              &request,
                                              response,
                                              sizeof(response),
                                              &response_len) == 0 &&
                        decode_din_document(response, response_len, &decoded) == 0 &&
                        decoded.V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode ==
                            din_responseCodeType_OK,
                    "configured DIN DC_extended request must remain accepted") != 0) return 1;

    cpd.EVRequestedEnergyTransferType = din_EVRequestedEnergyTransferType_AC_single_phase_core;
    response_len = 0;
    if (assert_true(jpv2g_secc_default_handle(&secc,
                                              JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ,
                                              &request,
                                              response,
                                              sizeof(response),
                                              &response_len) == 0 &&
                        decode_din_document(response, response_len, &decoded) == 0 &&
                        decoded.V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode ==
                            din_responseCodeType_FAILED_WrongEnergyTransferType,
                    "DC-only hardware must reject a DIN AC transfer request cleanly") != 0) return 1;

    response_len = 0;
    if (assert_true(jpv2g_cbv2g_encode_din_charge_parameter_discovery_res(
                        session_id,
                        din_responseCodeType_OK,
                        din_EVSEProcessingType_Ongoing,
                        NULL,
                        response,
                        sizeof(response),
                        &response_len) == 0 &&
                        decode_din_document(response, response_len, &decoded) == 0,
                    "encode/decode DIN Ongoing CPD response") != 0) return 1;
    cpd_res = &decoded.V2G_Message.Body.ChargeParameterDiscoveryRes;
    if (assert_true(!cpd_res->SAScheduleList_isUsed && cpd_res->SASchedules_isUsed,
                    "DIN Ongoing CPD must omit the concrete Finished-only schedule") != 0) return 1;
    return 0;
}

static int test_iso_dc_transition_response_round_trip(void) {
    static const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE] =
        {0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98};
    uint8_t encoded[JPV2G_MAX_EXI_SIZE];
    size_t encoded_len = 0;

    struct iso2_ChargeParameterDiscoveryResType cpd;
    struct iso2_ChargeParameterDiscoveryResType decoded_cpd;
    init_iso2_ChargeParameterDiscoveryResType(&cpd);
    cpd.ResponseCode = iso2_responseCodeType_OK;
    cpd.EVSEProcessing = iso2_EVSEProcessingType_Ongoing;
    cpd.DC_EVSEChargeParameter_isUsed = 1;
    transition_fill_iso_cpd_limits(&cpd.DC_EVSEChargeParameter, 0);
    if (assert_true(jpv2g_cbv2g_encode_charge_parameter_discovery_res_payload(
                        session_id,
                        &cpd,
                        encoded,
                        sizeof(encoded),
                        &encoded_len) == 0 &&
                        jpv2g_cbv2g_decode_charge_parameter_discovery_res(
                            encoded, encoded_len, &decoded_cpd) == 0,
                    "ISO CPD OK/Ongoing must encode and decode") != 0) return 1;
    if (assert_true(decoded_cpd.ResponseCode == iso2_responseCodeType_OK &&
                        decoded_cpd.EVSEProcessing == iso2_EVSEProcessingType_Ongoing &&
                        decoded_cpd.DC_EVSEChargeParameter_isUsed &&
                        !decoded_cpd.SAScheduleList_isUsed &&
                        !decoded_cpd.SASchedules_isUsed &&
                        decoded_cpd.DC_EVSEChargeParameter.DC_EVSEStatus.EVSEStatusCode ==
                            iso2_DC_EVSEStatusCodeType_EVSE_NotReady &&
                        transition_iso_physical_equals(
                            &decoded_cpd.DC_EVSEChargeParameter.EVSEMaximumVoltageLimit,
                            iso2_unitSymbolType_V,
                            0,
                            0) &&
                        transition_iso_physical_equals(
                            &decoded_cpd.DC_EVSEChargeParameter.EVSEMaximumCurrentLimit,
                            iso2_unitSymbolType_A,
                            0,
                            0) &&
                        transition_iso_physical_equals(
                            &decoded_cpd.DC_EVSEChargeParameter.EVSEMaximumPowerLimit,
                            iso2_unitSymbolType_W,
                            0,
                            0),
                    "ISO CPD Ongoing must remain NotReady with zero limits and no schedule") != 0) return 1;

    init_iso2_ChargeParameterDiscoveryResType(&cpd);
    cpd.ResponseCode = iso2_responseCodeType_OK;
    cpd.EVSEProcessing = iso2_EVSEProcessingType_Finished;
    cpd.DC_EVSEChargeParameter_isUsed = 1;
    transition_fill_iso_cpd_limits(&cpd.DC_EVSEChargeParameter, 1);
    transition_fill_iso_schedule(&cpd);
    encoded_len = 0;
    if (assert_true(jpv2g_cbv2g_encode_charge_parameter_discovery_res_payload(
                        session_id,
                        &cpd,
                        encoded,
                        sizeof(encoded),
                        &encoded_len) == 0 &&
                        jpv2g_cbv2g_decode_charge_parameter_discovery_res(
                            encoded, encoded_len, &decoded_cpd) == 0,
                    "ISO CPD OK/Finished must encode and decode") != 0) return 1;
    const struct iso2_SAScheduleTupleType *iso_tuple =
        &decoded_cpd.SAScheduleList.SAScheduleTuple.array[0];
    if (assert_true(decoded_cpd.ResponseCode == iso2_responseCodeType_OK &&
                        decoded_cpd.EVSEProcessing == iso2_EVSEProcessingType_Finished &&
                        decoded_cpd.DC_EVSEChargeParameter_isUsed &&
                        decoded_cpd.DC_EVSEChargeParameter.DC_EVSEStatus.EVSEStatusCode ==
                            iso2_DC_EVSEStatusCodeType_EVSE_Ready &&
                        decoded_cpd.DC_EVSEChargeParameter.DC_EVSEStatus.EVSEIsolationStatus_isUsed &&
                        decoded_cpd.DC_EVSEChargeParameter.DC_EVSEStatus.EVSEIsolationStatus ==
                            iso2_isolationLevelType_Valid &&
                        transition_iso_physical_equals(
                            &decoded_cpd.DC_EVSEChargeParameter.EVSEMaximumVoltageLimit,
                            iso2_unitSymbolType_V,
                            500,
                            0) &&
                        transition_iso_physical_equals(
                            &decoded_cpd.DC_EVSEChargeParameter.EVSEMaximumCurrentLimit,
                            iso2_unitSymbolType_A,
                            120,
                            0) &&
                        transition_iso_physical_equals(
                            &decoded_cpd.DC_EVSEChargeParameter.EVSEMaximumPowerLimit,
                            iso2_unitSymbolType_W,
                            60,
                            3) &&
                        decoded_cpd.SAScheduleList_isUsed &&
                        decoded_cpd.SAScheduleList.SAScheduleTuple.arrayLen == 1 &&
                        iso_tuple->SAScheduleTupleID == 7 &&
                        iso_tuple->PMaxSchedule.PMaxScheduleEntry.arrayLen == 1 &&
                        iso_tuple->PMaxSchedule.PMaxScheduleEntry.array[0]
                                .RelativeTimeInterval.duration_isUsed &&
                        iso_tuple->PMaxSchedule.PMaxScheduleEntry.array[0]
                                .RelativeTimeInterval.duration == 86400 &&
                        transition_iso_physical_equals(
                            &iso_tuple->PMaxSchedule.PMaxScheduleEntry.array[0].PMax,
                            iso2_unitSymbolType_W,
                            60,
                            3),
                    "ISO CPD Finished must retain real EVSE limits and 60 kW schedule") != 0) return 1;

    struct iso2_CableCheckResType cable_check;
    struct iso2_CableCheckResType decoded_cable_check;
    init_iso2_CableCheckResType(&cable_check);
    cable_check.ResponseCode = iso2_responseCodeType_OK;
    cable_check.EVSEProcessing = iso2_EVSEProcessingType_Ongoing;
    transition_set_iso_status(
        &cable_check.DC_EVSEStatus,
        iso2_DC_EVSEStatusCodeType_EVSE_IsolationMonitoringActive,
        0);
    encoded_len = 0;
    if (assert_true(jpv2g_cbv2g_encode_cable_check_res(
                        session_id,
                        iso2_responseCodeType_OK,
                        iso2_EVSEProcessingType_Ongoing,
                        &cable_check,
                        encoded,
                        sizeof(encoded),
                        &encoded_len) == 0 &&
                        jpv2g_cbv2g_decode_cable_check_res(
                            encoded, encoded_len, &decoded_cable_check) == 0,
                    "ISO CableCheck OK/Ongoing must encode and decode") != 0) return 1;
    if (assert_true(decoded_cable_check.ResponseCode == iso2_responseCodeType_OK &&
                        decoded_cable_check.EVSEProcessing == iso2_EVSEProcessingType_Ongoing &&
                        decoded_cable_check.DC_EVSEStatus.EVSEStatusCode ==
                            iso2_DC_EVSEStatusCodeType_EVSE_IsolationMonitoringActive &&
                        !decoded_cable_check.DC_EVSEStatus.EVSEIsolationStatus_isUsed,
                    "ISO CableCheck Ongoing must preserve IsolationMonitoringActive") != 0) return 1;

    init_iso2_CableCheckResType(&cable_check);
    cable_check.ResponseCode = iso2_responseCodeType_OK;
    cable_check.EVSEProcessing = iso2_EVSEProcessingType_Finished;
    transition_set_iso_status(
        &cable_check.DC_EVSEStatus,
        iso2_DC_EVSEStatusCodeType_EVSE_Ready,
        1);
    encoded_len = 0;
    if (assert_true(jpv2g_cbv2g_encode_cable_check_res(
                        session_id,
                        iso2_responseCodeType_OK,
                        iso2_EVSEProcessingType_Finished,
                        &cable_check,
                        encoded,
                        sizeof(encoded),
                        &encoded_len) == 0 &&
                        jpv2g_cbv2g_decode_cable_check_res(
                            encoded, encoded_len, &decoded_cable_check) == 0,
                    "ISO CableCheck OK/Finished must encode and decode") != 0) return 1;
    if (assert_true(decoded_cable_check.ResponseCode == iso2_responseCodeType_OK &&
                        decoded_cable_check.EVSEProcessing == iso2_EVSEProcessingType_Finished &&
                        decoded_cable_check.DC_EVSEStatus.EVSEStatusCode ==
                            iso2_DC_EVSEStatusCodeType_EVSE_Ready &&
                        decoded_cable_check.DC_EVSEStatus.EVSEIsolationStatus_isUsed &&
                        decoded_cable_check.DC_EVSEStatus.EVSEIsolationStatus ==
                            iso2_isolationLevelType_Valid,
                    "ISO CableCheck Finished must preserve Ready plus Valid isolation") != 0) return 1;

    struct iso2_PreChargeResType precharge;
    struct iso2_PreChargeResType decoded_precharge;
    init_iso2_PreChargeResType(&precharge);
    precharge.ResponseCode = iso2_responseCodeType_OK;
    transition_set_iso_status(
        &precharge.DC_EVSEStatus,
        iso2_DC_EVSEStatusCodeType_EVSE_NotReady,
        1);
    transition_set_iso_physical(
        &precharge.EVSEPresentVoltage, iso2_unitSymbolType_V, 0, 0);
    encoded_len = 0;
    if (assert_true(jpv2g_cbv2g_encode_pre_charge_res(
                        session_id,
                        iso2_responseCodeType_OK,
                        &precharge,
                        encoded,
                        sizeof(encoded),
                        &encoded_len) == 0 &&
                        jpv2g_cbv2g_decode_pre_charge_res(
                            encoded, encoded_len, &decoded_precharge) == 0,
                    "first ISO PreCharge NotReady/0 V must encode and decode") != 0) return 1;
    if (assert_true(decoded_precharge.ResponseCode == iso2_responseCodeType_OK &&
                        decoded_precharge.DC_EVSEStatus.EVSEStatusCode ==
                            iso2_DC_EVSEStatusCodeType_EVSE_NotReady &&
                        transition_iso_physical_equals(
                            &decoded_precharge.EVSEPresentVoltage,
                            iso2_unitSymbolType_V,
                            0,
                            0),
                    "first ISO PreCharge must remain NotReady at zero volts") != 0) return 1;

    init_iso2_PreChargeResType(&precharge);
    precharge.ResponseCode = iso2_responseCodeType_OK;
    transition_set_iso_status(
        &precharge.DC_EVSEStatus,
        iso2_DC_EVSEStatusCodeType_EVSE_Ready,
        1);
    transition_set_iso_physical(
        &precharge.EVSEPresentVoltage, iso2_unitSymbolType_V, 360, 0);
    encoded_len = 0;
    if (assert_true(jpv2g_cbv2g_encode_pre_charge_res(
                        session_id,
                        iso2_responseCodeType_OK,
                        &precharge,
                        encoded,
                        sizeof(encoded),
                        &encoded_len) == 0 &&
                        jpv2g_cbv2g_decode_pre_charge_res(
                            encoded, encoded_len, &decoded_precharge) == 0,
                    "matching-target ISO PreCharge Ready voltage must encode and decode") != 0) return 1;
    if (assert_true(decoded_precharge.ResponseCode == iso2_responseCodeType_OK &&
                        decoded_precharge.DC_EVSEStatus.EVSEStatusCode ==
                            iso2_DC_EVSEStatusCodeType_EVSE_Ready &&
                        transition_iso_physical_equals(
                            &decoded_precharge.EVSEPresentVoltage,
                            iso2_unitSymbolType_V,
                            360,
                            0),
                    "matching-target ISO PreCharge must preserve Ready at 360 V") != 0) return 1;
    return 0;
}

static int test_din_dc_transition_response_round_trip(void) {
    static const uint8_t session_id[din_sessionIDType_BYTES_SIZE] =
        {0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97, 0xA8};
    uint8_t encoded[JPV2G_MAX_EXI_SIZE];
    size_t encoded_len = 0;
    struct din_exiDocument decoded;
    struct din_DC_EVSEChargeParameterType limits;

    transition_fill_din_cpd_limits(&limits, 0);
    if (assert_true(jpv2g_cbv2g_encode_din_charge_parameter_discovery_res(
                        session_id,
                        din_responseCodeType_OK,
                        din_EVSEProcessingType_Ongoing,
                        &limits,
                        encoded,
                        sizeof(encoded),
                        &encoded_len) == 0 &&
                        decode_din_document(encoded, encoded_len, &decoded) == 0,
                    "DIN CPD OK/Ongoing must encode and decode") != 0) return 1;
    const struct din_ChargeParameterDiscoveryResType *decoded_cpd =
        &decoded.V2G_Message.Body.ChargeParameterDiscoveryRes;
    if (assert_true(decoded.V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed &&
                        decoded_cpd->ResponseCode == din_responseCodeType_OK &&
                        decoded_cpd->EVSEProcessing == din_EVSEProcessingType_Ongoing &&
                        decoded_cpd->DC_EVSEChargeParameter_isUsed &&
                        !decoded_cpd->SAScheduleList_isUsed &&
                        decoded_cpd->SASchedules_isUsed &&
                        decoded_cpd->DC_EVSEChargeParameter.DC_EVSEStatus.EVSEStatusCode ==
                            din_DC_EVSEStatusCodeType_EVSE_NotReady &&
                        transition_din_physical_equals(
                            &decoded_cpd->DC_EVSEChargeParameter.EVSEMaximumVoltageLimit,
                            din_unitSymbolType_V,
                            0,
                            0) &&
                        transition_din_physical_equals(
                            &decoded_cpd->DC_EVSEChargeParameter.EVSEMaximumCurrentLimit,
                            din_unitSymbolType_A,
                            0,
                            0) &&
                        transition_din_physical_equals(
                            &decoded_cpd->DC_EVSEChargeParameter.EVSEMaximumPowerLimit,
                            din_unitSymbolType_W,
                            0,
                            0),
                    "DIN CPD Ongoing must remain NotReady with zero limits and no concrete schedule") != 0) return 1;

    transition_fill_din_cpd_limits(&limits, 1);
    encoded_len = 0;
    if (assert_true(jpv2g_cbv2g_encode_din_charge_parameter_discovery_res(
                        session_id,
                        din_responseCodeType_OK,
                        din_EVSEProcessingType_Finished,
                        &limits,
                        encoded,
                        sizeof(encoded),
                        &encoded_len) == 0 &&
                        decode_din_document(encoded, encoded_len, &decoded) == 0,
                    "DIN CPD OK/Finished must encode and decode") != 0) return 1;
    decoded_cpd = &decoded.V2G_Message.Body.ChargeParameterDiscoveryRes;
    const struct din_SAScheduleTupleType *din_tuple =
        &decoded_cpd->SAScheduleList.SAScheduleTuple.array[0];
    if (assert_true(decoded_cpd->ResponseCode == din_responseCodeType_OK &&
                        decoded_cpd->EVSEProcessing == din_EVSEProcessingType_Finished &&
                        decoded_cpd->DC_EVSEChargeParameter_isUsed &&
                        decoded_cpd->DC_EVSEChargeParameter.DC_EVSEStatus.EVSEStatusCode ==
                            din_DC_EVSEStatusCodeType_EVSE_Ready &&
                        decoded_cpd->DC_EVSEChargeParameter.DC_EVSEStatus.EVSEIsolationStatus_isUsed &&
                        decoded_cpd->DC_EVSEChargeParameter.DC_EVSEStatus.EVSEIsolationStatus ==
                            din_isolationLevelType_Valid &&
                        transition_din_physical_equals(
                            &decoded_cpd->DC_EVSEChargeParameter.EVSEMaximumVoltageLimit,
                            din_unitSymbolType_V,
                            500,
                            0) &&
                        transition_din_physical_equals(
                            &decoded_cpd->DC_EVSEChargeParameter.EVSEMaximumCurrentLimit,
                            din_unitSymbolType_A,
                            120,
                            0) &&
                        transition_din_physical_equals(
                            &decoded_cpd->DC_EVSEChargeParameter.EVSEMaximumPowerLimit,
                            din_unitSymbolType_W,
                            60,
                            3) &&
                        decoded_cpd->SAScheduleList_isUsed &&
                        decoded_cpd->SAScheduleList.SAScheduleTuple.arrayLen == 1 &&
                        din_tuple->SAScheduleTupleID == 1 &&
                        din_tuple->PMaxSchedule.PMaxScheduleID == 1 &&
                        din_tuple->PMaxSchedule.PMaxScheduleEntry.arrayLen == 1 &&
                        din_tuple->PMaxSchedule.PMaxScheduleEntry.array[0].PMax == 32767,
                    "DIN CPD Finished must retain real limits and a valid concrete schedule") != 0) return 1;

    struct din_CableCheckResType cable_check;
    init_din_CableCheckResType(&cable_check);
    cable_check.ResponseCode = din_responseCodeType_OK;
    cable_check.EVSEProcessing = din_EVSEProcessingType_Ongoing;
    transition_set_din_status(
        &cable_check.DC_EVSEStatus,
        din_DC_EVSEStatusCodeType_EVSE_IsolationMonitoringActive,
        0);
    encoded_len = 0;
    if (assert_true(jpv2g_cbv2g_encode_din_cable_check_res(
                        session_id,
                        din_responseCodeType_OK,
                        din_EVSEProcessingType_Ongoing,
                        &cable_check,
                        encoded,
                        sizeof(encoded),
                        &encoded_len) == 0 &&
                        decode_din_document(encoded, encoded_len, &decoded) == 0,
                    "DIN CableCheck OK/Ongoing must encode and decode") != 0) return 1;
    const struct din_CableCheckResType *decoded_cable_check =
        &decoded.V2G_Message.Body.CableCheckRes;
    if (assert_true(decoded.V2G_Message.Body.CableCheckRes_isUsed &&
                        decoded_cable_check->ResponseCode == din_responseCodeType_OK &&
                        decoded_cable_check->EVSEProcessing == din_EVSEProcessingType_Ongoing &&
                        decoded_cable_check->DC_EVSEStatus.EVSEStatusCode ==
                            din_DC_EVSEStatusCodeType_EVSE_IsolationMonitoringActive &&
                        !decoded_cable_check->DC_EVSEStatus.EVSEIsolationStatus_isUsed,
                    "DIN CableCheck Ongoing must preserve IsolationMonitoringActive") != 0) return 1;

    init_din_CableCheckResType(&cable_check);
    cable_check.ResponseCode = din_responseCodeType_OK;
    cable_check.EVSEProcessing = din_EVSEProcessingType_Finished;
    transition_set_din_status(
        &cable_check.DC_EVSEStatus,
        din_DC_EVSEStatusCodeType_EVSE_Ready,
        1);
    encoded_len = 0;
    if (assert_true(jpv2g_cbv2g_encode_din_cable_check_res(
                        session_id,
                        din_responseCodeType_OK,
                        din_EVSEProcessingType_Finished,
                        &cable_check,
                        encoded,
                        sizeof(encoded),
                        &encoded_len) == 0 &&
                        decode_din_document(encoded, encoded_len, &decoded) == 0,
                    "DIN CableCheck OK/Finished must encode and decode") != 0) return 1;
    decoded_cable_check = &decoded.V2G_Message.Body.CableCheckRes;
    if (assert_true(decoded_cable_check->ResponseCode == din_responseCodeType_OK &&
                        decoded_cable_check->EVSEProcessing == din_EVSEProcessingType_Finished &&
                        decoded_cable_check->DC_EVSEStatus.EVSEStatusCode ==
                            din_DC_EVSEStatusCodeType_EVSE_Ready &&
                        decoded_cable_check->DC_EVSEStatus.EVSEIsolationStatus_isUsed &&
                        decoded_cable_check->DC_EVSEStatus.EVSEIsolationStatus ==
                            din_isolationLevelType_Valid,
                    "DIN CableCheck Finished must preserve Ready plus Valid isolation") != 0) return 1;

    struct din_PreChargeResType precharge;
    init_din_PreChargeResType(&precharge);
    precharge.ResponseCode = din_responseCodeType_OK;
    transition_set_din_status(
        &precharge.DC_EVSEStatus,
        din_DC_EVSEStatusCodeType_EVSE_NotReady,
        1);
    transition_set_din_physical(
        &precharge.EVSEPresentVoltage, din_unitSymbolType_V, 0, 0);
    encoded_len = 0;
    if (assert_true(jpv2g_cbv2g_encode_din_pre_charge_res(
                        session_id,
                        din_responseCodeType_OK,
                        &precharge,
                        encoded,
                        sizeof(encoded),
                        &encoded_len) == 0 &&
                        decode_din_document(encoded, encoded_len, &decoded) == 0,
                    "first DIN PreCharge NotReady/0 V must encode and decode") != 0) return 1;
    const struct din_PreChargeResType *decoded_precharge =
        &decoded.V2G_Message.Body.PreChargeRes;
    if (assert_true(decoded.V2G_Message.Body.PreChargeRes_isUsed &&
                        decoded_precharge->ResponseCode == din_responseCodeType_OK &&
                        decoded_precharge->DC_EVSEStatus.EVSEStatusCode ==
                            din_DC_EVSEStatusCodeType_EVSE_NotReady &&
                        transition_din_physical_equals(
                            &decoded_precharge->EVSEPresentVoltage,
                            din_unitSymbolType_V,
                            0,
                            0),
                    "first DIN PreCharge must remain NotReady at zero volts") != 0) return 1;

    init_din_PreChargeResType(&precharge);
    precharge.ResponseCode = din_responseCodeType_OK;
    transition_set_din_status(
        &precharge.DC_EVSEStatus,
        din_DC_EVSEStatusCodeType_EVSE_Ready,
        1);
    transition_set_din_physical(
        &precharge.EVSEPresentVoltage, din_unitSymbolType_V, 360, 0);
    encoded_len = 0;
    if (assert_true(jpv2g_cbv2g_encode_din_pre_charge_res(
                        session_id,
                        din_responseCodeType_OK,
                        &precharge,
                        encoded,
                        sizeof(encoded),
                        &encoded_len) == 0 &&
                        decode_din_document(encoded, encoded_len, &decoded) == 0,
                    "matching-target DIN PreCharge Ready voltage must encode and decode") != 0) return 1;
    decoded_precharge = &decoded.V2G_Message.Body.PreChargeRes;
    if (assert_true(decoded_precharge->ResponseCode == din_responseCodeType_OK &&
                        decoded_precharge->DC_EVSEStatus.EVSEStatusCode ==
                            din_DC_EVSEStatusCodeType_EVSE_Ready &&
                        transition_din_physical_equals(
                            &decoded_precharge->EVSEPresentVoltage,
                            din_unitSymbolType_V,
                            360,
                            0),
                    "matching-target DIN PreCharge must preserve Ready at 360 V") != 0) return 1;
    return 0;
}

static int test_iso_pause_resume(void) {
    static const uint8_t paused_sid[iso2_sessionIDType_BYTES_SIZE] =
        {0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28};
    uint8_t response[JPV2G_MAX_EXI_SIZE];
    uint8_t response_sid[iso2_sessionIDType_BYTES_SIZE] = {0};
    size_t response_len = 0;
    jpv2g_secc_t secc;
    jpv2g_secc_request_t request;
    struct iso2_MessageHeaderType header;
    struct iso2_SessionStopReqType stop;
    struct iso2_SessionSetupReqType setup;
    struct iso2_SessionSetupResType setup_res;

    memset(&secc, 0, sizeof(secc));
    memset(&request, 0, sizeof(request));
    jpv2g_secc_config_default(&secc.cfg);
    memcpy(secc.session_id, paused_sid, sizeof(paused_sid));
    init_iso2_MessageHeaderType(&header);
    memcpy(header.SessionID.bytes, paused_sid, sizeof(paused_sid));
    header.SessionID.bytesLen = sizeof(paused_sid);
    init_iso2_SessionStopReqType(&stop);
    stop.ChargingSession = iso2_chargingSessionType_Pause;
    request.protocol = JPV2G_PROTOCOL_ISO15118_2;
    request.header = &header;
    request.body = &stop;

    if (assert_true(jpv2g_secc_default_handle(&secc,
                                              JPV2G_SESSION_STOP_REQ,
                                              &request,
                                              response,
                                              sizeof(response),
                                              &response_len) == 0,
                    "ISO SessionStop(Pause) must be answered") != 0) return 1;
    if (assert_true(memcmp(secc.last_session_id, paused_sid, sizeof(paused_sid)) == 0,
                    "Pause must retain the resumable SessionID") != 0) return 1;
    const uint8_t zero_sid[iso2_sessionIDType_BYTES_SIZE] = {0};
    if (assert_true(memcmp(secc.session_id, zero_sid, sizeof(zero_sid)) == 0,
                    "Pause must retire the live SessionID") != 0) return 1;

    init_iso2_SessionSetupReqType(&setup);
    request.body = &setup;
    response_len = 0;
    if (assert_true(jpv2g_secc_default_handle(&secc,
                                              JPV2G_SESSION_SETUP_REQ,
                                              &request,
                                              response,
                                              sizeof(response),
                                              &response_len) == 0,
                    "SessionSetup must resume a retained pause") != 0) return 1;
    if (assert_true(jpv2g_cbv2g_decode_session_setup_res(
                        response, response_len, &setup_res, response_sid) == 0,
                    "decode resumed SessionSetup response") != 0) return 1;
    if (assert_true(setup_res.ResponseCode == iso2_responseCodeType_OK_OldSessionJoined &&
                        memcmp(response_sid, paused_sid, sizeof(paused_sid)) == 0,
                    "valid paused SID must receive OK_OldSessionJoined") != 0) return 1;
    return 0;
}

static int test_secc_session_id_validation(void) {
    jpv2g_secc_t secc;
    jpv2g_secc_request_t req;
    struct iso2_MessageHeaderType header;
    memset(&secc, 0, sizeof(secc));
    memset(&req, 0, sizeof(req));
    memset(&header, 0, sizeof(header));
    req.protocol = JPV2G_PROTOCOL_ISO15118_2;
    req.header = &header;

    if (assert_true(jpv2g_secc_validate_request_session(&secc,
                                                        JPV2G_SESSION_SETUP_REQ,
                                                        &req) == 0,
                    "new SessionSetup may omit SessionID") != 0) return 1;
    header.SessionID.bytesLen = 3;
    if (assert_true(jpv2g_secc_validate_request_session(&secc,
                                                        JPV2G_SESSION_SETUP_REQ,
                                                        &req) == -EINVAL,
                    "malformed SessionSetup SessionID length must be rejected") != 0) return 1;

    for (size_t i = 0; i < sizeof(secc.session_id); ++i) secc.session_id[i] = (uint8_t)(i + 1);
    header.SessionID.bytesLen = sizeof(header.SessionID.bytes);
    memcpy(header.SessionID.bytes, secc.session_id, sizeof(secc.session_id));
    if (assert_true(jpv2g_secc_validate_request_session(&secc,
                                                        JPV2G_SERVICE_DISCOVERY_REQ,
                                                        &req) == 0,
                    "matching active SessionID must be accepted") != 0) return 1;
    header.SessionID.bytes[0] ^= 0xFF;
    if (assert_true(jpv2g_secc_validate_request_session(&secc,
                                                        JPV2G_SERVICE_DISCOVERY_REQ,
                                                        &req) == -EACCES,
                    "stale or foreign SessionID must be rejected") != 0) return 1;
    header.SessionID.bytesLen = 0;
    if (assert_true(jpv2g_secc_validate_request_session(&secc,
                                                        JPV2G_SERVICE_DISCOVERY_REQ,
                                                        &req) == -EACCES,
                    "post-setup requests must not omit SessionID") != 0) return 1;
    return 0;
}

static int test_secc_stream_enforces_sequence(void) {
    jpv2g_codec_ctx *codec = NULL;
    jpv2g_secc_config_t cfg;
    jpv2g_secc_t secc;
    int sockets[2] = {-1, -1};
    uint8_t exi[JPV2G_MAX_EXI_SIZE];
    uint8_t frame[JPV2G_MAX_V2GTP_SIZE];
    size_t exi_len = 0;
    size_t frame_len = 0;
    const uint8_t evcc_id[iso2_evccIDType_BYTES_SIZE] = {1, 2, 3, 4, 5, 6};

    jpv2g_secc_config_default(&cfg);
    if (assert_true(jpv2g_codec_init(&codec) == 0, "codec init for stream test") != 0) return 1;
    if (assert_true(jpv2g_secc_init(&secc, &cfg, codec) == 0, "SECC init for stream test") != 0) {
        jpv2g_codec_free(codec);
        return 1;
    }
    if (assert_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0,
                    "socketpair for stream test") != 0) {
        jpv2g_codec_free(codec);
        return 1;
    }
    if (assert_true(jpv2g_cbv2g_encode_session_setup_req(
                        evcc_id, exi, sizeof(exi), &exi_len) == 0,
                    "encode out-of-order SessionSetup") != 0) return 1;
    if (assert_true(jpv2g_v2gtp_build(JPV2G_PAYLOAD_EXI,
                                      exi,
                                      exi_len,
                                      frame,
                                      sizeof(frame),
                                      &frame_len) == 0,
                    "wrap out-of-order SessionSetup") != 0) return 1;
    if (assert_true(send(sockets[1], frame, frame_len, 0) == (ssize_t)frame_len,
                    "write complete stream test frame") != 0) return 1;
    shutdown(sockets[1], SHUT_WR);

    const int rc = jpv2g_secc_handle_client(&secc, sockets[0], 100);
    if (assert_true(rc == -EPROTO,
                    "production stream dispatcher must reject SessionSetup before app negotiation") != 0) return 1;
    if (assert_true(jpv2g_secc_classify_disconnect(rc, false, false) ==
                        JPV2G_HLC_DROP_SEQUENCE_ERROR,
                    "sequence rejection must retain its diagnostic classification") != 0) return 1;

    close(sockets[0]);
    close(sockets[1]);
    jpv2g_codec_free(codec);
    return 0;
}
#endif

int main(void) {
    if (test_v2gtp_round_trip() != 0) return 1;
    if (test_evcc_state_sequence() != 0) return 1;
    if (test_secc_state_sequence() != 0) return 1;
    if (test_secc_production_sequence() != 0) return 1;
#ifdef JPV2G_ENABLE_CBV2G_CODEC
    if (test_supported_app_protocol_interop() != 0) return 1;
    if (test_din_dc_interop_responses() != 0) return 1;
    if (test_iso_dc_transition_response_round_trip() != 0) return 1;
    if (test_din_dc_transition_response_round_trip() != 0) return 1;
    if (test_iso_pause_resume() != 0) return 1;
    if (test_secc_session_id_validation() != 0) return 1;
    if (test_secc_stream_enforces_sequence() != 0) return 1;
#endif
    printf("jpv2g_unit_test: PASS\n");
    return 0;
}

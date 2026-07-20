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
#include "cbv2g_workspace.h"
#endif
#include "jpv2g/evcc.h"
#include "jpv2g/handler.h"
#include "jpv2g/secc.h"
#include "jpv2g/state_evcc.h"
#include "jpv2g/state_machine.h"
#include "jpv2g/state_secc.h"
#include "jpv2g/v2gtp.h"
#include "jpv2g/byte_utils.h"
#include "jpv2g/constants.h"

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

/*
 * Regression for the V2GTP payload-length bound (byte_utils.h
 * JPV2G_MAX_PAYLOAD_LENGTH). A V2GTP frame's 32-bit length field is
 * attacker-controlled on the CCS PLC link. Before the fix the macro was
 * UINT32_MAX, so the `payload_length > JPV2G_MAX_PAYLOAD_LENGTH` guard could
 * never fire and a length near the top of the uint32 range wrapped
 * `header + length` on 32-bit size_t, reading gigabytes into a ~4 KB on-stack
 * buffer in secc_recv_v2gtp(). secc_recv_v2gtp() is static; jpv2g_v2gtp_parse()
 * shares the exact same guard and constants, so it is the public witness for
 * the invariant. NOTE: on this 64-bit host the size_t addition does not wrap,
 * so this proves the LENGTH-BOUND guard now fires (returns -E2BIG) for any
 * oversized frame; the on-target stack-smash reproduction is 32-bit-specific
 * and belongs to HIL. The distinguishing signal is -E2BIG (guard fired) vs the
 * pre-fix -EMSGSIZE/-ENOSPC (fell through to the buffer-size check).
 */
static int test_v2gtp_length_bounds(void) {
    /* A valid maximum-size payload still round-trips. */
    static uint8_t big_payload[JPV2G_MAX_EXI_SIZE];
    for (size_t i = 0; i < sizeof(big_payload); ++i) big_payload[i] = (uint8_t)i;
    uint8_t frame[JPV2G_MAX_V2GTP_SIZE];
    size_t frame_len = 0;
    int rc = jpv2g_v2gtp_build(JPV2G_PAYLOAD_EXI, big_payload, sizeof(big_payload),
                               frame, sizeof(frame), &frame_len);
    if (assert_true(rc == 0, "max-size V2GTP payload must build") != 0) return 1;
    jpv2g_v2gtp_t parsed;
    rc = jpv2g_v2gtp_parse(frame, frame_len, &parsed);
    if (assert_true(rc == 0, "max-size V2GTP payload must parse") != 0) return 1;

    /* Hand-craft a header claiming one byte more than the EXI ceiling. Provide
     * a buffer large enough that the ONLY thing that can reject it is the length
     * guard — before the fix this fell through to validate() and was accepted
     * as a well-formed (oversized) frame. */
    uint8_t over[JPV2G_V2GTP_HEADER_LEN + 8] = {0};
    over[0] = 0x01;           /* protocol version */
    over[1] = (uint8_t)0xFE;  /* inverse version  */
    jpv2g_write_u16_be(&over[2], (uint16_t)JPV2G_PAYLOAD_EXI);
    jpv2g_write_u32_be(&over[4], (uint32_t)(JPV2G_MAX_EXI_SIZE + 1));
    jpv2g_v2gtp_t out;
    rc = jpv2g_v2gtp_parse(over, sizeof(over), &out);
    if (assert_true(rc == -E2BIG, "payload_length above the EXI ceiling must be rejected -E2BIG") != 0) return 1;

    /* The wrap trigger: a length field in 0xFFFFFFF8..0xFFFFFFFF must be
     * rejected by the length guard, never allowed to wrap the header+length
     * total. Assert the guard result, not merely "some error". */
    jpv2g_write_u32_be(&over[4], 0xFFFFFFFFu);
    rc = jpv2g_v2gtp_parse(over, sizeof(over), &out);
    if (assert_true(rc == -E2BIG, "max-uint32 payload_length must hit the length guard, not wrap") != 0) return 1;
    jpv2g_write_u32_be(&over[4], 0xFFFFFFF8u);
    rc = jpv2g_v2gtp_parse(over, sizeof(over), &out);
    if (assert_true(rc == -E2BIG, "near-wrap payload_length must hit the length guard") != 0) return 1;
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

    set_app_offer_version(&mixed.AppProtocol.array[0],
                          "urn:iso:std:iso:15118:-20:CommonMessages",
                          1,
                          0,
                          60,
                          1);
    if (assert_true(negotiate_app_protocol(&secc, &mixed, &response_doc) == 0 &&
                        response_doc.ResponseCode ==
                            appHand_responseCodeType_Failed_NoNegotiation &&
                        !response_doc.SchemaID_isUsed,
                    "ISO 15118-20-only offer must fail explicitly while unsupported") != 0) return 1;

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

static bool test_authorize_allow(void *user_ctx) {
    (void)user_ctx;
    return true;
}

static int test_default_secc_safety_is_fail_closed(void) {
    static const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE] =
        {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x17, 0x28};
    uint8_t response[JPV2G_MAX_EXI_SIZE];
    size_t response_len = 0;
    jpv2g_secc_t secc;
    jpv2g_secc_request_t request;
    struct iso2_MessageHeaderType header;
    struct iso2_AuthorizationReqType authorization;
    struct iso2_AuthorizationResType authorization_res;
    struct iso2_CableCheckReqType cable_check;
    struct iso2_CableCheckResType cable_check_res;

    memset(&secc, 0, sizeof(secc));
    memset(&request, 0, sizeof(request));
    jpv2g_secc_config_default(&secc.cfg);
    jpv2g_backend_set_defaults(&secc.backend);
    if (assert_true(!secc.backend.authorize_contract(secc.backend.user_ctx) &&
                        !secc.backend.authorize_external(secc.backend.user_ctx),
                    "default backend authorization must deny both payment modes") != 0) return 1;

    memcpy(secc.session_id, session_id, sizeof(session_id));
    init_iso2_MessageHeaderType(&header);
    memcpy(header.SessionID.bytes, session_id, sizeof(session_id));
    header.SessionID.bytesLen = sizeof(session_id);
    request.protocol = JPV2G_PROTOCOL_ISO15118_2;
    request.header = &header;

    init_iso2_AuthorizationReqType(&authorization);
    request.body = &authorization;
    if (assert_true(jpv2g_secc_default_handle(&secc,
                                              JPV2G_AUTHORIZATION_REQ,
                                              &request,
                                              response,
                                              sizeof(response),
                                              &response_len) == 0 &&
                        jpv2g_cbv2g_decode_authorization_res(
                            response, response_len, &authorization_res) == 0,
                    "default authorization denial must encode") != 0) return 1;
    if (assert_true(authorization_res.ResponseCode == iso2_responseCodeType_FAILED &&
                        authorization_res.EVSEProcessing == iso2_EVSEProcessingType_Finished,
                    "missing application authorization must be a terminal denial") != 0) return 1;

    init_iso2_CableCheckReqType(&cable_check);
    request.body = &cable_check;
    response_len = 0;
    if (assert_true(jpv2g_secc_default_handle(&secc,
                                              JPV2G_CABLE_CHECK_REQ,
                                              &request,
                                              response,
                                              sizeof(response),
                                              &response_len) == 0 &&
                        jpv2g_cbv2g_decode_cable_check_res(
                            response, response_len, &cable_check_res) == 0,
                    "default CableCheck failure must encode") != 0) return 1;
    if (assert_true(cable_check_res.ResponseCode == iso2_responseCodeType_FAILED &&
                        cable_check_res.EVSEProcessing == iso2_EVSEProcessingType_Finished &&
                        cable_check_res.DC_EVSEStatus.EVSEStatusCode ==
                            iso2_DC_EVSEStatusCodeType_EVSE_Malfunction &&
                        cable_check_res.DC_EVSEStatus.EVSEIsolationStatus_isUsed &&
                        cable_check_res.DC_EVSEStatus.EVSEIsolationStatus ==
                            iso2_isolationLevelType_No_IMD,
                    "default CableCheck must never fabricate Ready/Valid isolation") != 0) return 1;

    secc.backend.authorize_contract = test_authorize_allow;
    request.body = &authorization;
    response_len = 0;
    if (assert_true(jpv2g_secc_default_handle(&secc,
                                              JPV2G_AUTHORIZATION_REQ,
                                              &request,
                                              response,
                                              sizeof(response),
                                              &response_len) == 0 &&
                        jpv2g_cbv2g_decode_authorization_res(
                            response, response_len, &authorization_res) == 0 &&
                        authorization_res.ResponseCode == iso2_responseCodeType_OK,
                    "an explicit application authorization callback must still allow") != 0) return 1;
    return 0;
}

static int din_service_discovery(jpv2g_secc_t *secc,
                                 jpv2g_secc_request_t *request,
                                 struct din_ServiceDiscoveryReqType *discovery,
                                 uint8_t *response,
                                 size_t response_size,
                                 struct din_exiDocument *decoded) {
    size_t response_len = 0;
    request->body = discovery;
    int rc = jpv2g_secc_default_handle(secc,
                                        JPV2G_SERVICE_DISCOVERY_REQ,
                                        request,
                                        response,
                                        response_size,
                                        &response_len);
    if (rc != 0) return rc;
    return decode_din_document(response, response_len, decoded);
}

static int din_charge_parameter_discovery(jpv2g_secc_t *secc,
                                          jpv2g_secc_request_t *request,
                                          din_EVRequestedEnergyTransferType requested,
                                          uint8_t *response,
                                          size_t response_size,
                                          struct din_exiDocument *decoded) {
    struct din_ChargeParameterDiscoveryReqType cpd;
    size_t response_len = 0;
    init_din_ChargeParameterDiscoveryReqType(&cpd);
    cpd.EVRequestedEnergyTransferType = requested;
    cpd.DC_EVChargeParameter_isUsed = 1;
    init_din_DC_EVChargeParameterType(&cpd.DC_EVChargeParameter);
    request->body = &cpd;
    int rc = jpv2g_secc_default_handle(secc,
                                        JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ,
                                        request,
                                        response,
                                        response_size,
                                        &response_len);
    if (rc != 0) return rc;
    return decode_din_document(response, response_len, decoded);
}

static int test_din_dc_interop_responses(void) {
    static const uint8_t session_id[din_sessionIDType_BYTES_SIZE] =
        {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    uint8_t response[JPV2G_MAX_EXI_SIZE];
    jpv2g_secc_t secc;
    jpv2g_secc_request_t request;
    struct din_MessageHeaderType header;
    struct din_ServiceDiscoveryReqType discovery;
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

    strcpy(secc.cfg.supported_energy_modes, "DC_extended");
    if (assert_true(din_service_discovery(&secc,
                                          &request,
                                          &discovery,
                                          response,
                                          sizeof(response),
                                          &decoded) == 0 &&
                        decoded.V2G_Message.Body.ServiceDiscoveryRes_isUsed &&
                        decoded.V2G_Message.Body.ServiceDiscoveryRes.ResponseCode ==
                            din_responseCodeType_OK &&
                        decoded.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.EnergyTransferType ==
                            din_EVSESupportedEnergyTransferType_DC_extended,
                    "extended-only DIN configuration must advertise DC_extended") != 0) return 1;
    if (assert_true(din_charge_parameter_discovery(
                        &secc,
                        &request,
                        din_EVRequestedEnergyTransferType_DC_extended,
                        response,
                        sizeof(response),
                        &decoded) == 0,
                    "decode extended-only DIN CPD response") != 0) return 1;
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
    if (assert_true(din_charge_parameter_discovery(
                        &secc,
                        &request,
                        din_EVRequestedEnergyTransferType_DC_core,
                        response,
                        sizeof(response),
                        &decoded) == 0 &&
                        decoded.V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode ==
                            din_responseCodeType_FAILED_WrongEnergyTransferType,
                    "extended-only DIN offer must reject DC_core CPD") != 0) return 1;

    strcpy(secc.cfg.supported_energy_modes, "DC_core");
    if (assert_true(din_service_discovery(&secc,
                                          &request,
                                          &discovery,
                                          response,
                                          sizeof(response),
                                          &decoded) == 0 &&
                        decoded.V2G_Message.Body.ServiceDiscoveryRes.ResponseCode ==
                            din_responseCodeType_OK &&
                        decoded.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.EnergyTransferType ==
                            din_EVSESupportedEnergyTransferType_DC_core,
                    "core-only DIN configuration must advertise DC_core") != 0) return 1;
    if (assert_true(din_charge_parameter_discovery(
                        &secc,
                        &request,
                        din_EVRequestedEnergyTransferType_DC_core,
                        response,
                        sizeof(response),
                        &decoded) == 0 &&
                        decoded.V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode ==
                            din_responseCodeType_OK,
                    "core-only DIN offer must accept DC_core CPD") != 0) return 1;
    if (assert_true(din_charge_parameter_discovery(
                        &secc,
                        &request,
                        din_EVRequestedEnergyTransferType_DC_extended,
                        response,
                        sizeof(response),
                        &decoded) == 0 &&
                        decoded.V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode ==
                            din_responseCodeType_FAILED_WrongEnergyTransferType,
                    "core-only DIN offer must reject DC_extended CPD") != 0) return 1;

    strcpy(secc.cfg.supported_energy_modes, "DC_core,DC_extended");
    if (assert_true(din_service_discovery(&secc,
                                          &request,
                                          &discovery,
                                          response,
                                          sizeof(response),
                                          &decoded) == 0 &&
                        decoded.V2G_Message.Body.ServiceDiscoveryRes.ResponseCode ==
                            din_responseCodeType_OK &&
                        decoded.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.EnergyTransferType ==
                            din_EVSESupportedEnergyTransferType_DC_extended,
                    "dual-listed DIN config must resolve its single offer to DC_extended") != 0) return 1;
    strcpy(secc.cfg.supported_energy_modes, "DC_core");
    if (assert_true(din_charge_parameter_discovery(
                        &secc,
                        &request,
                        din_EVRequestedEnergyTransferType_DC_core,
                        response,
                        sizeof(response),
                        &decoded) == 0 &&
                        decoded.V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode ==
                            din_responseCodeType_FAILED_WrongEnergyTransferType,
                    "DIN CPD must reject a generic-list mode not encoded in ServiceDiscovery") != 0) return 1;
    if (assert_true(din_charge_parameter_discovery(
                        &secc,
                        &request,
                        din_EVRequestedEnergyTransferType_DC_extended,
                        response,
                        sizeof(response),
                        &decoded) == 0 &&
                        decoded.V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode ==
                            din_responseCodeType_OK,
                    "DIN CPD must retain the exact encoded offer despite later config mutation") != 0) return 1;

    secc.cfg.supported_energy_modes[0] = '\0';
    if (assert_true(din_service_discovery(&secc,
                                          &request,
                                          &discovery,
                                          response,
                                          sizeof(response),
                                          &decoded) == 0 &&
                        decoded.V2G_Message.Body.ServiceDiscoveryRes.ResponseCode ==
                            din_responseCodeType_FAILED &&
                        !secc.din_advertised_energy_transfer_valid,
                    "empty DIN mode config must fail ServiceDiscovery closed") != 0) return 1;
    if (assert_true(din_charge_parameter_discovery(
                        &secc,
                        &request,
                        din_EVRequestedEnergyTransferType_DC_extended,
                        response,
                        sizeof(response),
                        &decoded) == 0 &&
                        decoded.V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode ==
                            din_responseCodeType_FAILED_WrongEnergyTransferType,
                    "CPD must fail closed when no DIN mode was advertised") != 0) return 1;

    strcpy(secc.cfg.supported_energy_modes, "DC_extended");
    if (assert_true(din_service_discovery(&secc,
                                          &request,
                                          &discovery,
                                          response,
                                          sizeof(response),
                                          &decoded) == 0 &&
                        din_charge_parameter_discovery(
                            &secc,
                            &request,
                            din_EVRequestedEnergyTransferType_AC_single_phase_core,
                            response,
                            sizeof(response),
                            &decoded) == 0 &&
                        decoded.V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode ==
                            din_responseCodeType_FAILED_WrongEnergyTransferType,
                    "DC-only hardware must reject a DIN AC transfer request cleanly") != 0) return 1;

    size_t response_len = 0;
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

static int iso_charge_parameter_discovery(jpv2g_secc_t *secc,
                                          jpv2g_secc_request_t *request,
                                          iso2_EnergyTransferModeType requested,
                                          uint8_t *response,
                                          size_t response_size,
                                          struct iso2_ChargeParameterDiscoveryResType *decoded) {
    struct iso2_ChargeParameterDiscoveryReqType cpd;
    size_t response_len = 0;
    init_iso2_ChargeParameterDiscoveryReqType(&cpd);
    cpd.RequestedEnergyTransferMode = requested;
    cpd.DC_EVChargeParameter_isUsed = 1;
    init_iso2_DC_EVChargeParameterType(&cpd.DC_EVChargeParameter);
    request->body = &cpd;
    int rc = jpv2g_secc_default_handle(secc,
                                        JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ,
                                        request,
                                        response,
                                        response_size,
                                        &response_len);
    if (rc != 0) return rc;
    return jpv2g_cbv2g_decode_charge_parameter_discovery_res(
        response, response_len, decoded);
}

static int test_iso_energy_mode_membership(void) {
    static const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE] =
        {0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97, 0xA8};
    uint8_t response[JPV2G_MAX_EXI_SIZE];
    size_t response_len = 0;
    jpv2g_secc_t secc;
    jpv2g_secc_request_t request;
    struct iso2_MessageHeaderType header;
    struct iso2_ServiceDiscoveryReqType discovery;
    struct iso2_ServiceDiscoveryResType discovery_res;
    struct iso2_ChargeParameterDiscoveryResType cpd_res;

    memset(&secc, 0, sizeof(secc));
    memset(&request, 0, sizeof(request));
    jpv2g_secc_config_default(&secc.cfg);
    strcpy(secc.cfg.supported_energy_modes, "DC_core,DC_extended");
    memcpy(secc.session_id, session_id, sizeof(session_id));
    init_iso2_MessageHeaderType(&header);
    memcpy(header.SessionID.bytes, session_id, sizeof(session_id));
    header.SessionID.bytesLen = sizeof(session_id);
    init_iso2_ServiceDiscoveryReqType(&discovery);
    request.protocol = JPV2G_PROTOCOL_ISO15118_2;
    request.header = &header;
    request.body = &discovery;

    if (assert_true(jpv2g_secc_default_handle(&secc,
                                              JPV2G_SERVICE_DISCOVERY_REQ,
                                              &request,
                                              response,
                                              sizeof(response),
                                              &response_len) == 0 &&
                        jpv2g_cbv2g_decode_service_discovery_res(
                            response, response_len, &discovery_res) == 0 &&
                        discovery_res.ResponseCode == iso2_responseCodeType_OK &&
                        discovery_res.ChargeService.SupportedEnergyTransferMode
                                .EnergyTransferMode.arrayLen == 2 &&
                        discovery_res.ChargeService.SupportedEnergyTransferMode
                                .EnergyTransferMode.array[0] ==
                            iso2_EnergyTransferModeType_DC_core &&
                        discovery_res.ChargeService.SupportedEnergyTransferMode
                                .EnergyTransferMode.array[1] ==
                            iso2_EnergyTransferModeType_DC_extended,
                    "ISO ServiceDiscovery must retain multi-mode membership") != 0) return 1;

    if (assert_true(iso_charge_parameter_discovery(
                        &secc,
                        &request,
                        iso2_EnergyTransferModeType_DC_core,
                        response,
                        sizeof(response),
                        &cpd_res) == 0 &&
                        cpd_res.ResponseCode == iso2_responseCodeType_OK,
                    "ISO CPD must accept advertised DC_core membership") != 0) return 1;
    if (assert_true(iso_charge_parameter_discovery(
                        &secc,
                        &request,
                        iso2_EnergyTransferModeType_DC_extended,
                        response,
                        sizeof(response),
                        &cpd_res) == 0 &&
                        cpd_res.ResponseCode == iso2_responseCodeType_OK,
                    "ISO CPD must accept advertised DC_extended membership") != 0) return 1;
    if (assert_true(iso_charge_parameter_discovery(
                        &secc,
                        &request,
                        iso2_EnergyTransferModeType_DC_combo_core,
                        response,
                        sizeof(response),
                        &cpd_res) == 0 &&
                        cpd_res.ResponseCode ==
                            iso2_responseCodeType_FAILED_WrongEnergyTransferMode,
                    "ISO CPD must reject an unadvertised transfer mode") != 0) return 1;
    return 0;
}

static int test_cbv2g_workspace_identity_and_service_discovery_multi(void) {
    static const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE] =
        {0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87};
    jpv2g_cbv2g_codec_init();
    void *workspaces[] = {
        jpv2g_cbv2g_encode_app_workspace(),
        jpv2g_cbv2g_encode_iso_workspace(),
        jpv2g_cbv2g_encode_din_workspace(),
        jpv2g_cbv2g_secc_request_app_workspace(),
        jpv2g_cbv2g_secc_request_iso_workspace(),
        jpv2g_cbv2g_secc_request_din_workspace(),
        jpv2g_cbv2g_secc_log_app_workspace(),
        jpv2g_cbv2g_secc_log_iso_workspace(),
        jpv2g_cbv2g_secc_log_din_workspace(),
    };
    const size_t workspace_count = sizeof(workspaces) / sizeof(workspaces[0]);

    if (assert_true(jpv2g_cbv2g_codec_ready(),
                    "all cbv2g workspaces must be ready after init") != 0) return 1;
    for (size_t i = 0; i < workspace_count; ++i) {
        if (assert_true(workspaces[i] != NULL,
                        "every cbv2g workspace must be allocated") != 0) return 1;
        for (size_t j = i + 1; j < workspace_count; ++j) {
            if (assert_true(workspaces[i] != workspaces[j],
                            "encoder/request/log EXI workspaces must not alias") != 0) return 1;
        }
    }

    jpv2g_cbv2g_codec_init();
    void *workspaces_after_second_init[] = {
        jpv2g_cbv2g_encode_app_workspace(),
        jpv2g_cbv2g_encode_iso_workspace(),
        jpv2g_cbv2g_encode_din_workspace(),
        jpv2g_cbv2g_secc_request_app_workspace(),
        jpv2g_cbv2g_secc_request_iso_workspace(),
        jpv2g_cbv2g_secc_request_din_workspace(),
        jpv2g_cbv2g_secc_log_app_workspace(),
        jpv2g_cbv2g_secc_log_iso_workspace(),
        jpv2g_cbv2g_secc_log_din_workspace(),
    };
    for (size_t i = 0; i < workspace_count; ++i) {
        if (assert_true(workspaces[i] == workspaces_after_second_init[i],
                        "cbv2g workspace init must be idempotent") != 0) return 1;
    }

    uint8_t single[JPV2G_MAX_EXI_SIZE];
    uint8_t multi[JPV2G_MAX_EXI_SIZE];
    size_t single_len = 0;
    size_t multi_len = 0;
    const iso2_paymentOptionType payment = iso2_paymentOptionType_ExternalPayment;
    const iso2_EnergyTransferModeType mode = iso2_EnergyTransferModeType_DC_core;
    if (assert_true(jpv2g_cbv2g_encode_service_discovery_res(
                        session_id, iso2_responseCodeType_OK, payment, mode,
                        1, "DC charging", 0,
                        single, sizeof(single), &single_len) == 0,
                    "single-mode ServiceDiscovery response must encode") != 0) return 1;
    if (assert_true(jpv2g_cbv2g_encode_service_discovery_res_multi(
                        session_id, iso2_responseCodeType_OK,
                        &payment, 1, &mode, 1,
                        1, "DC charging", 0,
                        multi, sizeof(multi), &multi_len) == 0,
                    "one-entry multi-mode ServiceDiscovery response must encode") != 0) return 1;
    if (assert_true(single_len == multi_len &&
                        memcmp(single, multi, single_len) == 0,
                    "single-mode wrapper and one-entry multi encoder must be byte-equivalent") != 0) return 1;

    const iso2_paymentOptionType payments[] = {
        iso2_paymentOptionType_ExternalPayment,
        iso2_paymentOptionType_Contract,
        iso2_paymentOptionType_ExternalPayment,
    };
    const iso2_EnergyTransferModeType modes[] = {
        iso2_EnergyTransferModeType_DC_core,
        iso2_EnergyTransferModeType_DC_extended,
        iso2_EnergyTransferModeType_DC_combo_core,
        iso2_EnergyTransferModeType_DC_unique,
        iso2_EnergyTransferModeType_DC_core,
        iso2_EnergyTransferModeType_DC_extended,
        iso2_EnergyTransferModeType_DC_combo_core,
    };
    struct iso2_ServiceDiscoveryResType decoded;
    if (assert_true(jpv2g_cbv2g_encode_service_discovery_res_multi(
                        session_id, iso2_responseCodeType_OK,
                        payments, sizeof(payments) / sizeof(payments[0]),
                        modes, sizeof(modes) / sizeof(modes[0]),
                        7, "multi", 1,
                        multi, sizeof(multi), &multi_len) == 0 &&
                        jpv2g_cbv2g_decode_service_discovery_res(
                            multi, multi_len, &decoded) == 0,
                    "multi-entry ServiceDiscovery response must round trip") != 0) return 1;
    if (assert_true(decoded.PaymentOptionList.PaymentOption.arrayLen ==
                            iso2_paymentOptionType_2_ARRAY_SIZE &&
                        decoded.ChargeService.SupportedEnergyTransferMode
                                .EnergyTransferMode.arrayLen ==
                            iso2_EnergyTransferModeType_6_ARRAY_SIZE,
                    "multi encoder must clamp arrays to schema capacity") != 0) return 1;
    if (assert_true(decoded.PaymentOptionList.PaymentOption.array[0] == payments[0] &&
                        decoded.PaymentOptionList.PaymentOption.array[1] == payments[1] &&
                        decoded.ChargeService.SupportedEnergyTransferMode
                                .EnergyTransferMode.array[0] == modes[0] &&
                        decoded.ChargeService.SupportedEnergyTransferMode
                                .EnergyTransferMode.array[5] == modes[5],
                    "multi encoder must preserve ordered members through the schema limit") != 0) return 1;

    if (assert_true(jpv2g_cbv2g_encode_service_discovery_res_multi(
                        session_id, iso2_responseCodeType_OK,
                        NULL, 0, &mode, 1, 1, NULL, 0,
                        multi, sizeof(multi), &multi_len) == -EINVAL &&
                        jpv2g_cbv2g_encode_service_discovery_res_multi(
                            session_id, iso2_responseCodeType_OK,
                            &payment, 1, NULL, 0, 1, NULL, 0,
                            multi, sizeof(multi), &multi_len) == -EINVAL,
                    "multi encoder must reject missing payment or energy-mode membership") != 0) return 1;
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
    /* Gap audit #2 (2026-07-20): short SessionIDs are FIELD REALITY, not
     * malformed input — RISE-V2G's own EVCC sends a 1-byte 0x00 SID at
     * SessionSetup, and EvseV2G zero-pads short SIDs. Any length <= 8 must be
     * accepted at SessionSetup (resolve treats non-8 as "no SID" -> fresh
     * session); the old -EINVAL hard-dropped every RISE-derived EV stack. */
    header.SessionID.bytesLen = 3;
    if (assert_true(jpv2g_secc_validate_request_session(&secc,
                                                        JPV2G_SESSION_SETUP_REQ,
                                                        &req) == 0,
                    "short SessionSetup SessionID must be tolerated (gap #2)") != 0) return 1;
    header.SessionID.bytesLen = 1;
    header.SessionID.bytes[0] = 0x00;
    if (assert_true(jpv2g_secc_validate_request_session(&secc,
                                                        JPV2G_SESSION_SETUP_REQ,
                                                        &req) == 0,
                    "1-byte zero SessionID (RISE-V2G EVCC) must be tolerated") != 0) return 1;

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

/* Gap audit #3 (2026-07-20): the minimal per-message FAILED responses must be
 * schema-valid — an EV EXI decoder that cannot decode the Res is no better
 * than the silent RST this feature replaces. Round-trip a representative
 * sample through the real decoders. */
static int test_secc_min_failed_res_is_decodable(void) {
    uint8_t sid[iso2_sessionIDType_BYTES_SIZE];
    uint8_t exi[JPV2G_MAX_EXI_SIZE];
    size_t exi_len = 0;
    for (size_t i = 0; i < sizeof(sid); ++i) sid[i] = (uint8_t)(0xA0 + i);

    /* ISO2 CurrentDemandRes / FAILED_SequenceError */
    if (assert_true(jpv2g_cbv2g_encode_min_failed_res(
                        JPV2G_PROTOCOL_ISO15118_2, JPV2G_CURRENT_DEMAND_REQ,
                        JPV2G_MIN_FAILED_SEQUENCE_ERROR, sid, "IN*JPE*E1", NULL, 0,
                        exi, sizeof(exi), &exi_len) == 0 && exi_len > 0,
                    "min-failed ISO2 CurrentDemandRes encodes") != 0) return 1;
    {
        struct iso2_CurrentDemandResType res;
        if (assert_true(jpv2g_cbv2g_decode_current_demand_res(exi, exi_len, &res) == 0,
                        "min-failed ISO2 CurrentDemandRes decodes") != 0) return 1;
        if (assert_true(res.ResponseCode == iso2_responseCodeType_FAILED_SequenceError,
                        "min-failed ISO2 CurrentDemandRes carries FAILED_SequenceError") != 0) return 1;
    }

    /* ISO2 SessionSetupRes / FAILED_UnknownSession */
    if (assert_true(jpv2g_cbv2g_encode_min_failed_res(
                        JPV2G_PROTOCOL_ISO15118_2, JPV2G_SESSION_SETUP_REQ,
                        JPV2G_MIN_FAILED_UNKNOWN_SESSION, sid, "IN*JPE*E1", NULL, 0,
                        exi, sizeof(exi), &exi_len) == 0 && exi_len > 0,
                    "min-failed ISO2 SessionSetupRes encodes") != 0) return 1;
    {
        struct iso2_SessionSetupResType res;
        uint8_t sid_out[iso2_sessionIDType_BYTES_SIZE];
        if (assert_true(jpv2g_cbv2g_decode_session_setup_res(exi, exi_len, &res, sid_out) == 0,
                        "min-failed ISO2 SessionSetupRes decodes") != 0) return 1;
        if (assert_true(res.ResponseCode == iso2_responseCodeType_FAILED_UnknownSession,
                        "min-failed ISO2 SessionSetupRes carries FAILED_UnknownSession") != 0) return 1;
    }

    /* DIN CableCheckRes / FAILED_SequenceError (decode via the raw document) */
    static const uint8_t din_evse_id[] = {'J','P','1'};
    if (assert_true(jpv2g_cbv2g_encode_min_failed_res(
                        JPV2G_PROTOCOL_DIN70121, JPV2G_CABLE_CHECK_REQ,
                        JPV2G_MIN_FAILED_SEQUENCE_ERROR, sid, NULL,
                        din_evse_id, sizeof(din_evse_id),
                        exi, sizeof(exi), &exi_len) == 0 && exi_len > 0,
                    "min-failed DIN CableCheckRes encodes") != 0) return 1;
    {
        struct din_exiDocument doc;
        exi_bitstream_t stream;
        exi_bitstream_init(&stream, exi, exi_len, 0, NULL);
        if (assert_true(decode_din_exiDocument(&stream, &doc) == 0 &&
                            doc.V2G_Message.Body.CableCheckRes_isUsed,
                        "min-failed DIN CableCheckRes decodes") != 0) return 1;
        if (assert_true(doc.V2G_Message.Body.CableCheckRes.ResponseCode ==
                            din_responseCodeType_FAILED_SequenceError,
                        "min-failed DIN CableCheckRes carries FAILED_SequenceError") != 0) return 1;
    }

    /* DIN SessionStopRes / FAILED_UnknownSession */
    if (assert_true(jpv2g_cbv2g_encode_min_failed_res(
                        JPV2G_PROTOCOL_DIN70121, JPV2G_SESSION_STOP_REQ,
                        JPV2G_MIN_FAILED_UNKNOWN_SESSION, sid, NULL,
                        din_evse_id, sizeof(din_evse_id),
                        exi, sizeof(exi), &exi_len) == 0 && exi_len > 0,
                    "min-failed DIN SessionStopRes encodes") != 0) return 1;
    {
        struct din_exiDocument doc;
        exi_bitstream_t stream;
        exi_bitstream_init(&stream, exi, exi_len, 0, NULL);
        if (assert_true(decode_din_exiDocument(&stream, &doc) == 0 &&
                            doc.V2G_Message.Body.SessionStopRes_isUsed,
                        "min-failed DIN SessionStopRes decodes") != 0) return 1;
        if (assert_true(doc.V2G_Message.Body.SessionStopRes.ResponseCode ==
                            din_responseCodeType_FAILED_UnknownSession,
                        "min-failed DIN SessionStopRes carries FAILED_UnknownSession") != 0) return 1;
    }
    return 0;
}

/* Gap audit #3 wire proof: a sequence-violating request must produce a
 * decodable FAILED Res ON THE SOCKET before the stream tears down. */
static int test_secc_stream_sends_failed_res_before_teardown(void) {
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
    if (assert_true(jpv2g_codec_init(&codec) == 0, "codec init for failed-res test") != 0) return 1;
    if (assert_true(jpv2g_secc_init(&secc, &cfg, codec) == 0, "SECC init for failed-res test") != 0) {
        jpv2g_codec_free(codec);
        return 1;
    }
    if (assert_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0,
                    "socketpair for failed-res test") != 0) {
        jpv2g_codec_free(codec);
        return 1;
    }
    /* SessionSetup before app-protocol negotiation = sequence violation. */
    if (assert_true(jpv2g_cbv2g_encode_session_setup_req(
                        evcc_id, exi, sizeof(exi), &exi_len) == 0,
                    "encode out-of-order SessionSetup (failed-res)") != 0) return 1;
    if (assert_true(jpv2g_v2gtp_build(JPV2G_PAYLOAD_EXI, exi, exi_len,
                                      frame, sizeof(frame), &frame_len) == 0,
                    "wrap out-of-order SessionSetup (failed-res)") != 0) return 1;
    if (assert_true(send(sockets[1], frame, frame_len, 0) == (ssize_t)frame_len,
                    "write failed-res trigger frame") != 0) return 1;
    shutdown(sockets[1], SHUT_WR);

    const int rc = jpv2g_secc_handle_client(&secc, sockets[0], 100);
    if (assert_true(rc == -EPROTO,
                    "sequence violation still terminates with -EPROTO") != 0) return 1;

    /* The FAILED Res must be on the wire: V2GTP header + EXI SessionSetupRes
     * with FAILED_SequenceError. */
    uint8_t rx[JPV2G_MAX_V2GTP_SIZE];
    ssize_t got = recv(sockets[1], rx, sizeof(rx), 0);
    if (assert_true(got > (ssize_t)JPV2G_V2GTP_HEADER_LEN,
                    "FAILED Res bytes present on the socket") != 0) return 1;
    jpv2g_v2gtp_t msg;
    if (assert_true(jpv2g_v2gtp_parse(rx, (size_t)got, &msg) == 0 &&
                        msg.payload_type == JPV2G_PAYLOAD_EXI,
                    "FAILED Res is a valid V2GTP EXI frame") != 0) return 1;
    struct iso2_SessionSetupResType res;
    uint8_t sid_out[iso2_sessionIDType_BYTES_SIZE];
    if (assert_true(jpv2g_cbv2g_decode_session_setup_res(
                        msg.payload, msg.payload_length, &res, sid_out) == 0,
                    "FAILED Res decodes as SessionSetupRes") != 0) return 1;
    if (assert_true(res.ResponseCode == iso2_responseCodeType_FAILED_SequenceError,
                    "FAILED Res carries FAILED_SequenceError") != 0) return 1;

    close(sockets[0]);
    close(sockets[1]);
    jpv2g_codec_free(codec);
    return 0;
}

/* Gap audit #9: one undecodable frame mid-stream must NOT tear down the
 * session (bounded ignore); pre-session garbage still must. */
static int test_secc_stream_ignores_undecodable_midsession(void) {
    jpv2g_codec_ctx *codec = NULL;
    jpv2g_secc_config_t cfg;
    jpv2g_secc_t secc;
    int sockets[2] = {-1, -1};
    uint8_t exi[JPV2G_MAX_EXI_SIZE];
    uint8_t frame[JPV2G_MAX_V2GTP_SIZE];
    size_t exi_len = 0;
    size_t frame_len = 0;

    jpv2g_secc_config_default(&cfg);
    if (assert_true(jpv2g_codec_init(&codec) == 0, "codec init for ignore test") != 0) return 1;
    if (assert_true(jpv2g_secc_init(&secc, &cfg, codec) == 0, "SECC init for ignore test") != 0) {
        jpv2g_codec_free(codec);
        return 1;
    }
    if (assert_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0,
                    "socketpair for ignore test") != 0) {
        jpv2g_codec_free(codec);
        return 1;
    }

    /* 1: valid SupportedAppProtocolReq (DIN offer) — establishes handled_any. */
    if (assert_true(jpv2g_cbv2g_encode_sapp_req(
                        "urn:din:70121:2012:MsgDef", 2, 0, 1, 1,
                        exi, sizeof(exi), &exi_len) == 0,
                    "encode SAPP for ignore test") != 0) return 1;
    if (assert_true(jpv2g_v2gtp_build(JPV2G_PAYLOAD_EXI, exi, exi_len,
                                      frame, sizeof(frame), &frame_len) == 0,
                    "wrap SAPP for ignore test") != 0) return 1;
    if (assert_true(send(sockets[1], frame, frame_len, 0) == (ssize_t)frame_len,
                    "send SAPP for ignore test") != 0) return 1;

    /* 2: garbage EXI payload — must be IGNORED, not fatal. */
    {
        uint8_t junk[24];
        for (size_t i = 0; i < sizeof(junk); ++i) junk[i] = (uint8_t)(0x5A ^ i);
        if (assert_true(jpv2g_v2gtp_build(JPV2G_PAYLOAD_EXI, junk, sizeof(junk),
                                          frame, sizeof(frame), &frame_len) == 0,
                        "wrap garbage frame") != 0) return 1;
        if (assert_true(send(sockets[1], frame, frame_len, 0) == (ssize_t)frame_len,
                        "send garbage frame") != 0) return 1;
    }
    shutdown(sockets[1], SHUT_WR);

    /* After the garbage frame is ignored the writer side is already shut
     * down, so the next recv sees EOF -> -ECONNRESET (peer closed). The
     * defect this guards against is -EBADMSG: the OLD code tore the stream
     * down ON the garbage frame itself, before ever reaching EOF. */
    const int rc = jpv2g_secc_handle_client(&secc, sockets[0], 100);
    if (assert_true(rc == -ECONNRESET,
                    "stream survives one undecodable mid-session frame (exits on peer EOF, not -EBADMSG)") != 0) return 1;

    /* The SAPP response must still have been produced. */
    uint8_t rx[JPV2G_MAX_V2GTP_SIZE];
    ssize_t got = recv(sockets[1], rx, sizeof(rx), 0);
    if (assert_true(got > (ssize_t)JPV2G_V2GTP_HEADER_LEN,
                    "SAPP res present despite garbage frame") != 0) return 1;

    close(sockets[0]);
    close(sockets[1]);
    jpv2g_codec_free(codec);
    return 0;
}

/* Gap audit #10: negative timestamp must OMIT the optional DIN DateTimeNow
 * (RTC-less hardware sent epoch-1970 before). */
static int test_din_session_setup_timestamp_gate(void) {
    uint8_t sid[din_sessionIDType_BYTES_SIZE];
    static const uint8_t evse_id[] = {'J','P','1'};
    uint8_t exi[JPV2G_MAX_EXI_SIZE];
    size_t exi_len = 0;
    for (size_t i = 0; i < sizeof(sid); ++i) sid[i] = (uint8_t)(i + 1);

    if (assert_true(jpv2g_cbv2g_encode_din_session_setup_res(
                        sid, evse_id, sizeof(evse_id),
                        din_responseCodeType_OK_NewSessionEstablished, -1,
                        exi, sizeof(exi), &exi_len) == 0,
                    "DIN SessionSetupRes encodes with absent timestamp") != 0) return 1;
    {
        struct din_exiDocument doc;
        exi_bitstream_t stream;
        exi_bitstream_init(&stream, exi, exi_len, 0, NULL);
        if (assert_true(decode_din_exiDocument(&stream, &doc) == 0 &&
                            doc.V2G_Message.Body.SessionSetupRes_isUsed,
                        "absent-timestamp DIN SessionSetupRes decodes") != 0) return 1;
        if (assert_true(doc.V2G_Message.Body.SessionSetupRes.DateTimeNow_isUsed == 0,
                        "negative timestamp omits DateTimeNow (gap #10)") != 0) return 1;
    }
    if (assert_true(jpv2g_cbv2g_encode_din_session_setup_res(
                        sid, evse_id, sizeof(evse_id),
                        din_responseCodeType_OK_NewSessionEstablished, 1752969600,
                        exi, sizeof(exi), &exi_len) == 0,
                    "DIN SessionSetupRes encodes with real timestamp") != 0) return 1;
    {
        struct din_exiDocument doc;
        exi_bitstream_t stream;
        exi_bitstream_init(&stream, exi, exi_len, 0, NULL);
        if (assert_true(decode_din_exiDocument(&stream, &doc) == 0 &&
                            doc.V2G_Message.Body.SessionSetupRes.DateTimeNow_isUsed == 1,
                        "real timestamp keeps DateTimeNow") != 0) return 1;
    }
    return 0;
}

/* Gap audit #12: a payment option we never offered must be rejected with
 * FAILED_PaymentSelectionInvalid — via handler rc 0 so the Res transmits. */
static int test_payment_selection_rejects_unoffered(void) {
    jpv2g_codec_ctx *codec = NULL;
    jpv2g_secc_config_t cfg;
    jpv2g_secc_t secc;
    uint8_t out[JPV2G_MAX_EXI_SIZE];
    size_t out_len = 0;

    jpv2g_secc_config_default(&cfg);
    if (assert_true(jpv2g_codec_init(&codec) == 0, "codec init for payment test") != 0) return 1;
    if (assert_true(jpv2g_secc_init(&secc, &cfg, codec) == 0, "SECC init for payment test") != 0) {
        jpv2g_codec_free(codec);
        return 1;
    }

    struct iso2_MessageHeaderType header;
    memset(&header, 0, sizeof(header));
    header.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE;
    for (size_t i = 0; i < iso2_sessionIDType_BYTES_SIZE; ++i) {
        header.SessionID.bytes[i] = (uint8_t)(i + 1);
    }
    struct iso2_PaymentServiceSelectionReqType psreq;
    memset(&psreq, 0, sizeof(psreq));
    psreq.SelectedPaymentOption = iso2_paymentOptionType_Contract;

    jpv2g_secc_request_t req;
    memset(&req, 0, sizeof(req));
    req.protocol = JPV2G_PROTOCOL_ISO15118_2;
    req.header = &header;
    req.body = &psreq;

    const int rc = jpv2g_secc_default_handle(
        &secc, JPV2G_PAYMENT_SERVICE_SELECTION_REQ, &req, out, sizeof(out), &out_len);
    if (assert_true(rc == 0 && out_len > 0,
                    "Contract selection answered (rc 0), not torn down") != 0) return 1;
    struct iso2_PaymentServiceSelectionResType res;
    if (assert_true(jpv2g_cbv2g_decode_payment_service_selection_res(out, out_len, &res) == 0,
                    "payment-selection Res decodes") != 0) return 1;
    if (assert_true(res.ResponseCode == iso2_responseCodeType_FAILED_PaymentSelectionInvalid,
                    "Contract selection rejected with FAILED_PaymentSelectionInvalid") != 0) return 1;

    /* ExternalPayment stays OK. */
    psreq.SelectedPaymentOption = iso2_paymentOptionType_ExternalPayment;
    if (assert_true(jpv2g_secc_default_handle(
                        &secc, JPV2G_PAYMENT_SERVICE_SELECTION_REQ, &req,
                        out, sizeof(out), &out_len) == 0 &&
                        jpv2g_cbv2g_decode_payment_service_selection_res(out, out_len, &res) == 0 &&
                        res.ResponseCode == iso2_responseCodeType_OK,
                    "ExternalPayment still answered OK") != 0) return 1;

    jpv2g_codec_free(codec);
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

/* ------------------------------------------------------------------------- */
/* TLS Tier-1: host-side tests that require NO mbedtls.                      */
/*                                                                           */
/* The jpv2g_tls_credentials_t contract (in-memory PEM, mbedtls 2.x rule:    */
/* NUL-terminated buffer with the length counting the NUL) is enforced by    */
/* jpv2g_tls_credentials_validate() in BOTH tls.c branches, so the shape     */
/* checks are testable on hosts that never link mbedtls. The stub branch     */
/* must keep refusing TLS with -ENOTSUP so the single-port auto-detect path  */
/* (ClientHello -> wrap -> -ENOTSUP -> close) behaves exactly as shipped.    */
/* ------------------------------------------------------------------------- */

/* Structurally PEM-shaped fixtures; validation is shape-only, so the body
 * content is irrelevant (parsing happens later, inside mbedtls builds). */
static const char k_tls_test_cert_pem[] =
    "-----BEGIN CERTIFICATE-----\nMIIBdummy\n-----END CERTIFICATE-----\n";
static const char k_tls_test_key_pem[] =
    "-----BEGIN EC PRIVATE KEY-----\nMHcdummy\n-----END EC PRIVATE KEY-----\n";
static const char k_tls_test_ca_pem[] =
    "-----BEGIN CERTIFICATE-----\nMIIBcadummy\n-----END CERTIFICATE-----\n";

static jpv2g_tls_credentials_t tls_test_valid_creds(void) {
    jpv2g_tls_credentials_t creds;
    memset(&creds, 0, sizeof(creds));
    creds.cert_pem = (const uint8_t *)k_tls_test_cert_pem;
    creds.cert_pem_len = sizeof(k_tls_test_cert_pem); /* counts the NUL */
    creds.key_pem = (const uint8_t *)k_tls_test_key_pem;
    creds.key_pem_len = sizeof(k_tls_test_key_pem);
    return creds;
}

static int test_tls_credentials_validation(void) {
    if (assert_true(jpv2g_tls_credentials_validate(NULL) == -EINVAL,
                    "NULL credentials must be rejected") != 0) return 1;

    jpv2g_tls_credentials_t creds;
    memset(&creds, 0, sizeof(creds));
    if (assert_true(jpv2g_tls_credentials_validate(&creds) == -EINVAL,
                    "all-NULL credentials must be rejected") != 0) return 1;

    /* cert without key and key without cert are both incomplete. */
    creds = tls_test_valid_creds();
    creds.key_pem = NULL;
    creds.key_pem_len = 0;
    if (assert_true(jpv2g_tls_credentials_validate(&creds) == -EINVAL,
                    "cert without key must be rejected") != 0) return 1;
    creds = tls_test_valid_creds();
    creds.cert_pem = NULL;
    creds.cert_pem_len = 0;
    if (assert_true(jpv2g_tls_credentials_validate(&creds) == -EINVAL,
                    "key without cert must be rejected") != 0) return 1;

    /* The happy path: sizeof(string literal) satisfies the NUL rule. */
    creds = tls_test_valid_creds();
    if (assert_true(jpv2g_tls_credentials_validate(&creds) == 0,
                    "well-formed cert+key credentials must validate") != 0) return 1;

    /* mbedtls 2.x PEM rule: the length must COUNT the terminating NUL.
     * strlen()-style lengths (one short) are the classic integration bug
     * and must be caught here, not as an opaque ASN.1 error later. */
    creds = tls_test_valid_creds();
    creds.cert_pem_len = sizeof(k_tls_test_cert_pem) - 1;
    if (assert_true(jpv2g_tls_credentials_validate(&creds) == -EINVAL,
                    "cert length not counting the NUL must be rejected") != 0) return 1;
    creds = tls_test_valid_creds();
    creds.key_pem_len = sizeof(k_tls_test_key_pem) - 1;
    if (assert_true(jpv2g_tls_credentials_validate(&creds) == -EINVAL,
                    "key length not counting the NUL must be rejected") != 0) return 1;

    /* Empty PEM: a lone NUL (len 1) carries no content. */
    static const char empty_pem[] = "";
    creds = tls_test_valid_creds();
    creds.cert_pem = (const uint8_t *)empty_pem;
    creds.cert_pem_len = sizeof(empty_pem);
    if (assert_true(jpv2g_tls_credentials_validate(&creds) == -EINVAL,
                    "empty cert PEM must be rejected") != 0) return 1;

    /* CA chain is optional, but when present it obeys the same rules. */
    creds = tls_test_valid_creds();
    creds.ca_pem = (const uint8_t *)k_tls_test_ca_pem;
    creds.ca_pem_len = sizeof(k_tls_test_ca_pem);
    if (assert_true(jpv2g_tls_credentials_validate(&creds) == 0,
                    "credentials with a well-formed CA must validate") != 0) return 1;
    creds.ca_pem_len = sizeof(k_tls_test_ca_pem) - 1;
    if (assert_true(jpv2g_tls_credentials_validate(&creds) == -EINVAL,
                    "CA length not counting the NUL must be rejected") != 0) return 1;
    creds = tls_test_valid_creds();
    creds.ca_pem = NULL;
    creds.ca_pem_len = 4;
    if (assert_true(jpv2g_tls_credentials_validate(&creds) == -EINVAL,
                    "NULL CA with a non-zero length must be rejected") != 0) return 1;
    return 0;
}

/* The SECC config default must keep tls_mem_creds all-NULL: a NULL
 * cert_pem is the accept path's signal to fall back to the file-path
 * variant (and, without mbedtls, to refuse TLS exactly as today). */
static int test_tls_secc_config_default_has_no_mem_creds(void) {
    jpv2g_secc_config_t cfg;
    memset(&cfg, 0xA5, sizeof(cfg)); /* poison to prove default clears it */
    jpv2g_secc_config_default(&cfg);
    if (assert_true(cfg.tls_mem_creds.cert_pem == NULL && cfg.tls_mem_creds.cert_pem_len == 0,
                    "default config must not carry an in-memory cert") != 0) return 1;
    if (assert_true(cfg.tls_mem_creds.key_pem == NULL && cfg.tls_mem_creds.key_pem_len == 0,
                    "default config must not carry an in-memory key") != 0) return 1;
    if (assert_true(cfg.tls_mem_creds.ca_pem == NULL && cfg.tls_mem_creds.ca_pem_len == 0,
                    "default config must not carry an in-memory CA") != 0) return 1;
    return 0;
}

#ifndef HAVE_MBEDTLS
/* Stub-branch contract: every TLS entry point refuses with -ENOTSUP and
 * leaves the fd to the caller, so a ClientHello on the auto-detect port
 * is refused and closed exactly as the shipping firmware does today. */
static int test_tls_stub_returns_enotsup(void) {
    int sockets[2] = {-1, -1};
    if (assert_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0,
                    "socketpair for TLS stub test") != 0) return 1;
    jpv2g_tls_socket_t sock;
    memset(&sock, 0, sizeof(sock));
    sock.fd = -1;

    jpv2g_tls_credentials_t creds = tls_test_valid_creds();
    if (assert_true(jpv2g_tls_server_wrap_mem(&sock, sockets[0], &creds, 1000) == -ENOTSUP,
                    "stub jpv2g_tls_server_wrap_mem must return -ENOTSUP") != 0) return 1;
    if (assert_true(jpv2g_tls_server_wrap(&sock, sockets[0], "cert.pem", "key.pem", NULL) == -ENOTSUP,
                    "stub jpv2g_tls_server_wrap must return -ENOTSUP") != 0) return 1;
    if (assert_true(!sock.secure,
                    "stub wrap must never mark the socket secure") != 0) return 1;

    /* The fd must still belong to the caller after a refused wrap: a
     * second syscall on it has to succeed. */
    if (assert_true(send(sockets[1], "x", 1, 0) == 1,
                    "peer fd must remain usable after refused wrap") != 0) return 1;

    uint8_t buf[4];
    if (assert_true(jpv2g_tls_send(&sock, buf, sizeof(buf)) == -ENOTSUP,
                    "stub jpv2g_tls_send must return -ENOTSUP") != 0) return 1;
    if (assert_true(jpv2g_tls_recv(&sock, buf, sizeof(buf), 10) == -ENOTSUP,
                    "stub jpv2g_tls_recv must return -ENOTSUP") != 0) return 1;

    close(sockets[0]);
    close(sockets[1]);
    return 0;
}
#endif /* !HAVE_MBEDTLS */

int main(void) {
    if (test_v2gtp_round_trip() != 0) return 1;
    if (test_v2gtp_length_bounds() != 0) return 1;
    if (test_evcc_state_sequence() != 0) return 1;
    if (test_secc_state_sequence() != 0) return 1;
    if (test_secc_production_sequence() != 0) return 1;
#ifdef JPV2G_ENABLE_CBV2G_CODEC
    if (test_supported_app_protocol_interop() != 0) return 1;
    if (test_default_secc_safety_is_fail_closed() != 0) return 1;
    if (test_din_dc_interop_responses() != 0) return 1;
    if (test_iso_energy_mode_membership() != 0) return 1;
    if (test_cbv2g_workspace_identity_and_service_discovery_multi() != 0) return 1;
    if (test_iso_dc_transition_response_round_trip() != 0) return 1;
    if (test_din_dc_transition_response_round_trip() != 0) return 1;
    if (test_iso_pause_resume() != 0) return 1;
    if (test_secc_session_id_validation() != 0) return 1;
    if (test_secc_stream_enforces_sequence() != 0) return 1;
    if (test_secc_min_failed_res_is_decodable() != 0) return 1;
    if (test_secc_stream_sends_failed_res_before_teardown() != 0) return 1;
    if (test_secc_stream_ignores_undecodable_midsession() != 0) return 1;
    if (test_din_session_setup_timestamp_gate() != 0) return 1;
    if (test_payment_selection_rejects_unoffered() != 0) return 1;
#endif
    if (test_tls_credentials_validation() != 0) return 1;
    if (test_tls_secc_config_default_has_no_mem_creds() != 0) return 1;
#ifndef HAVE_MBEDTLS
    if (test_tls_stub_returns_enotsup() != 0) return 1;
#endif
    printf("jpv2g_unit_test: PASS\n");
    return 0;
}

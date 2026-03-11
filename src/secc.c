/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/secc.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include "jpv2g/poll_compat.h"
#include <time.h>
#include <stdbool.h>

#include "cbv2g/app_handshake/appHand_Decoder.h"
#include "cbv2g/app_handshake/appHand_Datatypes.h"
#include "cbv2g/common/exi_bitstream.h"
#include "cbv2g/din/din_msgDefDecoder.h"
#include "cbv2g/din/din_msgDefDatatypes.h"
#include "cbv2g/iso_2/iso2_msgDefDecoder.h"
#include "cbv2g/iso_2/iso2_msgDefEncoder.h"
#include "cbv2g/iso_2/iso2_msgDefDatatypes.h"
#include "jpv2g/cbv2g_codec.h"
#include "jpv2g/constants.h"
#include "jpv2g/byte_utils.h"
#include "jpv2g/backend.h"
#include "jpv2g/evse_controller.h"
#include "jpv2g/messages.h"
#include "jpv2g/platform_compat.h"
#include "jpv2g/session.h"
#include "jpv2g/v2gtp.h"
#include "jpv2g/log.h"
#include "jpv2g/time_compat.h"

static bool s_enable_decoded_logs = true;
static const uint32_t SECC_CURRENT_DEMAND_LOG_EVERY = 50u;

void jpv2g_secc_set_decoded_logs(bool enable) {
    s_enable_decoded_logs = enable;
}

bool jpv2g_secc_get_decoded_logs(void) {
    return s_enable_decoded_logs;
}

static bool looks_like_tls_client_hello(const uint8_t *buf, size_t len) {
    /* TLS record layer handshake starts with 0x16 0x03 0x0x. */
    return buf && len >= 3 && buf[0] == 0x16 && buf[1] == 0x03;
}

static bool looks_like_v2gtp_header(const uint8_t *buf, size_t len) {
    return buf && len >= JPV2G_V2GTP_HEADER_LEN &&
           buf[0] == JPV2G_V2GTP_VERSION &&
           buf[1] == (uint8_t)(JPV2G_V2GTP_VERSION ^ 0xFF);
}

static int peek_first_bytes(int fd, uint8_t *buf, size_t buf_len, int timeout_ms) {
    if (fd < 0 || !buf || buf_len == 0) return -EINVAL;
    const int64_t deadline = timeout_ms > 0 ? (jpv2g_now_monotonic_ms() + timeout_ms) : -1;
    for (;;) {
        ssize_t r = recv(fd, buf, buf_len, MSG_PEEK | MSG_DONTWAIT);
        if (r > 0) return (int)r;
        if (r == 0) return -ECONNRESET;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (timeout_ms == 0) return -ETIMEDOUT;
            if (deadline >= 0 && jpv2g_now_monotonic_ms() >= deadline) return -ETIMEDOUT;
            jpv2g_sleep_ms(1);
            continue;
        }
        return -errno;
    }
}

static bool ns_contains(const char *haystack, size_t hay_len, const char *needle) {
    if (!haystack || !needle) return false;
    size_t nlen = strlen(needle);
    if (nlen == 0 || hay_len < nlen) return false;
    for (size_t i = 0; i + nlen <= hay_len; ++i) {
        if (memcmp(haystack + i, needle, nlen) == 0) return true;
    }
    return false;
}

static jpv2g_protocol_t detect_protocol_from_app(const struct appHand_supportedAppProtocolReq *app) {
    if (!app) return JPV2G_PROTOCOL_UNKNOWN;
    jpv2g_protocol_t best = JPV2G_PROTOCOL_UNKNOWN;
    uint8_t best_prio = 0xFF;
    for (uint16_t i = 0; i < app->AppProtocol.arrayLen; ++i) {
        const struct appHand_AppProtocolType *ap = &app->AppProtocol.array[i];
        const char *ns = (const char *)ap->ProtocolNamespace.characters;
        size_t ns_len = ap->ProtocolNamespace.charactersLen;
        uint8_t prio = ap->Priority;
        if (prio > best_prio) continue;
        if (ns_contains(ns, ns_len, "iso:15118:2") || ns_contains(ns, ns_len, "iso:15118-2")) {
            if (prio < best_prio || best == JPV2G_PROTOCOL_UNKNOWN || best == JPV2G_PROTOCOL_DIN70121) {
                best = JPV2G_PROTOCOL_ISO15118_2;
                best_prio = prio;
            }
            continue;
        }
        if (ns_contains(ns, ns_len, "din:70121")) {
            if (prio < best_prio || best == JPV2G_PROTOCOL_UNKNOWN) {
                best = JPV2G_PROTOCOL_DIN70121;
                best_prio = prio;
            }
        }
    }
    return best;
}

static uint8_t select_schema_for_protocol(const struct appHand_supportedAppProtocolReq *app,
                                          jpv2g_protocol_t protocol) {
    if (!app || app->AppProtocol.arrayLen == 0) return 1;
    uint8_t best_schema = app->AppProtocol.array[0].SchemaID;
    uint8_t best_prio = 0xFF;
    for (uint16_t i = 0; i < app->AppProtocol.arrayLen; ++i) {
        const struct appHand_AppProtocolType *ap = &app->AppProtocol.array[i];
        const char *ns = (const char *)ap->ProtocolNamespace.characters;
        size_t ns_len = ap->ProtocolNamespace.charactersLen;
        bool ns_match = false;
        if (protocol == JPV2G_PROTOCOL_ISO15118_2) {
            ns_match = ns_contains(ns, ns_len, "iso:15118:2") || ns_contains(ns, ns_len, "iso:15118-2");
        } else if (protocol == JPV2G_PROTOCOL_DIN70121) {
            ns_match = ns_contains(ns, ns_len, "din:70121");
        }
        if (!ns_match) continue;
        if (ap->Priority > best_prio) continue;
        best_prio = ap->Priority;
        best_schema = ap->SchemaID;
    }
    return best_schema;
}

static const char *secc_msg_name(jpv2g_message_type_t type) {
    switch (type) {
        case JPV2G_SUPP_APP_PROTOCOL_REQ: return "SupportedAppProtocolReq";
        case JPV2G_SESSION_SETUP_REQ: return "SessionSetupReq";
        case JPV2G_SERVICE_DISCOVERY_REQ: return "ServiceDiscoveryReq";
        case JPV2G_SERVICE_DETAIL_REQ: return "ServiceDetailReq";
        case JPV2G_PAYMENT_SERVICE_SELECTION_REQ: return "PaymentServiceSelectionReq";
        case JPV2G_PAYMENT_DETAILS_REQ: return "PaymentDetailsReq";
        case JPV2G_AUTHORIZATION_REQ: return "AuthorizationReq";
        case JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ: return "ChargeParameterDiscoveryReq";
        case JPV2G_CABLE_CHECK_REQ: return "CableCheckReq";
        case JPV2G_PRE_CHARGE_REQ: return "PreChargeReq";
        case JPV2G_POWER_DELIVERY_REQ: return "PowerDeliveryReq";
        case JPV2G_CURRENT_DEMAND_REQ: return "CurrentDemandReq";
        case JPV2G_METERING_RECEIPT_REQ: return "MeteringReceiptReq";
        case JPV2G_WELDING_DETECTION_REQ: return "WeldingDetectionReq";
        case JPV2G_SESSION_STOP_REQ: return "SessionStopReq";
        default: return "Unknown";
    }
}

static void secc_log_exi_hex(const char *tag, jpv2g_message_type_t type, const uint8_t *payload, size_t len) {
    if (!tag || !payload || len == 0) return;
    const size_t max_dump = 96;
    size_t dump_len = len > max_dump ? max_dump : len;
    char hex[(max_dump * 2) + 1];
    if (jpv2g_bytes_to_hex(payload, dump_len, hex, sizeof(hex)) != 0) return;
    JPV2G_INFO("%s %s exi_len=%u exi_hex=%s%s",
               tag,
               secc_msg_name(type),
               (unsigned)len,
               hex,
               (dump_len < len) ? "..." : "");
}

static double secc_pow10_i8(int8_t m) {
    double scale = 1.0;
    if (m > 0) {
        for (int8_t i = 0; i < m; ++i) scale *= 10.0;
    } else if (m < 0) {
        for (int8_t i = 0; i < (int8_t)(-m); ++i) scale /= 10.0;
    }
    return scale;
}

static double secc_iso_pv_to_double(const struct iso2_PhysicalValueType *pv) {
    if (!pv) return 0.0;
    return (double)pv->Value * secc_pow10_i8(pv->Multiplier);
}

static double secc_din_pv_to_double(const struct din_PhysicalValueType *pv) {
    if (!pv) return 0.0;
    return (double)pv->Value * secc_pow10_i8(pv->Multiplier);
}

static bool secc_should_log_current_demand(uint32_t loop_count) {
    if (loop_count == 0u) return false;
    return (loop_count % SECC_CURRENT_DEMAND_LOG_EVERY) == 0u;
}

static bool secc_iso_cap_precharge_current(struct iso2_PreChargeReqType *rq) {
    if (!rq) return false;
    if (secc_iso_pv_to_double(&rq->EVTargetCurrent) <= 2.0) return false;
    rq->EVTargetCurrent.Multiplier = 0;
    rq->EVTargetCurrent.Unit = iso2_unitSymbolType_A;
    rq->EVTargetCurrent.Value = 2;
    return true;
}

static bool secc_din_cap_precharge_current(struct din_PreChargeReqType *rq) {
    if (!rq) return false;
    if (secc_din_pv_to_double(&rq->EVTargetCurrent) <= 2.0) return false;
    rq->EVTargetCurrent.Multiplier = 0;
    rq->EVTargetCurrent.Unit_isUsed = 1;
    rq->EVTargetCurrent.Unit = din_unitSymbolType_A;
    rq->EVTargetCurrent.Value = 2;
    return true;
}

static int64_t secc_iso_pv_or_neg1(const struct iso2_PhysicalValueType *pv, unsigned used) {
    if (!pv || !used) return -1;
    return (int64_t)secc_iso_pv_to_double(pv);
}

static int64_t secc_din_pv_or_neg1(const struct din_PhysicalValueType *pv, unsigned used) {
    if (!pv || !used) return -1;
    return (int64_t)secc_din_pv_to_double(pv);
}

static const char *secc_iso_resp_code_str(iso2_responseCodeType code) {
    switch (code) {
        case iso2_responseCodeType_OK: return "OK";
        case iso2_responseCodeType_OK_NewSessionEstablished: return "OK_NewSessionEstablished";
        case iso2_responseCodeType_OK_OldSessionJoined: return "OK_OldSessionJoined";
        case iso2_responseCodeType_OK_CertificateExpiresSoon: return "OK_CertificateExpiresSoon";
        case iso2_responseCodeType_FAILED: return "FAILED";
        case iso2_responseCodeType_FAILED_SequenceError: return "FAILED_SequenceError";
        case iso2_responseCodeType_FAILED_ServiceIDInvalid: return "FAILED_ServiceIDInvalid";
        case iso2_responseCodeType_FAILED_UnknownSession: return "FAILED_UnknownSession";
        case iso2_responseCodeType_FAILED_ServiceSelectionInvalid: return "FAILED_ServiceSelectionInvalid";
        case iso2_responseCodeType_FAILED_PaymentSelectionInvalid: return "FAILED_PaymentSelectionInvalid";
        case iso2_responseCodeType_FAILED_CertificateExpired: return "FAILED_CertificateExpired";
        case iso2_responseCodeType_FAILED_SignatureError: return "FAILED_SignatureError";
        case iso2_responseCodeType_FAILED_NoCertificateAvailable: return "FAILED_NoCertificateAvailable";
        case iso2_responseCodeType_FAILED_CertChainError: return "FAILED_CertChainError";
        case iso2_responseCodeType_FAILED_ChallengeInvalid: return "FAILED_ChallengeInvalid";
        case iso2_responseCodeType_FAILED_ContractCanceled: return "FAILED_ContractCanceled";
        case iso2_responseCodeType_FAILED_WrongChargeParameter: return "FAILED_WrongChargeParameter";
        case iso2_responseCodeType_FAILED_PowerDeliveryNotApplied: return "FAILED_PowerDeliveryNotApplied";
        case iso2_responseCodeType_FAILED_TariffSelectionInvalid: return "FAILED_TariffSelectionInvalid";
        case iso2_responseCodeType_FAILED_ChargingProfileInvalid: return "FAILED_ChargingProfileInvalid";
        case iso2_responseCodeType_FAILED_MeteringSignatureNotValid: return "FAILED_MeteringSignatureNotValid";
        case iso2_responseCodeType_FAILED_NoChargeServiceSelected: return "FAILED_NoChargeServiceSelected";
        case iso2_responseCodeType_FAILED_WrongEnergyTransferMode: return "FAILED_WrongEnergyTransferMode";
        case iso2_responseCodeType_FAILED_ContactorError: return "FAILED_ContactorError";
        case iso2_responseCodeType_FAILED_CertificateNotAllowedAtThisEVSE: return "FAILED_CertificateNotAllowedAtThisEVSE";
        case iso2_responseCodeType_FAILED_CertificateRevoked: return "FAILED_CertificateRevoked";
        default: return "UNKNOWN";
    }
}

static const char *secc_din_resp_code_str(din_responseCodeType code) {
    switch (code) {
        case din_responseCodeType_OK: return "OK";
        case din_responseCodeType_OK_NewSessionEstablished: return "OK_NewSessionEstablished";
        case din_responseCodeType_OK_OldSessionJoined: return "OK_OldSessionJoined";
        case din_responseCodeType_OK_CertificateExpiresSoon: return "OK_CertificateExpiresSoon";
        case din_responseCodeType_FAILED: return "FAILED";
        case din_responseCodeType_FAILED_SequenceError: return "FAILED_SequenceError";
        case din_responseCodeType_FAILED_ServiceIDInvalid: return "FAILED_ServiceIDInvalid";
        case din_responseCodeType_FAILED_UnknownSession: return "FAILED_UnknownSession";
        case din_responseCodeType_FAILED_ServiceSelectionInvalid: return "FAILED_ServiceSelectionInvalid";
        case din_responseCodeType_FAILED_PaymentSelectionInvalid: return "FAILED_PaymentSelectionInvalid";
        case din_responseCodeType_FAILED_CertificateExpired: return "FAILED_CertificateExpired";
        case din_responseCodeType_FAILED_SignatureError: return "FAILED_SignatureError";
        case din_responseCodeType_FAILED_NoCertificateAvailable: return "FAILED_NoCertificateAvailable";
        case din_responseCodeType_FAILED_CertChainError: return "FAILED_CertChainError";
        case din_responseCodeType_FAILED_ChallengeInvalid: return "FAILED_ChallengeInvalid";
        case din_responseCodeType_FAILED_ContractCanceled: return "FAILED_ContractCanceled";
        case din_responseCodeType_FAILED_WrongChargeParameter: return "FAILED_WrongChargeParameter";
        case din_responseCodeType_FAILED_PowerDeliveryNotApplied: return "FAILED_PowerDeliveryNotApplied";
        case din_responseCodeType_FAILED_TariffSelectionInvalid: return "FAILED_TariffSelectionInvalid";
        case din_responseCodeType_FAILED_ChargingProfileInvalid: return "FAILED_ChargingProfileInvalid";
        case din_responseCodeType_FAILED_EVSEPresentVoltageToLow: return "FAILED_EVSEPresentVoltageToLow";
        case din_responseCodeType_FAILED_MeteringSignatureNotValid: return "FAILED_MeteringSignatureNotValid";
        case din_responseCodeType_FAILED_WrongEnergyTransferType: return "FAILED_WrongEnergyTransferType";
        default: return "UNKNOWN";
    }
}

static const char *secc_iso_proc_str(iso2_EVSEProcessingType p) {
    switch (p) {
        case iso2_EVSEProcessingType_Finished: return "Finished";
        case iso2_EVSEProcessingType_Ongoing: return "Ongoing";
        case iso2_EVSEProcessingType_Ongoing_WaitingForCustomerInteraction: return "Ongoing_WaitingForCustomerInteraction";
        default: return "Unknown";
    }
}

static const char *secc_din_proc_str(din_EVSEProcessingType p) {
    switch (p) {
        case din_EVSEProcessingType_Finished: return "Finished";
        case din_EVSEProcessingType_Ongoing: return "Ongoing";
        default: return "Unknown";
    }
}

static const char *secc_iso_dc_status_str(iso2_DC_EVSEStatusCodeType code) {
    switch (code) {
        case iso2_DC_EVSEStatusCodeType_EVSE_NotReady: return "EVSE_NotReady";
        case iso2_DC_EVSEStatusCodeType_EVSE_Ready: return "EVSE_Ready";
        case iso2_DC_EVSEStatusCodeType_EVSE_Shutdown: return "EVSE_Shutdown";
        case iso2_DC_EVSEStatusCodeType_EVSE_UtilityInterruptEvent: return "EVSE_UtilityInterruptEvent";
        case iso2_DC_EVSEStatusCodeType_EVSE_IsolationMonitoringActive: return "EVSE_IsolationMonitoringActive";
        case iso2_DC_EVSEStatusCodeType_EVSE_EmergencyShutdown: return "EVSE_EmergencyShutdown";
        case iso2_DC_EVSEStatusCodeType_EVSE_Malfunction: return "EVSE_Malfunction";
        default: return "EVSE_Unknown";
    }
}

static const char *secc_din_dc_status_str(din_DC_EVSEStatusCodeType code) {
    switch (code) {
        case din_DC_EVSEStatusCodeType_EVSE_NotReady: return "EVSE_NotReady";
        case din_DC_EVSEStatusCodeType_EVSE_Ready: return "EVSE_Ready";
        case din_DC_EVSEStatusCodeType_EVSE_Shutdown: return "EVSE_Shutdown";
        case din_DC_EVSEStatusCodeType_EVSE_UtilityInterruptEvent: return "EVSE_UtilityInterruptEvent";
        case din_DC_EVSEStatusCodeType_EVSE_IsolationMonitoringActive: return "EVSE_IsolationMonitoringActive";
        case din_DC_EVSEStatusCodeType_EVSE_EmergencyShutdown: return "EVSE_EmergencyShutdown";
        case din_DC_EVSEStatusCodeType_EVSE_Malfunction: return "EVSE_Malfunction";
        default: return "EVSE_Unknown";
    }
}

static const char *secc_iso_etm_str(iso2_EnergyTransferModeType etm) {
    switch (etm) {
        case iso2_EnergyTransferModeType_AC_single_phase_core: return "AC_single_phase_core";
        case iso2_EnergyTransferModeType_AC_three_phase_core: return "AC_three_phase_core";
        case iso2_EnergyTransferModeType_DC_core: return "DC_core";
        case iso2_EnergyTransferModeType_DC_extended: return "DC_extended";
        case iso2_EnergyTransferModeType_DC_combo_core: return "DC_combo_core";
        case iso2_EnergyTransferModeType_DC_unique: return "DC_unique";
        default: return "Unknown";
    }
}

static const char *secc_iso_payment_str(iso2_paymentOptionType opt) {
    switch (opt) {
        case iso2_paymentOptionType_Contract: return "Contract";
        case iso2_paymentOptionType_ExternalPayment: return "ExternalPayment";
        default: return "Unknown";
    }
}

static const char *secc_iso_charge_progress_str(iso2_chargeProgressType p) {
    switch (p) {
        case iso2_chargeProgressType_Start: return "Start";
        case iso2_chargeProgressType_Stop: return "Stop";
        case iso2_chargeProgressType_Renegotiate: return "Renegotiate";
        default: return "Unknown";
    }
}

static const char *secc_iso_charging_session_str(iso2_chargingSessionType s) {
    switch (s) {
        case iso2_chargingSessionType_Terminate: return "Terminate";
        case iso2_chargingSessionType_Pause: return "Pause";
        default: return "Unknown";
    }
}

static void secc_log_decoded_app(jpv2g_message_type_t mtype,
                                 const jpv2g_secc_request_t *req,
                                 const uint8_t *out_payload,
                                 size_t out_len) {
    if (!req || !req->body || mtype != JPV2G_SUPP_APP_PROTOCOL_REQ) return;
    const struct appHand_supportedAppProtocolReq *app =
        (const struct appHand_supportedAppProtocolReq *)req->body;

    struct appHand_exiDocument res_doc;
    init_appHand_exiDocument(&res_doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)out_payload, out_len, 0, NULL);
    if (decode_appHand_exiDocument(&stream, &res_doc) != 0 || !res_doc.supportedAppProtocolRes_isUsed) {
        return;
    }

    char offered[320];
    size_t off = 0;
    offered[0] = '\0';
    for (uint16_t i = 0; i < app->AppProtocol.arrayLen; ++i) {
        const struct appHand_AppProtocolType *ap = &app->AppProtocol.array[i];
        int w = snprintf(offered + off,
                         sizeof(offered) - off,
                         "%s{\"schema\":%u,\"prio\":%u,\"ns\":\"%.*s\"}",
                         (i == 0) ? "" : ",",
                         (unsigned)ap->SchemaID,
                         (unsigned)ap->Priority,
                         (int)ap->ProtocolNamespace.charactersLen,
                         ap->ProtocolNamespace.characters);
        if (w < 0) break;
        size_t ws = (size_t)w;
        if (ws >= (sizeof(offered) - off)) {
            off = sizeof(offered) - 1;
            break;
        }
        off += ws;
    }
    offered[sizeof(offered) - 1] = '\0';

    JPV2G_INFO("DECODED {\"msg\":\"SupportedAppProtocol\",\"req\":{\"protocols\":[%s]},\"res\":{\"responseCode\":%u,\"schema\":%u}}",
               offered,
               (unsigned)res_doc.supportedAppProtocolRes.ResponseCode,
               (unsigned)res_doc.supportedAppProtocolRes.SchemaID);
}

static void secc_log_decoded_iso(jpv2g_message_type_t mtype,
                                 const jpv2g_secc_request_t *req,
                                 const uint8_t *out_payload,
                                 size_t out_len) {
    static uint32_t s_iso_current_demand_loop = 0;
    if (!req || !req->body) return;
    if (mtype == JPV2G_SESSION_SETUP_REQ) s_iso_current_demand_loop = 0;

    struct iso2_exiDocument res_doc;
    init_iso2_exiDocument(&res_doc);
    exi_bitstream_t out_stream;
    exi_bitstream_init(&out_stream, (uint8_t *)out_payload, out_len, 0, NULL);
    if (decode_iso2_exiDocument(&out_stream, &res_doc) != 0) return;
    const struct iso2_BodyType *rb = &res_doc.V2G_Message.Body;

    switch (mtype) {
        case JPV2G_SESSION_SETUP_REQ: {
            const struct iso2_SessionSetupReqType *rq = (const struct iso2_SessionSetupReqType *)req->body;
            if (!rb->SessionSetupRes_isUsed) break;
            char evcc_hex[(iso2_evccIDType_BYTES_SIZE * 2) + 1];
            char sid_hex[(iso2_sessionIDType_BYTES_SIZE * 2) + 1];
            if (jpv2g_bytes_to_hex(rq->EVCCID.bytes, rq->EVCCID.bytesLen, evcc_hex, sizeof(evcc_hex)) != 0) strcpy(evcc_hex, "");
            if (jpv2g_bytes_to_hex(res_doc.V2G_Message.Header.SessionID.bytes,
                                   res_doc.V2G_Message.Header.SessionID.bytesLen,
                                   sid_hex,
                                   sizeof(sid_hex)) != 0) strcpy(sid_hex, "");
            JPV2G_INFO("DECODED ISO {\"msg\":\"SessionSetup\",\"req\":{\"evccId\":\"%s\"},\"res\":{\"responseCode\":\"%s\",\"evseId\":\"%.*s\",\"sessionId\":\"%s\"}}",
                       evcc_hex,
                       secc_iso_resp_code_str(rb->SessionSetupRes.ResponseCode),
                       (int)rb->SessionSetupRes.EVSEID.charactersLen,
                       rb->SessionSetupRes.EVSEID.characters,
                       sid_hex);
            break;
        }
        case JPV2G_SERVICE_DISCOVERY_REQ: {
            const struct iso2_ServiceDiscoveryReqType *rq = (const struct iso2_ServiceDiscoveryReqType *)req->body;
            if (!rb->ServiceDiscoveryRes_isUsed) break;
            char pay[64] = {0};
            char etms[160] = {0};
            size_t pay_off = 0;
            size_t etm_off = 0;
            for (uint16_t i = 0; i < rb->ServiceDiscoveryRes.PaymentOptionList.PaymentOption.arrayLen; ++i) {
                const char *p = secc_iso_payment_str(rb->ServiceDiscoveryRes.PaymentOptionList.PaymentOption.array[i]);
                int w = snprintf(pay + pay_off, sizeof(pay) - pay_off, "%s\"%s\"", (i == 0) ? "" : ",", p);
                if (w < 0 || (size_t)w >= (sizeof(pay) - pay_off)) break;
                pay_off += (size_t)w;
            }
            for (uint16_t i = 0; i < rb->ServiceDiscoveryRes.ChargeService.SupportedEnergyTransferMode.EnergyTransferMode.arrayLen; ++i) {
                const char *e = secc_iso_etm_str(rb->ServiceDiscoveryRes.ChargeService.SupportedEnergyTransferMode.EnergyTransferMode.array[i]);
                int w = snprintf(etms + etm_off, sizeof(etms) - etm_off, "%s\"%s\"", (i == 0) ? "" : ",", e);
                if (w < 0 || (size_t)w >= (sizeof(etms) - etm_off)) break;
                etm_off += (size_t)w;
            }
            JPV2G_INFO("DECODED ISO {\"msg\":\"ServiceDiscovery\",\"req\":{\"scope\":\"%.*s\",\"category\":%d},\"res\":{\"responseCode\":\"%s\",\"payments\":[%s],\"serviceId\":%u,\"serviceName\":\"%.*s\",\"freeService\":%d,\"etm\":[%s]}}",
                       rq->ServiceScope_isUsed ? (int)rq->ServiceScope.charactersLen : 0,
                       rq->ServiceScope_isUsed ? rq->ServiceScope.characters : "",
                       rq->ServiceCategory_isUsed ? (int)rq->ServiceCategory : -1,
                       secc_iso_resp_code_str(rb->ServiceDiscoveryRes.ResponseCode),
                       pay,
                       (unsigned)rb->ServiceDiscoveryRes.ChargeService.ServiceID,
                       rb->ServiceDiscoveryRes.ChargeService.ServiceName_isUsed ? (int)rb->ServiceDiscoveryRes.ChargeService.ServiceName.charactersLen : 0,
                       rb->ServiceDiscoveryRes.ChargeService.ServiceName_isUsed ? rb->ServiceDiscoveryRes.ChargeService.ServiceName.characters : "",
                       rb->ServiceDiscoveryRes.ChargeService.FreeService,
                       etms);
            break;
        }
        case JPV2G_PAYMENT_SERVICE_SELECTION_REQ: {
            const struct iso2_PaymentServiceSelectionReqType *rq = (const struct iso2_PaymentServiceSelectionReqType *)req->body;
            if (!rb->PaymentServiceSelectionRes_isUsed) break;
            int16_t psid = -1;
            if (rq->SelectedServiceList.SelectedService.arrayLen > 0) {
                psid = (int16_t)rq->SelectedServiceList.SelectedService.array[0].ServiceID;
            }
            JPV2G_INFO("DECODED ISO {\"msg\":\"PaymentServiceSelection\",\"req\":{\"payment\":\"%s\",\"paymentRaw\":%d,\"serviceId\":%d},\"res\":{\"responseCode\":\"%s\"}}",
                       secc_iso_payment_str(rq->SelectedPaymentOption),
                       (int)rq->SelectedPaymentOption,
                       (int)psid,
                       secc_iso_resp_code_str(rb->PaymentServiceSelectionRes.ResponseCode));
            break;
        }
        case JPV2G_AUTHORIZATION_REQ: {
            const struct iso2_AuthorizationReqType *rq = (const struct iso2_AuthorizationReqType *)req->body;
            if (!rb->AuthorizationRes_isUsed) break;
            JPV2G_INFO("DECODED ISO {\"msg\":\"Authorization\",\"req\":{\"genChallengeLen\":%u},\"res\":{\"responseCode\":\"%s\",\"processing\":\"%s\"}}",
                       (unsigned)(rq->GenChallenge_isUsed ? rq->GenChallenge.bytesLen : 0),
                       secc_iso_resp_code_str(rb->AuthorizationRes.ResponseCode),
                       secc_iso_proc_str(rb->AuthorizationRes.EVSEProcessing));
            break;
        }
        case JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ: {
            const struct iso2_ChargeParameterDiscoveryReqType *rq = (const struct iso2_ChargeParameterDiscoveryReqType *)req->body;
            if (!rb->ChargeParameterDiscoveryRes_isUsed) break;
            int32_t soc = rq->DC_EVChargeParameter_isUsed ? (int32_t)rq->DC_EVChargeParameter.DC_EVStatus.EVRESSSOC : -1;
            double ev_max_i = rq->DC_EVChargeParameter_isUsed ? secc_iso_pv_to_double(&rq->DC_EVChargeParameter.EVMaximumCurrentLimit) : 0.0;
            double ev_max_v = rq->DC_EVChargeParameter_isUsed ? secc_iso_pv_to_double(&rq->DC_EVChargeParameter.EVMaximumVoltageLimit) : 0.0;
            double evse_max_i = rb->ChargeParameterDiscoveryRes.DC_EVSEChargeParameter_isUsed
                                    ? secc_iso_pv_to_double(&rb->ChargeParameterDiscoveryRes.DC_EVSEChargeParameter.EVSEMaximumCurrentLimit)
                                    : 0.0;
            double evse_max_v = rb->ChargeParameterDiscoveryRes.DC_EVSEChargeParameter_isUsed
                                    ? secc_iso_pv_to_double(&rb->ChargeParameterDiscoveryRes.DC_EVSEChargeParameter.EVSEMaximumVoltageLimit)
                                    : 0.0;
            double evse_max_p_kw = rb->ChargeParameterDiscoveryRes.DC_EVSEChargeParameter_isUsed
                                       ? secc_iso_pv_to_double(&rb->ChargeParameterDiscoveryRes.DC_EVSEChargeParameter.EVSEMaximumPowerLimit) / 1000.0
                                       : 0.0;
            JPV2G_INFO("DECODED ISO {\"msg\":\"ChargeParameterDiscovery\",\"req\":{\"etm\":\"%s\",\"evMaxA\":%.1f,\"evMaxV\":%.1f,\"soc\":%d},\"res\":{\"responseCode\":\"%s\",\"processing\":\"%s\",\"scheduleCount\":%u,\"evseMaxA\":%.1f,\"evseMaxV\":%.1f,\"evseMaxkW\":%.1f}}",
                       secc_iso_etm_str(rq->RequestedEnergyTransferMode),
                       ev_max_i,
                       ev_max_v,
                       (int)soc,
                       secc_iso_resp_code_str(rb->ChargeParameterDiscoveryRes.ResponseCode),
                       secc_iso_proc_str(rb->ChargeParameterDiscoveryRes.EVSEProcessing),
                       (unsigned)(rb->ChargeParameterDiscoveryRes.SAScheduleList_isUsed ? rb->ChargeParameterDiscoveryRes.SAScheduleList.SAScheduleTuple.arrayLen : 0),
                       evse_max_i,
                       evse_max_v,
                       evse_max_p_kw);
            break;
        }
        case JPV2G_CABLE_CHECK_REQ: {
            const struct iso2_CableCheckReqType *rq = (const struct iso2_CableCheckReqType *)req->body;
            if (!rb->CableCheckRes_isUsed) break;
            JPV2G_INFO("DECODED ISO {\"msg\":\"CableCheck\",\"req\":{\"soc\":%d,\"evReady\":%d},\"res\":{\"responseCode\":\"%s\",\"processing\":\"%s\",\"status\":\"%s\"}}",
                       (int)rq->DC_EVStatus.EVRESSSOC,
                       rq->DC_EVStatus.EVReady,
                       secc_iso_resp_code_str(rb->CableCheckRes.ResponseCode),
                       secc_iso_proc_str(rb->CableCheckRes.EVSEProcessing),
                       secc_iso_dc_status_str(rb->CableCheckRes.DC_EVSEStatus.EVSEStatusCode));
            break;
        }
        case JPV2G_PRE_CHARGE_REQ: {
            const struct iso2_PreChargeReqType *rq = (const struct iso2_PreChargeReqType *)req->body;
            if (!rb->PreChargeRes_isUsed) break;
            JPV2G_INFO("DECODED ISO {\"msg\":\"PreCharge\",\"req\":{\"targetV\":%.1f,\"targetI\":%.1f,\"soc\":%d},\"res\":{\"responseCode\":\"%s\",\"status\":\"%s\",\"v\":%.1f}}",
                       secc_iso_pv_to_double(&rq->EVTargetVoltage),
                       secc_iso_pv_to_double(&rq->EVTargetCurrent),
                       (int)rq->DC_EVStatus.EVRESSSOC,
                       secc_iso_resp_code_str(rb->PreChargeRes.ResponseCode),
                       secc_iso_dc_status_str(rb->PreChargeRes.DC_EVSEStatus.EVSEStatusCode),
                       secc_iso_pv_to_double(&rb->PreChargeRes.EVSEPresentVoltage));
            break;
        }
        case JPV2G_POWER_DELIVERY_REQ: {
            const struct iso2_PowerDeliveryReqType *rq = (const struct iso2_PowerDeliveryReqType *)req->body;
            if (!rb->PowerDeliveryRes_isUsed) break;
            int charging_complete = rq->DC_EVPowerDeliveryParameter_isUsed ? rq->DC_EVPowerDeliveryParameter.ChargingComplete : -1;
            JPV2G_INFO("DECODED ISO {\"msg\":\"PowerDelivery\",\"req\":{\"progress\":\"%s\",\"saId\":%u,\"chargingComplete\":%d},\"res\":{\"responseCode\":\"%s\",\"status\":\"%s\"}}",
                       secc_iso_charge_progress_str(rq->ChargeProgress),
                       (unsigned)rq->SAScheduleTupleID,
                       charging_complete,
                       secc_iso_resp_code_str(rb->PowerDeliveryRes.ResponseCode),
                       rb->PowerDeliveryRes.DC_EVSEStatus_isUsed
                           ? secc_iso_dc_status_str(rb->PowerDeliveryRes.DC_EVSEStatus.EVSEStatusCode)
                           : "n/a");
            break;
        }
        case JPV2G_CURRENT_DEMAND_REQ: {
            const struct iso2_CurrentDemandReqType *rq = (const struct iso2_CurrentDemandReqType *)req->body;
            if (!rb->CurrentDemandRes_isUsed) break;
            s_iso_current_demand_loop++;
            if (!secc_should_log_current_demand(s_iso_current_demand_loop)) break;
            const struct iso2_CurrentDemandResType *rs = &rb->CurrentDemandRes;
            int64_t wh = (rs->MeterInfo_isUsed && rs->MeterInfo.MeterReading_isUsed) ? (int64_t)rs->MeterInfo.MeterReading : -1;
            JPV2G_INFO("DECODED ISO {\"msg\":\"CurrentDemand\",\"loop\":%u,\"req\":{\"targetV\":%.1f,\"targetI\":%.1f,\"soc\":%d,\"chargingComplete\":%d,\"bulkChargingComplete\":%d,\"remainingFullS\":%lld,\"remainingBulkS\":%lld},\"res\":{\"responseCode\":\"%s\",\"status\":\"%s\",\"v\":%.1f,\"i\":%.1f,\"wh\":%lld}}",
                       (unsigned)s_iso_current_demand_loop,
                       secc_iso_pv_to_double(&rq->EVTargetVoltage),
                       secc_iso_pv_to_double(&rq->EVTargetCurrent),
                       (int)rq->DC_EVStatus.EVRESSSOC,
                       rq->ChargingComplete ? 1 : 0,
                       rq->BulkChargingComplete_isUsed ? (rq->BulkChargingComplete ? 1 : 0) : -1,
                       (long long)secc_iso_pv_or_neg1(&rq->RemainingTimeToFullSoC, rq->RemainingTimeToFullSoC_isUsed),
                       (long long)secc_iso_pv_or_neg1(&rq->RemainingTimeToBulkSoC, rq->RemainingTimeToBulkSoC_isUsed),
                       secc_iso_resp_code_str(rs->ResponseCode),
                       secc_iso_dc_status_str(rs->DC_EVSEStatus.EVSEStatusCode),
                       secc_iso_pv_to_double(&rs->EVSEPresentVoltage),
                       secc_iso_pv_to_double(&rs->EVSEPresentCurrent),
                       (long long)wh);
            break;
        }
        case JPV2G_METERING_RECEIPT_REQ: {
            const struct iso2_MeteringReceiptReqType *rq = (const struct iso2_MeteringReceiptReqType *)req->body;
            if (!rb->MeteringReceiptRes_isUsed) break;
            int64_t wh = rq->MeterInfo.MeterReading_isUsed ? (int64_t)rq->MeterInfo.MeterReading : -1;
            JPV2G_INFO("DECODED ISO {\"msg\":\"MeteringReceipt\",\"req\":{\"meterWh\":%lld,\"saId\":%d},\"res\":{\"responseCode\":\"%s\"}}",
                       (long long)wh,
                       rq->SAScheduleTupleID_isUsed ? (int)rq->SAScheduleTupleID : -1,
                       secc_iso_resp_code_str(rb->MeteringReceiptRes.ResponseCode));
            break;
        }
        case JPV2G_WELDING_DETECTION_REQ: {
            const struct iso2_WeldingDetectionReqType *rq = (const struct iso2_WeldingDetectionReqType *)req->body;
            if (!rb->WeldingDetectionRes_isUsed) break;
            JPV2G_INFO("DECODED ISO {\"msg\":\"WeldingDetection\",\"req\":{\"soc\":%d},\"res\":{\"responseCode\":\"%s\",\"status\":\"%s\",\"v\":%.1f}}",
                       (int)rq->DC_EVStatus.EVRESSSOC,
                       secc_iso_resp_code_str(rb->WeldingDetectionRes.ResponseCode),
                       secc_iso_dc_status_str(rb->WeldingDetectionRes.DC_EVSEStatus.EVSEStatusCode),
                       secc_iso_pv_to_double(&rb->WeldingDetectionRes.EVSEPresentVoltage));
            break;
        }
        case JPV2G_SESSION_STOP_REQ: {
            const struct iso2_SessionStopReqType *rq = (const struct iso2_SessionStopReqType *)req->body;
            if (!rb->SessionStopRes_isUsed) break;
            s_iso_current_demand_loop = 0;
            JPV2G_INFO("DECODED ISO {\"msg\":\"SessionStop\",\"req\":{\"chargingSession\":\"%s\"},\"res\":{\"responseCode\":\"%s\"}}",
                       secc_iso_charging_session_str(rq->ChargingSession),
                       secc_iso_resp_code_str(rb->SessionStopRes.ResponseCode));
            break;
        }
        default:
            break;
    }
}

static void secc_log_decoded_din(jpv2g_message_type_t mtype,
                                 const jpv2g_secc_request_t *req,
                                 const uint8_t *out_payload,
                                 size_t out_len) {
    static uint32_t s_din_current_demand_loop = 0;
    if (!req || !req->body) return;
    if (mtype == JPV2G_SESSION_SETUP_REQ) s_din_current_demand_loop = 0;

    struct din_exiDocument res_doc;
    init_din_exiDocument(&res_doc);
    exi_bitstream_t out_stream;
    exi_bitstream_init(&out_stream, (uint8_t *)out_payload, out_len, 0, NULL);
    if (decode_din_exiDocument(&out_stream, &res_doc) != 0) return;
    const struct din_BodyType *rb = &res_doc.V2G_Message.Body;

    switch (mtype) {
        case JPV2G_CURRENT_DEMAND_REQ: {
            const struct din_CurrentDemandReqType *rq = (const struct din_CurrentDemandReqType *)req->body;
            if (!rb->CurrentDemandRes_isUsed) break;
            const struct din_CurrentDemandResType *rs = &rb->CurrentDemandRes;
            s_din_current_demand_loop++;
            if (!secc_should_log_current_demand(s_din_current_demand_loop)) break;
            JPV2G_INFO("DECODED DIN {\"msg\":\"CurrentDemand\",\"loop\":%u,\"req\":{\"targetV\":%.1f,\"targetI\":%.1f,\"soc\":%d,\"chargingComplete\":%d,\"bulkChargingComplete\":%d,\"remainingFullS\":%lld,\"remainingBulkS\":%lld},\"res\":{\"responseCode\":\"%s\",\"status\":\"%s\",\"v\":%.1f,\"i\":%.1f}}",
                       (unsigned)s_din_current_demand_loop,
                       secc_din_pv_to_double(&rq->EVTargetVoltage),
                       secc_din_pv_to_double(&rq->EVTargetCurrent),
                       (int)rq->DC_EVStatus.EVRESSSOC,
                       rq->ChargingComplete ? 1 : 0,
                       rq->BulkChargingComplete_isUsed ? (rq->BulkChargingComplete ? 1 : 0) : -1,
                       (long long)secc_din_pv_or_neg1(&rq->RemainingTimeToFullSoC, rq->RemainingTimeToFullSoC_isUsed),
                       (long long)secc_din_pv_or_neg1(&rq->RemainingTimeToBulkSoC, rq->RemainingTimeToBulkSoC_isUsed),
                       secc_din_resp_code_str(rs->ResponseCode),
                       secc_din_dc_status_str(rs->DC_EVSEStatus.EVSEStatusCode),
                       secc_din_pv_to_double(&rs->EVSEPresentVoltage),
                       secc_din_pv_to_double(&rs->EVSEPresentCurrent));
            break;
        }
        case JPV2G_SESSION_STOP_REQ:
            s_din_current_demand_loop = 0;
            break;
        default:
            break;
    }
}

static void secc_log_decoded_transaction(jpv2g_message_type_t mtype,
                                         const jpv2g_secc_request_t *req,
                                         const uint8_t *out_payload,
                                         size_t out_len) {
    if (!s_enable_decoded_logs || !req || !out_payload || out_len == 0) return;
    if (mtype == JPV2G_SUPP_APP_PROTOCOL_REQ) {
        secc_log_decoded_app(mtype, req, out_payload, out_len);
        return;
    }
    if (req->protocol == JPV2G_PROTOCOL_ISO15118_2) {
        secc_log_decoded_iso(mtype, req, out_payload, out_len);
    } else if (req->protocol == JPV2G_PROTOCOL_DIN70121) {
        secc_log_decoded_din(mtype, req, out_payload, out_len);
    }
}

static bool secc_sid_all_zero(const uint8_t *sid, size_t len) {
    if (!sid || len == 0) return true;
    for (size_t i = 0; i < len; ++i) {
        if (sid[i] != 0) return false;
    }
    return true;
}

static bool secc_has_active_session(const jpv2g_secc_t *secc) {
    if (!secc) return false;
    return !secc_sid_all_zero(secc->session_id, sizeof(secc->session_id));
}

static const uint8_t *secc_resolve_session(jpv2g_secc_t *secc,
                                           jpv2g_message_type_t type,
                                           const struct iso2_MessageHeaderType *iso_hdr,
                                           const struct din_MessageHeaderType *din_hdr,
                                           bool *old_session_joined) {
    if (!secc) return NULL;
    if (old_session_joined) *old_session_joined = false;

    bool incoming_has_sid = false;
    bool incoming_sid_zero = true;
    uint8_t incoming_sid[iso2_sessionIDType_BYTES_SIZE] = {0};

    if (iso_hdr && iso_hdr->SessionID.bytesLen == iso2_sessionIDType_BYTES_SIZE) {
        incoming_has_sid = true;
        memcpy(incoming_sid, iso_hdr->SessionID.bytes, sizeof(incoming_sid));
        incoming_sid_zero = secc_sid_all_zero(incoming_sid, sizeof(incoming_sid));
    } else if (din_hdr && din_hdr->SessionID.bytesLen == din_sessionIDType_BYTES_SIZE) {
        incoming_has_sid = true;
        memcpy(incoming_sid, din_hdr->SessionID.bytes, sizeof(incoming_sid));
        incoming_sid_zero = secc_sid_all_zero(incoming_sid, sizeof(incoming_sid));
    }

    if (type == JPV2G_SESSION_SETUP_REQ) {
        if (incoming_has_sid && !incoming_sid_zero) {
            memcpy(secc->session_id, incoming_sid, sizeof(secc->session_id));
            if (old_session_joined) *old_session_joined = true;
        } else {
            jpv2g_generate_session_id(NULL, secc->session_id);
        }
        return secc->session_id;
    }

    if (!secc_has_active_session(secc)) {
        if (incoming_has_sid && !incoming_sid_zero) {
            memcpy(secc->session_id, incoming_sid, sizeof(secc->session_id));
        } else {
            jpv2g_generate_session_id(NULL, secc->session_id);
        }
    }
    return secc->session_id;
}

static void secc_fill_iso_meter_info(jpv2g_secc_t *secc, struct iso2_MeterInfoType *meter) {
    if (!secc || !meter) return;
    init_iso2_MeterInfoType(meter);
    size_t len = strlen(secc->meter_id);
    if (len >= iso2_MeterID_CHARACTER_SIZE) len = iso2_MeterID_CHARACTER_SIZE - 1;
    memcpy(meter->MeterID.characters, secc->meter_id, len);
    meter->MeterID.charactersLen = (uint16_t)len;
    meter->MeterReading = (uint64_t)(secc->meter_Wh);
    meter->MeterReading_isUsed = 1;
    meter->MeterStatus = 0;
    meter->MeterStatus_isUsed = 1;
}

static void secc_fill_din_meter_info(jpv2g_secc_t *secc, struct din_MeterInfoType *meter) {
    if (!secc || !meter) return;
    init_din_MeterInfoType(meter);
    size_t len = strlen(secc->meter_id);
    if (len >= din_MeterID_CHARACTER_SIZE) len = din_MeterID_CHARACTER_SIZE - 1;
    memcpy(meter->MeterID.characters, secc->meter_id, len);
    meter->MeterID.charactersLen = (uint16_t)len;
    meter->MeterReading.Value = (int16_t)(secc->meter_Wh);
    meter->MeterReading.Multiplier = 0;
    meter->MeterReading.Unit = din_unitSymbolType_Wh;
    meter->MeterReading_isUsed = 1;
}

static void secc_bump_meter(jpv2g_secc_t *secc, int64_t delta_Wh) {
    if (!secc) return;
    secc->meter_Wh += delta_Wh;
    if (secc->meter_Wh < 0) secc->meter_Wh = 0;
}

static iso2_EnergyTransferModeType secc_select_iso_etm(const jpv2g_secc_t *secc) {
    (void)secc;
    return iso2_EnergyTransferModeType_DC_extended;
}

static din_EVSESupportedEnergyTransferType secc_select_din_etm(const jpv2g_secc_t *secc) {
    (void)secc;
    return din_EVSESupportedEnergyTransferType_DC_combo_core;
}

static bool secc_iso_etm_supported(iso2_EnergyTransferModeType etm) {
    return etm == iso2_EnergyTransferModeType_DC_core ||
           etm == iso2_EnergyTransferModeType_DC_extended ||
           etm == iso2_EnergyTransferModeType_DC_combo_core;
}

static int secc_encode_iso_service_discovery_res_multi(
    const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
    iso2_responseCodeType code,
    const iso2_paymentOptionType *payments,
    size_t payment_count,
    const iso2_EnergyTransferModeType *etm,
    size_t etm_count,
    uint16_t service_id,
    const char *service_name,
    int free_service,
    uint8_t *out,
    size_t out_len,
    size_t *written) {
    if (!session_id || !payments || payment_count == 0 || !etm || etm_count == 0 || !out) return -EINVAL;
    struct iso2_exiDocument doc;
    init_iso2_exiDocument(&doc);
    init_iso2_MessageHeaderType(&doc.V2G_Message.Header);
    memcpy(doc.V2G_Message.Header.SessionID.bytes, session_id, iso2_sessionIDType_BYTES_SIZE);
    doc.V2G_Message.Header.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE;
    init_iso2_BodyType(&doc.V2G_Message.Body);
    doc.V2G_Message.Body.ServiceDiscoveryRes_isUsed = 1;
    init_iso2_ServiceDiscoveryResType(&doc.V2G_Message.Body.ServiceDiscoveryRes);
    struct iso2_ServiceDiscoveryResType *res = &doc.V2G_Message.Body.ServiceDiscoveryRes;
    res->ResponseCode = code;

    init_iso2_PaymentOptionListType(&res->PaymentOptionList);
    size_t pay_to_copy = payment_count > iso2_paymentOptionType_2_ARRAY_SIZE
                             ? iso2_paymentOptionType_2_ARRAY_SIZE
                             : payment_count;
    res->PaymentOptionList.PaymentOption.arrayLen = (uint16_t)pay_to_copy;
    for (size_t i = 0; i < pay_to_copy; ++i) {
        res->PaymentOptionList.PaymentOption.array[i] = payments[i];
    }

    init_iso2_ChargeServiceType(&res->ChargeService);
    res->ChargeService.ServiceID = service_id;
    res->ChargeService.ServiceCategory = iso2_serviceCategoryType_EVCharging;
    res->ChargeService.FreeService = free_service ? 1 : 0;
    init_iso2_SupportedEnergyTransferModeType(&res->ChargeService.SupportedEnergyTransferMode);
    size_t etm_to_copy = etm_count > iso2_EnergyTransferModeType_6_ARRAY_SIZE
                             ? iso2_EnergyTransferModeType_6_ARRAY_SIZE
                             : etm_count;
    res->ChargeService.SupportedEnergyTransferMode.EnergyTransferMode.arrayLen = (uint16_t)etm_to_copy;
    for (size_t i = 0; i < etm_to_copy; ++i) {
        res->ChargeService.SupportedEnergyTransferMode.EnergyTransferMode.array[i] = etm[i];
    }
    if (service_name) {
        size_t sn_len = strnlen(service_name, iso2_ServiceName_CHARACTER_SIZE - 1);
        memcpy(res->ChargeService.ServiceName.characters, service_name, sn_len);
        res->ChargeService.ServiceName.charactersLen = (uint16_t)sn_len;
        res->ChargeService.ServiceName_isUsed = 1;
    }
    res->ServiceList_isUsed = 0;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, &doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

static void secc_set_dc_evse_status_iso(struct iso2_DC_EVSEStatusType *st) {
    init_iso2_DC_EVSEStatusType(st);
    st->NotificationMaxDelay = 1;
    st->EVSENotification = iso2_EVSENotificationType_None;
    st->EVSEStatusCode = iso2_DC_EVSEStatusCodeType_EVSE_Ready;
    st->EVSEIsolationStatus_isUsed = 0;
}

static void secc_set_dc_evse_status_din(struct din_DC_EVSEStatusType *st) {
    init_din_DC_EVSEStatusType(st);
    st->NotificationMaxDelay = 1;
    st->EVSENotification = din_EVSENotificationType_None;
    st->EVSEStatusCode = din_DC_EVSEStatusCodeType_EVSE_Ready;
    st->EVSEIsolationStatus_isUsed = 0;
}

static void secc_set_din_physical(struct din_PhysicalValueType *pv, din_unitSymbolType unit, int16_t value, int8_t mult) {
    if (!pv) return;
    pv->Unit = unit;
    pv->Value = value;
    pv->Multiplier = mult;
}

typedef union {
    struct iso2_ChargeParameterDiscoveryReqType iso_charge_parameter_discovery;
    struct iso2_PaymentServiceSelectionReqType iso_payment_service_selection;
    struct iso2_PreChargeReqType iso_pre_charge;
    struct iso2_CurrentDemandReqType iso_current_demand;
    struct din_PreChargeReqType din_pre_charge;
    struct din_CurrentDemandReqType din_current_demand;
} secc_log_req_copy_t;

static const void *secc_copy_req_body_for_log(jpv2g_protocol_t protocol,
                                              jpv2g_message_type_t mtype,
                                              const void *body,
                                              secc_log_req_copy_t *copy) {
    if (!body || !copy) return body;
    if (protocol == JPV2G_PROTOCOL_ISO15118_2) {
        if (mtype == JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ) {
            copy->iso_charge_parameter_discovery = *(const struct iso2_ChargeParameterDiscoveryReqType *)body;
            return &copy->iso_charge_parameter_discovery;
        }
        if (mtype == JPV2G_PAYMENT_SERVICE_SELECTION_REQ) {
            copy->iso_payment_service_selection = *(const struct iso2_PaymentServiceSelectionReqType *)body;
            return &copy->iso_payment_service_selection;
        }
        if (mtype == JPV2G_PRE_CHARGE_REQ) {
            copy->iso_pre_charge = *(const struct iso2_PreChargeReqType *)body;
            (void)secc_iso_cap_precharge_current(&copy->iso_pre_charge);
            return &copy->iso_pre_charge;
        }
        if (mtype == JPV2G_CURRENT_DEMAND_REQ) {
            copy->iso_current_demand = *(const struct iso2_CurrentDemandReqType *)body;
            return &copy->iso_current_demand;
        }
    } else if (protocol == JPV2G_PROTOCOL_DIN70121) {
        if (mtype == JPV2G_PRE_CHARGE_REQ) {
            copy->din_pre_charge = *(const struct din_PreChargeReqType *)body;
            (void)secc_din_cap_precharge_current(&copy->din_pre_charge);
            return &copy->din_pre_charge;
        }
        if (mtype == JPV2G_CURRENT_DEMAND_REQ) {
            copy->din_current_demand = *(const struct din_CurrentDemandReqType *)body;
            return &copy->din_current_demand;
        }
    }
    return body;
}

int jpv2g_secc_default_handle(jpv2g_secc_t *secc,
                                jpv2g_message_type_t type,
                                const jpv2g_secc_request_t *req,
                                uint8_t *out,
                                size_t out_len,
                                size_t *written) {
    static uint8_t s_last_iso_auth_sid[iso2_sessionIDType_BYTES_SIZE] = {0};
    static bool s_iso_auth_pending_sent = false;

    if (!secc || !req || !out) return -EINVAL;
    static const char kIsoEvseId[] = "IN*JPE*E000100010001";
    static const uint8_t kDinEvseId[] = { 'J','P','E','V','S','E','0','0','0','1','0','0','1','0','0','0','1','0' };

    bool old_session_joined = false;
    const uint8_t *sid = secc_resolve_session(secc, type, req->header, req->din_header, &old_session_joined);
    switch (type) {
        case JPV2G_SUPP_APP_PROTOCOL_REQ: {
            const struct appHand_supportedAppProtocolReq *app = (const struct appHand_supportedAppProtocolReq *)req->body;
            jpv2g_protocol_t det = detect_protocol_from_app(app);
            uint8_t schema = select_schema_for_protocol(app, det);
            if (app) {
                for (uint16_t i = 0; i < app->AppProtocol.arrayLen; ++i) {
                    const struct appHand_AppProtocolType *ap = &app->AppProtocol.array[i];
                    char ns_buf[96];
                    size_t n = ap->ProtocolNamespace.charactersLen;
                    if (n >= sizeof(ns_buf)) n = sizeof(ns_buf) - 1;
                    memcpy(ns_buf, ap->ProtocolNamespace.characters, n);
                    ns_buf[n] = '\0';
                    JPV2G_INFO("SAPP opt[%u] schema=%u prio=%u ns=%s",
                               (unsigned)i,
                               (unsigned)ap->SchemaID,
                               (unsigned)ap->Priority,
                               ns_buf);
                }
            }
            JPV2G_INFO("SAPP selected proto=%d schema=%u", (int)det, (unsigned)schema);
            appHand_responseCodeType code = det != JPV2G_PROTOCOL_UNKNOWN
                                                ? appHand_responseCodeType_OK_SuccessfulNegotiation
                                                : appHand_responseCodeType_Failed_NoNegotiation;
            return jpv2g_cbv2g_encode_sapp_res(schema, code, out, out_len, written);
        }
        case JPV2G_SESSION_SETUP_REQ: {
            if (req->protocol == JPV2G_PROTOCOL_DIN70121) {
                din_responseCodeType code = old_session_joined
                                                ? din_responseCodeType_OK_OldSessionJoined
                                                : din_responseCodeType_OK_NewSessionEstablished;
                return jpv2g_cbv2g_encode_din_session_setup_res(sid,
                                                                 kDinEvseId,
                                                                 sizeof(kDinEvseId),
                                                                 code,
                                                                 (int64_t)time(NULL),
                                                                 out,
                                                                 out_len,
                                                                 written);
            }
            iso2_responseCodeType code = old_session_joined
                                             ? iso2_responseCodeType_OK_OldSessionJoined
                                             : iso2_responseCodeType_OK_NewSessionEstablished;
            memcpy(s_last_iso_auth_sid, sid, sizeof(s_last_iso_auth_sid));
            s_iso_auth_pending_sent = false;
            return jpv2g_cbv2g_encode_session_setup_res(sid, kIsoEvseId, code, out, out_len, written);
        }
        case JPV2G_SERVICE_DISCOVERY_REQ: {
            int free_service = secc->evse_ctl.is_free_charging ? secc->evse_ctl.is_free_charging(secc->evse_ctl.user_ctx) : (secc->cfg.free_charging ? 1 : 0);
            if (req->protocol == JPV2G_PROTOCOL_DIN70121) {
                return jpv2g_cbv2g_encode_din_service_discovery_res(sid,
                                                                     din_responseCodeType_OK,
                                                                     din_paymentOptionType_Contract,
                                                                     secc_select_din_etm(secc),
                                                                     1,
                                                                     "DCFC",
                                                                     free_service,
                                                                     out,
                                                                     out_len,
                                                                     written);
            }
            const iso2_paymentOptionType payments[1] = {iso2_paymentOptionType_ExternalPayment};
            const iso2_EnergyTransferModeType etms[3] = {
                iso2_EnergyTransferModeType_DC_core,
                iso2_EnergyTransferModeType_DC_extended,
                iso2_EnergyTransferModeType_DC_combo_core};
            return secc_encode_iso_service_discovery_res_multi(sid,
                                                               iso2_responseCodeType_OK,
                                                               payments,
                                                               1,
                                                               etms,
                                                               3,
                                                               1,
                                                               "DCFC",
                                                               free_service,
                                                               out,
                                                               out_len,
                                                               written);
        }
        case JPV2G_SERVICE_DETAIL_REQ: {
            if (req->protocol == JPV2G_PROTOCOL_DIN70121) return -ENOTSUP;
            return jpv2g_cbv2g_encode_service_detail_res(sid, iso2_responseCodeType_OK, 1, NULL, out, out_len, written);
        }
        case JPV2G_PAYMENT_SERVICE_SELECTION_REQ: {
            if (req->protocol == JPV2G_PROTOCOL_DIN70121) {
                return jpv2g_cbv2g_encode_din_service_payment_selection_res(sid, din_responseCodeType_OK, out, out_len, written);
            }
            return jpv2g_cbv2g_encode_payment_service_selection_res(sid, iso2_responseCodeType_OK, out, out_len, written);
        }
        case JPV2G_PAYMENT_DETAILS_REQ: {
            bool ok = secc->backend.authorize_contract ? secc->backend.authorize_contract(secc->backend.user_ctx) : true;
            if (req->protocol == JPV2G_PROTOCOL_DIN70121) {
                return jpv2g_cbv2g_encode_din_payment_details_res(sid, ok ? din_responseCodeType_OK : din_responseCodeType_FAILED, NULL, (int64_t)time(NULL), out, out_len, written);
            }
            return jpv2g_cbv2g_encode_payment_details_res(sid, ok ? iso2_responseCodeType_OK : iso2_responseCodeType_FAILED, NULL, 0, time(NULL), out, out_len, written);
        }
        case JPV2G_AUTHORIZATION_REQ: {
            bool ok = secc->backend.authorize_contract ? secc->backend.authorize_contract(secc->backend.user_ctx) : true;
            if (req->protocol == JPV2G_PROTOCOL_DIN70121) {
                return jpv2g_cbv2g_encode_din_contract_authentication_res(sid, ok ? din_responseCodeType_OK : din_responseCodeType_FAILED, din_EVSEProcessingType_Finished, out, out_len, written);
            }
            if (memcmp(s_last_iso_auth_sid, sid, sizeof(s_last_iso_auth_sid)) != 0) {
                memcpy(s_last_iso_auth_sid, sid, sizeof(s_last_iso_auth_sid));
                s_iso_auth_pending_sent = false;
            }
            iso2_EVSEProcessingType proc = iso2_EVSEProcessingType_Finished;
            if (ok && !s_iso_auth_pending_sent) {
                proc = iso2_EVSEProcessingType_Ongoing;
                s_iso_auth_pending_sent = true;
            }
            return jpv2g_cbv2g_encode_authorization_res(sid,
                                                        ok ? iso2_responseCodeType_OK : iso2_responseCodeType_FAILED,
                                                        proc,
                                                        out,
                                                        out_len,
                                                        written);
        }
        case JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ: {
            if (req->protocol == JPV2G_PROTOCOL_DIN70121) {
                return jpv2g_cbv2g_encode_din_charge_parameter_discovery_res(sid, din_responseCodeType_OK, NULL, out, out_len, written);
            }
            iso2_EnergyTransferModeType requested_etm = secc_select_iso_etm(secc);
            if (req->body) {
                const struct iso2_ChargeParameterDiscoveryReqType *cpd =
                    (const struct iso2_ChargeParameterDiscoveryReqType *)req->body;
                requested_etm = cpd->RequestedEnergyTransferMode;
            }
            iso2_responseCodeType code = iso2_responseCodeType_OK;
            if (!secc_iso_etm_supported(requested_etm)) {
                code = iso2_responseCodeType_FAILED_WrongEnergyTransferMode;
            }
            return jpv2g_cbv2g_encode_charge_parameter_discovery_res(sid, code, requested_etm, out, out_len, written);
        }
        case JPV2G_CABLE_CHECK_REQ: {
            if (req->protocol == JPV2G_PROTOCOL_DIN70121) {
                return jpv2g_cbv2g_encode_din_cable_check_res(sid, din_responseCodeType_OK, din_EVSEProcessingType_Finished, NULL, out, out_len, written);
            }
            return jpv2g_cbv2g_encode_cable_check_res(sid, iso2_responseCodeType_OK, iso2_EVSEProcessingType_Finished, NULL, out, out_len, written);
        }
        case JPV2G_PRE_CHARGE_REQ: {
            if (req->protocol == JPV2G_PROTOCOL_DIN70121) {
                struct din_PreChargeResType res;
                init_din_PreChargeResType(&res);
                secc_set_dc_evse_status_din(&res.DC_EVSEStatus);
                if (req->body) {
                    const struct din_PreChargeReqType *rq = (const struct din_PreChargeReqType *)req->body;
                    struct din_PreChargeReqType rq_eff = *rq;
                    if (secc_din_cap_precharge_current(&rq_eff)) {
                        JPV2G_INFO("PreCharge current limited to 2.0A (DIN)");
                    }
                    res.EVSEPresentVoltage = rq_eff.EVTargetVoltage;
                } else {
                    secc_set_din_physical(&res.EVSEPresentVoltage, din_unitSymbolType_V, 400, 0);
                }
                return jpv2g_cbv2g_encode_din_pre_charge_res(sid, din_responseCodeType_OK, &res, out, out_len, written);
            }
            struct iso2_PreChargeResType res;
            init_iso2_PreChargeResType(&res);
            secc_set_dc_evse_status_iso(&res.DC_EVSEStatus);
            if (req->body) {
                const struct iso2_PreChargeReqType *rq = (const struct iso2_PreChargeReqType *)req->body;
                struct iso2_PreChargeReqType rq_eff = *rq;
                if (secc_iso_cap_precharge_current(&rq_eff)) {
                    JPV2G_INFO("PreCharge current limited to 2.0A (ISO)");
                }
                res.EVSEPresentVoltage = rq_eff.EVTargetVoltage;
            } else {
                res.EVSEPresentVoltage.Unit = iso2_unitSymbolType_V;
                res.EVSEPresentVoltage.Value = 400;
                res.EVSEPresentVoltage.Multiplier = 0;
            }
            return jpv2g_cbv2g_encode_pre_charge_res(sid, iso2_responseCodeType_OK, &res, out, out_len, written);
        }
        case JPV2G_POWER_DELIVERY_REQ: {
            if (req->protocol == JPV2G_PROTOCOL_DIN70121) {
                return jpv2g_cbv2g_encode_din_power_delivery_res(sid, din_responseCodeType_OK, NULL, out, out_len, written);
            }
            return jpv2g_cbv2g_encode_power_delivery_res(sid, iso2_responseCodeType_OK, NULL, out, out_len, written);
        }
        case JPV2G_CHARGING_STATUS_REQ: {
            return jpv2g_cbv2g_encode_charging_status_res(sid, iso2_responseCodeType_OK, "EVSE_ID_1", 1, NULL, out, out_len, written);
        }
        case JPV2G_CURRENT_DEMAND_REQ: {
            if (req->protocol == JPV2G_PROTOCOL_DIN70121) {
                struct din_CurrentDemandResType res;
                init_din_CurrentDemandResType(&res);
                secc_set_dc_evse_status_din(&res.DC_EVSEStatus);
                if (req->body) {
                    const struct din_CurrentDemandReqType *rq = (const struct din_CurrentDemandReqType *)req->body;
                    res.EVSEPresentVoltage = rq->EVTargetVoltage;
                    res.EVSEPresentCurrent = rq->EVTargetCurrent;
                } else {
                    secc_set_din_physical(&res.EVSEPresentVoltage, din_unitSymbolType_V, 400, 0);
                    secc_set_din_physical(&res.EVSEPresentCurrent, din_unitSymbolType_A, 16, 0);
                }
                res.EVSECurrentLimitAchieved = 0;
                res.EVSEVoltageLimitAchieved = 0;
                res.EVSEPowerLimitAchieved = 0;
                secc_bump_meter(secc, 100);
                return jpv2g_cbv2g_encode_din_current_demand_res(sid, din_responseCodeType_OK, &res, out, out_len, written);
            }
            struct iso2_CurrentDemandResType res;
            init_iso2_CurrentDemandResType(&res);
            secc_set_dc_evse_status_iso(&res.DC_EVSEStatus);
            if (req->body) {
                const struct iso2_CurrentDemandReqType *rq = (const struct iso2_CurrentDemandReqType *)req->body;
                res.EVSEPresentVoltage = rq->EVTargetVoltage;
                res.EVSEPresentCurrent = rq->EVTargetCurrent;
            } else {
                res.EVSEPresentVoltage.Unit = iso2_unitSymbolType_V;
                res.EVSEPresentVoltage.Value = 400;
                res.EVSEPresentCurrent.Unit = iso2_unitSymbolType_A;
                res.EVSEPresentCurrent.Value = 16;
                res.EVSEPresentVoltage.Multiplier = 0;
                res.EVSEPresentCurrent.Multiplier = 0;
            }
            res.EVSECurrentLimitAchieved = 0;
            res.EVSEVoltageLimitAchieved = 0;
            res.EVSEPowerLimitAchieved = 0;
            secc_bump_meter(secc, 100);
            secc_fill_iso_meter_info(secc, &res.MeterInfo);
            res.MeterInfo_isUsed = 1;
            res.EVSEID.charactersLen = 0;
            return jpv2g_cbv2g_encode_current_demand_res(sid, iso2_responseCodeType_OK, &res, out, out_len, written);
        }
        case JPV2G_METERING_RECEIPT_REQ: {
            if (req->protocol == JPV2G_PROTOCOL_DIN70121) {
                struct din_MeteringReceiptResType res;
                init_din_MeteringReceiptResType(&res);
                return jpv2g_cbv2g_encode_din_metering_receipt_res(sid, din_responseCodeType_OK, &res, out, out_len, written);
            }
            struct iso2_MeteringReceiptResType res;
            init_iso2_MeteringReceiptResType(&res);
            res.ResponseCode = iso2_responseCodeType_OK;
            res.AC_EVSEStatus_isUsed = 0;
            return jpv2g_cbv2g_encode_metering_receipt_res(sid, iso2_responseCodeType_OK, &res, out, out_len, written);
        }
        case JPV2G_WELDING_DETECTION_REQ: {
            if (req->protocol == JPV2G_PROTOCOL_DIN70121) {
                return jpv2g_cbv2g_encode_din_welding_detection_res(sid, din_responseCodeType_OK, NULL, out, out_len, written);
            }
            return jpv2g_cbv2g_encode_welding_detection_res(sid, iso2_responseCodeType_OK, NULL, out, out_len, written);
        }
        case JPV2G_SESSION_STOP_REQ: {
            int rc = 0;
            if (req->protocol == JPV2G_PROTOCOL_DIN70121) {
                rc = jpv2g_cbv2g_encode_din_session_stop_res(sid, din_responseCodeType_OK, out, out_len, written);
            } else {
                rc = jpv2g_cbv2g_encode_session_stop_res(sid, iso2_responseCodeType_OK, out, out_len, written);
            }
            memset(secc->session_id, 0, sizeof(secc->session_id));
            return rc;
        }
        default:
            return -ENOTSUP;
    }
}

typedef ssize_t (*secc_recv_fn)(void *ctx, uint8_t *buf, size_t len, int timeout_ms);
typedef ssize_t (*secc_send_fn)(void *ctx, const uint8_t *buf, size_t len);

static ssize_t secc_recv_tcp(void *ctx, uint8_t *buf, size_t len, int timeout_ms) {
    int fd = ctx ? *(int *)ctx : -1;
    return jpv2g_tcp_recv(fd, buf, len, timeout_ms);
}

static ssize_t secc_send_tcp(void *ctx, const uint8_t *buf, size_t len) {
    int fd = ctx ? *(int *)ctx : -1;
    return jpv2g_tcp_send(fd, buf, len);
}

static ssize_t secc_recv_tls(void *ctx, uint8_t *buf, size_t len, int timeout_ms) {
    jpv2g_tls_socket_t *sock = (jpv2g_tls_socket_t *)ctx;
    return jpv2g_tls_recv(sock, buf, len, timeout_ms);
}

static ssize_t secc_send_tls(void *ctx, const uint8_t *buf, size_t len) {
    jpv2g_tls_socket_t *sock = (jpv2g_tls_socket_t *)ctx;
    return jpv2g_tls_send(sock, buf, len);
}

static int secc_recv_bytes(secc_recv_fn fn, void *ctx, uint8_t *buf, size_t len, int timeout_ms) {
    if (!fn || !buf) return -EINVAL;
    size_t off = 0;
    int64_t deadline = timeout_ms > 0 ? jpv2g_now_monotonic_ms() + timeout_ms : 0;
    while (off < len) {
        int slice = timeout_ms;
        if (timeout_ms > 0) {
            int64_t remaining = deadline - jpv2g_now_monotonic_ms();
            if (remaining <= 0) return -ETIMEDOUT;
            if (remaining > INT32_MAX) remaining = INT32_MAX;
            slice = (int)remaining;
        }
        ssize_t r = fn(ctx, buf + off, len - off, slice);
        if (r == 0) return -ECONNRESET;
        if (r < 0) {
            if (r == -EAGAIN) {
                /* try again until deadline */
                continue;
            }
            return (int)r;
        }
        off += (size_t)r;
    }
    return 0;
}

static int secc_recv_v2gtp(secc_recv_fn fn, void *ctx, uint8_t *buf, size_t buf_len, jpv2g_v2gtp_t *out, int timeout_ms) {
    if (buf_len < JPV2G_V2GTP_HEADER_LEN) return -ENOSPC;
    int rc = secc_recv_bytes(fn, ctx, buf, JPV2G_V2GTP_HEADER_LEN, timeout_ms);
    if (rc != 0) return rc;
    uint32_t payload_len = jpv2g_read_u32_be(&buf[4]);
    if (payload_len > JPV2G_MAX_PAYLOAD_LENGTH) return -E2BIG;
    size_t total = JPV2G_V2GTP_HEADER_LEN + payload_len;
    if (total > buf_len) return -ENOSPC;
    rc = secc_recv_bytes(fn, ctx, buf + JPV2G_V2GTP_HEADER_LEN, payload_len, timeout_ms);
    if (rc != 0) return rc;
    return jpv2g_v2gtp_parse(buf, total, out);
}

int jpv2g_secc_init(jpv2g_secc_t *secc, const jpv2g_secc_config_t *cfg, jpv2g_codec_ctx *codec) {
    if (!secc || !cfg || !codec) return -EINVAL;
    memset(secc, 0, sizeof(*secc));
    secc->cfg = *cfg;
    secc->codec = codec;
    secc->udp.fd = -1;
    secc->tcp.fd = -1;
    secc->tls.fd = -1;
    secc->handle_request = NULL;
    secc->user_ctx = NULL;
    jpv2g_backend_set_defaults(&secc->backend);
    jpv2g_evse_controller_set_defaults(&secc->evse_ctl);
    memset(secc->session_id, 0, sizeof(secc->session_id));
    secc->meter_Wh = 0;
    strcpy(secc->meter_id, "METER01");
    return 0;
}

int jpv2g_secc_start_udp(jpv2g_secc_t *secc) {
    if (!secc) return -EINVAL;
    return jpv2g_udp_server_start(&secc->udp, secc->cfg.network_interface, JPV2G_UDP_SDP_SERVER_PORT);
}

int jpv2g_secc_start_tcp(jpv2g_secc_t *secc) {
    if (!secc) return -EINVAL;
    return jpv2g_tcp_server_start(&secc->tcp, secc->cfg.network_interface, (uint16_t)secc->cfg.tcp_port, true);
}

int jpv2g_secc_start_tls(jpv2g_secc_t *secc) {
    if (!secc) return -EINVAL;
    return jpv2g_tcp_server_start(&secc->tls, secc->cfg.network_interface, (uint16_t)secc->cfg.tls_port, true);
}

void jpv2g_secc_stop(jpv2g_secc_t *secc) {
    if (!secc) return;
    jpv2g_udp_server_stop(&secc->udp);
    jpv2g_tcp_server_stop(&secc->tcp);
    jpv2g_tcp_server_stop(&secc->tls);
}

static int jpv2g_secc_handle_stream(jpv2g_secc_t *secc,
                                      secc_recv_fn recv_fn,
                                      void *recv_ctx,
                                      secc_send_fn send_fn,
                                      void *send_ctx,
                                      int timeout_ms) {
    if (!secc || !recv_fn || !send_fn) return -EINVAL;
    uint8_t buf[JPV2G_MAX_V2GTP_SIZE];
    jpv2g_protocol_t protocol = JPV2G_PROTOCOL_UNKNOWN;
    bool handled_any = false;
    for (;;) {
        jpv2g_v2gtp_t msg;
        int rc = secc_recv_v2gtp(recv_fn, recv_ctx, buf, sizeof(buf), &msg, timeout_ms);
        if (rc == -ETIMEDOUT) {
            if (!handled_any) {
                JPV2G_WARN("Timeout waiting for V2GTP frame");
                return rc;
            }
            return 0;
        }
        if (rc == -EAGAIN) return 0; /* graceful idle exit */
        if (rc != 0) return rc;
        if (msg.payload_type != JPV2G_PAYLOAD_EXI) return -EBADMSG;
        jpv2g_message_type_t mtype = JPV2G_UNKNOWN_MESSAGE;
        uint8_t out_payload[JPV2G_MAX_EXI_SIZE];
        size_t out_len = 0;
        int handler_rc = 0;
        jpv2g_secc_request_t req_ctx = {.protocol = protocol, .header = NULL, .din_header = NULL, .body = NULL};
        jpv2g_secc_request_t req_log_ctx = req_ctx;
        secc_log_req_copy_t req_log_copy;
        bool decoded_ok = false;

        /* Try to decode as AppProtocol */
        struct appHand_supportedAppProtocolReq app_req;
        struct appHand_exiDocument app_doc;
        init_appHand_exiDocument(&app_doc);
        exi_bitstream_t app_stream;
        exi_bitstream_init(&app_stream, (uint8_t *)msg.payload, msg.payload_length, 0, NULL);
        if (decode_appHand_exiDocument(&app_stream, &app_doc) == 0 && app_doc.supportedAppProtocolReq_isUsed) {
            mtype = JPV2G_SUPP_APP_PROTOCOL_REQ;
            app_req = app_doc.supportedAppProtocolReq;
            jpv2g_protocol_t detected = detect_protocol_from_app(&app_req);
            if (detected != JPV2G_PROTOCOL_UNKNOWN) protocol = detected;
            req_ctx.protocol = protocol;
            req_ctx.body = &app_req;
            req_log_ctx = req_ctx;
            if (secc->handle_request) {
                handler_rc = secc->handle_request(mtype, &req_ctx, out_payload, sizeof(out_payload), &out_len, secc->user_ctx);
            } else {
                handler_rc = jpv2g_secc_default_handle(secc, mtype, &req_ctx, out_payload, sizeof(out_payload), &out_len);
            }
            decoded_ok = true;
        }

        /* Try ISO 15118 message if allowed or unknown */
        if (!decoded_ok && protocol != JPV2G_PROTOCOL_DIN70121) {
            struct iso2_exiDocument iso_doc;
            init_iso2_exiDocument(&iso_doc);
            exi_bitstream_t iso_stream;
            exi_bitstream_init(&iso_stream, (uint8_t *)msg.payload, msg.payload_length, 0, NULL);
            if (decode_iso2_exiDocument(&iso_stream, &iso_doc) == 0) {
                const struct iso2_BodyType *b = &iso_doc.V2G_Message.Body;
                const void *decoded = NULL;
                if (b->SessionSetupReq_isUsed) {
                    mtype = JPV2G_SESSION_SETUP_REQ;
                    decoded = &b->SessionSetupReq;
                } else if (b->ServiceDiscoveryReq_isUsed) {
                    mtype = JPV2G_SERVICE_DISCOVERY_REQ;
                    decoded = &b->ServiceDiscoveryReq;
                } else if (b->ServiceDetailReq_isUsed) {
                    mtype = JPV2G_SERVICE_DETAIL_REQ;
                    decoded = &b->ServiceDetailReq;
                } else if (b->PaymentServiceSelectionReq_isUsed) {
                    mtype = JPV2G_PAYMENT_SERVICE_SELECTION_REQ;
                    decoded = &b->PaymentServiceSelectionReq;
                } else if (b->PaymentDetailsReq_isUsed) {
                    mtype = JPV2G_PAYMENT_DETAILS_REQ;
                    decoded = &b->PaymentDetailsReq;
                } else if (b->AuthorizationReq_isUsed) {
                    mtype = JPV2G_AUTHORIZATION_REQ;
                    decoded = &b->AuthorizationReq;
                } else if (b->ChargeParameterDiscoveryReq_isUsed) {
                    mtype = JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ;
                    decoded = &b->ChargeParameterDiscoveryReq;
                } else if (b->CableCheckReq_isUsed) {
                    mtype = JPV2G_CABLE_CHECK_REQ;
                    decoded = &b->CableCheckReq;
                } else if (b->PowerDeliveryReq_isUsed) {
                    mtype = JPV2G_POWER_DELIVERY_REQ;
                    decoded = &b->PowerDeliveryReq;
                } else if (b->ChargingStatusReq_isUsed) {
                    mtype = JPV2G_CHARGING_STATUS_REQ;
                    decoded = &b->ChargingStatusReq;
                } else if (b->CurrentDemandReq_isUsed) {
                    mtype = JPV2G_CURRENT_DEMAND_REQ;
                    decoded = &b->CurrentDemandReq;
                } else if (b->MeteringReceiptReq_isUsed) {
                    mtype = JPV2G_METERING_RECEIPT_REQ;
                    decoded = &b->MeteringReceiptReq;
                } else if (b->PreChargeReq_isUsed) {
                    mtype = JPV2G_PRE_CHARGE_REQ;
                    decoded = &b->PreChargeReq;
                } else if (b->WeldingDetectionReq_isUsed) {
                    mtype = JPV2G_WELDING_DETECTION_REQ;
                    decoded = &b->WeldingDetectionReq;
                } else if (b->SessionStopReq_isUsed) {
                    mtype = JPV2G_SESSION_STOP_REQ;
                    decoded = &b->SessionStopReq;
                }

                if (mtype != JPV2G_UNKNOWN_MESSAGE) {
                    if (protocol == JPV2G_PROTOCOL_UNKNOWN) {
                        protocol = JPV2G_PROTOCOL_ISO15118_2;
                    } else if (protocol != JPV2G_PROTOCOL_ISO15118_2) {
                        JPV2G_WARN("Protocol hint was %d but ISO 15118 payload received, switching to ISO", protocol);
                        protocol = JPV2G_PROTOCOL_ISO15118_2;
                    }
                    req_ctx.protocol = protocol;
                    req_ctx.header = &iso_doc.V2G_Message.Header;
                    req_ctx.din_header = NULL;
                    req_ctx.body = decoded;
                    req_log_ctx = req_ctx;
                    req_log_ctx.body = secc_copy_req_body_for_log(req_ctx.protocol, mtype, req_ctx.body, &req_log_copy);
                    if (secc->handle_request) {
                        handler_rc = secc->handle_request(mtype, &req_ctx, out_payload, sizeof(out_payload), &out_len, secc->user_ctx);
                    } else {
                        handler_rc = jpv2g_secc_default_handle(secc, mtype, &req_ctx, out_payload, sizeof(out_payload), &out_len);
                    }
                    decoded_ok = true;
                }
            }
        }

        /* Try DIN 70121 message if not already decoded */
        if (!decoded_ok) {
            struct din_exiDocument din_doc;
            init_din_exiDocument(&din_doc);
            exi_bitstream_t din_stream;
            exi_bitstream_init(&din_stream, (uint8_t *)msg.payload, msg.payload_length, 0, NULL);
            if (decode_din_exiDocument(&din_stream, &din_doc) == 0) {
                const struct din_BodyType *b = &din_doc.V2G_Message.Body;
                const void *decoded = NULL;
                if (b->SessionSetupReq_isUsed) {
                    mtype = JPV2G_SESSION_SETUP_REQ;
                    decoded = &b->SessionSetupReq;
                } else if (b->ServiceDiscoveryReq_isUsed) {
                    mtype = JPV2G_SERVICE_DISCOVERY_REQ;
                    decoded = &b->ServiceDiscoveryReq;
                } else if (b->ServiceDetailReq_isUsed) {
                    mtype = JPV2G_SERVICE_DETAIL_REQ;
                    decoded = &b->ServiceDetailReq;
                } else if (b->ServicePaymentSelectionReq_isUsed) {
                    mtype = JPV2G_PAYMENT_SERVICE_SELECTION_REQ;
                    decoded = &b->ServicePaymentSelectionReq;
                } else if (b->PaymentDetailsReq_isUsed) {
                    mtype = JPV2G_PAYMENT_DETAILS_REQ;
                    decoded = &b->PaymentDetailsReq;
                } else if (b->ContractAuthenticationReq_isUsed) {
                    mtype = JPV2G_AUTHORIZATION_REQ;
                    decoded = &b->ContractAuthenticationReq;
                } else if (b->ChargeParameterDiscoveryReq_isUsed) {
                    mtype = JPV2G_CHARGE_PARAMETER_DISCOVERY_REQ;
                    decoded = &b->ChargeParameterDiscoveryReq;
                } else if (b->CableCheckReq_isUsed) {
                    mtype = JPV2G_CABLE_CHECK_REQ;
                    decoded = &b->CableCheckReq;
                } else if (b->PowerDeliveryReq_isUsed) {
                    mtype = JPV2G_POWER_DELIVERY_REQ;
                    decoded = &b->PowerDeliveryReq;
                } else if (b->ChargingStatusReq_isUsed) {
                    mtype = JPV2G_CHARGING_STATUS_REQ;
                    decoded = &b->ChargingStatusReq;
                } else if (b->CurrentDemandReq_isUsed) {
                    mtype = JPV2G_CURRENT_DEMAND_REQ;
                    decoded = &b->CurrentDemandReq;
                } else if (b->MeteringReceiptReq_isUsed) {
                    mtype = JPV2G_METERING_RECEIPT_REQ;
                    decoded = &b->MeteringReceiptReq;
                } else if (b->PreChargeReq_isUsed) {
                    mtype = JPV2G_PRE_CHARGE_REQ;
                    decoded = &b->PreChargeReq;
                } else if (b->WeldingDetectionReq_isUsed) {
                    mtype = JPV2G_WELDING_DETECTION_REQ;
                    decoded = &b->WeldingDetectionReq;
                } else if (b->SessionStopReq_isUsed) {
                    mtype = JPV2G_SESSION_STOP_REQ;
                    decoded = &b->SessionStopReq;
                }

                if (mtype != JPV2G_UNKNOWN_MESSAGE) {
                    if (protocol == JPV2G_PROTOCOL_UNKNOWN) {
                        protocol = JPV2G_PROTOCOL_DIN70121;
                    } else if (protocol != JPV2G_PROTOCOL_DIN70121) {
                        JPV2G_WARN("Protocol hint was %d but DIN 70121 payload received, switching to DIN", protocol);
                        protocol = JPV2G_PROTOCOL_DIN70121;
                    }
                    req_ctx.protocol = protocol;
                    req_ctx.header = NULL;
                    req_ctx.din_header = &din_doc.V2G_Message.Header;
                    req_ctx.body = decoded;
                    req_log_ctx = req_ctx;
                    req_log_ctx.body = secc_copy_req_body_for_log(req_ctx.protocol, mtype, req_ctx.body, &req_log_copy);
                    if (secc->handle_request) {
                        handler_rc = secc->handle_request(mtype, &req_ctx, out_payload, sizeof(out_payload), &out_len, secc->user_ctx);
                    } else {
                        handler_rc = jpv2g_secc_default_handle(secc, mtype, &req_ctx, out_payload, sizeof(out_payload), &out_len);
                    }
                    decoded_ok = true;
                }
            }
        }

        if (mtype == JPV2G_UNKNOWN_MESSAGE) {
            /* Fallback: echo */
            if (msg.payload_length > sizeof(out_payload)) return -ENOSPC;
            memcpy(out_payload, msg.payload, msg.payload_length);
            out_len = msg.payload_length;
        }

        if (!decoded_ok) {
            JPV2G_WARN("Failed to decode EXI message (payload_len=%u)", (unsigned)msg.payload_length);
            return -EBADMSG;
        }
        JPV2G_INFO("RX %s (proto=%d)", secc_msg_name(mtype), (int)req_ctx.protocol);
        secc_log_exi_hex("RX", mtype, msg.payload, msg.payload_length);
        if (handler_rc != 0) {
            JPV2G_WARN("Handler failed for %s rc=%d", secc_msg_name(mtype), handler_rc);
            return handler_rc;
        }
        if (out_len == 0) return -EIO;
        secc_log_decoded_transaction(mtype, &req_log_ctx, out_payload, out_len);
        secc_log_exi_hex("TX", mtype, out_payload, out_len);
        uint8_t out[JPV2G_V2GTP_HEADER_LEN + JPV2G_MAX_EXI_SIZE];
        size_t total = 0;
        rc = jpv2g_v2gtp_build(JPV2G_PAYLOAD_EXI, out_payload, out_len, out, sizeof(out), &total);
        if (rc != 0) return rc;
        ssize_t sent = send_fn(send_ctx, out, total);
        if (sent < 0 || (size_t)sent != total) return -EIO;
        JPV2G_INFO("TX %s bytes=%u", secc_msg_name(mtype), (unsigned)total);
        handled_any = true;
    }
}

int jpv2g_secc_handle_client(jpv2g_secc_t *secc, int client_fd, int timeout_ms) {
    if (!secc || client_fd < 0) return -EINVAL;
    return jpv2g_secc_handle_stream(secc, secc_recv_tcp, &client_fd, secc_send_tcp, &client_fd, timeout_ms);
}

int jpv2g_secc_handle_client_tls(jpv2g_secc_t *secc,
                                   int client_fd,
                                   const char *cert_path,
                                   const char *key_path,
                                   const char *ca_path,
                                   int timeout_ms) {
    if (!secc || client_fd < 0) return -EINVAL;
    jpv2g_tls_socket_t sock;
    memset(&sock, 0, sizeof(sock));
    const char *cert = cert_path ? cert_path : secc->cfg.tls_cert_path;
    const char *key = key_path ? key_path : secc->cfg.tls_key_path;
    const char *ca = ca_path ? ca_path : secc->cfg.tls_ca_path;
    int rc = jpv2g_tls_server_wrap(&sock, client_fd, cert, key, ca);
    if (rc != 0) {
        jpv2g_socket_close(client_fd);
        return rc;
    }
    rc = jpv2g_secc_handle_stream(secc, secc_recv_tls, &sock, secc_send_tls, &sock, timeout_ms);
    jpv2g_tls_close(&sock);
    return rc;
}

int jpv2g_secc_handle_client_detect(jpv2g_secc_t *secc,
                                      int client_fd,
                                      int first_timeout_ms,
                                      int timeout_ms) {
    if (!secc || client_fd < 0) return -EINVAL;
    int wait_ms = first_timeout_ms > 0 ? first_timeout_ms : JPV2G_TIMEOUT_FIRST_HLC;
    uint8_t peek[JPV2G_V2GTP_HEADER_LEN] = {0};
    int r = peek_first_bytes(client_fd, peek, sizeof(peek), wait_ms);
    if (r < 0) {
        if (r == -ETIMEDOUT) {
            JPV2G_WARN("No HLC bytes received within %d ms", wait_ms);
        } else {
            JPV2G_WARN("Failed to peek incoming HLC bytes (%d)", r);
        }
        return r;
    }
    bool tls = looks_like_tls_client_hello(peek, (size_t)r);
    bool v2g = looks_like_v2gtp_header(peek, (size_t)r);
    if (tls) {
        JPV2G_INFO("Detected TLS ClientHello; switching to TLS handler");
        return jpv2g_secc_handle_client_tls(secc, client_fd, NULL, NULL, NULL, timeout_ms);
    }
    if (!v2g) {
        JPV2G_WARN("Unknown HLC prefix (0x%02X 0x%02X ... len=%d); treating as plaintext V2GTP",
                   peek[0], (r > 1) ? peek[1] : 0, r);
    }
    return jpv2g_secc_handle_client(secc, client_fd, timeout_ms);
}

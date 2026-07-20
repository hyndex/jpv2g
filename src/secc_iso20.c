/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2026 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

/*
 * ISO 15118-20 DC SECC session engine (DC + EIM + Scheduled only).
 *
 * See include/jpv2g/secc_iso20.h for the module contract. Implementation
 * notes that matter to a future maintainer:
 *
 *  - One decode/encode workspace per schema. The request is decoded into the
 *    caller-provided workspace, every field the handler needs is extracted
 *    into small locals, and the response is then built IN THE SAME union —
 *    the generated init_* functions do NOT zero struct contents (they only
 *    clear document-level _isUsed flags), so every response member is
 *    explicitly memset before filling. Extract-before-memset is the rule.
 *
 *  - The two response-code enums (iso20_responseCodeType_* for CommonMessages
 *    and iso20_dc_responseCodeType_* for DC) are value-identical but
 *    type-distinct. Codes travel through this file as plain int and are cast
 *    at the single assignment into each response struct; enumerators from one
 *    schema are never assigned to the other schema's field.
 *
 *  - Sequence errors and unknown-session errors answer with the REQUEST'S own
 *    response type carrying only mandatory fields, our SessionID, and the
 *    request's payload id, then terminate. The one soft spot is
 *    CertificateInstallationReq (a PnC probe on an EIM-only EVSE): its Res has
 *    deep mandatory crypto structures that a zeroed skeleton may fail to
 *    encode; if the encoder rejects it we report -EBADMSG so the stream
 *    dispatcher applies the same bounded undecodable-frame tolerance it uses
 *    for -2/DIN probes (gap audit #9) instead of crashing or silently
 *    dropping and stalling.
 */

#include "jpv2g/secc_iso20.h"

#include <errno.h>
#include <string.h>

/* ----------------------------------------------------------------------------
 * Dependency-free pieces shared by both build flavours (mirrors tls.c, whose
 * close path is also real in the stub branch).
 * ------------------------------------------------------------------------- */

/* Single active -20 session per process: the firmware runs one SECC per MCU
 * (one g_secc), and the host tools/tests handle one client at a time. */
static jpv2g_secc20_t *s_stream_session = NULL;

void jpv2g_secc20_set_stream_session(jpv2g_secc20_t *s) {
    s_stream_session = s;
}

jpv2g_secc20_t *jpv2g_secc20_stream_session(void) {
    return s_stream_session;
}

const char *jpv2g_secc20_state_name(jpv2g_secc20_state_t state) {
    switch (state) {
        case JPV2G_SECC20_STATE_SESSION_SETUP: return "SessionSetup";
        case JPV2G_SECC20_STATE_AUTH_SETUP: return "AuthorizationSetup";
        case JPV2G_SECC20_STATE_AUTHORIZATION: return "Authorization";
        case JPV2G_SECC20_STATE_SERVICE_DISCOVERY: return "ServiceDiscovery";
        case JPV2G_SECC20_STATE_SERVICE_DETAIL: return "ServiceDetail";
        case JPV2G_SECC20_STATE_DC_CPD: return "DC_ChargeParameterDiscovery";
        case JPV2G_SECC20_STATE_SCHEDULE_EXCHANGE: return "ScheduleExchange";
        case JPV2G_SECC20_STATE_CABLE_CHECK: return "DC_CableCheck";
        case JPV2G_SECC20_STATE_PRE_CHARGE: return "DC_PreCharge";
        case JPV2G_SECC20_STATE_POWER_DELIVERY: return "PowerDelivery";
        case JPV2G_SECC20_STATE_CHARGE_LOOP: return "DC_ChargeLoop";
        case JPV2G_SECC20_STATE_WELDING: return "DC_WeldingDetection";
        case JPV2G_SECC20_STATE_SESSION_STOP: return "SessionStop";
        case JPV2G_SECC20_STATE_ENDED: return "Ended";
        default: return "Unknown";
    }
}

/* libm-free absolute value / rounding so the helpers cost nothing on the
 * Xtensa build and add no link dependency to host tests. */
static double s20_fabs(double v) { return v < 0.0 ? -v : v; }

static long s20_lround(double v) {
    return (long)(v >= 0.0 ? v + 0.5 : v - 0.5);
}

void jpv2g_secc20_rat_from_float(float value, int8_t *exponent, int16_t *mantissa) {
    if (!exponent || !mantissa) return;
    *exponent = 0;
    *mantissa = 0;
    double v = (double)value;
    if (!(v == v)) return; /* NaN */
    if (v == 0.0) return;
    int e = 0;
    double mag = s20_fabs(v);
    /* Scale down until the mantissa fits the int16 wire type. */
    while (mag > 32767.0 && e < 127) {
        v /= 10.0;
        mag /= 10.0;
        ++e;
    }
    /* Scale up only while it buys exactness, so integral inputs keep the
     * smallest |Exponent| (500 -> {500,0}) while fractional inputs gain the
     * precision the schema allows (1000.5 -> {10005,-1}). -3 is plenty for
     * every V2G electrical quantity (milli-resolution). */
    while (e > -3) {
        if (s20_fabs(v - (double)s20_lround(v)) <= 1e-6 * (mag + 1.0)) break;
        if (mag * 10.0 > 32767.0) break;
        v *= 10.0;
        mag *= 10.0;
        --e;
    }
    long m = s20_lround(v);
    if (m > 32767) m = 32767;
    if (m < -32767) m = -32767;
    *mantissa = (int16_t)m;
    *exponent = (int8_t)e;
}

float jpv2g_secc20_rat_to_float(int8_t exponent, int16_t mantissa) {
    double v = (double)mantissa;
    if (exponent >= 0) {
        for (int8_t i = 0; i < exponent; ++i) v *= 10.0;
    } else {
        for (int8_t i = 0; i > exponent; --i) v /= 10.0;
    }
    return (float)v;
}

#ifdef JPV2G_ENABLE_ISO20

#include "cbv2g/common/exi_bitstream.h"
#include "cbv2g/iso_20/iso20_CommonMessages_Datatypes.h"
#include "cbv2g/iso_20/iso20_CommonMessages_Decoder.h"
#include "cbv2g/iso_20/iso20_CommonMessages_Encoder.h"
#include "cbv2g/iso_20/iso20_DC_Datatypes.h"
#include "cbv2g/iso_20/iso20_DC_Decoder.h"
#include "cbv2g/iso_20/iso20_DC_Encoder.h"

#include "jpv2g/log.h"
#include "jpv2g/session.h"
#include "jpv2g/time_compat.h"

/* Response-code threshold: >= FAILED terminates, WARNINGs never do. The two
 * enums are value-identical; assert the anchor values once at compile time so
 * a regenerated codec cannot silently shift the shared int value space. */
#define S20_RC_FAILED ((int)iso20_responseCodeType_FAILED)
typedef char s20_assert_rc_failed[(int)iso20_responseCodeType_FAILED ==
                                  (int)iso20_dc_responseCodeType_FAILED ? 1 : -1];
typedef char s20_assert_rc_seq[(int)iso20_responseCodeType_FAILED_SequenceError ==
                               (int)iso20_dc_responseCodeType_FAILED_SequenceError ? 1 : -1];
typedef char s20_assert_rc_unk[(int)iso20_responseCodeType_FAILED_UnknownSession ==
                               (int)iso20_dc_responseCodeType_FAILED_UnknownSession ? 1 : -1];

/* Fallback EVSEID when the config carries none: same identity string the -2
 * default handler advertises, so a misconfigured build stays schema-valid
 * and recognisable in logs rather than sending an empty identifier. */
static const char kSecc20DefaultEvseId[] = "IN*JPE*E000100010001";

/* Internal request classification (both schemas). */
typedef enum {
    S20_REQ_NONE = 0,
    /* CommonMessages (payload 0x8002) */
    S20_REQ_SESSION_SETUP,
    S20_REQ_AUTH_SETUP,
    S20_REQ_AUTHORIZATION,
    S20_REQ_SERVICE_DISCOVERY,
    S20_REQ_SERVICE_DETAIL,
    S20_REQ_SERVICE_SELECTION,
    S20_REQ_SCHEDULE_EXCHANGE,
    S20_REQ_POWER_DELIVERY,
    S20_REQ_METERING_CONFIRMATION,
    S20_REQ_SESSION_STOP,
    S20_REQ_CERT_INSTALL,
    S20_REQ_VEHICLE_CHECKIN,
    S20_REQ_VEHICLE_CHECKOUT,
    /* DC (payload 0x8004) */
    S20_REQ_DC_CPD,
    S20_REQ_DC_CABLE_CHECK,
    S20_REQ_DC_PRE_CHARGE,
    S20_REQ_DC_CHARGE_LOOP,
    S20_REQ_DC_WELDING
} s20_req_t;

/* ---------------------------------------------------------------- helpers */

static uint64_t s20_now_unix(const jpv2g_secc20_t *s) {
    if (s && s->cfg.now_unix_s) return s->cfg.now_unix_s(s->cfg.now_ctx);
    return 0u; /* schema-valid; PLC has no RTC until the controller feeds one */
}

static void s20_set_rat(struct iso20_RationalNumberType *r, float v) {
    jpv2g_secc20_rat_from_float(v, &r->Exponent, &r->Value);
}

static void s20_set_dc_rat(struct iso20_dc_RationalNumberType *r, float v) {
    jpv2g_secc20_rat_from_float(v, &r->Exponent, &r->Value);
}

static float s20_dc_rat_value(const struct iso20_dc_RationalNumberType *r) {
    return jpv2g_secc20_rat_to_float(r->Exponent, r->Value);
}

static void s20_fill_common_header(const jpv2g_secc20_t *s,
                                   struct iso20_MessageHeaderType *h) {
    memcpy(h->SessionID.bytes, s->session_id, JPV2G_SECC20_SESSION_ID_LEN);
    h->SessionID.bytesLen = JPV2G_SECC20_SESSION_ID_LEN;
    /* Mandatory both directions; init_* leaves it 0, so set it explicitly. */
    h->TimeStamp = s20_now_unix(s);
    h->Signature_isUsed = 0u;
}

static void s20_fill_dc_header(const jpv2g_secc20_t *s,
                               struct iso20_dc_MessageHeaderType *h) {
    memcpy(h->SessionID.bytes, s->session_id, JPV2G_SECC20_SESSION_ID_LEN);
    h->SessionID.bytesLen = JPV2G_SECC20_SESSION_ID_LEN;
    h->TimeStamp = s20_now_unix(s);
    h->Signature_isUsed = 0u;
}

static bool s20_session_id_matches(const jpv2g_secc20_t *s,
                                   const uint8_t *bytes, uint16_t len) {
    return len == JPV2G_SECC20_SESSION_ID_LEN &&
           memcmp(bytes, s->session_id, JPV2G_SECC20_SESSION_ID_LEN) == 0;
}

static int s20_encode_common(struct iso20_exiDocument *doc,
                             uint8_t *out, size_t out_cap, size_t *out_len) {
    exi_bitstream_t bs;
    exi_bitstream_init(&bs, out, out_cap, 0, NULL);
    int rc = encode_iso20_exiDocument(&bs, doc);
    if (rc != 0) {
        JPV2G_WARN("iso20 CommonMessages encode failed rc=%d", rc);
        return -EBADMSG;
    }
    *out_len = exi_bitstream_get_length(&bs);
    return 0;
}

static int s20_encode_dc(struct iso20_dc_exiDocument *doc,
                         uint8_t *out, size_t out_cap, size_t *out_len) {
    exi_bitstream_t bs;
    exi_bitstream_init(&bs, out, out_cap, 0, NULL);
    int rc = encode_iso20_dc_exiDocument(&bs, doc);
    if (rc != 0) {
        JPV2G_WARN("iso20 DC encode failed rc=%d", rc);
        return -EBADMSG;
    }
    *out_len = exi_bitstream_get_length(&bs);
    return 0;
}

/* Safe-default callback wrappers. The module never invents values: with no
 * controller wired in, limits and telemetry are zero, auth stays pending,
 * isolation stays ongoing, the contactor refuses to close. */

static jpv2g_secc20_auth_status_t s20_cb_auth(const jpv2g_secc20_t *s) {
    if (s->cfg.callbacks.auth_status) {
        return s->cfg.callbacks.auth_status(s->cfg.callbacks.user_ctx);
    }
    return JPV2G_SECC20_AUTH_PENDING;
}

static void s20_cb_limits(const jpv2g_secc20_t *s, jpv2g_secc20_dc_limits_t *out) {
    memset(out, 0, sizeof(*out));
    if (s->cfg.callbacks.get_dc_limits &&
        s->cfg.callbacks.get_dc_limits(s->cfg.callbacks.user_ctx, out) == 0) {
        return;
    }
    memset(out, 0, sizeof(*out));
}

static jpv2g_secc20_cable_check_status_t s20_cb_cable_check(const jpv2g_secc20_t *s) {
    if (s->cfg.callbacks.cable_check_status) {
        return s->cfg.callbacks.cable_check_status(s->cfg.callbacks.user_ctx);
    }
    return JPV2G_SECC20_CABLE_CHECK_ONGOING;
}

static void s20_cb_present(const jpv2g_secc20_t *s, jpv2g_secc20_present_t *out) {
    memset(out, 0, sizeof(*out));
    if (s->cfg.callbacks.get_present &&
        s->cfg.callbacks.get_present(s->cfg.callbacks.user_ctx, out) == 0) {
        return;
    }
    memset(out, 0, sizeof(*out));
}

static int s20_cb_contactor(const jpv2g_secc20_t *s, bool close_contactor) {
    if (s->cfg.callbacks.contactor_set) {
        return s->cfg.callbacks.contactor_set(s->cfg.callbacks.user_ctx, close_contactor);
    }
    /* Refusing an OPEN request when nothing is wired would be inventing a
     * fault; only the CLOSE direction must fail safe. */
    return close_contactor ? -ENOTSUP : 0;
}

static jpv2g_secc20_stop_request_t s20_cb_stop(const jpv2g_secc20_t *s) {
    if (s->cfg.callbacks.stop_request) {
        return s->cfg.callbacks.stop_request(s->cfg.callbacks.user_ctx);
    }
    return JPV2G_SECC20_STOP_NONE;
}

/* ------------------------------------------------ shared response pieces */

/* The DC energy-transfer service parameter set offered in ServiceDetailRes:
 * Connector=2 (CCS2), ControlMode=1 (Scheduled), MobilityNeedsMode=1
 * (ProvidedByEvcc — forced with Scheduled), Pricing=0. */
static void s20_fill_service_param_set(struct iso20_ServiceParameterListType *list) {
    static const struct { const char *name; int32_t value; } kParams[] = {
        {"Connector", JPV2G_SECC20_PARAM_CONNECTOR},
        {"ControlMode", JPV2G_SECC20_PARAM_CONTROL_MODE},
        {"MobilityNeedsMode", JPV2G_SECC20_PARAM_MOBILITY_NEEDS},
        {"Pricing", JPV2G_SECC20_PARAM_PRICING},
    };
    list->ParameterSet.arrayLen = 1;
    struct iso20_ParameterSetType *set = &list->ParameterSet.array[0];
    set->ParameterSetID = JPV2G_SECC20_DC_PARAMETER_SET_ID;
    set->Parameter.arrayLen = 4;
    for (size_t i = 0; i < 4; ++i) {
        struct iso20_ParameterType *p = &set->Parameter.array[i];
        size_t n = strlen(kParams[i].name);
        memcpy(p->Name.characters, kParams[i].name, n);
        p->Name.charactersLen = (uint16_t)n;
        p->intValue = kParams[i].value;
        p->intValue_isUsed = 1u;
    }
}

/* Scheduled_SEResControlMode: exactly one tuple (ID 1) with one 24 h entry at
 * the EVSE maximum power. Schema-mandatory even on FAILED/Ongoing answers
 * (SwitchEV Table-49 note), which is why the min-res builder reuses this. */
static void s20_fill_schedule_tuple(struct iso20_Scheduled_SEResControlModeType *mode,
                                    uint64_t time_anchor, float power_w) {
    mode->ScheduleTuple.arrayLen = 1;
    struct iso20_ScheduleTupleType *tuple = &mode->ScheduleTuple.array[0];
    tuple->ScheduleTupleID = JPV2G_SECC20_SCHEDULE_TUPLE_ID;
    tuple->DischargingSchedule_isUsed = 0u;
    struct iso20_PowerScheduleType *ps = &tuple->ChargingSchedule.PowerSchedule;
    tuple->ChargingSchedule.AbsolutePriceSchedule_isUsed = 0u;
    tuple->ChargingSchedule.PriceLevelSchedule_isUsed = 0u;
    ps->TimeAnchor = time_anchor;
    ps->AvailableEnergy_isUsed = 0u;
    ps->PowerTolerance_isUsed = 0u;
    ps->PowerScheduleEntries.PowerScheduleEntry.arrayLen = 1;
    struct iso20_PowerScheduleEntryType *entry =
        &ps->PowerScheduleEntries.PowerScheduleEntry.array[0];
    entry->Duration = JPV2G_SECC20_SCHEDULE_DURATION_S;
    s20_set_rat(&entry->Power, power_w);
    entry->Power_L2_isUsed = 0u;
    entry->Power_L3_isUsed = 0u;
}

static void s20_fill_dc_limits_res(struct iso20_dc_DC_CPDResEnergyTransferModeType *res,
                                   const jpv2g_secc20_dc_limits_t *lim) {
    s20_set_dc_rat(&res->EVSEMaximumChargePower, lim->max_charge_power_w);
    s20_set_dc_rat(&res->EVSEMinimumChargePower, lim->min_charge_power_w);
    s20_set_dc_rat(&res->EVSEMaximumChargeCurrent, lim->max_charge_current_a);
    s20_set_dc_rat(&res->EVSEMinimumChargeCurrent, lim->min_charge_current_a);
    s20_set_dc_rat(&res->EVSEMaximumVoltage, lim->max_voltage_v);
    s20_set_dc_rat(&res->EVSEMinimumVoltage, lim->min_voltage_v);
    res->EVSEPowerRampLimitation_isUsed = 0u;
}

static void s20_fill_evse_id(jpv2g_secc20_t *s, char *characters, uint16_t *characters_len) {
    const char *id = s->cfg.evse_id[0] != '\0' ? s->cfg.evse_id : kSecc20DefaultEvseId;
    size_t n = strlen(id);
    if (n >= JPV2G_SECC20_EVSEID_MAX) n = JPV2G_SECC20_EVSEID_MAX - 1;
    memcpy(characters, id, n);
    *characters_len = (uint16_t)n;
}

/* --------------------------------------- minimal per-type response builders
 *
 * Build a response of the given request's own type carrying only mandatory
 * fields plus the given ResponseCode. Used verbatim for sequence-error and
 * unknown-session answers and reused by the happy-path handlers whose full
 * response IS the minimal one. `code` is the shared int value space.
 */

static int s20_build_common_res(jpv2g_secc20_t *s, s20_req_t kind, int code,
                                uint8_t *out, size_t out_cap, size_t *out_len) {
    struct iso20_exiDocument *doc = s->cfg.common_workspace;
    init_iso20_exiDocument(doc);
    s->last_response_code = code;
    switch (kind) {
        case S20_REQ_SESSION_SETUP: {
            struct iso20_SessionSetupResType *res = &doc->SessionSetupRes;
            memset(res, 0, sizeof(*res));
            doc->SessionSetupRes_isUsed = 1u;
            s20_fill_common_header(s, &res->Header);
            res->ResponseCode = (iso20_responseCodeType)code;
            s20_fill_evse_id(s, res->EVSEID.characters, &res->EVSEID.charactersLen);
            break;
        }
        case S20_REQ_AUTH_SETUP: {
            struct iso20_AuthorizationSetupResType *res = &doc->AuthorizationSetupRes;
            memset(res, 0, sizeof(*res));
            doc->AuthorizationSetupRes_isUsed = 1u;
            s20_fill_common_header(s, &res->Header);
            res->ResponseCode = (iso20_responseCodeType)code;
            res->AuthorizationServices.array[0] = iso20_authorizationType_EIM;
            res->AuthorizationServices.arrayLen = 1;
            res->CertificateInstallationService = 0;
            res->EIM_ASResAuthorizationMode_isUsed = 1u; /* PnC twin stays 0: mutually exclusive */
            break;
        }
        case S20_REQ_AUTHORIZATION: {
            struct iso20_AuthorizationResType *res = &doc->AuthorizationRes;
            memset(res, 0, sizeof(*res));
            doc->AuthorizationRes_isUsed = 1u;
            s20_fill_common_header(s, &res->Header);
            res->ResponseCode = (iso20_responseCodeType)code;
            res->EVSEProcessing = iso20_processingType_Finished;
            break;
        }
        case S20_REQ_SERVICE_DISCOVERY: {
            struct iso20_ServiceDiscoveryResType *res = &doc->ServiceDiscoveryRes;
            memset(res, 0, sizeof(*res));
            doc->ServiceDiscoveryRes_isUsed = 1u;
            s20_fill_common_header(s, &res->Header);
            res->ResponseCode = (iso20_responseCodeType)code;
            res->ServiceRenegotiationSupported = 0;
            res->EnergyTransferServiceList.Service.arrayLen = 1;
            res->EnergyTransferServiceList.Service.array[0].ServiceID = JPV2G_SECC20_DC_SERVICE_ID;
            res->EnergyTransferServiceList.Service.array[0].FreeService = 0;
            break;
        }
        case S20_REQ_SERVICE_DETAIL: {
            struct iso20_ServiceDetailResType *res = &doc->ServiceDetailRes;
            memset(res, 0, sizeof(*res));
            doc->ServiceDetailRes_isUsed = 1u;
            s20_fill_common_header(s, &res->Header);
            res->ResponseCode = (iso20_responseCodeType)code;
            res->ServiceID = JPV2G_SECC20_DC_SERVICE_ID;
            s20_fill_service_param_set(&res->ServiceParameterList);
            break;
        }
        case S20_REQ_SERVICE_SELECTION: {
            struct iso20_ServiceSelectionResType *res = &doc->ServiceSelectionRes;
            memset(res, 0, sizeof(*res));
            doc->ServiceSelectionRes_isUsed = 1u;
            s20_fill_common_header(s, &res->Header);
            res->ResponseCode = (iso20_responseCodeType)code;
            break;
        }
        case S20_REQ_SCHEDULE_EXCHANGE: {
            struct iso20_ScheduleExchangeResType *res = &doc->ScheduleExchangeRes;
            memset(res, 0, sizeof(*res));
            doc->ScheduleExchangeRes_isUsed = 1u;
            s20_fill_common_header(s, &res->Header);
            res->ResponseCode = (iso20_responseCodeType)code;
            res->EVSEProcessing = iso20_processingType_Finished;
            res->GoToPause_isUsed = 0u;
            res->Scheduled_SEResControlMode_isUsed = 1u;
            s20_fill_schedule_tuple(&res->Scheduled_SEResControlMode, s20_now_unix(s), 0.0f);
            break;
        }
        case S20_REQ_POWER_DELIVERY: {
            struct iso20_PowerDeliveryResType *res = &doc->PowerDeliveryRes;
            memset(res, 0, sizeof(*res));
            doc->PowerDeliveryRes_isUsed = 1u;
            s20_fill_common_header(s, &res->Header);
            res->ResponseCode = (iso20_responseCodeType)code;
            res->EVSEStatus_isUsed = 0u;
            break;
        }
        case S20_REQ_METERING_CONFIRMATION: {
            struct iso20_MeteringConfirmationResType *res = &doc->MeteringConfirmationRes;
            memset(res, 0, sizeof(*res));
            doc->MeteringConfirmationRes_isUsed = 1u;
            s20_fill_common_header(s, &res->Header);
            res->ResponseCode = (iso20_responseCodeType)code;
            break;
        }
        case S20_REQ_SESSION_STOP: {
            struct iso20_SessionStopResType *res = &doc->SessionStopRes;
            memset(res, 0, sizeof(*res));
            doc->SessionStopRes_isUsed = 1u;
            s20_fill_common_header(s, &res->Header);
            res->ResponseCode = (iso20_responseCodeType)code;
            break;
        }
        case S20_REQ_CERT_INSTALL: {
            /* Best-effort: mandatory chains are zero skeletons; if the encoder
             * rejects them the caller falls back to the bounded-ignore path. */
            struct iso20_CertificateInstallationResType *res = &doc->CertificateInstallationRes;
            memset(res, 0, sizeof(*res));
            doc->CertificateInstallationRes_isUsed = 1u;
            s20_fill_common_header(s, &res->Header);
            res->ResponseCode = (iso20_responseCodeType)code;
            res->EVSEProcessing = iso20_processingType_Finished;
            break;
        }
        case S20_REQ_VEHICLE_CHECKIN: {
            struct iso20_VehicleCheckInResType *res = &doc->VehicleCheckInRes;
            memset(res, 0, sizeof(*res));
            doc->VehicleCheckInRes_isUsed = 1u;
            s20_fill_common_header(s, &res->Header);
            res->ResponseCode = (iso20_responseCodeType)code;
            break;
        }
        case S20_REQ_VEHICLE_CHECKOUT: {
            struct iso20_VehicleCheckOutResType *res = &doc->VehicleCheckOutRes;
            memset(res, 0, sizeof(*res));
            doc->VehicleCheckOutRes_isUsed = 1u;
            s20_fill_common_header(s, &res->Header);
            res->ResponseCode = (iso20_responseCodeType)code;
            break;
        }
        default:
            return -EINVAL;
    }
    return s20_encode_common(doc, out, out_cap, out_len);
}

static int s20_build_dc_res(jpv2g_secc20_t *s, s20_req_t kind, int code,
                            uint8_t *out, size_t out_cap, size_t *out_len) {
    struct iso20_dc_exiDocument *doc = s->cfg.dc_workspace;
    init_iso20_dc_exiDocument(doc);
    s->last_response_code = code;
    switch (kind) {
        case S20_REQ_DC_CPD: {
            struct iso20_dc_DC_ChargeParameterDiscoveryResType *res =
                &doc->DC_ChargeParameterDiscoveryRes;
            memset(res, 0, sizeof(*res));
            doc->DC_ChargeParameterDiscoveryRes_isUsed = 1u;
            s20_fill_dc_header(s, &res->Header);
            res->ResponseCode = (iso20_dc_responseCodeType)code;
            res->DC_CPDResEnergyTransferMode_isUsed = 1u;
            jpv2g_secc20_dc_limits_t zero;
            memset(&zero, 0, sizeof(zero));
            s20_fill_dc_limits_res(&res->DC_CPDResEnergyTransferMode, &zero);
            break;
        }
        case S20_REQ_DC_CABLE_CHECK: {
            struct iso20_dc_DC_CableCheckResType *res = &doc->DC_CableCheckRes;
            memset(res, 0, sizeof(*res));
            doc->DC_CableCheckRes_isUsed = 1u;
            s20_fill_dc_header(s, &res->Header);
            res->ResponseCode = (iso20_dc_responseCodeType)code;
            res->EVSEProcessing = iso20_dc_processingType_Finished;
            break;
        }
        case S20_REQ_DC_PRE_CHARGE: {
            struct iso20_dc_DC_PreChargeResType *res = &doc->DC_PreChargeRes;
            memset(res, 0, sizeof(*res));
            doc->DC_PreChargeRes_isUsed = 1u;
            s20_fill_dc_header(s, &res->Header);
            res->ResponseCode = (iso20_dc_responseCodeType)code;
            s20_set_dc_rat(&res->EVSEPresentVoltage, 0.0f);
            break;
        }
        case S20_REQ_DC_CHARGE_LOOP: {
            struct iso20_dc_DC_ChargeLoopResType *res = &doc->DC_ChargeLoopRes;
            memset(res, 0, sizeof(*res));
            doc->DC_ChargeLoopRes_isUsed = 1u;
            s20_fill_dc_header(s, &res->Header);
            res->ResponseCode = (iso20_dc_responseCodeType)code;
            s20_set_dc_rat(&res->EVSEPresentCurrent, 0.0f);
            s20_set_dc_rat(&res->EVSEPresentVoltage, 0.0f);
            /* Mirror our only supported mode; all members optional. */
            res->Scheduled_DC_CLResControlMode_isUsed = 1u;
            break;
        }
        case S20_REQ_DC_WELDING: {
            struct iso20_dc_DC_WeldingDetectionResType *res = &doc->DC_WeldingDetectionRes;
            memset(res, 0, sizeof(*res));
            doc->DC_WeldingDetectionRes_isUsed = 1u;
            s20_fill_dc_header(s, &res->Header);
            res->ResponseCode = (iso20_dc_responseCodeType)code;
            s20_set_dc_rat(&res->EVSEPresentVoltage, 0.0f);
            break;
        }
        default:
            return -EINVAL;
    }
    return s20_encode_dc(doc, out, out_cap, out_len);
}

/* ------------------------------------------------------ state accept sets */

static bool s20_state_accepts(jpv2g_secc20_state_t state, s20_req_t kind) {
    switch (state) {
        case JPV2G_SECC20_STATE_SESSION_SETUP:
            /* SessionStop before SessionSetup is a sequence error (row 2). */
            return kind == S20_REQ_SESSION_SETUP;
        case JPV2G_SECC20_STATE_AUTH_SETUP:
            return kind == S20_REQ_AUTH_SETUP || kind == S20_REQ_SESSION_STOP;
        case JPV2G_SECC20_STATE_AUTHORIZATION:
            return kind == S20_REQ_AUTHORIZATION || kind == S20_REQ_SESSION_STOP;
        case JPV2G_SECC20_STATE_SERVICE_DISCOVERY:
            return kind == S20_REQ_SERVICE_DISCOVERY || kind == S20_REQ_SESSION_STOP;
        case JPV2G_SECC20_STATE_SERVICE_DETAIL:
            return kind == S20_REQ_SERVICE_DETAIL || kind == S20_REQ_SERVICE_SELECTION ||
                   kind == S20_REQ_SESSION_STOP;
        case JPV2G_SECC20_STATE_DC_CPD:
            return kind == S20_REQ_DC_CPD || kind == S20_REQ_SESSION_STOP;
        case JPV2G_SECC20_STATE_SCHEDULE_EXCHANGE:
            /* Direct DC_CableCheck/PowerDelivery skips are rejected: the
             * [V2G20-2122] skip is only legal with retained isolation from a
             * resumed session, and we always run new sessions (FLAG #3). */
            return kind == S20_REQ_SCHEDULE_EXCHANGE || kind == S20_REQ_SESSION_STOP;
        case JPV2G_SECC20_STATE_CABLE_CHECK:
            return kind == S20_REQ_DC_CABLE_CHECK || kind == S20_REQ_SESSION_STOP;
        case JPV2G_SECC20_STATE_PRE_CHARGE:
            return kind == S20_REQ_DC_PRE_CHARGE || kind == S20_REQ_SESSION_STOP;
        case JPV2G_SECC20_STATE_POWER_DELIVERY:
            /* B's PreCharge model: further DC_PreChargeReqs are answered here.
             * SessionStop is ACCEPTED pre-Start (FLAG #4): an EV aborting
             * between precharge and start gets a clean stop while the
             * contactors are still open. */
            return kind == S20_REQ_POWER_DELIVERY || kind == S20_REQ_DC_PRE_CHARGE ||
                   kind == S20_REQ_SESSION_STOP;
        case JPV2G_SECC20_STATE_CHARGE_LOOP:
            /* SessionStop mid-loop is a sequence error (both references
             * agree): the EV must stop power via PowerDelivery(Stop) first. */
            return kind == S20_REQ_DC_CHARGE_LOOP || kind == S20_REQ_POWER_DELIVERY;
        case JPV2G_SECC20_STATE_WELDING:
            return kind == S20_REQ_DC_WELDING || kind == S20_REQ_SESSION_STOP;
        case JPV2G_SECC20_STATE_SESSION_STOP:
            return kind == S20_REQ_SESSION_STOP;
        default:
            return false;
    }
}

/* -------------------------------------------------- CommonMessages handlers
 * Each handler extracts what it needs from the decoded request, then builds
 * the response in the same workspace. `disp` starts as CONTINUE; the
 * dispatcher upgrades it via the >= FAILED rule after the handler returns.
 */

static int s20_handle_session_setup(jpv2g_secc20_t *s, struct iso20_exiDocument *doc,
                                    uint8_t *out, size_t out_cap, size_t *out_len) {
    const struct iso20_SessionSetupReqType *req = &doc->SessionSetupReq;
    /* -20 EVCCID is a string (not the -2 MAC bytes); bounded copy, never
     * hex-decode. Extract before the response overwrites the union. */
    char evccid[iso20_EVCCID_CHARACTER_SIZE];
    size_t evccid_len = req->EVCCID.charactersLen;
    if (evccid_len >= sizeof(evccid)) evccid_len = sizeof(evccid) - 1;
    memcpy(evccid, req->EVCCID.characters, evccid_len);
    evccid[evccid_len] = '\0';

    /* Always a fresh session on EIM/TCP: no cert-session resume without TLS,
     * and a non-zero EV SessionID is NOT an error — assign a new id. */
    if (jpv2g_generate_session_id(NULL, s->session_id) != 0) {
        /* RNG unavailable: derive a non-zero id from the monotonic clock so
         * the session can still proceed (bench/host degenerate case). */
        int64_t t = jpv2g_now_monotonic_ms();
        for (size_t i = 0; i < JPV2G_SECC20_SESSION_ID_LEN; ++i) {
            s->session_id[i] = (uint8_t)((t >> (i * 8)) ^ 0xA5u);
        }
        s->session_id[0] |= 0x01u;
    }
    s->session_established = true;
    s->state = JPV2G_SECC20_STATE_AUTH_SETUP;

    if (s->cfg.callbacks.on_evccid) {
        s->cfg.callbacks.on_evccid(s->cfg.callbacks.user_ctx, evccid, evccid_len);
    }
    JPV2G_INFO("ISO20 SessionSetup evccid=%s", evccid);
    return s20_build_common_res(s, S20_REQ_SESSION_SETUP,
                                (int)iso20_responseCodeType_OK_NewSessionEstablished,
                                out, out_cap, out_len);
}

static int s20_handle_auth_setup(jpv2g_secc20_t *s, struct iso20_exiDocument *doc,
                                 uint8_t *out, size_t out_cap, size_t *out_len) {
    (void)doc; /* header-only request */
    s->state = JPV2G_SECC20_STATE_AUTHORIZATION;
    /* Side effect: the controller starts its OCPP Authorize now. */
    if (s->cfg.callbacks.on_auth_required) {
        s->cfg.callbacks.on_auth_required(s->cfg.callbacks.user_ctx);
    }
    return s20_build_common_res(s, S20_REQ_AUTH_SETUP, (int)iso20_responseCodeType_OK,
                                out, out_cap, out_len);
}

static int s20_handle_authorization(jpv2g_secc20_t *s, struct iso20_exiDocument *doc,
                                    uint8_t *out, size_t out_cap, size_t *out_len) {
    const struct iso20_AuthorizationReqType *req = &doc->AuthorizationReq;
    const bool selected_eim = req->SelectedAuthorizationService == iso20_authorizationType_EIM;

    const int64_t now = jpv2g_now_monotonic_ms();
    if (s->eim_ongoing_deadline_ms == 0) {
        s->eim_ongoing_deadline_ms = now + JPV2G_SECC20_EIM_ONGOING_TIMEOUT_MS;
    }

    int code = (int)iso20_responseCodeType_OK;
    iso20_processingType processing = iso20_processingType_Ongoing_WaitingForCustomerInteraction;

    if (!selected_eim) {
        /* Non-terminal warning: the EV may retry with EIM. */
        code = (int)iso20_responseCodeType_WARNING_AuthorizationSelectionInvalid;
    } else if (now > s->eim_ongoing_deadline_ms) {
        /* 180 s EIM ONGOING expiry: hard-fail per plan 1.4. */
        code = (int)iso20_responseCodeType_FAILED;
        processing = iso20_processingType_Finished;
    } else {
        switch (s20_cb_auth(s)) {
            case JPV2G_SECC20_AUTH_GRANTED:
                /* Finished-when-granted (2026-07-20 DIN lesson): never hold
                 * Ongoing after the grant, EVs stall on it. */
                processing = iso20_processingType_Finished;
                s->state = JPV2G_SECC20_STATE_SERVICE_DISCOVERY;
                s->eim_ongoing_deadline_ms = 0;
                break;
            case JPV2G_SECC20_AUTH_REJECTED:
                processing = iso20_processingType_Finished;
                code = (int)iso20_responseCodeType_WARNING_EIMAuthorizationFailure;
                break;
            case JPV2G_SECC20_AUTH_PENDING:
            default:
                /* EIM pending answers Ongoing_WaitingForCustomerInteraction
                 * (FLAG #7): a human is presenting RFID/app. */
                break;
        }
    }

    int rc = s20_build_common_res(s, S20_REQ_AUTHORIZATION, code, out, out_cap, out_len);
    if (rc == 0) {
        struct iso20_AuthorizationResType *res = &s->cfg.common_workspace->AuthorizationRes;
        res->EVSEProcessing = processing;
        rc = s20_encode_common(s->cfg.common_workspace, out, out_cap, out_len);
    }
    return rc;
}

static int s20_handle_service_discovery(jpv2g_secc20_t *s, struct iso20_exiDocument *doc,
                                        uint8_t *out, size_t out_cap, size_t *out_len) {
    const struct iso20_ServiceDiscoveryReqType *req = &doc->ServiceDiscoveryReq;
    bool offer_dc = true;
    if (req->SupportedServiceIDs_isUsed) {
        offer_dc = false;
        uint16_t n = req->SupportedServiceIDs.ServiceID.arrayLen;
        if (n > iso20_serviceIDType_16_ARRAY_SIZE) n = iso20_serviceIDType_16_ARRAY_SIZE;
        for (uint16_t i = 0; i < n; ++i) {
            if (req->SupportedServiceIDs.ServiceID.array[i] == JPV2G_SECC20_DC_SERVICE_ID) {
                offer_dc = true;
                break;
            }
        }
    }
    s->state = JPV2G_SECC20_STATE_SERVICE_DETAIL;
    int rc = s20_build_common_res(s, S20_REQ_SERVICE_DISCOVERY, (int)iso20_responseCodeType_OK,
                                  out, out_cap, out_len);
    if (rc == 0 && !offer_dc) {
        /* EV filtered service 2 out: empty offer list, still RC=OK. */
        struct iso20_ServiceDiscoveryResType *res = &s->cfg.common_workspace->ServiceDiscoveryRes;
        res->EnergyTransferServiceList.Service.arrayLen = 0;
        rc = s20_encode_common(s->cfg.common_workspace, out, out_cap, out_len);
    }
    return rc;
}

static int s20_handle_service_detail(jpv2g_secc20_t *s, struct iso20_exiDocument *doc,
                                     uint8_t *out, size_t out_cap, size_t *out_len) {
    const uint16_t service_id = doc->ServiceDetailReq.ServiceID;
    if (service_id != JPV2G_SECC20_DC_SERVICE_ID) {
        /* FLAG #2 resolution: terminate — we only ever offer one service, so
         * a wrong id is an EV defect and the blanket >= FAILED rule wins. */
        return s20_build_common_res(s, S20_REQ_SERVICE_DETAIL,
                                    (int)iso20_responseCodeType_FAILED_ServiceIDInvalid,
                                    out, out_cap, out_len);
    }
    /* Stays in SERVICE_DETAIL: the request is repeatable until selection. */
    return s20_build_common_res(s, S20_REQ_SERVICE_DETAIL, (int)iso20_responseCodeType_OK,
                                out, out_cap, out_len);
}

static int s20_handle_service_selection(jpv2g_secc20_t *s, struct iso20_exiDocument *doc,
                                        uint8_t *out, size_t out_cap, size_t *out_len) {
    const struct iso20_ServiceSelectionReqType *req = &doc->ServiceSelectionReq;
    int code = (int)iso20_responseCodeType_OK;
    if (req->SelectedEnergyTransferService.ServiceID != JPV2G_SECC20_DC_SERVICE_ID) {
        code = (int)iso20_responseCodeType_FAILED_NoEnergyTransferServiceSelected;
    } else if (req->SelectedEnergyTransferService.ParameterSetID != JPV2G_SECC20_DC_PARAMETER_SET_ID ||
               (req->SelectedVASList_isUsed && req->SelectedVASList.SelectedService.arrayLen > 0)) {
        /* We advertise no VAS; selecting one (or an unknown parameter set)
         * is a selection defect. */
        code = (int)iso20_responseCodeType_FAILED_ServiceSelectionInvalid;
    } else {
        s->state = JPV2G_SECC20_STATE_DC_CPD;
        JPV2G_INFO("ISO20 ServiceSelection latched {DC, Scheduled}");
    }
    return s20_build_common_res(s, S20_REQ_SERVICE_SELECTION, code, out, out_cap, out_len);
}

static int s20_handle_schedule_exchange(jpv2g_secc20_t *s, struct iso20_exiDocument *doc,
                                        uint8_t *out, size_t out_cap, size_t *out_len) {
    const struct iso20_ScheduleExchangeReqType *req = &doc->ScheduleExchangeReq;
    const bool dynamic_mode = req->Dynamic_SEReqControlMode_isUsed != 0;
    const bool scheduled_mode = req->Scheduled_SEReqControlMode_isUsed != 0;

    const int64_t now = jpv2g_now_monotonic_ms();
    if (s->se_ongoing_deadline_ms == 0) {
        s->se_ongoing_deadline_ms = now + JPV2G_SECC20_SE_ONGOING_TIMEOUT_MS;
    }

    if (dynamic_mode || !scheduled_mode || now > s->se_ongoing_deadline_ms) {
        /* Dynamic is not offered (ControlMode=Scheduled was latched at
         * ServiceSelection); a missing mode is malformed; ONGOING expiry
         * hard-fails. All are plain FAILED per plan row 9. */
        return s20_build_common_res(s, S20_REQ_SCHEDULE_EXCHANGE,
                                    (int)iso20_responseCodeType_FAILED,
                                    out, out_cap, out_len);
    }

    jpv2g_secc20_dc_limits_t lim;
    s20_cb_limits(s, &lim);

    /* EVSEProcessing=Finished immediately — no tariff backend to wait for.
     * The tuple is present even then (schema-mandatory either way). */
    s->se_ongoing_deadline_ms = 0;
    s->state = JPV2G_SECC20_STATE_CABLE_CHECK;
    int rc = s20_build_common_res(s, S20_REQ_SCHEDULE_EXCHANGE, (int)iso20_responseCodeType_OK,
                                  out, out_cap, out_len);
    if (rc == 0) {
        struct iso20_ScheduleExchangeResType *res = &s->cfg.common_workspace->ScheduleExchangeRes;
        s20_fill_schedule_tuple(&res->Scheduled_SEResControlMode, s20_now_unix(s),
                                lim.max_charge_power_w);
        rc = s20_encode_common(s->cfg.common_workspace, out, out_cap, out_len);
    }
    return rc;
}

static int s20_handle_power_delivery(jpv2g_secc20_t *s, struct iso20_exiDocument *doc,
                                     uint8_t *out, size_t out_cap, size_t *out_len) {
    const struct iso20_PowerDeliveryReqType *req = &doc->PowerDeliveryReq;
    const iso20_chargeProgressType progress = req->ChargeProgress;

    /* Scheduled EVPowerProfile must reference the one tuple we offered;
     * profile content itself is accepted silently (plan row 12). */
    if (req->EVPowerProfile_isUsed &&
        req->EVPowerProfile.Scheduled_EVPPTControlMode_isUsed &&
        req->EVPowerProfile.Scheduled_EVPPTControlMode.SelectedScheduleTupleID !=
            JPV2G_SECC20_SCHEDULE_TUPLE_ID) {
        return s20_build_common_res(s, S20_REQ_POWER_DELIVERY,
                                    (int)iso20_responseCodeType_FAILED_ScheduleSelectionInvalid,
                                    out, out_cap, out_len);
    }

    int code = (int)iso20_responseCodeType_OK;
    switch (progress) {
        case iso20_chargeProgressType_Start:
            if (s->state != JPV2G_SECC20_STATE_CHARGE_LOOP) {
                /* SETUP_FINISHED: contactor close is controller-owned; the
                 * callback returns only once the position is confirmed. The
                 * CP C2/D2 check is folded into that confirmation and is
                 * warning-only on the controller side ([V2G20-1617]). */
                if (s20_cb_contactor(s, true) != 0) {
                    JPV2G_WARN("ISO20 PowerDelivery(Start): contactor close refused");
                    return s20_build_common_res(s, S20_REQ_POWER_DELIVERY,
                                                (int)iso20_responseCodeType_FAILED_ContactorError,
                                                out, out_cap, out_len);
                }
                s->contactor_closed = true;
                s->state = JPV2G_SECC20_STATE_CHARGE_LOOP;
                JPV2G_INFO("ISO20 PowerDelivery(Start): contactor closed, entering charge loop");
            }
            /* Start again inside the loop is idempotent: OK, stay. */
            break;
        case iso20_chargeProgressType_Stop:
            if (s->state == JPV2G_SECC20_STATE_CHARGE_LOOP) {
                if (s->cfg.callbacks.on_charge_loop_finished) {
                    s->cfg.callbacks.on_charge_loop_finished(s->cfg.callbacks.user_ctx);
                }
            }
            if (s->contactor_closed) {
                if (s20_cb_contactor(s, false) != 0) {
                    /* Never block the stop on an open refusal; the controller
                     * owns the fault handling out-of-band. */
                    JPV2G_WARN("ISO20 PowerDelivery(Stop): contactor open request failed");
                }
                s->contactor_closed = false;
            }
            s->state = JPV2G_SECC20_STATE_WELDING;
            break;
        case iso20_chargeProgressType_Standby:
            /* FLAG #5 resolution: WARNING only, never self-terminate — the
             * warning is the EV's signal and the EV decides what to do. */
            code = (int)iso20_responseCodeType_WARNING_StandbyNotAllowed;
            break;
        case iso20_chargeProgressType_ScheduleRenegotiation:
        default:
            /* ServiceDiscoveryRes advertised renegotiation unsupported. */
            code = (int)iso20_responseCodeType_FAILED_ScheduleRenegotiation;
            break;
    }
    return s20_build_common_res(s, S20_REQ_POWER_DELIVERY, code, out, out_cap, out_len);
}

static int s20_handle_session_stop(jpv2g_secc20_t *s, struct iso20_exiDocument *doc,
                                   uint8_t *out, size_t out_cap, size_t *out_len,
                                   jpv2g_secc20_disposition_t *disp) {
    const struct iso20_SessionStopReqType *req = &doc->SessionStopReq;
    const iso20_chargingSessionType session_action = req->ChargingSession;

    /* Extract the optional diagnostics before the union is reused. */
    char code_buf[iso20_EVTerminationCode_CHARACTER_SIZE] = {0};
    char expl_buf[iso20_EVTerminationExplanation_CHARACTER_SIZE] = {0};
    size_t code_len = 0;
    size_t expl_len = 0;
    if (req->EVTerminationCode_isUsed) {
        code_len = req->EVTerminationCode.charactersLen;
        if (code_len >= sizeof(code_buf)) code_len = sizeof(code_buf) - 1;
        memcpy(code_buf, req->EVTerminationCode.characters, code_len);
    }
    if (req->EVTerminationExplanation_isUsed) {
        expl_len = req->EVTerminationExplanation.charactersLen;
        if (expl_len >= sizeof(expl_buf)) expl_len = sizeof(expl_buf) - 1;
        memcpy(expl_buf, req->EVTerminationExplanation.characters, expl_len);
    }
    if ((code_len || expl_len) && s->cfg.callbacks.on_ev_termination) {
        s->cfg.callbacks.on_ev_termination(s->cfg.callbacks.user_ctx,
                                           code_buf, code_len, expl_buf, expl_len);
    }
    if (code_len) {
        JPV2G_INFO("ISO20 SessionStop EVTerminationCode=%s explanation=%s", code_buf, expl_buf);
    }

    if (session_action == iso20_chargingSessionType_ServiceRenegotiation) {
        return s20_build_common_res(s, S20_REQ_SESSION_STOP,
                                    (int)iso20_responseCodeType_FAILED_NoServiceRenegotiationSupported,
                                    out, out_cap, out_len);
    }

    /* Pause is accepted minimally: RC=OK + pause EVT; the next TCP session is
     * a NEW -20 session (no resume without a TLS cert session hash). */
    *disp = (session_action == iso20_chargingSessionType_Pause)
                ? JPV2G_SECC20_DONE_PAUSED
                : JPV2G_SECC20_DONE_STOPPED;
    return s20_build_common_res(s, S20_REQ_SESSION_STOP, (int)iso20_responseCodeType_OK,
                                out, out_cap, out_len);
}

/* --------------------------------------------------------- DC handlers */

static int s20_handle_dc_cpd(jpv2g_secc20_t *s, struct iso20_dc_exiDocument *doc,
                             uint8_t *out, size_t out_cap, size_t *out_len) {
    const struct iso20_dc_DC_ChargeParameterDiscoveryReqType *req =
        &doc->DC_ChargeParameterDiscoveryReq;
    if (req->BPT_DC_CPDReqEnergyTransferMode_isUsed ||
        !req->DC_CPDReqEnergyTransferMode_isUsed) {
        /* BPT was never offered; a missing DC mode is equally wrong. */
        return s20_build_dc_res(s, S20_REQ_DC_CPD,
                                (int)iso20_dc_responseCodeType_FAILED_WrongChargeParameter,
                                out, out_cap, out_len);
    }

    /* Forward the EV envelope on the same conceptual lane the -2 CPD uses. */
    const struct iso20_dc_DC_CPDReqEnergyTransferModeType *ev = &req->DC_CPDReqEnergyTransferMode;
    jpv2g_secc20_ev_limits_t ev_limits;
    ev_limits.ev_max_charge_power_w = s20_dc_rat_value(&ev->EVMaximumChargePower);
    ev_limits.ev_min_charge_power_w = s20_dc_rat_value(&ev->EVMinimumChargePower);
    ev_limits.ev_max_charge_current_a = s20_dc_rat_value(&ev->EVMaximumChargeCurrent);
    ev_limits.ev_min_charge_current_a = s20_dc_rat_value(&ev->EVMinimumChargeCurrent);
    ev_limits.ev_max_voltage_v = s20_dc_rat_value(&ev->EVMaximumVoltage);
    ev_limits.ev_min_voltage_v = s20_dc_rat_value(&ev->EVMinimumVoltage);
    ev_limits.target_soc_percent = ev->TargetSOC_isUsed ? (int)ev->TargetSOC : -1;
    if (s->cfg.callbacks.on_ev_limits) {
        s->cfg.callbacks.on_ev_limits(s->cfg.callbacks.user_ctx, &ev_limits);
    }

    jpv2g_secc20_dc_limits_t lim;
    s20_cb_limits(s, &lim);
    s->state = JPV2G_SECC20_STATE_SCHEDULE_EXCHANGE;

    /* -20 CPD is single-shot (no EVSEProcessing field): answer in one go. */
    int rc = s20_build_dc_res(s, S20_REQ_DC_CPD, (int)iso20_dc_responseCodeType_OK,
                              out, out_cap, out_len);
    if (rc == 0) {
        struct iso20_dc_DC_ChargeParameterDiscoveryResType *res =
            &s->cfg.dc_workspace->DC_ChargeParameterDiscoveryRes;
        s20_fill_dc_limits_res(&res->DC_CPDResEnergyTransferMode, &lim);
        rc = s20_encode_dc(s->cfg.dc_workspace, out, out_cap, out_len);
    }
    return rc;
}

static int s20_handle_dc_cable_check(jpv2g_secc20_t *s, struct iso20_dc_exiDocument *doc,
                                     uint8_t *out, size_t out_cap, size_t *out_len) {
    (void)doc; /* header-only request */
    if (!s->cable_check_started) {
        s->cable_check_started = true;
        if (s->cfg.callbacks.on_cable_check_started) {
            s->cfg.callbacks.on_cable_check_started(s->cfg.callbacks.user_ctx);
        }
    }

    /* There is no isolation-status field in -20: Finished IS the isolation
     * verdict, so it is only sent after a real IMD pass (controller Warning
     * still proceeds — never terminal, 2026-07-20 lesson). */
    iso20_dc_processingType processing = iso20_dc_processingType_Ongoing;
    switch (s20_cb_cable_check(s)) {
        case JPV2G_SECC20_CABLE_CHECK_FINISHED:
            processing = iso20_dc_processingType_Finished;
            s->state = JPV2G_SECC20_STATE_PRE_CHARGE;
            break;
        case JPV2G_SECC20_CABLE_CHECK_FAULT:
            return s20_build_dc_res(s, S20_REQ_DC_CABLE_CHECK,
                                    (int)iso20_dc_responseCodeType_FAILED,
                                    out, out_cap, out_len);
        case JPV2G_SECC20_CABLE_CHECK_ONGOING:
        default:
            break;
    }

    int rc = s20_build_dc_res(s, S20_REQ_DC_CABLE_CHECK, (int)iso20_dc_responseCodeType_OK,
                              out, out_cap, out_len);
    if (rc == 0 && processing != iso20_dc_processingType_Finished) {
        struct iso20_dc_DC_CableCheckResType *res = &s->cfg.dc_workspace->DC_CableCheckRes;
        res->EVSEProcessing = processing;
        rc = s20_encode_dc(s->cfg.dc_workspace, out, out_cap, out_len);
    }
    return rc;
}

static int s20_handle_dc_pre_charge(jpv2g_secc20_t *s, struct iso20_dc_exiDocument *doc,
                                    uint8_t *out, size_t out_cap, size_t *out_len) {
    const struct iso20_dc_DC_PreChargeReqType *req = &doc->DC_PreChargeReq;
    const float target_v = s20_dc_rat_value(&req->EVTargetVoltage);
    const float ev_present_v = s20_dc_rat_value(&req->EVPresentVoltage);

    /* Every request re-drives the PSU target (same as the -2 PreCharge
     * lane); the EV decides completion by comparing our EVSEPresentVoltage
     * against its target, so the telemetry must stay fresh. */
    if (s->cfg.callbacks.on_precharge_target) {
        s->cfg.callbacks.on_precharge_target(s->cfg.callbacks.user_ctx, target_v, ev_present_v);
    }

    jpv2g_secc20_present_t present;
    s20_cb_present(s, &present);

    /* B's state model (FLAG #6): after the FIRST PreChargeRes the session
     * sits in POWER_DELIVERY, which keeps answering further PreChargeReqs. */
    if (s->state == JPV2G_SECC20_STATE_PRE_CHARGE) {
        s->state = JPV2G_SECC20_STATE_POWER_DELIVERY;
    }

    int rc = s20_build_dc_res(s, S20_REQ_DC_PRE_CHARGE, (int)iso20_dc_responseCodeType_OK,
                              out, out_cap, out_len);
    if (rc == 0) {
        struct iso20_dc_DC_PreChargeResType *res = &s->cfg.dc_workspace->DC_PreChargeRes;
        s20_set_dc_rat(&res->EVSEPresentVoltage, present.voltage_v);
        rc = s20_encode_dc(s->cfg.dc_workspace, out, out_cap, out_len);
    }
    return rc;
}

static int s20_handle_dc_charge_loop(jpv2g_secc20_t *s, struct iso20_dc_exiDocument *doc,
                                     uint8_t *out, size_t out_cap, size_t *out_len) {
    const struct iso20_dc_DC_ChargeLoopReqType *req = &doc->DC_ChargeLoopReq;

    /* Only the Scheduled DC control mode was negotiated; any other member
     * (Dynamic, BPT_*, bare CLReqControlMode) hard-fails per plan row 13. */
    if (!req->Scheduled_DC_CLReqControlMode_isUsed ||
        req->Dynamic_DC_CLReqControlMode_isUsed ||
        req->BPT_Scheduled_DC_CLReqControlMode_isUsed ||
        req->BPT_Dynamic_DC_CLReqControlMode_isUsed ||
        req->CLReqControlMode_isUsed) {
        return s20_build_dc_res(s, S20_REQ_DC_CHARGE_LOOP,
                                (int)iso20_dc_responseCodeType_FAILED,
                                out, out_cap, out_len);
    }

    if (!s->charge_loop_started) {
        s->charge_loop_started = true;
        if (s->cfg.callbacks.on_charge_loop_started) {
            s->cfg.callbacks.on_charge_loop_started(s->cfg.callbacks.user_ctx);
        }
    }

    /* Extract everything needed, then reuse the union for the response. */
    const float target_i = s20_dc_rat_value(&req->Scheduled_DC_CLReqControlMode.EVTargetCurrent);
    const float target_v = s20_dc_rat_value(&req->Scheduled_DC_CLReqControlMode.EVTargetVoltage);
    const float ev_present_v = s20_dc_rat_value(&req->EVPresentVoltage);
    const bool meter_requested = req->MeterInfoRequested != 0;
    int present_soc = -1;
    if (req->DisplayParameters_isUsed && req->DisplayParameters.PresentSOC_isUsed) {
        present_soc = (int)req->DisplayParameters.PresentSOC;
    }
    const bool display_used = req->DisplayParameters_isUsed != 0;

    /* The -20 CurrentDemand targets: forward to the controller every tick. */
    if (s->cfg.callbacks.on_charge_targets) {
        s->cfg.callbacks.on_charge_targets(s->cfg.callbacks.user_ctx,
                                           target_v, target_i, ev_present_v);
    }
    if (display_used && s->cfg.callbacks.on_display_parameters) {
        s->cfg.callbacks.on_display_parameters(s->cfg.callbacks.user_ctx, present_soc);
    }

    jpv2g_secc20_present_t present;
    s20_cb_present(s, &present);
    jpv2g_secc20_dc_limits_t lim;
    s20_cb_limits(s, &lim); /* live fetch: runtime smart-charging limit channel */
    const jpv2g_secc20_stop_request_t stop = s20_cb_stop(s);

    char meter_id[iso20_dc_MeterID_CHARACTER_SIZE] = {0};
    uint64_t meter_wh = 0;
    bool meter_fresh = false;
    if (meter_requested && s->cfg.callbacks.get_meter &&
        s->cfg.callbacks.get_meter(s->cfg.callbacks.user_ctx,
                                   meter_id, sizeof(meter_id), &meter_wh) == 0) {
        meter_fresh = true;
    }

    int rc = s20_build_dc_res(s, S20_REQ_DC_CHARGE_LOOP, (int)iso20_dc_responseCodeType_OK,
                              out, out_cap, out_len);
    if (rc != 0) return rc;

    struct iso20_dc_DC_ChargeLoopResType *res = &s->cfg.dc_workspace->DC_ChargeLoopRes;
    s20_set_dc_rat(&res->EVSEPresentVoltage, present.voltage_v);
    s20_set_dc_rat(&res->EVSEPresentCurrent, present.current_a);
    res->EVSEPowerLimitAchieved = present.power_limit_achieved ? 1 : 0;
    res->EVSECurrentLimitAchieved = present.current_limit_achieved ? 1 : 0;
    res->EVSEVoltageLimitAchieved = present.voltage_limit_achieved ? 1 : 0;

    struct iso20_dc_Scheduled_DC_CLResControlModeType *mode = &res->Scheduled_DC_CLResControlMode;
    s20_set_dc_rat(&mode->EVSEMaximumChargePower, lim.max_charge_power_w);
    mode->EVSEMaximumChargePower_isUsed = 1u;
    s20_set_dc_rat(&mode->EVSEMinimumChargePower, lim.min_charge_power_w);
    mode->EVSEMinimumChargePower_isUsed = 1u;
    s20_set_dc_rat(&mode->EVSEMaximumChargeCurrent, lim.max_charge_current_a);
    mode->EVSEMaximumChargeCurrent_isUsed = 1u;
    s20_set_dc_rat(&mode->EVSEMaximumVoltage, lim.max_voltage_v);
    mode->EVSEMaximumVoltage_isUsed = 1u;

    if (meter_fresh) {
        res->MeterInfo_isUsed = 1u;
        size_t idn = strlen(meter_id);
        if (idn >= sizeof(res->MeterInfo.MeterID.characters)) {
            idn = sizeof(res->MeterInfo.MeterID.characters) - 1;
        }
        memcpy(res->MeterInfo.MeterID.characters, meter_id, idn);
        res->MeterInfo.MeterID.charactersLen = (uint16_t)idn;
        res->MeterInfo.ChargedEnergyReadingWh = meter_wh;
    }

    if (stop != JPV2G_SECC20_STOP_NONE) {
        /* Controller stop/pause: notify, keep answering until the EV sends
         * PowerDelivery(Stop). Delay 0 in Scheduled mode. */
        res->EVSEStatus_isUsed = 1u;
        res->EVSEStatus.NotificationMaxDelay = 0;
        res->EVSEStatus.EVSENotification = (stop == JPV2G_SECC20_STOP_PAUSE)
                                               ? iso20_dc_evseNotificationType_Pause
                                               : iso20_dc_evseNotificationType_Terminate;
    }

    return s20_encode_dc(s->cfg.dc_workspace, out, out_cap, out_len);
}

static int s20_handle_dc_welding(jpv2g_secc20_t *s, struct iso20_dc_exiDocument *doc,
                                 uint8_t *out, size_t out_cap, size_t *out_len) {
    const struct iso20_dc_DC_WeldingDetectionReqType *req = &doc->DC_WeldingDetectionReq;
    const bool ev_finished = req->EVProcessing == iso20_dc_processingType_Finished;

    jpv2g_secc20_present_t present;
    s20_cb_present(s, &present);

    /* The EV owns the weld verdict; we only report inlet voltage with the
     * contactors open and follow its Ongoing/Finished lead. */
    if (ev_finished) s->state = JPV2G_SECC20_STATE_SESSION_STOP;

    int rc = s20_build_dc_res(s, S20_REQ_DC_WELDING, (int)iso20_dc_responseCodeType_OK,
                              out, out_cap, out_len);
    if (rc == 0) {
        struct iso20_dc_DC_WeldingDetectionResType *res = &s->cfg.dc_workspace->DC_WeldingDetectionRes;
        s20_set_dc_rat(&res->EVSEPresentVoltage, present.voltage_v);
        rc = s20_encode_dc(s->cfg.dc_workspace, out, out_cap, out_len);
    }
    return rc;
}

/* ------------------------------------------------------------- dispatch */

static const char *s20_req_name(s20_req_t kind) {
    switch (kind) {
        case S20_REQ_SESSION_SETUP: return "SessionSetupReq";
        case S20_REQ_AUTH_SETUP: return "AuthorizationSetupReq";
        case S20_REQ_AUTHORIZATION: return "AuthorizationReq";
        case S20_REQ_SERVICE_DISCOVERY: return "ServiceDiscoveryReq";
        case S20_REQ_SERVICE_DETAIL: return "ServiceDetailReq";
        case S20_REQ_SERVICE_SELECTION: return "ServiceSelectionReq";
        case S20_REQ_SCHEDULE_EXCHANGE: return "ScheduleExchangeReq";
        case S20_REQ_POWER_DELIVERY: return "PowerDeliveryReq";
        case S20_REQ_METERING_CONFIRMATION: return "MeteringConfirmationReq";
        case S20_REQ_SESSION_STOP: return "SessionStopReq";
        case S20_REQ_CERT_INSTALL: return "CertificateInstallationReq";
        case S20_REQ_VEHICLE_CHECKIN: return "VehicleCheckInReq";
        case S20_REQ_VEHICLE_CHECKOUT: return "VehicleCheckOutReq";
        case S20_REQ_DC_CPD: return "DC_ChargeParameterDiscoveryReq";
        case S20_REQ_DC_CABLE_CHECK: return "DC_CableCheckReq";
        case S20_REQ_DC_PRE_CHARGE: return "DC_PreChargeReq";
        case S20_REQ_DC_CHARGE_LOOP: return "DC_ChargeLoopReq";
        case S20_REQ_DC_WELDING: return "DC_WeldingDetectionReq";
        default: return "Unknown";
    }
}

static int s20_dispatch_common(jpv2g_secc20_t *s,
                               const uint8_t *exi, size_t exi_len,
                               uint8_t *out, size_t out_cap, size_t *out_len,
                               jpv2g_secc20_disposition_t *disp) {
    struct iso20_exiDocument *doc = s->cfg.common_workspace;
    init_iso20_exiDocument(doc);
    exi_bitstream_t bs;
    exi_bitstream_init(&bs, (uint8_t *)exi, exi_len, 0, NULL);
    if (decode_iso20_exiDocument(&bs, doc) != 0) {
        JPV2G_WARN("ISO20 CommonMessages frame did not decode (len=%u)", (unsigned)exi_len);
        return -EBADMSG;
    }

    s20_req_t kind = S20_REQ_NONE;
    const struct iso20_MessageHeaderType *hdr = NULL;
    if (doc->SessionSetupReq_isUsed) {
        kind = S20_REQ_SESSION_SETUP;
        hdr = &doc->SessionSetupReq.Header;
    } else if (doc->AuthorizationSetupReq_isUsed) {
        kind = S20_REQ_AUTH_SETUP;
        hdr = &doc->AuthorizationSetupReq.Header;
    } else if (doc->AuthorizationReq_isUsed) {
        kind = S20_REQ_AUTHORIZATION;
        hdr = &doc->AuthorizationReq.Header;
    } else if (doc->ServiceDiscoveryReq_isUsed) {
        kind = S20_REQ_SERVICE_DISCOVERY;
        hdr = &doc->ServiceDiscoveryReq.Header;
    } else if (doc->ServiceDetailReq_isUsed) {
        kind = S20_REQ_SERVICE_DETAIL;
        hdr = &doc->ServiceDetailReq.Header;
    } else if (doc->ServiceSelectionReq_isUsed) {
        kind = S20_REQ_SERVICE_SELECTION;
        hdr = &doc->ServiceSelectionReq.Header;
    } else if (doc->ScheduleExchangeReq_isUsed) {
        kind = S20_REQ_SCHEDULE_EXCHANGE;
        hdr = &doc->ScheduleExchangeReq.Header;
    } else if (doc->PowerDeliveryReq_isUsed) {
        kind = S20_REQ_POWER_DELIVERY;
        hdr = &doc->PowerDeliveryReq.Header;
    } else if (doc->MeteringConfirmationReq_isUsed) {
        kind = S20_REQ_METERING_CONFIRMATION;
        hdr = &doc->MeteringConfirmationReq.Header;
    } else if (doc->SessionStopReq_isUsed) {
        kind = S20_REQ_SESSION_STOP;
        hdr = &doc->SessionStopReq.Header;
    } else if (doc->CertificateInstallationReq_isUsed) {
        kind = S20_REQ_CERT_INSTALL;
        hdr = &doc->CertificateInstallationReq.Header;
    } else if (doc->VehicleCheckInReq_isUsed) {
        kind = S20_REQ_VEHICLE_CHECKIN;
        hdr = &doc->VehicleCheckInReq.Header;
    } else if (doc->VehicleCheckOutReq_isUsed) {
        kind = S20_REQ_VEHICLE_CHECKOUT;
        hdr = &doc->VehicleCheckOutReq.Header;
    }
    if (kind == S20_REQ_NONE) {
        /* A decodable non-request document (loose Signature fragment etc.) is
         * treated like an undecodable frame: nothing sane to answer. */
        JPV2G_WARN("ISO20 CommonMessages document carries no request");
        return -EBADMSG;
    }
    JPV2G_INFO("ISO20 RX %s state=%s", s20_req_name(kind), jpv2g_secc20_state_name(s->state));

    /* Per-message session check (every message after SessionSetup): answer
     * FAILED_UnknownSession in the request's own Res, OUR id in the header,
     * then terminate. Pre-establishment the sequence gate speaks instead. */
    if (kind != S20_REQ_SESSION_SETUP && s->session_established &&
        !s20_session_id_matches(s, hdr->SessionID.bytes, hdr->SessionID.bytesLen)) {
        JPV2G_WARN("ISO20 %s: unknown SessionID", s20_req_name(kind));
        return s20_build_common_res(s, kind,
                                    (int)iso20_responseCodeType_FAILED_UnknownSession,
                                    out, out_cap, out_len);
    }

    if (!s20_state_accepts(s->state, kind)) {
        JPV2G_WARN("ISO20 sequence error: %s in state %s",
                   s20_req_name(kind), jpv2g_secc20_state_name(s->state));
        return s20_build_common_res(s, kind,
                                    (int)iso20_responseCodeType_FAILED_SequenceError,
                                    out, out_cap, out_len);
    }

    switch (kind) {
        case S20_REQ_SESSION_SETUP:
            return s20_handle_session_setup(s, doc, out, out_cap, out_len);
        case S20_REQ_AUTH_SETUP:
            return s20_handle_auth_setup(s, doc, out, out_cap, out_len);
        case S20_REQ_AUTHORIZATION:
            return s20_handle_authorization(s, doc, out, out_cap, out_len);
        case S20_REQ_SERVICE_DISCOVERY:
            return s20_handle_service_discovery(s, doc, out, out_cap, out_len);
        case S20_REQ_SERVICE_DETAIL:
            return s20_handle_service_detail(s, doc, out, out_cap, out_len);
        case S20_REQ_SERVICE_SELECTION:
            return s20_handle_service_selection(s, doc, out, out_cap, out_len);
        case S20_REQ_SCHEDULE_EXCHANGE:
            return s20_handle_schedule_exchange(s, doc, out, out_cap, out_len);
        case S20_REQ_POWER_DELIVERY:
            return s20_handle_power_delivery(s, doc, out, out_cap, out_len);
        case S20_REQ_SESSION_STOP:
            return s20_handle_session_stop(s, doc, out, out_cap, out_len, disp);
        default:
            /* Unreachable: the accept sets never admit the exotic kinds. */
            return s20_build_common_res(s, kind,
                                        (int)iso20_responseCodeType_FAILED_SequenceError,
                                        out, out_cap, out_len);
    }
}

static int s20_dispatch_dc(jpv2g_secc20_t *s,
                           const uint8_t *exi, size_t exi_len,
                           uint8_t *out, size_t out_cap, size_t *out_len) {
    struct iso20_dc_exiDocument *doc = s->cfg.dc_workspace;
    init_iso20_dc_exiDocument(doc);
    exi_bitstream_t bs;
    exi_bitstream_init(&bs, (uint8_t *)exi, exi_len, 0, NULL);
    if (decode_iso20_dc_exiDocument(&bs, doc) != 0) {
        JPV2G_WARN("ISO20 DC frame did not decode (len=%u)", (unsigned)exi_len);
        return -EBADMSG;
    }

    s20_req_t kind = S20_REQ_NONE;
    const struct iso20_dc_MessageHeaderType *hdr = NULL;
    if (doc->DC_ChargeParameterDiscoveryReq_isUsed) {
        kind = S20_REQ_DC_CPD;
        hdr = &doc->DC_ChargeParameterDiscoveryReq.Header;
    } else if (doc->DC_CableCheckReq_isUsed) {
        kind = S20_REQ_DC_CABLE_CHECK;
        hdr = &doc->DC_CableCheckReq.Header;
    } else if (doc->DC_PreChargeReq_isUsed) {
        kind = S20_REQ_DC_PRE_CHARGE;
        hdr = &doc->DC_PreChargeReq.Header;
    } else if (doc->DC_ChargeLoopReq_isUsed) {
        kind = S20_REQ_DC_CHARGE_LOOP;
        hdr = &doc->DC_ChargeLoopReq.Header;
    } else if (doc->DC_WeldingDetectionReq_isUsed) {
        kind = S20_REQ_DC_WELDING;
        hdr = &doc->DC_WeldingDetectionReq.Header;
    }
    if (kind == S20_REQ_NONE) {
        JPV2G_WARN("ISO20 DC document carries no request");
        return -EBADMSG;
    }
    JPV2G_INFO("ISO20 RX %s state=%s", s20_req_name(kind), jpv2g_secc20_state_name(s->state));

    if (s->session_established &&
        !s20_session_id_matches(s, hdr->SessionID.bytes, hdr->SessionID.bytesLen)) {
        JPV2G_WARN("ISO20 %s: unknown SessionID", s20_req_name(kind));
        return s20_build_dc_res(s, kind,
                                (int)iso20_dc_responseCodeType_FAILED_UnknownSession,
                                out, out_cap, out_len);
    }

    if (!s20_state_accepts(s->state, kind)) {
        JPV2G_WARN("ISO20 sequence error: %s in state %s",
                   s20_req_name(kind), jpv2g_secc20_state_name(s->state));
        return s20_build_dc_res(s, kind,
                                (int)iso20_dc_responseCodeType_FAILED_SequenceError,
                                out, out_cap, out_len);
    }

    switch (kind) {
        case S20_REQ_DC_CPD:
            return s20_handle_dc_cpd(s, doc, out, out_cap, out_len);
        case S20_REQ_DC_CABLE_CHECK:
            return s20_handle_dc_cable_check(s, doc, out, out_cap, out_len);
        case S20_REQ_DC_PRE_CHARGE:
            return s20_handle_dc_pre_charge(s, doc, out, out_cap, out_len);
        case S20_REQ_DC_CHARGE_LOOP:
            return s20_handle_dc_charge_loop(s, doc, out, out_cap, out_len);
        case S20_REQ_DC_WELDING:
            return s20_handle_dc_welding(s, doc, out, out_cap, out_len);
        default:
            return -EINVAL;
    }
}

/* ------------------------------------------------------------ public API */

int jpv2g_secc20_init(jpv2g_secc20_t *s, const jpv2g_secc20_config_t *cfg) {
    if (!s || !cfg) return -EINVAL;
    if (!cfg->common_workspace || !cfg->dc_workspace) return -EINVAL;
    memset(s, 0, sizeof(*s));
    s->cfg = *cfg;
    s->state = JPV2G_SECC20_STATE_SESSION_SETUP;
    return 0;
}

void jpv2g_secc20_reset(jpv2g_secc20_t *s) {
    if (!s) return;
    s->state = JPV2G_SECC20_STATE_SESSION_SETUP;
    memset(s->session_id, 0, sizeof(s->session_id));
    s->session_established = false;
    s->contactor_closed = false;
    s->cable_check_started = false;
    s->charge_loop_started = false;
    s->last_response_code = 0;
    /* SAP Res just went out: the SEQUENCE timer starts here (it must not
     * run before SupportedAppProtocolReq). */
    s->sequence_deadline_ms = jpv2g_now_monotonic_ms() + JPV2G_SECC20_SEQUENCE_TIMEOUT_MS;
    s->se_ongoing_deadline_ms = 0;
    s->eim_ongoing_deadline_ms = 0;
}

int jpv2g_secc20_handle_frame(jpv2g_secc20_t *s,
                              uint16_t payload_id,
                              const uint8_t *exi, size_t exi_len,
                              uint8_t *out, size_t out_cap, size_t *out_len,
                              uint16_t *out_payload_id,
                              jpv2g_secc20_disposition_t *disposition) {
    if (!s || !exi || exi_len == 0 || !out || !out_len || !out_payload_id || !disposition) {
        return -EINVAL;
    }
    if (s->state == JPV2G_SECC20_STATE_ENDED) return -EPROTO;

    *out_len = 0;
    *disposition = JPV2G_SECC20_CONTINUE;

    /* Blanket SEQUENCE timer (60 s, everywhere — plan 1.4): expiry sends
     * nothing and the caller tears down after the [V2G20-1643] hold. */
    const int64_t now = jpv2g_now_monotonic_ms();
    if (s->sequence_deadline_ms != 0 && now > s->sequence_deadline_ms) {
        JPV2G_WARN("ISO20 SEQUENCE timer expired in state %s",
                   jpv2g_secc20_state_name(s->state));
        s->state = JPV2G_SECC20_STATE_ENDED;
        return -ETIMEDOUT;
    }
    /* Request receipt stops the timer; it re-arms after the response. */
    s->sequence_deadline_ms = 0;

    int rc;
    if (payload_id == JPV2G_SECC20_PAYLOAD_MAINSTREAM) {
        *out_payload_id = JPV2G_SECC20_PAYLOAD_MAINSTREAM;
        rc = s20_dispatch_common(s, exi, exi_len, out, out_cap, out_len, disposition);
    } else if (payload_id == JPV2G_SECC20_PAYLOAD_DC) {
        *out_payload_id = JPV2G_SECC20_PAYLOAD_DC;
        rc = s20_dispatch_dc(s, exi, exi_len, out, out_cap, out_len);
    } else {
        return -EBADMSG;
    }
    if (rc != 0) return rc;

    /* Termination rule: ResponseCode >= FAILED ends the session after the
     * response is sent; WARNING_* never terminates. */
    if (*disposition == JPV2G_SECC20_CONTINUE && s->last_response_code >= S20_RC_FAILED) {
        *disposition = JPV2G_SECC20_DONE_FAILED;
    }
    if (*disposition != JPV2G_SECC20_CONTINUE) {
        s->state = JPV2G_SECC20_STATE_ENDED;
    } else {
        s->sequence_deadline_ms = jpv2g_now_monotonic_ms() + JPV2G_SECC20_SEQUENCE_TIMEOUT_MS;
    }
    return 0;
}

#else /* !JPV2G_ENABLE_ISO20 */

/* -ENOTSUP stubs, same shape as the no-mbedtls branch of tls.c: callers may
 * link and probe unconditionally; the module simply refuses to run. */

int jpv2g_secc20_init(jpv2g_secc20_t *s, const jpv2g_secc20_config_t *cfg) {
    (void)s; (void)cfg;
    return -ENOTSUP;
}

void jpv2g_secc20_reset(jpv2g_secc20_t *s) {
    (void)s;
}

int jpv2g_secc20_handle_frame(jpv2g_secc20_t *s,
                              uint16_t payload_id,
                              const uint8_t *exi, size_t exi_len,
                              uint8_t *out, size_t out_cap, size_t *out_len,
                              uint16_t *out_payload_id,
                              jpv2g_secc20_disposition_t *disposition) {
    (void)s; (void)payload_id; (void)exi; (void)exi_len;
    (void)out; (void)out_cap; (void)out_len; (void)out_payload_id; (void)disposition;
    return -ENOTSUP;
}

#endif /* JPV2G_ENABLE_ISO20 */

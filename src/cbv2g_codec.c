/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/cbv2g_codec.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "cbv2g/app_handshake/appHand_Decoder.h"
#include "cbv2g/app_handshake/appHand_Encoder.h"
#include "cbv2g/common/exi_bitstream.h"
#include "cbv2g/din/din_msgDefDecoder.h"
#include "cbv2g/din/din_msgDefEncoder.h"
#include "cbv2g/din/din_msgDefDatatypes.h"
#include "cbv2g/iso_2/iso2_msgDefDecoder.h"
#include "cbv2g/iso_2/iso2_msgDefEncoder.h"
#include "jpv2g/byte_utils.h"

#if defined(ESP_PLATFORM)
#include <esp_attr.h>
#endif
#ifndef EXT_RAM_ATTR
#define EXT_RAM_ATTR
#endif

static EXT_RAM_ATTR struct appHand_exiDocument g_app_doc_psram;
static EXT_RAM_ATTR struct iso2_exiDocument g_iso_doc_psram;
static EXT_RAM_ATTR struct din_exiDocument g_din_doc_psram;

static uint16_t copy_chars(char *dst, size_t dst_size, const char *src) {
    if (!dst || !dst_size) return 0;
    if (!src) {
        *dst = 0;
        return 0;
    }
    size_t len = strnlen(src, dst_size - 1);
    memcpy(dst, src, len);
    return (uint16_t)len;
}

static void set_header_session(struct iso2_MessageHeaderType *hdr, const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE]) {
    init_iso2_MessageHeaderType(hdr);
    if (session_id) {
        memcpy(hdr->SessionID.bytes, session_id, iso2_sessionIDType_BYTES_SIZE);
        hdr->SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE;
    } else {
        hdr->SessionID.bytesLen = 0;
    }
}

static void set_physical_value(struct iso2_PhysicalValueType *pv, iso2_unitSymbolType unit, int16_t value, int8_t multiplier);

int jpv2g_cbv2g_encode_sapp_req(const char *ns,
                                  uint32_t ver_major,
                                  uint32_t ver_minor,
                                  uint8_t schema_id,
                                  uint8_t priority,
                                  uint8_t *out,
                                  size_t out_len,
                                  size_t *written) {
    if (!ns || !out) return -EINVAL;
    struct appHand_exiDocument *doc = &g_app_doc_psram;
    init_appHand_exiDocument(doc);
    doc->supportedAppProtocolReq_isUsed = 1;
    init_appHand_supportedAppProtocolReq(&doc->supportedAppProtocolReq);
    doc->supportedAppProtocolReq.AppProtocol.arrayLen = 1;
    struct appHand_AppProtocolType *ap = &doc->supportedAppProtocolReq.AppProtocol.array[0];
    init_appHand_AppProtocolType(ap);
    size_t ns_len = strnlen(ns, appHand_ProtocolNamespace_CHARACTER_SIZE - 1);
    memcpy(ap->ProtocolNamespace.characters, ns, ns_len);
    ap->ProtocolNamespace.charactersLen = (uint16_t)ns_len;
    ap->VersionNumberMajor = ver_major;
    ap->VersionNumberMinor = ver_minor;
    ap->SchemaID = schema_id;
    ap->Priority = priority;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_appHand_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_sapp_res(const uint8_t *buf, size_t len, struct appHand_supportedAppProtocolRes *res) {
    if (!buf || !res) return -EINVAL;
    struct appHand_exiDocument *doc = &g_app_doc_psram;
    init_appHand_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_appHand_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->supportedAppProtocolRes_isUsed) return -EBADMSG;
    *res = doc->supportedAppProtocolRes;
    return 0;
}

int jpv2g_cbv2g_encode_sapp_res(uint8_t schema_id,
                                  appHand_responseCodeType code,
                                  uint8_t *out,
                                  size_t out_len,
                                  size_t *written) {
    if (!out) return -EINVAL;
    struct appHand_exiDocument *doc = &g_app_doc_psram;
    init_appHand_exiDocument(doc);
    doc->supportedAppProtocolRes_isUsed = 1;
    init_appHand_supportedAppProtocolRes(&doc->supportedAppProtocolRes);
    doc->supportedAppProtocolRes.ResponseCode = code;
    doc->supportedAppProtocolRes.SchemaID = schema_id;
    doc->supportedAppProtocolRes.SchemaID_isUsed = 1;
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_appHand_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_encode_session_setup_req(const uint8_t evcc_id[iso2_evccIDType_BYTES_SIZE],
                                           uint8_t *out,
                                           size_t out_len,
                                           size_t *written) {
    if (!evcc_id || !out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    init_iso2_MessageHeaderType(&doc->V2G_Message.Header);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.SessionSetupReq_isUsed = 1;
    init_iso2_SessionSetupReqType(&doc->V2G_Message.Body.SessionSetupReq);
    memcpy(doc->V2G_Message.Body.SessionSetupReq.EVCCID.bytes, evcc_id, iso2_evccIDType_BYTES_SIZE);
    doc->V2G_Message.Body.SessionSetupReq.EVCCID.bytesLen = iso2_evccIDType_BYTES_SIZE;
    doc->V2G_Message.Header.SessionID.bytesLen = 0; /* new session */

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_session_setup_req(const uint8_t *buf, size_t len, struct iso2_SessionSetupReqType *req) {
    if (!buf || !req) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.SessionSetupReq_isUsed) return -EBADMSG;
    *req = doc->V2G_Message.Body.SessionSetupReq;
    return 0;
}

int jpv2g_cbv2g_encode_session_setup_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                           const char *evse_id,
                                           iso2_responseCodeType code,
                                           uint8_t *out,
                                           size_t out_len,
                                           size_t *written) {
    if (!session_id || !evse_id || !out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    init_iso2_MessageHeaderType(&doc->V2G_Message.Header);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    memcpy(doc->V2G_Message.Header.SessionID.bytes, session_id, iso2_sessionIDType_BYTES_SIZE);
    doc->V2G_Message.Header.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE;

    doc->V2G_Message.Body.SessionSetupRes_isUsed = 1;
    init_iso2_SessionSetupResType(&doc->V2G_Message.Body.SessionSetupRes);
    doc->V2G_Message.Body.SessionSetupRes.ResponseCode = code;
    size_t evse_len = strnlen(evse_id, iso2_EVSEID_CHARACTER_SIZE - 1);
    memcpy(doc->V2G_Message.Body.SessionSetupRes.EVSEID.characters, evse_id, evse_len);
    doc->V2G_Message.Body.SessionSetupRes.EVSEID.charactersLen = (uint16_t)evse_len;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_session_setup_res(const uint8_t *buf, size_t len, struct iso2_SessionSetupResType *res, uint8_t session_id_out[iso2_sessionIDType_BYTES_SIZE]) {
    if (!buf || !res || !session_id_out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    memcpy(session_id_out, doc->V2G_Message.Header.SessionID.bytes, iso2_sessionIDType_BYTES_SIZE);
    if (!doc->V2G_Message.Body.SessionSetupRes_isUsed) return -EBADMSG;
    *res = doc->V2G_Message.Body.SessionSetupRes;
    return 0;
}

static void set_default_meter_info(struct iso2_MeterInfoType *meter, const char *id) {
    init_iso2_MeterInfoType(meter);
    meter->MeterID.charactersLen = copy_chars(meter->MeterID.characters, iso2_MeterID_CHARACTER_SIZE, id ? id : "METER01");
    meter->MeterReading = 0;
    meter->MeterReading_isUsed = 1;
    meter->MeterStatus = 0;
    meter->MeterStatus_isUsed = 1;
}

static void set_default_ac_status(struct iso2_AC_EVSEStatusType *status) {
    init_iso2_AC_EVSEStatusType(status);
    status->NotificationMaxDelay = 1;
    status->EVSENotification = iso2_EVSENotificationType_None;
    status->RCD = 0;
}

static void set_default_dc_ev_status(struct iso2_DC_EVStatusType *status) {
    init_iso2_DC_EVStatusType(status);
    status->EVReady = 1;
    status->EVErrorCode = iso2_DC_EVErrorCodeType_NO_ERROR;
    status->EVRESSSOC = 50;
}

static void set_default_dc_evse_status(struct iso2_DC_EVSEStatusType *status) {
    init_iso2_DC_EVSEStatusType(status);
    status->NotificationMaxDelay = 1;
    status->EVSENotification = iso2_EVSENotificationType_None;
    status->EVSEStatusCode = iso2_DC_EVSEStatusCodeType_EVSE_Ready;
    status->EVSEIsolationStatus_isUsed = 1;
    status->EVSEIsolationStatus = iso2_isolationLevelType_Valid;
}

static void set_default_iso_dc_charge_params(struct iso2_DC_EVSEChargeParameterType *params) {
    if (!params) return;
    init_iso2_DC_EVSEChargeParameterType(params);
    set_default_dc_evse_status(&params->DC_EVSEStatus);
    set_physical_value(&params->EVSEMaximumCurrentLimit, iso2_unitSymbolType_A, 200, 0);
    set_physical_value(&params->EVSEMaximumPowerLimit, iso2_unitSymbolType_W, 240, 3);
    set_physical_value(&params->EVSEMaximumVoltageLimit, iso2_unitSymbolType_V, 1000, 0);
    set_physical_value(&params->EVSEMinimumCurrentLimit, iso2_unitSymbolType_A, 0, 0);
    set_physical_value(&params->EVSEMinimumVoltageLimit, iso2_unitSymbolType_V, 200, 0);
    set_physical_value(&params->EVSEPeakCurrentRipple, iso2_unitSymbolType_A, 1, 0);
    params->EVSECurrentRegulationTolerance_isUsed = 0;
    params->EVSEEnergyToBeDelivered_isUsed = 0;
}

static void set_default_iso_sa_schedule(struct iso2_ChargeParameterDiscoveryResType *res) {
    if (!res) return;
    res->SASchedules_isUsed = 0;
    res->SAScheduleList_isUsed = 1;
    init_iso2_SAScheduleListType(&res->SAScheduleList);
    res->SAScheduleList.SAScheduleTuple.arrayLen = 1;
    struct iso2_SAScheduleTupleType *tuple = &res->SAScheduleList.SAScheduleTuple.array[0];
    init_iso2_SAScheduleTupleType(tuple);
    tuple->SAScheduleTupleID = 1;
    tuple->SalesTariff_isUsed = 0;

    init_iso2_PMaxScheduleType(&tuple->PMaxSchedule);
    tuple->PMaxSchedule.PMaxScheduleEntry.arrayLen = 1;
    struct iso2_PMaxScheduleEntryType *entry = &tuple->PMaxSchedule.PMaxScheduleEntry.array[0];
    init_iso2_PMaxScheduleEntryType(entry);
    init_iso2_RelativeTimeIntervalType(&entry->RelativeTimeInterval);
    entry->RelativeTimeInterval.start = 0;
    entry->RelativeTimeInterval.duration = 24U * 3600U;
    entry->RelativeTimeInterval.duration_isUsed = 1;
    entry->RelativeTimeInterval_isUsed = 1;
    set_physical_value(&entry->PMax, iso2_unitSymbolType_W, 60, 3);
}

static bool iso_etm_is_dc(iso2_EnergyTransferModeType etm) {
    return etm == iso2_EnergyTransferModeType_DC_core ||
           etm == iso2_EnergyTransferModeType_DC_extended ||
           etm == iso2_EnergyTransferModeType_DC_combo_core ||
           etm == iso2_EnergyTransferModeType_DC_unique;
}

static void set_din_header_session(struct din_MessageHeaderType *hdr, const uint8_t session_id[din_sessionIDType_BYTES_SIZE]) {
    init_din_MessageHeaderType(hdr);
    if (session_id) {
        memcpy(hdr->SessionID.bytes, session_id, din_sessionIDType_BYTES_SIZE);
        hdr->SessionID.bytesLen = din_sessionIDType_BYTES_SIZE;
    } else {
        hdr->SessionID.bytesLen = 0;
    }
}

static void set_din_physical_value(struct din_PhysicalValueType *pv, din_unitSymbolType unit, int16_t value, int8_t mult) {
    if (!pv) return;
    init_din_PhysicalValueType(pv);
    pv->Unit = unit;
    pv->Unit_isUsed = 1;
    pv->Value = value;
    pv->Multiplier = mult;
}

static void set_din_default_dc_evse_status(struct din_DC_EVSEStatusType *status) {
    if (!status) return;
    init_din_DC_EVSEStatusType(status);
    status->NotificationMaxDelay = 1;
    status->EVSENotification = din_EVSENotificationType_None;
    status->EVSEStatusCode = din_DC_EVSEStatusCodeType_EVSE_Ready;
    status->EVSEIsolationStatus_isUsed = 0;
}

static void set_din_default_ac_status(struct din_AC_EVSEStatusType *status) {
    if (!status) return;
    init_din_AC_EVSEStatusType(status);
    status->NotificationMaxDelay = 1;
    status->EVSENotification = din_EVSENotificationType_None;
    status->RCD = 0;
}

static void set_din_default_payment_options(struct din_PaymentOptionsType *opts, din_paymentOptionType preferred) {
    if (!opts) return;
    init_din_PaymentOptionsType(opts);
    opts->PaymentOption.arrayLen = 0;
    opts->PaymentOption.array[opts->PaymentOption.arrayLen++] = preferred;
}

static void set_din_service_tag(struct din_ServiceTagType *tag, uint16_t service_id, const char *name, din_serviceCategoryType category) {
    if (!tag) return;
    init_din_ServiceTagType(tag);
    tag->ServiceID = service_id;
    tag->ServiceCategory = category;
    if (name && *name) {
        tag->ServiceName.charactersLen = copy_chars(tag->ServiceName.characters, din_ServiceName_CHARACTER_SIZE, name);
        tag->ServiceName_isUsed = 1;
    } else {
        tag->ServiceName_isUsed = 0;
    }
    tag->ServiceScope_isUsed = 0;
}

static void set_din_default_dc_charge_params(struct din_DC_EVSEChargeParameterType *params) {
    if (!params) return;
    init_din_DC_EVSEChargeParameterType(params);
    set_din_default_dc_evse_status(&params->DC_EVSEStatus);
    set_din_physical_value(&params->EVSEMaximumCurrentLimit, din_unitSymbolType_A, 200, 0);
    set_din_physical_value(&params->EVSEMaximumVoltageLimit, din_unitSymbolType_V, 1000, 0);
    params->EVSEMaximumPowerLimit_isUsed = 1;
    set_din_physical_value(&params->EVSEMaximumPowerLimit, din_unitSymbolType_W, 240, 3);
    set_din_physical_value(&params->EVSEMinimumCurrentLimit, din_unitSymbolType_A, 0, 0);
    set_din_physical_value(&params->EVSEMinimumVoltageLimit, din_unitSymbolType_V, 200, 0);
    set_din_physical_value(&params->EVSEPeakCurrentRipple, din_unitSymbolType_A, 1, 0);
    params->EVSECurrentRegulationTolerance_isUsed = 0;
    params->EVSEEnergyToBeDelivered_isUsed = 0;
}

static void set_bytes_field(uint8_t *dst, uint16_t *len_field, size_t max, const uint8_t *src, size_t src_len) {
    if (!dst || !len_field || !max) return;
    if (!src || src_len == 0) {
        *len_field = 0;
        return;
    }
    size_t len = src_len > max ? max : src_len;
    memcpy(dst, src, len);
    *len_field = (uint16_t)len;
}

int jpv2g_cbv2g_encode_service_discovery_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE], uint8_t *out, size_t out_len, size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.ServiceDiscoveryReq_isUsed = 1;
    init_iso2_ServiceDiscoveryReqType(&doc->V2G_Message.Body.ServiceDiscoveryReq);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_service_discovery_req(const uint8_t *buf, size_t len, struct iso2_ServiceDiscoveryReqType *req) {
    if (!buf || !req) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.ServiceDiscoveryReq_isUsed) return -EBADMSG;
    *req = doc->V2G_Message.Body.ServiceDiscoveryReq;
    return 0;
}

int jpv2g_cbv2g_encode_service_discovery_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                               iso2_responseCodeType code,
                                               iso2_paymentOptionType payment,
                                               iso2_EnergyTransferModeType etm,
                                               uint16_t service_id,
                                               const char *service_name,
                                               int free_service,
                                               uint8_t *out,
                                               size_t out_len,
                                               size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.ServiceDiscoveryRes_isUsed = 1;
    init_iso2_ServiceDiscoveryResType(&doc->V2G_Message.Body.ServiceDiscoveryRes);
    doc->V2G_Message.Body.ServiceDiscoveryRes.ResponseCode = code;
    /* Payment option list */
    init_iso2_PaymentOptionListType(&doc->V2G_Message.Body.ServiceDiscoveryRes.PaymentOptionList);
    doc->V2G_Message.Body.ServiceDiscoveryRes.PaymentOptionList.PaymentOption.arrayLen = 1;
    doc->V2G_Message.Body.ServiceDiscoveryRes.PaymentOptionList.PaymentOption.array[0] = payment;
    /* Charge service */
    init_iso2_ChargeServiceType(&doc->V2G_Message.Body.ServiceDiscoveryRes.ChargeService);
    doc->V2G_Message.Body.ServiceDiscoveryRes.ChargeService.ServiceID = service_id;
    doc->V2G_Message.Body.ServiceDiscoveryRes.ChargeService.ServiceCategory = iso2_serviceCategoryType_EVCharging;
    doc->V2G_Message.Body.ServiceDiscoveryRes.ChargeService.FreeService = free_service ? 1 : 0;
    init_iso2_SupportedEnergyTransferModeType(&doc->V2G_Message.Body.ServiceDiscoveryRes.ChargeService.SupportedEnergyTransferMode);
    doc->V2G_Message.Body.ServiceDiscoveryRes.ChargeService.SupportedEnergyTransferMode.EnergyTransferMode.arrayLen = 1;
    doc->V2G_Message.Body.ServiceDiscoveryRes.ChargeService.SupportedEnergyTransferMode.EnergyTransferMode.array[0] = etm;
    if (service_name) {
        size_t sn_len = strnlen(service_name, iso2_ServiceName_CHARACTER_SIZE - 1);
        memcpy(doc->V2G_Message.Body.ServiceDiscoveryRes.ChargeService.ServiceName.characters, service_name, sn_len);
        doc->V2G_Message.Body.ServiceDiscoveryRes.ChargeService.ServiceName.charactersLen = (uint16_t)sn_len;
        doc->V2G_Message.Body.ServiceDiscoveryRes.ChargeService.ServiceName_isUsed = 1;
    }
    /* No additional ServiceList */
    doc->V2G_Message.Body.ServiceDiscoveryRes.ServiceList_isUsed = 0;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_service_discovery_res(const uint8_t *buf, size_t len, struct iso2_ServiceDiscoveryResType *res) {
    if (!buf || !res) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.ServiceDiscoveryRes_isUsed) return -EBADMSG;
    *res = doc->V2G_Message.Body.ServiceDiscoveryRes;
    return 0;
}

int jpv2g_cbv2g_encode_payment_service_selection_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                                       iso2_paymentOptionType payment,
                                                       uint8_t *out,
                                                       size_t out_len,
                                                       size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.PaymentServiceSelectionReq_isUsed = 1;
    init_iso2_PaymentServiceSelectionReqType(&doc->V2G_Message.Body.PaymentServiceSelectionReq);
    doc->V2G_Message.Body.PaymentServiceSelectionReq.SelectedPaymentOption = payment;
    init_iso2_SelectedServiceListType(&doc->V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList);
    doc->V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.arrayLen = 1;
    init_iso2_SelectedServiceType(&doc->V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.array[0]);
    doc->V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.array[0].ServiceID = 1;
    doc->V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.array[0].ParameterSetID_isUsed = 0;
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_payment_service_selection_req(const uint8_t *buf, size_t len, struct iso2_PaymentServiceSelectionReqType *req) {
    if (!buf || !req) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.PaymentServiceSelectionReq_isUsed) return -EBADMSG;
    *req = doc->V2G_Message.Body.PaymentServiceSelectionReq;
    return 0;
}

int jpv2g_cbv2g_encode_payment_service_selection_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                                       iso2_responseCodeType code,
                                                       uint8_t *out,
                                                       size_t out_len,
                                                       size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.PaymentServiceSelectionRes_isUsed = 1;
    init_iso2_PaymentServiceSelectionResType(&doc->V2G_Message.Body.PaymentServiceSelectionRes);
    doc->V2G_Message.Body.PaymentServiceSelectionRes.ResponseCode = code;
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_payment_service_selection_res(const uint8_t *buf, size_t len, struct iso2_PaymentServiceSelectionResType *res) {
    if (!buf || !res) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.PaymentServiceSelectionRes_isUsed) return -EBADMSG;
    *res = doc->V2G_Message.Body.PaymentServiceSelectionRes;
    return 0;
}

static void set_physical_value(struct iso2_PhysicalValueType *pv, iso2_unitSymbolType unit, int16_t value, int8_t multiplier) {
    if (!pv) return;
    init_iso2_PhysicalValueType(pv);
    pv->Unit = unit;
    pv->Value = value;
    pv->Multiplier = multiplier;
}

int jpv2g_cbv2g_encode_charge_parameter_discovery_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                                        iso2_EnergyTransferModeType etm,
                                                        uint8_t *out,
                                                        size_t out_len,
                                                        size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed = 1;
    init_iso2_ChargeParameterDiscoveryReqType(&doc->V2G_Message.Body.ChargeParameterDiscoveryReq);
    doc->V2G_Message.Body.ChargeParameterDiscoveryReq.RequestedEnergyTransferMode = etm;
    init_iso2_AC_EVChargeParameterType(&doc->V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVChargeParameter);
    doc->V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVChargeParameter_isUsed = 1;
    set_physical_value(&doc->V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVChargeParameter.EAmount, iso2_unitSymbolType_Wh, 5000, 0);
    set_physical_value(&doc->V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVChargeParameter.EVMaxVoltage, iso2_unitSymbolType_V, 400, 0);
    set_physical_value(&doc->V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVChargeParameter.EVMaxCurrent, iso2_unitSymbolType_A, 32, 0);
    set_physical_value(&doc->V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVChargeParameter.EVMinCurrent, iso2_unitSymbolType_A, 6, 0);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_charge_parameter_discovery_req(const uint8_t *buf, size_t len, struct iso2_ChargeParameterDiscoveryReqType *req) {
    if (!buf || !req) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed) return -EBADMSG;
    *req = doc->V2G_Message.Body.ChargeParameterDiscoveryReq;
    return 0;
}

int jpv2g_cbv2g_encode_charge_parameter_discovery_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                                        iso2_responseCodeType code,
                                                        iso2_EnergyTransferModeType etm,
                                                        uint8_t *out,
                                                        size_t out_len,
                                                        size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed = 1;
    init_iso2_ChargeParameterDiscoveryResType(&doc->V2G_Message.Body.ChargeParameterDiscoveryRes);
    doc->V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode = code;
    doc->V2G_Message.Body.ChargeParameterDiscoveryRes.EVSEProcessing = iso2_EVSEProcessingType_Finished;
    struct iso2_ChargeParameterDiscoveryResType *res = &doc->V2G_Message.Body.ChargeParameterDiscoveryRes;
    if (code == iso2_responseCodeType_OK) {
        set_default_iso_sa_schedule(res);
    } else {
        res->SAScheduleList_isUsed = 0;
        res->SASchedules_isUsed = 0;
    }
    res->EVSEChargeParameter_isUsed = 0;
    if (iso_etm_is_dc(etm)) {
        res->AC_EVSEChargeParameter_isUsed = 0;
        res->DC_EVSEChargeParameter_isUsed = 1;
        set_default_iso_dc_charge_params(&res->DC_EVSEChargeParameter);
    } else {
        res->DC_EVSEChargeParameter_isUsed = 0;
        res->AC_EVSEChargeParameter_isUsed = 1;
        init_iso2_AC_EVSEChargeParameterType(&res->AC_EVSEChargeParameter);
        set_default_ac_status(&res->AC_EVSEChargeParameter.AC_EVSEStatus);
        set_physical_value(&res->AC_EVSEChargeParameter.EVSENominalVoltage, iso2_unitSymbolType_V, 400, 0);
        set_physical_value(&res->AC_EVSEChargeParameter.EVSEMaxCurrent, iso2_unitSymbolType_A, 32, 0);
    }

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_encode_charge_parameter_discovery_res_payload(
    const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
    const struct iso2_ChargeParameterDiscoveryResType *payload,
    uint8_t *out,
    size_t out_len,
    size_t *written) {
    if (!out || !payload) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed = 1;
    doc->V2G_Message.Body.ChargeParameterDiscoveryRes = *payload;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_charge_parameter_discovery_res(const uint8_t *buf, size_t len, struct iso2_ChargeParameterDiscoveryResType *res) {
    if (!buf || !res) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed) return -EBADMSG;
    *res = doc->V2G_Message.Body.ChargeParameterDiscoveryRes;
    return 0;
}

int jpv2g_cbv2g_encode_cable_check_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                         const struct iso2_CableCheckReqType *payload,
                                         uint8_t *out,
                                         size_t out_len,
                                         size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.CableCheckReq_isUsed = 1;
    init_iso2_CableCheckReqType(&doc->V2G_Message.Body.CableCheckReq);
    if (payload) {
        doc->V2G_Message.Body.CableCheckReq = *payload;
    } else {
        set_default_dc_ev_status(&doc->V2G_Message.Body.CableCheckReq.DC_EVStatus);
    }
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_cable_check_req(const uint8_t *buf, size_t len, struct iso2_CableCheckReqType *req) {
    if (!buf || !req) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.CableCheckReq_isUsed) return -EBADMSG;
    *req = doc->V2G_Message.Body.CableCheckReq;
    return 0;
}

int jpv2g_cbv2g_encode_cable_check_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                         iso2_responseCodeType code,
                                         iso2_EVSEProcessingType processing,
                                         const struct iso2_CableCheckResType *payload,
                                         uint8_t *out,
                                         size_t out_len,
                                         size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.CableCheckRes_isUsed = 1;
    init_iso2_CableCheckResType(&doc->V2G_Message.Body.CableCheckRes);
    if (payload) {
        doc->V2G_Message.Body.CableCheckRes = *payload;
    } else {
        set_default_dc_evse_status(&doc->V2G_Message.Body.CableCheckRes.DC_EVSEStatus);
        doc->V2G_Message.Body.CableCheckRes.EVSEProcessing = processing;
    }
    doc->V2G_Message.Body.CableCheckRes.ResponseCode = code;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_cable_check_res(const uint8_t *buf, size_t len, struct iso2_CableCheckResType *res) {
    if (!buf || !res) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.CableCheckRes_isUsed) return -EBADMSG;
    *res = doc->V2G_Message.Body.CableCheckRes;
    return 0;
}

int jpv2g_cbv2g_encode_service_detail_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                            uint16_t service_id,
                                            uint8_t *out,
                                            size_t out_len,
                                            size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.ServiceDetailReq_isUsed = 1;
    init_iso2_ServiceDetailReqType(&doc->V2G_Message.Body.ServiceDetailReq);
    doc->V2G_Message.Body.ServiceDetailReq.ServiceID = service_id;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_service_detail_req(const uint8_t *buf, size_t len, struct iso2_ServiceDetailReqType *req) {
    if (!buf || !req) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.ServiceDetailReq_isUsed) return -EBADMSG;
    *req = doc->V2G_Message.Body.ServiceDetailReq;
    return 0;
}

int jpv2g_cbv2g_encode_service_detail_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                            iso2_responseCodeType code,
                                            uint16_t service_id,
                                            const struct iso2_ServiceParameterListType *params,
                                            uint8_t *out,
                                            size_t out_len,
                                            size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.ServiceDetailRes_isUsed = 1;
    init_iso2_ServiceDetailResType(&doc->V2G_Message.Body.ServiceDetailRes);
    doc->V2G_Message.Body.ServiceDetailRes.ResponseCode = code;
    doc->V2G_Message.Body.ServiceDetailRes.ServiceID = service_id;
    if (params) {
        doc->V2G_Message.Body.ServiceDetailRes.ServiceParameterList = *params;
        doc->V2G_Message.Body.ServiceDetailRes.ServiceParameterList_isUsed = 1;
    }
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_service_detail_res(const uint8_t *buf, size_t len, struct iso2_ServiceDetailResType *res) {
    if (!buf || !res) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.ServiceDetailRes_isUsed) return -EBADMSG;
    *res = doc->V2G_Message.Body.ServiceDetailRes;
    return 0;
}

int jpv2g_cbv2g_encode_payment_details_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                             const char *emaid,
                                             const struct iso2_CertificateChainType *chain,
                                             uint8_t *out,
                                             size_t out_len,
                                             size_t *written) {
    if (!out || !emaid) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.PaymentDetailsReq_isUsed = 1;
    init_iso2_PaymentDetailsReqType(&doc->V2G_Message.Body.PaymentDetailsReq);
    doc->V2G_Message.Body.PaymentDetailsReq.eMAID.charactersLen =
        copy_chars(doc->V2G_Message.Body.PaymentDetailsReq.eMAID.characters, iso2_eMAID_CHARACTER_SIZE, emaid);
    if (chain) {
        doc->V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain = *chain;
    } else {
        init_iso2_CertificateChainType(&doc->V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain);
        doc->V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.Certificate.bytesLen = 0;
        doc->V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates_isUsed = 0;
    }

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_payment_details_req(const uint8_t *buf, size_t len, struct iso2_PaymentDetailsReqType *req) {
    if (!buf || !req) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.PaymentDetailsReq_isUsed) return -EBADMSG;
    *req = doc->V2G_Message.Body.PaymentDetailsReq;
    return 0;
}

int jpv2g_cbv2g_encode_payment_details_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                             iso2_responseCodeType code,
                                             const uint8_t *gen_challenge,
                                             size_t gen_challenge_len,
                                             int64_t evse_timestamp,
                                             uint8_t *out,
                                             size_t out_len,
                                             size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.PaymentDetailsRes_isUsed = 1;
    init_iso2_PaymentDetailsResType(&doc->V2G_Message.Body.PaymentDetailsRes);
    doc->V2G_Message.Body.PaymentDetailsRes.ResponseCode = code;
    if (gen_challenge && gen_challenge_len > 0) {
        set_bytes_field(doc->V2G_Message.Body.PaymentDetailsRes.GenChallenge.bytes,
                        &doc->V2G_Message.Body.PaymentDetailsRes.GenChallenge.bytesLen,
                        iso2_genChallengeType_BYTES_SIZE,
                        gen_challenge,
                        gen_challenge_len);
    } else {
        /* Generate a random short challenge for robustness */
        uint8_t tmp[iso2_genChallengeType_BYTES_SIZE];
        size_t fill = sizeof(tmp);
        if (jpv2g_random_bytes(tmp, fill) != 0) fill = 0;
        set_bytes_field(doc->V2G_Message.Body.PaymentDetailsRes.GenChallenge.bytes,
                        &doc->V2G_Message.Body.PaymentDetailsRes.GenChallenge.bytesLen,
                        iso2_genChallengeType_BYTES_SIZE,
                        tmp,
                        fill);
    }
    doc->V2G_Message.Body.PaymentDetailsRes.EVSETimeStamp = evse_timestamp;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_payment_details_res(const uint8_t *buf, size_t len, struct iso2_PaymentDetailsResType *res) {
    if (!buf || !res) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.PaymentDetailsRes_isUsed) return -EBADMSG;
    *res = doc->V2G_Message.Body.PaymentDetailsRes;
    return 0;
}

int jpv2g_cbv2g_encode_authorization_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                           const uint8_t *gen_challenge,
                                           size_t gen_challenge_len,
                                           uint8_t *out,
                                           size_t out_len,
                                           size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.AuthorizationReq_isUsed = 1;
    init_iso2_AuthorizationReqType(&doc->V2G_Message.Body.AuthorizationReq);
    if (gen_challenge && gen_challenge_len > 0) {
        set_bytes_field(doc->V2G_Message.Body.AuthorizationReq.GenChallenge.bytes,
                        &doc->V2G_Message.Body.AuthorizationReq.GenChallenge.bytesLen,
                        iso2_genChallengeType_BYTES_SIZE,
                        gen_challenge,
                        gen_challenge_len);
        doc->V2G_Message.Body.AuthorizationReq.GenChallenge_isUsed = 1;
    } else {
        doc->V2G_Message.Body.AuthorizationReq.GenChallenge_isUsed = 0;
    }

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_authorization_req(const uint8_t *buf, size_t len, struct iso2_AuthorizationReqType *req) {
    if (!buf || !req) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.AuthorizationReq_isUsed) return -EBADMSG;
    *req = doc->V2G_Message.Body.AuthorizationReq;
    return 0;
}

int jpv2g_cbv2g_encode_authorization_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                           iso2_responseCodeType code,
                                           iso2_EVSEProcessingType processing,
                                           uint8_t *out,
                                           size_t out_len,
                                           size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.AuthorizationRes_isUsed = 1;
    init_iso2_AuthorizationResType(&doc->V2G_Message.Body.AuthorizationRes);
    doc->V2G_Message.Body.AuthorizationRes.ResponseCode = code;
    doc->V2G_Message.Body.AuthorizationRes.EVSEProcessing = processing;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_authorization_res(const uint8_t *buf, size_t len, struct iso2_AuthorizationResType *res) {
    if (!buf || !res) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.AuthorizationRes_isUsed) return -EBADMSG;
    *res = doc->V2G_Message.Body.AuthorizationRes;
    return 0;
}

int jpv2g_cbv2g_encode_power_delivery_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                            iso2_chargeProgressType progress,
                                            uint8_t sa_id,
                                            const struct iso2_PowerDeliveryReqType *payload,
                                            uint8_t *out,
                                            size_t out_len,
                                            size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.PowerDeliveryReq_isUsed = 1;
    init_iso2_PowerDeliveryReqType(&doc->V2G_Message.Body.PowerDeliveryReq);
    if (payload) {
        doc->V2G_Message.Body.PowerDeliveryReq = *payload;
    }
    doc->V2G_Message.Body.PowerDeliveryReq.ChargeProgress = progress;
    doc->V2G_Message.Body.PowerDeliveryReq.SAScheduleTupleID = sa_id;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_power_delivery_req(const uint8_t *buf, size_t len, struct iso2_PowerDeliveryReqType *req) {
    if (!buf || !req) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.PowerDeliveryReq_isUsed) return -EBADMSG;
    *req = doc->V2G_Message.Body.PowerDeliveryReq;
    return 0;
}

int jpv2g_cbv2g_encode_power_delivery_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                            iso2_responseCodeType code,
                                            const struct iso2_PowerDeliveryResType *payload,
                                            uint8_t *out,
                                            size_t out_len,
                                            size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.PowerDeliveryRes_isUsed = 1;
    init_iso2_PowerDeliveryResType(&doc->V2G_Message.Body.PowerDeliveryRes);
    if (payload) {
        doc->V2G_Message.Body.PowerDeliveryRes = *payload;
    } else {
        set_default_ac_status(&doc->V2G_Message.Body.PowerDeliveryRes.AC_EVSEStatus);
        doc->V2G_Message.Body.PowerDeliveryRes.AC_EVSEStatus_isUsed = 1;
    }
    doc->V2G_Message.Body.PowerDeliveryRes.ResponseCode = code;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_power_delivery_res(const uint8_t *buf, size_t len, struct iso2_PowerDeliveryResType *res) {
    if (!buf || !res) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.PowerDeliveryRes_isUsed) return -EBADMSG;
    *res = doc->V2G_Message.Body.PowerDeliveryRes;
    return 0;
}

int jpv2g_cbv2g_encode_charging_status_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                             uint8_t *out,
                                             size_t out_len,
                                             size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.ChargingStatusReq_isUsed = 1;
    init_iso2_ChargingStatusReqType(&doc->V2G_Message.Body.ChargingStatusReq);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_charging_status_req(const uint8_t *buf, size_t len, struct iso2_ChargingStatusReqType *req) {
    if (!buf || !req) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.ChargingStatusReq_isUsed) return -EBADMSG;
    *req = doc->V2G_Message.Body.ChargingStatusReq;
    return 0;
}

int jpv2g_cbv2g_encode_charging_status_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                             iso2_responseCodeType code,
                                             const char *evse_id,
                                             uint8_t sa_id,
                                             const struct iso2_ChargingStatusResType *payload,
                                             uint8_t *out,
                                             size_t out_len,
                                             size_t *written) {
    if (!out || !evse_id) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.ChargingStatusRes_isUsed = 1;
    init_iso2_ChargingStatusResType(&doc->V2G_Message.Body.ChargingStatusRes);
    if (payload) {
        doc->V2G_Message.Body.ChargingStatusRes = *payload;
    } else {
        set_default_ac_status(&doc->V2G_Message.Body.ChargingStatusRes.AC_EVSEStatus);
        doc->V2G_Message.Body.ChargingStatusRes.EVSEMaxCurrent_isUsed = 0;
        doc->V2G_Message.Body.ChargingStatusRes.MeterInfo_isUsed = 0;
        doc->V2G_Message.Body.ChargingStatusRes.ReceiptRequired_isUsed = 0;
    }
    doc->V2G_Message.Body.ChargingStatusRes.ResponseCode = code;
    doc->V2G_Message.Body.ChargingStatusRes.SAScheduleTupleID = sa_id;
    doc->V2G_Message.Body.ChargingStatusRes.EVSEID.charactersLen =
        copy_chars(doc->V2G_Message.Body.ChargingStatusRes.EVSEID.characters, iso2_EVSEID_CHARACTER_SIZE, evse_id);

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_charging_status_res(const uint8_t *buf, size_t len, struct iso2_ChargingStatusResType *res) {
    if (!buf || !res) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.ChargingStatusRes_isUsed) return -EBADMSG;
    *res = doc->V2G_Message.Body.ChargingStatusRes;
    return 0;
}

int jpv2g_cbv2g_encode_current_demand_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                            const struct iso2_CurrentDemandReqType *payload,
                                            uint8_t *out,
                                            size_t out_len,
                                            size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.CurrentDemandReq_isUsed = 1;
    init_iso2_CurrentDemandReqType(&doc->V2G_Message.Body.CurrentDemandReq);
    if (payload) {
        doc->V2G_Message.Body.CurrentDemandReq = *payload;
    } else {
        set_default_dc_ev_status(&doc->V2G_Message.Body.CurrentDemandReq.DC_EVStatus);
        set_physical_value(&doc->V2G_Message.Body.CurrentDemandReq.EVTargetVoltage, iso2_unitSymbolType_V, 400, 0);
        set_physical_value(&doc->V2G_Message.Body.CurrentDemandReq.EVTargetCurrent, iso2_unitSymbolType_A, 32, 0);
        doc->V2G_Message.Body.CurrentDemandReq.ChargingComplete = 0;
    }

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_current_demand_req(const uint8_t *buf, size_t len, struct iso2_CurrentDemandReqType *req) {
    if (!buf || !req) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.CurrentDemandReq_isUsed) return -EBADMSG;
    *req = doc->V2G_Message.Body.CurrentDemandReq;
    return 0;
}

int jpv2g_cbv2g_encode_current_demand_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                            iso2_responseCodeType code,
                                            const struct iso2_CurrentDemandResType *payload,
                                            uint8_t *out,
                                            size_t out_len,
                                            size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.CurrentDemandRes_isUsed = 1;
    init_iso2_CurrentDemandResType(&doc->V2G_Message.Body.CurrentDemandRes);
    if (payload) {
        doc->V2G_Message.Body.CurrentDemandRes = *payload;
    } else {
        set_default_dc_evse_status(&doc->V2G_Message.Body.CurrentDemandRes.DC_EVSEStatus);
        set_physical_value(&doc->V2G_Message.Body.CurrentDemandRes.EVSEPresentVoltage, iso2_unitSymbolType_V, 400, 0);
        set_physical_value(&doc->V2G_Message.Body.CurrentDemandRes.EVSEPresentCurrent, iso2_unitSymbolType_A, 16, 0);
        doc->V2G_Message.Body.CurrentDemandRes.EVSECurrentLimitAchieved = 0;
        doc->V2G_Message.Body.CurrentDemandRes.EVSEVoltageLimitAchieved = 0;
        doc->V2G_Message.Body.CurrentDemandRes.EVSEPowerLimitAchieved = 0;
        doc->V2G_Message.Body.CurrentDemandRes.EVSEMaximumCurrentLimit_isUsed = 0;
        doc->V2G_Message.Body.CurrentDemandRes.EVSEMaximumPowerLimit_isUsed = 0;
        doc->V2G_Message.Body.CurrentDemandRes.EVSEMaximumVoltageLimit_isUsed = 0;
        doc->V2G_Message.Body.CurrentDemandRes.MeterInfo_isUsed = 0;
        doc->V2G_Message.Body.CurrentDemandRes.ReceiptRequired_isUsed = 0;
        doc->V2G_Message.Body.CurrentDemandRes.SAScheduleTupleID = 1;
        doc->V2G_Message.Body.CurrentDemandRes.EVSEID.charactersLen =
            copy_chars(doc->V2G_Message.Body.CurrentDemandRes.EVSEID.characters, iso2_EVSEID_CHARACTER_SIZE, "EVSE1");
    }
    doc->V2G_Message.Body.CurrentDemandRes.ResponseCode = code;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_current_demand_res(const uint8_t *buf, size_t len, struct iso2_CurrentDemandResType *res) {
    if (!buf || !res) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.CurrentDemandRes_isUsed) return -EBADMSG;
    *res = doc->V2G_Message.Body.CurrentDemandRes;
    return 0;
}

int jpv2g_cbv2g_encode_metering_receipt_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                              uint8_t sa_id,
                                              const struct iso2_MeterInfoType *meter,
                                              const struct iso2_MeteringReceiptReqType *payload,
                                              uint8_t *out,
                                              size_t out_len,
                                              size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.MeteringReceiptReq_isUsed = 1;
    init_iso2_MeteringReceiptReqType(&doc->V2G_Message.Body.MeteringReceiptReq);
    if (payload) {
        doc->V2G_Message.Body.MeteringReceiptReq = *payload;
    } else {
        set_default_meter_info(&doc->V2G_Message.Body.MeteringReceiptReq.MeterInfo, "METER01");
    }
    if (session_id) {
        memcpy(doc->V2G_Message.Body.MeteringReceiptReq.SessionID.bytes, session_id, iso2_sessionIDType_BYTES_SIZE);
        doc->V2G_Message.Body.MeteringReceiptReq.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE;
    } else {
        doc->V2G_Message.Body.MeteringReceiptReq.SessionID.bytesLen = 0;
    }
    if (sa_id) {
        doc->V2G_Message.Body.MeteringReceiptReq.SAScheduleTupleID = sa_id;
        doc->V2G_Message.Body.MeteringReceiptReq.SAScheduleTupleID_isUsed = 1;
    }
    if (meter) {
        doc->V2G_Message.Body.MeteringReceiptReq.MeterInfo = *meter;
    }

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_metering_receipt_req(const uint8_t *buf, size_t len, struct iso2_MeteringReceiptReqType *req) {
    if (!buf || !req) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.MeteringReceiptReq_isUsed) return -EBADMSG;
    *req = doc->V2G_Message.Body.MeteringReceiptReq;
    return 0;
}

int jpv2g_cbv2g_encode_metering_receipt_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                              iso2_responseCodeType code,
                                              const struct iso2_MeteringReceiptResType *payload,
                                              uint8_t *out,
                                              size_t out_len,
                                              size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.MeteringReceiptRes_isUsed = 1;
    init_iso2_MeteringReceiptResType(&doc->V2G_Message.Body.MeteringReceiptRes);
    if (payload) {
        doc->V2G_Message.Body.MeteringReceiptRes = *payload;
    } else {
        set_default_ac_status(&doc->V2G_Message.Body.MeteringReceiptRes.AC_EVSEStatus);
        doc->V2G_Message.Body.MeteringReceiptRes.AC_EVSEStatus_isUsed = 1;
    }
    doc->V2G_Message.Body.MeteringReceiptRes.ResponseCode = code;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_metering_receipt_res(const uint8_t *buf, size_t len, struct iso2_MeteringReceiptResType *res) {
    if (!buf || !res) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.MeteringReceiptRes_isUsed) return -EBADMSG;
    *res = doc->V2G_Message.Body.MeteringReceiptRes;
    return 0;
}

int jpv2g_cbv2g_encode_session_stop_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                          iso2_chargingSessionType reason,
                                          uint8_t *out,
                                          size_t out_len,
                                          size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.SessionStopReq_isUsed = 1;
    init_iso2_SessionStopReqType(&doc->V2G_Message.Body.SessionStopReq);
    doc->V2G_Message.Body.SessionStopReq.ChargingSession = reason;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_session_stop_req(const uint8_t *buf, size_t len, struct iso2_SessionStopReqType *req) {
    if (!buf || !req) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.SessionStopReq_isUsed) return -EBADMSG;
    *req = doc->V2G_Message.Body.SessionStopReq;
    return 0;
}

int jpv2g_cbv2g_encode_session_stop_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                          iso2_responseCodeType code,
                                          uint8_t *out,
                                          size_t out_len,
                                          size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.SessionStopRes_isUsed = 1;
    init_iso2_SessionStopResType(&doc->V2G_Message.Body.SessionStopRes);
    doc->V2G_Message.Body.SessionStopRes.ResponseCode = code;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_session_stop_res(const uint8_t *buf, size_t len, struct iso2_SessionStopResType *res) {
    if (!buf || !res) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.SessionStopRes_isUsed) return -EBADMSG;
    *res = doc->V2G_Message.Body.SessionStopRes;
    return 0;
}

int jpv2g_cbv2g_encode_pre_charge_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                        const struct iso2_PreChargeReqType *payload,
                                        uint8_t *out,
                                        size_t out_len,
                                        size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.PreChargeReq_isUsed = 1;
    init_iso2_PreChargeReqType(&doc->V2G_Message.Body.PreChargeReq);
    if (payload) {
        doc->V2G_Message.Body.PreChargeReq = *payload;
    } else {
        set_default_dc_ev_status(&doc->V2G_Message.Body.PreChargeReq.DC_EVStatus);
        set_physical_value(&doc->V2G_Message.Body.PreChargeReq.EVTargetVoltage, iso2_unitSymbolType_V, 380, 0);
        set_physical_value(&doc->V2G_Message.Body.PreChargeReq.EVTargetCurrent, iso2_unitSymbolType_A, 10, 0);
    }

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_pre_charge_req(const uint8_t *buf, size_t len, struct iso2_PreChargeReqType *req) {
    if (!buf || !req) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.PreChargeReq_isUsed) return -EBADMSG;
    *req = doc->V2G_Message.Body.PreChargeReq;
    return 0;
}

int jpv2g_cbv2g_encode_pre_charge_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                        iso2_responseCodeType code,
                                        const struct iso2_PreChargeResType *payload,
                                        uint8_t *out,
                                        size_t out_len,
                                        size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.PreChargeRes_isUsed = 1;
    init_iso2_PreChargeResType(&doc->V2G_Message.Body.PreChargeRes);
    if (payload) {
        doc->V2G_Message.Body.PreChargeRes = *payload;
    } else {
        set_default_dc_evse_status(&doc->V2G_Message.Body.PreChargeRes.DC_EVSEStatus);
        set_physical_value(&doc->V2G_Message.Body.PreChargeRes.EVSEPresentVoltage, iso2_unitSymbolType_V, 380, 0);
    }
    doc->V2G_Message.Body.PreChargeRes.ResponseCode = code;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_pre_charge_res(const uint8_t *buf, size_t len, struct iso2_PreChargeResType *res) {
    if (!buf || !res) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.PreChargeRes_isUsed) return -EBADMSG;
    *res = doc->V2G_Message.Body.PreChargeRes;
    return 0;
}

int jpv2g_cbv2g_encode_welding_detection_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                               const struct iso2_WeldingDetectionReqType *payload,
                                               uint8_t *out,
                                               size_t out_len,
                                               size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.WeldingDetectionReq_isUsed = 1;
    init_iso2_WeldingDetectionReqType(&doc->V2G_Message.Body.WeldingDetectionReq);
    if (payload) {
        doc->V2G_Message.Body.WeldingDetectionReq = *payload;
    } else {
        set_default_dc_ev_status(&doc->V2G_Message.Body.WeldingDetectionReq.DC_EVStatus);
    }

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_welding_detection_req(const uint8_t *buf, size_t len, struct iso2_WeldingDetectionReqType *req) {
    if (!buf || !req) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.WeldingDetectionReq_isUsed) return -EBADMSG;
    *req = doc->V2G_Message.Body.WeldingDetectionReq;
    return 0;
}

int jpv2g_cbv2g_encode_welding_detection_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                               iso2_responseCodeType code,
                                               const struct iso2_WeldingDetectionResType *payload,
                                               uint8_t *out,
                                               size_t out_len,
                                               size_t *written) {
    if (!out) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    set_header_session(&doc->V2G_Message.Header, session_id);
    init_iso2_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.WeldingDetectionRes_isUsed = 1;
    init_iso2_WeldingDetectionResType(&doc->V2G_Message.Body.WeldingDetectionRes);
    if (payload) {
        doc->V2G_Message.Body.WeldingDetectionRes = *payload;
    } else {
        set_default_dc_evse_status(&doc->V2G_Message.Body.WeldingDetectionRes.DC_EVSEStatus);
        set_physical_value(&doc->V2G_Message.Body.WeldingDetectionRes.EVSEPresentVoltage, iso2_unitSymbolType_V, 400, 0);
    }
    doc->V2G_Message.Body.WeldingDetectionRes.ResponseCode = code;

    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_decode_welding_detection_res(const uint8_t *buf, size_t len, struct iso2_WeldingDetectionResType *res) {
    if (!buf || !res) return -EINVAL;
    struct iso2_exiDocument *doc = &g_iso_doc_psram;
    init_iso2_exiDocument(doc);
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, (uint8_t *)buf, len, 0, NULL);
    if (decode_iso2_exiDocument(&stream, doc) != 0) return -EIO;
    if (!doc->V2G_Message.Body.WeldingDetectionRes_isUsed) return -EBADMSG;
    *res = doc->V2G_Message.Body.WeldingDetectionRes;
    return 0;
}

int jpv2g_cbv2g_encode_din_session_setup_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                               const uint8_t *evse_id,
                                               size_t evse_id_len,
                                               din_responseCodeType code,
                                               int64_t timestamp,
                                               uint8_t *out,
                                               size_t out_len,
                                               size_t *written) {
    if (!session_id || !evse_id || !out) return -EINVAL;
    if (evse_id_len == 0 || evse_id_len > din_evseIDType_BYTES_SIZE) return -EINVAL;
    struct din_exiDocument *doc = &g_din_doc_psram;
    init_din_exiDocument(doc);
    set_din_header_session(&doc->V2G_Message.Header, session_id);
    init_din_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.SessionSetupRes_isUsed = 1;
    init_din_SessionSetupResType(&doc->V2G_Message.Body.SessionSetupRes);
    doc->V2G_Message.Body.SessionSetupRes.ResponseCode = code;
    memcpy(doc->V2G_Message.Body.SessionSetupRes.EVSEID.bytes, evse_id, evse_id_len);
    doc->V2G_Message.Body.SessionSetupRes.EVSEID.bytesLen = (uint16_t)evse_id_len;
    if (timestamp >= 0) {
        doc->V2G_Message.Body.SessionSetupRes.DateTimeNow = timestamp;
        doc->V2G_Message.Body.SessionSetupRes.DateTimeNow_isUsed = 1;
    } else {
        doc->V2G_Message.Body.SessionSetupRes.DateTimeNow_isUsed = 0;
    }
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_din_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_encode_din_service_discovery_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                   din_responseCodeType code,
                                                   din_paymentOptionType payment,
                                                   din_EVSESupportedEnergyTransferType etm,
                                                   uint16_t service_id,
                                                   const char *service_name,
                                                   int free_service,
                                                   uint8_t *out,
                                                   size_t out_len,
                                                   size_t *written) {
    if (!session_id || !out) return -EINVAL;
    struct din_exiDocument *doc = &g_din_doc_psram;
    init_din_exiDocument(doc);
    set_din_header_session(&doc->V2G_Message.Header, session_id);
    init_din_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.ServiceDiscoveryRes_isUsed = 1;
    init_din_ServiceDiscoveryResType(&doc->V2G_Message.Body.ServiceDiscoveryRes);
    doc->V2G_Message.Body.ServiceDiscoveryRes.ResponseCode = code;
    set_din_default_payment_options(&doc->V2G_Message.Body.ServiceDiscoveryRes.PaymentOptions, payment);
    set_din_service_tag(&doc->V2G_Message.Body.ServiceDiscoveryRes.ChargeService.ServiceTag,
                        service_id,
                        service_name ? service_name : "DC Charging",
                        din_serviceCategoryType_EVCharging);
    doc->V2G_Message.Body.ServiceDiscoveryRes.ChargeService.FreeService = free_service ? 1 : 0;
    doc->V2G_Message.Body.ServiceDiscoveryRes.ChargeService.EnergyTransferType = etm;
    doc->V2G_Message.Body.ServiceDiscoveryRes.ServiceList_isUsed = 0;
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_din_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_encode_din_service_payment_selection_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                           din_responseCodeType code,
                                                           uint8_t *out,
                                                           size_t out_len,
                                                           size_t *written) {
    if (!session_id || !out) return -EINVAL;
    struct din_exiDocument *doc = &g_din_doc_psram;
    init_din_exiDocument(doc);
    set_din_header_session(&doc->V2G_Message.Header, session_id);
    init_din_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.ServicePaymentSelectionRes_isUsed = 1;
    init_din_ServicePaymentSelectionResType(&doc->V2G_Message.Body.ServicePaymentSelectionRes);
    doc->V2G_Message.Body.ServicePaymentSelectionRes.ResponseCode = code;
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_din_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_encode_din_payment_details_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                 din_responseCodeType code,
                                                 const char *gen_challenge,
                                                 int64_t timestamp,
                                                 uint8_t *out,
                                                 size_t out_len,
                                                 size_t *written) {
    if (!session_id || !out) return -EINVAL;
    struct din_exiDocument *doc = &g_din_doc_psram;
    init_din_exiDocument(doc);
    set_din_header_session(&doc->V2G_Message.Header, session_id);
    init_din_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.PaymentDetailsRes_isUsed = 1;
    init_din_PaymentDetailsResType(&doc->V2G_Message.Body.PaymentDetailsRes);
    doc->V2G_Message.Body.PaymentDetailsRes.ResponseCode = code;
    if (gen_challenge && *gen_challenge) {
        doc->V2G_Message.Body.PaymentDetailsRes.GenChallenge.charactersLen =
            copy_chars(doc->V2G_Message.Body.PaymentDetailsRes.GenChallenge.characters,
                       din_GenChallenge_CHARACTER_SIZE,
                       gen_challenge);
    } else {
        doc->V2G_Message.Body.PaymentDetailsRes.GenChallenge.charactersLen = 0;
    }
    doc->V2G_Message.Body.PaymentDetailsRes.DateTimeNow = timestamp >= 0 ? timestamp : 0;
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_din_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_encode_din_contract_authentication_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                         din_responseCodeType code,
                                                         din_EVSEProcessingType processing,
                                                         uint8_t *out,
                                                         size_t out_len,
                                                         size_t *written) {
    if (!session_id || !out) return -EINVAL;
    struct din_exiDocument *doc = &g_din_doc_psram;
    init_din_exiDocument(doc);
    set_din_header_session(&doc->V2G_Message.Header, session_id);
    init_din_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.ContractAuthenticationRes_isUsed = 1;
    init_din_ContractAuthenticationResType(&doc->V2G_Message.Body.ContractAuthenticationRes);
    doc->V2G_Message.Body.ContractAuthenticationRes.ResponseCode = code;
    doc->V2G_Message.Body.ContractAuthenticationRes.EVSEProcessing = processing;
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_din_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_encode_din_charge_parameter_discovery_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                            din_responseCodeType code,
                                                            const struct din_DC_EVSEChargeParameterType *dc_params,
                                                            uint8_t *out,
                                                            size_t out_len,
                                                            size_t *written) {
    if (!session_id || !out) return -EINVAL;
    struct din_exiDocument *doc = &g_din_doc_psram;
    init_din_exiDocument(doc);
    set_din_header_session(&doc->V2G_Message.Header, session_id);
    init_din_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed = 1;
    init_din_ChargeParameterDiscoveryResType(&doc->V2G_Message.Body.ChargeParameterDiscoveryRes);
    doc->V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode = code;
    doc->V2G_Message.Body.ChargeParameterDiscoveryRes.EVSEProcessing = din_EVSEProcessingType_Finished;
    doc->V2G_Message.Body.ChargeParameterDiscoveryRes.DC_EVSEChargeParameter_isUsed = 1;
    if (dc_params) {
        doc->V2G_Message.Body.ChargeParameterDiscoveryRes.DC_EVSEChargeParameter = *dc_params;
    } else {
        set_din_default_dc_charge_params(&doc->V2G_Message.Body.ChargeParameterDiscoveryRes.DC_EVSEChargeParameter);
    }
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_din_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_encode_din_power_delivery_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                din_responseCodeType code,
                                                const struct din_PowerDeliveryResType *payload,
                                                uint8_t *out,
                                                size_t out_len,
                                                size_t *written) {
    if (!session_id || !out) return -EINVAL;
    struct din_exiDocument *doc = &g_din_doc_psram;
    init_din_exiDocument(doc);
    set_din_header_session(&doc->V2G_Message.Header, session_id);
    init_din_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.PowerDeliveryRes_isUsed = 1;
    init_din_PowerDeliveryResType(&doc->V2G_Message.Body.PowerDeliveryRes);
    if (payload) {
        doc->V2G_Message.Body.PowerDeliveryRes = *payload;
    } else {
        doc->V2G_Message.Body.PowerDeliveryRes.DC_EVSEStatus_isUsed = 1;
        set_din_default_dc_evse_status(&doc->V2G_Message.Body.PowerDeliveryRes.DC_EVSEStatus);
        doc->V2G_Message.Body.PowerDeliveryRes.AC_EVSEStatus_isUsed = 0;
        doc->V2G_Message.Body.PowerDeliveryRes.EVSEStatus_isUsed = 0;
    }
    doc->V2G_Message.Body.PowerDeliveryRes.ResponseCode = code;
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_din_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_encode_din_current_demand_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                din_responseCodeType code,
                                                const struct din_CurrentDemandResType *payload,
                                                uint8_t *out,
                                                size_t out_len,
                                                size_t *written) {
    if (!session_id || !out) return -EINVAL;
    struct din_exiDocument *doc = &g_din_doc_psram;
    init_din_exiDocument(doc);
    set_din_header_session(&doc->V2G_Message.Header, session_id);
    init_din_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.CurrentDemandRes_isUsed = 1;
    init_din_CurrentDemandResType(&doc->V2G_Message.Body.CurrentDemandRes);
    if (payload) {
        doc->V2G_Message.Body.CurrentDemandRes = *payload;
    } else {
        set_din_default_dc_evse_status(&doc->V2G_Message.Body.CurrentDemandRes.DC_EVSEStatus);
        set_din_physical_value(&doc->V2G_Message.Body.CurrentDemandRes.EVSEPresentVoltage, din_unitSymbolType_V, 400, 0);
        set_din_physical_value(&doc->V2G_Message.Body.CurrentDemandRes.EVSEPresentCurrent, din_unitSymbolType_A, 0, 0);
        doc->V2G_Message.Body.CurrentDemandRes.EVSECurrentLimitAchieved = 0;
        doc->V2G_Message.Body.CurrentDemandRes.EVSEVoltageLimitAchieved = 0;
        doc->V2G_Message.Body.CurrentDemandRes.EVSEPowerLimitAchieved = 0;
        doc->V2G_Message.Body.CurrentDemandRes.EVSEMaximumVoltageLimit_isUsed = 0;
        doc->V2G_Message.Body.CurrentDemandRes.EVSEMaximumCurrentLimit_isUsed = 0;
        doc->V2G_Message.Body.CurrentDemandRes.EVSEMaximumPowerLimit_isUsed = 0;
    }
    doc->V2G_Message.Body.CurrentDemandRes.ResponseCode = code;
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_din_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_encode_din_metering_receipt_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                  din_responseCodeType code,
                                                  const struct din_MeteringReceiptResType *payload,
                                                  uint8_t *out,
                                                  size_t out_len,
                                                  size_t *written) {
    if (!session_id || !out) return -EINVAL;
    struct din_exiDocument *doc = &g_din_doc_psram;
    init_din_exiDocument(doc);
    set_din_header_session(&doc->V2G_Message.Header, session_id);
    init_din_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.MeteringReceiptRes_isUsed = 1;
    init_din_MeteringReceiptResType(&doc->V2G_Message.Body.MeteringReceiptRes);
    if (payload) {
        doc->V2G_Message.Body.MeteringReceiptRes = *payload;
    } else {
        set_din_default_ac_status(&doc->V2G_Message.Body.MeteringReceiptRes.AC_EVSEStatus);
    }
    doc->V2G_Message.Body.MeteringReceiptRes.ResponseCode = code;
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_din_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_encode_din_session_stop_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                              din_responseCodeType code,
                                              uint8_t *out,
                                              size_t out_len,
                                              size_t *written) {
    if (!session_id || !out) return -EINVAL;
    struct din_exiDocument *doc = &g_din_doc_psram;
    init_din_exiDocument(doc);
    set_din_header_session(&doc->V2G_Message.Header, session_id);
    init_din_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.SessionStopRes_isUsed = 1;
    init_din_SessionStopResType(&doc->V2G_Message.Body.SessionStopRes);
    doc->V2G_Message.Body.SessionStopRes.ResponseCode = code;
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_din_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_encode_din_welding_detection_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                   din_responseCodeType code,
                                                   const struct din_WeldingDetectionResType *payload,
                                                   uint8_t *out,
                                                   size_t out_len,
                                                   size_t *written) {
    if (!session_id || !out) return -EINVAL;
    struct din_exiDocument *doc = &g_din_doc_psram;
    init_din_exiDocument(doc);
    set_din_header_session(&doc->V2G_Message.Header, session_id);
    init_din_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.WeldingDetectionRes_isUsed = 1;
    init_din_WeldingDetectionResType(&doc->V2G_Message.Body.WeldingDetectionRes);
    if (payload) {
        doc->V2G_Message.Body.WeldingDetectionRes = *payload;
    } else {
        set_din_default_dc_evse_status(&doc->V2G_Message.Body.WeldingDetectionRes.DC_EVSEStatus);
        set_din_physical_value(&doc->V2G_Message.Body.WeldingDetectionRes.EVSEPresentVoltage, din_unitSymbolType_V, 400, 0);
    }
    doc->V2G_Message.Body.WeldingDetectionRes.ResponseCode = code;
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_din_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_encode_din_pre_charge_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                            din_responseCodeType code,
                                            const struct din_PreChargeResType *payload,
                                            uint8_t *out,
                                            size_t out_len,
                                            size_t *written) {
    if (!session_id || !out) return -EINVAL;
    struct din_exiDocument *doc = &g_din_doc_psram;
    init_din_exiDocument(doc);
    set_din_header_session(&doc->V2G_Message.Header, session_id);
    init_din_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.PreChargeRes_isUsed = 1;
    init_din_PreChargeResType(&doc->V2G_Message.Body.PreChargeRes);
    if (payload) {
        doc->V2G_Message.Body.PreChargeRes = *payload;
    } else {
        set_din_default_dc_evse_status(&doc->V2G_Message.Body.PreChargeRes.DC_EVSEStatus);
        set_din_physical_value(&doc->V2G_Message.Body.PreChargeRes.EVSEPresentVoltage, din_unitSymbolType_V, 400, 0);
    }
    doc->V2G_Message.Body.PreChargeRes.ResponseCode = code;
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_din_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

int jpv2g_cbv2g_encode_din_cable_check_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                             din_responseCodeType code,
                                             din_EVSEProcessingType processing,
                                             const struct din_CableCheckResType *payload,
                                             uint8_t *out,
                                             size_t out_len,
                                             size_t *written) {
    if (!session_id || !out) return -EINVAL;
    struct din_exiDocument *doc = &g_din_doc_psram;
    init_din_exiDocument(doc);
    set_din_header_session(&doc->V2G_Message.Header, session_id);
    init_din_BodyType(&doc->V2G_Message.Body);
    doc->V2G_Message.Body.CableCheckRes_isUsed = 1;
    init_din_CableCheckResType(&doc->V2G_Message.Body.CableCheckRes);
    if (payload) {
        doc->V2G_Message.Body.CableCheckRes = *payload;
    } else {
        set_din_default_dc_evse_status(&doc->V2G_Message.Body.CableCheckRes.DC_EVSEStatus);
        doc->V2G_Message.Body.CableCheckRes.EVSEProcessing = processing;
    }
    doc->V2G_Message.Body.CableCheckRes.ResponseCode = code;
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, out, out_len, 0, NULL);
    if (encode_din_exiDocument(&stream, doc) != 0) return -EIO;
    if (written) *written = exi_bitstream_get_length(&stream);
    return 0;
}

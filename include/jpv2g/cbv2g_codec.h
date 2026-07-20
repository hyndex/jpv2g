/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "jpv2g/messages.h"
#include "jpv2g/types.h"

#ifdef JPV2G_ENABLE_CBV2G_CODEC

#include "cbv2g/app_handshake/appHand_Datatypes.h"
#include "cbv2g/din/din_msgDefDatatypes.h"
#include "cbv2g/iso_2/iso2_msgDefDatatypes.h"

// Pre-allocate the large ISO-15118 / DIN / app message workspaces from PSRAM at
// boot, off the HLC timing path. There are three independent document sets:
// encoder, SECC request decoder, and decoded-response logger. OPTIONAL — the
// codec also allocates them lazily on first use — but calling this in setup
// keeps allocation out of the live V2G handshake. Idempotent.
void jpv2g_cbv2g_codec_init(void);

// True once all three independent sets (nine EXI documents total) are
// allocated. Lets HLC bring-up gate on the codec being ready instead of
// reaching the first V2G message with an incomplete workspace.
bool jpv2g_cbv2g_codec_ready(void);

int jpv2g_cbv2g_encode_sapp_req(const char *ns,
                                  uint32_t ver_major,
                                  uint32_t ver_minor,
                                  uint8_t schema_id,
                                  uint8_t priority,
                                  uint8_t *out,
                                  size_t out_len,
                                  size_t *written);

int jpv2g_cbv2g_decode_sapp_res(const uint8_t *buf, size_t len, struct appHand_supportedAppProtocolRes *res);
int jpv2g_cbv2g_encode_sapp_res(uint8_t schema_id,
                                  appHand_responseCodeType code,
                                  uint8_t *out,
                                  size_t out_len,
                                  size_t *written);

int jpv2g_cbv2g_encode_session_setup_req(const uint8_t evcc_id[iso2_evccIDType_BYTES_SIZE],
                                           uint8_t *out,
                                           size_t out_len,
                                           size_t *written);

int jpv2g_cbv2g_decode_session_setup_req(const uint8_t *buf, size_t len, struct iso2_SessionSetupReqType *req);

int jpv2g_cbv2g_encode_session_setup_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                           const char *evse_id,
                                           iso2_responseCodeType code,
                                           uint8_t *out,
                                           size_t out_len,
                                           size_t *written);

int jpv2g_cbv2g_decode_session_setup_res(const uint8_t *buf, size_t len, struct iso2_SessionSetupResType *res, uint8_t session_id_out[iso2_sessionIDType_BYTES_SIZE]);

int jpv2g_cbv2g_encode_service_discovery_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE], uint8_t *out, size_t out_len, size_t *written);
int jpv2g_cbv2g_decode_service_discovery_req(const uint8_t *buf, size_t len, struct iso2_ServiceDiscoveryReqType *req);

int jpv2g_cbv2g_encode_service_discovery_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                               iso2_responseCodeType code,
                                               iso2_paymentOptionType payment,
                                               iso2_EnergyTransferModeType etm,
                                               uint16_t service_id,
                                               const char *service_name,
                                               int free_service,
                                               uint8_t *out,
                                               size_t out_len,
                                               size_t *written);
int jpv2g_cbv2g_encode_service_discovery_res_multi(
    const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
    iso2_responseCodeType code,
    const iso2_paymentOptionType *payments,
    size_t payment_count,
    const iso2_EnergyTransferModeType *energy_modes,
    size_t energy_mode_count,
    uint16_t service_id,
    const char *service_name,
    int free_service,
    uint8_t *out,
    size_t out_len,
    size_t *written);
int jpv2g_cbv2g_decode_service_discovery_res(const uint8_t *buf, size_t len, struct iso2_ServiceDiscoveryResType *res);

int jpv2g_cbv2g_encode_payment_service_selection_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                                       iso2_paymentOptionType payment,
                                                       uint8_t *out,
                                                       size_t out_len,
                                                       size_t *written);
int jpv2g_cbv2g_decode_payment_service_selection_req(const uint8_t *buf, size_t len, struct iso2_PaymentServiceSelectionReqType *req);
int jpv2g_cbv2g_encode_payment_service_selection_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                                       iso2_responseCodeType code,
                                                       uint8_t *out,
                                                       size_t out_len,
                                                       size_t *written);
int jpv2g_cbv2g_decode_payment_service_selection_res(const uint8_t *buf, size_t len, struct iso2_PaymentServiceSelectionResType *res);

int jpv2g_cbv2g_encode_charge_parameter_discovery_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                                        iso2_EnergyTransferModeType etm,
                                                        uint8_t *out,
                                                        size_t out_len,
                                                        size_t *written);
int jpv2g_cbv2g_decode_charge_parameter_discovery_req(const uint8_t *buf, size_t len, struct iso2_ChargeParameterDiscoveryReqType *req);
int jpv2g_cbv2g_encode_charge_parameter_discovery_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                                        iso2_responseCodeType code,
                                                        iso2_EnergyTransferModeType etm,
                                                        uint8_t *out,
                                                        size_t out_len,
                                                        size_t *written);
int jpv2g_cbv2g_encode_charge_parameter_discovery_res_payload(
    const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
    const struct iso2_ChargeParameterDiscoveryResType *payload,
    uint8_t *out,
    size_t out_len,
    size_t *written);
int jpv2g_cbv2g_decode_charge_parameter_discovery_res(const uint8_t *buf, size_t len, struct iso2_ChargeParameterDiscoveryResType *res);

int jpv2g_cbv2g_encode_cable_check_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                         const struct iso2_CableCheckReqType *payload,
                                         uint8_t *out,
                                         size_t out_len,
                                         size_t *written);
int jpv2g_cbv2g_decode_cable_check_req(const uint8_t *buf, size_t len, struct iso2_CableCheckReqType *req);
int jpv2g_cbv2g_encode_cable_check_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                         iso2_responseCodeType code,
                                         iso2_EVSEProcessingType processing,
                                         const struct iso2_CableCheckResType *payload,
                                         uint8_t *out,
                                         size_t out_len,
                                         size_t *written);
int jpv2g_cbv2g_decode_cable_check_res(const uint8_t *buf, size_t len, struct iso2_CableCheckResType *res);

int jpv2g_cbv2g_encode_service_detail_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                            uint16_t service_id,
                                            uint8_t *out,
                                            size_t out_len,
                                            size_t *written);
int jpv2g_cbv2g_decode_service_detail_req(const uint8_t *buf, size_t len, struct iso2_ServiceDetailReqType *req);
int jpv2g_cbv2g_encode_service_detail_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                            iso2_responseCodeType code,
                                            uint16_t service_id,
                                            const struct iso2_ServiceParameterListType *params,
                                            uint8_t *out,
                                            size_t out_len,
                                            size_t *written);
int jpv2g_cbv2g_decode_service_detail_res(const uint8_t *buf, size_t len, struct iso2_ServiceDetailResType *res);

int jpv2g_cbv2g_encode_payment_details_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                             const char *emaid,
                                             const struct iso2_CertificateChainType *chain,
                                             uint8_t *out,
                                             size_t out_len,
                                             size_t *written);
int jpv2g_cbv2g_decode_payment_details_req(const uint8_t *buf, size_t len, struct iso2_PaymentDetailsReqType *req);
int jpv2g_cbv2g_encode_payment_details_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                             iso2_responseCodeType code,
                                             const uint8_t *gen_challenge,
                                             size_t gen_challenge_len,
                                             int64_t evse_timestamp,
                                             uint8_t *out,
                                             size_t out_len,
                                             size_t *written);
int jpv2g_cbv2g_decode_payment_details_res(const uint8_t *buf, size_t len, struct iso2_PaymentDetailsResType *res);

int jpv2g_cbv2g_encode_authorization_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                           const uint8_t *gen_challenge,
                                           size_t gen_challenge_len,
                                           uint8_t *out,
                                           size_t out_len,
                                           size_t *written);
int jpv2g_cbv2g_decode_authorization_req(const uint8_t *buf, size_t len, struct iso2_AuthorizationReqType *req);
int jpv2g_cbv2g_encode_authorization_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                           iso2_responseCodeType code,
                                           iso2_EVSEProcessingType processing,
                                           uint8_t *out,
                                           size_t out_len,
                                           size_t *written);
int jpv2g_cbv2g_decode_authorization_res(const uint8_t *buf, size_t len, struct iso2_AuthorizationResType *res);

int jpv2g_cbv2g_encode_power_delivery_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                            iso2_chargeProgressType progress,
                                            uint8_t sa_id,
                                            const struct iso2_PowerDeliveryReqType *payload,
                                            uint8_t *out,
                                            size_t out_len,
                                            size_t *written);
int jpv2g_cbv2g_decode_power_delivery_req(const uint8_t *buf, size_t len, struct iso2_PowerDeliveryReqType *req);
int jpv2g_cbv2g_encode_power_delivery_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                            iso2_responseCodeType code,
                                            const struct iso2_PowerDeliveryResType *payload,
                                            uint8_t *out,
                                            size_t out_len,
                                            size_t *written);
int jpv2g_cbv2g_decode_power_delivery_res(const uint8_t *buf, size_t len, struct iso2_PowerDeliveryResType *res);

int jpv2g_cbv2g_encode_charging_status_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                             uint8_t *out,
                                             size_t out_len,
                                             size_t *written);
int jpv2g_cbv2g_decode_charging_status_req(const uint8_t *buf, size_t len, struct iso2_ChargingStatusReqType *req);
int jpv2g_cbv2g_encode_charging_status_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                             iso2_responseCodeType code,
                                             const char *evse_id,
                                             uint8_t sa_id,
                                             const struct iso2_ChargingStatusResType *payload,
                                             uint8_t *out,
                                             size_t out_len,
                                             size_t *written);
int jpv2g_cbv2g_decode_charging_status_res(const uint8_t *buf, size_t len, struct iso2_ChargingStatusResType *res);

int jpv2g_cbv2g_encode_current_demand_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                            const struct iso2_CurrentDemandReqType *payload,
                                            uint8_t *out,
                                            size_t out_len,
                                            size_t *written);
int jpv2g_cbv2g_decode_current_demand_req(const uint8_t *buf, size_t len, struct iso2_CurrentDemandReqType *req);
int jpv2g_cbv2g_encode_current_demand_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                            iso2_responseCodeType code,
                                            const struct iso2_CurrentDemandResType *payload,
                                            uint8_t *out,
                                            size_t out_len,
                                            size_t *written);
int jpv2g_cbv2g_decode_current_demand_res(const uint8_t *buf, size_t len, struct iso2_CurrentDemandResType *res);

int jpv2g_cbv2g_encode_metering_receipt_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                              uint8_t sa_id,
                                              const struct iso2_MeterInfoType *meter,
                                              const struct iso2_MeteringReceiptReqType *payload,
                                              uint8_t *out,
                                              size_t out_len,
                                              size_t *written);
int jpv2g_cbv2g_decode_metering_receipt_req(const uint8_t *buf, size_t len, struct iso2_MeteringReceiptReqType *req);
int jpv2g_cbv2g_encode_metering_receipt_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                              iso2_responseCodeType code,
                                              const struct iso2_MeteringReceiptResType *payload,
                                              uint8_t *out,
                                              size_t out_len,
                                              size_t *written);
int jpv2g_cbv2g_decode_metering_receipt_res(const uint8_t *buf, size_t len, struct iso2_MeteringReceiptResType *res);

int jpv2g_cbv2g_encode_session_stop_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                          iso2_chargingSessionType reason,
                                          uint8_t *out,
                                          size_t out_len,
                                          size_t *written);
int jpv2g_cbv2g_decode_session_stop_req(const uint8_t *buf, size_t len, struct iso2_SessionStopReqType *req);
int jpv2g_cbv2g_encode_session_stop_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                          iso2_responseCodeType code,
                                          uint8_t *out,
                                          size_t out_len,
                                          size_t *written);
int jpv2g_cbv2g_decode_session_stop_res(const uint8_t *buf, size_t len, struct iso2_SessionStopResType *res);

int jpv2g_cbv2g_encode_pre_charge_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                        const struct iso2_PreChargeReqType *payload,
                                        uint8_t *out,
                                        size_t out_len,
                                        size_t *written);
int jpv2g_cbv2g_decode_pre_charge_req(const uint8_t *buf, size_t len, struct iso2_PreChargeReqType *req);
int jpv2g_cbv2g_encode_pre_charge_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                        iso2_responseCodeType code,
                                        const struct iso2_PreChargeResType *payload,
                                        uint8_t *out,
                                        size_t out_len,
                                        size_t *written);
int jpv2g_cbv2g_decode_pre_charge_res(const uint8_t *buf, size_t len, struct iso2_PreChargeResType *res);

int jpv2g_cbv2g_encode_welding_detection_req(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                               const struct iso2_WeldingDetectionReqType *payload,
                                               uint8_t *out,
                                               size_t out_len,
                                               size_t *written);
int jpv2g_cbv2g_decode_welding_detection_req(const uint8_t *buf, size_t len, struct iso2_WeldingDetectionReqType *req);
int jpv2g_cbv2g_encode_welding_detection_res(const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                               iso2_responseCodeType code,
                                               const struct iso2_WeldingDetectionResType *payload,
                                               uint8_t *out,
                                               size_t out_len,
                                               size_t *written);
int jpv2g_cbv2g_decode_welding_detection_res(const uint8_t *buf, size_t len, struct iso2_WeldingDetectionResType *res);

/* DIN 70121 helpers (minimal DC-focused set) */
int jpv2g_cbv2g_encode_din_session_setup_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                               const uint8_t *evse_id,
                                               size_t evse_id_len,
                                               din_responseCodeType code,
                                               int64_t timestamp,
                                               uint8_t *out,
                                               size_t out_len,
                                               size_t *written);
int jpv2g_cbv2g_encode_din_service_discovery_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                   din_responseCodeType code,
                                                   din_paymentOptionType payment,
                                                   din_EVSESupportedEnergyTransferType etm,
                                                   uint16_t service_id,
                                                   const char *service_name,
                                                   int free_service,
                                                   uint8_t *out,
                                                   size_t out_len,
                                                   size_t *written);
int jpv2g_cbv2g_encode_din_service_detail_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                din_responseCodeType code,
                                                uint16_t service_id,
                                                uint8_t *out,
                                                size_t out_len,
                                                size_t *written);
int jpv2g_cbv2g_encode_din_service_payment_selection_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                           din_responseCodeType code,
                                                           uint8_t *out,
                                                           size_t out_len,
                                                           size_t *written);
int jpv2g_cbv2g_encode_din_payment_details_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                 din_responseCodeType code,
                                                 const char *gen_challenge,
                                                 int64_t timestamp,
                                                 uint8_t *out,
                                                 size_t out_len,
                                                 size_t *written);
int jpv2g_cbv2g_encode_din_contract_authentication_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                         din_responseCodeType code,
                                                         din_EVSEProcessingType processing,
                                                         uint8_t *out,
                                                         size_t out_len,
                                                         size_t *written);
int jpv2g_cbv2g_encode_din_charge_parameter_discovery_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                            din_responseCodeType code,
                                                            din_EVSEProcessingType processing,
                                                            const struct din_DC_EVSEChargeParameterType *dc_params,
                                                            uint8_t *out,
                                                            size_t out_len,
                                                            size_t *written);
int jpv2g_cbv2g_encode_din_power_delivery_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                din_responseCodeType code,
                                                const struct din_PowerDeliveryResType *payload,
                                                uint8_t *out,
                                                size_t out_len,
                                                size_t *written);
int jpv2g_cbv2g_encode_din_current_demand_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                din_responseCodeType code,
                                                const struct din_CurrentDemandResType *payload,
                                                uint8_t *out,
                                                size_t out_len,
                                                size_t *written);
int jpv2g_cbv2g_encode_din_metering_receipt_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                  din_responseCodeType code,
                                                  const struct din_MeteringReceiptResType *payload,
                                                  uint8_t *out,
                                                  size_t out_len,
                                                  size_t *written);
int jpv2g_cbv2g_encode_din_session_stop_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                              din_responseCodeType code,
                                              uint8_t *out,
                                              size_t out_len,
                                              size_t *written);
int jpv2g_cbv2g_encode_din_welding_detection_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                                   din_responseCodeType code,
                                                   const struct din_WeldingDetectionResType *payload,
                                                   uint8_t *out,
                                                   size_t out_len,
                                                   size_t *written);
int jpv2g_cbv2g_encode_din_pre_charge_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                            din_responseCodeType code,
                                            const struct din_PreChargeResType *payload,
                                            uint8_t *out,
                                            size_t out_len,
                                            size_t *written);
int jpv2g_cbv2g_encode_din_cable_check_res(const uint8_t session_id[din_sessionIDType_BYTES_SIZE],
                                             din_responseCodeType code,
                                             din_EVSEProcessingType processing,
                                             const struct din_CableCheckResType *payload,
                                             uint8_t *out,
                                             size_t out_len,
                                             size_t *written);

/* Minimal per-message FAILED response ([V2G2-538]/[V2G2-460]/[V2G2-736],
 * DIN [V2G-DC-665]). When the SECC rejects a request for a sequence violation
 * or an unknown SessionID it must still answer with a schema-valid Res whose
 * ResponseCode names the failure, THEN terminate — a silent TCP RST reads as
 * "EVSE died" to the vehicle and several stacks retry-loop on it. The
 * dispatcher reuses the existing per-message encoders (the same proven paths
 * production responses take) with the FAILED code and, for the DC energy
 * messages, an explicit fail-shaped DC_EVSEStatus (StopCharging notification,
 * isolation Invalid) mirroring Josev's failed_responses tables. Covers every
 * DIN + ISO2 message type the stream dispatcher can produce; returns -ENOTSUP
 * for types that have their own response path (SupportedAppProtocol) so the
 * caller falls back to plain termination. */
typedef enum {
    JPV2G_MIN_FAILED_SEQUENCE_ERROR = 0,
    JPV2G_MIN_FAILED_UNKNOWN_SESSION = 1,
} jpv2g_min_failed_kind_t;

int jpv2g_cbv2g_encode_min_failed_res(jpv2g_protocol_t protocol,
                                      jpv2g_message_type_t message_type,
                                      jpv2g_min_failed_kind_t kind,
                                      const uint8_t session_id[iso2_sessionIDType_BYTES_SIZE],
                                      const char *iso_evse_id,
                                      const uint8_t *din_evse_id,
                                      size_t din_evse_id_len,
                                      uint8_t *out,
                                      size_t out_len,
                                      size_t *written);

#else
/* cbv2g codec is disabled for this build. */
#endif

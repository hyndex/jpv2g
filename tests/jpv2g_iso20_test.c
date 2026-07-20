/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2026 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

/*
 * ISO 15118-20 DC SECC module tests (built only with JPV2G_ENABLE_ISO20).
 *
 * Message-level harness: each EV request is encoded with the cbv2g structs
 * and encode_iso20_* into a buffer, handed to the module's single-frame
 * handler, and the response is decoded back with decode_iso20_* — no sockets
 * needed, which keeps every assertion on the actual wire encoding.
 *
 * Covers: the full DC/EIM/Scheduled happy-path walk, the negative matrix
 * (unknown session, sequence error, BPT/Dynamic rejects, wrong service,
 * ServiceRenegotiation, Standby warning), RationalNumber round-trips, and
 * the SupportedAppProtocol dual-offer selection including the -20 AC
 * namespace reject and the -2-only regression.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cbv2g/app_handshake/appHand_Datatypes.h"
#include "cbv2g/app_handshake/appHand_Encoder.h"
#include "cbv2g/common/exi_bitstream.h"
#include "cbv2g/iso_20/iso20_CommonMessages_Datatypes.h"
#include "cbv2g/iso_20/iso20_CommonMessages_Decoder.h"
#include "cbv2g/iso_20/iso20_CommonMessages_Encoder.h"
#include "cbv2g/iso_20/iso20_DC_Datatypes.h"
#include "cbv2g/iso_20/iso20_DC_Decoder.h"
#include "cbv2g/iso_20/iso20_DC_Encoder.h"

#include "jpv2g/cbv2g_codec.h"
#include "jpv2g/secc.h"
#include "jpv2g/secc_iso20.h"
#include "jpv2g/v2gtp.h"

#define TEST_UNIX_TIME 1753000000ull
#define TEST_EVSE_ID "IN*JPT*E12345*1"
#define TEST_EVCCID "JPTESTEVCC01"

static int assert_true(int cond, const char *msg) {
    if (cond) return 0;
    fprintf(stderr, "ASSERT FAILED: %s\n", msg);
    return 1;
}

static int near(float a, float b, float tol) {
    float d = a - b;
    if (d < 0) d = -d;
    return d <= tol;
}

/* ------------------------------------------------------------ fixtures */

/* Module workspaces (the module never allocates its own) + separate request/
 * response documents for the test side. All heap: iso20_exiDocument is
 * hundreds of KB and must not live in test BSS either. */
static struct iso20_exiDocument *g_ws_common;
static struct iso20_dc_exiDocument *g_ws_dc;
static struct iso20_exiDocument *g_doc;    /* test-side common req/res doc */
static struct iso20_dc_exiDocument *g_dc_doc; /* test-side DC req/res doc */

static uint8_t g_frame[4096];
static uint8_t g_res[4096];
static uint8_t g_sid[8]; /* captured from SessionSetupRes */

typedef struct {
    jpv2g_secc20_auth_status_t auth;
    jpv2g_secc20_cable_check_status_t cable;
    jpv2g_secc20_stop_request_t stop;
    int contactor_result;
    int contactor_close_calls;
    int contactor_open_calls;
    float present_v;
    float present_i;
    int current_limit_achieved;
    float last_target_v;
    float last_target_i;
    float last_precharge_target_v;
    jpv2g_secc20_ev_limits_t last_ev_limits;
    int evccid_ok;
    int auth_required_calls;
    int cable_check_started_calls;
    int charge_loop_started_calls;
    int charge_loop_finished_calls;
    int last_present_soc;
    char last_term_code[81];
} test_ctx_t;

static void cb_on_evccid(void *ctx, const char *evccid, size_t len) {
    test_ctx_t *t = (test_ctx_t *)ctx;
    t->evccid_ok = (len == strlen(TEST_EVCCID) && memcmp(evccid, TEST_EVCCID, len) == 0);
}
static void cb_on_auth_required(void *ctx) { ((test_ctx_t *)ctx)->auth_required_calls++; }
static void cb_on_ev_limits(void *ctx, const jpv2g_secc20_ev_limits_t *limits) {
    ((test_ctx_t *)ctx)->last_ev_limits = *limits;
}
static void cb_on_cable_check_started(void *ctx) {
    ((test_ctx_t *)ctx)->cable_check_started_calls++;
}
static void cb_on_precharge_target(void *ctx, float target_v, float present_v) {
    (void)present_v;
    ((test_ctx_t *)ctx)->last_precharge_target_v = target_v;
}
static void cb_on_charge_loop_started(void *ctx) {
    ((test_ctx_t *)ctx)->charge_loop_started_calls++;
}
static void cb_on_charge_targets(void *ctx, float target_v, float target_i, float ev_present_v) {
    (void)ev_present_v;
    test_ctx_t *t = (test_ctx_t *)ctx;
    t->last_target_v = target_v;
    t->last_target_i = target_i;
}
static void cb_on_display_parameters(void *ctx, int soc) {
    ((test_ctx_t *)ctx)->last_present_soc = soc;
}
static void cb_on_charge_loop_finished(void *ctx) {
    ((test_ctx_t *)ctx)->charge_loop_finished_calls++;
}
static void cb_on_ev_termination(void *ctx, const char *code, size_t code_len,
                                 const char *expl, size_t expl_len) {
    (void)expl; (void)expl_len;
    test_ctx_t *t = (test_ctx_t *)ctx;
    if (code_len >= sizeof(t->last_term_code)) code_len = sizeof(t->last_term_code) - 1;
    memcpy(t->last_term_code, code, code_len);
    t->last_term_code[code_len] = '\0';
}
static jpv2g_secc20_auth_status_t cb_auth_status(void *ctx) {
    return ((test_ctx_t *)ctx)->auth;
}
static int cb_get_dc_limits(void *ctx, jpv2g_secc20_dc_limits_t *out) {
    (void)ctx;
    out->max_charge_power_w = 60000.0f;
    out->min_charge_power_w = 500.0f;
    out->max_charge_current_a = 200.0f;
    out->min_charge_current_a = 1.0f;
    out->max_voltage_v = 1000.0f;
    out->min_voltage_v = 150.0f;
    return 0;
}
static jpv2g_secc20_cable_check_status_t cb_cable_check(void *ctx) {
    return ((test_ctx_t *)ctx)->cable;
}
static int cb_get_present(void *ctx, jpv2g_secc20_present_t *out) {
    test_ctx_t *t = (test_ctx_t *)ctx;
    out->voltage_v = t->present_v;
    out->current_a = t->present_i;
    out->power_limit_achieved = false;
    out->current_limit_achieved = t->current_limit_achieved != 0;
    out->voltage_limit_achieved = false;
    return 0;
}
static int cb_contactor_set(void *ctx, bool close_contactor) {
    test_ctx_t *t = (test_ctx_t *)ctx;
    if (close_contactor) t->contactor_close_calls++;
    else t->contactor_open_calls++;
    return t->contactor_result;
}
static jpv2g_secc20_stop_request_t cb_stop_request(void *ctx) {
    return ((test_ctx_t *)ctx)->stop;
}
static int cb_get_meter(void *ctx, char *meter_id, size_t meter_id_size, uint64_t *wh) {
    (void)ctx;
    snprintf(meter_id, meter_id_size, "M1");
    *wh = 12345u;
    return 0;
}
static uint64_t test_now_unix(void *ctx) {
    (void)ctx;
    return TEST_UNIX_TIME;
}

static void test_ctx_reset(test_ctx_t *t) {
    memset(t, 0, sizeof(*t));
    t->auth = JPV2G_SECC20_AUTH_PENDING;
    t->cable = JPV2G_SECC20_CABLE_CHECK_ONGOING;
    t->stop = JPV2G_SECC20_STOP_NONE;
    t->last_present_soc = -1;
}

static int module_init(jpv2g_secc20_t *s, test_ctx_t *ctx) {
    jpv2g_secc20_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.evse_id, sizeof(cfg.evse_id), "%s", TEST_EVSE_ID);
    cfg.now_unix_s = test_now_unix;
    cfg.common_workspace = g_ws_common;
    cfg.dc_workspace = g_ws_dc;
    cfg.callbacks.user_ctx = ctx;
    cfg.callbacks.on_evccid = cb_on_evccid;
    cfg.callbacks.on_auth_required = cb_on_auth_required;
    cfg.callbacks.on_ev_limits = cb_on_ev_limits;
    cfg.callbacks.on_cable_check_started = cb_on_cable_check_started;
    cfg.callbacks.on_precharge_target = cb_on_precharge_target;
    cfg.callbacks.on_charge_loop_started = cb_on_charge_loop_started;
    cfg.callbacks.on_charge_targets = cb_on_charge_targets;
    cfg.callbacks.on_display_parameters = cb_on_display_parameters;
    cfg.callbacks.on_charge_loop_finished = cb_on_charge_loop_finished;
    cfg.callbacks.on_ev_termination = cb_on_ev_termination;
    cfg.callbacks.auth_status = cb_auth_status;
    cfg.callbacks.get_dc_limits = cb_get_dc_limits;
    cfg.callbacks.cable_check_status = cb_cable_check;
    cfg.callbacks.get_present = cb_get_present;
    cfg.callbacks.contactor_set = cb_contactor_set;
    cfg.callbacks.stop_request = cb_stop_request;
    cfg.callbacks.get_meter = cb_get_meter;
    int rc = jpv2g_secc20_init(s, &cfg);
    if (rc != 0) return rc;
    jpv2g_secc20_reset(s); /* what the stream loop does after the SAP Res */
    return 0;
}

/* ----------------------------------------------------- request builders */

static void fill_common_header(struct iso20_MessageHeaderType *h, const uint8_t *sid) {
    memset(h, 0, sizeof(*h));
    h->SessionID.bytesLen = 8;
    if (sid) memcpy(h->SessionID.bytes, sid, 8);
    h->TimeStamp = TEST_UNIX_TIME;
}

static void fill_dc_header(struct iso20_dc_MessageHeaderType *h, const uint8_t *sid) {
    memset(h, 0, sizeof(*h));
    h->SessionID.bytesLen = 8;
    if (sid) memcpy(h->SessionID.bytes, sid, 8);
    h->TimeStamp = TEST_UNIX_TIME;
}

static void build_session_setup_req(void) {
    init_iso20_exiDocument(g_doc);
    struct iso20_SessionSetupReqType *req = &g_doc->SessionSetupReq;
    memset(req, 0, sizeof(*req));
    g_doc->SessionSetupReq_isUsed = 1u;
    fill_common_header(&req->Header, NULL); /* all-zero SID: new session */
    size_t n = strlen(TEST_EVCCID);
    memcpy(req->EVCCID.characters, TEST_EVCCID, n);
    req->EVCCID.charactersLen = (uint16_t)n;
}

static void build_auth_setup_req(const uint8_t *sid) {
    init_iso20_exiDocument(g_doc);
    struct iso20_AuthorizationSetupReqType *req = &g_doc->AuthorizationSetupReq;
    memset(req, 0, sizeof(*req));
    g_doc->AuthorizationSetupReq_isUsed = 1u;
    fill_common_header(&req->Header, sid);
}

static void build_auth_req(const uint8_t *sid) {
    init_iso20_exiDocument(g_doc);
    struct iso20_AuthorizationReqType *req = &g_doc->AuthorizationReq;
    memset(req, 0, sizeof(*req));
    g_doc->AuthorizationReq_isUsed = 1u;
    fill_common_header(&req->Header, sid);
    req->SelectedAuthorizationService = iso20_authorizationType_EIM;
    req->EIM_AReqAuthorizationMode_isUsed = 1u;
}

static void build_service_discovery_req(const uint8_t *sid) {
    init_iso20_exiDocument(g_doc);
    struct iso20_ServiceDiscoveryReqType *req = &g_doc->ServiceDiscoveryReq;
    memset(req, 0, sizeof(*req));
    g_doc->ServiceDiscoveryReq_isUsed = 1u;
    fill_common_header(&req->Header, sid);
}

static void build_service_detail_req(const uint8_t *sid, uint16_t service_id) {
    init_iso20_exiDocument(g_doc);
    struct iso20_ServiceDetailReqType *req = &g_doc->ServiceDetailReq;
    memset(req, 0, sizeof(*req));
    g_doc->ServiceDetailReq_isUsed = 1u;
    fill_common_header(&req->Header, sid);
    req->ServiceID = service_id;
}

static void build_service_selection_req(const uint8_t *sid, uint16_t service_id,
                                        uint16_t parameter_set_id) {
    init_iso20_exiDocument(g_doc);
    struct iso20_ServiceSelectionReqType *req = &g_doc->ServiceSelectionReq;
    memset(req, 0, sizeof(*req));
    g_doc->ServiceSelectionReq_isUsed = 1u;
    fill_common_header(&req->Header, sid);
    req->SelectedEnergyTransferService.ServiceID = service_id;
    req->SelectedEnergyTransferService.ParameterSetID = parameter_set_id;
}

static void build_schedule_exchange_req(const uint8_t *sid, int dynamic) {
    init_iso20_exiDocument(g_doc);
    struct iso20_ScheduleExchangeReqType *req = &g_doc->ScheduleExchangeReq;
    memset(req, 0, sizeof(*req));
    g_doc->ScheduleExchangeReq_isUsed = 1u;
    fill_common_header(&req->Header, sid);
    req->MaximumSupportingPoints = 1024;
    if (dynamic) {
        req->Dynamic_SEReqControlMode_isUsed = 1u;
        req->Dynamic_SEReqControlMode.DepartureTime = 3600;
    } else {
        req->Scheduled_SEReqControlMode_isUsed = 1u;
    }
}

static void build_power_delivery_req(const uint8_t *sid, iso20_chargeProgressType progress) {
    init_iso20_exiDocument(g_doc);
    struct iso20_PowerDeliveryReqType *req = &g_doc->PowerDeliveryReq;
    memset(req, 0, sizeof(*req));
    g_doc->PowerDeliveryReq_isUsed = 1u;
    fill_common_header(&req->Header, sid);
    req->EVProcessing = iso20_processingType_Finished;
    req->ChargeProgress = progress;
}

static void build_session_stop_req(const uint8_t *sid, iso20_chargingSessionType action,
                                   const char *term_code) {
    init_iso20_exiDocument(g_doc);
    struct iso20_SessionStopReqType *req = &g_doc->SessionStopReq;
    memset(req, 0, sizeof(*req));
    g_doc->SessionStopReq_isUsed = 1u;
    fill_common_header(&req->Header, sid);
    req->ChargingSession = action;
    if (term_code) {
        size_t n = strlen(term_code);
        memcpy(req->EVTerminationCode.characters, term_code, n);
        req->EVTerminationCode.charactersLen = (uint16_t)n;
        req->EVTerminationCode_isUsed = 1u;
    }
}

static void set_dc_rat(struct iso20_dc_RationalNumberType *r, float v) {
    jpv2g_secc20_rat_from_float(v, &r->Exponent, &r->Value);
}

static void build_dc_cpd_req(const uint8_t *sid, int bpt) {
    init_iso20_dc_exiDocument(g_dc_doc);
    struct iso20_dc_DC_ChargeParameterDiscoveryReqType *req =
        &g_dc_doc->DC_ChargeParameterDiscoveryReq;
    memset(req, 0, sizeof(*req));
    g_dc_doc->DC_ChargeParameterDiscoveryReq_isUsed = 1u;
    fill_dc_header(&req->Header, sid);
    if (bpt) {
        req->BPT_DC_CPDReqEnergyTransferMode_isUsed = 1u;
        /* zeroed mandatory rationals encode fine; content is irrelevant */
    } else {
        req->DC_CPDReqEnergyTransferMode_isUsed = 1u;
        set_dc_rat(&req->DC_CPDReqEnergyTransferMode.EVMaximumChargePower, 150000.0f);
        set_dc_rat(&req->DC_CPDReqEnergyTransferMode.EVMinimumChargePower, 1000.0f);
        set_dc_rat(&req->DC_CPDReqEnergyTransferMode.EVMaximumChargeCurrent, 400.0f);
        set_dc_rat(&req->DC_CPDReqEnergyTransferMode.EVMinimumChargeCurrent, 2.0f);
        set_dc_rat(&req->DC_CPDReqEnergyTransferMode.EVMaximumVoltage, 500.0f);
        set_dc_rat(&req->DC_CPDReqEnergyTransferMode.EVMinimumVoltage, 250.0f);
        req->DC_CPDReqEnergyTransferMode.TargetSOC = 80;
        req->DC_CPDReqEnergyTransferMode.TargetSOC_isUsed = 1u;
    }
}

static void build_dc_cable_check_req(const uint8_t *sid) {
    init_iso20_dc_exiDocument(g_dc_doc);
    struct iso20_dc_DC_CableCheckReqType *req = &g_dc_doc->DC_CableCheckReq;
    memset(req, 0, sizeof(*req));
    g_dc_doc->DC_CableCheckReq_isUsed = 1u;
    fill_dc_header(&req->Header, sid);
}

static void build_dc_pre_charge_req(const uint8_t *sid, float target_v, float present_v) {
    init_iso20_dc_exiDocument(g_dc_doc);
    struct iso20_dc_DC_PreChargeReqType *req = &g_dc_doc->DC_PreChargeReq;
    memset(req, 0, sizeof(*req));
    g_dc_doc->DC_PreChargeReq_isUsed = 1u;
    fill_dc_header(&req->Header, sid);
    req->EVProcessing = iso20_dc_processingType_Ongoing;
    set_dc_rat(&req->EVTargetVoltage, target_v);
    set_dc_rat(&req->EVPresentVoltage, present_v);
}

static void build_dc_charge_loop_req(const uint8_t *sid, float target_v, float target_i,
                                     int meter_requested, int present_soc) {
    init_iso20_dc_exiDocument(g_dc_doc);
    struct iso20_dc_DC_ChargeLoopReqType *req = &g_dc_doc->DC_ChargeLoopReq;
    memset(req, 0, sizeof(*req));
    g_dc_doc->DC_ChargeLoopReq_isUsed = 1u;
    fill_dc_header(&req->Header, sid);
    req->MeterInfoRequested = meter_requested;
    set_dc_rat(&req->EVPresentVoltage, 399.0f);
    req->Scheduled_DC_CLReqControlMode_isUsed = 1u;
    set_dc_rat(&req->Scheduled_DC_CLReqControlMode.EVTargetCurrent, target_i);
    set_dc_rat(&req->Scheduled_DC_CLReqControlMode.EVTargetVoltage, target_v);
    if (present_soc >= 0) {
        req->DisplayParameters_isUsed = 1u;
        req->DisplayParameters.PresentSOC = (int8_t)present_soc;
        req->DisplayParameters.PresentSOC_isUsed = 1u;
    }
}

static void build_dc_welding_req(const uint8_t *sid, int finished) {
    init_iso20_dc_exiDocument(g_dc_doc);
    struct iso20_dc_DC_WeldingDetectionReqType *req = &g_dc_doc->DC_WeldingDetectionReq;
    memset(req, 0, sizeof(*req));
    g_dc_doc->DC_WeldingDetectionReq_isUsed = 1u;
    fill_dc_header(&req->Header, sid);
    req->EVProcessing = finished ? iso20_dc_processingType_Finished
                                 : iso20_dc_processingType_Ongoing;
}

/* -------------------------------------------------------- frame runner */

static int run_common_frame(jpv2g_secc20_t *s, jpv2g_secc20_disposition_t *disp) {
    exi_bitstream_t bs;
    exi_bitstream_init(&bs, g_frame, sizeof(g_frame), 0, NULL);
    if (encode_iso20_exiDocument(&bs, g_doc) != 0) return -1000;
    size_t req_len = exi_bitstream_get_length(&bs);
    size_t res_len = 0;
    uint16_t res_pid = 0;
    int rc = jpv2g_secc20_handle_frame(s, (uint16_t)JPV2G_PAYLOAD_EXI_20_MAINSTREAM,
                                       g_frame, req_len, g_res, sizeof(g_res),
                                       &res_len, &res_pid, disp);
    if (rc != 0) return rc;
    if (res_pid != (uint16_t)JPV2G_PAYLOAD_EXI_20_MAINSTREAM) return -1001;
    init_iso20_exiDocument(g_doc);
    exi_bitstream_init(&bs, g_res, res_len, 0, NULL);
    if (decode_iso20_exiDocument(&bs, g_doc) != 0) return -1002;
    return 0;
}

static int run_dc_frame(jpv2g_secc20_t *s, jpv2g_secc20_disposition_t *disp) {
    exi_bitstream_t bs;
    exi_bitstream_init(&bs, g_frame, sizeof(g_frame), 0, NULL);
    if (encode_iso20_dc_exiDocument(&bs, g_dc_doc) != 0) return -1000;
    size_t req_len = exi_bitstream_get_length(&bs);
    size_t res_len = 0;
    uint16_t res_pid = 0;
    int rc = jpv2g_secc20_handle_frame(s, (uint16_t)JPV2G_PAYLOAD_EXI_20_DC,
                                       g_frame, req_len, g_res, sizeof(g_res),
                                       &res_len, &res_pid, disp);
    if (rc != 0) return rc;
    if (res_pid != (uint16_t)JPV2G_PAYLOAD_EXI_20_DC) return -1001;
    init_iso20_dc_exiDocument(g_dc_doc);
    exi_bitstream_init(&bs, g_res, res_len, 0, NULL);
    if (decode_iso20_dc_exiDocument(&bs, g_dc_doc) != 0) return -1002;
    return 0;
}

/* Walk stages for the negative-test setup (coarse checks only; the happy
 * path test re-does this walk with full assertions). */
typedef enum {
    WALK_SESSION_ESTABLISHED, /* SessionSetup done -> AUTH_SETUP */
    WALK_AUTH_GRANTED,        /* ... -> SERVICE_DISCOVERY */
    WALK_DISCOVERY_DONE,      /* ... -> SERVICE_DETAIL */
    WALK_SELECTED,            /* ... -> DC_CPD */
    WALK_CPD_DONE,            /* ... -> SCHEDULE_EXCHANGE */
    WALK_SCHEDULED,           /* ... -> CABLE_CHECK */
    WALK_CABLE_OK,            /* ... -> PRE_CHARGE */
    WALK_PRECHARGED,          /* ... -> POWER_DELIVERY */
    WALK_CHARGING             /* PowerDelivery(Start) -> CHARGE_LOOP */
} walk_stage_t;

static int walk_to(jpv2g_secc20_t *s, test_ctx_t *ctx, walk_stage_t stage) {
    jpv2g_secc20_disposition_t disp;
    ctx->auth = JPV2G_SECC20_AUTH_GRANTED;
    ctx->cable = JPV2G_SECC20_CABLE_CHECK_FINISHED;

    build_session_setup_req();
    if (run_common_frame(s, &disp) != 0 || disp != JPV2G_SECC20_CONTINUE) return -1;
    if (!g_doc->SessionSetupRes_isUsed) return -1;
    memcpy(g_sid, g_doc->SessionSetupRes.Header.SessionID.bytes, 8);
    if (stage == WALK_SESSION_ESTABLISHED) return 0;

    build_auth_setup_req(g_sid);
    if (run_common_frame(s, &disp) != 0 || disp != JPV2G_SECC20_CONTINUE) return -2;
    build_auth_req(g_sid);
    if (run_common_frame(s, &disp) != 0 || disp != JPV2G_SECC20_CONTINUE) return -2;
    if (stage == WALK_AUTH_GRANTED) return 0;

    build_service_discovery_req(g_sid);
    if (run_common_frame(s, &disp) != 0 || disp != JPV2G_SECC20_CONTINUE) return -3;
    if (stage == WALK_DISCOVERY_DONE) return 0;

    build_service_selection_req(g_sid, JPV2G_SECC20_DC_SERVICE_ID,
                                JPV2G_SECC20_DC_PARAMETER_SET_ID);
    if (run_common_frame(s, &disp) != 0 || disp != JPV2G_SECC20_CONTINUE) return -4;
    if (stage == WALK_SELECTED) return 0;

    build_dc_cpd_req(g_sid, 0);
    if (run_dc_frame(s, &disp) != 0 || disp != JPV2G_SECC20_CONTINUE) return -5;
    if (stage == WALK_CPD_DONE) return 0;

    build_schedule_exchange_req(g_sid, 0);
    if (run_common_frame(s, &disp) != 0 || disp != JPV2G_SECC20_CONTINUE) return -6;
    if (stage == WALK_SCHEDULED) return 0;

    build_dc_cable_check_req(g_sid);
    if (run_dc_frame(s, &disp) != 0 || disp != JPV2G_SECC20_CONTINUE) return -7;
    if (stage == WALK_CABLE_OK) return 0;

    build_dc_pre_charge_req(g_sid, 400.0f, 10.0f);
    if (run_dc_frame(s, &disp) != 0 || disp != JPV2G_SECC20_CONTINUE) return -8;
    if (stage == WALK_PRECHARGED) return 0;

    build_power_delivery_req(g_sid, iso20_chargeProgressType_Start);
    if (run_common_frame(s, &disp) != 0 || disp != JPV2G_SECC20_CONTINUE) return -9;
    if (stage == WALK_CHARGING) return 0;

    return -100;
}

/* ---------------------------------------------------------- test cases */

static int test_happy_path(void) {
    jpv2g_secc20_t s;
    test_ctx_t ctx;
    test_ctx_reset(&ctx);
    if (assert_true(module_init(&s, &ctx) == 0, "module init") != 0) return 1;
    jpv2g_secc20_disposition_t disp;

    /* SessionSetup */
    build_session_setup_req();
    if (assert_true(run_common_frame(&s, &disp) == 0, "SessionSetup frame") != 0) return 1;
    if (assert_true(g_doc->SessionSetupRes_isUsed, "SessionSetupRes present") != 0) return 1;
    if (assert_true(g_doc->SessionSetupRes.ResponseCode ==
                        iso20_responseCodeType_OK_NewSessionEstablished,
                    "SessionSetupRes OK_NewSessionEstablished") != 0) return 1;
    if (assert_true(g_doc->SessionSetupRes.EVSEID.charactersLen == strlen(TEST_EVSE_ID) &&
                        memcmp(g_doc->SessionSetupRes.EVSEID.characters, TEST_EVSE_ID,
                               strlen(TEST_EVSE_ID)) == 0,
                    "SessionSetupRes EVSEID") != 0) return 1;
    if (assert_true(g_doc->SessionSetupRes.Header.SessionID.bytesLen == 8,
                    "SessionSetupRes 8-byte SessionID") != 0) return 1;
    memcpy(g_sid, g_doc->SessionSetupRes.Header.SessionID.bytes, 8);
    {
        int nonzero = 0;
        for (int i = 0; i < 8; ++i) nonzero |= g_sid[i];
        if (assert_true(nonzero != 0, "SessionID must be non-zero") != 0) return 1;
    }
    if (assert_true(g_doc->SessionSetupRes.Header.TimeStamp == TEST_UNIX_TIME,
                    "response TimeStamp from now_unix_s supplier") != 0) return 1;
    if (assert_true(ctx.evccid_ok, "EVCCID forwarded to controller hook") != 0) return 1;

    /* AuthorizationSetup */
    build_auth_setup_req(g_sid);
    if (assert_true(run_common_frame(&s, &disp) == 0, "AuthorizationSetup frame") != 0) return 1;
    if (assert_true(g_doc->AuthorizationSetupRes_isUsed &&
                        g_doc->AuthorizationSetupRes.ResponseCode == iso20_responseCodeType_OK,
                    "AuthorizationSetupRes OK") != 0) return 1;
    if (assert_true(g_doc->AuthorizationSetupRes.AuthorizationServices.arrayLen == 1 &&
                        g_doc->AuthorizationSetupRes.AuthorizationServices.array[0] ==
                            iso20_authorizationType_EIM &&
                        g_doc->AuthorizationSetupRes.EIM_ASResAuthorizationMode_isUsed &&
                        !g_doc->AuthorizationSetupRes.PnC_ASResAuthorizationMode_isUsed &&
                        g_doc->AuthorizationSetupRes.CertificateInstallationService == 0,
                    "AuthorizationSetupRes offers EIM only") != 0) return 1;
    if (assert_true(ctx.auth_required_calls == 1, "REQUIRE_AUTH hook fired") != 0) return 1;

    /* Authorization: pending then granted */
    build_auth_req(g_sid);
    if (assert_true(run_common_frame(&s, &disp) == 0, "Authorization frame (pending)") != 0) return 1;
    if (assert_true(g_doc->AuthorizationRes_isUsed &&
                        g_doc->AuthorizationRes.ResponseCode == iso20_responseCodeType_OK &&
                        g_doc->AuthorizationRes.EVSEProcessing ==
                            iso20_processingType_Ongoing_WaitingForCustomerInteraction,
                    "pending EIM auth answers Ongoing_WaitingForCustomerInteraction") != 0) return 1;
    ctx.auth = JPV2G_SECC20_AUTH_GRANTED;
    build_auth_req(g_sid);
    if (assert_true(run_common_frame(&s, &disp) == 0, "Authorization frame (granted)") != 0) return 1;
    if (assert_true(g_doc->AuthorizationRes.EVSEProcessing == iso20_processingType_Finished &&
                        g_doc->AuthorizationRes.ResponseCode == iso20_responseCodeType_OK,
                    "granted auth answers Finished (never held Ongoing)") != 0) return 1;

    /* ServiceDiscovery */
    build_service_discovery_req(g_sid);
    if (assert_true(run_common_frame(&s, &disp) == 0, "ServiceDiscovery frame") != 0) return 1;
    if (assert_true(g_doc->ServiceDiscoveryRes_isUsed &&
                        g_doc->ServiceDiscoveryRes.ResponseCode == iso20_responseCodeType_OK &&
                        g_doc->ServiceDiscoveryRes.ServiceRenegotiationSupported == 0 &&
                        g_doc->ServiceDiscoveryRes.EnergyTransferServiceList.Service.arrayLen == 1 &&
                        g_doc->ServiceDiscoveryRes.EnergyTransferServiceList.Service.array[0]
                                .ServiceID == JPV2G_SECC20_DC_SERVICE_ID,
                    "ServiceDiscoveryRes offers DC (ServiceID 2) only") != 0) return 1;

    /* ServiceDetail */
    build_service_detail_req(g_sid, JPV2G_SECC20_DC_SERVICE_ID);
    if (assert_true(run_common_frame(&s, &disp) == 0, "ServiceDetail frame") != 0) return 1;
    if (assert_true(g_doc->ServiceDetailRes_isUsed &&
                        g_doc->ServiceDetailRes.ResponseCode == iso20_responseCodeType_OK &&
                        g_doc->ServiceDetailRes.ServiceID == JPV2G_SECC20_DC_SERVICE_ID &&
                        g_doc->ServiceDetailRes.ServiceParameterList.ParameterSet.arrayLen == 1 &&
                        g_doc->ServiceDetailRes.ServiceParameterList.ParameterSet.array[0]
                                .ParameterSetID == JPV2G_SECC20_DC_PARAMETER_SET_ID &&
                        g_doc->ServiceDetailRes.ServiceParameterList.ParameterSet.array[0]
                                .Parameter.arrayLen == 4,
                    "ServiceDetailRes parameter set shape") != 0) return 1;
    {
        /* ControlMode=Scheduled must be among the four parameters. */
        int control_mode_ok = 0;
        const struct iso20_ParameterSetType *set =
            &g_doc->ServiceDetailRes.ServiceParameterList.ParameterSet.array[0];
        for (uint16_t i = 0; i < set->Parameter.arrayLen; ++i) {
            const struct iso20_ParameterType *p = &set->Parameter.array[i];
            if (p->Name.charactersLen == strlen("ControlMode") &&
                memcmp(p->Name.characters, "ControlMode", p->Name.charactersLen) == 0 &&
                p->intValue_isUsed && p->intValue == JPV2G_SECC20_PARAM_CONTROL_MODE) {
                control_mode_ok = 1;
            }
        }
        if (assert_true(control_mode_ok, "ControlMode=Scheduled advertised") != 0) return 1;
    }

    /* ServiceSelection */
    build_service_selection_req(g_sid, JPV2G_SECC20_DC_SERVICE_ID,
                                JPV2G_SECC20_DC_PARAMETER_SET_ID);
    if (assert_true(run_common_frame(&s, &disp) == 0, "ServiceSelection frame") != 0) return 1;
    if (assert_true(g_doc->ServiceSelectionRes_isUsed &&
                        g_doc->ServiceSelectionRes.ResponseCode == iso20_responseCodeType_OK,
                    "ServiceSelectionRes OK") != 0) return 1;

    /* DC_ChargeParameterDiscovery */
    build_dc_cpd_req(g_sid, 0);
    if (assert_true(run_dc_frame(&s, &disp) == 0, "DC_CPD frame") != 0) return 1;
    if (assert_true(g_dc_doc->DC_ChargeParameterDiscoveryRes_isUsed &&
                        g_dc_doc->DC_ChargeParameterDiscoveryRes.ResponseCode ==
                            iso20_dc_responseCodeType_OK &&
                        g_dc_doc->DC_ChargeParameterDiscoveryRes
                            .DC_CPDResEnergyTransferMode_isUsed,
                    "DC_CPDRes OK with DC mode") != 0) return 1;
    {
        const struct iso20_dc_DC_CPDResEnergyTransferModeType *m =
            &g_dc_doc->DC_ChargeParameterDiscoveryRes.DC_CPDResEnergyTransferMode;
        if (assert_true(near(jpv2g_secc20_rat_to_float(m->EVSEMaximumChargePower.Exponent,
                                                       m->EVSEMaximumChargePower.Value),
                             60000.0f, 60.0f),
                        "EVSEMaximumChargePower ~= 60 kW") != 0) return 1;
        if (assert_true(near(jpv2g_secc20_rat_to_float(m->EVSEMaximumVoltage.Exponent,
                                                       m->EVSEMaximumVoltage.Value),
                             1000.0f, 1.0f),
                        "EVSEMaximumVoltage ~= 1000 V") != 0) return 1;
    }
    if (assert_true(near(ctx.last_ev_limits.ev_max_voltage_v, 500.0f, 1.0f) &&
                        ctx.last_ev_limits.target_soc_percent == 80,
                    "EV limits + TargetSOC forwarded to controller") != 0) return 1;

    /* ScheduleExchange */
    build_schedule_exchange_req(g_sid, 0);
    if (assert_true(run_common_frame(&s, &disp) == 0, "ScheduleExchange frame") != 0) return 1;
    if (assert_true(g_doc->ScheduleExchangeRes_isUsed &&
                        g_doc->ScheduleExchangeRes.ResponseCode == iso20_responseCodeType_OK &&
                        g_doc->ScheduleExchangeRes.EVSEProcessing == iso20_processingType_Finished &&
                        g_doc->ScheduleExchangeRes.Scheduled_SEResControlMode_isUsed,
                    "ScheduleExchangeRes Finished + Scheduled mode") != 0) return 1;
    {
        const struct iso20_Scheduled_SEResControlModeType *m =
            &g_doc->ScheduleExchangeRes.Scheduled_SEResControlMode;
        if (assert_true(m->ScheduleTuple.arrayLen == 1 &&
                            m->ScheduleTuple.array[0].ScheduleTupleID ==
                                JPV2G_SECC20_SCHEDULE_TUPLE_ID,
                        "exactly one schedule tuple, ID 1") != 0) return 1;
        const struct iso20_PowerScheduleType *ps =
            &m->ScheduleTuple.array[0].ChargingSchedule.PowerSchedule;
        if (assert_true(ps->TimeAnchor == TEST_UNIX_TIME, "TimeAnchor = now") != 0) return 1;
        if (assert_true(ps->PowerScheduleEntries.PowerScheduleEntry.arrayLen == 1 &&
                            ps->PowerScheduleEntries.PowerScheduleEntry.array[0].Duration ==
                                JPV2G_SECC20_SCHEDULE_DURATION_S,
                        "one entry, 86400 s duration") != 0) return 1;
        const struct iso20_RationalNumberType *pw =
            &ps->PowerScheduleEntries.PowerScheduleEntry.array[0].Power;
        if (assert_true(near(jpv2g_secc20_rat_to_float(pw->Exponent, pw->Value),
                             60000.0f, 60.0f),
                        "schedule power = EVSE max W") != 0) return 1;
    }

    /* DC_CableCheck: Ongoing, then Finished */
    build_dc_cable_check_req(g_sid);
    if (assert_true(run_dc_frame(&s, &disp) == 0, "CableCheck frame (ongoing)") != 0) return 1;
    if (assert_true(g_dc_doc->DC_CableCheckRes_isUsed &&
                        g_dc_doc->DC_CableCheckRes.ResponseCode == iso20_dc_responseCodeType_OK &&
                        g_dc_doc->DC_CableCheckRes.EVSEProcessing ==
                            iso20_dc_processingType_Ongoing,
                    "CableCheckRes Ongoing while isolation runs") != 0) return 1;
    ctx.cable = JPV2G_SECC20_CABLE_CHECK_FINISHED;
    build_dc_cable_check_req(g_sid);
    if (assert_true(run_dc_frame(&s, &disp) == 0, "CableCheck frame (finished)") != 0) return 1;
    if (assert_true(g_dc_doc->DC_CableCheckRes.EVSEProcessing ==
                        iso20_dc_processingType_Finished,
                    "CableCheckRes Finished after IMD pass") != 0) return 1;
    if (assert_true(ctx.cable_check_started_calls == 1,
                    "START_CABLE_CHECK signalled exactly once") != 0) return 1;

    /* DC_PreCharge */
    ctx.present_v = 398.0f;
    build_dc_pre_charge_req(g_sid, 400.0f, 10.0f);
    if (assert_true(run_dc_frame(&s, &disp) == 0, "PreCharge frame") != 0) return 1;
    if (assert_true(g_dc_doc->DC_PreChargeRes_isUsed &&
                        g_dc_doc->DC_PreChargeRes.ResponseCode == iso20_dc_responseCodeType_OK,
                    "PreChargeRes OK") != 0) return 1;
    if (assert_true(near(jpv2g_secc20_rat_to_float(
                             g_dc_doc->DC_PreChargeRes.EVSEPresentVoltage.Exponent,
                             g_dc_doc->DC_PreChargeRes.EVSEPresentVoltage.Value),
                         398.0f, 0.5f),
                    "PreChargeRes echoes controller present voltage") != 0) return 1;
    if (assert_true(near(ctx.last_precharge_target_v, 400.0f, 0.5f),
                    "EVTargetVoltage forwarded to controller") != 0) return 1;

    /* PowerDelivery(Start) */
    build_power_delivery_req(g_sid, iso20_chargeProgressType_Start);
    if (assert_true(run_common_frame(&s, &disp) == 0, "PowerDelivery(Start) frame") != 0) return 1;
    if (assert_true(g_doc->PowerDeliveryRes_isUsed &&
                        g_doc->PowerDeliveryRes.ResponseCode == iso20_responseCodeType_OK,
                    "PowerDeliveryRes(Start) OK") != 0) return 1;
    if (assert_true(ctx.contactor_close_calls == 1, "contactor close requested") != 0) return 1;

    /* DC_ChargeLoop x3 */
    ctx.present_v = 400.5f;
    ctx.present_i = 100.25f;
    ctx.current_limit_achieved = 1;
    for (int i = 0; i < 3; ++i) {
        const float target_i = 100.0f + (float)i;
        const int want_meter = (i == 1);
        if (i == 2) ctx.stop = JPV2G_SECC20_STOP_TERMINATE;
        build_dc_charge_loop_req(g_sid, 400.0f, target_i, want_meter, 55);
        if (assert_true(run_dc_frame(&s, &disp) == 0, "ChargeLoop frame") != 0) return 1;
        if (assert_true(g_dc_doc->DC_ChargeLoopRes_isUsed &&
                            g_dc_doc->DC_ChargeLoopRes.ResponseCode ==
                                iso20_dc_responseCodeType_OK &&
                            disp == JPV2G_SECC20_CONTINUE,
                        "ChargeLoopRes OK") != 0) return 1;
        const struct iso20_dc_DC_ChargeLoopResType *res = &g_dc_doc->DC_ChargeLoopRes;
        if (assert_true(near(jpv2g_secc20_rat_to_float(res->EVSEPresentVoltage.Exponent,
                                                       res->EVSEPresentVoltage.Value),
                             400.5f, 0.1f) &&
                            near(jpv2g_secc20_rat_to_float(res->EVSEPresentCurrent.Exponent,
                                                           res->EVSEPresentCurrent.Value),
                                 100.25f, 0.1f),
                        "present V/I echoed from controller telemetry") != 0) return 1;
        if (assert_true(res->EVSECurrentLimitAchieved == 1 &&
                            res->EVSEPowerLimitAchieved == 0,
                        "limit-achieved flags mirror telemetry") != 0) return 1;
        if (assert_true(res->Scheduled_DC_CLResControlMode_isUsed &&
                            res->Scheduled_DC_CLResControlMode.EVSEMaximumChargePower_isUsed &&
                            near(jpv2g_secc20_rat_to_float(
                                     res->Scheduled_DC_CLResControlMode.EVSEMaximumChargePower
                                         .Exponent,
                                     res->Scheduled_DC_CLResControlMode.EVSEMaximumChargePower
                                         .Value),
                                 60000.0f, 60.0f),
                        "live EVSE limits in Scheduled_DC_CLResControlMode") != 0) return 1;
        if (assert_true(near(ctx.last_target_i, target_i, 0.01f) &&
                            near(ctx.last_target_v, 400.0f, 0.5f),
                        "-20 CurrentDemand targets forwarded each tick") != 0) return 1;
        if (assert_true(res->MeterInfo_isUsed == (want_meter ? 1u : 0u),
                        "MeterInfo only when requested") != 0) return 1;
        if (want_meter) {
            if (assert_true(res->MeterInfo.ChargedEnergyReadingWh == 12345u &&
                                res->MeterInfo.MeterID.charactersLen == 2 &&
                                memcmp(res->MeterInfo.MeterID.characters, "M1", 2) == 0,
                            "MeterInfo content") != 0) return 1;
        }
        if (i == 2) {
            if (assert_true(res->EVSEStatus_isUsed &&
                                res->EVSEStatus.EVSENotification ==
                                    iso20_dc_evseNotificationType_Terminate &&
                                res->EVSEStatus.NotificationMaxDelay == 0,
                            "controller stop surfaces EVSEStatus Terminate") != 0) return 1;
        } else {
            if (assert_true(!res->EVSEStatus_isUsed,
                            "no EVSEStatus without a stop request") != 0) return 1;
        }
        if (assert_true(ctx.last_present_soc == 55, "PresentSOC forwarded") != 0) return 1;
    }
    if (assert_true(ctx.charge_loop_started_calls == 1,
                    "CHARGE_LOOP_STARTED signalled once") != 0) return 1;

    /* PowerDelivery(Stop) */
    ctx.stop = JPV2G_SECC20_STOP_NONE;
    build_power_delivery_req(g_sid, iso20_chargeProgressType_Stop);
    if (assert_true(run_common_frame(&s, &disp) == 0, "PowerDelivery(Stop) frame") != 0) return 1;
    if (assert_true(g_doc->PowerDeliveryRes.ResponseCode == iso20_responseCodeType_OK &&
                        disp == JPV2G_SECC20_CONTINUE,
                    "PowerDeliveryRes(Stop) OK") != 0) return 1;
    if (assert_true(ctx.charge_loop_finished_calls == 1 && ctx.contactor_open_calls == 1,
                    "stop opens contactor + signals loop finished") != 0) return 1;

    /* DC_WeldingDetection: ongoing, then finished */
    ctx.present_v = 42.0f;
    build_dc_welding_req(g_sid, 0);
    if (assert_true(run_dc_frame(&s, &disp) == 0, "Welding frame (ongoing)") != 0) return 1;
    if (assert_true(g_dc_doc->DC_WeldingDetectionRes_isUsed &&
                        g_dc_doc->DC_WeldingDetectionRes.ResponseCode ==
                            iso20_dc_responseCodeType_OK &&
                        near(jpv2g_secc20_rat_to_float(
                                 g_dc_doc->DC_WeldingDetectionRes.EVSEPresentVoltage.Exponent,
                                 g_dc_doc->DC_WeldingDetectionRes.EVSEPresentVoltage.Value),
                             42.0f, 0.1f),
                    "WeldingDetectionRes reports present voltage") != 0) return 1;
    build_dc_welding_req(g_sid, 1);
    if (assert_true(run_dc_frame(&s, &disp) == 0, "Welding frame (finished)") != 0) return 1;

    /* SessionStop(Terminate) */
    build_session_stop_req(g_sid, iso20_chargingSessionType_Terminate, "EV_SHUTDOWN");
    if (assert_true(run_common_frame(&s, &disp) == 0, "SessionStop frame") != 0) return 1;
    if (assert_true(g_doc->SessionStopRes_isUsed &&
                        g_doc->SessionStopRes.ResponseCode == iso20_responseCodeType_OK,
                    "SessionStopRes OK") != 0) return 1;
    if (assert_true(disp == JPV2G_SECC20_DONE_STOPPED, "terminate disposition") != 0) return 1;
    if (assert_true(strcmp(ctx.last_term_code, "EV_SHUTDOWN") == 0,
                    "EVTerminationCode forwarded") != 0) return 1;
    if (assert_true(s.state == JPV2G_SECC20_STATE_ENDED, "session ended") != 0) return 1;
    return 0;
}

static int test_unknown_session(void) {
    jpv2g_secc20_t s;
    test_ctx_t ctx;
    test_ctx_reset(&ctx);
    if (assert_true(module_init(&s, &ctx) == 0, "module init") != 0) return 1;
    if (assert_true(walk_to(&s, &ctx, WALK_SESSION_ESTABLISHED) == 0, "walk") != 0) return 1;

    uint8_t bad_sid[8];
    memcpy(bad_sid, g_sid, 8);
    bad_sid[0] ^= 0xFFu;
    build_auth_setup_req(bad_sid);
    jpv2g_secc20_disposition_t disp;
    if (assert_true(run_common_frame(&s, &disp) == 0, "frame handled") != 0) return 1;
    if (assert_true(g_doc->AuthorizationSetupRes_isUsed &&
                        g_doc->AuthorizationSetupRes.ResponseCode ==
                            iso20_responseCodeType_FAILED_UnknownSession,
                    "wrong SID answers FAILED_UnknownSession in own Res type") != 0) return 1;
    if (assert_true(memcmp(g_doc->AuthorizationSetupRes.Header.SessionID.bytes, g_sid, 8) == 0,
                    "response header carries OUR session id") != 0) return 1;
    if (assert_true(disp == JPV2G_SECC20_DONE_FAILED, "terminates after send") != 0) return 1;
    return 0;
}

static int test_sequence_error(void) {
    jpv2g_secc20_t s;
    test_ctx_t ctx;
    test_ctx_reset(&ctx);
    if (assert_true(module_init(&s, &ctx) == 0, "module init") != 0) return 1;
    if (assert_true(walk_to(&s, &ctx, WALK_SESSION_ESTABLISHED) == 0, "walk") != 0) return 1;

    /* CableCheck long before its state: FAILED_SequenceError in the DC
     * schema's own response type, on the DC payload id. */
    build_dc_cable_check_req(g_sid);
    jpv2g_secc20_disposition_t disp;
    if (assert_true(run_dc_frame(&s, &disp) == 0, "frame handled") != 0) return 1;
    if (assert_true(g_dc_doc->DC_CableCheckRes_isUsed &&
                        g_dc_doc->DC_CableCheckRes.ResponseCode ==
                            iso20_dc_responseCodeType_FAILED_SequenceError,
                    "out-of-state request answers FAILED_SequenceError in own Res") != 0) return 1;
    if (assert_true(disp == JPV2G_SECC20_DONE_FAILED, "terminates after send") != 0) return 1;
    return 0;
}

static int test_bpt_cpd_rejected(void) {
    jpv2g_secc20_t s;
    test_ctx_t ctx;
    test_ctx_reset(&ctx);
    if (assert_true(module_init(&s, &ctx) == 0, "module init") != 0) return 1;
    if (assert_true(walk_to(&s, &ctx, WALK_SELECTED) == 0, "walk") != 0) return 1;

    build_dc_cpd_req(g_sid, 1);
    jpv2g_secc20_disposition_t disp;
    if (assert_true(run_dc_frame(&s, &disp) == 0, "frame handled") != 0) return 1;
    if (assert_true(g_dc_doc->DC_ChargeParameterDiscoveryRes_isUsed &&
                        g_dc_doc->DC_ChargeParameterDiscoveryRes.ResponseCode ==
                            iso20_dc_responseCodeType_FAILED_WrongChargeParameter,
                    "BPT CPD answers FAILED_WrongChargeParameter") != 0) return 1;
    if (assert_true(disp == JPV2G_SECC20_DONE_FAILED, "terminates") != 0) return 1;
    return 0;
}

static int test_dynamic_schedule_rejected(void) {
    jpv2g_secc20_t s;
    test_ctx_t ctx;
    test_ctx_reset(&ctx);
    if (assert_true(module_init(&s, &ctx) == 0, "module init") != 0) return 1;
    if (assert_true(walk_to(&s, &ctx, WALK_CPD_DONE) == 0, "walk") != 0) return 1;

    build_schedule_exchange_req(g_sid, 1);
    jpv2g_secc20_disposition_t disp;
    if (assert_true(run_common_frame(&s, &disp) == 0, "frame handled") != 0) return 1;
    if (assert_true(g_doc->ScheduleExchangeRes_isUsed &&
                        g_doc->ScheduleExchangeRes.ResponseCode == iso20_responseCodeType_FAILED,
                    "Dynamic ScheduleExchange answers FAILED") != 0) return 1;
    if (assert_true(disp == JPV2G_SECC20_DONE_FAILED, "terminates") != 0) return 1;
    return 0;
}

static int test_wrong_service_selection(void) {
    jpv2g_secc20_t s;
    test_ctx_t ctx;
    test_ctx_reset(&ctx);
    if (assert_true(module_init(&s, &ctx) == 0, "module init") != 0) return 1;
    if (assert_true(walk_to(&s, &ctx, WALK_DISCOVERY_DONE) == 0, "walk") != 0) return 1;

    build_service_selection_req(g_sid, 5 /* AC_BPT: never offered */, 0);
    jpv2g_secc20_disposition_t disp;
    if (assert_true(run_common_frame(&s, &disp) == 0, "frame handled") != 0) return 1;
    if (assert_true(g_doc->ServiceSelectionRes_isUsed &&
                        g_doc->ServiceSelectionRes.ResponseCode ==
                            iso20_responseCodeType_FAILED_NoEnergyTransferServiceSelected,
                    "wrong ServiceID answers FAILED_NoEnergyTransferServiceSelected") != 0)
        return 1;
    if (assert_true(disp == JPV2G_SECC20_DONE_FAILED, "terminates") != 0) return 1;
    return 0;
}

static int test_session_stop_renegotiation(void) {
    jpv2g_secc20_t s;
    test_ctx_t ctx;
    test_ctx_reset(&ctx);
    if (assert_true(module_init(&s, &ctx) == 0, "module init") != 0) return 1;
    if (assert_true(walk_to(&s, &ctx, WALK_SESSION_ESTABLISHED) == 0, "walk") != 0) return 1;

    build_session_stop_req(g_sid, iso20_chargingSessionType_ServiceRenegotiation, NULL);
    jpv2g_secc20_disposition_t disp;
    if (assert_true(run_common_frame(&s, &disp) == 0, "frame handled") != 0) return 1;
    if (assert_true(g_doc->SessionStopRes_isUsed &&
                        g_doc->SessionStopRes.ResponseCode ==
                            iso20_responseCodeType_FAILED_NoServiceRenegotiationSupported,
                    "ServiceRenegotiation answers FAILED_NoServiceRenegotiationSupported") != 0)
        return 1;
    if (assert_true(disp == JPV2G_SECC20_DONE_FAILED, "terminates") != 0) return 1;
    return 0;
}

static int test_standby_warning_non_terminal(void) {
    jpv2g_secc20_t s;
    test_ctx_t ctx;
    test_ctx_reset(&ctx);
    if (assert_true(module_init(&s, &ctx) == 0, "module init") != 0) return 1;
    if (assert_true(walk_to(&s, &ctx, WALK_CHARGING) == 0, "walk") != 0) return 1;

    build_power_delivery_req(g_sid, iso20_chargeProgressType_Standby);
    jpv2g_secc20_disposition_t disp;
    if (assert_true(run_common_frame(&s, &disp) == 0, "frame handled") != 0) return 1;
    if (assert_true(g_doc->PowerDeliveryRes_isUsed &&
                        g_doc->PowerDeliveryRes.ResponseCode ==
                            iso20_responseCodeType_WARNING_StandbyNotAllowed,
                    "Standby answers WARNING_StandbyNotAllowed") != 0) return 1;
    if (assert_true(disp == JPV2G_SECC20_CONTINUE, "warning never terminates") != 0) return 1;

    /* Session continues: a charge-loop tick still answers OK. */
    build_dc_charge_loop_req(g_sid, 400.0f, 100.0f, 0, -1);
    if (assert_true(run_dc_frame(&s, &disp) == 0, "loop after warning") != 0) return 1;
    if (assert_true(g_dc_doc->DC_ChargeLoopRes_isUsed &&
                        g_dc_doc->DC_ChargeLoopRes.ResponseCode == iso20_dc_responseCodeType_OK,
                    "charge loop still alive after Standby warning") != 0) return 1;
    return 0;
}

static int test_rational_round_trip(void) {
    /* {input, expect exact} — clamped cases only need bounded relative error. */
    static const struct { float in; int exact; } cases[] = {
        {0.0f, 1}, {500.0f, 1}, {60000.0f, 1}, {1000.5f, 1},
        {-750.5f, 1}, {3276800.0f, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int8_t e = 0;
        int16_t m = 0;
        jpv2g_secc20_rat_from_float(cases[i].in, &e, &m);
        if (assert_true(m >= -32767 && m <= 32767, "mantissa within int16") != 0) return 1;
        float back = jpv2g_secc20_rat_to_float(e, m);
        if (cases[i].exact) {
            if (assert_true(near(back, cases[i].in, 0.0001f), "exact round trip") != 0) {
                fprintf(stderr, "  case %f -> {%d,%d} -> %f\n",
                        (double)cases[i].in, (int)e, (int)m, (double)back);
                return 1;
            }
        } else {
            float mag = cases[i].in < 0 ? -cases[i].in : cases[i].in;
            if (assert_true(near(back, cases[i].in, 0.001f * mag),
                            "clamped round trip within 0.1%") != 0) return 1;
        }
    }
    /* Plan example: 500 must keep the smallest |Exponent| representation. */
    int8_t e = 0;
    int16_t m = 0;
    jpv2g_secc20_rat_from_float(500.0f, &e, &m);
    if (assert_true(e == 0 && m == 500, "500 -> {500, 0}") != 0) return 1;
    jpv2g_secc20_rat_from_float(60000.0f, &e, &m);
    if (assert_true(e == 1 && m == 6000, "60000 -> {6000, 1}") != 0) return 1;
    return 0;
}

/* ------------------------------------------------ SAPP selection tests */

static void set_offer(struct appHand_AppProtocolType *ap, const char *ns,
                      uint32_t major, uint32_t minor, uint8_t schema, uint8_t prio) {
    memset(ap, 0, sizeof(*ap));
    size_t n = strlen(ns);
    memcpy(ap->ProtocolNamespace.characters, ns, n);
    ap->ProtocolNamespace.charactersLen = (uint16_t)n;
    ap->VersionNumberMajor = major;
    ap->VersionNumberMinor = minor;
    ap->SchemaID = schema;
    ap->Priority = prio;
}

static int run_sapp(struct appHand_supportedAppProtocolReq *offers,
                    struct appHand_supportedAppProtocolRes *res_out) {
    jpv2g_secc_t secc;
    jpv2g_secc_request_t request;
    uint8_t response[512];
    size_t response_len = 0;
    memset(&secc, 0, sizeof(secc));
    memset(&request, 0, sizeof(request));
    jpv2g_secc_config_default(&secc.cfg);
    request.protocol = JPV2G_PROTOCOL_UNKNOWN;
    request.body = offers;
    int rc = jpv2g_secc_default_handle(&secc, JPV2G_SUPP_APP_PROTOCOL_REQ, &request,
                                       response, sizeof(response), &response_len);
    if (rc != 0) return rc;
    return jpv2g_cbv2g_decode_sapp_res(response, response_len, res_out);
}

static int test_sapp_selection(void) {
    jpv2g_secc20_t s;
    test_ctx_t ctx;
    test_ctx_reset(&ctx);
    if (assert_true(module_init(&s, &ctx) == 0, "module init") != 0) return 1;

    struct appHand_supportedAppProtocolReq offers;
    struct appHand_supportedAppProtocolRes res;

    /* Regression: a -2-only offer still selects -2, module registered. */
    jpv2g_secc20_set_stream_session(&s);
    init_appHand_supportedAppProtocolReq(&offers);
    offers.AppProtocol.arrayLen = 1;
    set_offer(&offers.AppProtocol.array[0], "urn:iso:15118:2:2013:MsgDef", 2, 0, 1, 1);
    if (assert_true(run_sapp(&offers, &res) == 0, "SAPP -2 only") != 0) return 1;
    if (assert_true(res.ResponseCode == appHand_responseCodeType_OK_SuccessfulNegotiation &&
                        res.SchemaID_isUsed && res.SchemaID == 1,
                    "-2-only offer still selects -2") != 0) return 1;

    /* Dual offer with the EV preferring -20 (lower Priority wins). */
    init_appHand_supportedAppProtocolReq(&offers);
    offers.AppProtocol.arrayLen = 2;
    set_offer(&offers.AppProtocol.array[0], JPV2G_SECC20_NAMESPACE_DC, 1, 0, 10, 1);
    set_offer(&offers.AppProtocol.array[1], "urn:iso:15118:2:2013:MsgDef", 2, 0, 1, 2);
    if (assert_true(run_sapp(&offers, &res) == 0, "SAPP dual offer") != 0) return 1;
    if (assert_true(res.ResponseCode == appHand_responseCodeType_OK_SuccessfulNegotiation &&
                        res.SchemaID_isUsed && res.SchemaID == 10,
                    "-20 DC offer selected when flag on + registered") != 0) return 1;

    /* -20 AC namespace as the only offer must be rejected outright. */
    init_appHand_supportedAppProtocolReq(&offers);
    offers.AppProtocol.arrayLen = 1;
    set_offer(&offers.AppProtocol.array[0], "urn:iso:std:iso:15118:-20:AC", 1, 0, 11, 1);
    if (assert_true(run_sapp(&offers, &res) == 0, "SAPP -20 AC only") != 0) return 1;
    if (assert_true(res.ResponseCode == appHand_responseCodeType_Failed_NoNegotiation,
                    "-20 AC namespace rejected (Failed_NoNegotiation)") != 0) return 1;

    /* Wrong -20 major version must not match either. */
    init_appHand_supportedAppProtocolReq(&offers);
    offers.AppProtocol.arrayLen = 1;
    set_offer(&offers.AppProtocol.array[0], JPV2G_SECC20_NAMESPACE_DC, 2, 0, 12, 1);
    if (assert_true(run_sapp(&offers, &res) == 0, "SAPP -20 wrong major") != 0) return 1;
    if (assert_true(res.ResponseCode == appHand_responseCodeType_Failed_NoNegotiation,
                    "-20 DC with major 2 rejected") != 0) return 1;

    /* Without a registered module the -20 offer must fall back to -2. */
    jpv2g_secc20_set_stream_session(NULL);
    init_appHand_supportedAppProtocolReq(&offers);
    offers.AppProtocol.arrayLen = 2;
    set_offer(&offers.AppProtocol.array[0], JPV2G_SECC20_NAMESPACE_DC, 1, 0, 10, 1);
    set_offer(&offers.AppProtocol.array[1], "urn:iso:15118:2:2013:MsgDef", 2, 0, 1, 2);
    if (assert_true(run_sapp(&offers, &res) == 0, "SAPP unregistered") != 0) return 1;
    if (assert_true(res.ResponseCode == appHand_responseCodeType_OK_SuccessfulNegotiation &&
                        res.SchemaID_isUsed && res.SchemaID == 1,
                    "unwired module: EV falls back to -2") != 0) return 1;
    jpv2g_secc20_set_stream_session(&s);
    return 0;
}

/* ---------------------------------------------- stream-loop end-to-end
 *
 * Drives the actual secc.c stream dispatcher over a socketpair (the same
 * pre-write + SHUT_WR pattern the -2 stream tests use): SAP dual offer
 * selects -20, SessionSetupReq (payload 0x8002) is routed to the module, and
 * a SessionStopReq carrying a WRONG SessionID (the real one is random and
 * unknowable at pre-write time) must come back as FAILED_UnknownSession in
 * its own Res type before the stream terminates with -EPROTO. This is the
 * one test that exercises SAP-reset wiring, 0x8002 routing, response
 * framing, and the [V2G20-1643] hold's early exit on peer close.
 */
static int test_stream_end_to_end(void) {
    jpv2g_codec_ctx *codec = NULL;
    jpv2g_secc_config_t cfg;
    jpv2g_secc_t secc;
    jpv2g_secc20_t s20;
    test_ctx_t ctx;
    int sockets[2] = {-1, -1};
    exi_bitstream_t bs;
    uint8_t frame[JPV2G_V2GTP_HEADER_LEN + 4096];
    size_t frame_len = 0;

    test_ctx_reset(&ctx);
    if (assert_true(module_init(&s20, &ctx) == 0, "module init") != 0) return 1;
    jpv2g_secc20_set_stream_session(&s20);

    jpv2g_secc_config_default(&cfg);
    if (assert_true(jpv2g_codec_init(&codec) == 0, "codec init") != 0) return 1;
    if (assert_true(jpv2g_secc_init(&secc, &cfg, codec) == 0, "secc init") != 0) {
        jpv2g_codec_free(codec);
        return 1;
    }
    if (assert_true(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0, "socketpair") != 0) {
        jpv2g_codec_free(codec);
        return 1;
    }

    /* Frame 1: SAP dual offer, EV prefers -20 DC. */
    struct appHand_exiDocument app;
    init_appHand_exiDocument(&app);
    app.supportedAppProtocolReq_isUsed = 1u;
    init_appHand_supportedAppProtocolReq(&app.supportedAppProtocolReq);
    app.supportedAppProtocolReq.AppProtocol.arrayLen = 2;
    set_offer(&app.supportedAppProtocolReq.AppProtocol.array[0],
              JPV2G_SECC20_NAMESPACE_DC, 1, 0, 10, 1);
    set_offer(&app.supportedAppProtocolReq.AppProtocol.array[1],
              "urn:iso:15118:2:2013:MsgDef", 2, 0, 1, 2);
    exi_bitstream_init(&bs, g_frame, sizeof(g_frame), 0, NULL);
    if (assert_true(encode_appHand_exiDocument(&bs, &app) == 0, "encode SAP") != 0) return 1;
    if (assert_true(jpv2g_v2gtp_build(JPV2G_PAYLOAD_EXI, g_frame,
                                      exi_bitstream_get_length(&bs),
                                      frame, sizeof(frame), &frame_len) == 0,
                    "frame SAP") != 0) return 1;
    if (assert_true(send(sockets[1], frame, frame_len, 0) == (ssize_t)frame_len,
                    "send SAP") != 0) return 1;

    /* Frame 2: SessionSetupReq on the -20 mainstream payload id. */
    build_session_setup_req();
    exi_bitstream_init(&bs, g_frame, sizeof(g_frame), 0, NULL);
    if (assert_true(encode_iso20_exiDocument(&bs, g_doc) == 0, "encode SessionSetup") != 0)
        return 1;
    if (assert_true(jpv2g_v2gtp_build(JPV2G_PAYLOAD_EXI_20_MAINSTREAM, g_frame,
                                      exi_bitstream_get_length(&bs),
                                      frame, sizeof(frame), &frame_len) == 0,
                    "frame SessionSetup") != 0) return 1;
    if (assert_true(send(sockets[1], frame, frame_len, 0) == (ssize_t)frame_len,
                    "send SessionSetup") != 0) return 1;

    /* Frame 3: SessionStopReq with a deliberately wrong (all-0xAA) SID. */
    uint8_t bogus_sid[8];
    memset(bogus_sid, 0xAA, sizeof(bogus_sid));
    build_session_stop_req(bogus_sid, iso20_chargingSessionType_Terminate, NULL);
    exi_bitstream_init(&bs, g_frame, sizeof(g_frame), 0, NULL);
    if (assert_true(encode_iso20_exiDocument(&bs, g_doc) == 0, "encode SessionStop") != 0)
        return 1;
    if (assert_true(jpv2g_v2gtp_build(JPV2G_PAYLOAD_EXI_20_MAINSTREAM, g_frame,
                                      exi_bitstream_get_length(&bs),
                                      frame, sizeof(frame), &frame_len) == 0,
                    "frame SessionStop") != 0) return 1;
    if (assert_true(send(sockets[1], frame, frame_len, 0) == (ssize_t)frame_len,
                    "send SessionStop") != 0) return 1;
    shutdown(sockets[1], SHUT_WR); /* lets the teardown hold exit early */

    const int rc = jpv2g_secc_handle_client(&secc, sockets[0], 200);
    if (assert_true(rc == -EPROTO,
                    "stream ends -EPROTO after the FAILED_UnknownSession send") != 0) return 1;
    close(sockets[0]);

    /* Collect the three response frames. */
    uint8_t rx[3 * sizeof(frame)];
    size_t rx_len = 0;
    for (;;) {
        ssize_t got = recv(sockets[1], rx + rx_len, sizeof(rx) - rx_len, 0);
        if (got <= 0) break;
        rx_len += (size_t)got;
    }
    close(sockets[1]);
    jpv2g_codec_free(codec);

    size_t off = 0;
    jpv2g_v2gtp_t msg;

    /* Response 1: SAP res selecting the -20 schema. */
    if (assert_true(jpv2g_v2gtp_parse(rx + off, rx_len - off, &msg) == 0 &&
                        msg.payload_type == JPV2G_PAYLOAD_EXI,
                    "SAP res framed 0x8001") != 0) return 1;
    {
        struct appHand_supportedAppProtocolRes sapp_res;
        if (assert_true(jpv2g_cbv2g_decode_sapp_res(msg.payload, msg.payload_length,
                                                    &sapp_res) == 0 &&
                            sapp_res.ResponseCode ==
                                appHand_responseCodeType_OK_SuccessfulNegotiation &&
                            sapp_res.SchemaID_isUsed && sapp_res.SchemaID == 10,
                        "stream selected the -20 DC offer") != 0) return 1;
    }
    off += JPV2G_V2GTP_HEADER_LEN + msg.payload_length;

    /* Response 2: SessionSetupRes on 0x8002 with a fresh session id. */
    if (assert_true(jpv2g_v2gtp_parse(rx + off, rx_len - off, &msg) == 0 &&
                        msg.payload_type == JPV2G_PAYLOAD_EXI_20_MAINSTREAM,
                    "SessionSetupRes framed 0x8002") != 0) return 1;
    uint8_t live_sid[8];
    {
        init_iso20_exiDocument(g_doc);
        exi_bitstream_init(&bs, (uint8_t *)msg.payload, msg.payload_length, 0, NULL);
        if (assert_true(decode_iso20_exiDocument(&bs, g_doc) == 0 &&
                            g_doc->SessionSetupRes_isUsed &&
                            g_doc->SessionSetupRes.ResponseCode ==
                                iso20_responseCodeType_OK_NewSessionEstablished,
                        "stream SessionSetupRes OK") != 0) return 1;
        memcpy(live_sid, g_doc->SessionSetupRes.Header.SessionID.bytes, 8);
    }
    off += JPV2G_V2GTP_HEADER_LEN + msg.payload_length;

    /* Response 3: SessionStopRes carrying FAILED_UnknownSession + OUR sid. */
    if (assert_true(jpv2g_v2gtp_parse(rx + off, rx_len - off, &msg) == 0 &&
                        msg.payload_type == JPV2G_PAYLOAD_EXI_20_MAINSTREAM,
                    "SessionStopRes framed 0x8002") != 0) return 1;
    {
        init_iso20_exiDocument(g_doc);
        exi_bitstream_init(&bs, (uint8_t *)msg.payload, msg.payload_length, 0, NULL);
        if (assert_true(decode_iso20_exiDocument(&bs, g_doc) == 0 &&
                            g_doc->SessionStopRes_isUsed &&
                            g_doc->SessionStopRes.ResponseCode ==
                                iso20_responseCodeType_FAILED_UnknownSession,
                        "wrong SID answered FAILED_UnknownSession on the wire") != 0) return 1;
        if (assert_true(memcmp(g_doc->SessionStopRes.Header.SessionID.bytes, live_sid, 8) == 0,
                        "stream response header carries the live sid") != 0) return 1;
    }
    return 0;
}

/* --------------------------------------------------------------- main */

int main(void) {
    int failures = 0;

    g_ws_common = (struct iso20_exiDocument *)malloc(sizeof(*g_ws_common));
    g_ws_dc = (struct iso20_dc_exiDocument *)malloc(sizeof(*g_ws_dc));
    g_doc = (struct iso20_exiDocument *)malloc(sizeof(*g_doc));
    g_dc_doc = (struct iso20_dc_exiDocument *)malloc(sizeof(*g_dc_doc));
    if (!g_ws_common || !g_ws_dc || !g_doc || !g_dc_doc) {
        fprintf(stderr, "OOM allocating iso20 documents\n");
        return 1;
    }

    struct {
        const char *name;
        int (*fn)(void);
    } tests[] = {
        {"rational_round_trip", test_rational_round_trip},
        {"sapp_selection", test_sapp_selection},
        {"happy_path", test_happy_path},
        {"unknown_session", test_unknown_session},
        {"sequence_error", test_sequence_error},
        {"bpt_cpd_rejected", test_bpt_cpd_rejected},
        {"dynamic_schedule_rejected", test_dynamic_schedule_rejected},
        {"wrong_service_selection", test_wrong_service_selection},
        {"session_stop_renegotiation", test_session_stop_renegotiation},
        {"standby_warning_non_terminal", test_standby_warning_non_terminal},
        {"stream_end_to_end", test_stream_end_to_end},
    };
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        int rc = tests[i].fn();
        printf("%-32s %s\n", tests[i].name, rc == 0 ? "PASS" : "FAIL");
        failures += rc;
    }

    free(g_ws_common);
    free(g_ws_dc);
    free(g_doc);
    free(g_dc_doc);

    if (failures) {
        fprintf(stderr, "%d ISO20 test(s) failed\n", failures);
        return 1;
    }
    printf("All ISO20 tests passed\n");
    return 0;
}

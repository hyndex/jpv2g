/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2026 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

/*
 * ISO 15118-20 DC SECC module — DC + EIM + Scheduled control mode only.
 *
 * This module owns the -20 session state machine for one physical connector:
 * SessionSetup -> AuthorizationSetup -> Authorization -> ServiceDiscovery ->
 * ServiceDetail -> ServiceSelection -> DC_ChargeParameterDiscovery ->
 * ScheduleExchange -> DC_CableCheck -> DC_PreCharge -> PowerDelivery ->
 * DC_ChargeLoop -> PowerDelivery(Stop) -> DC_WeldingDetection -> SessionStop.
 *
 * Design contract (see the 2026-07 -20 build plan, Part 1):
 *  - Every decision that involves a real electrical value or an authorization
 *    verdict is delegated to the controller through the callback table below.
 *    The module NEVER invents electrical values: a missing callback yields the
 *    safe default (auth pending, zero limits, isolation ongoing, 0 V / 0 A,
 *    contactor refused, no stop request).
 *  - The two generated document workspaces (struct iso20_exiDocument is
 *    hundreds of KB) are caller-provided pointers: firmware allocates them
 *    from PSRAM, host tests malloc() them. The module never declares one by
 *    value in static or automatic storage.
 *  - ResponseCode >= FAILED terminates the session after the response is
 *    sent; WARNING_* codes never terminate. A per-message SessionID mismatch
 *    answers FAILED_UnknownSession in that request's own response type; a
 *    request outside the current state's accept set answers
 *    FAILED_SequenceError the same way. No decodable -20 request is silently
 *    dropped.
 *
 * When built without JPV2G_ENABLE_ISO20 every entry point is a -ENOTSUP stub
 * (same pattern as the no-mbedtls branch of src/tls.c) so callers can link
 * unconditionally.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Generated cbv2g documents; only ever handled by pointer here. */
struct iso20_exiDocument;
struct iso20_dc_exiDocument;

/* ---- Pinned -20 numeric contract (build plan section 1.8) ---- */

/* V2GTP payload ids (also mirrored in jpv2g/v2gtp.h payload enum). */
#define JPV2G_SECC20_PAYLOAD_SAP        0x8001u
#define JPV2G_SECC20_PAYLOAD_MAINSTREAM 0x8002u /* iso20 CommonMessages */
#define JPV2G_SECC20_PAYLOAD_DC         0x8004u /* iso20 DC */

/* SupportedAppProtocol: exact namespace + version gate for the -20 DC offer. */
#define JPV2G_SECC20_NAMESPACE_DC       "urn:iso:std:iso:15118:-20:DC"
#define JPV2G_SECC20_SAP_MAJOR          1u
#define JPV2G_SECC20_SAP_MINOR          0u

/* Timers. SEQUENCE is the blanket per-message timer (deliberately NOT
 * tightened inside the charge loop — see build plan 1.4 FLAG resolution). */
#define JPV2G_SECC20_SEQUENCE_TIMEOUT_MS    60000u
#define JPV2G_SECC20_SE_ONGOING_TIMEOUT_MS  55000u
#define JPV2G_SECC20_EIM_ONGOING_TIMEOUT_MS 180000u
/* [V2G20-1643]: hold the TCP link open after the final response. */
#define JPV2G_SECC20_TEARDOWN_HOLD_MS       5000u

/* Service offer: DC (ServiceID 2), one parameter set. */
#define JPV2G_SECC20_DC_SERVICE_ID          2u
#define JPV2G_SECC20_DC_PARAMETER_SET_ID    0u
#define JPV2G_SECC20_PARAM_CONNECTOR        2  /* Extended / CCS2 inlet */
#define JPV2G_SECC20_PARAM_CONTROL_MODE     1  /* Scheduled */
#define JPV2G_SECC20_PARAM_MOBILITY_NEEDS   1  /* ProvidedByEvcc (forced with Scheduled) */
#define JPV2G_SECC20_PARAM_PRICING          0  /* NoPricing */

/* ScheduleExchange: one tuple, one entry. */
#define JPV2G_SECC20_SCHEDULE_TUPLE_ID      1u
#define JPV2G_SECC20_SCHEDULE_DURATION_S    86400u

#define JPV2G_SECC20_SESSION_ID_LEN         8u
#define JPV2G_SECC20_EVSEID_MAX             64u

/* ---- Controller-facing value carriers ---- */

/* EVSE-side DC limits, fetched at CPD and re-fetched every charge-loop tick
 * (the live fetch is the runtime smart-charging limit channel). */
typedef struct {
    float max_charge_power_w;
    float min_charge_power_w;
    float max_charge_current_a;
    float min_charge_current_a;
    float max_voltage_v;
    float min_voltage_v;
} jpv2g_secc20_dc_limits_t;

/* EV-side limits reported in DC_ChargeParameterDiscoveryReq. */
typedef struct {
    float ev_max_charge_power_w;
    float ev_min_charge_power_w;
    float ev_max_charge_current_a;
    float ev_min_charge_current_a;
    float ev_max_voltage_v;
    float ev_min_voltage_v;
    int target_soc_percent; /* -1 when the EV omitted TargetSOC */
} jpv2g_secc20_ev_limits_t;

/* Present-output telemetry. The *_limit_achieved flags must be true iff the
 * respective commanded limit is actively clamping delivery — they are echoed
 * verbatim into DC_ChargeLoopRes and must not be left hardwired false. */
typedef struct {
    float voltage_v;
    float current_a;
    bool power_limit_achieved;
    bool current_limit_achieved;
    bool voltage_limit_achieved;
} jpv2g_secc20_present_t;

typedef enum {
    JPV2G_SECC20_AUTH_PENDING = 0,
    JPV2G_SECC20_AUTH_GRANTED = 1,
    JPV2G_SECC20_AUTH_REJECTED = 2
} jpv2g_secc20_auth_status_t;

typedef enum {
    JPV2G_SECC20_CABLE_CHECK_ONGOING = 0,
    JPV2G_SECC20_CABLE_CHECK_FINISHED = 1, /* only after a real IMD pass */
    JPV2G_SECC20_CABLE_CHECK_FAULT = 2
} jpv2g_secc20_cable_check_status_t;

typedef enum {
    JPV2G_SECC20_STOP_NONE = 0,
    JPV2G_SECC20_STOP_TERMINATE = 1, /* EVSEStatus Terminate in ChargeLoopRes */
    JPV2G_SECC20_STOP_PAUSE = 2      /* EVSEStatus Pause in ChargeLoopRes */
} jpv2g_secc20_stop_request_t;

/* What the caller must do with the connection after a handled frame. */
typedef enum {
    JPV2G_SECC20_CONTINUE = 0,     /* response written; keep the stream */
    JPV2G_SECC20_DONE_STOPPED = 1, /* SessionStop(Terminate) answered OK */
    JPV2G_SECC20_DONE_PAUSED = 2,  /* SessionStop(Pause) answered OK */
    JPV2G_SECC20_DONE_FAILED = 3   /* a FAILED_* response was sent */
} jpv2g_secc20_disposition_t;

/* Session FSM state, exposed for diagnostics and tests. */
typedef enum {
    JPV2G_SECC20_STATE_SESSION_SETUP = 0,
    JPV2G_SECC20_STATE_AUTH_SETUP,
    JPV2G_SECC20_STATE_AUTHORIZATION,
    JPV2G_SECC20_STATE_SERVICE_DISCOVERY,
    JPV2G_SECC20_STATE_SERVICE_DETAIL,
    JPV2G_SECC20_STATE_DC_CPD,
    JPV2G_SECC20_STATE_SCHEDULE_EXCHANGE,
    JPV2G_SECC20_STATE_CABLE_CHECK,
    JPV2G_SECC20_STATE_PRE_CHARGE,
    JPV2G_SECC20_STATE_POWER_DELIVERY,
    JPV2G_SECC20_STATE_CHARGE_LOOP,
    JPV2G_SECC20_STATE_WELDING,
    JPV2G_SECC20_STATE_SESSION_STOP,
    JPV2G_SECC20_STATE_ENDED
} jpv2g_secc20_state_t;

/*
 * Controller hook table. Every pointer is optional; user_ctx is passed to
 * each call. "on_*" hooks are fire-and-forget reports to the controller,
 * matching the -2/DIN EVT/FEEDBACK lanes listed in build plan section 1.7.
 * The remaining hooks are polled decisions with the safe defaults documented
 * at the top of this header.
 */
typedef struct {
    void *user_ctx;

    /* -- reports (module -> controller) -- */
    void (*on_evccid)(void *ctx, const char *evccid, size_t len);
    void (*on_auth_required)(void *ctx); /* AuthorizationSetupRes sent: kick OCPP Authorize */
    void (*on_ev_limits)(void *ctx, const jpv2g_secc20_ev_limits_t *limits);
    void (*on_cable_check_started)(void *ctx);
    void (*on_precharge_target)(void *ctx, float ev_target_voltage_v, float ev_present_voltage_v);
    void (*on_charge_loop_started)(void *ctx);
    void (*on_charge_targets)(void *ctx,
                              float ev_target_voltage_v,
                              float ev_target_current_a,
                              float ev_present_voltage_v);
    void (*on_display_parameters)(void *ctx, int present_soc_percent); /* -1 if absent */
    void (*on_charge_loop_finished)(void *ctx); /* PowerDelivery(Stop): DC_OPEN_CONTACTOR lane */
    void (*on_ev_termination)(void *ctx,
                              const char *code, size_t code_len,
                              const char *explanation, size_t explanation_len);

    /* -- polled decisions (controller -> module) -- */
    jpv2g_secc20_auth_status_t (*auth_status)(void *ctx);          /* NULL: pending */
    int (*get_dc_limits)(void *ctx, jpv2g_secc20_dc_limits_t *out); /* NULL/<0: zero limits */
    jpv2g_secc20_cable_check_status_t (*cable_check_status)(void *ctx); /* NULL: ongoing */
    int (*get_present)(void *ctx, jpv2g_secc20_present_t *out);    /* NULL/<0: 0 V / 0 A */
    /* Close (true) / open (false) the DC contactors. Return 0 once the
     * requested position is confirmed; non-zero refuses the close and fails
     * PowerDelivery(Start) with FAILED_ContactorError. NULL: refused. */
    int (*contactor_set)(void *ctx, bool close_contactor);
    jpv2g_secc20_stop_request_t (*stop_request)(void *ctx);        /* NULL: none */
    /* MeterInfo source: return 0 with a fresh reading to include MeterInfo
     * when the EV requested it; non-zero (or NULL) omits it. */
    int (*get_meter)(void *ctx, char *meter_id, size_t meter_id_size,
                     uint64_t *charged_energy_wh);
} jpv2g_secc20_callbacks_t;

typedef struct {
    /* EVSEID for SessionSetupRes, e.g. "IN*JPT*E12345*1". Empty string picks
     * the library default so a misconfigured build still answers validly. */
    char evse_id[JPV2G_SECC20_EVSEID_MAX];
    /* Wall-clock supplier for the mandatory Header.TimeStamp (unix seconds).
     * NULL -> 0 (schema-valid; the PLC has no RTC until the controller feeds
     * an epoch). Tests supply a fixed value. */
    uint64_t (*now_unix_s)(void *ctx);
    void *now_ctx;
    /* Caller-owned decode/encode workspaces (PSRAM on firmware, malloc on
     * host). Both must stay valid for the lifetime of the session object. */
    struct iso20_exiDocument *common_workspace;
    struct iso20_dc_exiDocument *dc_workspace;
    jpv2g_secc20_callbacks_t callbacks;
} jpv2g_secc20_config_t;

typedef struct {
    jpv2g_secc20_config_t cfg;
    jpv2g_secc20_state_t state;
    uint8_t session_id[JPV2G_SECC20_SESSION_ID_LEN];
    bool session_established;
    bool contactor_closed;
    bool cable_check_started;
    bool charge_loop_started;
    /* Most recent ResponseCode value sent (iso20[_dc]_responseCodeType value
     * space; the two enums are value-identical). Diagnostics only. */
    int last_response_code;
    /* Timer deadlines on the jpv2g_now_monotonic_ms() clock; 0 = unarmed. */
    int64_t sequence_deadline_ms;
    int64_t se_ongoing_deadline_ms;
    int64_t eim_ongoing_deadline_ms;
} jpv2g_secc20_t;

/* Initialize a session object. Fails -EINVAL without both workspaces. */
int jpv2g_secc20_init(jpv2g_secc20_t *s, const jpv2g_secc20_config_t *cfg);

/* Re-arm for a fresh -20 session on the current connection. Called by the
 * stream dispatcher right after the SupportedAppProtocolRes that selected
 * -20 went out (this also arms the SEQUENCE timer, which must not run before
 * SupportedAppProtocolReq). */
void jpv2g_secc20_reset(jpv2g_secc20_t *s);

/*
 * Handle one post-SAP -20 request frame (EXI payload only, no V2GTP header).
 * payload_id is the request's V2GTP payload id (0x8002 or 0x8004); the
 * response is written to out and *out_payload_id reports the id to frame it
 * with (always the request's own id).
 *
 * Returns 0 with *disposition set when a response was produced (including
 * FAILED responses — the caller must still send them before acting on the
 * disposition). Negative errno otherwise:
 *   -EBADMSG   frame did not decode (caller applies its undecodable-frame
 *              tolerance policy; nothing to send)
 *   -ETIMEDOUT the 60 s SEQUENCE timer had already expired (send nothing,
 *              tear down per [V2G20-1643])
 */
int jpv2g_secc20_handle_frame(jpv2g_secc20_t *s,
                              uint16_t payload_id,
                              const uint8_t *exi, size_t exi_len,
                              uint8_t *out, size_t out_cap, size_t *out_len,
                              uint16_t *out_payload_id,
                              jpv2g_secc20_disposition_t *disposition);

/*
 * Process-wide active-session registry consumed by the secc.c stream
 * dispatcher (one SECC per MCU, mirroring the single g_secc instance the
 * firmware runs). The SupportedAppProtocol handler only matches the -20 DC
 * namespace while a session object is registered, so a flag-on build whose
 * firmware never wired the module behaves exactly like a flag-off build
 * (the EV falls back to -2/DIN).
 */
void jpv2g_secc20_set_stream_session(jpv2g_secc20_t *s);
jpv2g_secc20_t *jpv2g_secc20_stream_session(void);

const char *jpv2g_secc20_state_name(jpv2g_secc20_state_t state);

/*
 * RationalNumber helpers (Value int16 mantissa, Exponent int8, value =
 * Value * 10^Exponent). rat_from_float picks the smallest |Exponent| that
 * represents the value exactly when possible (500 -> {500,0}, 60000 ->
 * {6000,1}, 1000.5 -> {10005,-1}) and otherwise clamps the mantissa into
 * +/-32767 by raising the exponent (3,276,800 -> {3277,3}).
 */
void jpv2g_secc20_rat_from_float(float value, int8_t *exponent, int16_t *mantissa);
float jpv2g_secc20_rat_to_float(int8_t exponent, int16_t mantissa);

#ifdef __cplusplus
}
#endif

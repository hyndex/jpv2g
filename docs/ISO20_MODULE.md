# ISO 15118-20 DC SECC module (`secc_iso20`) + TLS tier

Status (2026-07-20): **implemented and host-tested; NOT wired into the
PLC firmware.** `plc_firmware` defines neither `JPV2G_ENABLE_ISO20` nor
`HAVE_MBEDTLS` (verified in `platformio.ini` build_flags), so on the
charger every entry point in this module is a `-ENOTSUP` stub and EVs
negotiate -2/DIN exactly as before.

Line anchors are approximate — grep the symbol.

---

## 1. Enable flag and default-build guarantee

`-DJPV2G_ENABLE_ISO20=ON` (CMake, default **OFF**). Two layers make the
default build byte-identical in behavior:

1. `src/secc_iso20.c` is always compiled; without the flag its body
   collapses to `-ENOTSUP` stubs (same pattern as the no-mbedtls branch
   of `src/tls.c`), so callers link unconditionally.
2. Even with the flag ON, the SupportedAppProtocol handler matches the
   -20 DC namespace **only while a session object is registered** via
   `jpv2g_secc20_set_stream_session()` (~secc.c:138). A flag-on build
   whose firmware never wired the module behaves exactly like a flag-off
   build — the EV falls back to -2/DIN.

Flag-on additionally compiles exactly 6 generated codec files
(`iso20_CommonMessages_*` + `iso20_DC_*`, `JPV2G_ISO20_CODEC_SOURCES` in
`CMakeLists.txt`) — never the upstream `cbv2g_iso20` target, which drags
in AC/ACDP/WPT (~77k dead LOC).

## 2. What is / is not implemented

**Implemented — DC + EIM + Scheduled control mode only:**

```
SessionSetup -> AuthorizationSetup -> Authorization -> ServiceDiscovery ->
ServiceDetail -> ServiceSelection -> DC_ChargeParameterDiscovery ->
ScheduleExchange -> DC_CableCheck -> DC_PreCharge -> PowerDelivery ->
DC_ChargeLoop -> PowerDelivery(Stop) -> DC_WeldingDetection -> SessionStop
```

**Not implemented (rejected, not silently accepted):** BPT, Plug&Charge
(contract auth), Dynamic control mode, AC, ACDP, WPT. Regression tests:
`test_bpt_cpd_rejected`, `test_dynamic_schedule_rejected`,
`test_wrong_service_selection` (`tests/jpv2g_iso20_test.c`).

Termination rules: any `ResponseCode >= FAILED` terminates the session
after the response is sent; `WARNING_*` never terminates
(`test_standby_warning_non_terminal`). A per-message SessionID mismatch
answers `FAILED_UnknownSession` in that request's own response type; a
request outside the current state's accept set answers
`FAILED_SequenceError` the same way. No decodable -20 request is
silently dropped.

## 3. Pinned numeric contract (`secc_iso20.h`)

| Constant | Value | Note |
|---|---|---|
| `JPV2G_SECC20_PAYLOAD_SAP / _MAINSTREAM / _DC` | `0x8001 / 0x8002 / 0x8004` | V2GTP payload ids (mirrored in `v2gtp.h`) |
| `JPV2G_SECC20_NAMESPACE_DC` | `urn:iso:std:iso:15118:-20:DC`, SAP version 1.0 | exact SAP match gate |
| `JPV2G_SECC20_SEQUENCE_TIMEOUT_MS` | 60 000 | blanket per-message timer; deliberately NOT tightened inside the charge loop |
| `JPV2G_SECC20_SE_ONGOING_TIMEOUT_MS` | 55 000 | ScheduleExchange Ongoing cap |
| `JPV2G_SECC20_EIM_ONGOING_TIMEOUT_MS` | 180 000 | Authorization(EIM) Ongoing cap |
| `JPV2G_SECC20_TEARDOWN_HOLD_MS` | 5 000 | `[V2G20-1643]`: hold TCP open after the final response (§6) |
| DC service | ServiceID 2, one parameter set: Connector=2 (CCS2), ControlMode=1 (Scheduled), MobilityNeeds=1 (ProvidedByEvcc), Pricing=0 | |
| Schedule | one tuple (ID 1), one entry, 86 400 s | |

RationalNumber helpers: `jpv2g_secc20_rat_from_float()` picks the
smallest `|Exponent|` that represents the value exactly when possible
(500 → {500,0}; 1000.5 → {10005,−1}) and otherwise clamps the int16
mantissa by raising the exponent. `jpv2g_secc20_rat_to_float()` inverts.

## 4. `jpv2g_secc20_callbacks_t` — the controller contract

Design rule: **the module never invents electrical values.** Every
electrical or authorization decision is delegated; every pointer is
optional and a missing callback yields the safe default. `user_ctx` is
passed to each call.

Reports (module → controller, fire-and-forget — the -20 mirror of the
-2/DIN EVT/FEEDBACK lanes):

| Callback | Fired when |
|---|---|
| `on_evccid` | SessionSetupReq (EVCCID bytes) |
| `on_auth_required` | AuthorizationSetupRes sent — kick OCPP Authorize |
| `on_ev_limits` | DC_ChargeParameterDiscoveryReq (EV limit set + TargetSOC, −1 when omitted) |
| `on_cable_check_started` | DC_CableCheckReq first seen |
| `on_precharge_target` | each DC_PreChargeReq (EV target + present voltage) |
| `on_charge_loop_started` | charge loop entered |
| `on_charge_targets` | each DC_ChargeLoopReq (target V/I, present V) |
| `on_display_parameters` | DisplayParameters present (SOC, −1 if absent) |
| `on_charge_loop_finished` | PowerDelivery(Stop) — the DC_OPEN_CONTACTOR lane |
| `on_ev_termination` | EV-supplied termination code/explanation |

Polled decisions (controller → module) with safe defaults when NULL:

| Callback | NULL / failure default | Consumed at |
|---|---|---|
| `auth_status` | `AUTH_PENDING` | Authorization loop (EIM Ongoing cap 180 s) |
| `get_dc_limits` | **zero limits** | CPD and re-fetched every charge-loop tick — this live fetch is the runtime smart-charging limit channel |
| `cable_check_status` | `ONGOING` — `FINISHED` only after a real IMD pass | DC_CableCheck loop |
| `get_present` | 0 V / 0 A | PreCharge, ChargeLoop, WeldingDetection |
| `contactor_set` | close **refused** (→ `FAILED_ContactorError` at PowerDelivery(Start)); open allowed — refusing an OPEN when nothing is wired would be inventing a fault (~secc_iso20.c:296) | PowerDelivery |
| `stop_request` | `STOP_NONE` (`TERMINATE`→EVSEStatus Terminate, `PAUSE`→Pause in ChargeLoopRes) | charge loop |
| `get_meter` | omit MeterInfo | when the EV requested it |

The `*_limit_achieved` flags in `jpv2g_secc20_present_t` must be true
iff the respective commanded limit is actively clamping delivery — they
are echoed verbatim into DC_ChargeLoopRes; do not hardwire false.

## 5. Caller-provided workspaces (PSRAM on ESP32)

`jpv2g_secc20_config_t` carries two workspace pointers —
`struct iso20_exiDocument *common_workspace` and
`struct iso20_dc_exiDocument *dc_workspace`. The generated documents are
**hundreds of KB**: firmware must allocate them from PSRAM, host tests
`malloc()` them. Both must outlive the session object;
`jpv2g_secc20_init()` fails `-EINVAL` without both. The module never
declares one in static or automatic storage — enforced by the
`jpv2g_no_automatic_iso20_exi_documents` ctest guard.

Other config: `evse_id` (empty → library default, so a misconfigured
build still answers validly) and `now_unix_s` (NULL → 0, schema-valid;
the PLC has no RTC until the controller feeds an epoch).

## 6. Frame handling and stream integration

`jpv2g_secc20_handle_frame(s, payload_id, exi, exi_len, out, out_cap,
&out_len, &out_payload_id, &disposition)` handles one post-SAP request
frame (EXI payload only). Returns 0 with a response to send — including
FAILED responses, which the caller must still send before acting on the
disposition (`CONTINUE` / `DONE_STOPPED` / `DONE_PAUSED` /
`DONE_FAILED`). Negative rc:

- `-EBADMSG` — frame did not decode; the caller applies the same bounded
  undecodable-frame tolerance as -2/DIN (6 consecutive, mid-session
  only; ~secc.c:2020). Also used for the one soft spot: a PnC-probing
  CertificateInstallationReq whose skeleton Res fails to encode.
- `-ETIMEDOUT` — the 60 s SEQUENCE timer had already expired: send
  nothing, tear down per `[V2G20-1643]`.

The `secc.c` stream dispatcher integrates the module as follows: after a
SupportedAppProtocolRes selecting -20 goes out, `jpv2g_secc20_reset()`
re-arms the session (this is also where the SEQUENCE timer legitimately
starts); subsequent `0x8002`/`0x8004` frames route to the module while
`0x8001` still falls through so a SAP retry stays possible. Every
terminal path — SessionStop, FAILED, sequence-timeout — runs the
teardown hold: keep TCP open ~5 s discarding whatever the EV still
sends, so a slow EVCC never sees its last request answered by a RST.

Registry: `jpv2g_secc20_set_stream_session()` /
`jpv2g_secc20_stream_session()` — one process-wide active session,
mirroring the single `g_secc` the firmware runs.
`jpv2g_secc20_state_name()` exposes FSM state for diagnostics.

## 7. TLS tier (and the -20 production blocker)

Current tier (tier-1, `-DJPV2G_HAVE_MBEDTLS=ON`, default **OFF**):
server-side **TLS 1.2** per the ISO 15118-2 profile — `src/tls.c` pins
the `[V2G2-602]` TLS 1.2 ciphersuites and `MBEDTLS_SSL_MINOR_VERSION_3`
(~tls.c:249), mbedtls 2.28. Without the flag every wrap returns
`-ENOTSUP` (TLS refused; plaintext -2/DIN unaffected).

**Blocker:** ISO 15118-20 mandates TLS 1.3, which this tier does not
provide. The -20 module is therefore host-tested over plaintext streams
only; wiring it into a production charger requires the TLS 1.3 tier
first. Do not ship -20 on the strength of this module alone.

Credentials — `jpv2g_tls_credentials_t` (`tls.h`), the in-memory PEM
path and the only workable one on the PLC (no filesystem PKI):

- Each buffer must be NUL-terminated and its `*_len` must **count the
  NUL** (mbedtls 2.x PEM rule; `sizeof` of a string literal satisfies
  both). `jpv2g_tls_credentials_validate()` enforces this in every
  build, mbedtls or not.
- `ca_pem == NULL` means no client auth; then `ca_pem_len` must be 0.
- Populate `jpv2g_secc_config_t.tls_mem_creds` and the SECC accept path
  uses `jpv2g_tls_server_wrap_mem()` automatically, taking precedence
  over the `tls_*_path` files (~secc.c:2404). Handshake deadline:
  `JPV2G_TLS_HANDSHAKE_TIMEOUT_MS` (15 s) — a peer that sends a
  ClientHello prefix and goes silent must not pin the HLC worker.

**Dev-grade only.** The struct is mbedtls-free so it lives in the SECC
config unconditionally; without `HAVE_MBEDTLS` the buffers are simply
never read. Production credential provisioning (per-device certs in NVS,
rotation, V2G root trust) is out of scope of this tier.

## 8. Wiring checklist (when the firmware adopts -20)

1. Define `JPV2G_ENABLE_ISO20` in the firmware build (and only compile
   the 6 codec files listed in `JPV2G_ISO20_CODEC_SOURCES`).
2. Allocate both workspaces from PSRAM at HLC startup; fail startup, not
   mid-session, if PSRAM is short.
3. Fill `jpv2g_secc20_callbacks_t` from the same controller-fed state
   that backs the -2/DIN FEEDBACK consumption — the module's polled
   hooks are the -20 equivalents of `CTRL LIMITS` / FEEDBACK fields.
4. `jpv2g_secc20_init()` + `jpv2g_secc20_set_stream_session()` before
   the listener accepts; the SAP gate does the rest.
5. TLS 1.3 tier first (see §7).

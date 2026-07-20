# SECC embedding API (DIN 70121 / ISO 15118-2)

Audience: a firmware or controller integrator embedding the jpv2g SECC —
the code that accepts the EV's TCP connection and answers its V2G
requests. The wire-facing behavior of the shipping charger (UART EVT
lanes, session choreography) lives in `plc_firmware/docs/`; this document
covers the library boundary itself.

All line anchors below are approximate ("~line") and drift — grep the
function name.

---

## 1. Lifecycle

```
jpv2g_secc_config_default(&cfg);        /* config.c */
jpv2g_secc_init(&secc, &cfg, codec);    /* zeroes state, binds codec */
secc.handle_request = my_dispatch;      /* optional override, §4 */
secc.user_ctx = &my_ctx;
jpv2g_secc_start_udp(&secc);            /* SDP responder */
jpv2g_secc_start_tcp(&secc);            /* V2G listener */
/* per accepted client fd: */
rc = jpv2g_secc_handle_client_detect_ex(&secc, fd, first_timeout_ms,
                                        timeout_ms, &reason, &saw_stop);
jpv2g_secc_retire_session(&secc);       /* on EVERY teardown, §6 */
/* shutdown: */
jpv2g_secc_stop(&secc);
```

The stream engine (`jpv2g_secc_handle_stream`, `secc.c`) is synchronous:
one blocking loop per client connection, intended to run on a dedicated
worker task. The PLC firmware runs exactly one `jpv2g_secc_t` (`g_secc`)
on its HLC worker.

## 2. `jpv2g_secc_config_t` (config.h / config.c)

| Field | Type | Default (`jpv2g_secc_config_default`) | Notes |
|---|---|---|---|
| `network_interface` | `char[32]` | auto-resolved; falls back to `"pl0"` on ESP32 | the QCA7000 lwIP netif on the PLC |
| `free_charging` | `bool` | `false` | consulted by the default ServiceDiscovery handler unless `evse_ctl.is_free_charging` overrides |
| `private_environment` | `bool` | `false` | |
| `use_tls` | `bool` | `true` | advertised in the SDP response; plaintext still served on `tcp_port` |
| `supported_auth_modes` | `char[32]` | `"Contract,ExternalPayment"` | |
| `supported_energy_modes` | `char[128]` | `"AC_three_phase_core,AC_single_phase_core,DC_core,DC_extended,DC_combo_core"` | membership checked at CPD; DIN additionally pins the ONE mode advertised in ServiceDiscovery as a per-session contract (`din_advertised_energy_transfer_*`) |
| `tls_port` / `tcp_port` | `int` | `15118` / `15118` | |
| `tls_cert_path` / `tls_key_path` / `tls_ca_path` | `char[256]` | `certs/secc_chain.crt.pem` etc. (base overridable via `-DJPV2G_PKI_BASE`) | host/dev only — the PLC has no filesystem PKI |
| `tls_mem_creds` | `jpv2g_tls_credentials_t` | all-NULL | in-memory PEM credentials; when `cert_pem` is non-NULL the TLS accept path uses `jpv2g_tls_server_wrap_mem()` **instead of** the file paths — the only workable source on the PLC. See `docs/ISO20_MODULE.md` §7. |

`jpv2g_secc_init()` memsets the whole session object, so pause/resume
memory, DIN contract, and reject diagnostics all start zeroed.

## 3. Client handling

| Function | Use |
|---|---|
| `jpv2g_secc_handle_client(secc, fd, timeout_ms)` | plaintext stream |
| `jpv2g_secc_handle_client_tls(secc, fd, cert, key, ca, timeout_ms)` | TLS-wrap then stream. Credential precedence: populated `cfg.tls_mem_creds` wins (→ `jpv2g_tls_server_wrap_mem`, ~secc.c:2404); otherwise per-call paths, otherwise `cfg.tls_*_path`. On wrap failure the fd is closed and the rc returned. |
| `jpv2g_secc_handle_client_detect(secc, fd, first_timeout_ms, timeout_ms)` | peeks the first bytes and routes TLS vs plaintext automatically; waits up to `first_timeout_ms` for the first data |
| `jpv2g_secc_handle_client_detect_ex(..., *out_reason, *out_saw_session_stop)` | same + classified drop reason (§7). Both out-pointers optional. **This is what the firmware calls** (`main.cpp` ~26839). |

`timeout_ms` is the per-message idle timeout inside the stream loop. An
idle timeout after at least one handled message exits with rc 0 (normal
end); before any message it exits `-ETIMEDOUT` (first-packet timeout).

## 4. `handle_request` override pattern

`jpv2g_secc_t.handle_request` is the per-message dispatch hook:

```c
int (*handle_request)(jpv2g_message_type_t type, const void *decoded,
                      uint8_t *out, size_t out_len, size_t *written,
                      void *user_ctx);
```

- `NULL` (default): every request goes to `jpv2g_secc_default_handle()`,
  which fabricates library-default responses (fixed EVSE ID, echoed
  targets, fail-closed auth — `backend.authorize_contract == NULL` means
  denied). Good for bench simulators; NOT for a real charger.
- Overridden: `decoded` is a `const jpv2g_secc_request_t *` carrying
  `{protocol, header/din_header, body}`. The handler encodes the full EXI
  response into `out` and sets `*written`. The PLC firmware sets
  `g_secc.handle_request = hlc_handle_request` (`main.cpp` ~27659) and
  its per-message handlers call **back into**
  `jpv2g_secc_default_handle()` only for messages where the library
  default is acceptable (e.g. Authorization, SessionSetup), replacing
  everything electrical.

Contract (why before what — the VEH-3 lesson): a **non-zero handler rc
tears the stream down BEFORE any response transmits**. If you want the EV
to *see* a failure, encode a `FAILED_*` response yourself and return 0
(this is exactly what the PaymentSelection validation does, ~secc.c:1420).
Return non-zero only when the connection itself should die. `*written ==
0` with rc 0 exits the stream `-EIO`.

Sequence/session validation (§5) runs **before** your handler — you never
see out-of-order or foreign-session requests.

## 5. Sequence and session validation

Two gates run on every decoded request, in order (~secc.c:2265, :2281):

1. **Sequence gate** — `jpv2g_secc_sequence_t` (`state_secc.h`,
   `state_secc.c`). Unlike the legacy linear example FSM it models
   optional service/payment messages and repeatable Authorization,
   CableCheck, PreCharge, CurrentDemand, MeteringReceipt and
   WeldingDetection exchanges; it rejects out-of-order requests, protocol
   switching mid-session, and AC messages in a DC session. Rejection rc
   is `-EPROTO`.
2. **Session gate** — `jpv2g_secc_validate_request_session()`
   (~secc.c:917). SupportedAppProtocol is exempt (no V2G header).
   SessionSetup accepts **any SID length ≤ 8 bytes** (§8, tolerance #2).
   Every later request must present the exact 8-byte live SID; mismatch
   rc is `-EACCES`.

On either rejection the engine records the exact rejected message in
`secc->last_reject_phase/_type/_protocol` (the firmware surfaces these on
its never-gated EVT lane as `EVT V2G_SEQ_REJECT` — the library's own
`JPV2G_WARN` is compiled out of shipping firmware), then applies §6.

## 6. Minimal-FAILED behavior (send-then-terminate)

2026-07-20 gap audit #3 (`[V2G2-538]/[V2G2-460]/[V2G2-539]`, DIN
`[V2G-DC-665]`; ~secc.c:1886, encoders `cbv2g_codec.c` ~2186): a sequence
violation or unknown-SessionID request is answered with a **decodable
minimal Res of the request's own message type** carrying
`FAILED_SequenceError` / `FAILED_UnknownSession`, and THEN the stream
terminates. Every reference SECC (EvseV2G, Josev, RISE-V2G) behaves this
way; the previous silent TCP drop read as "EVSE died" to several EV
stacks, which retry-looped on it.

Details that matter:

- Best-effort: encode/send failures are ignored; the exit rc, the
  `last_reject_*` diagnostics and the drop-reason mapping are
  byte-identical either way. Send timeout 2 s
  (`SECC_MIN_FAILED_SEND_TIMEOUT_MS`).
- The encoders reuse each message's normal default-fill path with only
  the ResponseCode changed — no novel field combination on the wire.
- The caller MUST still terminate after sending: some EVs (ccs32clara)
  check only `<Res>_isUsed` and ignore ResponseCode entirely; staying in
  the loop would run a zombie sequence.
- Not covered: SupportedAppProtocol (own response path) and DIN
  ChargingStatus (no DIN Res exists) — plain termination.

**Always call `jpv2g_secc_retire_session()` on every client teardown**
(TCP drop, idle timeout, codec error, local stop). The default handler
clears the live SID only on an orderly SessionStopRes; an unclean drop
would otherwise leave the dead SID joinable by the next connection.
Retire preserves the pause memory (below).

## 7. Pause/resume contract and drop classification

**Pause/resume** (ISO 15118-2 `SessionStop ChargingSession=Pause`):

- On Pause the handler retains the SID in `last_session_id` +
  `last_session_end_ms`; the stream loop also records whether the paused
  session had negotiated DC (`last_session_was_dc`, SP-1 S9).
- A SessionSetupReq presenting that SID within the resume window
  (`SECC_PAUSE_RESUME_WINDOW_MS` = 60 min, ~secc.c:969) is answered
  `OK_OldSessionJoined`; the paused session's DC-ness is re-applied
  one-shot to the fresh sequence FSM so a resumed DC session's
  CPD → PowerDelivery(Start) is not mis-inferred as AC.
- **Any other** non-zero SID gets a fresh SECC SID +
  `OK_NewSessionEstablished` (VEH-2): echoing arbitrary SIDs back as
  "joined" both resurrected dead sessions and confused EVs that send a
  random SID expecting a new session. Resume comparison is strictly
  8-byte — short SIDs are never padded into it (a false
  `OK_OldSessionJoined` is worse than a fresh session).

**Drop classification** — `jpv2g_secc_classify_disconnect(rc,
handled_any, saw_session_stop)` maps the stream rc to
`jpv2g_hlc_drop_reason_t` (`secc.h`; values are stable diagnostic IDs, do
NOT renumber):

| rc | reason |
|---|---|
| `0` + saw_session_stop | `EV_SESSION_STOP` (4) |
| `0` otherwise | `IDLE_TIMEOUT` (2) |
| `-ETIMEDOUT` | `IDLE_TIMEOUT`, or `FIRST_PACKET_TIMEOUT` (1) if nothing was handled |
| `-ECONNRESET` | `PEER_RESET` (3) |
| `-EBADMSG` / `-ENOSPC` / `-E2BIG` | `CODEC_ERROR` (7) |
| `-EIO` / `-EPIPE` | `TCP_SEND_FAIL` (6) |
| `-EPROTO` | `SEQUENCE_ERROR` (11) |
| `-EACCES` | `UNKNOWN_SESSION` (12) |
| `-EINVAL` | `INVALID_ARG` (10) |
| rc > 0 or other non-errno | `HANDLER_ERROR` (8) |
| any other negative | `TCP_RECV_FAIL` (5) — catch-all |

The PLC worker branches on this for power-path policy: a clean
SESSION_STOP allows a relaxed teardown; a PEER_RESET during active
charging must drop current to 0 A immediately; CODEC_ERROR implies stack
incompatibility worth surfacing, not blind retry.

## 8. Interop tolerances (2026-07-20 V2G gap audit)

Each entry is deliberate, bounded, and cross-checked against reference
stacks (EvseV2G, Josev, RISE-V2G, pyslac-era field notes). Do not
"tighten" these without re-reading the WHY.

| # | Tolerance | Where | Why |
|---|---|---|---|
| 2 | SessionSetup accepts **any SID length ≤ 8** (was: 0 or exactly 8 → `-EINVAL` → silent TCP drop) | `jpv2g_secc_validate_request_session`, ~secc.c:939 | RISE-V2G's own EVCC sends a 1-byte `0x00` SID; EvseV2G zero-pads short SIDs; Josev decodes any length ≤ 8. Any RISE-derived EV was hard-stranded in total silence. A non-8-byte SID is classified "no SID" → fresh SECC SID + `OK_NewSessionEstablished`. Lengths > 8 cannot decode (schema cap). |
| 3 | Minimal decodable FAILED Res before teardown | §6 | silent RST reads as "EVSE died"; EVs retry-loop |
| 9 | **Bounded** ignore of undecodable mid-session frames: up to 6 consecutive, only after ≥1 handled message; counter resets on each dispatched message | stream loop, ~secc.c:2239 (same policy applied to -20 frames, ~secc.c:2020) | EvseV2G: "we must ignore packet which we cannot decode". A nonconformant EV EXI encoder or a PnC probe (CertificateInstallationReq) must not kill a live charge. Bounded because incoming bytes reset the idle timeout — unbounded ignore would let a babbling peer pin the worker forever. Pre-session garbage still tears down immediately (the stream may be desynced from byte one). |
| 10 | DIN `DateTimeNow` omitted when the platform has no plausible wall clock (`secc_wallclock_or_absent`, ~secc.c:1262; threshold 2020-01-01) | SessionSetupRes, PaymentDetailsRes | the ESP32-S3 PLC has no RTC/NTP; `time(NULL)` is seconds-since-boot, so every DIN session used to receive an epoch-1970 timestamp. Omitting the optional field is the honest answer; it reappears automatically on real-clock platforms. |
| 11 | DIN ChargingStatusReq answered `-EPROTO` (terminate) instead of ISO2-encoded bytes | ~secc.c:1589 | the DIN XSD retained ISO-draft AC messages so the decoder CAN produce it; the only handler with no protocol branch used to answer with wrong-schema bytes. EvseV2G likewise ignores it. |
| 12 | PaymentSelection **validated**: a payment option that was never offered (we advertise ExternalPayment only) answers `FAILED_PaymentSelectionInvalid` — encoded by the handler, rc 0, so the Res transmits before the sequence dies | ~secc.c:1420 | RISE-V2G validates the same; the old unconditional OK let a Contract-selecting EV sail into authorization as pseudo-EIM (PaymentDetails is optional in the DIN state table, so nothing downstream caught it). The SelectedServiceList walk stays deliberately lenient — VEH-3: never punish a quirky EV for its ServiceID bookkeeping. |
| — | DIN energy-transfer contract: the ONE mode successfully advertised in DIN ServiceDiscoveryRes is pinned per-session; CPD cannot accept a different mode merely because it is in `supported_energy_modes` | `din_advertised_energy_transfer_*` (secc.h) | DIN ServiceDiscovery carries exactly one EnergyTransferType — the generic list is not the session contract. |

Regression coverage: `tests/jpv2g_unit_test.c`
(`test_secc_session_id_validation`, `test_secc_min_failed_res_is_decodable`,
`test_secc_stream_sends_failed_res_before_teardown`,
`test_secc_stream_ignores_undecodable_midsession`,
`test_din_session_setup_timestamp_gate`,
`test_payment_selection_rejects_unoffered`, `test_iso_pause_resume`).

## 9. Logging

`JPV2G_LOG_LEVEL` gates the library's stdio logger at compile time
(6 = everything off — the shipping firmware's setting). Runtime toggles
`jpv2g_secc_set_decoded_logs()` / `jpv2g_secc_set_timing_logs()` control
the decoded-transaction and handler-timing lines in builds where logging
exists at all. Treat library logs as bench evidence only: on the charger
they do not exist, and the protocol-visible diagnostics are the firmware
EVT lane plus `last_reject_*` / drop-reason classification.

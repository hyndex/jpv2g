# jpv2g — embedded-first V2G library (SECC/EVCC)

![Language](https://img.shields.io/badge/language-C99-blue)
![DIN 70121](https://img.shields.io/badge/DIN%2070121-shipped-brightgreen)
![ISO 15118-2](https://img.shields.io/badge/ISO%2015118--2-shipped-brightgreen)
![ISO 15118-20](https://img.shields.io/badge/ISO%2015118--20%20DC-gated-yellow)
![EXI](https://img.shields.io/badge/EXI%20codec-cbv2g%20(bundled)-informational)
![TLS](https://img.shields.io/badge/TLS-tier--1%20(gated)-yellow)
![Tests](https://img.shields.io/badge/host%20tests-passing-success)

`jpv2g` is a platform-independent C99 library implementing the EV-side
high-level-communication protocols of a DC fast charger:

- **DIN 70121** and **ISO 15118-2** SECC (EVSE side) — production, shipped
  in the JoulePoint PLC firmware.
- **ISO 15118-20 DC** SECC — a gated module (`JPV2G_ENABLE_ISO20`, default
  OFF), host-tested, NOT yet wired into firmware. See
  [`docs/ISO20_MODULE.md`](docs/ISO20_MODULE.md).
- An EVCC counterpart (`evcc.c`, `state_evcc.c`) kept intact from the
  original extraction — exercised by the host tests and the
  `platformio/esp32_arduino_smoke` example; the charger firmware uses only
  the SECC role.

The EXI codec is the bundled **cbv2g** generated code
(`3rd_party/cbv2g/`, appHandshake + DIN + ISO-2 + ISO-20 schemas). jpv2g
adds the transport (V2GTP framing, SDP, TCP/TLS), the session/sequence
state machines, the response builders, and the interop hardening on top.

Authoritative API docs in this repo:

| Doc | Covers |
|---|---|
| [`docs/SECC_API.md`](docs/SECC_API.md) | embedding the -2/DIN SECC: config, client handling, handler override, validation, drop classification, interop tolerances |
| [`docs/ISO20_MODULE.md`](docs/ISO20_MODULE.md) | the ISO 15118-20 DC module + the TLS tier |
| [`docs/DEVELOPER_ESP32_ARDUINO.md`](docs/DEVELOPER_ESP32_ARDUINO.md) | MCU portability hooks (RNG, time, lwIP), legacy state-machine API |

The **wire-facing** behavior of the shipping charger (UART control plane,
EVT lanes, session choreography) is documented in the consuming repo:
`plc_firmware/DEVELOPER_CONTROL_PLANE_API.md` and `plc_firmware/docs/`.

---

## 🔁 SECC message flow

The `secc.c` stream engine walks the DIN 70121 / ISO 15118-2 request
sequence in order; each state accepts exactly its expected request and the
default handler builds the corresponding `Res`. External inputs (auth
grant, present V/I, isolation) are controller-owned and supplied through
the handler override.

```mermaid
stateDiagram-v2
    [*] --> SupportedAppProtocol
    SupportedAppProtocol --> SessionSetup
    SessionSetup --> ServiceDiscovery
    ServiceDiscovery --> PaymentServiceSelection
    PaymentServiceSelection --> Authorization
    Authorization --> ChargeParameterDiscovery: granted
    ChargeParameterDiscovery --> CableCheck
    CableCheck --> PreCharge
    PreCharge --> PowerDelivery
    PowerDelivery --> CurrentDemand
    CurrentDemand --> WeldingDetection: PowerDelivery(Stop)
    WeldingDetection --> SessionStop
    SessionStop --> [*]
    note right of Authorization: EIM: Ongoing_WaitingForCustomerInteraction\n→ Finished when granted
```

## 🔌 Embedding the SECC (C)

Developer reference for integrating the -2/DIN SECC into firmware. This is
the minimal shape; see [`docs/SECC_API.md`](docs/SECC_API.md) for the full
config, validation, and drop-classification contract.

```c
#include "jpv2g/secc.h"
#include "jpv2g/config.h"

static int on_request(jpv2g_message_type_t type, const jpv2g_secc_request_t *req,
                      uint8_t *out, size_t out_len, size_t *written, void *user) {
    /* Your controller-owned decisions land here (auth, limits, isolation,
     * present V/I). The library encodes the wire Res; you supply the values.
     * The PLC firmware installs exactly this override. */
    return jpv2g_secc_default_handle(/* secc */ user, type, req, out, out_len, written);
}

void secc_task(int listen_fd) {
    jpv2g_secc_config_t cfg;
    jpv2g_secc_config_default(&cfg);        /* tcp_port 15118; TLS off on the PLC */
    jpv2g_secc_t secc;
    jpv2g_secc_init(&secc, &cfg, /* codec */ NULL);
    secc.handle_request = on_request;
    for (;;) {
        int fd = accept(listen_fd, NULL, NULL);
        jpv2g_hlc_drop_reason_t why; bool saw_stop;
        jpv2g_secc_handle_client_detect_ex(&secc, fd, 20000, 60000, &why, &saw_stop);
    }
}
```

---

## ⚡ Build matrix (host CMake)

```bash
cmake -S . -B build -DJPV2G_BUILD_TESTING=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Options (defaults verified in `CMakeLists.txt`):

| Option | Default | Effect |
|---|---|---|
| `JPV2G_ENABLE_CBV2G_CODEC` | `ON` | compiles the full EVCC/SECC stack (`cbv2g_codec.c`, `evcc.c`, `secc.c`, `secc_iso20.c`) against the cbv2g EXI codec. OFF leaves only the codec-free core (transport, state machines, TLS shell). |
| `JPV2G_BUNDLE_CBV2G` | `ON` | build the bundled `3rd_party/cbv2g` sources. OFF requires `JPV2G_CBV2G_INCLUDE_DIR` (and optionally `JPV2G_CBV2G_LIBRARY`). |
| `JPV2G_ENABLE_ISO20` | `OFF` | enable the ISO 15118-20 DC SECC module. A default build stays **byte-identical in behavior**: -20 SAP offers simply fail to match and the EV falls back to -2/DIN. `src/secc_iso20.c` is *always compiled*; with the flag off its entry points collapse to `-ENOTSUP` stubs (same pattern as the no-mbedtls branch of `src/tls.c`). ON additionally compiles exactly 6 generated -20 codec files (CommonMessages + DC) — never the upstream `cbv2g_iso20` target, which drags in AC/ACDP/WPT dead code. |
| `JPV2G_HAVE_MBEDTLS` | `OFF` | compile the mbedtls-backed TLS branch (`src/tls.c`, `src/security.c`); defines `HAVE_MBEDTLS` **PUBLIC** (it changes the layout of `jpv2g_tls_socket_t`, so every consumer must agree) and links mbedtls 2.28 (`mbedtls`/`mbedx509`/`mbedcrypto`). OFF: TLS wrap returns `-ENOTSUP`. The shipping firmware never sets this through CMake. |
| `JPV2G_BUILD_TESTING` | `OFF` | host unit tests (see below). |
| `JPV2G_BUILD_EXAMPLES` | `OFF` | `examples/microcontroller_usage_stub.c` → `jpv2g_mcu_usage_stub`. |
| `JPV2G_INSTALL` | `ON` | install `jpv2g::jpv2g` + headers + cmake export. |

Why the flags default OFF: the firmware release-provenance gate hashes
source inputs, and a default host build must reproduce the exact behavior
the charger ships — optional tiers are opt-in on both sides.

## ✅ Test suite

`-DJPV2G_BUILD_TESTING=ON` registers (see `tests/CMakeLists.txt`):

| ctest name | What it proves |
|---|---|
| `jpv2g_unit_test` | ~25 cases in `tests/jpv2g_unit_test.c`: V2GTP round-trip/bounds, EVCC/SECC legacy sequences, the production sequence gate, SAP interop, fail-closed default-handler safety, DIN/ISO DC response round-trips, pause/resume, SessionID validation, minimal-FAILED decodability + send-before-teardown, bounded undecodable-frame ignore, DIN timestamp gate, PaymentSelection rejection, TLS credential validation + `-ENOTSUP` stubs. |
| `jpv2g_no_automatic_secc_exi_documents` | static guard (`tests/forbid_automatic_exi_docs.cmake`): `secc.c` must never declare a cbv2g `exiDocument` in automatic/static storage (they are huge; workspaces are explicit). |
| `jpv2g_iso20_test` (flag-gated) | 11 cases in `tests/jpv2g_iso20_test.c`: full -20 happy path, unknown-session/sequence-error FAILED answers, BPT/Dynamic/wrong-service rejection, stop/renegotiation, standby warning, RationalNumber round-trip, SAP selection, end-to-end stream. Only with `-DJPV2G_ENABLE_ISO20=ON`. |
| `jpv2g_no_automatic_iso20_exi_documents` (flag-gated) | same guard for `secc_iso20.c` — the -20 documents are the largest of all. |

## 🔌 How the PLC firmware consumes this repo

`plc_firmware` does **not** link the CMake library. Its PlatformIO
pre-script (`plc_firmware/extra_script.py`) resolves the sibling checkout
(`evse_root / "jpv2g"`), then:

- appends `include/`, `3rd_party/cbv2g/include`, `3rd_party/cbv2g/lib` to
  `CPPPATH`;
- compiles `src/` and `3rd_party/cbv2g/lib/cbv2g` straight into the
  firmware image via `env.BuildSources(...)` (~line 1048);
- folds a content hash of the jpv2g tree into the release-provenance build
  id (`JOULEPOINT_JPV2G_SOURCE_ID`), so any jpv2g edit changes the
  attested firmware identity.

Firmware-side compile contract (verified in `plc_firmware/platformio.ini`):
`-DJPV2G_ENABLE_CBV2G_CODEC=1` and `-DJPV2G_LOG_LEVEL=6`. The latter
compiles **all library stdio logging out** of shipping firmware — jpv2g's
default logger writes through `fprintf(stderr)`, which would bypass the
firmware's serialized USB egress. Diagnostics on the charger therefore
come from the firmware's own EVT lane (e.g. `EVT V2G_RX`, the
`last_reject_*` fields surfaced as `EVT V2G_SEQ_REJECT`), not from
`JPV2G_WARN/INFO`. Neither `JPV2G_ENABLE_ISO20` nor `HAVE_MBEDTLS` is
defined in the firmware build: on the charger the -20 module and the TLS
tier are `-ENOTSUP` stubs today.

## Repo layout

| Path | Contents |
|---|---|
| `include/jpv2g/` | public headers (`secc.h`, `secc_iso20.h`, `config.h`, `tls.h`, `v2gtp.h`, …) |
| `src/` | implementation; `secc.c` is the -2/DIN stream engine + default handler, `secc_iso20.c` the -20 module, `cbv2g_codec.c` the per-message encode/decode helpers |
| `3rd_party/cbv2g/` | bundled generated EXI codec (appHandshake, common, din, iso_2, iso_20) |
| `tests/` | host unit tests + static guards |
| `examples/` | minimal MCU usage stub |
| `platformio/` | on-target smoke (`esp32_arduino_smoke`) and real-hardware SLAC+HLC precharge example (`esp32s3_slac_hlc_precharge`) |
| `docs/` | this repo's developer docs |

`build*/` directories are local build residue, not sources of truth.

## ⚠️ Conventions

- Errors are negative POSIX errno values; `0` is success.
- Time is `jpv2g_now_monotonic_ms()` (monotonic on ESP32; see the
  host-side caveats in `docs/DEVELOPER_ESP32_ARDUINO.md`).
- Encode/decode scratch is bounded by `JPV2G_MAX_EXI_SIZE` (4096 B,
  `include/jpv2g/constants.h`); V2GTP frames by `JPV2G_MAX_V2GTP_SIZE`.
- cbv2g `exiDocument` unions are never automatic/static locals — a ctest
  guard enforces this for both SECC sources.

# jpv2g Developer Guide (ESP32 Arduino)

## Scope

`jpv2g` is a standalone V2G C library extracted from `Basic/lib/jpv2g` and packaged
for microcontroller use while preserving protocol logic/state flow.

Author: Chinmoy Bhuyan  
Company: Joulepoint Private Limited

## Library Layout

- `include/jpv2g/`: public API
- `src/`: core implementation
- `3rd_party/cbv2g/`: bundled EXI codec implementation
- `tests/`: host-side unit tests
- `platformio/esp32_arduino_smoke/`: on-target smoke test
- `platformio/esp32s3_slac_hlc_precharge/`: real-hardware SLAC + HLC example

## What Was Kept Intact

- EVCC/SECC message processing and routing flow
- State machine semantics (`state_machine.c`, `state_evcc.c`, `state_secc.c`)
- V2GTP encode/decode path
- Discovery/transport/TLS API structure

Only portability scaffolding and packaging were added (CMake/project setup, RNG hook,
time compatibility helper, tests/docs/examples).

## State Handling

State logic is identical to the original source:

- `jpv2g_sm_handle()` validates expected message type and dispatches current state handler.
- EVCC sequence builder (`jpv2g_evcc_build_sequence`) produces:
  - 15 states in DC mode
  - 12 states in AC mode
- SECC sequence builder (`jpv2g_secc_build_sequence`) produces:
  - 15 states in DC mode
  - 12 states in AC mode
- Final state behavior:
  - EVCC remains on final state and permits repeated handling.
  - SECC remains on final state once reached.

## MCU Portability Hooks

### Random source

- API: `jpv2g_set_random_provider(jpv2g_random_provider_fn fn)`
- Default behavior:
  - `ESP_PLATFORM`: uses `esp_fill_random`
  - Linux/macOS: native OS randomness
  - fallback: `rand()`

### Time source

- API: `jpv2g_now_monotonic_ms()`, `jpv2g_sleep_ms()`
- `ESP_PLATFORM`: uses `esp_timer_get_time()` and `vTaskDelay()`
- non-ESP: uses `clock_gettime(CLOCK_MONOTONIC)` and `usleep()`

These hooks avoid direct dependency on Linux-only timing behavior in EVCC/SECC/TLS paths.

### Networking

- Linux networking support was removed.
- Socket transport is lwIP-only and intended for microcontroller targets.

## Build and Test (Host)

```bash
cmake -S /home/jpi/Desktop/EVSE/jpv2g -B /home/jpi/Desktop/EVSE/jpv2g/build
cmake --build /home/jpi/Desktop/EVSE/jpv2g/build -j
```

Enable tests:

```bash
cmake -S /home/jpi/Desktop/EVSE/jpv2g -B /home/jpi/Desktop/EVSE/jpv2g/build-test -DJPV2G_BUILD_TESTING=ON
cmake --build /home/jpi/Desktop/EVSE/jpv2g/build-test -j
ctest --test-dir /home/jpi/Desktop/EVSE/jpv2g/build-test --output-on-failure
```

## Build and Test (ESP32 Arduino via PlatformIO)

```bash
pio run -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32_arduino_smoke
pio run -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32_arduino_smoke -t upload
pio device monitor -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32_arduino_smoke -b 115200
```

Expected serial output should report `PASS` for all smoke checks.

## SLAC + HLC (to PreCharge) Example

Use:

```bash
pio run -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32s3_slac_hlc_precharge
pio run -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32s3_slac_hlc_precharge -t upload --upload-port /dev/ttyACM0
pio device monitor -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32s3_slac_hlc_precharge -b 115200
```

Flow:

1. CP detected (`B/C/D`)
2. SLAC runs to `Matched` via `cbslac`
3. `jpv2g` starts SDP responder + TCP HLC server on `15118`
4. EXI message handling continues and logs when `PreChargeReq` is received

## Notes for Real EV/EVSE End-to-End

- The smoke project validates core library behavior, not full EV cable session exchange.
- For live EV/EVSE exchange, integrate:
  - Control Pilot handling
  - PLC modem interface + IPv6 route/interface mapping
  - certificate/key provisioning for TLS mode
  - real backend callbacks (`authorize_contract`, `authorize_external`)

jpv2g
=====

Microcontroller-focused, platform-independent V2G library extracted from ``Basic/lib/jpv2g``.

Author: Chinmoy Bhuyan
Company: Joulepoint Private Limited

Overview
--------

This repository packages the original jpv2g code as a standalone reusable library,
similar to ``cbslac`` layout and workflow.

Key points:

- Code base copied from ``Basic/lib/jpv2g``.
- Structured as a standalone CMake library target: ``jpv2g::jpv2g``.
- Includes optional bundled ``cbv2g`` sources for full EXI codec support.
- Keeps EVCC/SECC state machine and protocol flow intact.
- Adds MCU portability hooks for RNG and monotonic timing.
- Includes host unit tests and PlatformIO ESP32 Arduino smoke tests.
- Linux support was removed; networking is lwIP-only (microcontroller-focused).

Build
-----

.. code-block:: bash

   cmake -S . -B build
   cmake --build build -j

Important CMake options:

- ``-DJPV2G_ENABLE_CBV2G_CODEC=ON|OFF``
- ``-DJPV2G_BUNDLE_CBV2G=ON|OFF``
- ``-DJPV2G_BUILD_EXAMPLES=ON|OFF``
- ``-DJPV2G_BUILD_TESTING=ON|OFF``
- ``-DJPV2G_INSTALL=ON|OFF``

Example (stub)
--------------

.. code-block:: bash

   cmake -S . -B build -DJPV2G_BUILD_EXAMPLES=ON
   cmake --build build -j
   ./build/jpv2g_mcu_usage_stub

Unit Tests (host)
-----------------

.. code-block:: bash

   cmake -S . -B build-test -DJPV2G_BUILD_TESTING=ON
   cmake --build build-test -j
   ctest --test-dir build-test --output-on-failure

PlatformIO ESP32 Arduino Smoke
------------------------------

.. code-block:: bash

   pio run -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32_arduino_smoke
   pio run -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32_arduino_smoke -t upload
   pio device monitor -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32_arduino_smoke -b 115200

PlatformIO ESP32-S3 SLAC + HLC (PreCharge)
------------------------------------------

.. code-block:: bash

   pio run -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32s3_slac_hlc_precharge
   pio run -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32s3_slac_hlc_precharge -t upload --upload-port /dev/ttyACM0
   pio device monitor -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32s3_slac_hlc_precharge -b 115200

Microcontroller Notes
---------------------

- For ESP-IDF/Arduino, ``jpv2g_random_bytes`` uses ``esp_fill_random`` when available.
- You can override RNG with ``jpv2g_set_random_provider`` for hardware TRNG integration.
- ``time_compat`` provides MCU-safe monotonic time and sleep helpers used by EVCC/SECC/TLS paths.
- Socket transport is lwIP-only.

Developer Documentation
-----------------------

- ``docs/DEVELOPER_ESP32_ARDUINO.md`` explains architecture, state handling, and end-to-end dev workflow.

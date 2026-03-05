# jpv2g ESP32 Arduino Smoke Test

This PlatformIO project builds `jpv2g` for ESP32 (`arduino` framework) and runs
smoke checks for:

- RNG path (`jpv2g_random_bytes`)
- V2GTP build/parse round trip
- EVCC state sequence construction and stepping
- SECC state sequence construction and stepping

## Build

```bash
pio run -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32_arduino_smoke
```

## Upload

```bash
pio run -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32_arduino_smoke -t upload
```

## Monitor

```bash
pio device monitor -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32_arduino_smoke -b 115200
```

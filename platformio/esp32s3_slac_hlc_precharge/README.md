# ESP32-S3 SLAC + HLC (PreCharge) Example

This project combines:

- `cbslac` EVSE SLAC matching (QCA7000 + CP)
- `jpv2g` SECC stack over lwIP (SDP + TCP HLC)

Target behavior:

1. Wait for CP `B/C/D`
2. Run SLAC until `Matched`
3. Start SDP responder + HLC TCP server on port `15118`
4. Process HLC session and log when `PreChargeReq` is observed

## Hardware (same as Basic / cbslac e2e)

- Board: `esp32-s3-devkitc-1`
- QCA INT: `GPIO2`
- QCA CS: `GPIO10`
- QCA RESET: `GPIO8`
- QCA SPI SCK/MISO/MOSI: `GPIO7/GPIO16/GPIO15`
- CP PWM output: `GPIO38`
- CP ADC input: `GPIO1`

## Build

```bash
pio run -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32s3_slac_hlc_precharge
```

## Upload

```bash
pio run -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32s3_slac_hlc_precharge -t upload --upload-port /dev/ttyACM0
```

## Monitor

```bash
pio device monitor -d /home/jpi/Desktop/EVSE/jpv2g/platformio/esp32s3_slac_hlc_precharge -b 115200
```

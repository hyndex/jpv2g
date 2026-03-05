#include <stdio.h>
#include <string.h>

#include "jpv2g/byte_utils.h"
#include "jpv2g/v2gtp.h"

int main(void) {
    uint8_t rnd[16];
    int rc = jpv2g_random_bytes(rnd, sizeof(rnd));
    if (rc != 0) {
        printf("jpv2g_random_bytes failed: %d\n", rc);
        return 1;
    }

    uint8_t payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t frame[64];
    size_t frame_len = 0;
    rc = jpv2g_v2gtp_build(JPV2G_PAYLOAD_EXI, payload, sizeof(payload), frame, sizeof(frame), &frame_len);
    if (rc != 0) {
        printf("jpv2g_v2gtp_build failed: %d\n", rc);
        return 1;
    }

    jpv2g_v2gtp_t parsed;
    memset(&parsed, 0, sizeof(parsed));
    rc = jpv2g_v2gtp_parse(frame, frame_len, &parsed);
    if (rc != 0) {
        printf("jpv2g_v2gtp_parse failed: %d\n", rc);
        return 1;
    }

    printf("jpv2g stub ok: frame_len=%zu payload_len=%u\n", frame_len, parsed.payload_length);
    return 0;
}

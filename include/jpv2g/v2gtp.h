/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "jpv2g/byte_utils.h"

#define JPV2G_V2GTP_VERSION 0x01
#define JPV2G_V2GTP_HEADER_LEN 8

typedef enum {
    JPV2G_PAYLOAD_EXI = 0x8001,
    /* ISO 15118-20 mainstream payload ids. Members exist unconditionally
     * (inert enum values, no behavior change); jpv2g_payload_type_supported()
     * only accepts them when built with JPV2G_ENABLE_ISO20. */
    JPV2G_PAYLOAD_EXI_20_MAINSTREAM = 0x8002, /* iso20 CommonMessages */
    JPV2G_PAYLOAD_EXI_20_DC = 0x8004,         /* iso20 DC */
    JPV2G_PAYLOAD_SDP_REQ = 0x9000,
    JPV2G_PAYLOAD_SDP_RES = 0x9001
} jpv2g_payload_type_t;

typedef struct {
    uint8_t protocol_version;
    uint8_t inverse_protocol_version;
    jpv2g_payload_type_t payload_type;
    uint32_t payload_length;
    const uint8_t *payload; /* Points into the source buffer or caller-owned memory */
} jpv2g_v2gtp_t;

int jpv2g_v2gtp_parse(const uint8_t *buf, size_t len, jpv2g_v2gtp_t *out);
int jpv2g_v2gtp_validate(const jpv2g_v2gtp_t *msg);
int jpv2g_v2gtp_build(jpv2g_payload_type_t type,
                        const uint8_t *payload,
                        size_t payload_len,
                        uint8_t *out,
                        size_t out_len,
                        size_t *written);
bool jpv2g_payload_type_supported(jpv2g_payload_type_t type);

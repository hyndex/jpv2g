/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/v2gtp.h"

#include <errno.h>
#include <string.h>

#include "jpv2g/log.h"

bool jpv2g_payload_type_supported(jpv2g_payload_type_t type) {
    switch (type) {
        case JPV2G_PAYLOAD_EXI:
        case JPV2G_PAYLOAD_SDP_REQ:
        case JPV2G_PAYLOAD_SDP_RES:
            return true;
        default:
            return false;
    }
}

int jpv2g_v2gtp_validate(const jpv2g_v2gtp_t *msg) {
    if (!msg) return -EINVAL;
    if (msg->protocol_version != JPV2G_V2GTP_VERSION) {
        return -EPROTONOSUPPORT;
    }
    if (msg->inverse_protocol_version != (uint8_t)(msg->protocol_version ^ 0xFF)) {
        return -EBADMSG;
    }
    if (!jpv2g_payload_type_supported(msg->payload_type)) {
        return -ENOTSUP;
    }
    if (msg->payload_length > JPV2G_MAX_PAYLOAD_LENGTH) {
        return -E2BIG;
    }
    if (msg->payload_length == 0 && msg->payload != NULL) {
        /* zero-length payload allowed, but payload pointer should be NULL */
        return -EINVAL;
    }
    return 0;
}

int jpv2g_v2gtp_parse(const uint8_t *buf, size_t len, jpv2g_v2gtp_t *out) {
    if (!buf || !out) return -EINVAL;
    if (len < JPV2G_V2GTP_HEADER_LEN) return -EMSGSIZE;

    memset(out, 0, sizeof(*out));
    out->protocol_version = buf[0];
    out->inverse_protocol_version = buf[1];
    out->payload_type = (jpv2g_payload_type_t)jpv2g_read_u16_be(&buf[2]);
    out->payload_length = jpv2g_read_u32_be(&buf[4]);

    if (out->payload_length > JPV2G_MAX_PAYLOAD_LENGTH) {
        return -E2BIG;
    }

    size_t required = (size_t)JPV2G_V2GTP_HEADER_LEN + (size_t)out->payload_length;
    if (required > len) return -EMSGSIZE;

    out->payload = (out->payload_length > 0) ? &buf[JPV2G_V2GTP_HEADER_LEN] : NULL;

    return jpv2g_v2gtp_validate(out);
}

int jpv2g_v2gtp_build(jpv2g_payload_type_t type,
                        const uint8_t *payload,
                        size_t payload_len,
                        uint8_t *out,
                        size_t out_len,
                        size_t *written) {
    if (!out) return -EINVAL;
    if (!jpv2g_payload_type_supported(type)) return -ENOTSUP;
    if (payload_len > JPV2G_MAX_PAYLOAD_LENGTH) return -E2BIG;
    if (out_len < JPV2G_V2GTP_HEADER_LEN + payload_len) return -ENOSPC;
    if (payload_len > 0 && payload == NULL) return -EINVAL;

    out[0] = JPV2G_V2GTP_VERSION;
    out[1] = (uint8_t)(JPV2G_V2GTP_VERSION ^ 0xFF);
    jpv2g_write_u16_be(&out[2], (uint16_t)type);
    jpv2g_write_u32_be(&out[4], (uint32_t)payload_len);

    if (payload_len > 0) {
        memcpy(&out[JPV2G_V2GTP_HEADER_LEN], payload, payload_len);
    }

    if (written) *written = JPV2G_V2GTP_HEADER_LEN + payload_len;
    return 0;
}

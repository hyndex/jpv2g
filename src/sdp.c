/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/sdp.h"

#include <errno.h>
#include <string.h>

#include "jpv2g/byte_utils.h"
#include "jpv2g/log.h"

int jpv2g_sdp_req_encode(const jpv2g_sdp_req_t *req, uint8_t *out, size_t out_len, size_t *written) {
    if (!req || !out) return -EINVAL;
    if (out_len < 2) return -ENOSPC;
    out[0] = req->security;
    out[1] = req->transport_protocol;
    if (written) *written = 2;
    return 0;
}

int jpv2g_sdp_req_decode(const uint8_t *buf, size_t len, jpv2g_sdp_req_t *out) {
    if (!buf || !out) return -EINVAL;
    if (len < 2) return -EMSGSIZE;
    out->security = buf[0];
    out->transport_protocol = buf[1];
    return 0;
}

int jpv2g_sdp_res_encode(const jpv2g_sdp_res_t *res, uint8_t *out, size_t out_len, size_t *written) {
    if (!res || !out) return -EINVAL;
    if (out_len < 20) return -ENOSPC;
    memcpy(out, res->secc_ip, 16);
    jpv2g_write_u16_be(&out[16], res->secc_port);
    out[18] = res->security;
    out[19] = res->transport_protocol;
    if (written) *written = 20;
    return 0;
}

int jpv2g_sdp_res_decode(const uint8_t *buf, size_t len, jpv2g_sdp_res_t *out) {
    if (!buf || !out) return -EINVAL;
    if (len < 20) return -EMSGSIZE;
    memcpy(out->secc_ip, buf, 16);
    out->secc_port = jpv2g_read_u16_be(&buf[16]);
    out->security = buf[18];
    out->transport_protocol = buf[19];
    return 0;
}

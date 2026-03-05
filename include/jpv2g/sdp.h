/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "jpv2g/v2gtp.h"

typedef struct {
    uint8_t security;
    uint8_t transport_protocol;
} jpv2g_sdp_req_t;

typedef struct {
    uint8_t secc_ip[16];
    uint16_t secc_port;
    uint8_t security;
    uint8_t transport_protocol;
} jpv2g_sdp_res_t;

int jpv2g_sdp_req_encode(const jpv2g_sdp_req_t *req, uint8_t *out, size_t out_len, size_t *written);
int jpv2g_sdp_req_decode(const uint8_t *buf, size_t len, jpv2g_sdp_req_t *out);

int jpv2g_sdp_res_encode(const jpv2g_sdp_res_t *res, uint8_t *out, size_t out_len, size_t *written);
int jpv2g_sdp_res_decode(const uint8_t *buf, size_t len, jpv2g_sdp_res_t *out);

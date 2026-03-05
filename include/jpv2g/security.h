/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef enum {
    JPV2G_CERT_OK = 0,
    JPV2G_CERT_EXPIRED,
    JPV2G_CERT_NOT_YET_VALID,
    JPV2G_CERT_INVALID,
    JPV2G_CERT_CHAIN_INCOMPLETE,
    JPV2G_CERT_UNSUPPORTED
} jpv2g_cert_status_t;

int jpv2g_load_private_key(const char *path, uint8_t **out, size_t *out_len);
int jpv2g_load_certificate(const char *path, uint8_t **out, size_t *out_len);
jpv2g_cert_status_t jpv2g_verify_certificate(const uint8_t *cert, size_t cert_len, const uint8_t *ca_chain, size_t ca_len);

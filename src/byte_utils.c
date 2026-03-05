/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/byte_utils.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(ESP_PLATFORM)
#include <esp_system.h>
#endif

static jpv2g_random_provider_fn g_random_provider = NULL;

static int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

int jpv2g_hex_to_bytes(const char *hex, uint8_t *out, size_t out_len, size_t *written) {
    if (!hex || !out) return -EINVAL;
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -EINVAL;
    size_t bytes = hex_len / 2;
    if (bytes > out_len) return -ENOSPC;
    for (size_t i = 0; i < bytes; ++i) {
        int hi = nibble(hex[2 * i]);
        int lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -EINVAL;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    if (written) *written = bytes;
    return 0;
}

int jpv2g_bytes_to_hex(const uint8_t *in, size_t len, char *out, size_t out_len) {
    static const char *hexmap = "0123456789ABCDEF";
    if (!in || !out) return -EINVAL;
    if (out_len < (len * 2 + 1)) return -ENOSPC;
    for (size_t i = 0; i < len; ++i) {
        out[2 * i]     = hexmap[(in[i] >> 4) & 0x0F];
        out[2 * i + 1] = hexmap[in[i] & 0x0F];
    }
    out[len * 2] = '\0';
    return 0;
}

uint16_t jpv2g_read_u16_be(const uint8_t *buf) {
    return (uint16_t)((buf[0] << 8) | buf[1]);
}

uint32_t jpv2g_read_u32_be(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) |
           (uint32_t)buf[3];
}

uint64_t jpv2g_read_u64_be(const uint8_t *buf) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | buf[i];
    }
    return v;
}

void jpv2g_write_u16_be(uint8_t *buf, uint16_t v) {
    buf[0] = (uint8_t)(v >> 8);
    buf[1] = (uint8_t)(v);
}

void jpv2g_write_u32_be(uint8_t *buf, uint32_t v) {
    buf[0] = (uint8_t)(v >> 24);
    buf[1] = (uint8_t)(v >> 16);
    buf[2] = (uint8_t)(v >> 8);
    buf[3] = (uint8_t)(v);
}

void jpv2g_write_u64_be(uint8_t *buf, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        buf[7 - i] = (uint8_t)(v >> (i * 8));
    }
}

void jpv2g_set_random_provider(jpv2g_random_provider_fn fn) {
    g_random_provider = fn;
}

int jpv2g_random_bytes(uint8_t *buf, size_t len) {
    if (!buf) return -EINVAL;
    if (g_random_provider) {
        return g_random_provider(buf, len);
    }
#if defined(ESP_PLATFORM)
    esp_fill_random(buf, len);
    return 0;
#else
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
    return 0;
#endif
}

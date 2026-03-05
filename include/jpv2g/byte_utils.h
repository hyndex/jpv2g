/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#define JPV2G_MAX_PAYLOAD_LENGTH 4294967295ULL

typedef int (*jpv2g_random_provider_fn)(uint8_t *buf, size_t len);

int jpv2g_hex_to_bytes(const char *hex, uint8_t *out, size_t out_len, size_t *written);
int jpv2g_bytes_to_hex(const uint8_t *in, size_t len, char *out, size_t out_len);
uint16_t jpv2g_read_u16_be(const uint8_t *buf);
uint32_t jpv2g_read_u32_be(const uint8_t *buf);
uint64_t jpv2g_read_u64_be(const uint8_t *buf);
void jpv2g_write_u16_be(uint8_t *buf, uint16_t v);
void jpv2g_write_u32_be(uint8_t *buf, uint32_t v);
void jpv2g_write_u64_be(uint8_t *buf, uint64_t v);
void jpv2g_set_random_provider(jpv2g_random_provider_fn fn);
int jpv2g_random_bytes(uint8_t *buf, size_t len);
